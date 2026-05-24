//! Per-connection interceptor state machine.
//!
//! The proxy feeds each decrypted plaintext chunk to
//! [`Interceptor::process_chunk`]. The handler tracks one of three
//! states:
//!
//! - **Pristine.** Haven't seen any data yet. On first chunk, parse
//!   the request line + Host header and check rules.
//! - **Forwarding.** First chunk didn't match any rule. Pass every
//!   chunk through unchanged forever (per connection).
//! - **Buffering.** First chunk matched. Accumulate until we have a
//!   complete request body, then invoke the hook.
//!
//! Per-connection state means a long-lived connection that opens with
//! an HTTP/1.1 keep-alive but ships an intercepted request first will
//! not have subsequent requests on the same connection inspected.
//! That's acceptable for the OAuth refresh use case (refresh requests
//! are short-lived single-shot connections in practice).

use std::process::Stdio;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::config::{InterceptConfig, InterceptRule};

/// What the proxy should do with the chunk it just fed in.
pub enum Verdict {
    /// Forward the chunk the caller already has — zero-copy hot path.
    Forward,
    /// We had previously held bytes (in `Buffering`) and now must
    /// flush them as a single upstream write so the request reaches
    /// the server reassembled. Includes the held bytes plus the
    /// current chunk. Used only on the rare overflow fallback path.
    ForwardBuffered(Vec<u8>),
    /// Hold this chunk; the interceptor is still accumulating bytes
    /// and will decide what to do later. The proxy should not touch
    /// the upstream server with this chunk.
    Hold,
    /// Send `response` back to the guest (the proxy's reverse path)
    /// and close the connection.
    Intercept(Vec<u8>),
}

/// Per-connection interceptor state.
pub struct Interceptor {
    config: InterceptConfig,
    sni: String,
    state: State,
}

enum State {
    Pristine,
    Forwarding,
    Buffering {
        rule: InterceptRule,
        accumulated: Vec<u8>,
        /// Position of the first byte of the body (= index just past
        /// the `\r\n\r\n` boundary). `None` until we've seen the
        /// headers in full.
        body_start: Option<usize>,
        /// Total body size from `Content-Length`. `None` if we can't
        /// parse one (treat as zero, i.e. no body expected — covers
        /// GET requests and OAuth refresh POST bodies are always
        /// Content-Length'd in practice).
        content_length: Option<usize>,
    },
    /// Terminal: hit the byte cap or some other unrecoverable parse
    /// state. Stop trying.
    Disabled,
}

impl Interceptor {
    pub fn new(config: InterceptConfig, sni: &str) -> Self {
        Self {
            config,
            sni: sni.to_ascii_lowercase(),
            state: State::Pristine,
        }
    }

    /// Drive the state machine forward with the next plaintext chunk.
    pub async fn process_chunk(&mut self, chunk: &[u8]) -> std::io::Result<Verdict> {
        match &mut self.state {
            State::Pristine => self.process_first_chunk(chunk).await,
            State::Forwarding | State::Disabled => Ok(Verdict::Forward),
            State::Buffering { .. } => self.process_buffer_chunk(chunk).await,
        }
    }

    async fn process_first_chunk(&mut self, chunk: &[u8]) -> std::io::Result<Verdict> {
        if !self.config.is_active() {
            self.state = State::Forwarding;
            return Ok(Verdict::Forward);
        }

        // Need at least one line + the `\r\n` separator to parse the
        // request line. If we don't have it, just stream the chunk
        // (in practice the request line lands in the very first
        // plaintext chunk every time).
        let Some(eol) = find_subsequence(chunk, b"\r\n") else {
            self.state = State::Forwarding;
            return Ok(Verdict::Forward);
        };
        let request_line = std::str::from_utf8(&chunk[..eol]).unwrap_or("");

        let Some((method, path)) = parse_request_line(request_line) else {
            self.state = State::Forwarding;
            return Ok(Verdict::Forward);
        };

        let Some(rule) = self.find_matching_rule(method, path) else {
            self.state = State::Forwarding;
            return Ok(Verdict::Forward);
        };
        let rule = rule.clone();

        // Match. Switch to buffering. We need the full request
        // (headers + body) before invoking the hook.
        tracing::debug!(
            sni = %self.sni,
            method,
            path = %sanitize(path),
            "interceptor: rule matched, buffering request",
        );

        let mut accumulated = Vec::with_capacity(chunk.len().max(2048));
        accumulated.extend_from_slice(chunk);
        // We may already have a complete request in this single chunk.
        let (body_start, content_length) = match find_subsequence(&accumulated, b"\r\n\r\n") {
            Some(p) => {
                let start = p + 4;
                let cl = parse_content_length(&accumulated[..start]);
                (Some(start), cl)
            }
            None => (None, None),
        };

        self.state = State::Buffering {
            rule,
            accumulated,
            body_start,
            content_length,
        };

        // Maybe the first chunk already had the whole request.
        self.maybe_dispatch().await
    }

    async fn process_buffer_chunk(&mut self, chunk: &[u8]) -> std::io::Result<Verdict> {
        if let State::Buffering { accumulated, .. } = &mut self.state {
            if accumulated.len() + chunk.len() > self.config.max_request_bytes {
                tracing::warn!(
                    sni = %self.sni,
                    accumulated = accumulated.len(),
                    chunk = chunk.len(),
                    max = self.config.max_request_bytes,
                    "interceptor: request exceeded max_request_bytes; disabling",
                );
                // Flush what we held plus this chunk to upstream so the
                // request can complete the slow way.
                let mut to_forward = std::mem::take(accumulated);
                to_forward.extend_from_slice(chunk);
                self.state = State::Disabled;
                return Ok(Verdict::ForwardBuffered(to_forward));
            }
            accumulated.extend_from_slice(chunk);
        }
        self.maybe_dispatch().await
    }

    async fn maybe_dispatch(&mut self) -> std::io::Result<Verdict> {
        let (rule, accumulated, body_start, content_length) = match &mut self.state {
            State::Buffering {
                rule,
                accumulated,
                body_start,
                content_length,
            } => (rule, accumulated, body_start, content_length),
            _ => return Ok(Verdict::Hold),
        };

        // Lazy-parse headers once they arrive.
        if body_start.is_none() {
            match find_subsequence(accumulated, b"\r\n\r\n") {
                Some(p) => {
                    *body_start = Some(p + 4);
                    *content_length = parse_content_length(&accumulated[..p + 4]);
                }
                None => return Ok(Verdict::Hold),
            }
        }

        let bs = body_start.expect("body_start set above");
        let expected = content_length.unwrap_or(0);
        let body_have = accumulated.len().saturating_sub(bs);

        // `dispatch_on_headers` rules fire the hook the moment we've
        // seen the headers — we don't need the body to make a
        // path-based allow/deny decision and we can't always buffer
        // it (git push pack data exceeds max_request_bytes by far).
        // Other rules wait for the full body as before.
        let dispatch_now = rule.dispatch_on_headers || body_have >= expected;
        if !dispatch_now {
            return Ok(Verdict::Hold);
        }

        // Hand the buffered prefix (headers + whatever body we have so
        // far) to the hook. For dispatch_on_headers rules this is
        // usually just the headers; for full-body rules it's the
        // complete request.
        let request = std::mem::take(accumulated);
        let rule_clone = rule.clone();
        let response = run_hook(
            self.config
                .hook
                .as_ref()
                .expect("is_active() guarantees hook is Some"),
            &self.sni,
            &rule_clone,
            &request,
        )
        .await?;

        // Move out of Buffering: subsequent chunks (if any) take the
        // Forwarding path so the network secret-substitution layer
        // still gets to swap placeholders on streaming body bytes.
        self.state = State::Disabled;

        // Empty hook stdout signals "passthrough": flush the prefix
        // we held to upstream verbatim (re-using the existing
        // ForwardBuffered code path) and let subsequent chunks
        // continue. Non-empty stdout is the synthesized response
        // (Intercept), same as before.
        if response.is_empty() {
            Ok(Verdict::ForwardBuffered(request))
        } else {
            Ok(Verdict::Intercept(response))
        }
    }

    fn find_matching_rule(&self, method: &str, path: &str) -> Option<&InterceptRule> {
        // Strip query string from path for prefix match.
        let path_no_query = path.split_once('?').map(|(p, _)| p).unwrap_or(path);
        self.config.rules.iter().find(|r| {
            r.host.eq_ignore_ascii_case(&self.sni)
                && r.method == method
                && path_no_query.starts_with(&r.path_prefix)
        })
    }
}

/// Invoke the hook subprocess. Pass `request` bytes on stdin, return
/// stdout bytes. Hook environment carries `MSB_INTERCEPT_SNI`,
/// `MSB_INTERCEPT_HOST_RULE`, `MSB_INTERCEPT_METHOD`, and
/// `MSB_INTERCEPT_PATH_PREFIX` so the hook doesn't have to re-parse
/// the request line just to know which rule fired.
async fn run_hook(
    hook: &[String],
    sni: &str,
    rule: &InterceptRule,
    request: &[u8],
) -> std::io::Result<Vec<u8>> {
    let (cmd, args) = hook.split_first().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "intercept hook is empty")
    })?;
    let mut child = Command::new(cmd)
        .args(args)
        .env("MSB_INTERCEPT_SNI", sni)
        .env("MSB_INTERCEPT_HOST_RULE", &rule.host)
        .env("MSB_INTERCEPT_METHOD", &rule.method)
        .env("MSB_INTERCEPT_PATH_PREFIX", &rule.path_prefix)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(request).await?;
        stdin.shutdown().await.ok();
    }

    let output = child.wait_with_output().await?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "intercept hook exited with {}",
            output.status
        )));
    }
    Ok(output.stdout)
}

fn parse_request_line(line: &str) -> Option<(&str, &str)> {
    let mut parts = line.split(' ');
    let method = parts.next()?;
    let path = parts.next()?;
    // Sanity-check the HTTP version slot so we don't intercept e.g.
    // a CONNECT preamble accidentally.
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    Some((method, path))
}

fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let s = std::str::from_utf8(headers).ok()?;
    // Skip the request line, then walk header lines until we find one
    // whose name matches case-insensitively. Lines without a `:`
    // (the request line, or the trailing empty line) are ignored.
    for line in s.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            return value.trim().parse().ok();
        }
    }
    None
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

fn sanitize(s: &str) -> String {
    s.chars()
        .take(80)
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(rules: Vec<InterceptRule>) -> InterceptConfig {
        InterceptConfig {
            rules,
            hook: Some(vec!["/bin/cat".to_string()]),
            max_request_bytes: 64 * 1024,
        }
    }

    #[tokio::test]
    async fn forwards_when_no_rules() {
        let mut i = Interceptor::new(InterceptConfig::default(), "example.com");
        let v = i.process_chunk(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        assert!(matches!(v, Verdict::Forward));
    }

    #[tokio::test]
    async fn forwards_when_no_rule_matches() {
        let mut i = Interceptor::new(
            cfg(vec![InterceptRule {
                host: "platform.claude.com".into(),
                method: "POST".into(),
                path_prefix: "/v1/oauth/token".into(),
                dispatch_on_headers: false,
            }]),
            "example.com",
        );
        let v = i
            .process_chunk(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        assert!(matches!(v, Verdict::Forward));
    }

    #[tokio::test]
    async fn intercepts_matching_request_with_no_body() {
        // /bin/cat echoes stdin → response = request, good enough for
        // the state machine test.
        let mut i = Interceptor::new(
            cfg(vec![InterceptRule {
                host: "platform.claude.com".into(),
                method: "POST".into(),
                path_prefix: "/v1/oauth/token".into(),
                dispatch_on_headers: false,
            }]),
            "platform.claude.com",
        );
        let v = i
            .process_chunk(
                b"POST /v1/oauth/token HTTP/1.1\r\nHost: platform.claude.com\r\nContent-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();
        match v {
            Verdict::Intercept(resp) => {
                assert!(String::from_utf8_lossy(&resp).contains("POST /v1/oauth/token"));
            }
            _ => panic!("expected Intercept, got something else"),
        }
    }

    #[tokio::test]
    async fn buffers_split_request_then_intercepts() {
        let mut i = Interceptor::new(
            cfg(vec![InterceptRule {
                host: "platform.claude.com".into(),
                method: "POST".into(),
                path_prefix: "/v1/oauth/token".into(),
                dispatch_on_headers: false,
            }]),
            "platform.claude.com",
        );
        let chunk1 = b"POST /v1/oauth/token HTTP/1.1\r\nHost: platform.claude.com\r\n";
        let chunk2 = b"Content-Length: 10\r\n\r\n";
        let chunk3 = b"0123456789";
        assert!(matches!(i.process_chunk(chunk1).await.unwrap(), Verdict::Hold));
        assert!(matches!(i.process_chunk(chunk2).await.unwrap(), Verdict::Hold));
        let v = i.process_chunk(chunk3).await.unwrap();
        assert!(matches!(v, Verdict::Intercept(_)));
    }
}
