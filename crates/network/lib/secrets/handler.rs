//! Secret substitution handler for the TLS proxy.
//!
//! Scans decrypted plaintext for placeholder strings and replaces them
//! with real secret values, but only when the destination host is allowed.

use std::borrow::Cow;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use percent_encoding::percent_decode;

use super::config::{SecretsConfig, ViolationAction};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Handles secret placeholder substitution in TLS-intercepted plaintext.
///
/// Created from [`SecretsConfig`] and the destination SNI. Determines which
/// secrets are eligible for this connection based on host matching.
pub struct SecretsHandler {
    /// Secrets eligible for substitution on this connection.
    eligible: Vec<EligibleSecret>,
    /// All placeholder strings (for violation detection on disallowed hosts).
    all_placeholders: Vec<String>,
    /// Violation action.
    on_violation: ViolationAction,
    /// Whether any ineligible secrets exist (pre-computed for fast-path skip).
    has_ineligible: bool,
    /// Whether this connection is TLS-intercepted (not bypass).
    tls_intercepted: bool,
    /// Longest placeholder length. Sizes the sliding-window tail.
    max_placeholder_len: usize,
    /// Trailing bytes carried over from the previous `substitute` call so a
    /// placeholder split across TCP writes still trips the violation check.
    /// Capped at `max_placeholder_len - 1` bytes.
    prev_tail: Vec<u8>,
    /// Set to true once we've seen `\r\n\r\n` on this stream. Used by the
    /// body-only fast path to safely distinguish "this chunk is body
    /// continuation" from "this chunk is partial headers (no boundary yet)".
    /// Without this, a chunk that happens to contain a placeholder in
    /// partial headers would be returned verbatim, leaking the placeholder.
    ///
    /// Limitation: with HTTP/1.1 pipelining (multiple requests on one
    /// connection) this flag stays true between requests, so the second
    /// request's partial headers could be skipped. agent-vm clients
    /// (Anthropic SDK, OpenAI SDK, gh, git) don't pipeline; for general
    /// use, a Content-Length-aware reset would be needed.
    headers_terminator_seen: bool,
    /// SNI / destination host this handler was created for. Surfaced
    /// in the violation log so a "secret violation" line names which
    /// destination tripped — without it the warn is anonymous and
    /// can't be matched to a conn during diagnosis.
    sni: String,
}

/// A secret that passed host matching for this connection.
struct EligibleSecret {
    placeholder: String,
    value: String,
    inject_headers: bool,
    inject_basic_auth: bool,
    inject_query_params: bool,
    inject_body: bool,
    require_tls_identity: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl EligibleSecret {
    /// Returns true if any of the header-side injection scopes is enabled
    /// (`headers`, `basic_auth`, or `query_params`).
    fn wants_header_injection(&self) -> bool {
        self.inject_headers || self.inject_basic_auth || self.inject_query_params
    }

    /// Substitute this secret's placeholder in the headers portion, scoped by
    /// the secret's `headers` / `basic_auth` / `query_params` flags.
    fn substitute_in_headers(&self, headers: &str) -> String {
        let mut result = String::with_capacity(headers.len());
        for (i, line) in headers.split("\r\n").enumerate() {
            if i > 0 {
                result.push_str("\r\n");
            }
            match self.substitute_in_header_line(line, i == 0) {
                Some(s) => result.push_str(&s),
                None => result.push_str(line),
            }
        }
        result
    }

    /// Substitute this secret's placeholder in a single header line. Returns
    /// `None` if the line is not in scope for any of the requested injection
    /// modes.
    fn substitute_in_header_line(&self, line: &str, is_request_line: bool) -> Option<String> {
        if self.inject_basic_auth
            && is_authorization_header(line)
            && let Some(replaced) = self.substitute_basic_auth_header(line)
        {
            return Some(replaced);
        }
        if self.inject_headers {
            return Some(line.replace(&self.placeholder, &self.value));
        }
        if is_request_line && self.inject_query_params {
            return Some(line.replace(&self.placeholder, &self.value));
        }
        None
    }

    /// Decode `Basic <base64>` credentials, substitute the placeholder in the
    /// decoded `user:password`, and return the re-encoded line. Returns `None`
    /// if the line isn't `Basic` scheme or the decoded credentials don't
    /// contain the placeholder. Non-Basic schemes (e.g. `Bearer`) are handled
    /// by `inject_headers` instead.
    fn substitute_basic_auth_header(&self, line: &str) -> Option<String> {
        let decoded = decode_basic_credentials(line)?;
        if !decoded.contains(&self.placeholder) {
            return None;
        }
        let (name, _) = line.split_once(':')?;
        let replaced = decoded.replace(&self.placeholder, &self.value);
        Some(format!(
            "{name}: Basic {}",
            BASE64.encode(replaced.as_bytes())
        ))
    }
}

impl SecretsHandler {
    /// Create a handler for a specific connection.
    ///
    /// Filters secrets by host matching against the SNI. Only secrets
    /// whose `allowed_hosts` match `sni` will be substituted.
    /// `tls_intercepted` indicates whether this is a MITM connection
    /// (true) or a bypass/plain connection (false).
    pub fn new(config: &SecretsConfig, sni: &str, tls_intercepted: bool) -> Self {
        let mut eligible = Vec::new();
        let mut all_placeholders = Vec::new();

        for secret in &config.secrets {
            // Placeholders go into the violation-detection set unconditionally
            // so a leak to a disallowed host (or an unresolvable secret) still
            // trips the violation check.
            all_placeholders.push(secret.placeholder.clone());

            let host_allowed = secret.allowed_hosts.is_empty()
                || secret.allowed_hosts.iter().any(|p| p.matches(sni));
            if !host_allowed {
                continue;
            }

            // Resolve the secret value at connection-setup time. For
            // `SecretValue::Static` this is a cheap clone; for
            // `SecretValue::File` this reads from disk. If the file is
            // unreadable, skip the secret rather than substitute an empty
            // string — the request will go upstream with the placeholder
            // intact, which the upstream server can reject and the violation
            // detector will catch if the host turns out to be disallowed.
            let value = match secret.value.resolve() {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(
                        env_var = %secret.env_var,
                        error = %e,
                        "failed to resolve secret value; skipping substitution for this connection"
                    );
                    continue;
                }
            };

            eligible.push(EligibleSecret {
                placeholder: secret.placeholder.clone(),
                value,
                inject_headers: secret.injection.headers,
                inject_basic_auth: secret.injection.basic_auth,
                inject_query_params: secret.injection.query_params,
                inject_body: secret.injection.body,
                require_tls_identity: secret.require_tls_identity,
            });
        }

        let has_ineligible = eligible.len() < all_placeholders.len();
        let max_placeholder_len = all_placeholders.iter().map(String::len).max().unwrap_or(0);

        Self {
            eligible,
            all_placeholders,
            on_violation: config.on_violation.clone(),
            has_ineligible,
            tls_intercepted,
            max_placeholder_len,
            prev_tail: Vec::new(),
            headers_terminator_seen: false,
            sni: sni.to_string(),
        }
    }

    /// Substitute secrets in plaintext data (guest → server direction).
    ///
    /// Splits the HTTP message on `\r\n\r\n` to scope substitution:
    /// - `headers`: substitutes in the header portion (before boundary)
    /// - `basic_auth`: substitutes in Authorization headers specifically
    /// - `query_params`: substitutes in the request line (first line, query portion)
    /// - `body`: substitutes in the body portion (after boundary)
    ///
    /// Returns `None` if a violation is detected (placeholder going to a
    /// disallowed host) or `BlockAndTerminate` is triggered.
    pub fn substitute<'a>(&mut self, data: &'a [u8]) -> Option<Cow<'a, [u8]>> {
        // Split raw bytes at the header boundary BEFORE converting to owned strings.
        // This avoids position shifts from from_utf8_lossy replacement chars.
        let boundary = find_header_boundary(data);
        let (header_bytes, body_bytes) = match boundary {
            Some(pos) => (&data[..pos], &data[pos..]),
            None => (data, &[] as &[u8]),
        };
        // Header strings are always ASCII per HTTP spec; lossy conversion
        // is a no-op for valid HTTP and a benign byte-replacement for
        // junk we wouldn't have substituted into anyway.
        let mut header_str = String::from_utf8_lossy(header_bytes).into_owned();

        // Fast path: skip violation check when no ineligible secrets exist.
        if self.has_ineligible {
            // Scan ONLY the header portion of this chunk. Body bytes are
            // user content (chat prompts, code, quoted logs) and may
            // legitimately contain literal `MSB_PLACEHOLDER_*` strings;
            // blocking on those mid-upload surfaces to the guest as
            // ECONNRESET and breaks long sessions. Body-continuation
            // chunks (boundary already seen on this stream, none in this
            // chunk) pass an empty slice and skip the scan entirely.
            let header_scan: &[u8] = if boundary.is_some() {
                header_bytes
            } else if self.headers_terminator_seen {
                &[]
            } else {
                // No boundary yet on this stream — the whole chunk is
                // still (potentially partial) headers.
                data
            };
            // Resolve the violation while only immutably borrowing self,
            // then drop that borrow before any mutating call (update_tail).
            let violation = self
                .first_violation(header_scan, &header_str)
                .map(|(p, k)| (p.to_string(), k));
            // Update the tail-sliding window with the same header
            // scope. Once we've crossed into body, header_scan is
            // empty so prev_tail naturally drains — body bytes never
            // stitch into a future scan.
            self.update_tail(header_scan);
            if let Some((placeholder, match_kind)) = violation {
                // Capture which placeholder and via which encoding so
                // the warn is actually useful — distinguishes "GH
                // token leaking to Anthropic" from "OpenAI placeholder
                // string quoted in the body". Truncate to a short
                // prefix to avoid loud lines even though placeholders
                // aren't themselves secret.
                let placeholder_label = if placeholder.len() > 48 {
                    format!("{}…(len {})", &placeholder[..48], placeholder.len())
                } else {
                    placeholder.clone()
                };
                match self.on_violation {
                    ViolationAction::Block => return None,
                    ViolationAction::BlockAndLog => {
                        tracing::warn!(
                            sni = %self.sni,
                            placeholder = %placeholder_label,
                            match_kind,
                            "secret violation: placeholder detected for disallowed host"
                        );
                        return None;
                    }
                    ViolationAction::BlockAndTerminate => {
                        tracing::error!(
                            sni = %self.sni,
                            placeholder = %placeholder_label,
                            match_kind,
                            "secret violation: placeholder detected for disallowed host — terminating"
                        );
                        return None;
                    }
                }
            }
        }

        if self.eligible.is_empty() {
            // No substitution needed. Return borrowed slice (zero-copy).
            return Some(Cow::Borrowed(data));
        }

        // Second fast path: if no eligible placeholder actually appears
        // anywhere in the chunk, substitution is a no-op anyway. Return
        // the bytes unchanged. This protects post-WebSocket-upgrade
        // binary frames, server-side chunked-body continuations, and
        // any other non-HTTP plaintext from the lossy UTF-8 round trip
        // below that would otherwise mangle non-UTF-8 bytes.
        //
        // Doesn't apply when any eligible secret enables `inject_basic_auth`,
        // because Basic credentials are base64-encoded — the placeholder
        // only appears after decoding, not in the raw bytes.
        let any_basic_auth = self.eligible.iter().any(|s| {
            !(s.require_tls_identity && !self.tls_intercepted) && s.inject_basic_auth
        });
        if !any_basic_auth {
            let any_eligible_placeholder_present = self.eligible.iter().any(|s| {
                !(s.require_tls_identity && !self.tls_intercepted)
                    && byte_contains(data, s.placeholder.as_bytes())
            });
            if !any_eligible_placeholder_present {
                return Some(Cow::Borrowed(data));
            }
        }

        // Track that we've seen the header terminator on this stream.
        // The body-only fast path below depends on this to distinguish
        // "this chunk is body continuation" from "this chunk is partial
        // headers, full request not yet received".
        if boundary.is_some() {
            self.headers_terminator_seen = true;
        }

        // Third fast path: this chunk is a pure body continuation. We
        // can prove that by (a) no `\r\n\r\n` boundary in this chunk
        // AND (b) we've already seen one earlier on this stream — so
        // this MUST be body bytes, not partial headers of the first
        // request.
        //
        // Combined with (c) no eligible secret wanting `inject_body`,
        // we can skip the slow path entirely. The slow path's
        // `from_utf8_lossy` on the whole chunk would otherwise mangle
        // bytes at any chunk boundary cut in the middle of a
        // multi-byte UTF-8 character (orphans → U+FFFD = 3 bytes
        // each), silently growing the chunk without updating
        // Content-Length and causing the receiver to truncate real
        // data at the original length mark.
        //
        // The boundary.is_none() alone is not sufficient: if the very
        // first chunk of a request hasn't reached `\r\n\r\n` yet
        // (large headers split across reads), a placeholder sitting
        // in partial headers would be skipped. The
        // `headers_terminator_seen` gate prevents that.
        let body_substitution_wanted = self.eligible.iter().any(|s| {
            !(s.require_tls_identity && !self.tls_intercepted) && s.inject_body
        });
        if self.headers_terminator_seen && boundary.is_none() && !body_substitution_wanted {
            return Some(Cow::Borrowed(data));
        }

        let body_substitution_active = body_substitution_wanted;

        let mut new_body: Option<String> = None;
        if body_substitution_active && boundary.is_some() {
            let mut body_str = String::from_utf8_lossy(body_bytes).into_owned();
            for secret in &self.eligible {
                if secret.require_tls_identity && !self.tls_intercepted {
                    continue;
                }
                if secret.inject_body && body_str.contains(&secret.placeholder) {
                    body_str = body_str.replace(&secret.placeholder, &secret.value);
                }
            }
            new_body = Some(body_str);
        }

        for secret in &self.eligible {
            if secret.require_tls_identity && !self.tls_intercepted {
                continue;
            }
            if secret.wants_header_injection() {
                header_str = secret.substitute_in_headers(&header_str);
            }
        }

        // If body substitution changed the length, update Content-Length.
        let body_len_for_header = new_body.as_ref().map(|b| b.len()).unwrap_or(body_bytes.len());
        if boundary.is_some() && body_len_for_header != body_bytes.len() {
            header_str = update_content_length(&header_str, body_len_for_header);
        }

        // Reassemble. Pass body bytes through verbatim unless we
        // actually rewrote them.
        let header_bytes = header_str.into_bytes();
        let mut output = Vec::with_capacity(header_bytes.len() + body_len_for_header);
        output.extend_from_slice(&header_bytes);
        match new_body {
            Some(b) => output.extend_from_slice(b.as_bytes()),
            None => output.extend_from_slice(body_bytes),
        }
        Some(Cow::Owned(output))
    }

    /// Returns true if no secrets are configured.
    pub fn is_empty(&self) -> bool {
        self.all_placeholders.is_empty()
    }

    /// Returns true if a violation should terminate the sandbox.
    pub fn terminates_on_violation(&self) -> bool {
        matches!(self.on_violation, ViolationAction::BlockAndTerminate)
    }

    /// Check if any placeholder appears in this chunk's HEADER region for
    /// a host that isn't allowed. Body bytes are user-controlled content
    /// (chat prompts, code, quoted log files) and routinely contain
    /// placeholder *strings* without meaning a real credential leak —
    /// blocking on those produces a connection RST mid-upload that the
    /// guest agent reports as ECONNRESET, breaking long sessions whose
    /// context happens to mention `MSB_PLACEHOLDER_*`.
    ///
    /// The real leak vectors are credential-bearing header positions
    /// (`Authorization`, `X-*-Key`, URL query params on the request
    /// line) — all inside the header region. Restricting the scan there
    /// closes the false-positive class without weakening the actual
    /// defense.
    ///
    /// `header_bytes` is the slice up to and including `\r\n\r\n` on
    /// chunks where the boundary fell in this chunk, or `data` itself
    /// on chunks that haven't reached the boundary yet (i.e. still
    /// pre-body). Pure body-continuation chunks must pass an empty
    /// slice so this scan does nothing.
    ///
    /// Returns `Some((placeholder, match_kind))` for the first hit so
    /// the caller can log which secret tripped and via which encoding.
    fn first_violation(
        &self,
        header_bytes: &[u8],
        headers: &str,
    ) -> Option<(&str, &'static str)> {
        // Fast path: if all placeholders have matching eligible entries, no
        // violation is possible (every secret is allowed for this host).
        if self.eligible.len() == self.all_placeholders.len() {
            return None;
        }
        // Pure body-continuation chunks pass empty header_bytes; nothing
        // to scan. Also skips the tail-stitching alloc on the hot path.
        if header_bytes.is_empty() && self.prev_tail.is_empty() {
            return None;
        }

        // Stitch in prev_tail so a placeholder split across writes is
        // still detected. We only carry tail for headers, since headers
        // are now the only thing we scan — that bounds the per-chunk
        // overhead to a few hundred bytes worst case.
        let scan_buf: Cow<[u8]> = if self.prev_tail.is_empty() {
            Cow::Borrowed(header_bytes)
        } else {
            let mut stitched =
                Vec::with_capacity(self.prev_tail.len() + header_bytes.len());
            stitched.extend_from_slice(&self.prev_tail);
            stitched.extend_from_slice(header_bytes);
            Cow::Owned(stitched)
        };
        let scan = scan_buf.as_ref();

        for placeholder in &self.all_placeholders {
            if self.eligible.iter().any(|s| s.placeholder == *placeholder) {
                continue;
            }
            let needle = placeholder.as_bytes();
            if contains_bytes(scan, needle) {
                return Some((placeholder.as_str(), "raw"));
            }
            if url_decoded_contains(scan, needle) {
                return Some((placeholder.as_str(), "url_decoded"));
            }
            if json_escaped_contains(scan, needle) {
                return Some((placeholder.as_str(), "json_escaped"));
            }
            if basic_auth_decoded_contains(headers, placeholder) {
                return Some((placeholder.as_str(), "basic_auth_decoded"));
            }
        }

        None
    }

    /// Update the sliding-window tail with the trailing bytes of `data`, so
    /// the next `substitute` call can detect placeholders split across the
    /// boundary.
    fn update_tail(&mut self, data: &[u8]) {
        let tail_size = self.max_placeholder_len.saturating_sub(1);
        if tail_size == 0 {
            return;
        }
        if data.len() >= tail_size {
            self.prev_tail.clear();
            self.prev_tail
                .extend_from_slice(&data[data.len() - tail_size..]);
            return;
        }
        self.prev_tail.extend_from_slice(data);
        let overflow = self.prev_tail.len().saturating_sub(tail_size);
        if overflow > 0 {
            self.prev_tail.drain(..overflow);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Returns true if `line` starts with the `Authorization:` header name
/// (case-insensitive).
fn is_authorization_header(line: &str) -> bool {
    line.as_bytes()
        .get(..14)
        .is_some_and(|b| b.eq_ignore_ascii_case(b"authorization:"))
}

/// Decode the credentials of a `Basic` `Authorization` header line. Returns
/// `None` if the line is not `Basic`-scheme or the payload is not valid
/// base64 / UTF-8.
fn decode_basic_credentials(line: &str) -> Option<String> {
    let (_, raw_value) = line.split_once(':')?;
    let (scheme, encoded) = split_auth_scheme(raw_value.trim_start())?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let bytes = BASE64.decode(encoded.trim()).ok()?;
    String::from_utf8(bytes).ok()
}

/// Split an `Authorization` header value into `(scheme, rest)` at the first
/// whitespace. Returns `None` if no whitespace separator is found.
fn split_auth_scheme(header_value: &str) -> Option<(&str, &str)> {
    let split_at = header_value.find(char::is_whitespace)?;
    let (scheme, rest) = header_value.split_at(split_at);
    Some((scheme, rest.trim_start()))
}

/// Returns true if any `Authorization: Basic` line in `headers` decodes to
/// credentials containing `placeholder`.
fn basic_auth_decoded_contains(headers: &str, placeholder: &str) -> bool {
    headers
        .split("\r\n")
        .filter(|line| is_authorization_header(line))
        .filter_map(decode_basic_credentials)
        .any(|decoded| decoded.contains(placeholder))
}

/// Byte-slice substring check.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Returns true if `haystack`, after URL percent-decoding, contains `needle`.
fn url_decoded_contains(haystack: &[u8], needle: &[u8]) -> bool {
    let decoded: Vec<u8> = percent_decode(haystack).collect();
    contains_bytes(&decoded, needle)
}

/// Returns true if `haystack`, after JSON `\uXXXX` decoding, contains `needle`.
/// Only `\uXXXX` escapes are expanded (sufficient to detect ASCII placeholders
/// hidden via unicode escapes); other JSON escapes pass through.
fn json_escaped_contains(haystack: &[u8], needle: &[u8]) -> bool {
    let mut decoded = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i] == b'\\'
            && i + 5 < haystack.len()
            && haystack[i + 1] == b'u'
            && let (Some(a), Some(b), Some(c), Some(d)) = (
                hex_digit(haystack[i + 2]),
                hex_digit(haystack[i + 3]),
                hex_digit(haystack[i + 4]),
                hex_digit(haystack[i + 5]),
            )
        {
            let cp = ((a as u32) << 12) | ((b as u32) << 8) | ((c as u32) << 4) | (d as u32);
            if let Some(ch) = char::from_u32(cp) {
                let mut buf = [0u8; 4];
                decoded.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
            i += 6;
            continue;
        }
        decoded.push(haystack[i]);
        i += 1;
    }
    contains_bytes(&decoded, needle)
}

fn hex_digit(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

/// Update the Content-Length header value in `headers` to `new_len`.
///
/// Performs a case-insensitive line scan. If no Content-Length header exists
/// (e.g. chunked transfer encoding), the headers are returned unchanged.
fn update_content_length(headers: &str, new_len: usize) -> String {
    let mut result = String::with_capacity(headers.len());
    for (i, line) in headers.split("\r\n").enumerate() {
        if i > 0 {
            result.push_str("\r\n");
        }
        if line
            .as_bytes()
            .get(..15)
            .is_some_and(|b| b.eq_ignore_ascii_case(b"content-length:"))
        {
            result.push_str(&format!("Content-Length: {new_len}"));
        } else {
            result.push_str(line);
        }
    }
    result
}

/// Find the `\r\n\r\n` boundary between HTTP headers and body.
fn find_header_boundary(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

/// Substring search on raw bytes. Used for placeholder presence
/// checks where allocating a String would defeat the purpose.
fn byte_contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::config::*;

    fn make_config(secrets: Vec<SecretEntry>) -> SecretsConfig {
        SecretsConfig {
            secrets,
            on_violation: ViolationAction::Block,
        }
    }

    fn make_secret(placeholder: &str, value: &str, host: &str) -> SecretEntry {
        SecretEntry {
            env_var: "TEST_KEY".into(),
            value: value.into(),
            placeholder: placeholder.into(),
            allowed_hosts: vec![HostPattern::Exact(host.into())],
            injection: SecretInjection::default(),
            require_tls_identity: true,
        }
    }

    fn basic_auth_only() -> SecretInjection {
        SecretInjection {
            headers: false,
            basic_auth: true,
            query_params: false,
            body: false,
        }
    }

    #[test]
    fn substitute_in_headers() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let input = b"GET / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\n\r\n";
        let output = handler.substitute(input).unwrap();
        assert_eq!(
            String::from_utf8(output.into_owned()).unwrap(),
            "GET / HTTP/1.1\r\nAuthorization: Bearer real-secret\r\n\r\n"
        );
    }

    /// Regression: a body-only chunk (no `\r\n\r\n` header boundary)
    /// that happens to mention the placeholder string in its data
    /// must NOT be UTF-8 round-tripped. The slow path used to feed
    /// the whole chunk through `from_utf8_lossy`, and any chunk-
    /// boundary cut in the middle of a multi-byte UTF-8 char turned
    /// the orphan bytes into U+FFFD (3 bytes each) — growing the
    /// body silently with no Content-Length adjustment, causing the
    /// receiver to truncate real data at the original Content-Length
    /// mark. Triggered when an LLM body included a literal
    /// placeholder string (e.g. agent-vm self-discussion).
    #[test]
    fn body_only_chunk_with_placeholder_substring_is_not_round_tripped() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        // First, send a chunk that establishes "we've seen the header
        // terminator on this stream" so subsequent body-only chunks
        // get the fast path.
        let _ = handler.substitute(b"POST /v1/x HTTP/1.1\r\nContent-Length: 999\r\n\r\n");

        // Body bytes: a JSON-like payload that legitimately mentions
        // the placeholder name as content, AND contains a multi-byte
        // UTF-8 char (€ = E2 82 AC). No `\r\n\r\n` boundary in this
        // chunk (it's a continuation of a previous header chunk).
        let mut input = b"{\"discussion\":\"the placeholder is $KEY in this codebase\",\"price\":\"".to_vec();
        input.extend_from_slice("€100".as_bytes());
        input.extend_from_slice(b"\"}");
        let original = input.clone();

        let output = handler.substitute(&input).unwrap();
        // Byte-for-byte identical: the substitution layer must NOT
        // touch the body when no eligible secret wants body
        // substitution.
        assert_eq!(&*output, original.as_slice());
    }

    /// Same idea but with the chunk boundary deliberately splitting
    /// a multi-byte UTF-8 character — the failure mode the bug
    /// triggered in production (chunked 16 KiB reads through 100 KB+
    /// JSON bodies).
    #[test]
    fn body_only_chunk_split_mid_utf8_is_not_round_tripped() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);
        let _ = handler.substitute(b"POST /v1/x HTTP/1.1\r\nContent-Length: 9999\r\n\r\n");

        // "€" = E2 82 AC. Split between E2 and the rest.
        let mut input = b"abc $KEY def \xE2".to_vec(); // ends with the high byte of €
        let original = input.clone();
        let output = handler.substitute(&input).unwrap();
        assert_eq!(&*output, original.as_slice(), "orphan continuation must survive verbatim");

        // The continuation chunk has the orphan low bytes.
        input = b"\x82\xAC100".to_vec();
        let original2 = input.clone();
        let output2 = handler.substitute(&input).unwrap();
        assert_eq!(&*output2, original2.as_slice());
    }

    /// Regression: a chunk with NO `\r\n\r\n` boundary at the very
    /// start of a stream (no prior chunk seen → headers_terminator_seen
    /// is false) must NOT take the body-only fast path, because the
    /// chunk could be partial headers carrying a placeholder. The
    /// previous fix gated only on `boundary.is_none()` and would
    /// silently leak a placeholder sitting in a header line that
    /// happened to fall in the first chunk before the headers
    /// terminator was reached.
    #[test]
    fn partial_headers_chunk_with_placeholder_still_substitutes() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        // First chunk of a request whose headers haven't reached
        // \r\n\r\n yet. Contains the placeholder in an Authorization
        // header that NEEDS to be substituted.
        let input = b"POST /v1/x HTTP/1.1\r\nAuthorization: Bearer $KEY\r\nUser-Agent: very-long-padding-".to_vec();
        let output = handler.substitute(&input).unwrap();
        let s = String::from_utf8(output.into_owned()).unwrap();
        assert!(
            s.contains("Authorization: Bearer real-secret"),
            "placeholder MUST be substituted in partial-headers chunk; got: {s}"
        );
        assert!(!s.contains("$KEY"), "placeholder must not survive: {s}");
    }

    #[test]
    fn no_substitute_for_wrong_host() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "evil.com", true);

        let input = b"GET / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\n\r\n";
        assert!(handler.substitute(input).is_none());
    }

    #[test]
    fn body_injection_disabled_by_default() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let input = b"POST / HTTP/1.1\r\n\r\n{\"key\": \"$KEY\"}";
        let output = handler.substitute(input).unwrap();
        assert!(
            String::from_utf8(output.into_owned())
                .unwrap()
                .contains("$KEY")
        );
    }

    #[test]
    fn body_injection_when_enabled() {
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.injection.body = true;
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let input = b"POST / HTTP/1.1\r\n\r\n{\"key\": \"$KEY\"}";
        let output = handler.substitute(input).unwrap();
        assert_eq!(
            String::from_utf8(output.into_owned()).unwrap(),
            "POST / HTTP/1.1\r\n\r\n{\"key\": \"real-secret\"}"
        );
    }

    #[test]
    fn body_injection_updates_content_length() {
        let mut secret = make_secret("$KEY", "a]longer]secret]value", "api.openai.com");
        secret.injection.body = true;
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let body = "{\"key\": \"$KEY\"}";
        let input = format!(
            "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let output = handler.substitute(input.as_bytes()).unwrap();
        let result = String::from_utf8(output.into_owned()).unwrap();

        let expected_body = "{\"key\": \"a]longer]secret]value\"}";
        assert!(result.contains(expected_body));
        assert!(result.contains(&format!("Content-Length: {}", expected_body.len())));
    }

    #[test]
    fn body_injection_no_content_length_header() {
        let mut secret = make_secret("$KEY", "longer-secret", "api.openai.com");
        secret.injection.body = true;
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        // No Content-Length header (e.g. chunked).
        let input = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n{\"key\": \"$KEY\"}";
        let output = handler.substitute(input).unwrap();
        let result = String::from_utf8(output.into_owned()).unwrap();
        assert!(result.contains("longer-secret"));
        assert!(!result.contains("Content-Length"));
    }

    #[test]
    fn header_only_substitution_preserves_content_length() {
        let config = make_config(vec![make_secret("$KEY", "longer-value", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let input =
            b"GET / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\nContent-Length: 5\r\n\r\nhello";
        let output = handler.substitute(input).unwrap();
        let result = String::from_utf8(output.into_owned()).unwrap();
        // Body unchanged, Content-Length should stay 5.
        assert!(result.contains("Content-Length: 5"));
        assert!(result.ends_with("hello"));
    }

    #[test]
    fn no_secrets_passthrough() {
        let config = make_config(vec![]);
        let mut handler = SecretsHandler::new(&config, "anything.com", true);

        let input = b"GET / HTTP/1.1\r\n\r\n";
        let output = handler.substitute(input).unwrap();
        assert_eq!(&*output, input);
    }

    #[test]
    fn require_tls_identity_blocks_on_non_intercepted() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        // tls_intercepted = false — secret requires TLS identity
        let mut handler = SecretsHandler::new(&config, "api.openai.com", false);

        let input = b"GET / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\n\r\n";
        let output = handler.substitute(input).unwrap();
        // Placeholder should NOT be substituted.
        assert!(
            String::from_utf8(output.into_owned())
                .unwrap()
                .contains("$KEY")
        );
    }

    #[test]
    fn basic_auth_only_does_not_substitute_other_schemes() {
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.injection = basic_auth_only();
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        // basic_auth only handles Basic credentials; Bearer needs inject_headers.
        let input = b"GET / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\nX-Custom: $KEY\r\n\r\n";
        let output = handler.substitute(input).unwrap();
        let result = String::from_utf8(output.into_owned()).unwrap();
        assert!(result.contains("Authorization: Bearer $KEY"));
        assert!(result.contains("X-Custom: $KEY"));
    }

    #[test]
    fn basic_auth_decodes_substitutes_and_reencodes_credentials() {
        let mut user = make_secret("$MSB_USER", "alice", "api.openai.com");
        user.env_var = "USER".into();
        user.injection = basic_auth_only();
        let mut password = make_secret("$MSB_PASSWORD", "s3cr3t", "api.openai.com");
        password.env_var = "PASSWORD".into();
        password.injection = basic_auth_only();
        let config = make_config(vec![user, password]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let encoded = BASE64.encode(b"$MSB_USER:$MSB_PASSWORD");
        let input = format!("GET / HTTP/1.1\r\nAuthorization: Basic {encoded}\r\n\r\n");
        let output = handler.substitute(input.as_bytes()).unwrap();
        let result = String::from_utf8(output.into_owned()).unwrap();

        assert!(result.contains(&format!(
            "Authorization: Basic {}",
            BASE64.encode(b"alice:s3cr3t")
        )));
        assert!(!result.contains("$MSB_USER"));
        assert!(!result.contains("$MSB_PASSWORD"));
    }

    #[test]
    fn basic_auth_encoded_placeholder_is_blocked_for_wrong_host() {
        let mut secret = make_secret("$MSB_PASSWORD", "s3cr3t", "api.openai.com");
        secret.injection = basic_auth_only();
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new(&config, "evil.com", true);

        let encoded = BASE64.encode(b"user:$MSB_PASSWORD");
        let input = format!("GET / HTTP/1.1\r\nAuthorization: Basic {encoded}\r\n\r\n");

        assert!(handler.substitute(input.as_bytes()).is_none());
    }

    #[test]
    fn basic_auth_encoded_placeholder_is_not_replaced_when_scope_disabled() {
        let mut secret = make_secret("$MSB_PASSWORD", "s3cr3t", "api.openai.com");
        secret.injection = SecretInjection {
            headers: false,
            basic_auth: false,
            query_params: false,
            body: false,
        };
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let encoded = BASE64.encode(b"user:$MSB_PASSWORD");
        let input = format!("GET / HTTP/1.1\r\nAuthorization: Basic {encoded}\r\n\r\n");
        let output = handler.substitute(input.as_bytes()).unwrap();

        assert_eq!(String::from_utf8(output.into_owned()).unwrap(), input);
    }

    #[test]
    fn query_params_substitution() {
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.injection = SecretInjection {
            headers: false,
            basic_auth: false,
            query_params: true,
            body: false,
        };
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let input = b"GET /api?key=$KEY HTTP/1.1\r\nHost: api.openai.com\r\n\r\n";
        let output = handler.substitute(input).unwrap();
        let result = String::from_utf8(output.into_owned()).unwrap();
        // Request line should be substituted.
        assert!(result.contains("GET /api?key=real-secret HTTP/1.1"));
        // Other headers should NOT be substituted.
    }

    #[test]
    fn url_encoded_placeholder_in_query_blocks_for_wrong_host() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "evil.com", true);

        // `%24KEY` is the URL-encoded form of `$KEY`.
        let input = b"GET /api?token=%24KEY HTTP/1.1\r\nHost: evil.com\r\n\r\n";
        assert!(handler.substitute(input).is_none());
    }

    /// The violation scan deliberately does NOT look inside the body —
    /// body bytes are user-controlled content (chat prompts, code,
    /// quoted log files) and routinely contain literal `MSB_PLACEHOLDER_*`
    /// strings without meaning a real credential leak. Blocking on
    /// those mid-upload surfaces to the guest as ECONNRESET and breaks
    /// long sessions. The real leak vectors are credential-bearing
    /// header positions (Authorization, X-*-Key, URL query params on
    /// the request line) — all inside the header region, which IS
    /// still scanned (see `url_encoded_placeholder_in_query_blocks_for_wrong_host`
    /// and `basic_auth_encoded_placeholder_is_blocked_for_wrong_host`).
    #[test]
    fn url_encoded_placeholder_in_body_is_not_blocked() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "evil.com", true);

        let input = b"POST / HTTP/1.1\r\nContent-Length: 13\r\n\r\nkey=%24KEY&x=1";
        assert!(handler.substitute(input).is_some());
    }

    #[test]
    fn json_escaped_placeholder_in_body_is_not_blocked() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "evil.com", true);

        // `$KEY` is the JSON unicode-escape form of `$KEY`.
        let input =
            b"POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"k\":\"\\u0024KEY\"}";
        assert!(handler.substitute(input).is_some());
    }

    /// Regression test for the original failure mode: an investigation
    /// session whose Anthropic POST body contains the literal text of
    /// *another* secret's placeholder (e.g. an OpenAI placeholder name
    /// quoted from a jsonl log file) used to trip the body scan and
    /// drop the conn mid-upload — the guest reported it as ECONNRESET
    /// and the session retried into a 10-attempt burst. Header-only
    /// scope means body content like this passes through untouched.
    #[test]
    fn ineligible_placeholder_in_body_to_allowed_host_passes_through() {
        let config = make_config(vec![
            make_secret("ANTHROPIC_KEY", "real-anthropic-secret", "api.anthropic.com"),
            make_secret("OPENAI_KEY", "real-openai-secret", "api.openai.com"),
        ]);
        let mut handler = SecretsHandler::new(&config, "api.anthropic.com", true);

        // Headers go to the Anthropic API; body quotes the OpenAI
        // placeholder (e.g. analyzing another session's jsonl).
        let input =
            b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: 56\r\n\r\n\
              {\"messages\":[{\"role\":\"user\",\"content\":\"OPENAI_KEY\"}]}";
        let out = handler.substitute(input).expect("body content is not a leak");
        assert!(out.windows(b"OPENAI_KEY".len()).any(|w| w == b"OPENAI_KEY"));
    }

    #[test]
    fn placeholder_split_across_writes_blocks_for_wrong_host() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "evil.com", true);

        // Send the placeholder bytes across two separate substitute() calls.
        let first = b"GET / HTTP/1.1\r\nX-Token: $K";
        let second = b"EY\r\nHost: evil.com\r\n\r\n";

        // The first chunk doesn't contain the full placeholder, so it forwards.
        assert!(handler.substitute(first).is_some());
        // The second chunk completes the placeholder when stitched with the tail.
        assert!(handler.substitute(second).is_none());
    }

    #[test]
    fn url_decoded_contains_basic() {
        assert!(url_decoded_contains(b"foo%24KEYbar", b"$KEY"));
        assert!(!url_decoded_contains(b"fooKEYbar", b"$KEY"));
        // Invalid escapes pass through unchanged.
        assert!(url_decoded_contains(b"%2", b"%2"));
    }

    #[test]
    fn json_escaped_contains_basic() {
        assert!(json_escaped_contains(b"\"\\u0024KEY\"", b"$KEY"));
        assert!(json_escaped_contains(
            b"\\u0024\\u004B\\u0045\\u0059",
            b"$KEY"
        ));
        assert!(!json_escaped_contains(b"KEY", b"$KEY"));
    }
}
