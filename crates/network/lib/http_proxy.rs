//! Host HTTP forward-proxy (`CONNECT`) support for guest egress.
//!
//! When the host runs behind an HTTP proxy, the agent inside the guest can't
//! reach the internet just by opening sockets — the host network only permits
//! outbound traffic through the proxy. The host-side reqwest clients (image
//! pull, registry probes, the intercept hook) already honour the proxy because
//! reqwest auto-detects `HTTP(S)_PROXY` from the environment. Guest egress did
//! not: the smoltcp proxy tasks ([`crate::proxy`], [`crate::tls::proxy`])
//! re-originate upstream connections with a plain [`TcpStream::connect`], which
//! ignores any proxy.
//!
//! This module closes that gap. [`ProxyConfig::from_env`] parses the standard
//! proxy environment variables once at network boot; the parsed config is
//! stored on [`crate::shared::SharedState`] and consulted by the proxy tasks.
//! [`connect_upstream`] is the single entry point they call instead of
//! `TcpStream::connect`: it opens an HTTP `CONNECT` tunnel through the proxy
//! when one applies to the destination, and falls back to a direct connection
//! otherwise.
//!
//! Crucially this keeps the TLS-intercept MITM and the egress policy intact:
//! the proxy tasks still terminate the guest's TLS, evaluate policy against the
//! real destination/SNI, and only *then* re-originate — now through the proxy
//! tunnel rather than directly. The proxy never sees plaintext; it only carries
//! the bytes the host would otherwise have sent straight to the origin.
//!
//! Recognised variables (lowercase preferred, uppercase as fallback — the
//! curl/wget convention):
//! - `https_proxy` / `HTTPS_PROXY` — proxy for TLS destinations.
//! - `http_proxy` / `HTTP_PROXY` — proxy for plain destinations.
//! - `all_proxy` / `ALL_PROXY` — fallback used for either when the specific
//!   one is unset.
//! - `no_proxy` / `NO_PROXY` — comma/space separated exclusion list
//!   (`*`, domain suffixes, exact hosts, IPs, CIDRs).
//!
//! Limitations: only `http://` (and scheme-less `host:port`) proxy URLs are
//! supported — a `CONNECT` tunnel over an HTTPS connection to the proxy itself
//! (`https://proxy`) is not yet implemented and such an endpoint is ignored
//! (with a one-time warning). SOCKS proxies are out of scope.
//!
//! Scope: when a proxy is configured, *all* non-host-local guest egress is
//! tunnelled through it — including non-HTTP TCP (SSH, git) and private/LAN
//! destinations — to fit the proxy-only-network model. Use `NO_PROXY` (host
//! suffixes, IPs, CIDRs, or `*`) to carve out destinations that must connect
//! directly. A `NO_PROXY` host/suffix entry only matches when the destination
//! hostname is known — that's the SNI on TLS flows, but a plain non-TLS TCP
//! connection has no name at this layer, so exclude those by IP/CIDR. A
//! configured-but-unreachable proxy fails closed (the connection errors)
//! rather than silently falling back to a direct dial.

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Once;

use base64::Engine as _;
use ipnetwork::IpNetwork;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Upper bound on the `CONNECT` response header size we'll buffer. A real
/// proxy response is well under 1 KiB; this guards against a misbehaving
/// peer streaming forever.
const MAX_CONNECT_RESPONSE: usize = 16 * 1024;

/// Wall-clock bound on the proxy TCP connect + `CONNECT` exchange. A direct
/// connect was bounded by the OS connect timeout; through a forward proxy the
/// TCP connect succeeds fast but the proxy could stall before replying, so we
/// cap the whole exchange to avoid wedging the guest connection indefinitely.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Parsed host proxy environment, resolved per scheme.
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    /// Endpoint for TLS destinations (`https_proxy`, else `all_proxy`).
    https: Option<ProxyEndpoint>,
    /// Endpoint for plain destinations (`http_proxy`, else `all_proxy`).
    http: Option<ProxyEndpoint>,
    /// Destinations that must bypass the proxy.
    no_proxy: NoProxy,
}

/// A single HTTP proxy endpoint to dial and `CONNECT` through.
#[derive(Clone, Debug)]
pub(crate) struct ProxyEndpoint {
    /// Proxy host (hostname or IP literal) — dialed via tokio, so a hostname
    /// is resolved by the host resolver.
    host: String,
    /// Proxy port.
    port: u16,
    /// Precomputed `Proxy-Authorization: Basic …` value when the URL carried
    /// `user:pass@` userinfo.
    auth_header: Option<String>,
    /// Credential-free string for logs (`http://host:port`).
    display: String,
}

/// Parsed `no_proxy` exclusion list.
#[derive(Clone, Debug, Default)]
struct NoProxy {
    /// `*` — bypass everything.
    wildcard: bool,
    /// Lowercased host/suffix entries (leading/trailing dots stripped).
    names: Vec<String>,
    /// IP and CIDR entries.
    nets: Vec<IpNetwork>,
    /// Original string, for the startup banner.
    raw: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ProxyConfig {
    /// Read the host proxy environment. Returns `None` when neither an HTTP
    /// nor an HTTPS proxy is configured (the common no-proxy case), so the
    /// caller can skip all proxy handling entirely.
    pub fn from_env() -> Option<ProxyConfig> {
        Self::from_vars(
            env_var("https_proxy").or_else(|| env_var("HTTPS_PROXY")),
            env_var("http_proxy").or_else(|| env_var("HTTP_PROXY")),
            env_var("all_proxy").or_else(|| env_var("ALL_PROXY")),
            env_var("no_proxy").or_else(|| env_var("NO_PROXY")),
        )
    }

    /// Core resolution shared by [`from_env`](Self::from_env) and tests.
    fn from_vars(
        https_raw: Option<String>,
        http_raw: Option<String>,
        all_raw: Option<String>,
        no_proxy_raw: Option<String>,
    ) -> Option<ProxyConfig> {
        // ALL_PROXY is the per-scheme fallback. Parse the scheme-specific var
        // first and fall back to ALL_PROXY when it is absent *or unusable*
        // (e.g. an unsupported scheme that parses to None) — otherwise a
        // malformed HTTPS_PROXY would suppress a perfectly valid ALL_PROXY.
        let all = all_raw.as_deref().and_then(parse_endpoint);
        let resolve = |specific: Option<String>| {
            specific
                .as_deref()
                .and_then(parse_endpoint)
                .or_else(|| all.clone())
        };
        let https = resolve(https_raw);
        let http = resolve(http_raw);
        if https.is_none() && http.is_none() {
            return None;
        }
        Some(ProxyConfig {
            https,
            http,
            no_proxy: NoProxy::parse(no_proxy_raw.as_deref().unwrap_or("")),
        })
    }

    /// Build a config that routes every destination through a single proxy
    /// URL with no exclusions. Convenience for callers that already hold a
    /// concrete URL (and for tests); [`from_env`](Self::from_env) is the
    /// normal entry point.
    pub(crate) fn from_url(url: &str) -> Option<ProxyConfig> {
        let ep = parse_endpoint(url)?;
        Some(ProxyConfig {
            https: Some(ep.clone()),
            http: Some(ep),
            no_proxy: NoProxy::default(),
        })
    }

    /// The proxy endpoint to use for `dst`, or `None` to connect directly.
    ///
    /// `host` is the destination hostname when known (the SNI for TLS, or a
    /// peeked name for plain TCP); it refines `no_proxy` matching and is named
    /// in the `CONNECT` line. `tls` selects the HTTPS vs HTTP endpoint.
    ///
    /// Host-local addresses (loopback / unspecified / link-local) always
    /// connect directly — a forward proxy can't reach them, and the
    /// `host.microsandbox.internal` alias is rewritten to loopback upstream.
    pub(crate) fn endpoint_for(
        &self,
        dst: SocketAddr,
        host: Option<&str>,
        tls: bool,
    ) -> Option<&ProxyEndpoint> {
        // Canonicalize IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to IPv4 so the
        // host-local checks below also catch a mapped loopback/link-local.
        let ip = match dst.ip() {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
            v4 => v4,
        };
        // Host-local destinations can't be reached through a forward proxy
        // (and `host.microsandbox.internal` is rewritten to loopback upstream).
        if ip.is_loopback() || ip.is_unspecified() || is_link_local(ip) {
            return None;
        }
        if self.no_proxy.matches(host, ip) {
            return None;
        }
        // Prefer the scheme-specific endpoint, but fall back to the other one:
        // an HTTP CONNECT proxy tunnels any TCP regardless of which env var
        // configured it, so setting just one of HTTPS_PROXY / HTTP_PROXY /
        // ALL_PROXY routes *all* egress through it rather than leaking a direct
        // connection (which fails in a proxy-only network) for the other scheme.
        let (primary, secondary) = if tls {
            (self.https.as_ref(), self.http.as_ref())
        } else {
            (self.http.as_ref(), self.https.as_ref())
        };
        primary.or(secondary)
    }

    /// Credential-free display of the HTTPS-destination proxy, if any.
    pub fn https_display(&self) -> Option<&str> {
        self.https.as_ref().map(|e| e.display.as_str())
    }

    /// Credential-free display of the HTTP-destination proxy, if any.
    pub fn http_display(&self) -> Option<&str> {
        self.http.as_ref().map(|e| e.display.as_str())
    }

    /// The raw `no_proxy` string for the startup banner, if non-empty.
    pub fn no_proxy_display(&self) -> Option<&str> {
        if self.no_proxy.raw.is_empty() {
            None
        } else {
            Some(self.no_proxy.raw.as_str())
        }
    }
}

impl NoProxy {
    fn parse(raw: &str) -> NoProxy {
        let mut np = NoProxy {
            raw: raw.trim().to_string(),
            ..Default::default()
        };
        for tok in raw
            .split([',', ' ', '\t', '\n', '\r'])
            .map(str::trim)
            .filter(|t| !t.is_empty())
        {
            if tok == "*" {
                np.wildcard = true;
                continue;
            }
            // An entry may carry a `:port` suffix (e.g. `example.com:8080`);
            // we match on host/IP only, so drop it for non-IPv6 tokens.
            let bare = strip_port(tok);
            if let Some(net) = parse_net(bare) {
                np.nets.push(net);
                continue;
            }
            let name = bare
                .trim_start_matches('.')
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if !name.is_empty() {
                np.names.push(name);
            }
        }
        np
    }

    /// Whether `host` (when known) or `ip` is excluded from proxying.
    fn matches(&self, host: Option<&str>, ip: IpAddr) -> bool {
        if self.wildcard {
            return true;
        }
        if let Some(h) = host {
            let h = h.trim_end_matches('.').to_ascii_lowercase();
            let hb = h.as_bytes();
            for n in &self.names {
                // Exact match, or a dotted suffix so `example.com` matches
                // `api.example.com` but not `notexample.com` — checked without
                // a per-entry `format!(".{n}")` allocation on this hot path.
                if h == *n
                    || (hb.len() > n.len()
                        && h.ends_with(n.as_str())
                        && hb[hb.len() - n.len() - 1] == b'.')
                {
                    return true;
                }
            }
        }
        self.nets.iter().any(|net| net.contains(ip))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Connect to `dst` on the guest's behalf, tunneling through the configured
/// HTTP proxy when one applies and connecting directly otherwise.
///
/// `proxy` is the boot-time config (`shared.proxy()`); `host` is the
/// destination hostname when known (named in the `CONNECT` line, falling back
/// to the destination IP); `tls` selects the HTTPS vs HTTP proxy endpoint.
pub(crate) async fn connect_upstream(
    proxy: Option<&ProxyConfig>,
    dst: SocketAddr,
    host: Option<&str>,
    tls: bool,
) -> io::Result<TcpStream> {
    // Clone the endpoint out so we hold no borrow of `proxy` across the await.
    let endpoint = proxy.and_then(|p| p.endpoint_for(dst, host, tls)).cloned();
    match endpoint {
        Some(ep) => {
            let target = host
                .map(str::to_string)
                .unwrap_or_else(|| dst.ip().to_string());
            connect_via_proxy(&ep, &target, dst.port()).await
        }
        None => TcpStream::connect(dst).await,
    }
}

/// Open a raw byte tunnel to `target_host:target_port` via `proxy` using the
/// HTTP `CONNECT` method. The returned stream is positioned right after the
/// proxy's `200` response — the caller drives the real protocol (a TLS
/// handshake, a buffered first flight, …) over it exactly as if it had dialed
/// the origin directly.
async fn connect_via_proxy(
    proxy: &ProxyEndpoint,
    target_host: &str,
    target_port: u16,
) -> io::Result<TcpStream> {
    let authority = format_authority(target_host, target_port);
    let exchange = async {
        let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port)).await?;
        let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
        if let Some(auth) = &proxy.auth_header {
            req.push_str("Proxy-Authorization: ");
            req.push_str(auth);
            req.push_str("\r\n");
        }
        req.push_str("Proxy-Connection: keep-alive\r\n\r\n");
        stream.write_all(req.as_bytes()).await?;

        let status = read_connect_response(&mut stream).await?;
        if !(200..=299).contains(&status) {
            return Err(io::Error::other(format!(
                "proxy {} refused CONNECT to {authority}: HTTP {status}",
                proxy.display
            )));
        }
        Ok(stream)
    };
    match tokio::time::timeout(CONNECT_TIMEOUT, exchange).await {
        Err(_elapsed) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("proxy {} CONNECT to {authority} timed out", proxy.display),
        )),
        Ok(Err(e)) => Err(e),
        Ok(Ok(stream)) => {
            tracing::debug!(proxy = %proxy.display, target = %authority, "established proxy CONNECT tunnel");
            Ok(stream)
        }
    }
}

/// Read the proxy's `CONNECT` response up to the blank line and return its
/// status code. Reads one byte at a time so we never consume tunnel bytes that
/// follow the header (a clean proxy sends nothing until we write, but this is
/// robust regardless).
async fn read_connect_response(stream: &mut TcpStream) -> io::Result<u16> {
    let mut buf = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "proxy closed connection during CONNECT handshake",
            ));
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > MAX_CONNECT_RESPONSE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy CONNECT response header too large",
            ));
        }
    }
    parse_status_line(&buf)
}

/// Parse the status code from an HTTP status line like
/// `HTTP/1.1 200 Connection established`.
fn parse_status_line(buf: &[u8]) -> io::Result<u16> {
    let line = buf
        .split(|&b| b == b'\r' || b == b'\n')
        .next()
        .unwrap_or(buf);
    let line = std::str::from_utf8(line)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 proxy status line"))?;
    line.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("malformed proxy CONNECT status line: {line:?}"),
            )
        })
}

/// Format a `host:port` authority for the request line, bracketing IPv6
/// literals (`[::1]:443`).
fn format_authority(host: &str, port: u16) -> String {
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Parse one proxy URL into an endpoint. Returns `None` for empty input or an
/// unsupported scheme (anything other than `http`/scheme-less).
fn parse_endpoint(raw: &str) -> Option<ProxyEndpoint> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let (scheme, rest) = match raw.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => (String::new(), raw),
    };
    if !scheme.is_empty() && scheme != "http" {
        warn_unsupported_scheme(&scheme);
        return None;
    }
    // Only the authority matters; drop any /path, ?query or #fragment.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if authority.is_empty() {
        return None;
    }
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, authority),
    };
    let (host, port) = parse_host_port(hostport)?;
    let auth_header = userinfo.and_then(basic_auth_header);
    let display = format!("http://{host}:{port}");
    Some(ProxyEndpoint {
        host,
        port,
        auth_header,
        display,
    })
}

/// Split a `host:port` (or bracketed `[ipv6]:port`) authority. Defaults to
/// port 80 when none is given.
fn parse_host_port(s: &str) -> Option<(String, u16)> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        // `[ipv6]` or `[ipv6]:port`.
        let (addr, after) = rest.split_once(']')?;
        addr.parse::<Ipv6Addr>().ok()?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if after.is_empty() => 80,
            None => return None,
        };
        return Some((addr.to_string(), port));
    }
    // An unbracketed authority with more than one ':' can only be a bare IPv6
    // literal — RFC 3986 requires brackets to attach a port — so accept it as
    // host-only (default port) rather than mis-splitting on the last ':'.
    if s.matches(':').count() > 1 {
        return s.parse::<Ipv6Addr>().ok().map(|_| (s.to_string(), 80));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => Some((h.to_string(), p.parse().ok()?)),
        Some(_) => None,
        None => Some((s.to_string(), 80)),
    }
}

/// Build a `Proxy-Authorization: Basic …` value from `user:pass` userinfo,
/// percent-decoding each component first.
fn basic_auth_header(userinfo: &str) -> Option<String> {
    if userinfo.is_empty() {
        return None;
    }
    let (user, pass) = match userinfo.split_once(':') {
        Some((u, p)) => (u, p),
        None => (userinfo, ""),
    };
    let user = percent_encoding::percent_decode_str(user).decode_utf8_lossy();
    let pass = percent_encoding::percent_decode_str(pass).decode_utf8_lossy();
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
    Some(format!("Basic {token}"))
}

/// Strip a trailing `:port` from a `no_proxy` token, leaving bracketed IPv6
/// and bare IPv6 literals untouched.
fn strip_port(tok: &str) -> &str {
    if tok.starts_with('[') {
        return tok; // bracketed IPv6 — leave to the net parser
    }
    match tok.rsplit_once(':') {
        // A second colon means a bare IPv6 literal, not host:port.
        Some((head, tail)) if !head.contains(':') && tail.chars().all(|c| c.is_ascii_digit()) => {
            head
        }
        _ => tok,
    }
}

/// Parse a `no_proxy` IP/CIDR token. A bare IP becomes a host route
/// (`/32` or `/128`).
fn parse_net(tok: &str) -> Option<IpNetwork> {
    if let Ok(ip) = tok.parse::<IpAddr>() {
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        return IpNetwork::new(ip, prefix).ok();
    }
    tok.parse::<IpNetwork>().ok()
}

fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        // fe80::/10
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Trimmed, non-empty environment value or `None`.
fn env_var(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Warn once per process that an unsupported proxy scheme was ignored.
fn warn_unsupported_scheme(scheme: &str) {
    static WARN: Once = Once::new();
    let scheme = scheme.to_string();
    WARN.call_once(move || {
        tracing::warn!(
            scheme = %scheme,
            "ignoring unsupported proxy scheme (only http:// CONNECT proxies are supported for guest egress)"
        );
    });
}

//--------------------------------------------------------------------------------------------------
// Test support + tests
//--------------------------------------------------------------------------------------------------

/// In-process origin server + HTTP `CONNECT` proxy fixtures, shared with the
/// proxy-task egress tests in [`crate::proxy`].
#[cfg(test)]
pub(crate) mod test_support {
    use std::net::SocketAddr;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};

    /// Accept one connection, send a fixed banner, then close.
    pub(crate) async fn spawn_echo_origin() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let _ = s.write_all(b"HELLO-FROM-ORIGIN").await;
                let _ = s.shutdown().await;
            }
        });
        addr
    }

    /// Minimal HTTP `CONNECT` proxy. Captures the requested authority (so a
    /// test can assert what the client asked to reach) but always dials the
    /// provided `origin`, so a synthetic hostname still routes to our local
    /// server. Splices until either side closes.
    pub(crate) async fn spawn_connect_proxy(
        origin: SocketAddr,
    ) -> (SocketAddr, tokio::sync::oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.unwrap();
            let mut req = Vec::new();
            let mut b = [0u8; 1];
            loop {
                match client.read(&mut b).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
                req.push(b[0]);
                if req.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let authority = String::from_utf8_lossy(&req)
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("")
                .to_string();
            let _ = tx.send(authority);
            let upstream = TcpStream::connect(origin).await.unwrap();
            client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            let (mut cr, mut cw) = client.into_split();
            let (mut ur, mut uw) = upstream.into_split();
            // Stop as soon as either direction closes (the origin sends its
            // banner then EOFs), dropping both halves and freeing the client.
            tokio::select! {
                _ = tokio::io::copy(&mut cr, &mut uw) => {}
                _ = tokio::io::copy(&mut ur, &mut cw) => {}
            }
        });
        (addr, rx)
    }
}

#[cfg(test)]
mod tests {
    // The module-level `use base64::Engine as _;` is anonymous, so `use
    // super::*` doesn't bring the trait's methods into this child module —
    // re-import it here for the `.decode` round-trip assertion below.
    use base64::Engine as _;

    use super::*;

    fn cfg(https: Option<&str>, http: Option<&str>, all: Option<&str>, no: Option<&str>) -> Option<ProxyConfig> {
        ProxyConfig::from_vars(
            https.map(String::from),
            http.map(String::from),
            all.map(String::from),
            no.map(String::from),
        )
    }

    #[test]
    fn parse_plain_host_port() {
        let ep = parse_endpoint("http://proxy.corp:3128").unwrap();
        assert_eq!(ep.host, "proxy.corp");
        assert_eq!(ep.port, 3128);
        assert!(ep.auth_header.is_none());
        assert_eq!(ep.display, "http://proxy.corp:3128");
    }

    #[test]
    fn parse_schemeless_and_default_port() {
        let ep = parse_endpoint("proxy.corp").unwrap();
        assert_eq!(ep.host, "proxy.corp");
        assert_eq!(ep.port, 80);
    }

    #[test]
    fn parse_strips_path_and_query() {
        let ep = parse_endpoint("http://proxy:8080/pac?x=1").unwrap();
        assert_eq!(ep.host, "proxy");
        assert_eq!(ep.port, 8080);
    }

    #[test]
    fn parse_ipv6_literal() {
        let ep = parse_endpoint("http://[2001:db8::1]:3128").unwrap();
        assert_eq!(ep.host, "2001:db8::1");
        assert_eq!(ep.port, 3128);
        assert_eq!(format_authority(&ep.host, ep.port), "[2001:db8::1]:3128");
    }

    #[test]
    fn parse_userinfo_into_basic_auth() {
        let ep = parse_endpoint("http://alice:s3cr3t@proxy:3128").unwrap();
        // base64("alice:s3cr3t")
        assert_eq!(
            ep.auth_header.as_deref(),
            Some("Basic YWxpY2U6czNjcjN0")
        );
        // Credentials never appear in the display string.
        assert_eq!(ep.display, "http://proxy:3128");
    }

    #[test]
    fn parse_percent_decoded_userinfo() {
        // user "a b", pass "p@ss"
        let ep = parse_endpoint("http://a%20b:p%40ss@proxy:3128").unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(ep.auth_header.unwrap().trim_start_matches("Basic "))
            .unwrap();
        assert_eq!(decoded, b"a b:p@ss");
    }

    #[test]
    fn https_scheme_proxy_is_ignored() {
        assert!(parse_endpoint("https://proxy:3128").is_none());
        assert!(parse_endpoint("socks5://proxy:1080").is_none());
    }

    #[test]
    fn from_vars_none_when_unset() {
        assert!(cfg(None, None, None, None).is_none());
    }

    #[test]
    fn all_proxy_is_fallback_for_both_schemes() {
        let c = cfg(None, None, Some("http://all:3128"), None).unwrap();
        assert_eq!(c.https_display(), Some("http://all:3128"));
        assert_eq!(c.http_display(), Some("http://all:3128"));
    }

    #[test]
    fn specific_scheme_overrides_all_proxy() {
        let c = cfg(Some("http://sec:1"), None, Some("http://all:2"), None).unwrap();
        assert_eq!(c.https_display(), Some("http://sec:1"));
        assert_eq!(c.http_display(), Some("http://all:2"));
    }

    #[test]
    fn all_proxy_used_when_scheme_specific_is_unsupported() {
        // An unsupported scheme in HTTPS_PROXY must NOT suppress a valid
        // ALL_PROXY fallback.
        let c = cfg(Some("socks5://sec:1"), None, Some("http://all:2"), None).unwrap();
        assert_eq!(c.https_display(), Some("http://all:2"));
        assert_eq!(c.http_display(), Some("http://all:2"));
    }

    #[test]
    fn single_scheme_falls_back_across_schemes() {
        // Only HTTPS_PROXY set: a plain (tls=false) destination must still
        // route through it instead of leaking a direct connection.
        let c = cfg(Some("http://only:1"), None, None, None).unwrap();
        let dst = sa("93.184.216.34:80");
        assert_eq!(c.endpoint_for(dst, None, false).unwrap().port, 1);
        assert_eq!(c.endpoint_for(dst, None, true).unwrap().port, 1);
        // Symmetrically, only HTTP_PROXY set still covers TLS destinations.
        let c = cfg(None, Some("http://only:2"), None, None).unwrap();
        assert_eq!(
            c.endpoint_for(sa("93.184.216.34:443"), Some("x.com"), true).unwrap().port,
            2
        );
    }

    #[test]
    fn ipv4_mapped_loopback_is_not_proxied() {
        let c = ProxyConfig::from_url("http://proxy:3128").unwrap();
        let dst: SocketAddr = "[::ffff:127.0.0.1]:443".parse().unwrap();
        assert!(c.endpoint_for(dst, None, true).is_none());
    }

    #[test]
    fn parse_bare_and_bracketed_ipv6_proxy_host() {
        // Unbracketed IPv6 literal → host-only with the default port (no
        // mis-split on the last ':').
        let ep = parse_endpoint("http://fe80::1").unwrap();
        assert_eq!(ep.host, "fe80::1");
        assert_eq!(ep.port, 80);
        // Bracketed form still carries an explicit port.
        let ep = parse_endpoint("[2001:db8::5]:3128").unwrap();
        assert_eq!(ep.host, "2001:db8::5");
        assert_eq!(ep.port, 3128);
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn endpoint_for_selects_by_scheme() {
        let c = cfg(Some("http://sec:1"), Some("http://plain:2"), None, None).unwrap();
        let dst = sa("93.184.216.34:443");
        assert_eq!(c.endpoint_for(dst, Some("example.com"), true).unwrap().port, 1);
        assert_eq!(c.endpoint_for(dst, Some("example.com"), false).unwrap().port, 2);
    }

    #[test]
    fn loopback_and_local_never_proxied() {
        let c = ProxyConfig::from_url("http://proxy:3128").unwrap();
        assert!(c.endpoint_for(sa("127.0.0.1:443"), None, true).is_none());
        assert!(c.endpoint_for(sa("0.0.0.0:443"), None, true).is_none());
        assert!(c.endpoint_for(sa("169.254.10.1:443"), None, true).is_none());
        assert!(c.endpoint_for("[fe80::1]:443".parse().unwrap(), None, true).is_none());
        // A routable address still proxies.
        assert!(c.endpoint_for(sa("93.184.216.34:443"), None, true).is_some());
    }

    #[test]
    fn no_proxy_wildcard_bypasses_all() {
        let c = cfg(Some("http://p:1"), None, None, Some("*")).unwrap();
        assert!(c.endpoint_for(sa("93.184.216.34:443"), Some("example.com"), true).is_none());
    }

    #[test]
    fn no_proxy_domain_suffix() {
        let c = cfg(Some("http://p:1"), None, None, Some("example.com,foo.org")).unwrap();
        let dst = sa("93.184.216.34:443");
        assert!(c.endpoint_for(dst, Some("api.example.com"), true).is_none());
        assert!(c.endpoint_for(dst, Some("example.com"), true).is_none());
        // Suffix must be dotted: notexample.com is NOT excluded by example.com.
        assert!(c.endpoint_for(dst, Some("notexample.com"), true).is_some());
        assert!(c.endpoint_for(dst, Some("other.net"), true).is_some());
    }

    #[test]
    fn no_proxy_leading_dot_and_port() {
        let c = cfg(Some("http://p:1"), None, None, Some(".internal:8080")).unwrap();
        let dst = sa("10.1.2.3:443");
        assert!(c.endpoint_for(dst, Some("svc.internal"), true).is_none());
    }

    #[test]
    fn no_proxy_ip_and_cidr() {
        let c = cfg(Some("http://p:1"), None, None, Some("10.0.0.0/8, 192.168.1.5")).unwrap();
        assert!(c.endpoint_for(sa("10.9.9.9:443"), None, true).is_none());
        assert!(c.endpoint_for(sa("192.168.1.5:443"), None, true).is_none());
        assert!(c.endpoint_for(sa("192.168.1.6:443"), None, true).is_some());
        assert!(c.endpoint_for(sa("8.8.8.8:443"), None, true).is_some());
    }

    #[test]
    fn parse_status_line_variants() {
        assert_eq!(
            parse_status_line(b"HTTP/1.1 200 Connection established\r\n\r\n").unwrap(),
            200
        );
        assert_eq!(parse_status_line(b"HTTP/1.0 403 Forbidden\r\n").unwrap(), 403);
        assert!(parse_status_line(b"garbage\r\n").is_err());
    }

    // --- CONNECT round-trip against an in-process proxy + origin ---

    use super::test_support::{spawn_connect_proxy, spawn_echo_origin};

    #[tokio::test]
    async fn connect_via_proxy_tunnels_to_origin() {
        let origin = spawn_echo_origin().await;
        let (proxy_addr, authority_rx) = spawn_connect_proxy(origin).await;

        let ep = parse_endpoint(&format!("http://{proxy_addr}")).unwrap();
        let mut tunnel = connect_via_proxy(&ep, &origin.ip().to_string(), origin.port())
            .await
            .expect("CONNECT tunnel");

        // The proxy was asked to reach our origin, not the proxy itself.
        assert_eq!(
            authority_rx.await.unwrap(),
            format!("{}:{}", origin.ip(), origin.port())
        );

        // Bytes flow end-to-end through the tunnel.
        let mut got = Vec::new();
        tunnel.read_to_end(&mut got).await.unwrap();
        assert_eq!(&got, b"HELLO-FROM-ORIGIN");
    }

    #[tokio::test]
    async fn connect_upstream_proxies_by_hostname() {
        let origin = spawn_echo_origin().await;
        let (proxy_addr, authority_rx) = spawn_connect_proxy(origin).await;
        let cfg = ProxyConfig::from_url(&format!("http://{proxy_addr}")).unwrap();

        // The hostname hint is named in the CONNECT line (the TLS-intercept
        // call shape). The dst IP is non-loopback so the proxy applies —
        // loopback would bypass it — and the fixture proxy ignores the
        // authority, dialing our real origin regardless.
        let dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let mut s = connect_upstream(Some(&cfg), dst, Some("origin.test"), true)
            .await
            .unwrap();
        assert_eq!(authority_rx.await.unwrap(), "origin.test:443");

        let mut got = Vec::new();
        s.read_to_end(&mut got).await.unwrap();
        assert_eq!(&got, b"HELLO-FROM-ORIGIN");
    }

    #[tokio::test]
    async fn connect_upstream_direct_when_no_proxy() {
        let origin = spawn_echo_origin().await;
        // No proxy config → direct connect.
        let mut s = connect_upstream(None, origin, None, true).await.unwrap();
        let mut got = Vec::new();
        s.read_to_end(&mut got).await.unwrap();
        assert_eq!(&got, b"HELLO-FROM-ORIGIN");
    }

    #[tokio::test]
    async fn connect_upstream_skips_proxy_for_loopback() {
        // A proxy is configured, but the destination is loopback — which
        // `endpoint_for` never proxies — so we connect directly. The proxy
        // address is an unroutable TEST-NET-1 host that would fail if dialed.
        let origin = spawn_echo_origin().await; // 127.0.0.1
        let cfg = ProxyConfig::from_url("http://192.0.2.1:3128").unwrap();
        let mut s = connect_upstream(Some(&cfg), origin, None, true)
            .await
            .unwrap();
        let mut got = Vec::new();
        s.read_to_end(&mut got).await.unwrap();
        assert_eq!(&got, b"HELLO-FROM-ORIGIN");
    }
}
