//! Channel-based TLS proxy task.
//!
//! Intercepts TLS connections by terminating the guest's TLS with a
//! generated per-domain certificate (MITM) and re-originating a TLS
//! connection to the real server. Bypass mode replays buffered bytes and
//! splices the connection without termination.

use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use super::sni;
use super::state::TlsState;
use crate::conn::ProxyConnectState;
use crate::intercept::handler::{Interceptor, Verdict};
use crate::policy::{EgressEvaluation, HostnameSource, NetworkPolicy, Protocol};
use crate::proxy::connect_upstream;
use crate::secrets::config::ViolationAction;
use crate::secrets::handler::SecretsHandler;
use crate::shared::SharedState;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Max bytes to buffer while waiting for the ClientHello.
const CLIENT_HELLO_BUF_SIZE: usize = 16384;

/// Buffer size for bidirectional relay.
const RELAY_BUF_SIZE: usize = 16384;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(crate) struct TlsProxyContext {
    pub(crate) guest_dst: SocketAddr,
    pub(crate) connect_dst: SocketAddr,
    pub(crate) shared: Arc<SharedState>,
    pub(crate) tls_state: Arc<TlsState>,
    pub(crate) network_policy: Arc<NetworkPolicy>,
    pub(crate) proxy_connect: Arc<ProxyConnectState>,
    /// Pre-connected upstream; when `Some`, skips dialing `connect_dst`.
    pub(crate) upstream_stream: Option<TcpStream>,
    /// Hostname from a CONNECT authority that must match the ClientHello SNI.
    pub(crate) expected_sni: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Spawn a TLS proxy task for a connection to an intercepted port.
///
/// See [`crate::proxy::spawn_tcp_proxy`] for the `proxy_connect`
/// contract.
#[allow(clippy::too_many_arguments)]
pub fn spawn_tls_proxy(
    handle: &tokio::runtime::Handle,
    guest_dst: SocketAddr,
    connect_dst: SocketAddr,
    from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    tls_state: Arc<TlsState>,
    network_policy: Arc<NetworkPolicy>,
    proxy_connect: Arc<ProxyConnectState>,
) {
    handle.spawn(async move {
        let context = TlsProxyContext {
            guest_dst,
            connect_dst,
            shared,
            tls_state,
            network_policy,
            proxy_connect,
            upstream_stream: None,
            expected_sni: None,
        };

        if let Err(e) = tls_proxy_task(context, from_smoltcp, to_smoltcp, Vec::new()).await {
            tracing::debug!(dst = %connect_dst, guest_dst = %guest_dst, error = %e, "TLS proxy task ended");
        }
    });
}

/// Core TLS proxy task.
pub(crate) async fn tls_proxy_task(
    context: TlsProxyContext,
    mut from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    tls_initial_buf: Vec<u8>,
) -> io::Result<()> {
    let TlsProxyContext {
        guest_dst,
        connect_dst,
        shared,
        tls_state,
        network_policy,
        proxy_connect,
        upstream_stream,
        expected_sni,
    } = context;

    // Buffer initial data to extract SNI from ClientHello. Timeout prevents a
    // slow/malicious guest from holding a proxy slot indefinitely.
    let sni_name = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        extract_sni_from_channel(&mut from_smoltcp, tls_initial_buf),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SNI extraction timed out"))?;
    let (sni_name, initial_buf) = sni_name?;

    // Canonicalize so byte equality against rule destinations works.
    let sni_name = sni_name.trim_end_matches('.').to_ascii_lowercase();

    if let Some(expected) = expected_sni.as_deref()
        && !sni_name.eq_ignore_ascii_case(expected.trim_end_matches('.'))
    {
        tracing::debug!(
            sni = %sni_name,
            expected = %expected,
            dst = %connect_dst,
            "TLS SNI did not match CONNECT authority",
        );
        proxy_connect.mark_policy_denied();
        shared.proxy_wake.wake();
        return Ok(());
    }

    // Apply Domain / DomainSuffix rules against the SNI.
    let eval = network_policy.evaluate_egress_with_source(
        guest_dst,
        Protocol::Tcp,
        &shared,
        HostnameSource::Sni(&sni_name),
    );
    if !matches!(eval, EgressEvaluation::Allow) {
        tracing::debug!(
            sni = %sni_name,
            dst = %guest_dst,
            "TLS egress denied by domain policy",
        );
        proxy_connect.mark_policy_denied();
        shared.proxy_wake.wake();
        return Ok(());
    }

    if tls_state.should_bypass(&sni_name) {
        tracing::debug!(sni = %sni_name, dst = %connect_dst, guest_dst = %guest_dst, "TLS bypass");
        bypass_relay(
            connect_dst,
            initial_buf,
            from_smoltcp,
            to_smoltcp,
            shared,
            proxy_connect,
            upstream_stream,
        )
        .await
    } else {
        tracing::debug!(sni = %sni_name, dst = %connect_dst, guest_dst = %guest_dst, "TLS intercept");
        intercept_relay(
            guest_dst,
            connect_dst,
            &sni_name,
            initial_buf,
            from_smoltcp,
            to_smoltcp,
            shared,
            tls_state,
            proxy_connect,
            upstream_stream,
        )
        .await
    }
}

/// Bypass mode: plain TCP splice, no TLS termination.
async fn bypass_relay(
    dst: SocketAddr,
    initial_buf: Vec<u8>,
    mut from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    proxy_connect: Arc<ProxyConnectState>,
    upstream_stream: Option<TcpStream>,
) -> io::Result<()> {
    let mut server = match upstream_stream {
        Some(s) => s,
        None => connect_upstream(dst, &proxy_connect, &shared).await?,
    };
    server.write_all(&initial_buf).await?;

    let (mut server_rx, mut server_tx) = server.into_split();
    let mut buf = vec![0u8; RELAY_BUF_SIZE];

    loop {
        tokio::select! {
            data = from_smoltcp.recv() => {
                match data {
                    Some(bytes) => server_tx.write_all(&bytes).await?,
                    None => break,
                }
            }
            result = server_rx.read(&mut buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        if to_smoltcp.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                            break;
                        }
                        shared.proxy_wake.wake();
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    Ok(())
}

/// Intercept mode: MITM with guest-facing rustls + server-facing tokio_rustls.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn intercept_relay(
    guest_dst: SocketAddr,
    connect_dst: SocketAddr,
    sni_name: &str,
    initial_buf: Vec<u8>,
    mut from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    tls_state: Arc<TlsState>,
    proxy_connect: Arc<ProxyConnectState>,
    upstream_stream: Option<TcpStream>,
) -> io::Result<()> {
    let mut secrets_handler =
        SecretsHandler::new_tls_intercepted(&tls_state.secrets, sni_name, guest_dst.ip(), &shared)
            .with_guest_dst(guest_dst);

    // Per-connection request interceptor (e.g. OAuth-refresh MITM, repo
    // allow-listing). Streams chunks through unchanged when no rule
    // matches; otherwise buffers a request and hands it to the hook
    // subprocess. The interceptor sees post-substitution bytes.
    let mut interceptor = if tls_state.intercept.is_active() {
        Some(Interceptor::new(tls_state.intercept.clone(), sni_name))
    } else {
        None
    };

    // Get or generate per-domain certificate (includes cached ServerConfig).
    let domain_cert = tls_state
        .get_or_generate_cert(sni_name)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    // Reuse cached ServerConfig — avoids cert chain clone + key clone + rebuild per connection.
    let mut guest_tls = rustls::ServerConnection::new(domain_cert.server_config.clone())
        .map_err(io::Error::other)?;

    // Feed the buffered ClientHello.
    {
        let mut remaining = &initial_buf[..];
        while !remaining.is_empty() {
            guest_tls
                .read_tls(&mut remaining)
                .map_err(io::Error::other)?;
            guest_tls.process_new_packets().map_err(io::Error::other)?;
        }
    }

    // Reusable buffer for TLS output — avoids per-flush heap allocation.
    let mut tls_buf = Vec::with_capacity(RELAY_BUF_SIZE + 256);

    // Send ServerHello etc. back to guest.
    flush_to_guest(&mut guest_tls, &to_smoltcp, &shared, &mut tls_buf).await?;

    // Complete guest-facing TLS handshake with timeout to prevent resource exhaustion.
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while guest_tls.is_handshaking() {
            let data = from_smoltcp
                .recv()
                .await
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "channel closed"))?;
            let mut remaining = &data[..];
            while !remaining.is_empty() {
                guest_tls
                    .read_tls(&mut remaining)
                    .map_err(io::Error::other)?;
                guest_tls.process_new_packets().map_err(io::Error::other)?;
            }
            flush_to_guest(&mut guest_tls, &to_smoltcp, &shared, &mut tls_buf).await?;
        }
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))??;

    // Connect to real server with TLS.
    let server_stream = match upstream_stream {
        Some(s) => s,
        None => connect_upstream(connect_dst, &proxy_connect, &shared).await?,
    };
    let server_name = ServerName::try_from(sni_name.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut server_tls = tls_state
        .connector
        .connect(server_name, server_stream)
        .await
        .map_err(io::Error::other)?;

    // Phase 2: Bidirectional plaintext relay.
    let mut server_buf = vec![0u8; RELAY_BUF_SIZE];
    let mut plaintext_buf = vec![0u8; RELAY_BUF_SIZE];

    // Drain any application data already buffered during the TLS handshake.
    // In TLS 1.3, the client sends Finished + application data in the same
    // flight, so process_new_packets() during the handshake loop may have
    // already decrypted the first HTTP request into the plaintext buffer.
    if forward_plaintext(
        &mut guest_tls,
        &mut server_tls,
        &mut secrets_handler,
        interceptor.as_mut(),
        &shared,
        &mut plaintext_buf,
        &to_smoltcp,
        &mut tls_buf,
    )
    .await?
    {
        // Interceptor synthesized a response to the guest; connection is done.
        return Ok(());
    }

    loop {
        tokio::select! {
            // Guest → server: receive encrypted, decrypt, forward plaintext.
            data = from_smoltcp.recv() => {
                let data = match data {
                    Some(d) => d,
                    None => break,
                };
                // Feed all data to rustls.
                let mut remaining = &data[..];
                while !remaining.is_empty() {
                    guest_tls
                        .read_tls(&mut remaining)
                        .map_err(io::Error::other)?;
                    guest_tls
                        .process_new_packets()
                        .map_err(io::Error::other)?;
                    if forward_plaintext(
                        &mut guest_tls,
                        &mut server_tls,
                        &mut secrets_handler,
                        interceptor.as_mut(),
                        &shared,
                        &mut plaintext_buf,
                        &to_smoltcp,
                        &mut tls_buf,
                    )
                    .await?
                    {
                        return Ok(());
                    }
                }
            }

            // Server → guest: read plaintext, encrypt, send via channel.
            result = server_tls.read(&mut server_buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        guest_tls
                            .writer()
                            .write_all(&server_buf[..n])
                            .map_err(io::Error::other)?;
                        flush_to_guest(&mut guest_tls, &to_smoltcp, &shared, &mut tls_buf).await?;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    Ok(())
}

/// Buffer channel data until a complete ClientHello with SNI is received.
///
/// `seed` carries bytes already read from the channel before this call
/// (e.g. bytes trailing a CONNECT request). Pass an empty `Vec` when no
/// bytes have been pre-consumed.
pub(crate) async fn extract_sni_from_channel(
    from_smoltcp: &mut mpsc::Receiver<Bytes>,
    seed: Vec<u8>,
) -> io::Result<(String, Vec<u8>)> {
    let mut initial_buf = seed;
    initial_buf.reserve(CLIENT_HELLO_BUF_SIZE.saturating_sub(initial_buf.len()));
    loop {
        if let Some(name) = sni::extract_sni(&initial_buf) {
            return Ok((name, initial_buf));
        }
        if initial_buf.len() >= CLIENT_HELLO_BUF_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ClientHello too large or no SNI found",
            ));
        }
        let data = from_smoltcp
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "channel closed"))?;
        initial_buf.extend_from_slice(&data);

        if let Some(name) = sni::extract_sni(&initial_buf) {
            return Ok((name, initial_buf));
        }
        if initial_buf.len() >= CLIENT_HELLO_BUF_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ClientHello too large or no SNI found",
            ));
        }
    }
}

/// Read all available decrypted plaintext from the guest-facing TLS
/// connection and forward it to the upstream server, applying secret
/// substitution and optional request interception when configured.
///
/// Returns `Ok(true)` if the interceptor handled a full request and wrote a
/// synthesized response back to the guest — the caller should stop the
/// connection. `Ok(false)` means streaming continues as normal.
#[allow(clippy::too_many_arguments)]
async fn forward_plaintext(
    guest_tls: &mut rustls::ServerConnection,
    server_tls: &mut tokio_rustls::client::TlsStream<TcpStream>,
    secrets_handler: &mut SecretsHandler,
    mut interceptor: Option<&mut Interceptor>,
    shared: &SharedState,
    buf: &mut [u8],
    to_smoltcp: &mpsc::Sender<Bytes>,
    tls_buf: &mut Vec<u8>,
) -> io::Result<bool> {
    let mut wrote_plaintext = false;

    loop {
        let n = match guest_tls.reader().read(buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        };

        // Substitution first: the interceptor sees post-substitution bytes
        // (the same request the upstream server would receive). Stay
        // zero-copy on the no-secrets path via `Cow::Borrowed`.
        let substituted: std::borrow::Cow<'_, [u8]> = if secrets_handler.is_empty() {
            std::borrow::Cow::Borrowed(&buf[..n])
        } else {
            match secrets_handler.substitute(&buf[..n]) {
                Ok(data) => data,
                Err(action) => {
                    // Violation: placeholder going to disallowed host. Drop it.
                    if matches!(action, ViolationAction::BlockAndTerminate) {
                        shared.trigger_termination();
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "secret violation: placeholder sent to disallowed host",
                    ));
                }
            }
        };

        // An empty result means the secrets handler is still buffering this
        // request (e.g. accumulating a header block it will emit on a later
        // chunk). There is nothing to forward yet AND nothing for the
        // interceptor to parse — feeding it an empty chunk would make
        // `process_first_chunk` find no request line and latch to `Forwarding`,
        // silently bypassing the hook for the whole connection. Skip until the
        // handler emits the real (substituted) bytes.
        if substituted.is_empty() {
            continue;
        }

        match interceptor.as_deref_mut() {
            None => {
                server_tls.write_all(&substituted).await?;
                wrote_plaintext = true;
            }
            Some(intercept) => match intercept.process_chunk(&substituted).await? {
                Verdict::Forward => {
                    server_tls.write_all(&substituted).await?;
                    wrote_plaintext = true;
                }
                Verdict::ForwardBuffered(buffered) => {
                    if !buffered.is_empty() {
                        server_tls.write_all(&buffered).await?;
                        wrote_plaintext = true;
                    }
                }
                Verdict::Hold => continue,
                Verdict::Intercept(response) => {
                    // Hook synthesized the whole response. Flush any pending
                    // upstream writes, hand the response to the guest, and
                    // signal the caller to close the connection.
                    if wrote_plaintext {
                        server_tls.flush().await?;
                    }
                    guest_tls
                        .writer()
                        .write_all(&response)
                        .map_err(io::Error::other)?;
                    flush_to_guest(guest_tls, to_smoltcp, shared, tls_buf).await?;
                    return Ok(true);
                }
            },
        }
    }

    // tokio-rustls buffers writes; flush each drained plaintext batch so
    // upstream servers waiting for the full request body can respond.
    if wrote_plaintext {
        server_tls.flush().await?;
    }

    Ok(false)
}

/// Flush pending TLS output from the guest-facing rustls connection
/// to the smoltcp channel.
///
/// Reuses `buf` across calls to avoid per-flush heap allocation. The
/// buffer grows to steady-state capacity on the first call and stays there.
async fn flush_to_guest(
    guest_tls: &mut rustls::ServerConnection,
    to_smoltcp: &mpsc::Sender<Bytes>,
    shared: &SharedState,
    buf: &mut Vec<u8>,
) -> io::Result<()> {
    if guest_tls.wants_write() {
        buf.clear();
        guest_tls.write_tls(buf)?;
        if !buf.is_empty() {
            to_smoltcp
                .send(Bytes::copy_from_slice(buf))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "channel closed"))?;
            shared.proxy_wake.wake();
        }
    }
    Ok(())
}
