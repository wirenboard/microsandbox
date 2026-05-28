//! In-guest TCP loopback forwarder for auto-publish.
//!
//! For each `LoopbackForwardReq`, this module spawns a tokio task
//! that binds `bind_addr:port` (typically the guest's eth0 IPv4)
//! inside the guest and bridges every accepted connection to
//! `127.0.0.1:port`.
//!
//! Why a separate listener instead of a kernel-level DNAT: the
//! sandbox guest kernel ships without netfilter, so
//! `iptables -t nat ... DNAT --to 127.0.0.1` + `route_localnet=1`
//! are unavailable. A userspace relay is the only path to make
//! `127.0.0.1`-only guest services reachable from outside the
//! guest's loopback (see the Lima/OrbStack agent design — same
//! idea: terminate the inbound TCP inside the guest, then re-dial
//! loopback there).
//!
//! Port collision: a process can bind `127.0.0.1:N` AND another
//! process can bind `<eth0_ip>:N` simultaneously because the binds
//! target different specific addresses. We rely on this — the
//! guest's user app keeps its loopback bind, and agentd lights up
//! the NIC bind next to it.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::AbortHandle;

/// Bookkeeping for active loopback forwarders. Keyed by port —
/// only one forwarder per port, since the smoltcp publisher dials a
/// single guest IP and the listener bind is on that IP.
#[derive(Default, Clone)]
pub struct ForwarderRegistry {
    inner: Arc<Mutex<HashMap<u16, AbortHandle>>>,
}

impl ForwarderRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Spawn a forwarder for `(bind_addr, port) → 127.0.0.1:port`.
    /// If a forwarder is already registered for `port`, this is a
    /// no-op (idempotent — covers the case where msb-side polling
    /// re-detects the same LISTEN before the previous one was
    /// removed).
    ///
    /// Returns `Ok(())` on success; `Err` carries a stringified
    /// reason (today: bind failure).
    pub async fn spawn(&self, bind_addr: IpAddr, port: u16) -> Result<(), String> {
        {
            let map = self.inner.lock().unwrap();
            if map.contains_key(&port) {
                return Ok(());
            }
        }
        let addr = SocketAddr::new(bind_addr, port);
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| format!("bind {addr}: {e}"))?;
        let join = tokio::spawn(accept_loop(listener, port));
        self.inner.lock().unwrap().insert(port, join.abort_handle());
        Ok(())
    }

    /// Stop the forwarder for `port` if any. In-flight bridge
    /// tasks continue to drain until both halves close; only the
    /// accept loop stops.
    pub fn cancel(&self, port: u16) {
        if let Some(h) = self.inner.lock().unwrap().remove(&port) {
            h.abort();
        }
    }
}

async fn accept_loop(listener: TcpListener, target_port: u16) {
    loop {
        let (incoming, _peer) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("loopback forwarder accept failed: {e}");
                continue;
            }
        };
        tokio::spawn(bridge(incoming, target_port));
    }
}

async fn bridge(mut incoming: TcpStream, target_port: u16) {
    let loop_addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), target_port);
    let mut outbound = match TcpStream::connect(loop_addr).await {
        Ok(s) => s,
        Err(e) => {
            // Loopback listener went away between the LISTEN we
            // observed and now (or msb's polling fired against a
            // stale entry). Close fast so the host peer sees
            // EOF/RST rather than hanging.
            eprintln!("loopback forwarder dial 127.0.0.1:{target_port} failed: {e}");
            let _ = incoming.shutdown().await;
            return;
        }
    };
    // tokio::io::copy_bidirectional handles half-close cleanly
    // (each direction closes when its source EOFs), which is what
    // HTTP/1.1 keep-alive and most TCP protocols expect.
    let _ = tokio::io::copy_bidirectional(&mut incoming, &mut outbound).await;
}
