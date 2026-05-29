//! Published port handling: host-side listeners that forward connections
//! into the guest VM via smoltcp.
//!
//! For each configured [`PublishedPort`], a tokio TCP or UDP listener binds
//! on the host. When a connection arrives, the poll loop creates a smoltcp
//! socket that connects to the guest, and a relay task bridges the host
//! socket to the smoltcp socket via channels.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use bytes::Bytes;
use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::IpEndpoint;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

use crate::config::{PortProtocol, PublishedPort};
use crate::policy::{NetworkPolicy, Protocol};
use crate::shared::SharedState;

//--------------------------------------------------------------------------------------------------
// Helpers
//--------------------------------------------------------------------------------------------------

/// Set zero-linger on a stream so the kernel sends a TCP RST instead of
/// the default FIN close when the stream drops. Used for deliberate
/// rejection paths (policy deny, max-inbound exhaustion,
/// smoltcp-connect failure) so the peer sees `ECONNRESET` rather than
/// a graceful close that looks like the server simply went away.
///
/// Goes through `socket2` rather than tokio's deprecated
/// `TcpStream::set_linger` so the call site doesn't trip
/// `#[deny(deprecated)]` in clippy. The cast to `SockRef` is
/// zero-cost — it borrows the underlying fd.
fn reject_with_rst(stream: &TcpStream) {
    let _ = socket2::SockRef::from(stream).set_linger(Some(Duration::ZERO));
}

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// TCP socket buffer sizes for inbound connections.
const TCP_RX_BUF_SIZE: usize = 65536;
const TCP_TX_BUF_SIZE: usize = 65536;

/// Channel capacity for relay tasks.
const CHANNEL_CAPACITY: usize = 32;

/// Buffer size for reading from host sockets.
const RELAY_BUF_SIZE: usize = 16384;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Manages published port listeners and inbound connections.
///
/// Spawns tokio listeners for each published port. When connections arrive,
/// they are queued for the poll loop to create smoltcp sockets and initiate
/// connections to the guest.
///
/// Listeners can also be added/removed at runtime via the channel
/// returned by [`PortPublisher::command_sender`]: send
/// [`PortCommand::Add`] / [`PortCommand::Remove`] from any tokio
/// task, and the poll loop applies them on the next
/// [`accept_inbound`](Self::accept_inbound) tick. Used by the
/// auto-publish poll loop to mirror new guest LISTEN sockets onto
/// host listeners as they appear.
pub struct PortPublisher {
    /// Receives accepted connections from listener tasks.
    inbound_rx: mpsc::Receiver<InboundConnection>,
    /// Cloned into every spawned listener task — both the boot-time
    /// `--publish` listeners and runtime-added ones from
    /// [`PortCommand::Add`].
    inbound_tx: mpsc::Sender<InboundConnection>,
    /// Tracked inbound connections (smoltcp socket → relay state).
    connections: Vec<InboundRelay>,
    /// Guest IP that inbound connections are dialed to. Prefers IPv4 (the
    /// common case — most services bind `0.0.0.0` or dual-stack `::`, both
    /// of which accept v4) and falls back to IPv6 for v6-only sandboxes.
    /// `None` when neither family is active; listeners are not spawned.
    guest_ip: Option<IpAddr>,
    /// Ephemeral port counter.
    ephemeral_port: Arc<AtomicU16>,
    /// Maximum inbound connections (prevents resource exhaustion from host-side floods).
    max_inbound: usize,
    /// Network policy used to gate runtime-added listeners (the
    /// boot-time `spawn_listeners` already captures its own copy
    /// for the initial listeners).
    policy: Arc<NetworkPolicy>,
    /// SharedState handed to runtime-added listener tasks.
    shared: Arc<SharedState>,
    /// Cloned for spawning runtime-added listeners.
    tokio_handle: tokio::runtime::Handle,
    /// Runtime add/remove command receiver. `SmoltcpNetwork` owns
    /// the matching sender so it can hand cloneable
    /// [`mpsc::UnboundedSender<PortCommand>`] handles out without
    /// the publisher being responsible for the lifetime.
    cmd_rx: mpsc::UnboundedReceiver<PortCommand>,
    /// Per-listener AbortHandle so [`PortCommand::Remove`] can stop
    /// the accept loop. Indexed by `(host_bind, host_port)` because
    /// that's the bind tuple — two listeners can share the same
    /// guest_port if they're on different host binds.
    listener_handles: HashMap<(IpAddr, u16), AbortHandle>,
}

/// Runtime command sent to a live [`PortPublisher`] from outside the
/// smoltcp poll thread. Sent on the unbounded channel returned by
/// [`crate::network::SmoltcpNetwork::port_handle`]; processed at the
/// head of each [`PortPublisher::accept_inbound`] tick.
///
/// `Add` carries a pre-bound listener rather than a `host_bind +
/// host_port` pair so the caller can pick its own bind strategy
/// (try preferred port → fall back to ephemeral, etc.) and know the
/// final port up front — useful for the auto-publish loop which
/// needs to emit a precise mapping back to the SDK. Static
/// `--publish` ports at boot bypass this channel entirely; they go
/// through [`PortPublisher::new`]'s internal `spawn_listener_one`.
#[derive(Debug)]
pub enum PortCommand {
    /// Take ownership of a host TCP listener and forward each
    /// accepted connection into the guest at `guest_port`. The
    /// `key` is registered in the publisher's listener map so a
    /// matching [`PortCommand::Remove`] can stop the accept loop.
    Add {
        /// Pre-bound host TCP listener. Caller chose the host port
        /// and address; PortPublisher just spawns the accept loop.
        listener: TcpListener,
        /// Bookkeeping key — `(host_bind, host_port)` from the
        /// listener's `local_addr()` at bind time. Stored so a
        /// later `Remove` lookup matches.
        key: (IpAddr, u16),
        /// Guest port to dial via smoltcp on each accepted
        /// connection.
        guest_port: u16,
    },
    /// Stop the listener at `(host_bind, host_port)` if any. In-flight
    /// connections continue to drain on the existing smoltcp sockets;
    /// only the accept loop stops.
    Remove {
        /// Host bind address of the listener to stop.
        host_bind: IpAddr,
        /// Host port of the listener to stop.
        host_port: u16,
    },
}

/// An accepted host-side connection waiting to be wired to the guest.
struct InboundConnection {
    /// The accepted host-side TCP stream.
    stream: TcpStream,
    /// Guest port to connect to.
    guest_port: u16,
}

/// Maximum number of poll iterations to attempt flushing remaining data
/// after the relay task has exited before force-aborting the socket.
const DEFERRED_CLOSE_LIMIT: u16 = 64;

/// Initial backoff after an `accept()` failure in `run_accept_loop`.
const ACCEPT_BACKOFF_INITIAL: Duration = Duration::from_millis(10);

/// Cap on the exponential backoff between `accept()` failures.
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// A single inbound connection relay (host socket ↔ smoltcp socket).
struct InboundRelay {
    handle: SocketHandle,
    /// Send data from smoltcp socket to host relay task.
    to_host: mpsc::Sender<Bytes>,
    /// Receive data from host relay task to write to smoltcp socket.
    from_host: mpsc::Receiver<Bytes>,
    /// Partial data that couldn't be fully written to smoltcp socket.
    write_buf: Option<(Bytes, usize)>,
    /// Counter for deferred close attempts (prevents stalling forever).
    close_attempts: u16,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PortPublisher {
    /// Create a new publisher and spawn listeners for all published ports.
    ///
    /// Listeners are only spawned when at least one of `guest_ipv4` /
    /// `guest_ipv6` is `Some`; published ports need a smoltcp dial target.
    /// Each TCP listener task gates accepted connections through the
    /// supplied [`NetworkPolicy`]'s `evaluate_ingress` before queuing
    /// them; rejected connections drop with TCP RST (zero-linger) so
    /// the peer observes `ECONNRESET`.
    pub fn new(
        ports: &[PublishedPort],
        guest_ipv4: Option<Ipv4Addr>,
        guest_ipv6: Option<Ipv6Addr>,
        policy: Arc<NetworkPolicy>,
        shared: Arc<SharedState>,
        tokio_handle: &tokio::runtime::Handle,
        cmd_rx: mpsc::UnboundedReceiver<PortCommand>,
    ) -> Self {
        let (inbound_tx, inbound_rx) = mpsc::channel(64);

        let guest_ip = guest_ipv4
            .map(IpAddr::V4)
            .or_else(|| guest_ipv6.map(IpAddr::V6));

        let mut listener_handles: HashMap<(IpAddr, u16), AbortHandle> = HashMap::new();

        if guest_ip.is_some() {
            for port in ports {
                if let Some(handle) = Self::spawn_listener_one(
                    port,
                    &inbound_tx,
                    &policy,
                    &shared,
                    tokio_handle,
                ) {
                    listener_handles.insert((port.host_bind, port.host_port), handle);
                }
            }
        } else if !ports.is_empty() {
            tracing::warn!(
                count = ports.len(),
                "skipping published port listeners: guest has no IPv4 or IPv6 address",
            );
        }

        Self {
            inbound_rx,
            inbound_tx,
            connections: Vec::new(),
            guest_ip,
            ephemeral_port: Arc::new(AtomicU16::new(49152)),
            max_inbound: 256,
            policy,
            shared,
            tokio_handle: tokio_handle.clone(),
            cmd_rx,
            listener_handles,
        }
    }

    /// Apply one runtime command. Called from the poll loop's
    /// accept_inbound tick so spawn/abort runs on the right tokio
    /// handle (the one passed to `new`).
    fn apply_command(&mut self, cmd: PortCommand) {
        match cmd {
            PortCommand::Add {
                listener,
                key,
                guest_port,
            } => {
                if self.guest_ip.is_none() {
                    tracing::warn!(
                        guest_port,
                        "ignoring PortCommand::Add: guest has no IPv4 or IPv6 address",
                    );
                    return;
                }
                if self.listener_handles.contains_key(&key) {
                    tracing::debug!(
                        bind = %key.0,
                        port = key.1,
                        "PortCommand::Add: listener already present, ignoring",
                    );
                    return;
                }
                let handle = Self::spawn_accept_task(
                    listener,
                    guest_port,
                    self.inbound_tx.clone(),
                    self.policy.clone(),
                    self.shared.clone(),
                    &self.tokio_handle,
                );
                self.listener_handles.insert(key, handle);
            }
            PortCommand::Remove { host_bind, host_port } => {
                if let Some(handle) = self.listener_handles.remove(&(host_bind, host_port)) {
                    handle.abort();
                }
            }
        }
    }

    /// Snapshot of currently-active listeners. Mostly for tests and
    /// the auto-publish loop's bookkeeping.
    pub fn active_listeners(&self) -> Vec<(IpAddr, u16)> {
        self.listener_handles.keys().copied().collect()
    }

    /// Accept queued inbound connections: create smoltcp sockets and
    /// initiate connections to the guest.
    ///
    /// Also drains pending [`PortCommand`]s at the head of the tick
    /// so runtime add/remove takes effect before any new connections
    /// land. Must be called each poll iteration.
    pub fn accept_inbound(
        &mut self,
        iface: &mut Interface,
        sockets: &mut SocketSet<'_>,
        shared: &Arc<SharedState>,
        tokio_handle: &tokio::runtime::Handle,
    ) {
        // Apply pending runtime commands first so an Add becomes
        // observable on the very next inbound_rx.try_recv() (no need
        // to wait another smoltcp tick).
        while let Ok(cmd) = self.cmd_rx.try_recv() {
            self.apply_command(cmd);
        }

        // No guest IP means listeners weren't spawned; the channel is empty
        // and there's nothing to do.
        let Some(guest_ip) = self.guest_ip else {
            return;
        };

        while let Ok(conn) = self.inbound_rx.try_recv() {
            if self.connections.len() >= self.max_inbound {
                tracing::debug!("published port: max inbound connections reached, rejecting");
                reject_with_rst(&conn.stream);
                continue;
            }
            // Create smoltcp TCP socket.
            let rx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUF_SIZE]);
            let tx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUF_SIZE]);
            let mut socket = tcp::Socket::new(rx_buf, tx_buf);

            // Connect to the guest.
            let remote = IpEndpoint::new(guest_ip.into(), conn.guest_port);
            let local_port = self.alloc_ephemeral_port();

            if socket.connect(iface.context(), remote, local_port).is_err() {
                tracing::debug!(
                    guest_port = conn.guest_port,
                    "failed to connect smoltcp socket to guest",
                );
                reject_with_rst(&conn.stream);
                continue;
            }

            let handle = sockets.add(socket);

            // Create channel pair for relay.
            let (to_host_tx, to_host_rx) = mpsc::channel(CHANNEL_CAPACITY);
            let (from_host_tx, from_host_rx) = mpsc::channel(CHANNEL_CAPACITY);

            // Spawn relay task: host TcpStream ↔ channels.
            let shared_clone = shared.clone();
            tokio_handle.spawn(async move {
                let _ =
                    inbound_relay_task(conn.stream, to_host_rx, from_host_tx, shared_clone).await;
            });

            self.connections.push(InboundRelay {
                handle,
                to_host: to_host_tx,
                from_host: from_host_rx,
                write_buf: None,
                close_attempts: 0,
            });
        }
    }

    /// Relay data between smoltcp sockets and host relay tasks.
    pub fn relay_data(&mut self, sockets: &mut SocketSet<'_>) {
        let mut relay_buf = [0u8; RELAY_BUF_SIZE];

        for relay in &mut self.connections {
            let socket = sockets.get_mut::<tcp::Socket>(relay.handle);

            // Detect relay task exit — close the smoltcp socket.
            if relay.to_host.is_closed() {
                write_host_data(socket, relay);
                if relay.write_buf.is_none() {
                    socket.close();
                } else {
                    // Abort if we've been trying to flush for too long
                    // (guest stopped reading, socket send buffer full).
                    relay.close_attempts += 1;
                    if relay.close_attempts >= DEFERRED_CLOSE_LIMIT {
                        socket.abort();
                    }
                }
                continue;
            }

            // smoltcp → host: read from socket, send via channel.
            while socket.can_recv() {
                match socket.recv_slice(&mut relay_buf) {
                    Ok(n) if n > 0 => {
                        let data = Bytes::copy_from_slice(&relay_buf[..n]);
                        if relay.to_host.try_send(data).is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }

            // host → smoltcp: write pending data, then drain channel.
            write_host_data(socket, relay);
        }
    }

    /// Remove closed inbound connections.
    ///
    /// Only removes sockets in `Closed` state. Sockets in `TimeWait` are
    /// left for smoltcp's 2*MSL timer to handle naturally.
    pub fn cleanup_closed(&mut self, sockets: &mut SocketSet<'_>) {
        self.connections.retain(|relay| {
            let socket = sockets.get::<tcp::Socket>(relay.handle);
            let closed = matches!(socket.state(), tcp::State::Closed);
            if closed {
                sockets.remove(relay.handle);
            }
            !closed
        });
    }

    /// Boot-time listener spawn for a declared `--publish` port.
    ///
    /// Binds synchronously (via `std::net::TcpListener::bind` +
    /// `tokio::net::TcpListener::from_std`) so the caller can
    /// distinguish bind success from failure BEFORE registering an
    /// `AbortHandle` in `listener_handles`. Without that ordering, a
    /// failed bind would still leave the (host_bind, host_port) key
    /// occupied in the handle map, blocking any future
    /// `PortCommand::Add` for the same key forever (apply_command
    /// rejects duplicates with `contains_key`).
    ///
    /// `PortPublisher::new` runs on the smoltcp poll thread, which
    /// is not a tokio context — std bind + `from_std` lets us turn
    /// the result into a tokio listener without entering the
    /// runtime ourselves.
    ///
    /// Returns `None` for non-TCP ports (UDP listener support is
    /// still TODO) and for binds that failed (the error is logged
    /// here so callers don't have to).
    fn spawn_listener_one(
        port: &PublishedPort,
        inbound_tx: &mpsc::Sender<InboundConnection>,
        policy: &Arc<NetworkPolicy>,
        shared: &Arc<SharedState>,
        tokio_handle: &tokio::runtime::Handle,
    ) -> Option<AbortHandle> {
        if port.protocol != PortProtocol::Tcp {
            // TODO: UDP published ports.
            return None;
        }
        let bind_addr = SocketAddr::new(port.host_bind, port.host_port);
        let std_listener = match std::net::TcpListener::bind(bind_addr) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(
                    bind = %bind_addr,
                    error = %e,
                    "published port listener failed to bind",
                );
                return None;
            }
        };
        if let Err(e) = std_listener.set_nonblocking(true) {
            tracing::error!(
                bind = %bind_addr,
                error = %e,
                "published port listener: set_nonblocking failed",
            );
            return None;
        }
        let listener = match TcpListener::from_std(std_listener) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(
                    bind = %bind_addr,
                    error = %e,
                    "published port listener: from_std failed",
                );
                return None;
            }
        };
        tracing::debug!(bind = %bind_addr, guest_port = port.guest_port, "published port listener started");
        Some(Self::spawn_accept_task(
            listener,
            port.guest_port,
            inbound_tx.clone(),
            policy.clone(),
            shared.clone(),
            tokio_handle,
        ))
    }

    /// Runtime listener spawn from a pre-bound `TcpListener`. Used
    /// by [`PortCommand::Add`].
    fn spawn_accept_task(
        listener: TcpListener,
        guest_port: u16,
        inbound_tx: mpsc::Sender<InboundConnection>,
        policy: Arc<NetworkPolicy>,
        shared: Arc<SharedState>,
        tokio_handle: &tokio::runtime::Handle,
    ) -> AbortHandle {
        let join = tokio_handle.spawn(async move {
            run_accept_loop(listener, guest_port, inbound_tx, policy, shared).await;
        });
        join.abort_handle()
    }

    fn alloc_ephemeral_port(&self) -> u16 {
        loop {
            let port = self.ephemeral_port.fetch_add(1, Ordering::Relaxed);
            // Wrap around in the ephemeral range.
            if port == 0 || port < 49152 {
                self.ephemeral_port.store(49152, Ordering::Relaxed);
                continue;
            }
            return port;
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Accept loop: read connections from a bound TCP listener, gate
/// each through the network policy's ingress evaluator, and queue
/// allowed connections for the publisher's accept loop. Denied
/// connections are dropped with TCP RST (zero-linger) so the peer
/// sees `ECONNRESET` rather than a graceful close.
///
/// Returns when the publisher drops `inbound_tx` (so the parent
/// poll loop is gone) or when the listener errors. Caller logs.
///
/// `accept()` errors get exponential backoff (capped) — `EMFILE` /
/// `ENFILE` / `EBADF` are sticky and would otherwise hot-spin the
/// loop. Backoff resets on the next successful accept.
async fn run_accept_loop(
    listener: TcpListener,
    guest_port: u16,
    inbound_tx: mpsc::Sender<InboundConnection>,
    policy: Arc<NetworkPolicy>,
    shared: Arc<SharedState>,
) {
    let mut backoff = ACCEPT_BACKOFF_INITIAL;
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(p) => {
                backoff = ACCEPT_BACKOFF_INITIAL;
                p
            }
            Err(e) => {
                tracing::warn!(error = %e, ?backoff, "published port: accept failed, backing off");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(ACCEPT_BACKOFF_MAX);
                continue;
            }
        };

        // Policy gate: peer source IP and the guest's listening port.
        let action = policy.evaluate_ingress(peer, guest_port, Protocol::Tcp, &shared);
        if action.is_deny() {
            tracing::debug!(
                peer = %peer,
                guest_port,
                "ingress denied by policy; sending RST",
            );
            reject_with_rst(&stream);
            drop(stream);
            continue;
        }

        let conn = InboundConnection { stream, guest_port };
        if inbound_tx.send(conn).await.is_err() {
            break; // Publisher dropped.
        }
    }
}

/// Relay task: bridges a host TcpStream to channels connected to smoltcp.
async fn inbound_relay_task(
    stream: TcpStream,
    mut to_host_rx: mpsc::Receiver<Bytes>,
    from_host_tx: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
) -> std::io::Result<()> {
    let (mut rx, mut tx) = stream.into_split();
    let mut buf = vec![0u8; RELAY_BUF_SIZE];

    loop {
        tokio::select! {
            // smoltcp → host: data from guest arrives via channel.
            data = to_host_rx.recv() => {
                match data {
                    Some(bytes) => {
                        if let Err(e) = tx.write_all(&bytes).await {
                            tracing::debug!(error = %e, "write to host client failed");
                            break;
                        }
                    }
                    None => break,
                }
            }

            // host → smoltcp: data from host client to write to guest.
            result = rx.read(&mut buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        let data = Bytes::copy_from_slice(&buf[..n]);
                        if from_host_tx.send(data).await.is_err() {
                            break;
                        }
                        shared.proxy_wake.wake();
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "read from host client failed");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Write data from the host relay channel to the smoltcp socket.
fn write_host_data(socket: &mut tcp::Socket<'_>, relay: &mut InboundRelay) {
    // First, try to finish writing any pending partial data.
    if let Some((data, offset)) = &mut relay.write_buf {
        if socket.can_send() {
            match socket.send_slice(&data[*offset..]) {
                Ok(written) => {
                    *offset += written;
                    if *offset >= data.len() {
                        relay.write_buf = None;
                    }
                }
                Err(_) => return,
            }
        } else {
            return;
        }
    }

    // Then drain the channel.
    while relay.write_buf.is_none() {
        match relay.from_host.try_recv() {
            Ok(data) => {
                if socket.can_send() {
                    match socket.send_slice(&data) {
                        Ok(written) if written < data.len() => {
                            relay.write_buf = Some((data, written));
                        }
                        Err(_) => {
                            relay.write_buf = Some((data, 0));
                        }
                        _ => {}
                    }
                } else {
                    relay.write_buf = Some((data, 0));
                }
            }
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PortProtocol;
    use std::net::Ipv4Addr;

    /// Regression for the "stale AbortHandle on bind failure" bug:
    /// when the boot-time bind fails, spawn_listener_one must
    /// return `None` so the caller doesn't register a dead handle
    /// in `listener_handles`. Otherwise the (host_bind, host_port)
    /// key would stay "occupied" forever and block every future
    /// PortCommand::Add for that key.
    #[tokio::test]
    async fn spawn_listener_one_returns_none_when_bind_fails() {
        // Bind the port first so the helper's bind fails.
        let blocker = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = blocker.local_addr().unwrap().port();

        let policy = Arc::new(NetworkPolicy::default());
        let shared = Arc::new(SharedState::new(crate::shared::DEFAULT_QUEUE_CAPACITY));
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let pp = PublishedPort {
            host_port: port,
            guest_port: 80,
            protocol: PortProtocol::Tcp,
            host_bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        };
        let handle =
            PortPublisher::spawn_listener_one(&pp, &tx, &policy, &shared, &tokio::runtime::Handle::current());
        assert!(handle.is_none(), "bind to a busy port must not register a handle");
        drop(blocker);
    }

    /// Companion: a successful bind DOES return a handle, AND the
    /// task that handle aborts is the accept loop (verified by
    /// rebinding the same port after abort).
    #[tokio::test]
    async fn spawn_listener_one_returns_abortable_handle_on_success() {
        let probe = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let policy = Arc::new(NetworkPolicy::default());
        let shared = Arc::new(SharedState::new(crate::shared::DEFAULT_QUEUE_CAPACITY));
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let pp = PublishedPort {
            host_port: port,
            guest_port: 80,
            protocol: PortProtocol::Tcp,
            host_bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        };
        let handle =
            PortPublisher::spawn_listener_one(&pp, &tx, &policy, &shared, &tokio::runtime::Handle::current())
                .expect("bind should succeed on free port");
        handle.abort();
        // Yield so the abort actually takes effect and the
        // TcpListener inside the task drops, releasing the port.
        tokio::task::yield_now().await;
        // A best-effort rebind after a short retry — without
        // SO_REUSEADDR the kernel may briefly hold the port in
        // TIME_WAIT, but for a never-accepted listener the abort
        // releases it immediately.
        let rebound = tokio::net::TcpListener::bind(("127.0.0.1", port)).await;
        assert!(rebound.is_ok(), "port should be re-bindable after abort");
    }
}
