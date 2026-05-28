//! Runtime side of auto-publish.
//!
//! Spawns a tokio task that loop-polls the guest's
//! `/proc/net/tcp{,6}` via a loopback connection to the relay's
//! agent.sock, diffs the LISTEN set against currently-active host
//! listeners, and drives [`PortPublisher`](microsandbox_network::publisher::PortPublisher)
//! through [`PortCommand`](microsandbox_network::publisher::PortCommand)s.
//!
//! Why the loopback UDS instead of an in-process channel into the
//! relay: the relay already routes framed messages to/from agentd,
//! and giving it a "synthetic client" by opening a UDS to itself is
//! one extra socketpair-equivalent round-trip — far cheaper than
//! extending the relay's internal API to support host-local frame
//! injection. Frames go agentd → ring → relay → loopback UDS → us,
//! same path any SDK client would take.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use microsandbox_network::auto_publish::{
    ListenEntry, needs_loopback_forwarder, parse_listen_v4, parse_listen_v6, should_forward,
};
use microsandbox_network::config::AutoPublishConfig;
use microsandbox_network::publisher::PortCommand;
use microsandbox_protocol::codec::{read_message, write_message};
use microsandbox_protocol::fs::{FsData, FsOp, FsRequest, FsResponse};
use microsandbox_protocol::message::{Message, MessageType};
use microsandbox_protocol::network::{
    LoopbackForwardCancelReq, LoopbackForwardReq, LoopbackForwardResp, PORT_EVENT_BROADCAST_ID,
    PortEvent,
};
use tokio::io::{AsyncReadExt, BufReader};
use tokio::net::{TcpListener, UnixStream};
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::sleep;

/// Spawn the auto-publish background task on the supplied tokio
/// runtime handle.
///
/// Takes the handle explicitly rather than relying on the current
/// tokio context because the caller in `vm.rs` runs in the
/// synchronous startup path, not inside a tokio task.
///
/// `guest_ipv4` is the guest's eth0 IPv4 (or `None` for v6-only
/// sandboxes). Used as the bind address sent to agentd via
/// `LoopbackForwardReq` when a `127.0.0.1`-only LISTEN is
/// detected — agentd binds `guest_ipv4:port` inside the guest so
/// smoltcp's existing dial-to-VLAN-IP path lands on that
/// listener instead of failing against guest loopback.
pub fn spawn(
    runtime: &tokio::runtime::Handle,
    agent_sock_path: PathBuf,
    cfg: AutoPublishConfig,
    port_handle: UnboundedSender<PortCommand>,
    guest_ipv4: Option<std::net::Ipv4Addr>,
    event_broadcast: Arc<dyn EventBroadcast>,
) {
    runtime.spawn(async move {
        if let Err(e) = run(
            &agent_sock_path,
            &cfg,
            &port_handle,
            guest_ipv4,
            &*event_broadcast,
        )
        .await
        {
            tracing::warn!(?e, "auto-publish task exited");
        }
    });
}

/// Abstraction so the runtime can plug its relay-side broadcast in
/// without the network crate (or this module) needing to import the
/// `AgentRelay` type directly. Implementations push the same
/// `PortEvent` frame to every connected SDK client.
pub trait EventBroadcast: Send + Sync {
    /// Push a [`PortEvent`] to every connected SDK client. The
    /// caller already constructed the framed `Message`; the impl
    /// just needs to forward the bytes.
    fn broadcast_port_event(&self, event: PortEvent);
}

/// Bookkeeping for one active mapping. Tracks the host side of
/// the forward (so we can emit a precise `Removed` event later)
/// plus whether agentd is running an in-guest loopback forwarder
/// for this port — only true when the guest LISTEN was
/// `127.0.0.1`-only.
struct ActiveMapping {
    host_bind: IpAddr,
    host_port: u16,
    has_loopback_forwarder: bool,
}

async fn run(
    agent_sock_path: &PathBuf,
    cfg: &AutoPublishConfig,
    port_handle: &UnboundedSender<PortCommand>,
    guest_ipv4: Option<std::net::Ipv4Addr>,
    broadcast: &dyn EventBroadcast,
) -> std::io::Result<()> {
    // Connect a loopback client to the relay. The handshake we
    // consume up front: 4 bytes of `id_offset`, then a Ready frame.
    //
    // `id_offset` is critical here: the ring reader demuxes
    // responses back to the originating slot via `frame.id /
    // ID_RANGE_STEP`. If we pick ids from outside our assigned
    // slot's range, responses get routed to a different client
    // (typically slot 0) and we time out forever waiting for a
    // reply that never arrives. So we use `id_offset + n` as our
    // request ids.
    let mut stream = connect_with_retry(agent_sock_path).await?;
    let mut offset_buf = [0u8; 4];
    stream.read_exact(&mut offset_buf).await?;
    let id_offset = u32::from_be_bytes(offset_buf);
    let mut read_half_tmp = BufReader::new(&mut stream);
    // Consume the Ready frame.
    let ready = read_message(&mut read_half_tmp).await.map_err(io_err)?;
    debug_assert_eq!(ready.t, MessageType::Ready);
    drop(read_half_tmp);

    let (mut read_half, mut write_half) = stream.into_split();
    let mut buf_read = BufReader::new(&mut read_half);

    let host_bind: IpAddr = cfg.host_bind;
    let poll = Duration::from_millis(cfg.poll_interval_ms);

    // Active mappings: guest_port → (host_bind, host_port,
    // is_loopback). `is_loopback` records whether we asked agentd
    // to spawn an in-guest forwarder for this port (so we can
    // cancel it on teardown).
    let mut active: HashMap<u16, ActiveMapping> = HashMap::new();
    // Start at id_offset + 1; id_offset itself is reserved (the
    // relay's id-range math treats `id == 0` as "unassigned").
    let mut next_req_id: u32 = id_offset + 1;

    loop {
        sleep(poll).await;

        let tcp4 = match read_proc(
            "/proc/net/tcp",
            &mut next_req_id,
            &mut write_half,
            &mut buf_read,
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(?e, "auto-publish: read /proc/net/tcp failed");
                continue;
            }
        };
        let tcp6 = read_proc(
            "/proc/net/tcp6",
            &mut next_req_id,
            &mut write_half,
            &mut buf_read,
        )
        .await
        .unwrap_or_default();

        let listening: std::collections::BTreeSet<ListenEntry> = parse_listen_v4(&tcp4)
            .into_iter()
            .chain(parse_listen_v6(&tcp6))
            .filter(|e| should_forward(*e))
            .collect();
        // wanted: guest_port → was it loopback-only? (If the same
        // port appears as both 127.0.0.1 and 0.0.0.0, the
        // wildcard bind wins — no forwarder needed.)
        let mut wanted: std::collections::BTreeMap<u16, bool> =
            std::collections::BTreeMap::new();
        for e in &listening {
            let lb = needs_loopback_forwarder(*e);
            wanted
                .entry(e.port)
                .and_modify(|prev| *prev = *prev && lb)
                .or_insert(lb);
        }

        // ADD: ports newly listening that we haven't mirrored yet.
        let new_ports: Vec<(u16, bool)> = wanted
            .iter()
            .filter(|(p, _)| !active.contains_key(p))
            .map(|(p, lb)| (*p, *lb))
            .collect();
        for (guest_port, is_loopback) in new_ports {
            // For loopback-only guest LISTENs, ask agentd to bring
            // up a forwarder on guest_ipv4:guest_port → 127.0.0.1:
            // guest_port BEFORE the host listener gets wired up.
            // Skipped silently when guest_ipv4 is None (v6-only
            // sandbox) — loopback forwarding for those would need
            // the IPv6 counterpart, not implemented yet.
            let loopback_ok = if is_loopback {
                match guest_ipv4 {
                    Some(addr) => match send_loopback_forward(
                        IpAddr::V4(addr),
                        guest_port,
                        &mut next_req_id,
                        &mut write_half,
                        &mut buf_read,
                    )
                    .await
                    {
                        Ok(()) => true,
                        Err(e) => {
                            tracing::warn!(
                                guest_port, ?e,
                                "auto-publish: LoopbackForward request failed; skipping port",
                            );
                            false
                        }
                    },
                    None => {
                        tracing::debug!(
                            guest_port,
                            "auto-publish: skipping 127.0.0.1 LISTEN on v6-only sandbox",
                        );
                        false
                    }
                }
            } else {
                true
            };
            if !loopback_ok {
                continue;
            }

            match bind_host_for(host_bind, guest_port).await {
                Ok((listener, addr)) => {
                    let key = (addr.ip(), addr.port());
                    if port_handle
                        .send(PortCommand::Add {
                            listener,
                            key,
                            guest_port,
                        })
                        .is_err()
                    {
                        // PortPublisher gone — sandbox shutting down.
                        return Ok(());
                    }
                    active.insert(
                        guest_port,
                        ActiveMapping {
                            host_bind: addr.ip(),
                            host_port: addr.port(),
                            has_loopback_forwarder: is_loopback,
                        },
                    );
                    broadcast.broadcast_port_event(PortEvent::Added {
                        host_bind: addr.ip(),
                        host_port: addr.port(),
                        guest_port,
                    });
                    tracing::info!(
                        guest_port,
                        host_port = addr.port(),
                        loopback = is_loopback,
                        "auto-publish: mapping added",
                    );
                }
                Err(e) => {
                    tracing::warn!(guest_port, ?e, "auto-publish: bind failed");
                    // The loopback forwarder we asked agentd to
                    // spawn would now leak. Cancel it so we don't
                    // accumulate orphans across poll cycles.
                    if is_loopback {
                        let _ = send_loopback_cancel(
                            guest_port,
                            &mut next_req_id,
                            &mut write_half,
                            &mut buf_read,
                        )
                        .await;
                    }
                }
            }
        }

        // REMOVE: previously-active ports that went away.
        let stale: Vec<u16> = active
            .keys()
            .copied()
            .filter(|p| !wanted.contains_key(p))
            .collect();
        for guest_port in stale {
            if let Some(mapping) = active.remove(&guest_port) {
                let _ = port_handle.send(PortCommand::Remove {
                    host_bind: mapping.host_bind,
                    host_port: mapping.host_port,
                });
                if mapping.has_loopback_forwarder {
                    if let Err(e) = send_loopback_cancel(
                        guest_port,
                        &mut next_req_id,
                        &mut write_half,
                        &mut buf_read,
                    )
                    .await
                    {
                        tracing::warn!(
                            guest_port, ?e,
                            "auto-publish: LoopbackForwardCancel failed (forwarder may leak)",
                        );
                    }
                }
                broadcast.broadcast_port_event(PortEvent::Removed {
                    host_bind: mapping.host_bind,
                    host_port: mapping.host_port,
                    guest_port,
                });
                tracing::info!(
                    guest_port,
                    host_port = mapping.host_port,
                    "auto-publish: mapping removed",
                );
            }
        }

        let _ = PORT_EVENT_BROADCAST_ID; // keep the import live; broadcast impl uses it.
    }
}

/// Try to bind `(host_bind, guest_port)` first so the host port
/// mirrors the guest port (Lima-ish). If that's taken, fall back to
/// an OS-assigned ephemeral port.
async fn bind_host_for(
    host_bind: IpAddr,
    guest_port: u16,
) -> std::io::Result<(TcpListener, SocketAddr)> {
    let preferred = SocketAddr::new(host_bind, guest_port);
    if let Ok(l) = TcpListener::bind(preferred).await {
        let addr = l.local_addr()?;
        return Ok((l, addr));
    }
    let any = SocketAddr::new(host_bind, 0);
    let l = TcpListener::bind(any).await?;
    let addr = l.local_addr()?;
    Ok((l, addr))
}

async fn connect_with_retry(path: &PathBuf) -> std::io::Result<UnixStream> {
    // The agent.sock listener is up before the auto-publish task
    // spawns (vm.rs orders this), but guard against early-boot
    // races where the listener hasn't yet bound on a slow host.
    let mut backoff = Duration::from_millis(50);
    for _ in 0..20 {
        match UnixStream::connect(path).await {
            Ok(s) => return Ok(s),
            Err(_) => {
                sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_millis(500));
            }
        }
    }
    UnixStream::connect(path).await
}

async fn read_proc(
    path: &str,
    next_req_id: &mut u32,
    write_half: &mut tokio::net::unix::OwnedWriteHalf,
    read_half: &mut BufReader<&mut tokio::net::unix::OwnedReadHalf>,
) -> std::io::Result<String> {
    let id = *next_req_id;
    *next_req_id = next_req_id.wrapping_add(1);
    let req = FsRequest {
        op: FsOp::Read {
            path: path.to_string(),
        },
    };
    let msg = Message::with_payload(MessageType::FsRequest, id, &req).map_err(io_err)?;
    write_message(write_half, &msg).await.map_err(io_err)?;

    let mut out = Vec::new();
    loop {
        let msg = read_message(read_half).await.map_err(io_err)?;
        if msg.id != id {
            // Not our reply (shouldn't happen on a private client,
            // but be defensive).
            continue;
        }
        match msg.t {
            MessageType::FsData => {
                let chunk: FsData = msg.payload().map_err(io_err)?;
                out.extend_from_slice(&chunk.data);
            }
            MessageType::FsResponse => {
                let resp: FsResponse = msg.payload().map_err(io_err)?;
                if !resp.ok {
                    return Err(std::io::Error::other(
                        resp.error.unwrap_or_else(|| "fs read failed".into()),
                    ));
                }
                break;
            }
            _ => {}
        }
    }
    String::from_utf8(out).map_err(|e| std::io::Error::other(format!("utf-8: {e}")))
}

async fn send_loopback_forward(
    bind_addr: IpAddr,
    port: u16,
    next_req_id: &mut u32,
    write_half: &mut tokio::net::unix::OwnedWriteHalf,
    read_half: &mut BufReader<&mut tokio::net::unix::OwnedReadHalf>,
) -> std::io::Result<()> {
    let req = LoopbackForwardReq { bind_addr, port };
    send_loopback_req(
        MessageType::LoopbackForward,
        &req,
        next_req_id,
        write_half,
        read_half,
    )
    .await
}

async fn send_loopback_cancel(
    port: u16,
    next_req_id: &mut u32,
    write_half: &mut tokio::net::unix::OwnedWriteHalf,
    read_half: &mut BufReader<&mut tokio::net::unix::OwnedReadHalf>,
) -> std::io::Result<()> {
    let req = LoopbackForwardCancelReq { port };
    send_loopback_req(
        MessageType::LoopbackForwardCancel,
        &req,
        next_req_id,
        write_half,
        read_half,
    )
    .await
}

async fn send_loopback_req<T: serde::Serialize>(
    msg_type: MessageType,
    payload: &T,
    next_req_id: &mut u32,
    write_half: &mut tokio::net::unix::OwnedWriteHalf,
    read_half: &mut BufReader<&mut tokio::net::unix::OwnedReadHalf>,
) -> std::io::Result<()> {
    let id = *next_req_id;
    *next_req_id = next_req_id.wrapping_add(1);
    let msg = Message::with_payload(msg_type, id, payload).map_err(io_err)?;
    write_message(write_half, &msg).await.map_err(io_err)?;

    loop {
        let reply = read_message(read_half).await.map_err(io_err)?;
        if reply.id != id {
            continue;
        }
        if reply.t != MessageType::LoopbackForwardResp {
            return Err(std::io::Error::other(format!(
                "unexpected reply type for loopback req: {:?}",
                reply.t
            )));
        }
        let resp: LoopbackForwardResp = reply.payload().map_err(io_err)?;
        if !resp.ok {
            return Err(std::io::Error::other(
                resp.error.unwrap_or_else(|| "agentd refused request".into()),
            ));
        }
        return Ok(());
    }
}

fn io_err<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}
