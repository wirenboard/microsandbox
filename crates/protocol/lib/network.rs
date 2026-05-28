//! Host ↔ host protocol messages for runtime port-forwarding events.
//!
//! These messages travel guest-side → relay → SDK over the same
//! agent.sock framing the exec/fs traffic uses. They are emitted by
//! the host-side smoltcp `PortPublisher` (not by agentd in the
//! guest) — the relay's host-local dispatch path injects them into
//! the outbound frame stream so subscribed SDK clients see them as
//! pushed events on a reserved correlation ID.
//!
//! Today only `PortEvent` exists; the design leaves room for the
//! reverse direction (SDK→host `PortAddRequest`/`PortRemoveRequest`)
//! when explicit declarative `--publish` migrates onto the same
//! channel.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Reserved correlation ID for the broadcast PortEvent stream.
///
/// The relay sends `PortEvent` frames on this id regardless of any
/// request id. SDK clients subscribe by reading from this id offset.
/// Picked at the top of the reserved range so a stray client-issued
/// id collision is unlikely.
pub const PORT_EVENT_BROADCAST_ID: u32 = u32::MAX - 1;

/// Host → agentd: spawn an in-guest loopback forwarder that binds
/// `bind_addr:port` (typically the guest's eth0 IPv4) and forwards
/// each accepted connection to `127.0.0.1:port` inside the guest.
///
/// Why this exists: the smoltcp `PortPublisher` dials the guest's
/// VLAN address from outside the guest. A guest service bound only
/// to `127.0.0.1` is not reachable by that dial — the guest kernel
/// won't route packets received on the NIC to `lo` (martian source).
/// The forwarder lets us recover Lima-style "127.0.0.1 in the guest
/// is reachable from the host" without an iptables/route_localnet
/// path (the guest kernel has no netfilter). agentd terminates the
/// inbound TCP on the NIC and re-dials loopback from inside, exactly
/// like Lima's guestagent does.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoopbackForwardReq {
    /// In-guest bind address for the forwarder's listener. Usually
    /// the guest's eth0 IPv4 (or IPv6) so the smoltcp publisher's
    /// existing dial-to-guest-VLAN-IP path lands here.
    pub bind_addr: IpAddr,
    /// Port to bind on the guest side AND the loopback port to
    /// re-dial. Both sides use the same number — the listener and
    /// the loopback target are on different specific addresses, so
    /// a guest app bound to `127.0.0.1:port` and the forwarder
    /// bound to `eth0_ip:port` do not collide.
    pub port: u16,
}

/// Host → agentd: stop a previously-spawned forwarder.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoopbackForwardCancelReq {
    /// The `port` from the matching [`LoopbackForwardReq`].
    pub port: u16,
}

/// agentd → host: ack for a LoopbackForward / LoopbackForwardCancel.
/// Terminal (last frame for the correlation ID).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoopbackForwardResp {
    /// True if the operation succeeded.
    pub ok: bool,
    /// Free-form error string when `ok == false`.
    #[serde(default)]
    pub error: Option<String>,
}

/// Per-event payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PortEvent {
    /// A new host listener was bound for a guest-side LISTEN socket.
    Added {
        /// Host-side bind address (today always `127.0.0.1`).
        host_bind: IpAddr,
        /// Host-side port (mirrors `guest_port` when free, else
        /// ephemeral).
        host_port: u16,
        /// Guest-side LISTEN port that triggered the mapping.
        guest_port: u16,
    },
    /// A previously-Added mapping was torn down (the guest LISTEN
    /// went away).
    Removed {
        /// The host bind address from the matching `Added`.
        host_bind: IpAddr,
        /// The host port from the matching `Added`.
        host_port: u16,
        /// The guest port from the matching `Added`.
        guest_port: u16,
    },
}
