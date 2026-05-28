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
