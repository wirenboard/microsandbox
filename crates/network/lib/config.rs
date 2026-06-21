//! Serializable network configuration types.
//!
//! These types represent the user-facing declarative network configuration
//! for sandbox networking. Designed for the smoltcp in-process engine.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnetwork::{Ipv4Network, Ipv6Network};
use serde::{Deserialize, Serialize};

use crate::dns::Nameserver;

use crate::intercept::config::InterceptConfig;
use crate::policy::NetworkPolicy;
use crate::secrets::config::SecretsConfig;
use crate::tls::TlsConfig;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Complete network configuration for a sandbox.
///
/// Narrowed for the smoltcp in-process engine. Gateway, prefix length, and
/// other host-backend details are engine internals derived from the sandbox
/// slot — the user only specifies what matters: interface overrides, ports,
/// policy, DNS, TLS, and connection limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Whether networking is enabled for this sandbox.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Guest interface overrides. Unset fields derived from sandbox slot.
    #[serde(default)]
    pub interface: InterfaceOverrides,

    /// Host → guest port mappings.
    #[serde(default)]
    pub ports: Vec<PublishedPort>,

    /// Egress/ingress policy rules.
    #[serde(default)]
    pub policy: NetworkPolicy,

    /// DNS interception and filtering settings.
    #[serde(default)]
    pub dns: DnsConfig,

    /// TLS interception settings.
    #[serde(default)]
    pub tls: TlsConfig,

    /// Secret injection settings.
    #[serde(default)]
    pub secrets: SecretsConfig,

    /// Request-interceptor hook. Buffers a matched request and hands it to
    /// a hook subprocess that returns a synthesized response — used e.g. to
    /// MITM an in-VM agent's OAuth refresh-token endpoint so the host can
    /// trigger a real refresh. See
    /// [`InterceptConfig`](crate::intercept::config::InterceptConfig).
    #[serde(default)]
    pub intercept: InterceptConfig,

    /// Max concurrent guest connections. Default: 256.
    #[serde(default)]
    pub max_connections: Option<usize>,

    /// Ship the host's trusted root CAs into the guest at boot so outbound
    /// TLS works behind corporate MITM proxies (Cloudflare Warp Zero
    /// Trust, Zscaler, Netskope, etc.) whose gateway CA is installed on
    /// the host but not shipped in the Mozilla root bundle the guest OS
    /// uses. Opt-in: host trust is not copied into the guest unless
    /// this is explicitly enabled. Default: false.
    #[serde(default)]
    pub trust_host_cas: bool,

    /// Auto-detect TCP LISTEN sockets inside the guest and mirror
    /// each on `127.0.0.1:<same port>` on the host (Lima-style). The
    /// runtime spawns a poll task on top of the smoltcp stack that
    /// reads `/proc/net/tcp{,6}` over the agent.sock channel every
    /// few seconds, diff-drives the [`crate::publisher::PortPublisher`]
    /// via [`PortCommand`](crate::publisher::PortCommand), and emits
    /// `MessageType::PortEvent` frames for SDK clients to observe.
    /// Default: `None` (disabled).
    #[serde(default)]
    pub auto_publish: Option<AutoPublishConfig>,
}

/// Configuration for the runtime auto-publish loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoPublishConfig {
    /// Poll interval in milliseconds. Default 2000 (matches Lima).
    #[serde(default = "default_auto_publish_poll_ms")]
    pub poll_interval_ms: u64,

    /// Host bind address for mirrored listeners. Default `127.0.0.1`.
    #[serde(default = "default_auto_publish_host_bind")]
    pub host_bind: IpAddr,
}

impl Default for AutoPublishConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: default_auto_publish_poll_ms(),
            host_bind: default_auto_publish_host_bind(),
        }
    }
}

fn default_auto_publish_poll_ms() -> u64 {
    2000
}

fn default_auto_publish_host_bind() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

/// Optional overrides for the guest interface.
///
/// If omitted, values are derived deterministically from the sandbox slot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InterfaceOverrides {
    /// Guest MAC address. Default: derived from slot.
    #[serde(default)]
    pub mac: Option<[u8; 6]>,

    /// Interface MTU. Default: 1500.
    #[serde(default)]
    pub mtu: Option<u16>,

    /// Guest IPv4 address. Default: derived from slot within `ipv4_pool`.
    #[serde(default)]
    pub ipv4_address: Option<Ipv4Addr>,

    /// Guest IPv4 pool. Default: derived from slot (172.16.0.0/12 pool).
    #[serde(default)]
    pub ipv4_pool: Option<Ipv4Network>,

    /// Guest IPv6 address. Default: derived from slot within `ipv6_pool`.
    #[serde(default)]
    pub ipv6_address: Option<Ipv6Addr>,

    /// Guest IPv6 pool. Default: derived from slot (fd42:6d73:62::/48 pool).
    #[serde(default)]
    pub ipv6_pool: Option<Ipv6Network>,
}

/// DNS interception settings for the sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Whether DNS rebinding protection is enabled.
    #[serde(default = "default_true")]
    pub rebind_protection: bool,

    /// Nameservers to forward DNS queries to. When empty, fall back to
    /// the `nameserver` entries in the host's `/etc/resolv.conf`. Set
    /// this to pin specific resolvers (e.g. `1.1.1.1:53`, `dns.google`)
    /// or to work around split-DNS / VPN setups where the host's
    /// resolv.conf is incomplete. Accepts IPs, `IP:PORT`, or hostnames
    /// (resolved once at startup via the host's OS resolver).
    #[serde(default)]
    pub nameservers: Vec<Nameserver>,

    /// Per-query timeout in milliseconds. Default: 5000.
    #[serde(default = "default_query_timeout_ms")]
    pub query_timeout_ms: u64,
}

/// A published port mapping between host and guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishedPort {
    /// Host-side port to bind.
    pub host_port: u16,

    /// Guest-side port to forward to.
    pub guest_port: u16,

    /// Protocol (TCP or UDP).
    #[serde(default)]
    pub protocol: PortProtocol,

    /// Host address to bind. Defaults to loopback.
    #[serde(default = "default_host_bind")]
    pub host_bind: IpAddr,
}

/// Protocol for a published port.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortProtocol {
    /// TCP (default).
    #[default]
    #[serde(rename = "tcp", alias = "Tcp")]
    Tcp,

    /// UDP.
    #[serde(rename = "udp", alias = "Udp")]
    Udp,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interface: InterfaceOverrides::default(),
            ports: Vec::new(),
            policy: NetworkPolicy::default(),
            dns: DnsConfig::default(),
            tls: TlsConfig::default(),
            secrets: SecretsConfig::default(),
            intercept: InterceptConfig::default(),
            max_connections: None,
            trust_host_cas: false,
            auto_publish: None,
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            rebind_protection: true,
            nameservers: Vec::new(),
            query_timeout_ms: default_query_timeout_ms(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn default_true() -> bool {
    true
}

fn default_host_bind() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

fn default_query_timeout_ms() -> u64 {
    5000
}

#[cfg(test)]
mod tests {
    use super::PortProtocol;

    #[test]
    fn port_protocol_serializes_lowercase_and_accepts_legacy_case() {
        assert_eq!(
            serde_json::to_string(&PortProtocol::Tcp).unwrap(),
            "\"tcp\""
        );
        assert_eq!(
            serde_json::to_string(&PortProtocol::Udp).unwrap(),
            "\"udp\""
        );
        assert_eq!(
            serde_json::from_str::<PortProtocol>("\"Tcp\"").unwrap(),
            PortProtocol::Tcp
        );
        assert_eq!(
            serde_json::from_str::<PortProtocol>("\"Udp\"").unwrap(),
            PortProtocol::Udp
        );
    }
}
