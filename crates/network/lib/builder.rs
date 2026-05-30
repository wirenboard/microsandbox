//! Fluent builder API for [`NetworkConfig`].
//!
//! Used by `SandboxBuilder::network(|n| n.port(8080, 80).policy(...))`.

use std::net::IpAddr;
use std::path::PathBuf;

use ipnetwork::{Ipv4Network, Ipv6Network};

use crate::config::{
    AutoPublishConfig, DnsConfig, InterfaceOverrides, NetworkConfig, PortProtocol, PublishedPort,
};
use crate::dns::Nameserver;
use crate::intercept::config::{InterceptConfig, InterceptRule};
use crate::policy::{
    BuildError, Destination, DestinationGroup, NetworkPolicy, Rule,
};
use crate::secrets::config::{
    HostPattern, SecretEntry, SecretInjection, SecretValue, ViolationAction,
};
use crate::tls::TlsConfig;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fluent builder for [`NetworkConfig`].
#[derive(Clone)]
pub struct NetworkBuilder {
    config: NetworkConfig,
    errors: Vec<BuildError>,
}

/// Fluent builder for [`DnsConfig`].
pub struct DnsBuilder {
    config: DnsConfig,
}

/// Fluent builder for [`TlsConfig`].
pub struct TlsBuilder {
    config: TlsConfig,
}

/// Fluent builder for a single [`SecretEntry`].
///
/// ```ignore
/// SecretBuilder::new()
///     .env("OPENAI_API_KEY")
///     .value(api_key)
///     .allow_host("api.openai.com")
///     .build()
/// ```
pub struct SecretBuilder {
    env_var: Option<String>,
    value: Option<SecretValue>,
    placeholder: Option<String>,
    allowed_hosts: Vec<HostPattern>,
    injection: SecretInjection,
    require_tls_identity: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl NetworkBuilder {
    /// Start building a network configuration with defaults.
    pub fn new() -> Self {
        Self {
            config: NetworkConfig::default(),
            errors: Vec::new(),
        }
    }

    /// Start building from an existing network configuration.
    pub fn from_config(config: NetworkConfig) -> Self {
        Self {
            config,
            errors: Vec::new(),
        }
    }

    /// Enable or disable networking.
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    /// Publish a TCP port: `host_port` on the host maps to `guest_port` in the guest.
    pub fn port(self, host_port: u16, guest_port: u16) -> Self {
        self.port_bind(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            host_port,
            guest_port,
        )
    }

    /// Publish a UDP port.
    pub fn port_udp(self, host_port: u16, guest_port: u16) -> Self {
        self.port_udp_bind(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            host_port,
            guest_port,
        )
    }

    /// Publish a TCP port on a specific host bind address.
    pub fn port_bind(self, host_bind: IpAddr, host_port: u16, guest_port: u16) -> Self {
        self.add_port(host_bind, host_port, guest_port, PortProtocol::Tcp)
    }

    /// Publish a UDP port on a specific host bind address.
    pub fn port_udp_bind(self, host_bind: IpAddr, host_port: u16, guest_port: u16) -> Self {
        self.add_port(host_bind, host_port, guest_port, PortProtocol::Udp)
    }

    fn add_port(
        mut self,
        host_bind: IpAddr,
        host_port: u16,
        guest_port: u16,
        protocol: PortProtocol,
    ) -> Self {
        self.config.ports.push(PublishedPort {
            host_port,
            guest_port,
            protocol,
            host_bind,
        });
        self
    }

    /// Set the network policy.
    pub fn policy(mut self, policy: NetworkPolicy) -> Self {
        self.config.policy = policy;
        self
    }

    /// Append an egress allow rule for an IP or CIDR — equivalent to
    /// `policy.rules.push(Rule::allow_egress(Destination::Cidr(...)))`.
    ///
    /// The default policy (`NetworkPolicy::public_only`) denies every
    /// destination group except `Public` + DNS. Hosts on RFC1918,
    /// loopback, link-local, and the gateway address are rejected
    /// with ECONNREFUSED at the smoltcp policy gate. This helper lets
    /// the caller punch a hole through that default for one specific
    /// IP/CIDR — typically a dev box on the same LAN as the host.
    ///
    /// Rule is appended (not prepended), so explicit deny rules added
    /// earlier still win. To allow an entire `DestinationGroup` see
    /// [`Self::allow_egress_group`].
    pub fn allow_egress_cidr(mut self, cidr: ipnetwork::IpNetwork) -> Self {
        self.config
            .policy
            .rules
            .push(Rule::allow_egress(Destination::Cidr(cidr)));
        self
    }

    /// Append an egress allow rule for an entire `DestinationGroup`
    /// (Public / Private / Loopback / LinkLocal / Metadata / Host /
    /// Multicast). The most common use is `Private` — equivalent to
    /// switching from `NetworkPolicy::public_only` to
    /// `NetworkPolicy::non_local` without replacing the whole policy.
    pub fn allow_egress_group(mut self, group: DestinationGroup) -> Self {
        self.config
            .policy
            .rules
            .push(Rule::allow_egress(Destination::Group(group)));
        self
    }

    /// Configure DNS interception via a closure.
    ///
    /// ```ignore
    /// .dns(|d| d
    ///     .nameservers(["1.1.1.1".parse::<Nameserver>()?])
    ///     .rebind_protection(false)
    /// )
    /// ```
    pub fn dns(mut self, f: impl FnOnce(DnsBuilder) -> DnsBuilder) -> Self {
        self.config.dns = f(DnsBuilder::new()).build();
        self
    }

    /// Configure TLS interception via a closure.
    pub fn tls(mut self, f: impl FnOnce(TlsBuilder) -> TlsBuilder) -> Self {
        self.config.tls = f(TlsBuilder::new()).build();
        self
    }

    /// Add a secret via a closure builder.
    ///
    /// ```ignore
    /// .secret(|s| s
    ///     .env("OPENAI_API_KEY")
    ///     .value(api_key)
    ///     .allow_host("api.openai.com")
    /// )
    /// ```
    pub fn secret(mut self, f: impl FnOnce(SecretBuilder) -> SecretBuilder) -> Self {
        self.config
            .secrets
            .secrets
            .push(f(SecretBuilder::new()).build());
        self
    }

    /// Shorthand: add a secret with env var, value, placeholder, and allowed host.
    ///
    /// `value` accepts `String`, `&str`, or `PathBuf` (host file whose
    /// contents are re-read at each connection-setup).
    pub fn secret_env(
        mut self,
        env_var: impl Into<String>,
        value: impl Into<SecretValue>,
        placeholder: impl Into<String>,
        allowed_host: impl Into<String>,
    ) -> Self {
        self.config.secrets.secrets.push(SecretEntry {
            env_var: env_var.into(),
            value: value.into(),
            placeholder: placeholder.into(),
            allowed_hosts: vec![HostPattern::Exact(allowed_host.into())],
            injection: SecretInjection::default(),
            require_tls_identity: true,
        });
        self
    }

    /// Set the violation action for secrets.
    pub fn on_secret_violation(mut self, action: ViolationAction) -> Self {
        self.config.secrets.on_violation = action;
        self
    }

    /// Configure the request-interceptor hook.
    ///
    /// `hook` is the subprocess command (argv vector) invoked when a
    /// matched intercepted request is fully buffered. The hook
    /// receives the request bytes on stdin and is expected to write a
    /// complete HTTP response on stdout. Environment variables
    /// `MSB_INTERCEPT_SNI`, `MSB_INTERCEPT_HOST_RULE`,
    /// `MSB_INTERCEPT_METHOD`, `MSB_INTERCEPT_PATH_PREFIX` are set
    /// per invocation so the hook can decide what to do without
    /// re-parsing the request line.
    ///
    /// Each `rule(host, method, path_prefix)` call adds one route to
    /// the match set. Rules are AND-matched (host + method +
    /// path_prefix all must hold) and the first matching rule fires.
    ///
    /// ```ignore
    /// .intercept(|i| i
    ///     .hook(["/usr/local/bin/agent-vm", "intercept-hook"])
    ///     .rule("platform.claude.com", "POST", "/v1/oauth/token")
    ///     .rule("auth.openai.com",     "POST", "/oauth/token"))
    /// ```
    pub fn intercept(mut self, f: impl FnOnce(InterceptBuilder) -> InterceptBuilder) -> Self {
        self.config.intercept = f(InterceptBuilder::default()).build();
        self
    }

    /// Set the maximum number of concurrent connections.
    pub fn max_connections(mut self, max: usize) -> Self {
        self.config.max_connections = Some(max);
        self
    }

    /// Set guest interface overrides.
    pub fn interface(mut self, overrides: InterfaceOverrides) -> Self {
        self.config.interface = overrides;
        self
    }

    /// Set the IPv4 pool used to derive per-sandbox `/30` guest subnets.
    ///
    /// The default is `172.16.0.0/12`. Pools must be at least `/30`.
    pub fn ipv4_pool(mut self, pool: Ipv4Network) -> Self {
        if pool.prefix() > 30 {
            self.errors.push(BuildError::InvalidIpv4Pool {
                raw: pool.to_string(),
            });
        } else {
            self.config.interface.ipv4_pool = Some(pool);
        }
        self
    }

    /// Set the IPv6 pool used to derive per-sandbox `/64` guest prefixes.
    ///
    /// The default is `fd42:6d73:62::/48`. Pools must be at least `/64`.
    pub fn ipv6_pool(mut self, pool: Ipv6Network) -> Self {
        if pool.prefix() > 64 {
            self.errors.push(BuildError::InvalidIpv6Pool {
                raw: pool.to_string(),
            });
        } else {
            self.config.interface.ipv6_pool = Some(pool);
        }
        self
    }

    /// Whether to ship the host's trusted root CAs into the guest at
    /// boot. Default: false. Opt in when running behind a corporate
    /// TLS-inspecting proxy (Cloudflare Warp Zero Trust, Zscaler,
    /// Netskope, ...) whose gateway CA is trusted on the host but
    /// unknown to the guest's stock Mozilla bundle.
    pub fn trust_host_cas(mut self, enabled: bool) -> Self {
        self.config.trust_host_cas = enabled;
        self
    }

    /// Enable auto-publish: the runtime polls the guest's
    /// `/proc/net/tcp{,6}` and mirrors each new LISTEN socket onto
    /// a host listener (Lima-style). Uses default poll interval
    /// (2s) and host bind (`127.0.0.1`). For non-default values
    /// use [`Self::auto_publish_with`].
    pub fn auto_publish(mut self) -> Self {
        self.config.auto_publish = Some(AutoPublishConfig::default());
        self
    }

    /// Enable auto-publish with explicit config (poll interval,
    /// host bind).
    pub fn auto_publish_with(mut self, cfg: AutoPublishConfig) -> Self {
        self.config.auto_publish = Some(cfg);
        self
    }

    /// Consume the builder and return the configuration.
    ///
    /// Surfaces the first [`BuildError`] accumulated by any nested
    /// builder (currently [`DnsBuilder`]). Errors stored on the
    /// network builder itself flow through here too.
    pub fn build(mut self) -> Result<NetworkConfig, BuildError> {
        if let Some(err) = self.errors.drain(..).next() {
            return Err(err);
        }
        Ok(self.config)
    }
}

impl DnsBuilder {
    /// Start building DNS configuration with defaults.
    pub fn new() -> Self {
        Self {
            config: DnsConfig::default(),
        }
    }

    /// Enable or disable DNS rebinding protection. Default: true.
    pub fn rebind_protection(mut self, enabled: bool) -> Self {
        self.config.rebind_protection = enabled;
        self
    }

    /// Set the upstream nameservers to forward queries to. When one or
    /// more are set, the interceptor uses these instead of the
    /// nameservers in the host's `/etc/resolv.conf`. Replaces any
    /// previously-set nameservers. Each element is any type convertible
    /// into [`Nameserver`] (`SocketAddr`, `IpAddr`, or a parsed
    /// string via `"dns.google:53".parse::<Nameserver>()?`).
    pub fn nameservers<I>(mut self, nameservers: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<Nameserver>,
    {
        self.config.nameservers = nameservers.into_iter().map(Into::into).collect();
        self
    }

    /// Set the per-DNS-query timeout in milliseconds. Default: 5000.
    pub fn query_timeout_ms(mut self, ms: u64) -> Self {
        self.config.query_timeout_ms = ms;
        self
    }

    /// Consume the builder and return the configuration.
    pub fn build(self) -> DnsConfig {
        self.config
    }
}

impl Default for DnsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsBuilder {
    /// Start building TLS configuration.
    pub fn new() -> Self {
        Self {
            config: TlsConfig {
                enabled: true,
                ..TlsConfig::default()
            },
        }
    }

    /// Add a domain to the bypass list (no MITM). Supports `*.suffix` wildcards.
    pub fn bypass(mut self, pattern: impl Into<String>) -> Self {
        self.config.bypass.push(pattern.into());
        self
    }

    /// Enable or disable upstream server certificate verification.
    pub fn verify_upstream(mut self, verify: bool) -> Self {
        self.config.verify_upstream = verify;
        self
    }

    /// Set the ports to intercept.
    pub fn intercepted_ports(mut self, ports: Vec<u16>) -> Self {
        self.config.intercepted_ports = ports;
        self
    }

    /// Enable or disable QUIC blocking on intercepted ports.
    pub fn block_quic(mut self, block: bool) -> Self {
        self.config.block_quic_on_intercept = block;
        self
    }

    /// Add a CA certificate PEM file to trust for upstream server verification.
    ///
    /// Useful when the upstream server uses a self-signed or private CA certificate.
    /// Can be called multiple times to add several CAs.
    pub fn upstream_ca_cert(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.upstream_ca_cert.push(path.into());
        self
    }

    /// Set a custom interception CA certificate PEM file path.
    pub fn intercept_ca_cert(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.intercept_ca.cert_path = Some(path.into());
        self
    }

    /// Set a custom interception CA private key PEM file path.
    pub fn intercept_ca_key(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.intercept_ca.key_path = Some(path.into());
        self
    }

    /// Consume the builder and return the configuration.
    pub fn build(self) -> TlsConfig {
        self.config
    }
}

impl SecretBuilder {
    /// Start building a secret.
    pub fn new() -> Self {
        Self {
            env_var: None,
            value: None,
            placeholder: None,
            allowed_hosts: Vec::new(),
            injection: SecretInjection::default(),
            require_tls_identity: true,
        }
    }

    /// Set the environment variable to expose the placeholder as (required).
    pub fn env(mut self, var: impl Into<String>) -> Self {
        self.env_var = Some(var.into());
        self
    }

    /// Set the secret value (required).
    ///
    /// Accepts a literal (`String`, `&str`) or a host file path
    /// (`PathBuf` → `SecretValue::File`). File-backed secrets are
    /// re-read at each connection-setup so a host-rotating credential
    /// is picked up on the next request without re-creating the
    /// sandbox.
    pub fn value(mut self, value: impl Into<SecretValue>) -> Self {
        self.value = Some(value.into());
        self
    }

    /// Set a custom placeholder string.
    /// If not set, auto-generated as `$MSB_<env_var>`.
    pub fn placeholder(mut self, placeholder: impl Into<String>) -> Self {
        self.placeholder = Some(placeholder.into());
        self
    }

    /// Add an allowed host (exact match).
    pub fn allow_host(mut self, host: impl Into<String>) -> Self {
        self.allowed_hosts.push(HostPattern::Exact(host.into()));
        self
    }

    /// Add an allowed host with wildcard pattern (e.g., `*.openai.com`).
    pub fn allow_host_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.allowed_hosts
            .push(HostPattern::Wildcard(pattern.into()));
        self
    }

    /// Allow for any host. **Dangerous**: secret can be exfiltrated to any
    /// destination. Requires explicit acknowledgment.
    pub fn allow_any_host_dangerous(mut self, i_understand_the_risk: bool) -> Self {
        if i_understand_the_risk {
            self.allowed_hosts.push(HostPattern::Any);
        }
        self
    }

    /// Require verified TLS identity before substituting (default: true).
    pub fn require_tls_identity(mut self, enabled: bool) -> Self {
        self.require_tls_identity = enabled;
        self
    }

    /// Configure header injection (default: true).
    pub fn inject_headers(mut self, enabled: bool) -> Self {
        self.injection.headers = enabled;
        self
    }

    /// Configure Basic Auth injection (default: true).
    pub fn inject_basic_auth(mut self, enabled: bool) -> Self {
        self.injection.basic_auth = enabled;
        self
    }

    /// Configure query parameter injection (default: false).
    pub fn inject_query(mut self, enabled: bool) -> Self {
        self.injection.query_params = enabled;
        self
    }

    /// Configure body injection (default: false).
    pub fn inject_body(mut self, enabled: bool) -> Self {
        self.injection.body = enabled;
        self
    }

    /// Consume the builder and return a [`SecretEntry`].
    ///
    /// # Panics
    /// Panics if `env` or `value` was not set.
    pub fn build(self) -> SecretEntry {
        let env_var = self.env_var.expect("SecretBuilder: .env() is required");
        let value = self.value.expect("SecretBuilder: .value() is required");
        let placeholder = self
            .placeholder
            .unwrap_or_else(|| format!("$MSB_{env_var}"));

        SecretEntry {
            env_var,
            value,
            placeholder,
            allowed_hosts: self.allowed_hosts,
            injection: self.injection,
            require_tls_identity: self.require_tls_identity,
        }
    }
}

/// Fluent builder for [`InterceptConfig`].
#[derive(Default)]
pub struct InterceptBuilder {
    config: InterceptConfig,
}

impl InterceptBuilder {
    /// Set the hook command (argv vector). Required for the
    /// interceptor to fire — without it the config stays inert.
    pub fn hook<I, S>(mut self, hook: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.config.hook = Some(hook.into_iter().map(Into::into).collect());
        self
    }

    /// Add one match rule. Multiple calls accumulate. The hook is
    /// invoked once the *full request body* has been buffered (or the
    /// per-request cap is hit).
    pub fn rule(
        mut self,
        host: impl Into<String>,
        method: impl Into<String>,
        path_prefix: impl Into<String>,
    ) -> Self {
        self.config.rules.push(InterceptRule {
            host: host.into(),
            method: method.into(),
            path_prefix: path_prefix.into(),
            dispatch_on_headers: false,
        });
        self
    }

    /// Add a match rule that fires the hook as soon as the request
    /// **headers** are seen — does NOT wait for the body. Use for
    /// path-based allow/deny decisions where the body is irrelevant
    /// (or too large to buffer, e.g. git push pack data).
    ///
    /// The hook signals via stdout: empty = passthrough (proxy
    /// continues streaming, network-secret substitution still applies);
    /// non-empty = synthesized response (same as `rule()`).
    pub fn rule_streaming(
        mut self,
        host: impl Into<String>,
        method: impl Into<String>,
        path_prefix: impl Into<String>,
    ) -> Self {
        self.config.rules.push(InterceptRule {
            host: host.into(),
            method: method.into(),
            path_prefix: path_prefix.into(),
            dispatch_on_headers: true,
        });
        self
    }

    /// Override the per-request buffer ceiling (default 64 KiB).
    pub fn max_request_bytes(mut self, n: usize) -> Self {
        self.config.max_request_bytes = n;
        self
    }

    /// Consume and return the configured [`InterceptConfig`].
    pub fn build(self) -> InterceptConfig {
        self.config
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for NetworkBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for TlsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for SecretBuilder {
    fn default() -> Self {
        Self::new()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Network builder happy path returns the config unchanged.
    #[test]
    fn network_builder_happy_path_returns_config() {
        let cfg = NetworkBuilder::new()
            .dns(|d| d.rebind_protection(false))
            .build()
            .unwrap();
        assert!(!cfg.dns.rebind_protection);
    }

    #[test]
    fn port_bind_sets_host_bind() {
        let bind = "0.0.0.0".parse().unwrap();
        let cfg = NetworkBuilder::new()
            .port_bind(bind, 8080, 80)
            .port_udp_bind(bind, 5353, 53)
            .build()
            .unwrap();

        assert_eq!(cfg.ports[0].host_bind, bind);
        assert_eq!(cfg.ports[0].host_port, 8080);
        assert_eq!(cfg.ports[0].guest_port, 80);
        assert_eq!(cfg.ports[0].protocol, PortProtocol::Tcp);
        assert_eq!(cfg.ports[1].host_bind, bind);
        assert_eq!(cfg.ports[1].protocol, PortProtocol::Udp);
    }

    #[test]
    fn allow_egress_cidr_appends_rule_that_overrides_public_only_deny() {
        // Default policy denies Private (10.0.0.0/8). After calling
        // allow_egress_cidr, evaluate_egress for an IP in the CIDR
        // must return Allow.
        use crate::policy::{Action, NetworkPolicy, Protocol};
        use std::net::SocketAddr;
        let shared = std::sync::Arc::new(crate::shared::SharedState::new(
            crate::shared::DEFAULT_QUEUE_CAPACITY,
        ));
        let cfg = NetworkBuilder::new()
            .allow_egress_cidr("10.100.1.0/24".parse().unwrap())
            .build()
            .unwrap();
        // Sanity: default policy is public_only.
        let default = NetworkPolicy::public_only();
        let target: SocketAddr = "10.100.1.75:80".parse().unwrap();
        assert!(
            default
                .evaluate_egress(target, Protocol::Tcp, &shared)
                == Action::Deny,
            "default public_only must DENY a Private IP"
        );
        assert!(
            cfg.policy
                .evaluate_egress(target, Protocol::Tcp, &shared)
                == Action::Allow,
            "allow_egress_cidr must override the default Deny for IPs in the CIDR"
        );
        // An IP outside the allowed CIDR still gets the default Deny.
        let other: SocketAddr = "192.168.1.1:80".parse().unwrap();
        assert!(
            cfg.policy
                .evaluate_egress(other, Protocol::Tcp, &shared)
                == Action::Deny,
            "allow_egress_cidr must NOT affect IPs outside the CIDR"
        );
    }

    #[test]
    fn allow_egress_group_private_opens_the_whole_lan() {
        // Equivalent to switching from public_only to non_local
        // without replacing the whole policy.
        use crate::policy::{Action, Protocol};
        use std::net::SocketAddr;
        let shared = std::sync::Arc::new(crate::shared::SharedState::new(
            crate::shared::DEFAULT_QUEUE_CAPACITY,
        ));
        let cfg = NetworkBuilder::new()
            .allow_egress_group(DestinationGroup::Private)
            .build()
            .unwrap();
        for ip_port in ["10.0.0.1:80", "172.16.5.5:443", "192.168.1.1:22"] {
            let target: SocketAddr = ip_port.parse().unwrap();
            assert_eq!(
                cfg.policy
                    .evaluate_egress(target, Protocol::Tcp, &shared),
                Action::Allow,
                "allow_egress_group(Private) must allow {ip_port}"
            );
        }
        // Loopback / link-local / metadata still denied — Private
        // group is disjoint from those.
        let metadata: SocketAddr = "169.254.169.254:80".parse().unwrap();
        assert_eq!(
            cfg.policy
                .evaluate_egress(metadata, Protocol::Tcp, &shared),
            Action::Deny,
            "allow_egress_group(Private) must NOT open Metadata"
        );
    }

    #[test]
    fn allow_egress_group_host_opens_the_gateway_only() {
        // --allow-host on the agent-vm side maps to this. The
        // gateway IP is the one resolve_host_dst rewrites to host
        // loopback, so allowing the Host group is what makes
        // `host.microsandbox.internal:<port>` actually reach the
        // host's `127.0.0.1:<port>`.
        use crate::policy::{Action, Protocol};
        use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
        let shared = std::sync::Arc::new(crate::shared::SharedState::new(
            crate::shared::DEFAULT_QUEUE_CAPACITY,
        ));
        // Pretend boot has set the per-sandbox gateway IPs; addr_classify
        // returns Host only for these exact addresses (it checks against
        // SharedState).
        let gw_v4 = Ipv4Addr::new(172, 16, 0, 1);
        let gw_v6: Ipv6Addr = "fd42:6d73:62::1".parse().unwrap();
        shared.set_gateway_ips(Some(gw_v4), Some(gw_v6));

        let cfg = NetworkBuilder::new()
            .allow_egress_group(DestinationGroup::Host)
            .build()
            .unwrap();

        // The gateway IPs (both families) become reachable.
        for target in [
            SocketAddr::new(gw_v4.into(), 8080),
            SocketAddr::new(gw_v6.into(), 8080),
        ] {
            assert_eq!(
                cfg.policy
                    .evaluate_egress(target, Protocol::Tcp, &shared),
                Action::Allow,
                "allow_egress_group(Host) must allow gateway {target}"
            );
        }

        // Non-gateway addresses in the same CIDR are still classified
        // as Private (or whatever), NOT Host, so they remain denied.
        let lan: SocketAddr = "172.16.0.42:80".parse().unwrap();
        assert_eq!(
            cfg.policy.evaluate_egress(lan, Protocol::Tcp, &shared),
            Action::Deny,
            "allow_egress_group(Host) must NOT open the rest of the LAN"
        );
        let host_loopback: SocketAddr = "127.0.0.1:80".parse().unwrap();
        assert_eq!(
            cfg.policy
                .evaluate_egress(host_loopback, Protocol::Tcp, &shared),
            Action::Deny,
            "allow_egress_group(Host) must NOT open the guest's own loopback"
        );
    }
}
