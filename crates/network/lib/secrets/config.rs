//! Secret injection configuration types.

use std::path::PathBuf;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Configuration for secret injection in a sandbox.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretsConfig {
    /// List of secrets to inject.
    #[serde(default)]
    pub secrets: Vec<SecretEntry>,

    /// Action on secret violation (placeholder leaked to disallowed host).
    #[serde(default)]
    pub on_violation: ViolationAction,
}

/// Source for a secret's real value. The value never enters the sandbox.
///
/// `Static` captures the bytes at builder time; `File` re-reads the host
/// file at *connection-setup* time, allowing the value to change over the
/// lifetime of the running sandbox (e.g. a host-side credential file
/// rotated by another process). The connection-scoped caching means a
/// single in-flight request always sees a consistent value even if the
/// file changes mid-stream.
///
/// ## Wire format
///
/// The on-the-wire form is a single string so the network engine's
/// serialized [`crate::config::NetworkConfig`] stays backward-compatible
/// with a `msb` daemon built before this enum existed:
///
/// - `Static(v)`        ↔ `v`                                (bare string)
/// - `File(p)`          ↔ `"\0msbfile:<path>"`               (NUL-prefixed sentinel)
///
/// API tokens are always printable ASCII, so the NUL prefix can't collide
/// with a legitimate static value. Old daemons that don't recognise the
/// sentinel will treat the whole string (including the NUL) as a static
/// value and substitute it verbatim — broken for `File`, but never
/// crashes. Phase 3 of agent-vm uses only `Static`, so the path stays
/// fully compatible until we ship a daemon that understands the sentinel.
#[derive(Clone)]
pub enum SecretValue {
    /// Literal value captured at builder time.
    Static(String),
    /// Path to a host file whose contents (trailing whitespace trimmed)
    /// are read on each new connection that matches this secret. Reads
    /// happen on the host's filesystem and never enter the sandbox.
    File(PathBuf),
}

const FILE_SENTINEL_PREFIX: &str = "\0msbfile:";

impl SecretValue {
    /// Resolve to the current secret bytes. For `Static` returns the
    /// captured string verbatim; for `File` reads from disk and trims
    /// trailing ASCII whitespace (a `\n` from editors is the common
    /// case).
    pub fn resolve(&self) -> std::io::Result<String> {
        match self {
            SecretValue::Static(s) => Ok(s.clone()),
            SecretValue::File(p) => {
                let mut s = std::fs::read_to_string(p)?;
                while matches!(s.as_bytes().last(), Some(b) if b.is_ascii_whitespace()) {
                    s.pop();
                }
                Ok(s)
            }
        }
    }
}

impl From<String> for SecretValue {
    fn from(s: String) -> Self {
        SecretValue::Static(s)
    }
}

impl From<&str> for SecretValue {
    fn from(s: &str) -> Self {
        SecretValue::Static(s.to_string())
    }
}

impl From<PathBuf> for SecretValue {
    fn from(p: PathBuf) -> Self {
        SecretValue::File(p)
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretValue::Static(_) => f.write_str("SecretValue::Static([REDACTED])"),
            SecretValue::File(p) => write!(f, "SecretValue::File({})", p.display()),
        }
    }
}

impl Serialize for SecretValue {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        match self {
            SecretValue::Static(v) => ser.serialize_str(v),
            SecretValue::File(p) => {
                let encoded = format!("{FILE_SENTINEL_PREFIX}{}", p.display());
                ser.serialize_str(&encoded)
            }
        }
    }
}

impl<'de> Deserialize<'de> for SecretValue {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        if let Some(rest) = s.strip_prefix(FILE_SENTINEL_PREFIX) {
            Ok(SecretValue::File(PathBuf::from(rest)))
        } else {
            Ok(SecretValue::Static(s))
        }
    }
}

/// A single secret entry (serializable form passed to the network engine).
#[derive(Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    /// Environment variable name exposed to the sandbox (holds the placeholder).
    pub env_var: String,

    /// The actual secret value (never enters the sandbox).
    pub value: SecretValue,

    /// Placeholder string the sandbox sees instead of the real value.
    pub placeholder: String,

    /// Hosts allowed to receive this secret.
    #[serde(default)]
    pub allowed_hosts: Vec<HostPattern>,

    /// Where the secret can be injected.
    #[serde(default)]
    pub injection: SecretInjection,

    /// Require verified TLS identity before substituting (default: true).
    /// When true, secret is only substituted if the connection uses TLS
    /// interception (not bypass) and the SNI matches an allowed host.
    #[serde(default = "default_true")]
    pub require_tls_identity: bool,
}

/// Host pattern for secret allowlist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HostPattern {
    /// Exact hostname match.
    Exact(String),
    /// Wildcard match (e.g., `*.openai.com`).
    Wildcard(String),
    /// Any host (dangerous — secret can be exfiltrated).
    Any,
}

/// Where in the HTTP request the secret can be injected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretInjection {
    /// Substitute in HTTP headers (default: true).
    #[serde(default = "default_true")]
    pub headers: bool,

    /// Substitute in HTTP Basic Auth (default: true).
    #[serde(default = "default_true")]
    pub basic_auth: bool,

    /// Substitute in URL query parameters (default: false).
    #[serde(default)]
    pub query_params: bool,

    /// Substitute in request body (default: false).
    #[serde(default)]
    pub body: bool,
}

/// Action when a secret placeholder is detected going to a disallowed host.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum ViolationAction {
    /// Block the request silently.
    Block,
    /// Block and log (default).
    #[default]
    BlockAndLog,
    /// Block and terminate the sandbox.
    BlockAndTerminate,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl std::fmt::Debug for SecretEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretEntry")
            .field("env_var", &self.env_var)
            .field("value", &"[REDACTED]")
            .field("placeholder", &self.placeholder)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("injection", &self.injection)
            .field("require_tls_identity", &self.require_tls_identity)
            .finish()
    }
}

impl HostPattern {
    /// Check if a hostname matches this pattern.
    ///
    /// Uses ASCII case-insensitive comparison to avoid `to_lowercase()`
    /// allocations (DNS hostnames are ASCII per RFC 4343).
    pub fn matches(&self, hostname: &str) -> bool {
        match self {
            HostPattern::Exact(h) => hostname.eq_ignore_ascii_case(h),
            HostPattern::Wildcard(pattern) => {
                if let Some(suffix) = pattern.strip_prefix("*.") {
                    hostname.eq_ignore_ascii_case(suffix)
                        || (hostname.len() > suffix.len() + 1
                            && hostname.as_bytes()[hostname.len() - suffix.len() - 1] == b'.'
                            && hostname[hostname.len() - suffix.len()..]
                                .eq_ignore_ascii_case(suffix))
                } else {
                    hostname.eq_ignore_ascii_case(pattern)
                }
            }
            HostPattern::Any => true,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for SecretInjection {
    fn default() -> Self {
        Self {
            headers: true,
            basic_auth: true,
            query_params: false,
            body: false,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn default_true() -> bool {
    true
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_host_match() {
        let p = HostPattern::Exact("api.openai.com".into());
        assert!(p.matches("api.openai.com"));
        assert!(p.matches("API.OpenAI.com"));
        assert!(!p.matches("evil.com"));
    }

    #[test]
    fn wildcard_host_match() {
        let p = HostPattern::Wildcard("*.openai.com".into());
        assert!(p.matches("api.openai.com"));
        assert!(p.matches("openai.com"));
        assert!(!p.matches("evil.com"));
    }

    #[test]
    fn any_host_match() {
        let p = HostPattern::Any;
        assert!(p.matches("anything.com"));
    }

    #[test]
    fn default_injection_scopes() {
        let inj = SecretInjection::default();
        assert!(inj.headers);
        assert!(inj.basic_auth);
        assert!(!inj.query_params);
        assert!(!inj.body);
    }

    #[test]
    fn default_require_tls_identity() {
        let entry = SecretEntry {
            env_var: "K".into(),
            value: SecretValue::Static("v".into()),
            placeholder: "$K".into(),
            allowed_hosts: vec![],
            injection: SecretInjection::default(),
            require_tls_identity: true,
        };
        assert!(entry.require_tls_identity);
    }

    #[test]
    fn secret_value_static_resolves() {
        let v = SecretValue::Static("hello".to_string());
        assert_eq!(v.resolve().unwrap(), "hello");
    }

    #[test]
    fn secret_value_file_resolves_and_trims() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        write!(f, "secret-token\n").unwrap();
        let v = SecretValue::File(f.path().to_path_buf());
        assert_eq!(v.resolve().unwrap(), "secret-token");
    }

    #[test]
    fn secret_value_file_missing_is_error() {
        let v = SecretValue::File("/definitely/not/here".into());
        assert!(v.resolve().is_err());
    }

    #[test]
    fn secret_value_debug_redacts_static_but_shows_path() {
        let s = SecretValue::Static("topsecret".to_string());
        assert!(!format!("{s:?}").contains("topsecret"));
        let f = SecretValue::File("/etc/foo".into());
        assert!(format!("{f:?}").contains("/etc/foo"));
    }

    #[test]
    fn secret_value_static_wire_format_is_bare_string() {
        // Backward compat with `value: String` daemons. The serialized
        // form must be JSON's "hello", not a tagged map.
        let s = SecretValue::Static("hello".into());
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"hello\"");
    }

    #[test]
    fn secret_value_file_wire_format_uses_sentinel() {
        let s = SecretValue::File("/tmp/tok".into());
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("msbfile:/tmp/tok"));
        // Round-trips back to File.
        let round: SecretValue = serde_json::from_str(&json).unwrap();
        assert!(matches!(round, SecretValue::File(p) if p == PathBuf::from("/tmp/tok")));
    }

    #[test]
    fn secret_value_bare_string_deserializes_to_static() {
        let s: SecretValue = serde_json::from_str("\"plain-token\"").unwrap();
        assert!(matches!(s, SecretValue::Static(v) if v == "plain-token"));
    }
}
