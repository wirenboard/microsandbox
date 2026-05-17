//! Request-interceptor hook for the TLS-intercept proxy.
//!
//! After secret substitution and before forwarding plaintext to the
//! upstream server, the proxy consults a per-connection `Interceptor`.
//! If a configured rule matches the request's SNI / method / path, the
//! interceptor buffers the full request (headers + body), spawns the
//! configured hook command with the request bytes on stdin, and uses
//! the hook's stdout as the response delivered to the guest. The
//! upstream connection stays idle and is closed when the proxy exits.
//!
//! This is the linchpin of agent-vm Phase 4: when the in-VM agent's
//! OAuth refresh attempt would otherwise hit `platform.claude.com` and
//! 401 (because the placeholder refresh token isn't real), the
//! interceptor traps it and the hook returns a synthesized response
//! built from a host-side re-run of `claude -p`.

pub mod config;
pub mod handler;
