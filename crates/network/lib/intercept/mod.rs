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
//! A representative use is OAuth refresh interception: when an in-VM
//! agent's token-refresh request would otherwise reach the provider with
//! a placeholder refresh token and fail, the interceptor traps it and the
//! hook returns a synthesized response produced out-of-band on the host.

pub mod config;
pub mod handler;
