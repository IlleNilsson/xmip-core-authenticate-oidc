#![forbid(unsafe_code)]
//! Authenticate by oidc: verifies an ID token against the issuer's published keys and the
//! nonce.
//!
//! Declared and not yet written: `architecture.toml` carries the maturity. When it
//! is, it implements `Authenticator` (ADR-0050).
