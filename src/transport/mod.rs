//! Transport layer for remote synchronization.
//!
//! This module implements the binary protocol over TCP/TLS for
//! sender-to-receiver file transfers, including authentication,
//! alias resolution, and delta synchronization.

pub mod client;
pub mod codec;
pub mod delta;
pub mod protocol;
pub mod receiver;
pub mod server;
pub mod tls;
