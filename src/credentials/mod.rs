//! Credentials module: CLI token storage, encryption, and resolution.
//!
//! This module handles reading/writing `~/.config/marmosyn/credentials.toml`,
//! encrypting tokens with a password (Argon2id + ChaCha20-Poly1305),
//! and resolving tokens by priority (flag → env → file).

pub mod encrypt;
pub mod resolve;
pub mod store;
