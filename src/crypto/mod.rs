//! Cryptographic operations for file encryption/decryption.
//!
//! This module handles per-job file encryption using ChaCha20-Poly1305 (AEAD).
//! Key management supports loading keys from environment variables, files, or raw strings.
//!
//! **Not to be confused with** `credentials::encrypt` which handles CLI token
//! encryption using Argon2id + ChaCha20-Poly1305.

pub mod cipher;
pub mod key;
