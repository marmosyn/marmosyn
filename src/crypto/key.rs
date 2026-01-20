// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Encryption key loading and management.
//!
//! Loads the data encryption key from the source specified in `[encryption].key_source`.
//! Supported key source formats:
//!
//! - `env:VAR_NAME` — load from an environment variable
//! - `file:/path/to/keyfile` — load from a file (first 32 bytes or base64-decoded)
//! - `raw:base64key` — decode directly from a base64 string
//!
//! The key must be exactly 256 bits (32 bytes) for use with ChaCha20-Poly1305.

use anyhow::{bail, Context, Result};
use base64::Engine;

/// The required key length in bytes for ChaCha20-Poly1305.
pub const KEY_LENGTH: usize = 32;

/// A validated 256-bit encryption key.
#[derive(Clone)]
pub struct EncryptionKey {
    /// The raw 32-byte key material.
    bytes: [u8; KEY_LENGTH],
}

impl EncryptionKey {
    /// Creates an `EncryptionKey` from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is not exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEY_LENGTH {
            bail!(
                "encryption key must be exactly {} bytes, got {}",
                KEY_LENGTH,
                bytes.len()
            );
        }
        let mut key = [0u8; KEY_LENGTH];
        key.copy_from_slice(bytes);
        Ok(Self { bytes: key })
    }

    /// Returns a reference to the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_LENGTH] {
        &self.bytes
    }
}

impl std::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EncryptionKey(***)")
    }
}

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        // Zeroize key material on drop to reduce exposure in memory
        self.bytes = [0u8; KEY_LENGTH];
    }
}

/// Loads an encryption key from the given `key_source` string.
///
/// Supported formats:
/// - `env:VAR_NAME` — reads the value of the environment variable `VAR_NAME`,
///   then base64-decodes it.
/// - `file:/path/to/keyfile` — reads the file and takes the first 32 bytes
///   (raw) or base64-decodes the entire file content if it is valid base64.
/// - `raw:base64key` — base64-decodes the key directly.
///
/// # Errors
///
/// Returns an error if the key source format is unrecognized, the source
/// cannot be read, or the decoded key is not exactly 32 bytes.
pub fn load_key(key_source: &str) -> Result<EncryptionKey> {
    if let Some(var_name) = key_source.strip_prefix("env:") {
        load_key_from_env(var_name)
    } else if let Some(file_path) = key_source.strip_prefix("file:") {
        load_key_from_file(file_path)
    } else if let Some(b64_data) = key_source.strip_prefix("raw:") {
        load_key_from_base64(b64_data)
    } else {
        bail!(
            "unrecognized key_source format '{}': expected 'env:VAR', 'file:/path', or 'raw:base64'",
            key_source
        );
    }
}

/// Loads a key from a base64-encoded environment variable.
fn load_key_from_env(var_name: &str) -> Result<EncryptionKey> {
    let value = std::env::var(var_name)
        .with_context(|| format!("environment variable '{}' is not set", var_name))?;
    load_key_from_base64(&value)
        .with_context(|| format!("failed to decode key from env var '{}'", var_name))
}

/// Loads a key from a file on disk.
///
/// If the file content is valid base64 text (after trimming whitespace), it
/// is decoded. Otherwise the raw bytes are used directly.
fn load_key_from_file(path: &str) -> Result<EncryptionKey> {
    let raw = std::fs::read(path).with_context(|| format!("failed to read key file '{}'", path))?;

    // Try interpreting the file as base64 text first
    let trimmed = String::from_utf8_lossy(&raw);
    let trimmed = trimmed.trim();
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(trimmed) {
        if decoded.len() == KEY_LENGTH {
            return EncryptionKey::from_bytes(&decoded);
        }
    }

    // Fall back to raw bytes
    if raw.len() >= KEY_LENGTH {
        EncryptionKey::from_bytes(&raw[..KEY_LENGTH])
    } else {
        bail!(
            "key file '{}' is too short: need at least {} bytes, got {}",
            path,
            KEY_LENGTH,
            raw.len()
        );
    }
}

/// Decodes a base64-encoded key string.
fn load_key_from_base64(b64: &str) -> Result<EncryptionKey> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .context("failed to base64-decode encryption key")?;
    EncryptionKey::from_bytes(&decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;

    fn make_b64_key() -> String {
        let key = [0xAB_u8; KEY_LENGTH];
        STANDARD.encode(key)
    }

    #[test]
    fn test_from_bytes_valid() {
        let bytes = [42u8; KEY_LENGTH];
        let key = EncryptionKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn test_from_bytes_wrong_length() {
        let bytes = [0u8; 16];
        let result = EncryptionKey::from_bytes(&bytes);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("32 bytes"));
    }

    #[test]
    fn test_debug_does_not_leak() {
        let key = EncryptionKey::from_bytes(&[1u8; KEY_LENGTH]).unwrap();
        let dbg = format!("{:?}", key);
        assert!(dbg.contains("***"));
        assert!(!dbg.contains("1"));
    }

    #[test]
    fn test_load_key_from_base64() {
        let b64 = make_b64_key();
        let key = load_key_from_base64(&b64).unwrap();
        assert_eq!(key.as_bytes(), &[0xAB_u8; KEY_LENGTH]);
    }

    #[test]
    fn test_load_key_from_base64_invalid() {
        let result = load_key_from_base64("not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_key_from_env() {
        let b64 = make_b64_key();
        std::env::set_var("MARMOSYN_TEST_KEY_123", &b64);
        let key = load_key_from_env("MARMOSYN_TEST_KEY_123").unwrap();
        assert_eq!(key.as_bytes(), &[0xAB_u8; KEY_LENGTH]);
        std::env::remove_var("MARMOSYN_TEST_KEY_123");
    }

    #[test]
    fn test_load_key_from_env_missing() {
        let result = load_key_from_env("MARMOSYN_NONEXISTENT_VAR_XYZ");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_key_from_file_base64() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("key.b64");
        let b64 = make_b64_key();
        std::fs::write(&key_path, &b64).unwrap();

        let key = load_key_from_file(key_path.to_str().unwrap()).unwrap();
        assert_eq!(key.as_bytes(), &[0xAB_u8; KEY_LENGTH]);
    }

    #[test]
    fn test_load_key_from_file_raw() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("key.bin");
        let raw = [0xCD_u8; KEY_LENGTH];
        std::fs::write(&key_path, raw).unwrap();

        let key = load_key_from_file(key_path.to_str().unwrap()).unwrap();
        assert_eq!(key.as_bytes(), &[0xCD_u8; KEY_LENGTH]);
    }

    #[test]
    fn test_load_key_from_file_too_short() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("short.bin");
        std::fs::write(&key_path, [0u8; 10]).unwrap();

        let result = load_key_from_file(key_path.to_str().unwrap());
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("too short"));
    }

    #[test]
    fn test_load_key_from_file_not_found() {
        let result = load_key_from_file("/nonexistent/key.bin");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_key_dispatch_env() {
        let b64 = make_b64_key();
        std::env::set_var("MARMOSYN_TEST_DISPATCH_KEY", &b64);
        let key = load_key("env:MARMOSYN_TEST_DISPATCH_KEY").unwrap();
        assert_eq!(key.as_bytes(), &[0xAB_u8; KEY_LENGTH]);
        std::env::remove_var("MARMOSYN_TEST_DISPATCH_KEY");
    }

    #[test]
    fn test_load_key_dispatch_raw() {
        let b64 = make_b64_key();
        let source = format!("raw:{}", b64);
        let key = load_key(&source).unwrap();
        assert_eq!(key.as_bytes(), &[0xAB_u8; KEY_LENGTH]);
    }

    #[test]
    fn test_load_key_dispatch_unknown() {
        let result = load_key("unknown:something");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("unrecognized key_source"));
    }
}
