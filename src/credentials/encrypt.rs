// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Token encryption and decryption using Argon2id + ChaCha20-Poly1305.
//!
//! This module provides functions to encrypt and decrypt CLI authentication tokens
//! with a user-provided password. The flow is:
//!
//! 1. Password → Argon2id → 256-bit key
//! 2. Key + random nonce → ChaCha20-Poly1305 → encrypted token
//!
//! Encrypted tokens are stored in `credentials.toml` with the prefix `encrypted:`,
//! followed by base64-encoded data containing the salt, nonce, and ciphertext+tag.
//!
//! **Not to be confused with** `crypto::cipher` which handles per-job file encryption.

use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

/// Length of the Argon2id salt in bytes.
const SALT_LENGTH: usize = 16;

/// Length of the ChaCha20-Poly1305 nonce in bytes.
const NONCE_LENGTH: usize = 12;

/// Length of the derived key in bytes (256 bits).
const KEY_LENGTH: usize = 32;

/// Errors that can occur during token encryption or decryption.
#[derive(Debug, thiserror::Error)]
pub enum EncryptError {
    /// Failed to derive the encryption key from the password via Argon2id.
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    /// The ChaCha20-Poly1305 encryption operation failed.
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    /// The ChaCha20-Poly1305 decryption operation failed (wrong password or corrupted data).
    #[error("decryption failed: wrong password or corrupted token data")]
    DecryptionFailed,

    /// The base64-encoded token data is malformed or too short.
    #[error("invalid encrypted token format: {0}")]
    InvalidFormat(String),

    /// Base64 decoding failed.
    #[error("base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),
}

/// Encrypts a plaintext token with the given password.
///
/// The encryption process:
/// 1. Generate a random 16-byte salt.
/// 2. Derive a 256-bit key from the password and salt using Argon2id.
/// 3. Generate a random 12-byte nonce.
/// 4. Encrypt the token with ChaCha20-Poly1305.
/// 5. Return base64(salt + nonce + ciphertext_with_tag).
///
/// The returned string can be stored directly (without the `encrypted:` prefix;
/// the caller is responsible for adding the prefix).
///
/// # Errors
///
/// Returns [`EncryptError`] if key derivation or encryption fails.
pub fn encrypt_token(plaintext_token: &str, password: &str) -> Result<String, EncryptError> {
    use rand::RngCore;

    // 1. Generate random salt
    let mut salt = [0u8; SALT_LENGTH];
    rand::thread_rng().fill_bytes(&mut salt);

    // 2. Derive key via Argon2id
    let key = derive_key(password.as_bytes(), &salt)?;

    // 3. Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // 4. Encrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| EncryptError::EncryptionFailed(e.to_string()))?;

    let ciphertext = cipher
        .encrypt(nonce, plaintext_token.as_bytes())
        .map_err(|_| EncryptError::EncryptionFailed("AEAD encryption failed".to_string()))?;

    // 5. Encode: salt + nonce + ciphertext_with_tag
    let mut payload = Vec::with_capacity(SALT_LENGTH + NONCE_LENGTH + ciphertext.len());
    payload.extend_from_slice(&salt);
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&ciphertext);

    let encoded = base64::engine::general_purpose::STANDARD.encode(&payload);
    Ok(encoded)
}

/// Decrypts a base64-encoded encrypted token with the given password.
///
/// The input `encrypted_b64` should be the base64 string (without the `encrypted:` prefix).
///
/// # Errors
///
/// Returns [`EncryptError::DecryptionFailed`] if the password is wrong or the data is corrupted.
/// Returns [`EncryptError::InvalidFormat`] if the data is too short or malformed.
pub fn decrypt_token(encrypted_b64: &str, password: &str) -> Result<String, EncryptError> {
    let payload = base64::engine::general_purpose::STANDARD.decode(encrypted_b64)?;

    let min_length = SALT_LENGTH + NONCE_LENGTH + 1; // at least 1 byte of ciphertext
    if payload.len() < min_length {
        return Err(EncryptError::InvalidFormat(format!(
            "encrypted data too short: expected at least {} bytes, got {}",
            min_length,
            payload.len()
        )));
    }

    // Extract salt, nonce, and ciphertext
    let salt = &payload[..SALT_LENGTH];
    let nonce_bytes = &payload[SALT_LENGTH..SALT_LENGTH + NONCE_LENGTH];
    let ciphertext = &payload[SALT_LENGTH + NONCE_LENGTH..];

    // Derive the same key
    let key = derive_key(password.as_bytes(), salt)?;

    // Decrypt
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| EncryptError::EncryptionFailed(e.to_string()))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| EncryptError::DecryptionFailed)?;

    String::from_utf8(plaintext)
        .map_err(|_| EncryptError::InvalidFormat("decrypted token is not valid UTF-8".to_string()))
}

/// Derives a 256-bit key from a password and salt using Argon2id.
fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; KEY_LENGTH], EncryptError> {
    use argon2::Argon2;

    let argon2 = Argon2::default();
    let mut key = [0u8; KEY_LENGTH];

    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| EncryptError::KeyDerivation(e.to_string()))?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let token = "my-secret-api-token";
        let password = "strong-password-123";

        let encrypted = encrypt_token(token, password).unwrap();
        assert!(!encrypted.is_empty());
        assert_ne!(encrypted, token);

        let decrypted = decrypt_token(&encrypted, password).unwrap();
        assert_eq!(decrypted, token);
    }

    #[test]
    fn test_wrong_password_fails() {
        let token = "my-secret-api-token";
        let password = "correct-password";

        let encrypted = encrypt_token(token, password).unwrap();

        let result = decrypt_token(&encrypted, "wrong-password");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EncryptError::DecryptionFailed
        ));
    }

    #[test]
    fn test_different_encryptions_produce_different_output() {
        let token = "same-token";
        let password = "same-password";

        let enc1 = encrypt_token(token, password).unwrap();
        let enc2 = encrypt_token(token, password).unwrap();

        // Due to random salt and nonce, outputs should differ
        assert_ne!(enc1, enc2);

        // But both should decrypt to the same token
        assert_eq!(decrypt_token(&enc1, password).unwrap(), token);
        assert_eq!(decrypt_token(&enc2, password).unwrap(), token);
    }

    #[test]
    fn test_empty_token() {
        let token = "";
        let password = "password";

        let encrypted = encrypt_token(token, password).unwrap();
        let decrypted = decrypt_token(&encrypted, password).unwrap();
        assert_eq!(decrypted, token);
    }

    #[test]
    fn test_invalid_base64() {
        let result = decrypt_token("not-valid-base64!!!", "password");
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_data() {
        // Base64 of just a few bytes (less than salt + nonce)
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 10]);
        let result = decrypt_token(&short, "password");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EncryptError::InvalidFormat(_)
        ));
    }

    #[test]
    fn test_corrupted_ciphertext() {
        let token = "test-token";
        let password = "password";

        let encrypted = encrypt_token(token, password).unwrap();
        let mut payload = base64::engine::general_purpose::STANDARD
            .decode(&encrypted)
            .unwrap();

        // Corrupt the last byte of the ciphertext
        if let Some(last) = payload.last_mut() {
            *last ^= 0xFF;
        }

        let corrupted = base64::engine::general_purpose::STANDARD.encode(&payload);
        let result = decrypt_token(&corrupted, password);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EncryptError::DecryptionFailed
        ));
    }

    #[test]
    fn test_unicode_token_and_password() {
        let token = "токен-с-юникодом-🔑";
        let password = "пароль-🔒";

        let encrypted = encrypt_token(token, password).unwrap();
        let decrypted = decrypt_token(&encrypted, password).unwrap();
        assert_eq!(decrypted, token);
    }
}
