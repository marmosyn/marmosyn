// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! File encryption and decryption using ChaCha20-Poly1305 (AEAD).
//!
//! This module implements streaming file encryption/decryption for per-job
//! encryption. Files are encrypted in blocks (64 KiB), each with its own
//! nonce derived from a base nonce and a block counter.
//!
//! Encrypted file format:
//! ```text
//! Offset  Size     Description
//! 0       4        Magic bytes: 0x4D 0x53 0x59 0x4E ("MSYN")
//! 4       1        Format version (0x01)
//! 5       12       Base nonce (random, unique per file)
//! 17      N        Encrypted blocks (each block: 4-byte LE length + ciphertext + 16-byte tag)
//! ```
//!
//! **Not to be confused with** `credentials::encrypt` which handles CLI token
//! encryption using Argon2id + ChaCha20-Poly1305.

use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
use tracing::{debug, trace};

use super::key::EncryptionKey;

/// Magic bytes identifying a MarmoSyn encrypted file.
const MAGIC: [u8; 4] = [0x4D, 0x53, 0x59, 0x4E]; // "MSYN"

/// Current format version.
const FORMAT_VERSION: u8 = 0x01;

/// Size of the file header: magic (4) + version (1) + nonce (12).
const HEADER_SIZE: usize = 4 + 1 + 12;

/// Size of the base nonce in bytes (ChaCha20-Poly1305 uses 96-bit nonces).
const NONCE_SIZE: usize = 12;

/// Size of the AEAD authentication tag appended to each encrypted block.
const TAG_SIZE: usize = 16;

/// Default plaintext block size (64 KiB).
const BLOCK_SIZE: usize = 64 * 1024;

/// Maximum number of blocks per file (limited by nonce derivation scheme).
/// With a 32-bit counter we can handle files up to ~256 TiB at 64 KiB blocks.
const MAX_BLOCKS: u64 = u32::MAX as u64;

/// Encrypts a file from `src_path` and writes the encrypted output to `dest_path`.
///
/// The source file is read in blocks of [`BLOCK_SIZE`] bytes. Each block is
/// encrypted independently with a nonce derived from a random base nonce and
/// the block index. The encrypted file includes a header with magic bytes,
/// format version, and the base nonce.
///
/// # Errors
///
/// Returns an error if the source file cannot be read, the destination cannot
/// be written, or the encryption fails.
pub fn encrypt_file(src_path: &Path, dest_path: &Path, key: &EncryptionKey) -> Result<u64> {
    let mut src = std::fs::File::open(src_path)
        .with_context(|| format!("failed to open source file '{}'", src_path.display()))?;

    let mut dest = std::fs::File::create(dest_path)
        .with_context(|| format!("failed to create encrypted file '{}'", dest_path.display()))?;

    let bytes_written = encrypt_stream(&mut src, &mut dest, key)?;

    debug!(
        src = %src_path.display(),
        dest = %dest_path.display(),
        bytes = bytes_written,
        "file encrypted"
    );

    Ok(bytes_written)
}

/// Decrypts a file from `src_path` and writes the plaintext output to `dest_path`.
///
/// Reads the header to extract the base nonce, then decrypts each block
/// using the derived per-block nonce.
///
/// # Errors
///
/// Returns an error if the source file is not a valid MarmoSyn encrypted file,
/// the key is wrong (authentication failure), or I/O operations fail.
pub fn decrypt_file(src_path: &Path, dest_path: &Path, key: &EncryptionKey) -> Result<u64> {
    let mut src = std::fs::File::open(src_path)
        .with_context(|| format!("failed to open encrypted file '{}'", src_path.display()))?;

    let mut dest = std::fs::File::create(dest_path)
        .with_context(|| format!("failed to create decrypted file '{}'", dest_path.display()))?;

    let bytes_written = decrypt_stream(&mut src, &mut dest, key)?;

    debug!(
        src = %src_path.display(),
        dest = %dest_path.display(),
        bytes = bytes_written,
        "file decrypted"
    );

    Ok(bytes_written)
}

/// Encrypts data from a reader and writes the encrypted output to a writer.
///
/// This is the core streaming encryption function. It can be used with any
/// `Read`/`Write` pair (files, buffers, network streams, etc.).
///
/// Returns the total number of bytes written to the output (including header).
pub fn encrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    key: &EncryptionKey,
) -> Result<u64> {
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|e| anyhow::anyhow!("failed to create cipher: {}", e))?;

    // Generate random base nonce
    let mut base_nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut base_nonce);

    // Write header
    writer.write_all(&MAGIC)?;
    writer.write_all(&[FORMAT_VERSION])?;
    writer.write_all(&base_nonce)?;

    let mut total_written = HEADER_SIZE as u64;
    let mut block_index: u64 = 0;
    let mut buf = vec![0u8; BLOCK_SIZE];

    loop {
        let bytes_read = read_full(reader, &mut buf)?;
        if bytes_read == 0 {
            break;
        }

        if block_index >= MAX_BLOCKS {
            bail!(
                "file too large: exceeded maximum of {} blocks ({} bytes)",
                MAX_BLOCKS,
                MAX_BLOCKS * BLOCK_SIZE as u64
            );
        }

        let nonce = derive_nonce(&base_nonce, block_index);
        let plaintext = &buf[..bytes_read];

        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| anyhow::anyhow!("encryption failed at block {}", block_index))?;

        // Write block: 4-byte LE length prefix + ciphertext (includes tag)
        let block_len = ciphertext.len() as u32;
        writer.write_all(&block_len.to_le_bytes())?;
        writer.write_all(&ciphertext)?;

        total_written += 4 + ciphertext.len() as u64;
        block_index += 1;

        trace!(block = block_index, bytes = bytes_read, "encrypted block");
    }

    writer.flush()?;

    debug!(
        blocks = block_index,
        total_bytes = total_written,
        "encryption complete"
    );

    Ok(total_written)
}

/// Decrypts data from a reader and writes the plaintext output to a writer.
///
/// Returns the total number of plaintext bytes written.
pub fn decrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    key: &EncryptionKey,
) -> Result<u64> {
    // Read and validate header
    let mut header = [0u8; HEADER_SIZE];
    reader
        .read_exact(&mut header)
        .context("failed to read encrypted file header (file too short or not encrypted)")?;

    if header[0..4] != MAGIC {
        bail!(
            "invalid magic bytes: expected MSYN, got {:02X} {:02X} {:02X} {:02X}",
            header[0],
            header[1],
            header[2],
            header[3]
        );
    }

    let version = header[4];
    if version != FORMAT_VERSION {
        bail!(
            "unsupported encrypted file format version: {} (expected {})",
            version,
            FORMAT_VERSION
        );
    }

    let mut base_nonce = [0u8; NONCE_SIZE];
    base_nonce.copy_from_slice(&header[5..HEADER_SIZE]);

    let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|e| anyhow::anyhow!("failed to create cipher: {}", e))?;

    let mut total_written: u64 = 0;
    let mut block_index: u64 = 0;

    loop {
        // Read block length prefix (4 bytes LE)
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // End of file — no more blocks
                break;
            }
            Err(e) => return Err(e).context("failed to read block length"),
        }

        let block_len = u32::from_le_bytes(len_buf) as usize;

        // Sanity check: block cannot be larger than BLOCK_SIZE + TAG_SIZE
        if block_len > BLOCK_SIZE + TAG_SIZE {
            bail!(
                "corrupted data: block {} has length {} (max expected {})",
                block_index,
                block_len,
                BLOCK_SIZE + TAG_SIZE
            );
        }

        if block_len == 0 {
            bail!("corrupted data: block {} has zero length", block_index);
        }

        // Read the ciphertext block
        let mut ciphertext = vec![0u8; block_len];
        reader
            .read_exact(&mut ciphertext)
            .with_context(|| format!("failed to read block {} data", block_index))?;

        let nonce = derive_nonce(&base_nonce, block_index);

        let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref()).map_err(|_| {
            anyhow::anyhow!(
                "decryption failed at block {}: wrong key or corrupted data",
                block_index
            )
        })?;

        writer.write_all(&plaintext)?;
        total_written += plaintext.len() as u64;
        block_index += 1;

        trace!(
            block = block_index,
            bytes = plaintext.len(),
            "decrypted block"
        );
    }

    writer.flush()?;

    debug!(
        blocks = block_index,
        total_bytes = total_written,
        "decryption complete"
    );

    Ok(total_written)
}

/// Checks whether a file appears to be a MarmoSyn encrypted file by
/// reading the first few bytes and checking the magic and version.
pub fn is_encrypted_file(path: &Path) -> Result<bool> {
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return Ok(false),
    };

    let mut header = [0u8; 5]; // magic (4) + version (1)
    match f.read_exact(&mut header) {
        Ok(()) => {}
        Err(_) => return Ok(false), // file too short
    }

    Ok(header[0..4] == MAGIC && header[4] == FORMAT_VERSION)
}

// ─── Internal helpers ──────────────────────────────────────────────────────

/// Derives a per-block nonce from the base nonce and a block index.
///
/// The block index is XORed into the last 4 bytes of the base nonce.
/// This ensures each block gets a unique nonce while keeping the scheme
/// deterministic (for the same file and key, the same block produces the
/// same nonce — but the base nonce is random per file).
fn derive_nonce(base: &[u8; NONCE_SIZE], block_index: u64) -> Nonce {
    let mut nonce = *base;
    let counter = block_index as u32;
    let counter_bytes = counter.to_le_bytes();

    // XOR the counter into the last 4 bytes of the nonce
    for i in 0..4 {
        nonce[NONCE_SIZE - 4 + i] ^= counter_bytes[i];
    }

    *Nonce::from_slice(&nonce)
}

/// Reads as many bytes as possible into `buf`, handling partial reads.
/// Returns the total number of bytes read (0 at EOF).
fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break, // EOF
            Ok(n) => total += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e).context("read error during encryption"),
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn test_key() -> EncryptionKey {
        EncryptionKey::from_bytes(&[0x42u8; 32]).unwrap()
    }

    fn wrong_key() -> EncryptionKey {
        EncryptionKey::from_bytes(&[0x99u8; 32]).unwrap()
    }

    // ── Stream encrypt/decrypt roundtrip ────────────────────────────────

    #[test]
    fn test_encrypt_decrypt_roundtrip_small() {
        let key = test_key();
        let plaintext = b"Hello, MarmoSyn encryption!";

        let mut encrypted = Vec::new();
        let mut reader = Cursor::new(plaintext);
        encrypt_stream(&mut reader, &mut encrypted, &key).unwrap();

        assert_ne!(encrypted.as_slice(), plaintext.as_slice());
        assert!(encrypted.len() > HEADER_SIZE);

        let mut decrypted = Vec::new();
        let mut enc_reader = Cursor::new(&encrypted);
        decrypt_stream(&mut enc_reader, &mut decrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty() {
        let key = test_key();
        let plaintext = b"";

        let mut encrypted = Vec::new();
        let mut reader = Cursor::new(plaintext);
        encrypt_stream(&mut reader, &mut encrypted, &key).unwrap();

        // Should only have the header
        assert_eq!(encrypted.len(), HEADER_SIZE);

        let mut decrypted = Vec::new();
        let mut enc_reader = Cursor::new(&encrypted);
        decrypt_stream(&mut enc_reader, &mut decrypted, &key).unwrap();

        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_encrypt_decrypt_exact_block_size() {
        let key = test_key();
        let plaintext = vec![0xAB_u8; BLOCK_SIZE];

        let mut encrypted = Vec::new();
        let mut reader = Cursor::new(&plaintext);
        encrypt_stream(&mut reader, &mut encrypted, &key).unwrap();

        let mut decrypted = Vec::new();
        let mut enc_reader = Cursor::new(&encrypted);
        decrypt_stream(&mut enc_reader, &mut decrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_multi_block() {
        let key = test_key();
        // 2.5 blocks
        let plaintext = vec![0xCD_u8; BLOCK_SIZE * 2 + BLOCK_SIZE / 2];

        let mut encrypted = Vec::new();
        let mut reader = Cursor::new(&plaintext);
        encrypt_stream(&mut reader, &mut encrypted, &key).unwrap();

        let mut decrypted = Vec::new();
        let mut enc_reader = Cursor::new(&encrypted);
        decrypt_stream(&mut enc_reader, &mut decrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_large() {
        let key = test_key();
        // 5 full blocks + partial
        let plaintext: Vec<u8> = (0..BLOCK_SIZE * 5 + 1234)
            .map(|i| (i % 256) as u8)
            .collect();

        let mut encrypted = Vec::new();
        let mut reader = Cursor::new(&plaintext);
        encrypt_stream(&mut reader, &mut encrypted, &key).unwrap();

        let mut decrypted = Vec::new();
        let mut enc_reader = Cursor::new(&encrypted);
        decrypt_stream(&mut enc_reader, &mut decrypted, &key).unwrap();

        assert_eq!(decrypted.len(), plaintext.len());
        assert_eq!(decrypted, plaintext);
    }

    // ── Wrong key ───────────────────────────────────────────────────────

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let key = test_key();
        let plaintext = b"secret data";

        let mut encrypted = Vec::new();
        let mut reader = Cursor::new(plaintext);
        encrypt_stream(&mut reader, &mut encrypted, &key).unwrap();

        let bad = wrong_key();
        let mut decrypted = Vec::new();
        let mut enc_reader = Cursor::new(&encrypted);
        let result = decrypt_stream(&mut enc_reader, &mut decrypted, &bad);

        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("wrong key") || msg.contains("decryption failed"));
    }

    // ── Invalid format ──────────────────────────────────────────────────

    #[test]
    fn test_decrypt_invalid_magic() {
        let mut data = vec![0x00, 0x00, 0x00, 0x00, FORMAT_VERSION];
        data.extend_from_slice(&[0u8; NONCE_SIZE]);

        let key = test_key();
        let mut decrypted = Vec::new();
        let mut reader = Cursor::new(&data);
        let result = decrypt_stream(&mut reader, &mut decrypted, &key);

        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("invalid magic"));
    }

    #[test]
    fn test_decrypt_wrong_version() {
        let mut data = Vec::new();
        data.extend_from_slice(&MAGIC);
        data.push(0xFF); // wrong version
        data.extend_from_slice(&[0u8; NONCE_SIZE]);

        let key = test_key();
        let mut decrypted = Vec::new();
        let mut reader = Cursor::new(&data);
        let result = decrypt_stream(&mut reader, &mut decrypted, &key);

        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("unsupported"));
    }

    #[test]
    fn test_decrypt_too_short() {
        let data = vec![0x4D, 0x53]; // too short for header

        let key = test_key();
        let mut decrypted = Vec::new();
        let mut reader = Cursor::new(&data);
        let result = decrypt_stream(&mut reader, &mut decrypted, &key);

        assert!(result.is_err());
    }

    // ── Corrupted data ──────────────────────────────────────────────────

    #[test]
    fn test_decrypt_corrupted_ciphertext() {
        let key = test_key();
        let plaintext = b"important data";

        let mut encrypted = Vec::new();
        let mut reader = Cursor::new(plaintext);
        encrypt_stream(&mut reader, &mut encrypted, &key).unwrap();

        // Corrupt a byte in the ciphertext area (after header + length prefix)
        if encrypted.len() > HEADER_SIZE + 4 + 2 {
            encrypted[HEADER_SIZE + 4 + 2] ^= 0xFF;
        }

        let mut decrypted = Vec::new();
        let mut enc_reader = Cursor::new(&encrypted);
        let result = decrypt_stream(&mut enc_reader, &mut decrypted, &key);

        assert!(result.is_err());
    }

    // ── Header structure ────────────────────────────────────────────────

    #[test]
    fn test_header_structure() {
        let key = test_key();
        let plaintext = b"test";

        let mut encrypted = Vec::new();
        let mut reader = Cursor::new(plaintext);
        encrypt_stream(&mut reader, &mut encrypted, &key).unwrap();

        // Check magic bytes
        assert_eq!(&encrypted[0..4], &MAGIC);
        // Check version
        assert_eq!(encrypted[4], FORMAT_VERSION);
        // Nonce is at bytes 5..17 — should be non-zero (extremely unlikely all zeros)
        let nonce_area = &encrypted[5..17];
        assert!(nonce_area.iter().any(|&b| b != 0), "nonce should be random");
    }

    // ── Nonce derivation ────────────────────────────────────────────────

    #[test]
    fn test_derive_nonce_different_blocks() {
        let base = [0x01u8; NONCE_SIZE];
        let n0 = derive_nonce(&base, 0);
        let n1 = derive_nonce(&base, 1);
        let n2 = derive_nonce(&base, 2);

        assert_ne!(n0, n1);
        assert_ne!(n1, n2);
        assert_ne!(n0, n2);
    }

    #[test]
    fn test_derive_nonce_deterministic() {
        let base = [0xAB; NONCE_SIZE];
        let n1 = derive_nonce(&base, 42);
        let n2 = derive_nonce(&base, 42);
        assert_eq!(n1, n2);
    }

    #[test]
    fn test_derive_nonce_zero_block() {
        let base = [0x01u8; NONCE_SIZE];
        let nonce = derive_nonce(&base, 0);
        // XOR with 0 should leave base unchanged
        assert_eq!(&nonce[..], &base[..]);
    }

    // ── File-level encrypt/decrypt ──────────────────────────────────────

    #[test]
    fn test_encrypt_decrypt_file() {
        let dir = tempfile::tempdir().unwrap();
        let src_path = dir.path().join("plaintext.txt");
        let enc_path = dir.path().join("encrypted.bin");
        let dec_path = dir.path().join("decrypted.txt");

        let content = "MarmoSyn file encryption test 🔒";
        std::fs::write(&src_path, content).unwrap();

        let key = test_key();

        let enc_bytes = encrypt_file(&src_path, &enc_path, &key).unwrap();
        assert!(enc_bytes > 0);
        assert!(enc_path.exists());

        let dec_bytes = decrypt_file(&enc_path, &dec_path, &key).unwrap();
        assert!(dec_bytes > 0);

        let decrypted = std::fs::read_to_string(&dec_path).unwrap();
        assert_eq!(decrypted, content);
    }

    #[test]
    fn test_encrypt_file_nonexistent_source() {
        let dir = tempfile::tempdir().unwrap();
        let key = test_key();
        let result = encrypt_file(
            Path::new("/nonexistent/file.txt"),
            &dir.path().join("out.bin"),
            &key,
        );
        assert!(result.is_err());
    }

    // ── is_encrypted_file ───────────────────────────────────────────────

    #[test]
    fn test_is_encrypted_file_true() {
        let dir = tempfile::tempdir().unwrap();
        let src_path = dir.path().join("plain.txt");
        let enc_path = dir.path().join("encrypted.bin");

        std::fs::write(&src_path, "test data").unwrap();

        let key = test_key();
        encrypt_file(&src_path, &enc_path, &key).unwrap();

        assert!(is_encrypted_file(&enc_path).unwrap());
    }

    #[test]
    fn test_is_encrypted_file_false_for_plain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain.txt");
        std::fs::write(&path, "just plain text").unwrap();

        assert!(!is_encrypted_file(&path).unwrap());
    }

    #[test]
    fn test_is_encrypted_file_false_for_nonexistent() {
        assert!(!is_encrypted_file(Path::new("/nonexistent/file.bin")).unwrap());
    }

    #[test]
    fn test_is_encrypted_file_false_for_short() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("short.bin");
        std::fs::write(&path, "ab").unwrap();

        assert!(!is_encrypted_file(&path).unwrap());
    }

    // ── Different encryptions of same file produce different output ─────

    #[test]
    fn test_encrypt_nondeterministic() {
        let key = test_key();
        let plaintext = b"same content every time";

        let mut enc1 = Vec::new();
        encrypt_stream(&mut Cursor::new(plaintext), &mut enc1, &key).unwrap();

        let mut enc2 = Vec::new();
        encrypt_stream(&mut Cursor::new(plaintext), &mut enc2, &key).unwrap();

        // Due to random nonce, encrypted output should differ
        assert_ne!(enc1, enc2);

        // But both should decrypt to the same plaintext
        let mut dec1 = Vec::new();
        decrypt_stream(&mut Cursor::new(&enc1), &mut dec1, &key).unwrap();
        let mut dec2 = Vec::new();
        decrypt_stream(&mut Cursor::new(&enc2), &mut dec2, &key).unwrap();

        assert_eq!(dec1, plaintext);
        assert_eq!(dec2, plaintext);
    }

    // ── Unicode / binary content ────────────────────────────────────────

    #[test]
    fn test_encrypt_decrypt_binary_content() {
        let key = test_key();
        let plaintext: Vec<u8> = (0..=255).collect();

        let mut encrypted = Vec::new();
        encrypt_stream(&mut Cursor::new(&plaintext), &mut encrypted, &key).unwrap();

        let mut decrypted = Vec::new();
        decrypt_stream(&mut Cursor::new(&encrypted), &mut decrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    // ── read_full helper ────────────────────────────────────────────────

    #[test]
    fn test_read_full_exact() {
        let data = vec![1u8, 2, 3, 4, 5];
        let mut reader = Cursor::new(&data);
        let mut buf = [0u8; 5];
        let n = read_full(&mut reader, &mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(buf, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_read_full_short() {
        let data = vec![1u8, 2, 3];
        let mut reader = Cursor::new(&data);
        let mut buf = [0u8; 10];
        let n = read_full(&mut reader, &mut buf).unwrap();
        assert_eq!(n, 3);
    }

    #[test]
    fn test_read_full_empty() {
        let data: Vec<u8> = vec![];
        let mut reader = Cursor::new(&data);
        let mut buf = [0u8; 10];
        let n = read_full(&mut reader, &mut buf).unwrap();
        assert_eq!(n, 0);
    }
}
