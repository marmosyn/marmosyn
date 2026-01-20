// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! BLAKE3 file hashing utilities.
//!
//! Provides fast, parallel-friendly file hashing using the BLAKE3 algorithm.
//! Hashing is performed asynchronously with `tokio::task::spawn_blocking`
//! to avoid blocking the async runtime.

use std::path::Path;

use anyhow::Result;

/// Size of the read buffer for hashing (64 KiB).
const HASH_BUFFER_SIZE: usize = 64 * 1024;

/// Computes the BLAKE3 hash of a file at the given path.
///
/// This function reads the file in chunks to handle large files efficiently.
/// It should be called from within `spawn_blocking` if used in an async context.
///
/// # Errors
///
/// Returns an error if the file cannot be opened or read.
pub fn hash_file_blocking(path: &Path) -> Result<String> {
    let mut hasher = blake3::Hasher::new();
    let mut file = std::fs::File::open(path)?;
    let mut buf = vec![0u8; HASH_BUFFER_SIZE];

    loop {
        let bytes_read = std::io::Read::read(&mut file, &mut buf)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buf[..bytes_read]);
    }

    Ok(hasher.finalize().to_hex().to_string())
}

/// Computes the BLAKE3 hash of a file asynchronously.
///
/// Offloads the blocking I/O to `tokio::task::spawn_blocking` so that the
/// async runtime is not blocked.
///
/// # Errors
///
/// Returns an error if the file cannot be opened or read.
pub async fn hash_file(path: &Path) -> Result<String> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || hash_file_blocking(&path)).await?
}

/// Computes the BLAKE3 hash of a byte slice (useful for testing).
pub fn hash_bytes(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_hash_bytes_deterministic() {
        let hash1 = hash_bytes(b"hello world");
        let hash2 = hash_bytes(b"hello world");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_bytes_different_input() {
        let hash1 = hash_bytes(b"hello");
        let hash2 = hash_bytes(b"world");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_bytes_empty() {
        let hash = hash_bytes(b"");
        // BLAKE3 hash of empty input is well-defined
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // 256 bits = 64 hex chars
    }

    #[test]
    fn test_hash_file_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        let mut f = std::fs::File::create(&file_path).unwrap();
        f.write_all(b"test content for hashing").unwrap();
        drop(f);

        let hash = hash_file_blocking(&file_path).unwrap();
        let expected = hash_bytes(b"test content for hashing");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_hash_file_blocking_not_found() {
        let result = hash_file_blocking(Path::new("/nonexistent/file.txt"));
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_hash_file_async() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("async_test.txt");
        tokio::fs::write(&file_path, b"async content")
            .await
            .unwrap();

        let hash = hash_file(&file_path).await.unwrap();
        let expected = hash_bytes(b"async content");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_hash_file_blocking_large() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("large.bin");
        // Create a file larger than HASH_BUFFER_SIZE to test chunked reading
        let data = vec![0xAB_u8; HASH_BUFFER_SIZE * 3 + 42];
        std::fs::write(&file_path, &data).unwrap();

        let file_hash = hash_file_blocking(&file_path).unwrap();
        let direct_hash = hash_bytes(&data);
        assert_eq!(file_hash, direct_hash);
    }
}
