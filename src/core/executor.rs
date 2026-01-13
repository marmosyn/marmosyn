//! Sync executor trait, local executor, and encrypting executor implementations.
//!
//! The [`SyncExecutor`] trait provides an abstraction over local and remote
//! file synchronization operations. [`LocalExecutor`] implements this trait
//! for local filesystem destinations, with optional safety backup integration.
//!
//! [`EncryptingExecutor`] is a decorator that wraps any `SyncExecutor` and
//! transparently encrypts files during copy operations using ChaCha20-Poly1305.
//! It is applied when a sync job has `encrypt = true`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use async_trait::async_trait;
use tracing::debug;

use super::file_tree::FileMetadata;
use super::safety::SafetyHandler;
use crate::crypto::key::EncryptionKey;

/// Abstraction over local and remote file synchronization operations.
///
/// Implementations of this trait handle the actual file I/O for a single
/// destination. The [`LocalExecutor`] writes to a local directory, while
/// `RemoteExecutor` (implemented in Phase 9) sends files over the network.
#[async_trait]
pub trait SyncExecutor: Send + Sync {
    /// Copy a file from an absolute source path to the destination by relative path.
    async fn copy_file(&self, src: &Path, rel_path: &Path) -> Result<u64>;

    /// Delete a file on the destination by relative path.
    async fn delete_file(&self, rel_path: &Path) -> Result<()>;

    /// Create a directory on the destination by relative path.
    async fn create_dir(&self, rel_path: &Path) -> Result<()>;

    /// List all files and their metadata on the destination side.
    async fn list_files(&self) -> Result<Vec<FileMetadata>>;

    /// Returns a human-readable description of this executor's target.
    fn description(&self) -> &str;
}

/// Local filesystem executor — copies files directly to a local directory.
///
/// Supports atomic writes (write to temp file, then rename) and optional
/// safety backup via [`SafetyHandler`].
pub struct LocalExecutor {
    /// Root directory of the destination.
    target_root: PathBuf,
    /// Optional safety backup handler (if safety is enabled for the job).
    safety: Option<SafetyHandler>,
    /// Human-readable description for logging.
    desc: String,
}

impl LocalExecutor {
    /// Creates a new `LocalExecutor` targeting the given directory.
    pub fn new(target_root: PathBuf, safety: Option<SafetyHandler>) -> Self {
        let desc = format!("local:{}", target_root.display());
        Self {
            target_root,
            safety,
            desc,
        }
    }

    /// Returns the target root path.
    pub fn target_root(&self) -> &Path {
        &self.target_root
    }

    /// Computes the absolute path on disk for a given relative path.
    fn absolute_path(&self, rel_path: &Path) -> PathBuf {
        self.target_root.join(rel_path)
    }

    /// Performs a safety backup of a file before it is overwritten or deleted.
    /// No-op if safety is not configured.
    async fn backup_if_needed(&self, rel_path: &Path) -> Result<()> {
        if let Some(ref handler) = self.safety {
            let abs_path = self.absolute_path(rel_path);
            if abs_path.exists() {
                handler.backup_file(&abs_path, rel_path).await?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl SyncExecutor for LocalExecutor {
    async fn copy_file(&self, src: &Path, rel_path: &Path) -> Result<u64> {
        let dest_path = self.absolute_path(rel_path);

        // Safety backup before overwrite
        self.backup_if_needed(rel_path).await?;

        // Ensure parent directory exists
        if let Some(parent) = dest_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Atomic copy: write to a temp file in the same directory, then rename
        let parent = dest_path.parent().unwrap_or_else(|| Path::new("."));
        let temp_file = tempfile::NamedTempFile::new_in(parent)?;
        let temp_path = temp_file.path().to_path_buf();

        // Copy content
        let bytes_copied = tokio::fs::copy(src, &temp_path).await?;

        // Preserve permissions (best effort)
        #[cfg(unix)]
        {
            if let Ok(src_meta) = tokio::fs::metadata(src).await {
                let perms = src_meta.permissions();
                let _ = tokio::fs::set_permissions(&temp_path, perms.clone()).await;
            }
        }

        // Atomic rename
        tokio::fs::rename(&temp_path, &dest_path).await?;

        // Persist the temp file handle so it doesn't get deleted on drop
        temp_file.into_temp_path().keep()?;

        Ok(bytes_copied)
    }

    async fn delete_file(&self, rel_path: &Path) -> Result<()> {
        let dest_path = self.absolute_path(rel_path);

        // Safety backup before delete
        self.backup_if_needed(rel_path).await?;

        if dest_path.is_file() {
            tokio::fs::remove_file(&dest_path).await?;
        } else if dest_path.is_dir() {
            tokio::fs::remove_dir_all(&dest_path).await?;
        }

        Ok(())
    }

    async fn create_dir(&self, rel_path: &Path) -> Result<()> {
        let dest_path = self.absolute_path(rel_path);
        tokio::fs::create_dir_all(&dest_path).await?;
        Ok(())
    }

    async fn list_files(&self) -> Result<Vec<FileMetadata>> {
        use super::excluder::Excluder;
        use super::scanner;
        let root = self.target_root.clone();
        let (_root_path, tree) = tokio::task::spawn_blocking(move || {
            scanner::scan_directory(&root, &Excluder::empty(), &scanner::ScanOptions::default())
        })
        .await??;
        Ok(tree.values().cloned().collect())
    }

    fn description(&self) -> &str {
        &self.desc
    }
}

/// Encrypting executor decorator — wraps any [`SyncExecutor`] and encrypts
/// files during copy operations using ChaCha20-Poly1305.
///
/// When a sync job has `encrypt = true`, this executor is layered on top of
/// the underlying executor (e.g. `LocalExecutor` or `RemoteExecutor`). The
/// encryption is transparent to the rest of the sync pipeline.
///
/// - **Copy/update**: the source file is encrypted into a temporary file, then
///   the encrypted content is passed to the inner executor's `copy_file`.
/// - **Delete/create_dir/list_files**: delegated directly to the inner executor.
pub struct EncryptingExecutor {
    /// The wrapped executor that performs the actual I/O.
    inner: Box<dyn SyncExecutor>,
    /// The encryption key (256-bit, ChaCha20-Poly1305).
    key: EncryptionKey,
    /// Human-readable description for logging.
    desc: String,
}

impl EncryptingExecutor {
    /// Creates a new `EncryptingExecutor` wrapping the given executor.
    pub fn new(inner: Box<dyn SyncExecutor>, key: EncryptionKey) -> Self {
        let desc = format!("encrypted({})", inner.description());
        Self { inner, key, desc }
    }
}

#[async_trait]
impl SyncExecutor for EncryptingExecutor {
    async fn copy_file(&self, src: &Path, rel_path: &Path) -> Result<u64> {
        // Encrypt the source file into a temporary file, then pass the
        // encrypted temp file to the inner executor.
        let src_path = src.to_path_buf();
        let key_clone = self.key.clone();

        // Run encryption in a blocking task (CPU-bound)
        let temp_file = tokio::task::spawn_blocking(move || -> Result<tempfile::NamedTempFile> {
            let tmp = tempfile::NamedTempFile::new()
                .context("failed to create temp file for encryption")?;
            crate::crypto::cipher::encrypt_file(&src_path, tmp.path(), &key_clone)
                .context("failed to encrypt file")?;
            Ok(tmp)
        })
        .await
        .context("encryption task panicked")??;

        let encrypted_path = temp_file.path().to_path_buf();

        debug!(
            src = %src.display(),
            rel_path = %rel_path.display(),
            "file encrypted; passing to inner executor"
        );

        // Pass the encrypted temp file to the inner executor
        let bytes = self.inner.copy_file(&encrypted_path, rel_path).await?;

        // temp_file is dropped here, cleaning up the temporary encrypted file
        drop(temp_file);

        Ok(bytes)
    }

    async fn delete_file(&self, rel_path: &Path) -> Result<()> {
        self.inner.delete_file(rel_path).await
    }

    async fn create_dir(&self, rel_path: &Path) -> Result<()> {
        self.inner.create_dir(rel_path).await
    }

    async fn list_files(&self) -> Result<Vec<FileMetadata>> {
        self.inner.list_files().await
    }

    fn description(&self) -> &str {
        &self.desc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_local_executor_copy_file() {
        let src_dir = tempfile::tempdir().unwrap();
        let dest_dir = tempfile::tempdir().unwrap();

        // Create a source file
        let src_file = src_dir.path().join("hello.txt");
        tokio::fs::write(&src_file, b"hello world").await.unwrap();

        let executor = LocalExecutor::new(dest_dir.path().to_path_buf(), None);
        let bytes = executor
            .copy_file(&src_file, Path::new("hello.txt"))
            .await
            .unwrap();

        assert_eq!(bytes, 11);

        let dest_content = tokio::fs::read_to_string(dest_dir.path().join("hello.txt"))
            .await
            .unwrap();
        assert_eq!(dest_content, "hello world");
    }

    #[tokio::test]
    async fn test_local_executor_copy_creates_parent_dirs() {
        let src_dir = tempfile::tempdir().unwrap();
        let dest_dir = tempfile::tempdir().unwrap();

        let src_file = src_dir.path().join("data.bin");
        tokio::fs::write(&src_file, b"data").await.unwrap();

        let executor = LocalExecutor::new(dest_dir.path().to_path_buf(), None);
        executor
            .copy_file(&src_file, Path::new("sub/dir/data.bin"))
            .await
            .unwrap();

        let dest_content = tokio::fs::read_to_string(dest_dir.path().join("sub/dir/data.bin"))
            .await
            .unwrap();
        assert_eq!(dest_content, "data");
    }

    #[tokio::test]
    async fn test_local_executor_delete_file() {
        let dest_dir = tempfile::tempdir().unwrap();
        let file_path = dest_dir.path().join("to_delete.txt");
        tokio::fs::write(&file_path, b"delete me").await.unwrap();

        let executor = LocalExecutor::new(dest_dir.path().to_path_buf(), None);
        executor
            .delete_file(Path::new("to_delete.txt"))
            .await
            .unwrap();

        assert!(!file_path.exists());
    }

    #[tokio::test]
    async fn test_local_executor_create_dir() {
        let dest_dir = tempfile::tempdir().unwrap();

        let executor = LocalExecutor::new(dest_dir.path().to_path_buf(), None);
        executor.create_dir(Path::new("a/b/c")).await.unwrap();

        assert!(dest_dir.path().join("a/b/c").is_dir());
    }

    #[tokio::test]
    async fn test_local_executor_description() {
        let executor = LocalExecutor::new(PathBuf::from("/mnt/backup"), None);
        assert!(executor.description().contains("/mnt/backup"));
    }

    #[tokio::test]
    async fn test_encrypting_executor_copy_file() {
        let src_dir = tempfile::tempdir().unwrap();
        let dest_dir = tempfile::tempdir().unwrap();

        // Create a source file
        let src_file = src_dir.path().join("secret.txt");
        tokio::fs::write(&src_file, b"top secret data")
            .await
            .unwrap();

        // Create a 32-byte key
        let key_bytes = [0x42u8; 32];
        let key = EncryptionKey::from_bytes(&key_bytes).unwrap();

        let inner = LocalExecutor::new(dest_dir.path().to_path_buf(), None);
        let executor = EncryptingExecutor::new(Box::new(inner), key);

        let bytes = executor
            .copy_file(&src_file, Path::new("secret.txt"))
            .await
            .unwrap();

        // The encrypted file should be larger than the plaintext (header + tag overhead)
        assert!(bytes > 15);

        // The destination file should exist but NOT contain plaintext
        let dest_content = tokio::fs::read(dest_dir.path().join("secret.txt"))
            .await
            .unwrap();
        assert_ne!(dest_content, b"top secret data");

        // Verify it's a valid encrypted file by checking the magic header
        assert!(
            crate::crypto::cipher::is_encrypted_file(&dest_dir.path().join("secret.txt")).unwrap()
        );
    }

    #[tokio::test]
    async fn test_encrypting_executor_decrypt_roundtrip() {
        let src_dir = tempfile::tempdir().unwrap();
        let dest_dir = tempfile::tempdir().unwrap();
        let dec_dir = tempfile::tempdir().unwrap();

        let original_content = b"hello encrypted world 1234567890";

        // Create a source file
        let src_file = src_dir.path().join("data.bin");
        tokio::fs::write(&src_file, original_content).await.unwrap();

        // Create a 32-byte key
        let key_bytes = [0xAB_u8; 32];
        let key = EncryptionKey::from_bytes(&key_bytes).unwrap();
        let key2 = EncryptionKey::from_bytes(&key_bytes).unwrap();

        let inner = LocalExecutor::new(dest_dir.path().to_path_buf(), None);
        let executor = EncryptingExecutor::new(Box::new(inner), key);

        executor
            .copy_file(&src_file, Path::new("data.bin"))
            .await
            .unwrap();

        // Decrypt the file and verify contents
        let encrypted_path = dest_dir.path().join("data.bin");
        let decrypted_path = dec_dir.path().join("data.bin");

        crate::crypto::cipher::decrypt_file(&encrypted_path, &decrypted_path, &key2).unwrap();

        let decrypted = std::fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted, original_content);
    }

    #[tokio::test]
    async fn test_encrypting_executor_delegates_delete() {
        let dest_dir = tempfile::tempdir().unwrap();
        let file_path = dest_dir.path().join("to_delete.txt");
        tokio::fs::write(&file_path, b"delete me").await.unwrap();

        let key = EncryptionKey::from_bytes(&[0x01u8; 32]).unwrap();
        let inner = LocalExecutor::new(dest_dir.path().to_path_buf(), None);
        let executor = EncryptingExecutor::new(Box::new(inner), key);

        executor
            .delete_file(Path::new("to_delete.txt"))
            .await
            .unwrap();

        assert!(!file_path.exists());
    }

    #[tokio::test]
    async fn test_encrypting_executor_delegates_create_dir() {
        let dest_dir = tempfile::tempdir().unwrap();

        let key = EncryptionKey::from_bytes(&[0x01u8; 32]).unwrap();
        let inner = LocalExecutor::new(dest_dir.path().to_path_buf(), None);
        let executor = EncryptingExecutor::new(Box::new(inner), key);

        executor.create_dir(Path::new("a/b/c")).await.unwrap();

        assert!(dest_dir.path().join("a/b/c").is_dir());
    }

    #[tokio::test]
    async fn test_encrypting_executor_description() {
        let key = EncryptionKey::from_bytes(&[0x01u8; 32]).unwrap();
        let inner = LocalExecutor::new(PathBuf::from("/mnt/backup"), None);
        let executor = EncryptingExecutor::new(Box::new(inner), key);

        let desc = executor.description();
        assert!(desc.contains("encrypted"));
        assert!(desc.contains("/mnt/backup"));
    }
}
