// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Destination router: maps dest strings to the appropriate `SyncExecutor` instances.
//!
//! `DestRouter` takes the parsed destinations from a sync job (via `collect_destinations`)
//! and creates a `LocalExecutor` for local paths or a [`RemoteExecutor`] for remote paths.
//! It then orchestrates plan execution across all destinations.

use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result};
use tracing::{debug, error, info, warn};

use crate::config::dest_parser::{ParsedDest, parse_dest};
use crate::config::types::{RemoteNode, SafetyConfig};
use crate::crypto::key::EncryptionKey;

use super::executor::{EncryptingExecutor, LocalExecutor, SyncExecutor};
use super::remote_executor::RemoteExecutor;
use super::safety::SafetyHandler;
use super::sync_plan::{SyncError, SyncPlan, SyncProgress, SyncResult};

/// Error handling strategy when a file operation fails during sync execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnError {
    /// Skip the failed file and continue with the remaining operations.
    #[default]
    Skip,
    /// Abort the entire sync on the first error.
    Stop,
}

/// Callback type for progress reporting during sync execution.
pub type ProgressCallback = Box<dyn Fn(&SyncProgress) + Send + Sync>;

/// Routes sync plan execution to one or more destination executors.
///
/// Each destination string from a sync job is resolved to either a
/// [`LocalExecutor`] (for local paths) or a [`RemoteExecutor`]
/// (for remote paths, communicating over the transport protocol).
pub struct DestRouter {
    /// Pairs of (dest description string, executor).
    executors: Vec<(String, Box<dyn SyncExecutor>)>,
}

impl std::fmt::Debug for DestRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let descs: Vec<&str> = self.executors.iter().map(|(d, _)| d.as_str()).collect();
        f.debug_struct("DestRouter")
            .field("dest_count", &self.executors.len())
            .field("destinations", &descs)
            .finish()
    }
}

impl DestRouter {
    /// Creates executors for all job destinations.
    ///
    /// # Arguments
    ///
    /// * `dests` — unified list of destination strings (from `collect_destinations()`).
    /// * `remotes` — configured remote nodes (for resolving remote dest strings).
    /// * `safety_config` — per-job safety backup configuration.
    /// * `safety_dir` — base directory for safety copies.
    /// * `job_name` — name of the sync job (used for safety subdirectory).
    ///
    /// # Errors
    ///
    /// Returns an error if a remote dest references an unknown remote name or
    /// if the safety handler cannot be created.
    pub fn new(
        dests: &[&str],
        remotes: &[RemoteNode],
        safety_config: Option<&SafetyConfig>,
        safety_dir: &Path,
        job_name: &str,
    ) -> Result<Self> {
        Self::new_with_encryption(dests, remotes, safety_config, safety_dir, job_name, None)
    }

    /// Creates executors for all job destinations, optionally wrapping each
    /// executor in an [`EncryptingExecutor`] when an encryption key is provided.
    ///
    /// # Arguments
    ///
    /// * `dests` — unified list of destination strings (from `collect_destinations()`).
    /// * `remotes` — configured remote nodes (for resolving remote dest strings).
    /// * `safety_config` — per-job safety backup configuration.
    /// * `safety_dir` — base directory for safety copies.
    /// * `job_name` — name of the sync job (used for safety subdirectory).
    /// * `encryption_key` — if `Some`, files are encrypted before writing to dest.
    ///
    /// # Errors
    ///
    /// Returns an error if a remote dest references an unknown remote name or
    /// if the safety handler cannot be created.
    pub fn new_with_encryption(
        dests: &[&str],
        remotes: &[RemoteNode],
        safety_config: Option<&SafetyConfig>,
        safety_dir: &Path,
        job_name: &str,
        encryption_key: Option<EncryptionKey>,
    ) -> Result<Self> {
        let mut executors: Vec<(String, Box<dyn SyncExecutor>)> = Vec::new();

        // Build the safety handler if safety is enabled
        let safety_handler = build_safety_handler(safety_config, safety_dir, job_name)?;

        for dest_str in dests {
            let parsed = parse_dest(dest_str);
            let base_executor: Box<dyn SyncExecutor> = match parsed {
                ParsedDest::Local { path } => {
                    debug!(
                        dest = %dest_str,
                        path = %path.display(),
                        "creating LocalExecutor"
                    );
                    Box::new(LocalExecutor::new(path, safety_handler.clone()))
                }
                ParsedDest::Remote {
                    remote_name,
                    remote_path,
                } => {
                    // Verify that the remote name is defined in configuration
                    let remote = remotes
                        .iter()
                        .find(|r| r.name == remote_name)
                        .with_context(|| {
                            format!(
                                "remote '{}' referenced in dest '{}' \
                                 but not defined in [[remote]]",
                                remote_name, dest_str
                            )
                        })?;

                    debug!(
                        dest = %dest_str,
                        remote = %remote_name,
                        path = %remote_path,
                        "creating RemoteExecutor"
                    );

                    Box::new(RemoteExecutor::new(remote, remote_path.clone()))
                }
            };

            // Wrap with EncryptingExecutor if encryption is enabled for this job
            let final_executor: Box<dyn SyncExecutor> = match &encryption_key {
                Some(key) => {
                    debug!(
                        dest = %dest_str,
                        "wrapping executor with encryption layer"
                    );
                    Box::new(EncryptingExecutor::new(base_executor, key.clone()))
                }
                None => base_executor,
            };

            executors.push((dest_str.to_string(), final_executor));
        }

        Ok(Self { executors })
    }

    /// Creates a `DestRouter` with a single pre-built executor.
    ///
    /// Useful for testing or when the executor is constructed externally.
    pub fn from_executor(desc: String, executor: Box<dyn SyncExecutor>) -> Self {
        Self {
            executors: vec![(desc, executor)],
        }
    }

    /// Creates a `DestRouter` from a list of pre-built executors.
    pub fn from_executors(executors: Vec<(String, Box<dyn SyncExecutor>)>) -> Self {
        Self { executors }
    }

    /// Returns the number of destination executors.
    pub fn dest_count(&self) -> usize {
        self.executors.len()
    }

    /// Returns descriptions of all destinations.
    pub fn dest_descriptions(&self) -> Vec<&str> {
        self.executors
            .iter()
            .map(|(desc, _)| desc.as_str())
            .collect()
    }

    /// Executes a [`SyncPlan`] on all destinations sequentially.
    ///
    /// For each destination executor, the plan is executed in order:
    /// 1. Create directories (implicit via copy)
    /// 2. Copy new files
    /// 3. Update changed files
    /// 4. Delete orphan files
    ///
    /// # Arguments
    ///
    /// * `plan` — the sync plan to execute.
    /// * `source_root` — absolute path to the source directory.
    /// * `on_error` — error handling strategy.
    /// * `progress_cb` — optional callback for progress reporting.
    ///
    /// # Returns
    ///
    /// A combined [`SyncResult`] aggregating outcomes from all destinations.
    pub async fn execute_plan(
        &self,
        plan: &SyncPlan,
        source_root: &Path,
        on_error: OnError,
        progress_cb: Option<&ProgressCallback>,
    ) -> SyncResult {
        let started = Instant::now();
        let mut combined = SyncResult {
            success: true,
            ..SyncResult::default()
        };

        let total_files = (plan.to_copy.len() + plan.to_update.len() + plan.to_delete.len()) as u64;
        let total_bytes = plan.total_bytes();

        for (dest_desc, executor) in &self.executors {
            info!(dest = %dest_desc, "executing sync plan");

            let result = execute_plan_on_executor(
                executor.as_ref(),
                plan,
                source_root,
                on_error,
                progress_cb,
                total_files,
                total_bytes,
            )
            .await;

            // Merge results
            combined.files_synced += result.files_synced;
            combined.files_deleted += result.files_deleted;
            combined.bytes_transferred += result.bytes_transferred;
            combined.errors.extend(result.errors);
            if !result.success {
                combined.success = false;
                if on_error == OnError::Stop {
                    error!(
                        dest = %dest_desc,
                        "sync failed on destination, aborting remaining destinations"
                    );
                    break;
                }
            }
        }

        combined.duration = started.elapsed();
        combined
    }
}

/// Executes a sync plan on a single executor.
async fn execute_plan_on_executor(
    executor: &dyn SyncExecutor,
    plan: &SyncPlan,
    source_root: &Path,
    on_error: OnError,
    progress_cb: Option<&ProgressCallback>,
    total_files: u64,
    total_bytes: u64,
) -> SyncResult {
    let mut result = SyncResult {
        success: true,
        ..SyncResult::default()
    };

    let mut progress = SyncProgress {
        files_total: total_files,
        bytes_total: total_bytes,
        ..SyncProgress::default()
    };

    // ── Phase 1: Copy new files ────────────────────────────────────────
    for entry in &plan.to_copy {
        let src_path = source_root.join(&entry.rel_path);
        match executor.copy_file(&src_path, &entry.rel_path).await {
            Ok(bytes) => {
                result.files_synced += 1;
                result.bytes_transferred += bytes;
                progress.files_done += 1;
                progress.bytes_done += bytes;
            }
            Err(err) => {
                let sync_err = SyncError {
                    rel_path: entry.rel_path.clone(),
                    message: format!("copy failed: {err}"),
                };
                warn!(
                    path = %entry.rel_path.display(),
                    error = %err,
                    "failed to copy file"
                );
                result.errors.push(sync_err);
                progress.files_done += 1;

                if on_error == OnError::Stop {
                    result.success = false;
                    return result;
                }
            }
        }

        if let Some(cb) = progress_cb {
            cb(&progress);
        }
    }

    // ── Phase 2: Update changed files ──────────────────────────────────
    for entry in &plan.to_update {
        let src_path = source_root.join(&entry.rel_path);
        match executor.copy_file(&src_path, &entry.rel_path).await {
            Ok(bytes) => {
                result.files_synced += 1;
                result.bytes_transferred += bytes;
                progress.files_done += 1;
                progress.bytes_done += bytes;
            }
            Err(err) => {
                let sync_err = SyncError {
                    rel_path: entry.rel_path.clone(),
                    message: format!("update failed: {err}"),
                };
                warn!(
                    path = %entry.rel_path.display(),
                    error = %err,
                    "failed to update file"
                );
                result.errors.push(sync_err);
                progress.files_done += 1;

                if on_error == OnError::Stop {
                    result.success = false;
                    return result;
                }
            }
        }

        if let Some(cb) = progress_cb {
            cb(&progress);
        }
    }

    // ── Phase 3: Delete orphan files and directories ───────────────────
    for entry in &plan.to_delete {
        match executor.delete_file(&entry.rel_path).await {
            Ok(()) => {
                result.files_deleted += 1;
                progress.files_done += 1;
            }
            Err(err) => {
                let sync_err = SyncError {
                    rel_path: entry.rel_path.clone(),
                    message: format!("delete failed: {err}"),
                };
                warn!(
                    path = %entry.rel_path.display(),
                    error = %err,
                    "failed to delete file"
                );
                result.errors.push(sync_err);
                progress.files_done += 1;

                if on_error == OnError::Stop {
                    result.success = false;
                    return result;
                }
            }
        }

        if let Some(cb) = progress_cb {
            cb(&progress);
        }
    }

    // If we got here without aborting, check if there were non-fatal errors.
    if !result.errors.is_empty() {
        // Had errors but continued (skip mode) — still mark as success if
        // at least some work got done.
        debug!(
            error_count = result.errors.len(),
            "sync completed with non-fatal errors"
        );
    }

    result
}

/// Builds an optional [`SafetyHandler`] from configuration.
fn build_safety_handler(
    safety_config: Option<&SafetyConfig>,
    safety_dir: &Path,
    job_name: &str,
) -> Result<Option<SafetyHandler>> {
    let config = match safety_config {
        Some(c) if c.enabled => c,
        _ => return Ok(None),
    };

    let retention = config
        .retention
        .as_deref()
        .map(|s| {
            humantime::parse_duration(s)
                .with_context(|| format!("invalid retention duration: '{s}'"))
        })
        .transpose()?;

    let max_size = config
        .max_size
        .as_deref()
        .map(|s| {
            s.parse::<bytesize::ByteSize>()
                .map(|bs| bs.as_u64())
                .map_err(|e| anyhow::anyhow!("invalid max_size value '{}': {}", s, e))
        })
        .transpose()?;

    let handler = SafetyHandler::new(safety_dir, job_name, retention, max_size);
    Ok(Some(handler))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::Secret;

    use crate::core::sync_plan::{DeleteEntry, SyncEntry, SyncPlan};
    use std::path::PathBuf;

    // ── Helper: create a temp source tree ───────────────────────────────

    async fn create_source_files(dir: &Path) {
        tokio::fs::create_dir_all(dir).await.unwrap();
        tokio::fs::write(dir.join("a.txt"), b"hello").await.unwrap();
        tokio::fs::write(dir.join("b.txt"), b"world").await.unwrap();
        tokio::fs::create_dir_all(dir.join("sub")).await.unwrap();
        tokio::fs::write(dir.join("sub/c.txt"), b"nested")
            .await
            .unwrap();
    }

    // ── DestRouter with local executor ──────────────────────────────────

    #[tokio::test]
    async fn test_dest_router_local_executor() {
        let tmp = tempfile::tempdir().unwrap();
        let dest_path = tmp.path().join("dest");
        tokio::fs::create_dir_all(&dest_path).await.unwrap();

        let dest_str = dest_path.to_string_lossy().to_string();
        let router = DestRouter::new(
            &[dest_str.as_str()],
            &[],  // no remotes
            None, // no safety
            tmp.path(),
            "test_job",
        )
        .unwrap();

        assert_eq!(router.dest_count(), 1);
        assert!(router.dest_descriptions()[0].contains(&dest_str));
    }

    #[tokio::test]
    async fn test_dest_router_execute_copy_plan() {
        let src_dir = tempfile::tempdir().unwrap();
        let dest_dir = tempfile::tempdir().unwrap();

        // Create source files
        create_source_files(src_dir.path()).await;

        let dest_str = dest_dir.path().to_string_lossy().to_string();
        let router =
            DestRouter::new(&[dest_str.as_str()], &[], None, dest_dir.path(), "test_job").unwrap();

        let plan = SyncPlan {
            to_copy: vec![
                SyncEntry {
                    rel_path: PathBuf::from("a.txt"),
                    size: 5,
                },
                SyncEntry {
                    rel_path: PathBuf::from("b.txt"),
                    size: 5,
                },
                SyncEntry {
                    rel_path: PathBuf::from("sub/c.txt"),
                    size: 6,
                },
            ],
            to_update: vec![],
            to_delete: vec![],
        };

        let result = router
            .execute_plan(&plan, src_dir.path(), OnError::Skip, None)
            .await;

        assert!(result.success);
        assert_eq!(result.files_synced, 3);
        assert_eq!(result.bytes_transferred, 16);
        assert!(result.errors.is_empty());

        // Verify files exist on dest
        let content = tokio::fs::read_to_string(dest_dir.path().join("a.txt"))
            .await
            .unwrap();
        assert_eq!(content, "hello");

        let content = tokio::fs::read_to_string(dest_dir.path().join("sub/c.txt"))
            .await
            .unwrap();
        assert_eq!(content, "nested");
    }

    #[tokio::test]
    async fn test_dest_router_execute_delete_plan() {
        let src_dir = tempfile::tempdir().unwrap();
        let dest_dir = tempfile::tempdir().unwrap();

        // Create a file in dest that should be deleted
        tokio::fs::write(dest_dir.path().join("orphan.txt"), b"delete me")
            .await
            .unwrap();

        let dest_str = dest_dir.path().to_string_lossy().to_string();
        let router =
            DestRouter::new(&[dest_str.as_str()], &[], None, dest_dir.path(), "test_job").unwrap();

        let plan = SyncPlan {
            to_copy: vec![],
            to_update: vec![],
            to_delete: vec![DeleteEntry {
                rel_path: PathBuf::from("orphan.txt"),
                is_dir: false,
            }],
        };

        let result = router
            .execute_plan(&plan, src_dir.path(), OnError::Skip, None)
            .await;

        assert!(result.success);
        assert_eq!(result.files_deleted, 1);
        assert!(!dest_dir.path().join("orphan.txt").exists());
    }

    #[tokio::test]
    async fn test_dest_router_execute_update_plan() {
        let src_dir = tempfile::tempdir().unwrap();
        let dest_dir = tempfile::tempdir().unwrap();

        // Create source file with new content
        tokio::fs::write(src_dir.path().join("file.txt"), b"new content")
            .await
            .unwrap();
        // Create dest file with old content
        tokio::fs::write(dest_dir.path().join("file.txt"), b"old content")
            .await
            .unwrap();

        let dest_str = dest_dir.path().to_string_lossy().to_string();
        let router =
            DestRouter::new(&[dest_str.as_str()], &[], None, dest_dir.path(), "test_job").unwrap();

        let plan = SyncPlan {
            to_copy: vec![],
            to_update: vec![SyncEntry {
                rel_path: PathBuf::from("file.txt"),
                size: 11,
            }],
            to_delete: vec![],
        };

        let result = router
            .execute_plan(&plan, src_dir.path(), OnError::Skip, None)
            .await;

        assert!(result.success);
        assert_eq!(result.files_synced, 1);

        let content = tokio::fs::read_to_string(dest_dir.path().join("file.txt"))
            .await
            .unwrap();
        assert_eq!(content, "new content");
    }

    // ── Error handling ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_dest_router_skip_on_error() {
        let src_dir = tempfile::tempdir().unwrap();
        let dest_dir = tempfile::tempdir().unwrap();

        // Create one source file but reference two in the plan
        tokio::fs::write(src_dir.path().join("exists.txt"), b"data")
            .await
            .unwrap();

        let dest_str = dest_dir.path().to_string_lossy().to_string();
        let router =
            DestRouter::new(&[dest_str.as_str()], &[], None, dest_dir.path(), "test_job").unwrap();

        let plan = SyncPlan {
            to_copy: vec![
                SyncEntry {
                    rel_path: PathBuf::from("nonexistent.txt"),
                    size: 100,
                },
                SyncEntry {
                    rel_path: PathBuf::from("exists.txt"),
                    size: 4,
                },
            ],
            to_update: vec![],
            to_delete: vec![],
        };

        let result = router
            .execute_plan(&plan, src_dir.path(), OnError::Skip, None)
            .await;

        // One file succeeded, one failed — but we continued
        assert_eq!(result.files_synced, 1);
        assert_eq!(result.errors.len(), 1);
        assert!(
            result.errors[0]
                .rel_path
                .to_string_lossy()
                .contains("nonexistent")
        );
    }

    #[tokio::test]
    async fn test_dest_router_stop_on_error() {
        let src_dir = tempfile::tempdir().unwrap();
        let dest_dir = tempfile::tempdir().unwrap();

        // Create one source file
        tokio::fs::write(src_dir.path().join("second.txt"), b"ok")
            .await
            .unwrap();

        let dest_str = dest_dir.path().to_string_lossy().to_string();
        let router =
            DestRouter::new(&[dest_str.as_str()], &[], None, dest_dir.path(), "test_job").unwrap();

        let plan = SyncPlan {
            to_copy: vec![
                SyncEntry {
                    rel_path: PathBuf::from("missing.txt"),
                    size: 10,
                },
                SyncEntry {
                    rel_path: PathBuf::from("second.txt"),
                    size: 2,
                },
            ],
            to_update: vec![],
            to_delete: vec![],
        };

        let result = router
            .execute_plan(&plan, src_dir.path(), OnError::Stop, None)
            .await;

        // Should have stopped after the first error
        assert!(!result.success);
        assert_eq!(result.errors.len(), 1);
        // second.txt should NOT have been copied
        assert!(!dest_dir.path().join("second.txt").exists());
    }

    // ── Multiple destinations ───────────────────────────────────────────

    #[tokio::test]
    async fn test_dest_router_multiple_local_dests() {
        let src_dir = tempfile::tempdir().unwrap();
        let dest1 = tempfile::tempdir().unwrap();
        let dest2 = tempfile::tempdir().unwrap();

        tokio::fs::write(src_dir.path().join("file.txt"), b"data")
            .await
            .unwrap();

        let dest1_str = dest1.path().to_string_lossy().to_string();
        let dest2_str = dest2.path().to_string_lossy().to_string();

        let router = DestRouter::new(
            &[dest1_str.as_str(), dest2_str.as_str()],
            &[],
            None,
            src_dir.path(),
            "test_job",
        )
        .unwrap();

        assert_eq!(router.dest_count(), 2);

        let plan = SyncPlan {
            to_copy: vec![SyncEntry {
                rel_path: PathBuf::from("file.txt"),
                size: 4,
            }],
            to_update: vec![],
            to_delete: vec![],
        };

        let result = router
            .execute_plan(&plan, src_dir.path(), OnError::Skip, None)
            .await;

        assert!(result.success);
        // 1 file copied to each of 2 destinations = 2 total
        assert_eq!(result.files_synced, 2);
        assert_eq!(result.bytes_transferred, 8);

        // Both destinations should have the file
        let c1 = tokio::fs::read_to_string(dest1.path().join("file.txt"))
            .await
            .unwrap();
        let c2 = tokio::fs::read_to_string(dest2.path().join("file.txt"))
            .await
            .unwrap();
        assert_eq!(c1, "data");
        assert_eq!(c2, "data");
    }

    // ── Remote dest validation ──────────────────────────────────────────

    #[test]
    fn test_dest_router_unknown_remote_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let result = DestRouter::new(
            &["unknown_server:backup/docs"],
            &[], // no remotes defined
            None,
            tmp.path(),
            "test_job",
        );
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("unknown_server"));
    }

    #[test]
    fn test_dest_router_known_remote_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        let remotes = vec![RemoteNode {
            name: "myserver".to_string(),
            host: "192.168.1.100:7854".to_string(),
            auth_token: Secret::new("token"),
            tls_ca: None,
            allow_self_signed: false,
        }];

        let result = DestRouter::new(
            &["myserver:backup/docs"],
            &remotes,
            None,
            tmp.path(),
            "test_job",
        );
        assert!(result.is_ok());
        let router = result.unwrap();
        assert_eq!(router.dest_count(), 1);
    }

    // ── Progress callback ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_dest_router_progress_callback() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};

        let src_dir = tempfile::tempdir().unwrap();
        let dest_dir = tempfile::tempdir().unwrap();

        tokio::fs::write(src_dir.path().join("a.txt"), b"aaa")
            .await
            .unwrap();
        tokio::fs::write(src_dir.path().join("b.txt"), b"bbb")
            .await
            .unwrap();

        let dest_str = dest_dir.path().to_string_lossy().to_string();
        let router =
            DestRouter::new(&[dest_str.as_str()], &[], None, dest_dir.path(), "test_job").unwrap();

        let plan = SyncPlan {
            to_copy: vec![
                SyncEntry {
                    rel_path: PathBuf::from("a.txt"),
                    size: 3,
                },
                SyncEntry {
                    rel_path: PathBuf::from("b.txt"),
                    size: 3,
                },
            ],
            to_update: vec![],
            to_delete: vec![],
        };

        let callback_count = Arc::new(AtomicU64::new(0));
        let count_clone = callback_count.clone();
        let cb: ProgressCallback = Box::new(move |_progress| {
            count_clone.fetch_add(1, Ordering::SeqCst);
        });

        router
            .execute_plan(&plan, src_dir.path(), OnError::Skip, Some(&cb))
            .await;

        // Should have been called once per copy operation
        assert_eq!(callback_count.load(Ordering::SeqCst), 2);
    }

    // ── from_executor helper ────────────────────────────────────────────

    #[tokio::test]
    async fn test_from_executor() {
        let dest_dir = tempfile::tempdir().unwrap();
        let executor = LocalExecutor::new(dest_dir.path().to_path_buf(), None);
        let router = DestRouter::from_executor("test".to_string(), Box::new(executor));
        assert_eq!(router.dest_count(), 1);
    }

    // ── Empty plan ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_execute_empty_plan() {
        let src_dir = tempfile::tempdir().unwrap();
        let dest_dir = tempfile::tempdir().unwrap();

        let dest_str = dest_dir.path().to_string_lossy().to_string();
        let router =
            DestRouter::new(&[dest_str.as_str()], &[], None, dest_dir.path(), "test_job").unwrap();

        let plan = SyncPlan::default();
        let result = router
            .execute_plan(&plan, src_dir.path(), OnError::Skip, None)
            .await;

        assert!(result.success);
        assert_eq!(result.files_synced, 0);
        assert_eq!(result.files_deleted, 0);
        assert!(result.errors.is_empty());
    }

    // ── Safety integration ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_dest_router_with_safety() {
        let src_dir = tempfile::tempdir().unwrap();
        let dest_dir = tempfile::tempdir().unwrap();
        let safety_dir = tempfile::tempdir().unwrap();

        // Create a file that will be overwritten
        tokio::fs::write(src_dir.path().join("file.txt"), b"new content")
            .await
            .unwrap();
        tokio::fs::write(dest_dir.path().join("file.txt"), b"old content")
            .await
            .unwrap();

        let safety_config = SafetyConfig {
            enabled: true,
            retention: Some("7d".to_string()),
            max_size: None,
        };

        let dest_str = dest_dir.path().to_string_lossy().to_string();
        let router = DestRouter::new(
            &[dest_str.as_str()],
            &[],
            Some(&safety_config),
            safety_dir.path(),
            "test_job",
        )
        .unwrap();

        let plan = SyncPlan {
            to_copy: vec![],
            to_update: vec![SyncEntry {
                rel_path: PathBuf::from("file.txt"),
                size: 11,
            }],
            to_delete: vec![],
        };

        let result = router
            .execute_plan(&plan, src_dir.path(), OnError::Skip, None)
            .await;

        assert!(result.success);
        assert_eq!(result.files_synced, 1);

        // Verify safety backup was created
        let job_safety = safety_dir.path().join("test_job");
        assert!(job_safety.exists(), "safety directory should exist");

        // There should be a timestamped subdirectory with the backup
        let mut entries = tokio::fs::read_dir(&job_safety).await.unwrap();
        let mut found_backup = false;
        while let Some(entry) = entries.next_entry().await.unwrap() {
            let backup_file = entry.path().join("file.txt");
            if backup_file.exists() {
                let content = tokio::fs::read_to_string(&backup_file).await.unwrap();
                assert_eq!(content, "old content");
                found_backup = true;
            }
        }
        assert!(found_backup, "safety backup should contain old file");
    }

    // ── build_safety_handler ────────────────────────────────────────────

    #[test]
    fn test_build_safety_handler_disabled() {
        let tmp = tempfile::tempdir().unwrap();
        let config = SafetyConfig {
            enabled: false,
            retention: None,
            max_size: None,
        };
        let handler = build_safety_handler(Some(&config), tmp.path(), "job").unwrap();
        assert!(handler.is_none());
    }

    #[test]
    fn test_build_safety_handler_enabled() {
        let tmp = tempfile::tempdir().unwrap();
        let config = SafetyConfig {
            enabled: true,
            retention: Some("7d".to_string()),
            max_size: Some("1GB".to_string()),
        };
        let handler = build_safety_handler(Some(&config), tmp.path(), "job").unwrap();
        assert!(handler.is_some());
    }

    #[test]
    fn test_build_safety_handler_none_config() {
        let tmp = tempfile::tempdir().unwrap();
        let handler = build_safety_handler(None, tmp.path(), "job").unwrap();
        assert!(handler.is_none());
    }

    #[test]
    fn test_build_safety_handler_invalid_retention() {
        let tmp = tempfile::tempdir().unwrap();
        let config = SafetyConfig {
            enabled: true,
            retention: Some("not-a-duration".to_string()),
            max_size: None,
        };
        let result = build_safety_handler(Some(&config), tmp.path(), "job");
        assert!(result.is_err());
    }

    #[test]
    fn test_build_safety_handler_invalid_max_size() {
        let tmp = tempfile::tempdir().unwrap();
        let config = SafetyConfig {
            enabled: true,
            retention: None,
            max_size: Some("not-a-size".to_string()),
        };
        let result = build_safety_handler(Some(&config), tmp.path(), "job");
        assert!(result.is_err());
    }
}
