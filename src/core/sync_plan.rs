//! Sync plan types — describes the set of operations needed to synchronize
//! a source file tree to a destination.
//!
//! A [`SyncPlan`] is produced by the diff algorithm (comparing source and dest
//! [`FileTree`]s) and consumed by a [`SyncExecutor`] (or [`DestRouter`]) to
//! perform the actual file operations.

use std::fmt;
use std::path::PathBuf;

/// A complete synchronization plan: the list of file-level operations that
/// must be executed to bring the destination in sync with the source.
///
/// Synchronization is **unidirectional** — the source is always the sole
/// source of truth.
#[derive(Debug, Clone, Default)]
pub struct SyncPlan {
    /// Files that exist in the source but not in the destination — must be copied.
    pub to_copy: Vec<SyncEntry>,

    /// Files that exist in both but differ (size, mtime, or hash) — must be updated.
    pub to_update: Vec<SyncEntry>,

    /// Files that exist in the destination but not in the source — must be deleted.
    pub to_delete: Vec<DeleteEntry>,
}

impl SyncPlan {
    /// Returns `true` if the plan contains no operations.
    pub fn is_empty(&self) -> bool {
        self.to_copy.is_empty() && self.to_update.is_empty() && self.to_delete.is_empty()
    }

    /// Total number of operations in the plan.
    pub fn total_operations(&self) -> usize {
        self.to_copy.len() + self.to_update.len() + self.to_delete.len()
    }

    /// Total bytes that need to be transferred (copy + update).
    pub fn total_bytes(&self) -> u64 {
        let copy_bytes: u64 = self.to_copy.iter().map(|e| e.size).sum();
        let update_bytes: u64 = self.to_update.iter().map(|e| e.size).sum();
        copy_bytes + update_bytes
    }
}

impl fmt::Display for SyncPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Sync plan:")?;
        writeln!(f, "  To copy:   {} files", self.to_copy.len())?;
        writeln!(f, "  To update: {} files", self.to_update.len())?;
        writeln!(f, "  To delete: {} files", self.to_delete.len())?;
        writeln!(f, "  Total bytes to transfer: {}", self.total_bytes())?;
        Ok(())
    }
}

/// An entry describing a file to be copied or updated.
#[derive(Debug, Clone)]
pub struct SyncEntry {
    /// Relative path from the source/dest root.
    pub rel_path: PathBuf,

    /// Size of the source file in bytes.
    pub size: u64,
}

/// An entry describing a file to be deleted from the destination.
#[derive(Debug, Clone)]
pub struct DeleteEntry {
    /// Relative path from the dest root.
    pub rel_path: PathBuf,

    /// Whether this entry is a directory (directories are deleted after their contents).
    pub is_dir: bool,
}

/// The result of executing a sync plan.
#[derive(Debug, Clone, Default)]
pub struct SyncResult {
    /// Whether the sync completed without fatal errors.
    pub success: bool,

    /// Number of files successfully synced (copied + updated).
    pub files_synced: u64,

    /// Number of files deleted.
    pub files_deleted: u64,

    /// Total bytes transferred.
    pub bytes_transferred: u64,

    /// Duration of the sync operation.
    pub duration: std::time::Duration,

    /// Errors encountered during sync (non-fatal if `skip_on_error` is enabled).
    pub errors: Vec<SyncError>,
}

/// A non-fatal error encountered during sync execution.
#[derive(Debug, Clone)]
pub struct SyncError {
    /// The relative path of the file that caused the error.
    pub rel_path: PathBuf,

    /// A human-readable description of the error.
    pub message: String,
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.rel_path.display(), self.message)
    }
}

/// Progress information for an ongoing synchronization.
#[derive(Debug, Clone, Default)]
pub struct SyncProgress {
    /// Number of files processed so far.
    pub files_done: u64,

    /// Total number of files to process.
    pub files_total: u64,

    /// Bytes transferred so far.
    pub bytes_done: u64,

    /// Total bytes to transfer.
    pub bytes_total: u64,
}

impl SyncProgress {
    /// Returns the progress as a fraction (0.0 to 1.0). Returns 0.0 if total is zero.
    pub fn fraction(&self) -> f64 {
        if self.bytes_total == 0 {
            if self.files_total == 0 {
                return 0.0;
            }
            return self.files_done as f64 / self.files_total as f64;
        }
        self.bytes_done as f64 / self.bytes_total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_plan() {
        let plan = SyncPlan::default();
        assert!(plan.is_empty());
        assert_eq!(plan.total_operations(), 0);
        assert_eq!(plan.total_bytes(), 0);
    }

    #[test]
    fn test_plan_with_entries() {
        let plan = SyncPlan {
            to_copy: vec![
                SyncEntry {
                    rel_path: PathBuf::from("a.txt"),
                    size: 100,
                },
                SyncEntry {
                    rel_path: PathBuf::from("b.txt"),
                    size: 200,
                },
            ],
            to_update: vec![SyncEntry {
                rel_path: PathBuf::from("c.txt"),
                size: 50,
            }],
            to_delete: vec![DeleteEntry {
                rel_path: PathBuf::from("old.txt"),
                is_dir: false,
            }],
        };

        assert!(!plan.is_empty());
        assert_eq!(plan.total_operations(), 4);
        assert_eq!(plan.total_bytes(), 350);
    }

    #[test]
    fn test_plan_display() {
        let plan = SyncPlan::default();
        let text = format!("{plan}");
        assert!(text.contains("Sync plan:"));
        assert!(text.contains("To copy:"));
    }

    #[test]
    fn test_sync_progress_fraction() {
        let progress = SyncProgress {
            files_done: 5,
            files_total: 10,
            bytes_done: 500,
            bytes_total: 1000,
        };
        assert!((progress.fraction() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_sync_progress_fraction_zero_bytes() {
        let progress = SyncProgress {
            files_done: 3,
            files_total: 6,
            bytes_done: 0,
            bytes_total: 0,
        };
        assert!((progress.fraction() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_sync_progress_fraction_zero_total() {
        let progress = SyncProgress::default();
        assert!((progress.fraction() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_sync_result_default() {
        let result = SyncResult::default();
        assert!(!result.success);
        assert_eq!(result.files_synced, 0);
        assert_eq!(result.errors.len(), 0);
    }
}
