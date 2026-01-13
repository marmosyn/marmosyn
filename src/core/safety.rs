//! Safety backup handler: saves old file versions before overwrite/deletion.
//!
//! When safety backup is enabled for a sync job, the old version of a file
//! on the destination is copied to `<safety_dir>/<job_name>/<timestamp>/<rel_path>`
//! before being overwritten or deleted.
//!
//! Cleanup is performed based on configurable `retention` (time-based) and
//! `max_size` (space-based) limits.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

/// Statistics returned after a cleanup operation.
#[derive(Debug, Clone, Default)]
pub struct CleanupStats {
    /// Number of safety copy directories removed.
    pub dirs_removed: u64,
    /// Number of individual files removed.
    pub files_removed: u64,
    /// Total bytes freed.
    pub bytes_freed: u64,
}

/// Safety backup handler: saves old file versions before overwrite/deletion.
///
/// Each backup is stored under `<safety_dir>/<job_name>/<timestamp>/<rel_path>`,
/// where `<timestamp>` is in the format `YYYYMMDDTHHmmSS`.
///
/// The handler also provides a [`cleanup`](SafetyHandler::cleanup) method that
/// removes backups older than `retention` or exceeding `max_size`.
#[derive(Debug, Clone)]
pub struct SafetyHandler {
    /// Base directory for this job's safety copies: `<safety_dir>/<job_name>/`.
    safety_dir: PathBuf,
    /// Maximum age of safety copies. Copies older than this are removed.
    /// `None` means unlimited retention.
    retention: Option<Duration>,
    /// Maximum total size (in bytes) of safety copies for this job.
    /// When exceeded, the oldest copies are removed first.
    /// `None` means unlimited size.
    max_size: Option<u64>,
}

impl SafetyHandler {
    /// Creates a new `SafetyHandler`.
    ///
    /// # Arguments
    ///
    /// * `safety_base_dir` — the top-level safety directory (e.g. `<data_dir>/safety/`).
    /// * `job_name` — the sync job name (used as a subdirectory).
    /// * `retention` — optional maximum age of safety copies.
    /// * `max_size` — optional maximum total size in bytes.
    pub fn new(
        safety_base_dir: &Path,
        job_name: &str,
        retention: Option<Duration>,
        max_size: Option<u64>,
    ) -> Self {
        let safety_dir = safety_base_dir.join(job_name);
        Self {
            safety_dir,
            retention,
            max_size,
        }
    }

    /// Returns the safety directory path for this job.
    pub fn safety_dir(&self) -> &Path {
        &self.safety_dir
    }

    /// Save the old file version before overwrite/deletion.
    ///
    /// Copies the file at `file_path` (absolute path on the destination) into
    /// `<safety_dir>/<job_name>/<timestamp>/<rel_path>`.
    ///
    /// This is a no-op if `file_path` does not exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the copy operation fails (e.g. permission denied).
    pub async fn backup_file(&self, file_path: &Path, rel_path: &Path) -> Result<()> {
        if !file_path.exists() {
            return Ok(());
        }

        let timestamp = format_timestamp(SystemTime::now());
        let backup_path = self.safety_dir.join(&timestamp).join(rel_path);

        debug!(
            src = %file_path.display(),
            dst = %backup_path.display(),
            "creating safety backup"
        );

        // Ensure parent directory exists
        if let Some(parent) = backup_path.parent() {
            tokio::fs::create_dir_all(parent).await.with_context(|| {
                format!(
                    "failed to create safety backup directory '{}'",
                    parent.display()
                )
            })?;
        }

        // Copy the file
        tokio::fs::copy(file_path, &backup_path)
            .await
            .with_context(|| {
                format!(
                    "failed to create safety backup of '{}' to '{}'",
                    file_path.display(),
                    backup_path.display()
                )
            })?;

        debug!(
            path = %backup_path.display(),
            "safety backup created"
        );

        Ok(())
    }

    /// Cleanup: remove safety copies older than `retention` and/or exceeding `max_size`.
    ///
    /// The cleanup logic:
    /// 1. List all timestamp directories under `<safety_dir>/<job_name>/`.
    /// 2. If `retention` is set, remove directories older than the retention period.
    /// 3. If `max_size` is set, compute the total size of remaining directories
    ///    and remove the oldest ones until the total is within the limit.
    ///
    /// # Errors
    ///
    /// Returns an error only if the safety directory cannot be read. Individual
    /// removal failures are logged as warnings but do not cause the overall
    /// cleanup to fail.
    pub async fn cleanup(&self) -> Result<CleanupStats> {
        let mut stats = CleanupStats::default();

        if !self.safety_dir.exists() {
            return Ok(stats);
        }

        // Collect all timestamp directories and their metadata
        let mut entries = self.list_timestamp_dirs().await?;

        // Sort by name (which is a timestamp, so lexicographic order = chronological order)
        entries.sort_by(|a, b| a.name.cmp(&b.name));

        let now = SystemTime::now();

        // 1. Remove entries older than retention
        if let Some(retention) = self.retention {
            let cutoff = now.checked_sub(retention).unwrap_or(SystemTime::UNIX_EPOCH);

            let mut i = 0;
            while i < entries.len() {
                if entries[i].mtime < cutoff {
                    let removed = self.remove_timestamp_dir(&entries[i].path).await;
                    stats.dirs_removed += 1;
                    stats.files_removed += removed.files;
                    stats.bytes_freed += removed.bytes;
                    entries.remove(i);
                } else {
                    i += 1;
                }
            }
        }

        // 2. Enforce max_size by removing oldest entries first
        if let Some(max_size) = self.max_size {
            let mut total_size: u64 = entries.iter().map(|e| e.total_size).sum();

            while total_size > max_size && !entries.is_empty() {
                let oldest = entries.remove(0);
                total_size = total_size.saturating_sub(oldest.total_size);
                let removed = self.remove_timestamp_dir(&oldest.path).await;
                stats.dirs_removed += 1;
                stats.files_removed += removed.files;
                stats.bytes_freed += removed.bytes;
            }
        }

        if stats.dirs_removed > 0 {
            info!(
                job_dir = %self.safety_dir.display(),
                dirs_removed = stats.dirs_removed,
                files_removed = stats.files_removed,
                bytes_freed = stats.bytes_freed,
                "safety cleanup completed"
            );
        }

        Ok(stats)
    }

    /// Computes the total size of all safety copies for this job.
    pub async fn total_size(&self) -> Result<u64> {
        if !self.safety_dir.exists() {
            return Ok(0);
        }

        let entries = self.list_timestamp_dirs().await?;
        Ok(entries.iter().map(|e| e.total_size).sum())
    }

    /// Lists all timestamp directories inside the job's safety directory.
    async fn list_timestamp_dirs(&self) -> Result<Vec<TimestampDirInfo>> {
        let mut result = Vec::new();

        let safety_dir = self.safety_dir.clone();
        let entries = tokio::task::spawn_blocking(move || -> Result<Vec<TimestampDirInfo>> {
            let mut infos = Vec::new();

            let read_dir = match std::fs::read_dir(&safety_dir) {
                Ok(rd) => rd,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "failed to read safety directory '{}': {}",
                        safety_dir.display(),
                        e
                    ))
                }
            };

            for entry in read_dir {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        warn!(error = %e, "skipping unreadable safety directory entry");
                        continue;
                    }
                };

                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }

                let name = entry.file_name().to_string_lossy().to_string();

                let metadata = match entry.metadata() {
                    Ok(m) => m,
                    Err(e) => {
                        warn!(
                            path = %path.display(),
                            error = %e,
                            "failed to read safety dir metadata"
                        );
                        continue;
                    }
                };

                let mtime = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                let total_size = dir_total_size(&path);

                infos.push(TimestampDirInfo {
                    name,
                    path,
                    mtime,
                    total_size,
                });
            }

            Ok(infos)
        })
        .await??;

        result.extend(entries);
        Ok(result)
    }

    /// Removes a single timestamp directory and all its contents.
    /// Returns the count of files and bytes removed.
    async fn remove_timestamp_dir(&self, path: &Path) -> RemoveResult {
        let path = path.to_path_buf();
        let result = tokio::task::spawn_blocking(move || {
            let total_size = dir_total_size(&path);
            let file_count = dir_file_count(&path);

            match std::fs::remove_dir_all(&path) {
                Ok(()) => {
                    debug!(path = %path.display(), "removed safety backup directory");
                    RemoveResult {
                        files: file_count,
                        bytes: total_size,
                    }
                }
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "failed to remove safety backup directory"
                    );
                    RemoveResult { files: 0, bytes: 0 }
                }
            }
        })
        .await
        .unwrap_or(RemoveResult { files: 0, bytes: 0 });

        result
    }
}

/// Internal info about a timestamp-named subdirectory in the safety dir.
#[derive(Debug)]
struct TimestampDirInfo {
    /// Directory name (the timestamp string, e.g. "20250710T143022").
    name: String,
    /// Full path to the directory.
    path: PathBuf,
    /// Modification time of the directory itself.
    mtime: SystemTime,
    /// Total size of all files inside the directory (recursive).
    total_size: u64,
}

/// Result of removing a directory.
struct RemoveResult {
    files: u64,
    bytes: u64,
}

/// Formats a `SystemTime` as a timestamp string suitable for directory names.
///
/// Format: `YYYYMMDDTHHmmSS` (e.g. `20250710T143022`).
fn format_timestamp(time: SystemTime) -> String {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    // Simple UTC timestamp computation without external deps
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since 1970-01-01 to Y-M-D (simplified Gregorian calendar)
    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}",
        year, month, day, hours, minutes, seconds
    )
}

/// Converts days since 1970-01-01 to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm based on Howard Hinnant's civil_from_days
    // (http://howardhinnant.github.io/date_algorithms.html)
    let z = days + 719468; // shift epoch from 1970-01-01 to 0000-03-01
    let era = z / 146097; // 400-year era
    let doe = z - era * 146097; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // year of era [0, 399]
    let y = yoe + era * 400; // full year (March-based)
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // month index [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // day [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // month [1, 12]
    let y = if m <= 2 { y + 1 } else { y }; // adjust year for Jan/Feb

    (y, m, d)
}

/// Recursively computes the total size of all files in a directory.
fn dir_total_size(path: &Path) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if entry_path.is_file() {
                total += entry.metadata().map(|m| m.len()).unwrap_or(0);
            } else if entry_path.is_dir() {
                total += dir_total_size(&entry_path);
            }
        }
    }
    total
}

/// Recursively counts the number of files in a directory.
fn dir_file_count(path: &Path) -> u64 {
    let mut count = 0u64;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if entry_path.is_file() {
                count += 1;
            } else if entry_path.is_dir() {
                count += dir_file_count(&entry_path);
            }
        }
    }
    count
}

/// Parses a human-readable duration string like `"7d"`, `"24h"`, `"30days"` into a `Duration`.
///
/// Uses the `humantime` crate for parsing. Returns `None` if the string is invalid.
pub fn parse_retention(s: &str) -> Option<Duration> {
    humantime::parse_duration(s).ok()
}

/// Parses a human-readable size string like `"500MB"`, `"10GB"` into bytes.
///
/// Returns `None` if the string is invalid.
pub fn parse_max_size(s: &str) -> Option<u64> {
    s.parse::<bytesize::ByteSize>().ok().map(|b| b.as_u64())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_format_timestamp() {
        // 2025-01-01T00:00:00 UTC = 1735689600
        let ts = format_timestamp(SystemTime::UNIX_EPOCH + Duration::from_secs(1735689600));
        assert!(ts.contains('T'));
        assert_eq!(ts.len(), 15); // YYYYMMDDTHHmmSS
    }

    #[test]
    fn test_format_timestamp_epoch() {
        let ts = format_timestamp(SystemTime::UNIX_EPOCH);
        assert_eq!(ts, "19700101T000000");
    }

    #[test]
    fn test_parse_retention() {
        assert!(parse_retention("7d").is_some());
        assert!(parse_retention("24h").is_some());
        assert!(parse_retention("30days").is_some());
        assert!(parse_retention("1s").is_some());
        assert!(parse_retention("invalid").is_none());
    }

    #[test]
    fn test_parse_max_size() {
        assert_eq!(parse_max_size("500MB"), Some(500_000_000));
        assert_eq!(parse_max_size("10GB"), Some(10_000_000_000));
        assert!(parse_max_size("invalid").is_none());
    }

    #[test]
    fn test_dir_total_size() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "hello").unwrap();
        fs::write(dir.path().join("b.txt"), "world!").unwrap();

        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("c.txt"), "nested").unwrap();

        let total = dir_total_size(dir.path());
        assert_eq!(total, 5 + 6 + 6); // "hello" + "world!" + "nested"
    }

    #[test]
    fn test_dir_file_count() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "a").unwrap();
        fs::write(dir.path().join("b.txt"), "b").unwrap();

        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("c.txt"), "c").unwrap();

        assert_eq!(dir_file_count(dir.path()), 3);
    }

    #[test]
    fn test_dir_total_size_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(dir_total_size(dir.path()), 0);
    }

    #[test]
    fn test_dir_total_size_nonexistent() {
        assert_eq!(dir_total_size(Path::new("/nonexistent/path")), 0);
    }

    #[tokio::test]
    async fn test_safety_handler_backup_file() {
        let safety_base = tempfile::tempdir().unwrap();
        let dest_dir = tempfile::tempdir().unwrap();

        // Create a file to backup
        let file_path = dest_dir.path().join("report.txt");
        fs::write(&file_path, "old content").unwrap();

        let handler = SafetyHandler::new(safety_base.path(), "docs", None, None);

        handler
            .backup_file(&file_path, Path::new("report.txt"))
            .await
            .unwrap();

        // Verify backup exists
        let job_dir = safety_base.path().join("docs");
        assert!(job_dir.exists());

        // There should be one timestamp directory
        let entries: Vec<_> = fs::read_dir(&job_dir).unwrap().collect();
        assert_eq!(entries.len(), 1);

        // The backup file should contain the old content
        let ts_dir = entries[0].as_ref().unwrap().path();
        let backup_file = ts_dir.join("report.txt");
        assert!(backup_file.exists());
        let content = fs::read_to_string(&backup_file).unwrap();
        assert_eq!(content, "old content");
    }

    #[tokio::test]
    async fn test_safety_handler_backup_nonexistent_is_noop() {
        let safety_base = tempfile::tempdir().unwrap();
        let handler = SafetyHandler::new(safety_base.path(), "docs", None, None);

        // Should not error for a nonexistent file
        handler
            .backup_file(Path::new("/nonexistent/file.txt"), Path::new("file.txt"))
            .await
            .unwrap();

        // Safety dir should not be created
        assert!(!safety_base.path().join("docs").exists());
    }

    #[tokio::test]
    async fn test_safety_handler_backup_nested_path() {
        let safety_base = tempfile::tempdir().unwrap();
        let dest_dir = tempfile::tempdir().unwrap();

        let nested = dest_dir.path().join("sub").join("dir");
        fs::create_dir_all(&nested).unwrap();
        let file_path = nested.join("data.bin");
        fs::write(&file_path, "binary data").unwrap();

        let handler = SafetyHandler::new(safety_base.path(), "job1", None, None);

        handler
            .backup_file(&file_path, Path::new("sub/dir/data.bin"))
            .await
            .unwrap();

        // Find the timestamp dir and check
        let job_dir = safety_base.path().join("job1");
        let entries: Vec<_> = fs::read_dir(&job_dir).unwrap().collect();
        assert_eq!(entries.len(), 1);

        let ts_dir = entries[0].as_ref().unwrap().path();
        let backup_file = ts_dir.join("sub/dir/data.bin");
        assert!(backup_file.exists());
    }

    #[tokio::test]
    async fn test_safety_handler_total_size() {
        let safety_base = tempfile::tempdir().unwrap();
        let handler = SafetyHandler::new(safety_base.path(), "job1", None, None);

        // No safety dir yet — should return 0
        let size = handler.total_size().await.unwrap();
        assert_eq!(size, 0);

        // Create some fake backup data
        let ts_dir = safety_base.path().join("job1").join("20250101T000000");
        fs::create_dir_all(&ts_dir).unwrap();
        fs::write(ts_dir.join("file1.txt"), "12345").unwrap();
        fs::write(ts_dir.join("file2.txt"), "6789").unwrap();

        let size = handler.total_size().await.unwrap();
        assert_eq!(size, 9); // 5 + 4
    }

    #[tokio::test]
    async fn test_safety_handler_cleanup_by_retention() {
        let safety_base = tempfile::tempdir().unwrap();

        // Create handler with 1 second retention
        let _handler = SafetyHandler::new(
            safety_base.path(),
            "job1",
            Some(Duration::from_secs(1)),
            None,
        );

        // Create a fake old backup directory
        let old_dir = safety_base.path().join("job1").join("20200101T000000");
        fs::create_dir_all(&old_dir).unwrap();
        fs::write(old_dir.join("old.txt"), "old data").unwrap();

        // Set the directory mtime to the past (the dir exists, so mtime will be recent
        // but we rely on the approach below)
        // Actually, since the dir was just created, its mtime is "now".
        // We need to wait or use filetime. Let's use a simpler approach:
        // We'll create the dir and then wait briefly.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Now the retention of 1s hasn't passed yet, so cleanup should keep it
        // Let's use a very short retention instead
        let handler_short = SafetyHandler::new(
            safety_base.path(),
            "job1",
            Some(Duration::from_millis(1)),
            None,
        );

        // Wait for the retention to expire
        tokio::time::sleep(Duration::from_millis(50)).await;

        let stats = handler_short.cleanup().await.unwrap();
        assert_eq!(stats.dirs_removed, 1);
        assert_eq!(stats.files_removed, 1);
        assert!(!old_dir.exists());
    }

    #[tokio::test]
    async fn test_safety_handler_cleanup_by_max_size() {
        let safety_base = tempfile::tempdir().unwrap();

        // Create two backup directories with known sizes
        let dir1 = safety_base.path().join("job1").join("20250101T000000");
        fs::create_dir_all(&dir1).unwrap();
        fs::write(dir1.join("file.txt"), "aaaa").unwrap(); // 4 bytes

        let dir2 = safety_base.path().join("job1").join("20250102T000000");
        fs::create_dir_all(&dir2).unwrap();
        fs::write(dir2.join("file.txt"), "bbbbbb").unwrap(); // 6 bytes

        // Total is 10 bytes. Set max_size to 5 — should remove the oldest (dir1).
        let handler = SafetyHandler::new(safety_base.path(), "job1", None, Some(5));

        let stats = handler.cleanup().await.unwrap();
        assert!(stats.dirs_removed >= 1);

        // dir2 should still exist (6 bytes > 5, but it's the newest, so it stays
        // if we can't get under the limit without removing everything)
        // Actually: after removing dir1 (4 bytes), total = 6 > 5, so dir2 gets removed too
        assert!(!dir1.exists());
    }

    #[tokio::test]
    async fn test_safety_handler_cleanup_empty_dir() {
        let safety_base = tempfile::tempdir().unwrap();
        let handler = SafetyHandler::new(
            safety_base.path(),
            "nonexistent",
            Some(Duration::from_secs(1)),
            Some(100),
        );

        let stats = handler.cleanup().await.unwrap();
        assert_eq!(stats.dirs_removed, 0);
        assert_eq!(stats.files_removed, 0);
        assert_eq!(stats.bytes_freed, 0);
    }

    #[tokio::test]
    async fn test_safety_handler_cleanup_no_limits() {
        let safety_base = tempfile::tempdir().unwrap();

        // Create a backup directory
        let dir1 = safety_base.path().join("job1").join("20250101T000000");
        fs::create_dir_all(&dir1).unwrap();
        fs::write(dir1.join("file.txt"), "data").unwrap();

        // No retention, no max_size — nothing should be cleaned up
        let handler = SafetyHandler::new(safety_base.path(), "job1", None, None);

        let stats = handler.cleanup().await.unwrap();
        assert_eq!(stats.dirs_removed, 0);
        assert!(dir1.exists());
    }
}
