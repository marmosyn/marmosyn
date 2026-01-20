// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Recursive filesystem scanner for building file trees.
//!
//! Traverses a directory tree, collects metadata for each file, applies
//! exclude patterns, and computes BLAKE3 hashes. The result is a [`FileTree`]
//! that can be compared against another tree to produce a [`SyncPlan`].
//!
//! The [`scan_directory_with_cache`] variant uses previously-stored DB metadata
//! to skip hashing files whose size and mtime have not changed, significantly
//! speeding up incremental syncs on large trees.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};
use tracing::{debug, trace, warn};
use walkdir::WalkDir;

use super::excluder::Excluder;
use super::file_tree::{FileMetadata, FileTree};
use super::hasher;
use crate::db::file_meta::{self, FileMetaRow};

/// Options controlling the scanning behaviour.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Whether to follow symbolic links during traversal.
    pub follow_symlinks: bool,

    /// Whether to compute BLAKE3 hashes for every file.
    /// Disabling this speeds up the scan but limits the diff to mtime/size only.
    pub compute_hashes: bool,

    /// Maximum directory depth (0 = unlimited).
    pub max_depth: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            follow_symlinks: false,
            compute_hashes: true,
            max_depth: 0,
        }
    }
}

/// Scans a directory tree and returns a [`FileTree`] with metadata for every
/// regular file that is not excluded.
///
/// # Arguments
///
/// * `root` — absolute path to the source directory.
/// * `excluder` — compiled exclude patterns (may be empty).
/// * `options` — scan behaviour knobs.
///
/// # Errors
///
/// Returns an error if `root` does not exist or is not a directory, or if an
/// I/O error prevents reading essential metadata.
pub fn scan_directory(
    root: &Path,
    excluder: &Excluder,
    options: &ScanOptions,
) -> Result<(PathBuf, FileTree)> {
    let root = root
        .canonicalize()
        .with_context(|| format!("failed to canonicalize source path '{}'", root.display()))?;

    if !root.is_dir() {
        anyhow::bail!("source path '{}' is not a directory", root.display());
    }

    debug!(path = %root.display(), "starting directory scan");

    let mut walker = WalkDir::new(&root).follow_links(options.follow_symlinks);

    if options.max_depth > 0 {
        walker = walker.max_depth(options.max_depth);
    }

    let mut entries = Vec::new();

    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(err) => {
                warn!(error = %err, "skipping inaccessible entry during scan");
                continue;
            }
        };

        // Only consider regular files
        let ft = entry.file_type();
        if !ft.is_file() {
            continue;
        }

        let abs_path = entry.path();

        // Compute the path relative to the scan root
        let rel_path = match abs_path.strip_prefix(&root) {
            Ok(p) => p.to_path_buf(),
            Err(_) => {
                warn!(
                    path = %abs_path.display(),
                    "could not compute relative path; skipping"
                );
                continue;
            }
        };

        // Apply exclude patterns
        if excluder.is_excluded(&rel_path) {
            trace!(path = %rel_path.display(), "excluded by pattern");
            continue;
        }

        // Read metadata
        let metadata = match std::fs::metadata(abs_path) {
            Ok(m) => m,
            Err(err) => {
                warn!(
                    path = %abs_path.display(),
                    error = %err,
                    "failed to read file metadata; skipping"
                );
                continue;
            }
        };

        let size = metadata.len();
        let mtime = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);

        // Optionally compute BLAKE3 hash (blocking — scanner runs synchronously)
        let hash = if options.compute_hashes {
            match hasher::hash_file_blocking(abs_path) {
                Ok(h) => Some(h),
                Err(err) => {
                    warn!(
                        path = %abs_path.display(),
                        error = %err,
                        "failed to hash file; recording without hash"
                    );
                    None
                }
            }
        } else {
            None
        };

        #[cfg(unix)]
        let permissions = {
            use std::os::unix::fs::PermissionsExt;
            Some(metadata.permissions().mode())
        };

        #[cfg(not(unix))]
        let permissions = None;

        entries.push(FileMetadata {
            rel_path,
            size,
            mtime,
            hash,
            is_dir: false,
            permissions,
        });
    }

    debug!(count = entries.len(), "scan complete");

    Ok((root, FileTree::from_entries(entries)))
}

/// Convenience wrapper that scans with default options and no excludes.
pub fn scan_directory_simple(root: &Path) -> Result<(PathBuf, FileTree)> {
    scan_directory(root, &Excluder::empty(), &ScanOptions::default())
}

/// Statistics from a cache-optimized scan, indicating how many files
/// were served from the DB cache vs. freshly hashed.
#[derive(Debug, Clone, Default)]
pub struct CacheScanStats {
    /// Number of files whose hash was reused from the DB cache.
    pub cache_hits: u64,
    /// Number of files that required a fresh BLAKE3 hash computation.
    pub cache_misses: u64,
    /// Total files scanned (hits + misses + skipped/unhashed).
    pub total_files: u64,
}

/// Scans a directory tree using DB-cached metadata to avoid re-hashing
/// unchanged files (Task 307 optimisation).
///
/// For each scanned file the function checks whether a matching
/// [`FileMetaRow`] exists in `cached_meta` (keyed by relative path).
/// If the stored size and mtime match the current filesystem values,
/// the cached BLAKE3 hash is reused directly. Otherwise a fresh hash
/// is computed.
///
/// This can dramatically reduce I/O and CPU time for incremental syncs
/// where most files are unchanged.
///
/// # Arguments
///
/// * `root` — absolute path to the source directory.
/// * `excluder` — compiled exclude patterns (may be empty).
/// * `options` — scan behaviour knobs. `compute_hashes` is respected:
///   when `false`, no hashing occurs and the cache is not consulted.
/// * `cached_meta` — previously stored DB rows for the job, indexed by
///   relative path. Obtain via [`file_meta::list_file_meta`] and then
///   convert with [`build_cache_map`].
///
/// # Returns
///
/// A tuple of `(canonical_root, FileTree, CacheScanStats)`.
pub fn scan_directory_with_cache(
    root: &Path,
    excluder: &Excluder,
    options: &ScanOptions,
    cached_meta: &HashMap<PathBuf, FileMetaRow>,
) -> Result<(PathBuf, FileTree, CacheScanStats)> {
    let root = root
        .canonicalize()
        .with_context(|| format!("failed to canonicalize source path '{}'", root.display()))?;

    if !root.is_dir() {
        anyhow::bail!("source path '{}' is not a directory", root.display());
    }

    debug!(
        path = %root.display(),
        cached_entries = cached_meta.len(),
        "starting cache-optimized directory scan"
    );

    let mut walker = WalkDir::new(&root).follow_links(options.follow_symlinks);

    if options.max_depth > 0 {
        walker = walker.max_depth(options.max_depth);
    }

    let mut entries = Vec::new();
    let mut stats = CacheScanStats::default();

    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(err) => {
                warn!(error = %err, "skipping inaccessible entry during scan");
                continue;
            }
        };

        if !entry.file_type().is_file() {
            continue;
        }

        let abs_path = entry.path();

        let rel_path = match abs_path.strip_prefix(&root) {
            Ok(p) => p.to_path_buf(),
            Err(_) => {
                warn!(
                    path = %abs_path.display(),
                    "could not compute relative path; skipping"
                );
                continue;
            }
        };

        if excluder.is_excluded(&rel_path) {
            trace!(path = %rel_path.display(), "excluded by pattern");
            continue;
        }

        let metadata = match std::fs::metadata(abs_path) {
            Ok(m) => m,
            Err(err) => {
                warn!(
                    path = %abs_path.display(),
                    error = %err,
                    "failed to read file metadata; skipping"
                );
                continue;
            }
        };

        let size = metadata.len();
        let mtime = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);

        stats.total_files += 1;

        // Determine the hash: try the DB cache first, then compute if needed.
        let hash = if options.compute_hashes {
            if let Some(cached) = cached_meta.get(&rel_path) {
                let (cur_secs, cur_nanos) = file_meta::system_time_to_parts(mtime);

                if cached.size == size
                    && cached.mtime_secs == cur_secs
                    && cached.mtime_nanos == cur_nanos
                {
                    // Cache hit — reuse stored hash
                    trace!(
                        path = %rel_path.display(),
                        "cache hit: reusing stored hash"
                    );
                    stats.cache_hits += 1;
                    Some(cached.blake3_hash.clone())
                } else {
                    // Cache miss — size or mtime changed, must re-hash
                    trace!(
                        path = %rel_path.display(),
                        "cache miss: file changed, re-hashing"
                    );
                    stats.cache_misses += 1;
                    match hasher::hash_file_blocking(abs_path) {
                        Ok(h) => Some(h),
                        Err(err) => {
                            warn!(
                                path = %abs_path.display(),
                                error = %err,
                                "failed to hash file; recording without hash"
                            );
                            None
                        }
                    }
                }
            } else {
                // No cached entry for this file — must compute hash
                trace!(
                    path = %rel_path.display(),
                    "no cache entry: computing hash"
                );
                stats.cache_misses += 1;
                match hasher::hash_file_blocking(abs_path) {
                    Ok(h) => Some(h),
                    Err(err) => {
                        warn!(
                            path = %abs_path.display(),
                            error = %err,
                            "failed to hash file; recording without hash"
                        );
                        None
                    }
                }
            }
        } else {
            None
        };

        #[cfg(unix)]
        let permissions = {
            use std::os::unix::fs::PermissionsExt;
            Some(metadata.permissions().mode())
        };

        #[cfg(not(unix))]
        let permissions = None;

        entries.push(FileMetadata {
            rel_path,
            size,
            mtime,
            hash,
            is_dir: false,
            permissions,
        });
    }

    debug!(
        total = stats.total_files,
        hits = stats.cache_hits,
        misses = stats.cache_misses,
        "cache-optimized scan complete"
    );

    Ok((root, FileTree::from_entries(entries), stats))
}

/// Converts a list of [`FileMetaRow`] into a lookup map keyed by relative path.
///
/// This is the expected input format for [`scan_directory_with_cache`].
pub fn build_cache_map(rows: Vec<FileMetaRow>) -> HashMap<PathBuf, FileMetaRow> {
    rows.into_iter().map(|r| (r.rel_path.clone(), r)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::migrations;
    use rusqlite::Connection;
    use std::fs;

    #[test]
    fn test_scan_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        let (_root, tree) = scan_directory_simple(dir.path()).unwrap();
        assert!(tree.is_empty());
    }

    #[test]
    fn test_scan_flat_directory() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "hello").unwrap();
        fs::write(dir.path().join("b.txt"), "world").unwrap();

        let (_root, tree) = scan_directory_simple(dir.path()).unwrap();
        assert_eq!(tree.len(), 2);

        let names: Vec<String> = tree
            .values()
            .map(|e| e.rel_path.to_string_lossy().to_string())
            .collect();
        assert!(names.contains(&"a.txt".to_string()));
        assert!(names.contains(&"b.txt".to_string()));
    }

    #[test]
    fn test_scan_nested_directory() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(dir.path().join("root.txt"), "root").unwrap();
        fs::write(sub.join("nested.txt"), "nested").unwrap();

        let (_root, tree) = scan_directory_simple(dir.path()).unwrap();
        assert_eq!(tree.len(), 2);
    }

    #[test]
    fn test_scan_with_excluder() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("keep.txt"), "keep").unwrap();
        fs::write(dir.path().join("skip.tmp"), "skip").unwrap();

        let excluder = Excluder::new(&["*.tmp"]).unwrap();
        let (_root, tree) = scan_directory(dir.path(), &excluder, &ScanOptions::default()).unwrap();
        assert_eq!(tree.len(), 1);
        let files = tree.files_sorted();
        assert_eq!(files[0].rel_path.to_string_lossy(), "keep.txt");
    }

    #[test]
    fn test_scan_nonexistent_directory() {
        let result = scan_directory_simple(Path::new("/nonexistent/path"));
        assert!(result.is_err());
    }

    #[test]
    fn test_scan_records_size() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("data.bin"), "12345").unwrap();

        let (_root, tree) = scan_directory_simple(dir.path()).unwrap();
        assert_eq!(tree.len(), 1);
        let files = tree.files_sorted();
        assert_eq!(files[0].size, 5);
    }

    #[test]
    fn test_scan_records_hash() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"hello world";
        fs::write(dir.path().join("file.txt"), content).unwrap();

        let (_root, tree) = scan_directory_simple(dir.path()).unwrap();
        assert_eq!(tree.len(), 1);
        let files = tree.files_sorted();
        assert!(files[0].hash.is_some());

        // Verify the hash matches a direct computation
        let expected = blake3::hash(content).to_hex().to_string();
        assert_eq!(files[0].hash.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn test_scan_without_hashes() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("file.txt"), "data").unwrap();

        let opts = ScanOptions {
            compute_hashes: false,
            ..ScanOptions::default()
        };
        let (_root, tree) = scan_directory(dir.path(), &Excluder::empty(), &opts).unwrap();
        assert_eq!(tree.len(), 1);
        let files = tree.files_sorted();
        assert!(files[0].hash.is_none());
    }

    // ── Cache-optimized scan tests ──────────────────────────────────────

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        migrations::run_migrations(&conn).unwrap();
        conn
    }

    #[test]
    fn test_scan_with_cache_all_hits() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "aaa").unwrap();
        fs::write(dir.path().join("b.txt"), "bbb").unwrap();

        // First scan to get real metadata
        let (_root, tree) = scan_directory_simple(dir.path()).unwrap();

        // Build DB rows from the scan results
        let conn = setup_db();
        for meta in tree.values() {
            let (secs, nanos) = file_meta::system_time_to_parts(meta.mtime);
            let row = FileMetaRow {
                id: 0,
                job_name: "test".to_string(),
                rel_path: meta.rel_path.clone(),
                size: meta.size,
                mtime_secs: secs,
                mtime_nanos: nanos,
                blake3_hash: meta.hash.clone().unwrap_or_default(),
            };
            file_meta::upsert_file_meta(&conn, &row).unwrap();
        }

        // Load the cache and re-scan
        let cached = file_meta::list_file_meta(&conn, "test").unwrap();
        let cache_map = build_cache_map(cached);

        let (_root2, tree2, stats) = scan_directory_with_cache(
            dir.path(),
            &Excluder::empty(),
            &ScanOptions::default(),
            &cache_map,
        )
        .unwrap();

        assert_eq!(tree2.len(), 2);
        assert_eq!(stats.total_files, 2);
        assert_eq!(stats.cache_hits, 2);
        assert_eq!(stats.cache_misses, 0);

        // Hashes should be identical to the first scan
        for meta in tree2.values() {
            let original = tree.get(&meta.rel_path).unwrap();
            assert_eq!(meta.hash, original.hash);
        }
    }

    #[test]
    fn test_scan_with_cache_some_misses() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("unchanged.txt"), "same").unwrap();
        fs::write(dir.path().join("will_change.txt"), "old content").unwrap();

        // First scan
        let (_root, tree) = scan_directory_simple(dir.path()).unwrap();

        let conn = setup_db();
        for meta in tree.values() {
            let (secs, nanos) = file_meta::system_time_to_parts(meta.mtime);
            let row = FileMetaRow {
                id: 0,
                job_name: "test".to_string(),
                rel_path: meta.rel_path.clone(),
                size: meta.size,
                mtime_secs: secs,
                mtime_nanos: nanos,
                blake3_hash: meta.hash.clone().unwrap_or_default(),
            };
            file_meta::upsert_file_meta(&conn, &row).unwrap();
        }

        // Modify one file (change content and therefore size/mtime)
        // Sleep briefly to ensure mtime differs
        std::thread::sleep(std::time::Duration::from_millis(50));
        fs::write(dir.path().join("will_change.txt"), "new content!!").unwrap();

        // Also add a brand-new file (no cache entry)
        fs::write(dir.path().join("new_file.txt"), "brand new").unwrap();

        let cached = file_meta::list_file_meta(&conn, "test").unwrap();
        let cache_map = build_cache_map(cached);

        let (_root2, tree2, stats) = scan_directory_with_cache(
            dir.path(),
            &Excluder::empty(),
            &ScanOptions::default(),
            &cache_map,
        )
        .unwrap();

        assert_eq!(tree2.len(), 3);
        assert_eq!(stats.total_files, 3);
        // "unchanged.txt" should be a hit; "will_change.txt" and
        // "new_file.txt" should be misses
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(stats.cache_misses, 2);

        // The unchanged file should still have the same hash
        let unchanged = tree2.get(std::path::Path::new("unchanged.txt")).unwrap();
        let original = tree.get(std::path::Path::new("unchanged.txt")).unwrap();
        assert_eq!(unchanged.hash, original.hash);

        // The changed file should have a different hash
        let changed = tree2.get(std::path::Path::new("will_change.txt")).unwrap();
        let original_changed = tree.get(std::path::Path::new("will_change.txt")).unwrap();
        assert_ne!(changed.hash, original_changed.hash);

        // New file should have a hash
        let new_file = tree2.get(std::path::Path::new("new_file.txt")).unwrap();
        assert!(new_file.hash.is_some());
    }

    #[test]
    fn test_scan_with_empty_cache() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("file.txt"), "data").unwrap();

        let cache_map = HashMap::new();

        let (_root, tree, stats) = scan_directory_with_cache(
            dir.path(),
            &Excluder::empty(),
            &ScanOptions::default(),
            &cache_map,
        )
        .unwrap();

        assert_eq!(tree.len(), 1);
        assert_eq!(stats.total_files, 1);
        assert_eq!(stats.cache_hits, 0);
        assert_eq!(stats.cache_misses, 1);
        assert!(tree.files_sorted()[0].hash.is_some());
    }

    #[test]
    fn test_scan_with_cache_no_hashes_skips_cache() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("file.txt"), "data").unwrap();

        // Even with cache entries present, compute_hashes=false should skip
        let mut cache_map = HashMap::new();
        cache_map.insert(
            PathBuf::from("file.txt"),
            FileMetaRow {
                id: 0,
                job_name: "test".to_string(),
                rel_path: PathBuf::from("file.txt"),
                size: 4,
                mtime_secs: 0,
                mtime_nanos: 0,
                blake3_hash: "cached_hash".to_string(),
            },
        );

        let opts = ScanOptions {
            compute_hashes: false,
            ..ScanOptions::default()
        };

        let (_root, tree, stats) =
            scan_directory_with_cache(dir.path(), &Excluder::empty(), &opts, &cache_map).unwrap();

        assert_eq!(tree.len(), 1);
        assert_eq!(stats.total_files, 1);
        assert_eq!(stats.cache_hits, 0);
        assert_eq!(stats.cache_misses, 0);
        assert!(tree.files_sorted()[0].hash.is_none());
    }

    #[test]
    fn test_build_cache_map() {
        let rows = vec![
            FileMetaRow {
                id: 1,
                job_name: "j".to_string(),
                rel_path: PathBuf::from("a.txt"),
                size: 10,
                mtime_secs: 100,
                mtime_nanos: 0,
                blake3_hash: "h1".to_string(),
            },
            FileMetaRow {
                id: 2,
                job_name: "j".to_string(),
                rel_path: PathBuf::from("b.txt"),
                size: 20,
                mtime_secs: 200,
                mtime_nanos: 0,
                blake3_hash: "h2".to_string(),
            },
        ];

        let map = build_cache_map(rows);
        assert_eq!(map.len(), 2);
        assert_eq!(map[&PathBuf::from("a.txt")].blake3_hash, "h1");
        assert_eq!(map[&PathBuf::from("b.txt")].blake3_hash, "h2");
    }

    #[test]
    fn test_scan_with_cache_size_change_triggers_rehash() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("file.txt"), "short").unwrap();

        // Build a fake cache entry with matching mtime but different size
        let meta = fs::metadata(dir.path().join("file.txt")).unwrap();
        let mtime = meta.modified().unwrap();
        let (secs, nanos) = file_meta::system_time_to_parts(mtime);

        let mut cache_map = HashMap::new();
        cache_map.insert(
            PathBuf::from("file.txt"),
            FileMetaRow {
                id: 0,
                job_name: "test".to_string(),
                rel_path: PathBuf::from("file.txt"),
                size: 999, // different size
                mtime_secs: secs,
                mtime_nanos: nanos,
                blake3_hash: "stale_hash".to_string(),
            },
        );

        let (_root, tree, stats) = scan_directory_with_cache(
            dir.path(),
            &Excluder::empty(),
            &ScanOptions::default(),
            &cache_map,
        )
        .unwrap();

        assert_eq!(stats.cache_hits, 0);
        assert_eq!(stats.cache_misses, 1);

        // Hash should be freshly computed, not the stale one
        let file = tree.files_sorted()[0];
        assert_ne!(file.hash.as_deref(), Some("stale_hash"));
        let expected = blake3::hash(b"short").to_hex().to_string();
        assert_eq!(file.hash.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn test_cache_scan_results_match_full_scan() {
        // Verify that a cache-optimized scan produces the exact same
        // FileTree as a regular full scan (correctness check).
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("x.txt"), "xxx").unwrap();
        fs::write(dir.path().join("y.txt"), "yyy").unwrap();
        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("z.txt"), "zzz").unwrap();

        // Full scan
        let (_root, full_tree) = scan_directory_simple(dir.path()).unwrap();

        // Cache-optimized scan with empty cache (should produce same result)
        let empty_cache = HashMap::new();
        let (_root2, cached_tree, _stats) = scan_directory_with_cache(
            dir.path(),
            &Excluder::empty(),
            &ScanOptions::default(),
            &empty_cache,
        )
        .unwrap();

        assert_eq!(full_tree.len(), cached_tree.len());

        for meta in full_tree.values() {
            let cached = cached_tree.get(&meta.rel_path).unwrap();
            assert_eq!(meta.size, cached.size);
            assert_eq!(meta.hash, cached.hash);
            assert_eq!(meta.is_dir, cached.is_dir);
        }
    }
}
