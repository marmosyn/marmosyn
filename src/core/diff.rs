// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Diff computation between source and destination file trees.
//!
//! Compares two [`FileTree`](super::file_tree::FileTree) instances (source vs dest) and
//! produces a [`SyncPlan`](super::sync_plan::SyncPlan) describing the actions needed to
//! bring the destination in sync with the source.
//!
//! Synchronization is **unidirectional**: the source is the sole source of truth.
//!
//! # Comparison strategy
//!
//! For each file present in the source tree:
//! - If missing from dest → **copy**
//! - If present in dest but differs (by hash, size, or mtime) → **update**
//! - If identical → skip
//!
//! For each file present in the dest tree but absent from source → **delete**
//!
//! Directories in the dest that become empty after deletions are also scheduled
//! for removal (deepest first).

use std::collections::HashSet;
use std::path::PathBuf;

use tracing::{debug, trace};

use super::file_tree::{FileMetadata, FileTree};
use super::sync_plan::{DeleteEntry, SyncEntry, SyncPlan};

/// Options controlling the diff comparison behaviour.
#[derive(Debug, Clone)]
pub struct DiffOptions {
    /// When `true`, files are compared by BLAKE3 hash (most accurate).
    /// When `false`, only size + mtime are used (faster but less precise).
    pub compare_by_hash: bool,

    /// When `true`, files present in the destination but absent from the
    /// source will be scheduled for deletion.
    /// When `false`, extra files in the destination are left untouched.
    pub delete_orphans: bool,

    /// When `true`, the diff produces a plan but is intended for display only
    /// (dry-run mode). The plan itself is identical; the caller decides
    /// whether to execute it.
    pub dry_run: bool,
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self {
            compare_by_hash: true,
            delete_orphans: true,
            dry_run: false,
        }
    }
}

/// Compares a source [`FileTree`] against a destination [`FileTree`] and
/// produces a [`SyncPlan`] with the operations needed to bring the
/// destination in sync with the source.
///
/// # Arguments
///
/// * `source` — the authoritative file tree (sender side).
/// * `dest` — the current state of the destination.
/// * `options` — comparison behaviour knobs.
///
/// # Returns
///
/// A [`SyncPlan`] listing files to copy, update, and delete.
pub fn compute_diff(source: &FileTree, dest: &FileTree, options: &DiffOptions) -> SyncPlan {
    let mut to_copy = Vec::new();
    let mut to_update = Vec::new();
    let mut to_delete = Vec::new();

    // Collect all source relative paths for quick lookup when detecting orphans.
    let source_paths: HashSet<&PathBuf> = source.paths().collect();

    // ── Pass 1: iterate over source entries ────────────────────────────
    for src_meta in source.values() {
        // Skip directories — we only track files; directories are created
        // implicitly when copying files.
        if src_meta.is_dir {
            continue;
        }

        match dest.get(&src_meta.rel_path) {
            None => {
                // File exists in source but not in dest → copy
                trace!(
                    path = %src_meta.rel_path.display(),
                    size = src_meta.size,
                    "new file → copy"
                );
                to_copy.push(SyncEntry {
                    rel_path: src_meta.rel_path.clone(),
                    size: src_meta.size,
                });
            }
            Some(dest_meta) => {
                if files_differ(src_meta, dest_meta, options.compare_by_hash) {
                    trace!(
                        path = %src_meta.rel_path.display(),
                        src_size = src_meta.size,
                        dest_size = dest_meta.size,
                        "file changed → update"
                    );
                    to_update.push(SyncEntry {
                        rel_path: src_meta.rel_path.clone(),
                        size: src_meta.size,
                    });
                } else {
                    trace!(
                        path = %src_meta.rel_path.display(),
                        "file unchanged → skip"
                    );
                }
            }
        }
    }

    // ── Pass 2: detect orphans (dest-only files) ───────────────────────
    if options.delete_orphans {
        // Collect parent directories that might become empty after deletions
        let mut orphan_dirs: HashSet<PathBuf> = HashSet::new();

        for dest_meta in dest.values() {
            if dest_meta.is_dir {
                continue;
            }
            if !source_paths.contains(&dest_meta.rel_path) {
                trace!(
                    path = %dest_meta.rel_path.display(),
                    "orphan file → delete"
                );
                // Record parent dirs for potential cleanup
                if let Some(parent) = dest_meta.rel_path.parent() {
                    let mut p = parent.to_path_buf();
                    while !p.as_os_str().is_empty() {
                        orphan_dirs.insert(p.clone());
                        if let Some(pp) = p.parent() {
                            p = pp.to_path_buf();
                        } else {
                            break;
                        }
                    }
                }
                to_delete.push(DeleteEntry {
                    rel_path: dest_meta.rel_path.clone(),
                    is_dir: false,
                });
            }
        }

        // Schedule empty directories for deletion (deepest first).
        // A directory should be deleted only if ALL of its children in the dest
        // tree are also being deleted and there are no surviving source files
        // within it.
        let mut dirs_to_delete = collect_empty_dirs(dest, &source_paths, &orphan_dirs);
        // Sort deepest first so that child dirs are removed before parents.
        dirs_to_delete.sort_by(|a, b| {
            let depth_a = a.components().count();
            let depth_b = b.components().count();
            depth_b.cmp(&depth_a)
        });

        for dir_path in dirs_to_delete {
            trace!(path = %dir_path.display(), "empty directory → delete");
            to_delete.push(DeleteEntry {
                rel_path: dir_path,
                is_dir: true,
            });
        }
    }

    // Sort for deterministic output
    to_copy.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    to_update.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    to_delete.sort_by(|a, b| {
        // Files first (sorted by path), then dirs (deepest first)
        match (a.is_dir, b.is_dir) {
            (false, false) => a.rel_path.cmp(&b.rel_path),
            (true, true) => {
                let depth_a = a.rel_path.components().count();
                let depth_b = b.rel_path.components().count();
                depth_b
                    .cmp(&depth_a)
                    .then_with(|| a.rel_path.cmp(&b.rel_path))
            }
            (false, true) => std::cmp::Ordering::Less,
            (true, false) => std::cmp::Ordering::Greater,
        }
    });

    debug!(
        copies = to_copy.len(),
        updates = to_update.len(),
        deletes = to_delete.len(),
        "diff computation complete"
    );

    SyncPlan {
        to_copy,
        to_update,
        to_delete,
    }
}

/// Convenience function: compute diff with default options.
pub fn compute_diff_default(source: &FileTree, dest: &FileTree) -> SyncPlan {
    compute_diff(source, dest, &DiffOptions::default())
}

/// Formats a [`SyncPlan`] as a human-readable dry-run report.
///
/// Returns a multi-line string suitable for printing to the terminal.
pub fn format_dry_run(plan: &SyncPlan) -> String {
    let mut lines = Vec::new();

    if plan.is_empty() {
        lines.push("No changes needed — source and destination are in sync.".to_string());
        return lines.join("\n");
    }

    lines.push(format!(
        "Dry-run: {} operation(s), {} bytes to transfer\n",
        plan.total_operations(),
        format_bytes(plan.total_bytes()),
    ));

    if !plan.to_copy.is_empty() {
        lines.push(format!("  Copy ({} file(s)):", plan.to_copy.len()));
        for entry in &plan.to_copy {
            lines.push(format!(
                "    + {} ({})",
                entry.rel_path.display(),
                format_bytes(entry.size),
            ));
        }
    }

    if !plan.to_update.is_empty() {
        lines.push(format!("  Update ({} file(s)):", plan.to_update.len()));
        for entry in &plan.to_update {
            lines.push(format!(
                "    ~ {} ({})",
                entry.rel_path.display(),
                format_bytes(entry.size),
            ));
        }
    }

    if !plan.to_delete.is_empty() {
        lines.push(format!("  Delete ({} item(s)):", plan.to_delete.len()));
        for entry in &plan.to_delete {
            let kind = if entry.is_dir { "dir " } else { "file" };
            lines.push(format!("    - [{}] {}", kind, entry.rel_path.display(),));
        }
    }

    lines.join("\n")
}

// ─── Internal helpers ──────────────────────────────────────────────────────

/// Determines whether two file metadata records represent different content.
fn files_differ(src: &FileMetadata, dest: &FileMetadata, compare_by_hash: bool) -> bool {
    // Size difference is always a change.
    if src.size != dest.size {
        return true;
    }

    // If hash comparison is enabled and both have hashes, use them.
    if compare_by_hash && let (Some(src_hash), Some(dest_hash)) = (&src.hash, &dest.hash) {
        return src_hash != dest_hash;
    }

    // Fall back to mtime comparison.
    src.mtime != dest.mtime
}

/// Identifies directories that should be deleted because all their contents
/// are being removed and no source files exist within them.
fn collect_empty_dirs(
    dest: &FileTree,
    source_paths: &HashSet<&PathBuf>,
    candidate_dirs: &HashSet<PathBuf>,
) -> Vec<PathBuf> {
    let mut result = Vec::new();

    for dir_path in candidate_dirs {
        // A candidate directory is "empty after sync" if no source file
        // has this directory as a prefix.
        let has_surviving_source_file = source_paths.iter().any(|sp| sp.starts_with(dir_path));
        if has_surviving_source_file {
            continue;
        }

        // Also verify that no dest file that would survive lives under this dir.
        let has_surviving_dest_file = dest.values().any(|m| {
            !m.is_dir && m.rel_path.starts_with(dir_path) && source_paths.contains(&m.rel_path)
        });
        if has_surviving_dest_file {
            continue;
        }

        // Check that this directory actually exists in the dest tree as a dir
        // entry, or that there are dest files under it (implying the dir exists).
        let dir_exists_in_dest = dest.get(dir_path).is_some_and(|m| m.is_dir)
            || dest
                .values()
                .any(|m| !m.is_dir && m.rel_path.starts_with(dir_path));
        if dir_exists_in_dest {
            result.push(dir_path.clone());
        }
    }

    result
}

/// Formats a byte count into a human-readable string.
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{Duration, UNIX_EPOCH};

    // ── Test helpers ────────────────────────────────────────────────────

    fn file_meta(rel: &str, size: u64, hash: &str) -> FileMetadata {
        FileMetadata {
            rel_path: PathBuf::from(rel),
            size,
            mtime: UNIX_EPOCH + Duration::from_secs(1000),
            hash: Some(hash.to_string()),
            is_dir: false,
            permissions: Some(0o644),
        }
    }

    fn file_meta_mtime(rel: &str, size: u64, hash: &str, secs: u64) -> FileMetadata {
        FileMetadata {
            rel_path: PathBuf::from(rel),
            size,
            mtime: UNIX_EPOCH + Duration::from_secs(secs),
            hash: Some(hash.to_string()),
            is_dir: false,
            permissions: Some(0o644),
        }
    }

    fn dir_meta(rel: &str) -> FileMetadata {
        FileMetadata {
            rel_path: PathBuf::from(rel),
            size: 0,
            mtime: UNIX_EPOCH,
            hash: None,
            is_dir: true,
            permissions: Some(0o755),
        }
    }

    fn tree_from(entries: Vec<FileMetadata>) -> FileTree {
        FileTree::from_entries(entries)
    }

    // ── Empty trees ─────────────────────────────────────────────────────

    #[test]
    fn test_both_empty() {
        let src = FileTree::new();
        let dst = FileTree::new();
        let plan = compute_diff_default(&src, &dst);
        assert!(plan.is_empty());
        assert_eq!(plan.total_operations(), 0);
    }

    // ── Copy new files ──────────────────────────────────────────────────

    #[test]
    fn test_new_files_are_copied() {
        let src = tree_from(vec![
            file_meta("a.txt", 100, "hash_a"),
            file_meta("b.txt", 200, "hash_b"),
        ]);
        let dst = FileTree::new();
        let plan = compute_diff_default(&src, &dst);

        assert_eq!(plan.to_copy.len(), 2);
        assert!(plan.to_update.is_empty());
        assert!(plan.to_delete.is_empty());
        assert_eq!(plan.total_bytes(), 300);

        let paths: Vec<String> = plan
            .to_copy
            .iter()
            .map(|e| e.rel_path.to_string_lossy().to_string())
            .collect();
        assert!(paths.contains(&"a.txt".to_string()));
        assert!(paths.contains(&"b.txt".to_string()));
    }

    #[test]
    fn test_nested_new_file() {
        let src = tree_from(vec![file_meta("dir/sub/file.txt", 50, "hash_f")]);
        let dst = FileTree::new();
        let plan = compute_diff_default(&src, &dst);

        assert_eq!(plan.to_copy.len(), 1);
        assert_eq!(plan.to_copy[0].rel_path, PathBuf::from("dir/sub/file.txt"));
    }

    // ── Update changed files ────────────────────────────────────────────

    #[test]
    fn test_changed_hash_triggers_update() {
        let src = tree_from(vec![file_meta("a.txt", 100, "hash_new")]);
        let dst = tree_from(vec![file_meta("a.txt", 100, "hash_old")]);
        let plan = compute_diff_default(&src, &dst);

        assert!(plan.to_copy.is_empty());
        assert_eq!(plan.to_update.len(), 1);
        assert_eq!(plan.to_update[0].rel_path, PathBuf::from("a.txt"));
        assert!(plan.to_delete.is_empty());
    }

    #[test]
    fn test_changed_size_triggers_update() {
        let src = tree_from(vec![file_meta("a.txt", 200, "hash_a")]);
        let dst = tree_from(vec![file_meta("a.txt", 100, "hash_a")]);
        let plan = compute_diff_default(&src, &dst);

        assert_eq!(plan.to_update.len(), 1);
    }

    #[test]
    fn test_changed_mtime_with_no_hash_triggers_update() {
        let src = tree_from(vec![FileMetadata {
            rel_path: PathBuf::from("a.txt"),
            size: 100,
            mtime: UNIX_EPOCH + Duration::from_secs(2000),
            hash: None,
            is_dir: false,
            permissions: Some(0o644),
        }]);
        let dst = tree_from(vec![FileMetadata {
            rel_path: PathBuf::from("a.txt"),
            size: 100,
            mtime: UNIX_EPOCH + Duration::from_secs(1000),
            hash: None,
            is_dir: false,
            permissions: Some(0o644),
        }]);

        let options = DiffOptions {
            compare_by_hash: true,
            ..DiffOptions::default()
        };
        let plan = compute_diff(&src, &dst, &options);
        assert_eq!(plan.to_update.len(), 1);
    }

    #[test]
    fn test_identical_files_are_skipped() {
        let src = tree_from(vec![file_meta("a.txt", 100, "hash_a")]);
        let dst = tree_from(vec![file_meta("a.txt", 100, "hash_a")]);
        let plan = compute_diff_default(&src, &dst);

        assert!(plan.is_empty());
    }

    // ── Delete orphan files ─────────────────────────────────────────────

    #[test]
    fn test_orphan_files_are_deleted() {
        let src = FileTree::new();
        let dst = tree_from(vec![
            file_meta("old.txt", 50, "hash_old"),
            file_meta("stale.log", 30, "hash_stale"),
        ]);
        let plan = compute_diff_default(&src, &dst);

        assert!(plan.to_copy.is_empty());
        assert!(plan.to_update.is_empty());
        // At least the 2 files should be deleted
        let file_deletes: Vec<_> = plan.to_delete.iter().filter(|d| !d.is_dir).collect();
        assert_eq!(file_deletes.len(), 2);
    }

    #[test]
    fn test_orphan_deletion_disabled() {
        let src = FileTree::new();
        let dst = tree_from(vec![file_meta("old.txt", 50, "hash_old")]);

        let options = DiffOptions {
            delete_orphans: false,
            ..DiffOptions::default()
        };
        let plan = compute_diff(&src, &dst, &options);
        assert!(plan.to_delete.is_empty());
    }

    // ── Mixed operations ────────────────────────────────────────────────

    #[test]
    fn test_mixed_copy_update_delete() {
        let src = tree_from(vec![
            file_meta("keep.txt", 100, "hash_keep"),
            file_meta("changed.txt", 200, "hash_new"),
            file_meta("new_file.txt", 300, "hash_brand_new"),
        ]);
        let dst = tree_from(vec![
            file_meta("keep.txt", 100, "hash_keep"),
            file_meta("changed.txt", 150, "hash_old"),
            file_meta("orphan.txt", 80, "hash_orphan"),
        ]);

        let plan = compute_diff_default(&src, &dst);

        assert_eq!(plan.to_copy.len(), 1);
        assert_eq!(plan.to_copy[0].rel_path, PathBuf::from("new_file.txt"));

        assert_eq!(plan.to_update.len(), 1);
        assert_eq!(plan.to_update[0].rel_path, PathBuf::from("changed.txt"));

        let file_deletes: Vec<_> = plan.to_delete.iter().filter(|d| !d.is_dir).collect();
        assert_eq!(file_deletes.len(), 1);
        assert_eq!(file_deletes[0].rel_path, PathBuf::from("orphan.txt"));
    }

    // ── Size-only comparison (no hash) ──────────────────────────────────

    #[test]
    fn test_size_only_comparison_same_size_different_mtime() {
        let src = tree_from(vec![file_meta_mtime("a.txt", 100, "h1", 2000)]);
        let dst = tree_from(vec![file_meta_mtime("a.txt", 100, "h1", 1000)]);

        let options = DiffOptions {
            compare_by_hash: false,
            ..DiffOptions::default()
        };
        let plan = compute_diff(&src, &dst, &options);
        // Same size, different mtime, hash comparison off → fallback to mtime → update
        assert_eq!(plan.to_update.len(), 1);
    }

    #[test]
    fn test_size_only_comparison_same_everything() {
        let src = tree_from(vec![file_meta_mtime("a.txt", 100, "h1", 1000)]);
        let dst = tree_from(vec![file_meta_mtime("a.txt", 100, "h1", 1000)]);

        let options = DiffOptions {
            compare_by_hash: false,
            ..DiffOptions::default()
        };
        let plan = compute_diff(&src, &dst, &options);
        assert!(plan.is_empty());
    }

    // ── Directory entries are skipped ───────────────────────────────────

    #[test]
    fn test_directories_are_ignored_in_source() {
        let src = tree_from(vec![
            dir_meta("sub"),
            file_meta("sub/file.txt", 10, "hash_f"),
        ]);
        let dst = FileTree::new();
        let plan = compute_diff_default(&src, &dst);

        // Only the file should be in to_copy, not the directory
        assert_eq!(plan.to_copy.len(), 1);
        assert_eq!(plan.to_copy[0].rel_path, PathBuf::from("sub/file.txt"));
    }

    // ── Orphan directory cleanup ────────────────────────────────────────

    #[test]
    fn test_orphan_directory_deleted_when_all_contents_removed() {
        let src = FileTree::new(); // source is empty
        let dst = tree_from(vec![
            dir_meta("old_dir"),
            file_meta("old_dir/file1.txt", 10, "h1"),
            file_meta("old_dir/file2.txt", 20, "h2"),
        ]);
        let plan = compute_diff_default(&src, &dst);

        let file_deletes: Vec<_> = plan.to_delete.iter().filter(|d| !d.is_dir).collect();
        assert_eq!(file_deletes.len(), 2);

        let dir_deletes: Vec<_> = plan.to_delete.iter().filter(|d| d.is_dir).collect();
        assert_eq!(dir_deletes.len(), 1);
        assert_eq!(dir_deletes[0].rel_path, PathBuf::from("old_dir"));
    }

    #[test]
    fn test_directory_not_deleted_if_source_files_remain() {
        let src = tree_from(vec![file_meta("shared_dir/keep.txt", 10, "h1")]);
        let dst = tree_from(vec![
            dir_meta("shared_dir"),
            file_meta("shared_dir/keep.txt", 10, "h1"),
            file_meta("shared_dir/orphan.txt", 20, "h2"),
        ]);
        let plan = compute_diff_default(&src, &dst);

        // The orphan file should be deleted, but the directory should survive.
        let file_deletes: Vec<_> = plan.to_delete.iter().filter(|d| !d.is_dir).collect();
        assert_eq!(file_deletes.len(), 1);
        assert_eq!(
            file_deletes[0].rel_path,
            PathBuf::from("shared_dir/orphan.txt")
        );

        let dir_deletes: Vec<_> = plan.to_delete.iter().filter(|d| d.is_dir).collect();
        assert!(dir_deletes.is_empty());
    }

    // ── Delete ordering ─────────────────────────────────────────────────

    #[test]
    fn test_delete_order_files_before_dirs() {
        let src = FileTree::new();
        let dst = tree_from(vec![dir_meta("dir"), file_meta("dir/file.txt", 10, "h")]);
        let plan = compute_diff_default(&src, &dst);

        let file_idx = plan
            .to_delete
            .iter()
            .position(|d| !d.is_dir)
            .expect("file delete should exist");
        let dir_idx = plan
            .to_delete
            .iter()
            .position(|d| d.is_dir)
            .expect("dir delete should exist");
        assert!(
            file_idx < dir_idx,
            "files should be deleted before directories"
        );
    }

    #[test]
    fn test_nested_dirs_deleted_deepest_first() {
        let src = FileTree::new();
        let dst = tree_from(vec![
            dir_meta("a"),
            dir_meta("a/b"),
            dir_meta("a/b/c"),
            file_meta("a/b/c/file.txt", 10, "h"),
        ]);
        let plan = compute_diff_default(&src, &dst);

        let dir_deletes: Vec<_> = plan
            .to_delete
            .iter()
            .filter(|d| d.is_dir)
            .map(|d| d.rel_path.to_string_lossy().to_string())
            .collect();

        // Deepest first: a/b/c, a/b, a
        assert!(dir_deletes.len() >= 2);
        if dir_deletes.len() >= 3 {
            let idx_abc = dir_deletes.iter().position(|p| p == "a/b/c").unwrap_or(0);
            let idx_ab = dir_deletes.iter().position(|p| p == "a/b").unwrap_or(0);
            let idx_a = dir_deletes.iter().position(|p| p == "a").unwrap_or(0);
            assert!(idx_abc < idx_ab, "a/b/c should come before a/b");
            assert!(idx_ab < idx_a, "a/b should come before a");
        }
    }

    // ── Copy list is sorted ─────────────────────────────────────────────

    #[test]
    fn test_copy_list_is_sorted() {
        let src = tree_from(vec![
            file_meta("z.txt", 10, "hz"),
            file_meta("a.txt", 20, "ha"),
            file_meta("m.txt", 30, "hm"),
        ]);
        let dst = FileTree::new();
        let plan = compute_diff_default(&src, &dst);

        let paths: Vec<String> = plan
            .to_copy
            .iter()
            .map(|e| e.rel_path.to_string_lossy().to_string())
            .collect();
        assert_eq!(paths, vec!["a.txt", "m.txt", "z.txt"]);
    }

    // ── Dry-run formatting ──────────────────────────────────────────────

    #[test]
    fn test_dry_run_empty_plan() {
        let plan = SyncPlan::default();
        let output = format_dry_run(&plan);
        assert!(output.contains("No changes needed"));
    }

    #[test]
    fn test_dry_run_with_operations() {
        let plan = SyncPlan {
            to_copy: vec![SyncEntry {
                rel_path: PathBuf::from("new.txt"),
                size: 1024,
            }],
            to_update: vec![SyncEntry {
                rel_path: PathBuf::from("changed.txt"),
                size: 2048,
            }],
            to_delete: vec![DeleteEntry {
                rel_path: PathBuf::from("old.txt"),
                is_dir: false,
            }],
        };
        let output = format_dry_run(&plan);
        assert!(output.contains("3 operation(s)"));
        assert!(output.contains("+ new.txt"));
        assert!(output.contains("~ changed.txt"));
        assert!(output.contains("- [file] old.txt"));
    }

    // ── format_bytes ────────────────────────────────────────────────────

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1_048_576), "1.00 MB");
        assert_eq!(format_bytes(1_073_741_824), "1.00 GB");
    }

    // ── files_differ helper ─────────────────────────────────────────────

    #[test]
    fn test_files_differ_by_size() {
        let a = file_meta("f.txt", 100, "same_hash");
        let b = file_meta("f.txt", 200, "same_hash");
        assert!(files_differ(&a, &b, true));
    }

    #[test]
    fn test_files_differ_by_hash() {
        let a = file_meta("f.txt", 100, "hash_a");
        let b = file_meta("f.txt", 100, "hash_b");
        assert!(files_differ(&a, &b, true));
    }

    #[test]
    fn test_files_identical() {
        let a = file_meta("f.txt", 100, "same");
        let b = file_meta("f.txt", 100, "same");
        assert!(!files_differ(&a, &b, true));
    }

    #[test]
    fn test_files_differ_mtime_fallback() {
        let a = file_meta_mtime("f.txt", 100, "h", 2000);
        let b = file_meta_mtime("f.txt", 100, "h", 1000);
        // With hash comparison on, hashes match → identical
        assert!(!files_differ(&a, &b, true));
        // With hash comparison off, mtime differs → different
        assert!(files_differ(&a, &b, false));
    }

    // ── Large tree stress test ──────────────────────────────────────────

    #[test]
    fn test_large_tree_diff() {
        let mut src_entries = Vec::new();
        let mut dst_entries = Vec::new();

        for i in 0..1000 {
            let path = format!("file_{i:04}.txt");
            let hash = format!("hash_{i:04}");
            src_entries.push(file_meta(&path, i as u64 * 10, &hash));

            // Even-numbered files exist in dest with same content,
            // odd-numbered files have different hashes in dest.
            if i % 2 == 0 {
                dst_entries.push(file_meta(&path, i as u64 * 10, &hash));
            } else {
                let old_hash = format!("old_hash_{i:04}");
                dst_entries.push(file_meta(&path, i as u64 * 10, &old_hash));
            }
        }

        // Add some orphans in dest
        for i in 1000..1050 {
            let path = format!("orphan_{i}.txt");
            let hash = format!("orphan_hash_{i}");
            dst_entries.push(file_meta(&path, 50, &hash));
        }

        let src = tree_from(src_entries);
        let dst = tree_from(dst_entries);
        let plan = compute_diff_default(&src, &dst);

        // 500 even files are identical → skip
        // 500 odd files have different hashes → update
        assert_eq!(plan.to_update.len(), 500);
        // No new files
        assert_eq!(plan.to_copy.len(), 0);
        // 50 orphan files to delete
        let file_deletes: Vec<_> = plan.to_delete.iter().filter(|d| !d.is_dir).collect();
        assert_eq!(file_deletes.len(), 50);
    }
}
