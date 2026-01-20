// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! File tree and file metadata types for synchronization.
//!
//! [`FileTree`] represents a snapshot of a directory's contents, consisting of
//! a collection of [`FileMetadata`] entries. These structures are used for
//! comparing source and destination states to produce a [`SyncPlan`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// Metadata for a single file or directory in a file tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMetadata {
    /// Relative path from the root of the scanned directory.
    pub rel_path: PathBuf,

    /// File size in bytes (0 for directories).
    pub size: u64,

    /// Last modification time.
    pub mtime: SystemTime,

    /// BLAKE3 hash of the file contents (None for directories).
    pub hash: Option<String>,

    /// Whether this entry is a directory.
    pub is_dir: bool,

    /// Unix file permissions (mode bits). None on non-Unix platforms.
    #[cfg(unix)]
    pub permissions: Option<u32>,

    /// Placeholder for non-Unix platforms.
    #[cfg(not(unix))]
    pub permissions: Option<u32>,
}

impl FileMetadata {
    /// Returns the relative path as a string slice, if valid UTF-8.
    pub fn rel_path_str(&self) -> Option<&str> {
        self.rel_path.to_str()
    }
}

/// A snapshot of a directory tree: a collection of file and directory metadata
/// indexed by relative path.
#[derive(Debug, Clone, Default)]
pub struct FileTree {
    /// All entries keyed by their relative path.
    entries: HashMap<PathBuf, FileMetadata>,
}

impl FileTree {
    /// Creates a new empty file tree.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Creates a file tree from a vector of metadata entries.
    pub fn from_entries(entries: Vec<FileMetadata>) -> Self {
        let map = entries
            .into_iter()
            .map(|m| (m.rel_path.clone(), m))
            .collect();
        Self { entries: map }
    }

    /// Inserts a metadata entry into the tree.
    pub fn insert(&mut self, meta: FileMetadata) {
        self.entries.insert(meta.rel_path.clone(), meta);
    }

    /// Returns the metadata for the given relative path, if present.
    pub fn get(&self, rel_path: &Path) -> Option<&FileMetadata> {
        self.entries.get(rel_path)
    }

    /// Returns the number of entries in the tree.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the tree contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns an iterator over all entries.
    pub fn iter(&self) -> impl Iterator<Item = (&PathBuf, &FileMetadata)> {
        self.entries.iter()
    }

    /// Returns an iterator over all relative paths.
    pub fn paths(&self) -> impl Iterator<Item = &PathBuf> {
        self.entries.keys()
    }

    /// Returns an iterator over all metadata values.
    pub fn values(&self) -> impl Iterator<Item = &FileMetadata> {
        self.entries.values()
    }

    /// Consumes the tree and returns the underlying entries as a HashMap.
    pub fn into_entries(self) -> HashMap<PathBuf, FileMetadata> {
        self.entries
    }

    /// Returns all file entries (non-directory) sorted by relative path.
    pub fn files_sorted(&self) -> Vec<&FileMetadata> {
        let mut files: Vec<&FileMetadata> = self.entries.values().filter(|m| !m.is_dir).collect();
        files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
        files
    }

    /// Returns all directory entries sorted by relative path.
    pub fn dirs_sorted(&self) -> Vec<&FileMetadata> {
        let mut dirs: Vec<&FileMetadata> = self.entries.values().filter(|m| m.is_dir).collect();
        dirs.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
        dirs
    }

    /// Returns the total size of all file entries in bytes.
    pub fn total_size(&self) -> u64 {
        self.entries
            .values()
            .filter(|m| !m.is_dir)
            .map(|m| m.size)
            .sum()
    }
}

impl IntoIterator for FileTree {
    type Item = (PathBuf, FileMetadata);
    type IntoIter = std::collections::hash_map::IntoIter<PathBuf, FileMetadata>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    fn sample_file(rel: &str, size: u64) -> FileMetadata {
        FileMetadata {
            rel_path: PathBuf::from(rel),
            size,
            mtime: UNIX_EPOCH,
            hash: Some(format!("hash-{rel}")),
            is_dir: false,
            permissions: Some(0o644),
        }
    }

    fn sample_dir(rel: &str) -> FileMetadata {
        FileMetadata {
            rel_path: PathBuf::from(rel),
            size: 0,
            mtime: UNIX_EPOCH,
            hash: None,
            is_dir: true,
            permissions: Some(0o755),
        }
    }

    #[test]
    fn test_new_is_empty() {
        let tree = FileTree::new();
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);
    }

    #[test]
    fn test_insert_and_get() {
        let mut tree = FileTree::new();
        let meta = sample_file("docs/readme.txt", 100);
        tree.insert(meta.clone());

        assert_eq!(tree.len(), 1);
        assert!(!tree.is_empty());

        let found = tree.get(Path::new("docs/readme.txt"));
        assert!(found.is_some());
        assert_eq!(found.unwrap().size, 100);
    }

    #[test]
    fn test_from_entries() {
        let entries = vec![
            sample_file("a.txt", 10),
            sample_file("b.txt", 20),
            sample_dir("sub"),
        ];
        let tree = FileTree::from_entries(entries);
        assert_eq!(tree.len(), 3);
        assert!(tree.get(Path::new("a.txt")).is_some());
        assert!(tree.get(Path::new("sub")).is_some());
    }

    #[test]
    fn test_files_sorted() {
        let entries = vec![
            sample_file("z.txt", 1),
            sample_dir("dir"),
            sample_file("a.txt", 2),
        ];
        let tree = FileTree::from_entries(entries);
        let files = tree.files_sorted();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].rel_path, PathBuf::from("a.txt"));
        assert_eq!(files[1].rel_path, PathBuf::from("z.txt"));
    }

    #[test]
    fn test_dirs_sorted() {
        let entries = vec![
            sample_dir("z_dir"),
            sample_file("file.txt", 1),
            sample_dir("a_dir"),
        ];
        let tree = FileTree::from_entries(entries);
        let dirs = tree.dirs_sorted();
        assert_eq!(dirs.len(), 2);
        assert_eq!(dirs[0].rel_path, PathBuf::from("a_dir"));
        assert_eq!(dirs[1].rel_path, PathBuf::from("z_dir"));
    }

    #[test]
    fn test_total_size() {
        let entries = vec![
            sample_file("a.txt", 100),
            sample_file("b.txt", 250),
            sample_dir("sub"),
        ];
        let tree = FileTree::from_entries(entries);
        assert_eq!(tree.total_size(), 350);
    }

    #[test]
    fn test_into_iterator() {
        let entries = vec![sample_file("f.txt", 5)];
        let tree = FileTree::from_entries(entries);
        let collected: Vec<_> = tree.into_iter().collect();
        assert_eq!(collected.len(), 1);
    }

    #[test]
    fn test_rel_path_str() {
        let meta = sample_file("hello/world.txt", 0);
        assert_eq!(meta.rel_path_str(), Some("hello/world.txt"));
    }
}
