// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Gitignore-style pattern filtering for file exclusion.
//!
//! Uses `globset::GlobSet` to compile exclude patterns once at startup and
//! efficiently test file paths against them during scanning.

use std::path::Path;

use globset::{Glob, GlobSet, GlobSetBuilder};

/// Errors that can occur when building an exclude filter.
#[derive(Debug, thiserror::Error)]
pub enum ExcludeError {
    /// A glob pattern failed to compile.
    #[error("invalid exclude pattern '{pattern}': {source}")]
    InvalidPattern {
        pattern: String,
        source: globset::Error,
    },

    /// The glob set failed to build.
    #[error("failed to build exclude set: {0}")]
    BuildError(#[from] globset::Error),
}

/// A compiled set of gitignore-style exclude patterns.
///
/// Patterns are compiled into a [`GlobSet`] for efficient matching against
/// relative file paths during directory scanning.
///
/// # Examples
///
/// ```
/// use marmosyn::core::excluder::Excluder;
/// use std::path::Path;
///
/// let excluder = Excluder::new(&["*.tmp", ".cache/", "node_modules/"]).unwrap();
/// assert!(excluder.is_excluded(Path::new("file.tmp")));
/// assert!(!excluder.is_excluded(Path::new("file.txt")));
/// ```
#[derive(Debug, Clone)]
pub struct Excluder {
    glob_set: GlobSet,
}

impl Excluder {
    /// Creates a new excluder from a list of gitignore-style patterns.
    ///
    /// Each pattern is compiled into a glob. Returns an error if any pattern
    /// is invalid.
    pub fn new(patterns: &[impl AsRef<str>]) -> Result<Self, ExcludeError> {
        let mut builder = GlobSetBuilder::new();

        for pattern in patterns {
            let pattern = pattern.as_ref();
            let glob = Glob::new(pattern).map_err(|e| ExcludeError::InvalidPattern {
                pattern: pattern.to_string(),
                source: e,
            })?;
            builder.add(glob);

            // If the pattern does not contain a path separator, also match it
            // in subdirectories by prepending "**/" — this mirrors gitignore
            // semantics where a bare pattern like "*.tmp" matches at any depth.
            if !pattern.contains('/') && !pattern.contains('\\') {
                let deep_pattern = format!("**/{pattern}");
                let deep_glob =
                    Glob::new(&deep_pattern).map_err(|e| ExcludeError::InvalidPattern {
                        pattern: deep_pattern,
                        source: e,
                    })?;
                builder.add(deep_glob);
            }
        }

        let glob_set = builder.build()?;
        Ok(Self { glob_set })
    }

    /// Creates an excluder with no patterns (matches nothing).
    pub fn empty() -> Self {
        Self {
            glob_set: GlobSetBuilder::new().build().expect("empty GlobSet"),
        }
    }

    /// Returns `true` if the given relative path matches any exclude pattern.
    pub fn is_excluded(&self, rel_path: &Path) -> bool {
        self.glob_set.is_match(rel_path)
    }

    /// Returns the number of compiled patterns in the set.
    pub fn pattern_count(&self) -> usize {
        self.glob_set.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_empty_excluder_matches_nothing() {
        let excluder = Excluder::empty();
        assert!(!excluder.is_excluded(Path::new("anything.txt")));
        assert!(!excluder.is_excluded(Path::new("dir/file.rs")));
    }

    #[test]
    fn test_simple_extension_pattern() {
        let excluder = Excluder::new(&["*.tmp"]).unwrap();
        assert!(excluder.is_excluded(Path::new("file.tmp")));
        assert!(excluder.is_excluded(Path::new("subdir/file.tmp")));
        assert!(!excluder.is_excluded(Path::new("file.txt")));
    }

    #[test]
    fn test_directory_pattern() {
        let excluder = Excluder::new(&[".cache"]).unwrap();
        assert!(excluder.is_excluded(Path::new(".cache")));
        assert!(excluder.is_excluded(Path::new("sub/.cache")));
    }

    #[test]
    fn test_deep_glob_pattern() {
        let excluder = Excluder::new(&["**/*.log"]).unwrap();
        assert!(excluder.is_excluded(Path::new("app.log")));
        assert!(excluder.is_excluded(Path::new("logs/app.log")));
        assert!(excluder.is_excluded(Path::new("a/b/c/app.log")));
        assert!(!excluder.is_excluded(Path::new("app.txt")));
    }

    #[test]
    fn test_node_modules_pattern() {
        let excluder = Excluder::new(&["node_modules"]).unwrap();
        assert!(excluder.is_excluded(Path::new("node_modules")));
        assert!(excluder.is_excluded(Path::new("project/node_modules")));
        // To match files *inside* node_modules, use "node_modules/**" pattern
        let excluder2 = Excluder::new(&["node_modules", "node_modules/**"]).unwrap();
        assert!(excluder2.is_excluded(Path::new("node_modules/package.json")));
    }

    #[test]
    fn test_multiple_patterns() {
        let excluder = Excluder::new(&["*.tmp", "*.log", ".git/"]).unwrap();
        assert!(excluder.is_excluded(Path::new("file.tmp")));
        assert!(excluder.is_excluded(Path::new("file.log")));
        assert!(excluder.is_excluded(Path::new(".git/")));
        assert!(!excluder.is_excluded(Path::new("file.rs")));
    }

    #[test]
    fn test_invalid_pattern_returns_error() {
        let result = Excluder::new(&["[invalid"]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(format!("{err}").contains("[invalid"));
    }

    #[test]
    fn test_pattern_count() {
        // "*.tmp" produces 2 globs (the original + the "**/*.tmp" variant),
        // and "**/*.log" produces 1 glob (it already contains a separator).
        let excluder = Excluder::new(&["*.tmp", "**/*.log"]).unwrap();
        assert!(excluder.pattern_count() >= 2);
    }

    #[test]
    fn test_bare_pattern_matches_in_subdirs() {
        let excluder = Excluder::new(&["*.bak"]).unwrap();
        assert!(excluder.is_excluded(Path::new("backup.bak")));
        assert!(excluder.is_excluded(Path::new("deep/nested/dir/backup.bak")));
    }
}
