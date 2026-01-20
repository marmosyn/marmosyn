// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Receiver logic: allowed_paths validation, alias resolution, and path-traversal protection.
//!
//! The [`ReceiverGuard`] is responsible for validating all incoming file paths
//! from remote senders against the configured `allowed_paths`. It resolves
//! aliases to real filesystem paths and ensures that path-traversal attacks
//! (e.g. using `..` components) cannot escape the allowed directories.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::config::types::AllowedPath;

/// Errors returned by receiver path validation.
#[derive(Debug, thiserror::Error)]
pub enum ReceiverError {
    /// The requested path does not match any allowed_path or alias.
    #[error("forbidden: path '{path}' is not within any allowed_path")]
    Forbidden { path: String },

    /// The resolved path escapes the allowed directory (path-traversal attempt).
    #[error("path traversal detected: '{path}' escapes allowed directory '{allowed}'")]
    PathTraversal { path: String, allowed: String },

    /// The alias referenced by the sender does not exist.
    #[error("unknown alias '{alias}'")]
    UnknownAlias { alias: String },

    /// An I/O error occurred during path canonicalization.
    #[error("failed to resolve path '{path}': {source}")]
    IoError {
        path: String,
        source: std::io::Error,
    },
}

/// Guards incoming file write requests against the configured `allowed_paths`.
///
/// On the receiver side, every file path sent by a remote sender must be
/// validated before any I/O is performed. `ReceiverGuard` handles:
///
/// 1. **Alias resolution** — if the first path component matches an alias,
///    it is replaced with the corresponding `allowed_paths` entry.
/// 2. **Absolute path validation** — if the path is absolute, it must be a
///    subpath of one of the `allowed_paths`.
/// 3. **Path-traversal protection** — after resolution, the canonical path
///    must not escape the allowed directory (e.g. via `..` components).
pub struct ReceiverGuard {
    /// Mapping from alias name to the allowed path entry.
    alias_map: HashMap<String, PathBuf>,

    /// All configured allowed paths (for absolute path validation).
    allowed_paths: Vec<PathBuf>,
}

impl ReceiverGuard {
    /// Creates a new `ReceiverGuard` from the receiver's allowed_paths configuration.
    pub fn new(allowed: &[AllowedPath]) -> Self {
        let mut alias_map = HashMap::new();
        let mut allowed_paths = Vec::new();

        for ap in allowed {
            allowed_paths.push(ap.path.clone());
            if let Some(ref alias) = ap.alias {
                alias_map.insert(alias.clone(), ap.path.clone());
            }
        }

        Self {
            alias_map,
            allowed_paths,
        }
    }

    /// Resolves a remote dest path to an absolute filesystem path, checking
    /// `allowed_paths` and protecting against path traversal.
    ///
    /// # Rules
    ///
    /// 1. If `remote_path` starts with `/` — it is treated as an absolute path
    ///    and must be a subpath of one of the `allowed_paths`.
    /// 2. Otherwise, the first path component may be an alias. If it matches,
    ///    the alias is replaced with the corresponding allowed path. The rest
    ///    of the path is appended.
    /// 3. After resolution, the path is canonicalized and verified to ensure
    ///    it does not escape the allowed directory.
    /// 4. If nothing matches — `Forbidden` is returned.
    pub fn resolve_path(&self, remote_path: &str) -> Result<PathBuf, ReceiverError> {
        if remote_path.is_empty() {
            return Err(ReceiverError::Forbidden {
                path: remote_path.to_string(),
            });
        }

        let path = Path::new(remote_path);

        if path.is_absolute() {
            self.resolve_absolute(remote_path, path)
        } else {
            self.resolve_relative(remote_path, path)
        }
    }

    /// Resolves an absolute path by checking it against all allowed_paths.
    fn resolve_absolute(&self, remote_path: &str, path: &Path) -> Result<PathBuf, ReceiverError> {
        for allowed in &self.allowed_paths {
            if path.starts_with(allowed) {
                // Verify no path-traversal after normalization
                return self.verify_no_traversal(path.to_path_buf(), allowed, remote_path);
            }
        }

        Err(ReceiverError::Forbidden {
            path: remote_path.to_string(),
        })
    }

    /// Resolves a relative path by trying alias resolution first, then
    /// checking against allowed_paths without aliases.
    fn resolve_relative(&self, remote_path: &str, path: &Path) -> Result<PathBuf, ReceiverError> {
        // Extract the first path component — it may be an alias
        let mut components = path.components();
        let first = components
            .next()
            .map(|c| c.as_os_str().to_string_lossy().to_string());

        if let Some(ref first_component) = first {
            // Check if it matches an alias
            if let Some(base_path) = self.alias_map.get(first_component.as_str()) {
                let rest: PathBuf = components.collect();
                let resolved = base_path.join(rest);
                return self.verify_no_traversal(resolved, base_path, remote_path);
            }
        }

        Err(ReceiverError::Forbidden {
            path: remote_path.to_string(),
        })
    }

    /// Verifies that the resolved path does not escape the allowed base directory.
    ///
    /// This normalizes the path to remove `.` and `..` components and then
    /// checks that the result still starts with the allowed base path.
    fn verify_no_traversal(
        &self,
        resolved: PathBuf,
        allowed_base: &Path,
        remote_path: &str,
    ) -> Result<PathBuf, ReceiverError> {
        let normalized = normalize_path(&resolved);

        // The normalized path must still be under the allowed base
        if !normalized.starts_with(allowed_base) {
            return Err(ReceiverError::PathTraversal {
                path: remote_path.to_string(),
                allowed: allowed_base.display().to_string(),
            });
        }

        Ok(normalized)
    }

    /// Returns `true` if the given alias is known.
    pub fn has_alias(&self, alias: &str) -> bool {
        self.alias_map.contains_key(alias)
    }

    /// Returns the filesystem path for a given alias, if it exists.
    pub fn resolve_alias(&self, alias: &str) -> Option<&PathBuf> {
        self.alias_map.get(alias)
    }
}

/// Normalize a path by resolving `.` and `..` components without touching
/// the filesystem (unlike `canonicalize()` which requires the path to exist).
fn normalize_path(path: &Path) -> PathBuf {
    use std::path::Component;

    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {
                // Skip '.' components
            }
            other => {
                normalized.push(other);
            }
        }
    }

    normalized
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::AllowedPath;

    fn make_guard() -> ReceiverGuard {
        ReceiverGuard::new(&[
            AllowedPath {
                path: PathBuf::from("/mnt/backup"),
                alias: Some("backup".to_string()),
            },
            AllowedPath {
                path: PathBuf::from("/mnt/archive"),
                alias: Some("archive".to_string()),
            },
            AllowedPath {
                path: PathBuf::from("/data/shared"),
                alias: None,
            },
        ])
    }

    #[test]
    fn test_resolve_alias_simple() {
        let guard = make_guard();
        let resolved = guard.resolve_path("backup/documents").unwrap();
        assert_eq!(resolved, PathBuf::from("/mnt/backup/documents"));
    }

    #[test]
    fn test_resolve_alias_root() {
        let guard = make_guard();
        let resolved = guard.resolve_path("archive").unwrap();
        assert_eq!(resolved, PathBuf::from("/mnt/archive"));
    }

    #[test]
    fn test_resolve_alias_nested() {
        let guard = make_guard();
        let resolved = guard.resolve_path("backup/a/b/c").unwrap();
        assert_eq!(resolved, PathBuf::from("/mnt/backup/a/b/c"));
    }

    #[test]
    fn test_resolve_absolute_within_allowed() {
        let guard = make_guard();
        let resolved = guard.resolve_path("/mnt/backup/docs").unwrap();
        assert_eq!(resolved, PathBuf::from("/mnt/backup/docs"));
    }

    #[test]
    fn test_resolve_absolute_shared_no_alias() {
        let guard = make_guard();
        let resolved = guard.resolve_path("/data/shared/file.txt").unwrap();
        assert_eq!(resolved, PathBuf::from("/data/shared/file.txt"));
    }

    #[test]
    fn test_reject_absolute_outside_allowed() {
        let guard = make_guard();
        let result = guard.resolve_path("/etc/passwd");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReceiverError::Forbidden { .. }
        ));
    }

    #[test]
    fn test_reject_unknown_alias() {
        let guard = make_guard();
        let result = guard.resolve_path("unknown/file.txt");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReceiverError::Forbidden { .. }
        ));
    }

    #[test]
    fn test_reject_empty_path() {
        let guard = make_guard();
        let result = guard.resolve_path("");
        assert!(result.is_err());
    }

    #[test]
    fn test_path_traversal_via_dotdot() {
        let guard = make_guard();
        let result = guard.resolve_path("backup/../../../etc/passwd");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReceiverError::PathTraversal { .. }
        ));
    }

    #[test]
    fn test_path_traversal_absolute() {
        let guard = make_guard();
        let result = guard.resolve_path("/mnt/backup/../../etc/passwd");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReceiverError::PathTraversal { .. }
        ));
    }

    #[test]
    fn test_has_alias() {
        let guard = make_guard();
        assert!(guard.has_alias("backup"));
        assert!(guard.has_alias("archive"));
        assert!(!guard.has_alias("nonexistent"));
    }

    #[test]
    fn test_resolve_alias_method() {
        let guard = make_guard();
        assert_eq!(
            guard.resolve_alias("backup"),
            Some(&PathBuf::from("/mnt/backup"))
        );
        assert_eq!(guard.resolve_alias("nonexistent"), None);
    }

    #[test]
    fn test_normalize_path() {
        assert_eq!(
            normalize_path(Path::new("/a/b/../c")),
            PathBuf::from("/a/c")
        );
        assert_eq!(
            normalize_path(Path::new("/a/./b/./c")),
            PathBuf::from("/a/b/c")
        );
        assert_eq!(
            normalize_path(Path::new("/a/b/c/../../d")),
            PathBuf::from("/a/d")
        );
    }

    #[test]
    fn test_dotdot_within_allowed_is_ok() {
        let guard = make_guard();
        // "backup/a/../b" normalizes to "/mnt/backup/b" which is still within allowed
        let resolved = guard.resolve_path("backup/a/../b").unwrap();
        assert_eq!(resolved, PathBuf::from("/mnt/backup/b"));
    }
}
