// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Destination format parsing for sync job targets.
//!
//! Parses dest strings into [`ParsedDest`] variants (local or remote) and provides
//! [`collect_destinations`] for unified access to `dest`/`dests` fields in a [`SyncJob`].
//!
//! # Dest string formats
//!
//! | Format | Type | Example |
//! |--------|------|---------|
//! | `/local/path` | Local | `/mnt/backup/docs` |
//! | `remote_name:/absolute/path` | Remote | `myserver:/mnt/data/docs` |
//! | `remote_name:alias` | Remote | `myserver:backup` |
//! | `remote_name:alias/subpath` | Remote | `myserver:backup/docs` |
//!
//! A colon after a single ASCII letter is treated as a Windows drive letter (e.g. `C:\path`)
//! and is **not** interpreted as a remote separator.

use std::path::PathBuf;

use super::types::SyncJob;

/// Result of parsing a single dest string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedDest {
    /// A local filesystem path.
    Local {
        /// The absolute local path.
        path: PathBuf,
    },
    /// A path on a remote receiver node.
    Remote {
        /// The name of the remote (must match a `[[remote]]` entry).
        remote_name: String,
        /// The path component sent to the receiver.
        /// Can be an alias, alias/subpath, or an absolute path.
        remote_path: String,
    },
}

/// Parses a single dest string into a [`ParsedDest`].
///
/// # Rules
///
/// * If the string contains `:` and the text before `:` is **not** a single ASCII letter
///   (Windows drive letter), and is a valid remote name (non-empty, no slashes), it is
///   treated as a remote dest.
/// * Otherwise it is treated as a local path.
///
/// # Examples
///
/// ```
/// use marmosyn::config::dest_parser::{parse_dest, ParsedDest};
/// use std::path::PathBuf;
///
/// assert_eq!(
///     parse_dest("/mnt/backup"),
///     ParsedDest::Local { path: PathBuf::from("/mnt/backup") },
/// );
///
/// assert_eq!(
///     parse_dest("myserver:backup/docs"),
///     ParsedDest::Remote {
///         remote_name: "myserver".into(),
///         remote_path: "backup/docs".into(),
///     },
/// );
/// ```
pub fn parse_dest(dest: &str) -> ParsedDest {
    if let Some(colon_pos) = dest.find(':') {
        let before_colon = &dest[..colon_pos];

        // Windows drive letter: single ASCII letter before colon (e.g. "C:\path")
        if before_colon.len() == 1 && before_colon.chars().all(|c| c.is_ascii_alphabetic()) {
            return ParsedDest::Local {
                path: PathBuf::from(dest),
            };
        }

        // Valid remote name: non-empty, contains no slashes
        if !before_colon.is_empty() && !before_colon.contains('/') && !before_colon.contains('\\') {
            return ParsedDest::Remote {
                remote_name: before_colon.to_string(),
                remote_path: dest[colon_pos + 1..].to_string(),
            };
        }
    }

    ParsedDest::Local {
        path: PathBuf::from(dest),
    }
}

/// Extracts the unified list of destination strings from a [`SyncJob`].
///
/// A job specifies destinations via either `dest` (single string) or `dests` (array of
/// strings). This function returns a `Vec<&str>` covering whichever field is set.
///
/// Must be called **after** validation — at that point it is guaranteed that exactly one of
/// `dest` or `dests` is present. If neither is set, an empty vec is returned (the validation
/// layer catches this case earlier).
pub fn collect_destinations(job: &SyncJob) -> Vec<&str> {
    if let Some(ref single) = job.dest {
        vec![single.as_str()]
    } else if let Some(ref multi) = job.dests {
        multi.iter().map(|s| s.as_str()).collect()
    } else {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_dest ───────────────────────────────────────────────────────

    #[test]
    fn test_parse_local_absolute_unix() {
        assert_eq!(
            parse_dest("/mnt/backup/docs"),
            ParsedDest::Local {
                path: PathBuf::from("/mnt/backup/docs"),
            },
        );
    }

    #[test]
    fn test_parse_local_relative() {
        assert_eq!(
            parse_dest("backup/docs"),
            ParsedDest::Local {
                path: PathBuf::from("backup/docs"),
            },
        );
    }

    #[test]
    fn test_parse_local_windows_drive() {
        assert_eq!(
            parse_dest("C:\\Users\\backup"),
            ParsedDest::Local {
                path: PathBuf::from("C:\\Users\\backup"),
            },
        );
    }

    #[test]
    fn test_parse_remote_with_alias() {
        assert_eq!(
            parse_dest("myserver:backup"),
            ParsedDest::Remote {
                remote_name: "myserver".into(),
                remote_path: "backup".into(),
            },
        );
    }

    #[test]
    fn test_parse_remote_with_alias_and_subpath() {
        assert_eq!(
            parse_dest("office-server:backup/documents"),
            ParsedDest::Remote {
                remote_name: "office-server".into(),
                remote_path: "backup/documents".into(),
            },
        );
    }

    #[test]
    fn test_parse_remote_absolute_path() {
        assert_eq!(
            parse_dest("cloud:/backups/documents"),
            ParsedDest::Remote {
                remote_name: "cloud".into(),
                remote_path: "/backups/documents".into(),
            },
        );
    }

    #[test]
    fn test_parse_remote_empty_path() {
        // Edge case: "remote:" with nothing after the colon
        assert_eq!(
            parse_dest("remote:"),
            ParsedDest::Remote {
                remote_name: "remote".into(),
                remote_path: String::new(),
            },
        );
    }

    #[test]
    fn test_parse_ignores_slash_in_prefix() {
        // "some/path:thing" — the part before ':' contains '/', so it's local
        assert_eq!(
            parse_dest("some/path:thing"),
            ParsedDest::Local {
                path: PathBuf::from("some/path:thing"),
            },
        );
    }

    // ── collect_destinations ─────────────────────────────────────────────

    #[test]
    fn test_collect_single_dest() {
        let job = SyncJob {
            name: "test".into(),
            source: PathBuf::from("/src"),
            dest: Some("/mnt/backup".into()),
            dests: None,
            ..SyncJob::default()
        };
        assert_eq!(collect_destinations(&job), vec!["/mnt/backup"]);
    }

    #[test]
    fn test_collect_multiple_dests() {
        let job = SyncJob {
            name: "test".into(),
            source: PathBuf::from("/src"),
            dest: None,
            dests: Some(vec!["/a".into(), "server:b".into()]),
            ..SyncJob::default()
        };
        assert_eq!(collect_destinations(&job), vec!["/a", "server:b"]);
    }

    #[test]
    fn test_collect_empty_when_neither_set() {
        let job = SyncJob {
            name: "test".into(),
            source: PathBuf::from("/src"),
            dest: None,
            dests: None,
            ..SyncJob::default()
        };
        assert!(collect_destinations(&job).is_empty());
    }
}
