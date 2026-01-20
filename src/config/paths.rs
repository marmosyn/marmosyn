// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! UID detection and default path selection.
//!
//! Determines whether the process is running as root (UID 0) or as a regular user,
//! and provides the appropriate default paths for configuration, data, safety backups,
//! PID files, logs, and credentials.

use std::path::PathBuf;

/// Determines whether the process is running as root (UID 0).
#[cfg(unix)]
pub fn is_root() -> bool {
    // SAFETY: getuid() is a simple syscall with no unsafe memory access.
    unsafe { libc::getuid() == 0 }
}

/// On non-Unix platforms, assume non-root.
#[cfg(not(unix))]
pub fn is_root() -> bool {
    false
}

/// Default filesystem paths depending on the effective UID.
///
/// - **Root (UID 0):** system-wide paths under `/etc`, `/var/lib`, `/var/log`, `/var/run`.
/// - **Regular user:** paths under `~/.config/marmosyn` and `~/.local/share/marmosyn`.
#[derive(Debug, Clone)]
pub struct DefaultPaths {
    /// Path to the TOML configuration file.
    pub config_file: PathBuf,
    /// Directory for internal data (SQLite DB, etc.).
    pub data_dir: PathBuf,
    /// Directory for safety backup copies.
    pub safety_dir: PathBuf,
    /// Path to the PID file.
    pub pid_file: PathBuf,
    /// Directory for log files.
    pub log_dir: PathBuf,
    /// Path to the CLI credentials file.
    pub credentials_file: PathBuf,
}

impl DefaultPaths {
    /// Detect the current UID and return the appropriate default paths.
    pub fn detect() -> Self {
        if is_root() {
            Self {
                config_file: PathBuf::from("/etc/marmosyn/config.toml"),
                data_dir: PathBuf::from("/var/lib/marmosyn"),
                safety_dir: PathBuf::from("/var/lib/marmosyn/safety"),
                pid_file: PathBuf::from("/var/run/marmosyn.pid"),
                log_dir: PathBuf::from("/var/log/marmosyn"),
                credentials_file: PathBuf::from("/root/.config/marmosyn/credentials.toml"),
            }
        } else {
            let home = dirs::home_dir().expect("cannot determine home directory");
            Self {
                config_file: home.join(".config/marmosyn/config.toml"),
                data_dir: home.join(".local/share/marmosyn"),
                safety_dir: home.join(".local/share/marmosyn/safety"),
                pid_file: home.join(".local/share/marmosyn/marmosyn.pid"),
                log_dir: home.join(".local/share/marmosyn/logs"),
                credentials_file: home.join(".config/marmosyn/credentials.toml"),
            }
        }
    }

    /// Return the path to the SQLite database file.
    pub fn db_file(&self) -> PathBuf {
        self.data_dir.join("marmosyn.db")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_returns_valid_paths() {
        let paths = DefaultPaths::detect();

        // All paths must be absolute
        assert!(paths.config_file.is_absolute());
        assert!(paths.data_dir.is_absolute());
        assert!(paths.safety_dir.is_absolute());
        assert!(paths.pid_file.is_absolute());
        assert!(paths.log_dir.is_absolute());
        assert!(paths.credentials_file.is_absolute());

        // DB file should be inside data_dir
        let db = paths.db_file();
        assert!(db.starts_with(&paths.data_dir));

        // Safety dir should be inside data_dir
        assert!(paths.safety_dir.starts_with(&paths.data_dir));
    }

    #[test]
    fn test_config_file_ends_with_toml() {
        let paths = DefaultPaths::detect();
        assert_eq!(
            paths.config_file.extension().and_then(|e| e.to_str()),
            Some("toml")
        );
    }

    #[test]
    fn test_credentials_file_ends_with_toml() {
        let paths = DefaultPaths::detect();
        assert_eq!(
            paths.credentials_file.extension().and_then(|e| e.to_str()),
            Some("toml")
        );
    }

    #[test]
    fn test_is_root_returns_bool() {
        // We can't assert the exact value in tests (depends on who runs them),
        // but we can confirm it doesn't panic.
        let _ = is_root();
    }

    #[test]
    fn test_user_paths_are_under_home() {
        if !is_root() {
            let paths = DefaultPaths::detect();
            let home = dirs::home_dir().expect("cannot determine home directory");
            assert!(paths.config_file.starts_with(&home));
            assert!(paths.data_dir.starts_with(&home));
            assert!(paths.credentials_file.starts_with(&home));
        }
    }
}
