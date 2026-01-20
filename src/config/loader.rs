// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Configuration file discovery and loading.
//!
//! Implements the configuration file search priority:
//! 1. CLI flag `--config <path>`
//! 2. `$MARMOSYN_CONFIG` environment variable
//! 3. `./marmosyn.toml` (current directory)
//! 4. Default path depending on UID (root vs user)

use std::path::{Path, PathBuf};

use crate::config::paths::DefaultPaths;
use crate::config::types::AppConfig;

/// Errors that can occur during configuration loading.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// Configuration file was not found in any of the searched paths.
    #[error("config file not found: searched {paths:?}")]
    NotFound { paths: Vec<PathBuf> },

    /// Failed to read the configuration file from disk.
    #[error("failed to read config file '{path}': {source}")]
    ReadError {
        path: PathBuf,
        source: std::io::Error,
    },

    /// Failed to parse the TOML content into configuration structs.
    #[error("failed to parse config file '{path}': {source}")]
    ParseError {
        path: PathBuf,
        source: toml::de::Error,
    },
}

/// Discovers the configuration file path using the priority chain:
/// 1. Explicit path from CLI `--config` flag
/// 2. `$MARMOSYN_CONFIG` environment variable
/// 3. `./marmosyn.toml` in the current directory
/// 4. Default UID-based path from `DefaultPaths::detect()`
///
/// Returns the first path that exists on disk, or `LoadError::NotFound`
/// with the list of all searched paths.
pub fn discover_config_path(explicit_path: Option<&Path>) -> Result<PathBuf, LoadError> {
    let mut searched = Vec::new();

    // 1. Explicit CLI flag
    if let Some(path) = explicit_path {
        let path = path.to_path_buf();
        if path.exists() {
            return Ok(path);
        }
        searched.push(path);
    }

    // 2. Environment variable
    if let Ok(env_path) = std::env::var("MARMOSYN_CONFIG") {
        let path = PathBuf::from(env_path);
        if path.exists() {
            return Ok(path);
        }
        searched.push(path);
    }

    // 3. Current directory
    let cwd_path = PathBuf::from("./marmosyn.toml");
    if cwd_path.exists() {
        return Ok(cwd_path);
    }
    searched.push(cwd_path);

    // 4. Default UID-based path
    let defaults = DefaultPaths::detect();
    let default_path = defaults.config_file;
    if default_path.exists() {
        return Ok(default_path);
    }
    searched.push(default_path);

    Err(LoadError::NotFound { paths: searched })
}

/// Loads and parses a configuration file from the given path.
pub fn load_config_from_path(path: &Path) -> Result<AppConfig, LoadError> {
    let content = std::fs::read_to_string(path).map_err(|e| LoadError::ReadError {
        path: path.to_path_buf(),
        source: e,
    })?;

    let config: AppConfig = toml::from_str(&content).map_err(|e| LoadError::ParseError {
        path: path.to_path_buf(),
        source: e,
    })?;

    Ok(config)
}

/// Discovers the configuration file and loads it.
///
/// This is the primary entry point for configuration loading. It combines
/// `discover_config_path` and `load_config_from_path`.
pub fn load_config(explicit_path: Option<&Path>) -> Result<(PathBuf, AppConfig), LoadError> {
    let path = discover_config_path(explicit_path)?;
    let config = load_config_from_path(&path)?;
    Ok((path, config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discover_config_not_found() {
        let result = discover_config_path(Some(Path::new("/nonexistent/path/config.toml")));
        assert!(result.is_err());
        match result.unwrap_err() {
            LoadError::NotFound { paths } => {
                assert!(!paths.is_empty());
            }
            other => panic!("expected NotFound, got: {other}"),
        }
    }

    #[test]
    fn test_load_config_from_path_not_found() {
        let result = load_config_from_path(Path::new("/nonexistent/config.toml"));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), LoadError::ReadError { .. }));
    }

    #[test]
    fn test_load_config_from_valid_toml() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            r#"
[server]
listen = "0.0.0.0:7854"
api_listen = "127.0.0.1:7855"
"#,
        )
        .unwrap();

        let config = load_config_from_path(&config_path).unwrap();
        assert_eq!(config.server.listen, "0.0.0.0:7854");
        assert_eq!(config.server.api_listen, "127.0.0.1:7855");
    }

    #[test]
    fn test_load_config_invalid_toml() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "this is not valid [[[toml").unwrap();

        let result = load_config_from_path(&config_path);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), LoadError::ParseError { .. }));
    }

    #[test]
    fn test_discover_config_explicit_path() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("custom.toml");
        std::fs::write(&config_path, "[server]\n").unwrap();

        let result = discover_config_path(Some(&config_path));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), config_path);
    }
}
