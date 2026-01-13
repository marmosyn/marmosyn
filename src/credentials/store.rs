//! Credentials file storage — read/write `~/.config/marmosyn/credentials.toml`.
//!
//! The credentials file stores authentication tokens for connecting to MarmoSyn
//! servers. Each entry is identified by a profile name (e.g. "default", "office")
//! and contains a server URL and a token (plain or encrypted).
//!
//! Token format in the file:
//! - `plain:actual-token` — stored in cleartext
//! - `encrypted:base64data` — encrypted with Argon2id + ChaCha20-Poly1305
//!
//! File permissions are set to `0600` (owner read/write only).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::paths::DefaultPaths;

/// Errors that can occur during credentials file operations.
///
/// Also re-exported as [`StoreError`] for use by other modules.
#[derive(Debug, thiserror::Error)]
pub enum CredentialsError {
    /// Failed to read the credentials file from disk.
    #[error("failed to read credentials file '{path}': {source}")]
    ReadError {
        path: PathBuf,
        source: std::io::Error,
    },

    /// Failed to write the credentials file to disk.
    #[error("failed to write credentials file '{path}': {source}")]
    WriteError {
        path: PathBuf,
        source: std::io::Error,
    },

    /// Failed to parse the TOML content of the credentials file.
    #[error("failed to parse credentials file '{path}': {source}")]
    ParseError {
        path: PathBuf,
        source: toml::de::Error,
    },

    /// Failed to serialize the credentials to TOML.
    #[error("failed to serialize credentials: {0}")]
    SerializeError(#[from] toml::ser::Error),

    /// Failed to set file permissions.
    #[error("failed to set permissions on '{path}': {source}")]
    PermissionError {
        path: PathBuf,
        source: std::io::Error,
    },

    /// The credentials file has insecure permissions.
    #[error("credentials file '{path}' has insecure permissions (should be 0600)")]
    InsecurePermissions { path: PathBuf },
}

/// Alias for [`CredentialsError`] used by the `resolve` module.
pub type StoreError = CredentialsError;

/// Top-level credentials file structure.
///
/// Maps profile names (e.g. "default", "office") to credential entries.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredentialsFile {
    /// Mapping from profile name to credential entry.
    #[serde(flatten)]
    pub entries: BTreeMap<String, CredentialEntry>,
}

/// A single credential entry for a server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialEntry {
    /// The server URL (e.g. `"http://127.0.0.1:7855"`).
    pub server: String,

    /// The token string, prefixed with `plain:` or `encrypted:`.
    pub token: String,
}

impl CredentialEntry {
    /// Returns `true` if the token is stored in encrypted form.
    pub fn is_encrypted(&self) -> bool {
        self.token.starts_with("encrypted:")
    }

    /// Returns the raw token value after stripping the `plain:` or `encrypted:` prefix.
    /// Returns `None` if the token has no recognized prefix.
    pub fn raw_token(&self) -> Option<&str> {
        if let Some(rest) = self.token.strip_prefix("plain:") {
            Some(rest)
        } else if let Some(rest) = self.token.strip_prefix("encrypted:") {
            Some(rest)
        } else {
            None
        }
    }
}

/// Returns the default path to the credentials file.
pub fn default_credentials_path() -> PathBuf {
    DefaultPaths::detect().credentials_file
}

/// Loads the credentials file from the given path.
///
/// Returns an empty `CredentialsFile` if the file does not exist.
pub fn load_credentials(path: &Path) -> Result<CredentialsFile, CredentialsError> {
    if !path.exists() {
        return Ok(CredentialsFile::default());
    }

    let content = std::fs::read_to_string(path).map_err(|e| CredentialsError::ReadError {
        path: path.to_path_buf(),
        source: e,
    })?;

    let creds: CredentialsFile =
        toml::from_str(&content).map_err(|e| CredentialsError::ParseError {
            path: path.to_path_buf(),
            source: e,
        })?;

    Ok(creds)
}

/// Saves the credentials file to the given path with `0600` permissions.
///
/// Creates parent directories if they do not exist.
pub fn save_credentials(path: &Path, creds: &CredentialsFile) -> Result<(), CredentialsError> {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| CredentialsError::WriteError {
            path: path.to_path_buf(),
            source: e,
        })?;
    }

    let content = toml::to_string_pretty(creds)?;

    std::fs::write(path, &content).map_err(|e| CredentialsError::WriteError {
        path: path.to_path_buf(),
        source: e,
    })?;

    // Set permissions to 0600 on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms).map_err(|e| CredentialsError::PermissionError {
            path: path.to_path_buf(),
            source: e,
        })?;
    }

    Ok(())
}

/// Checks whether the credentials file has secure permissions (0600).
///
/// Returns `Ok(())` if permissions are correct or on non-Unix platforms.
/// Returns `Err(CredentialsError::InsecurePermissions)` if the file is
/// readable/writable by others.
pub fn check_permissions(path: &Path) -> Result<(), CredentialsError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if !path.exists() {
            return Ok(());
        }

        let metadata = std::fs::metadata(path).map_err(|e| CredentialsError::ReadError {
            path: path.to_path_buf(),
            source: e,
        })?;

        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(CredentialsError::InsecurePermissions {
                path: path.to_path_buf(),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_entry_plain() {
        let entry = CredentialEntry {
            server: "http://localhost:7855".to_string(),
            token: "plain:my-secret-token".to_string(),
        };
        assert!(!entry.is_encrypted());
        assert_eq!(entry.raw_token(), Some("my-secret-token"));
    }

    #[test]
    fn test_credential_entry_encrypted() {
        let entry = CredentialEntry {
            server: "http://localhost:7855".to_string(),
            token: "encrypted:base64data".to_string(),
        };
        assert!(entry.is_encrypted());
        assert_eq!(entry.raw_token(), Some("base64data"));
    }

    #[test]
    fn test_credential_entry_no_prefix() {
        let entry = CredentialEntry {
            server: "http://localhost:7855".to_string(),
            token: "bare-token".to_string(),
        };
        assert!(!entry.is_encrypted());
        assert_eq!(entry.raw_token(), None);
    }

    #[test]
    fn test_load_nonexistent_returns_empty() {
        let path = Path::new("/nonexistent/credentials.toml");
        let creds = load_credentials(path).unwrap();
        assert!(creds.entries.is_empty());
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");

        let mut creds = CredentialsFile::default();
        creds.entries.insert(
            "default".to_string(),
            CredentialEntry {
                server: "http://127.0.0.1:7855".to_string(),
                token: "plain:test-token".to_string(),
            },
        );

        save_credentials(&path, &creds).unwrap();
        assert!(path.exists());

        let loaded = load_credentials(&path).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries["default"].server, "http://127.0.0.1:7855");
        assert_eq!(loaded.entries["default"].token, "plain:test-token");
    }

    #[cfg(unix)]
    #[test]
    fn test_save_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");

        let creds = CredentialsFile::default();
        save_credentials(&path, &creds).unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn test_check_permissions_secure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");

        let creds = CredentialsFile::default();
        save_credentials(&path, &creds).unwrap();

        assert!(check_permissions(&path).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_check_permissions_insecure() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let result = check_permissions(&path);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CredentialsError::InsecurePermissions { .. }
        ));
    }

    #[test]
    fn test_check_permissions_nonexistent_ok() {
        let path = Path::new("/nonexistent/credentials.toml");
        assert!(check_permissions(path).is_ok());
    }
}
