// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Handler for the `login` subcommand.
//!
//! Prompts the user for a server URL, token, and optionally a password
//! for token encryption, then saves the credentials to `credentials.toml`.

use std::path::Path;

use anyhow::{Context, Result};
use tracing::info;

use crate::credentials::encrypt::encrypt_token;
use crate::credentials::store::{
    CredentialEntry, CredentialsFile, default_credentials_path, load_credentials, save_credentials,
};

/// Options for the login operation, typically derived from CLI arguments.
pub struct LoginOptions<'a> {
    /// Server URL (e.g. `"http://127.0.0.1:7855"`).
    pub server: &'a str,
    /// API token to store.
    pub token: &'a str,
    /// Whether to encrypt the token with a password.
    pub use_password: bool,
    /// Profile name for the credentials entry (default: `"default"`).
    pub profile: &'a str,
    /// Optional explicit path to the credentials file.
    pub credentials_path: Option<&'a Path>,
}

/// Result of a successful login operation.
pub struct LoginResult {
    /// Path to the credentials file that was written.
    pub credentials_path: std::path::PathBuf,
    /// Whether the token was stored encrypted.
    pub encrypted: bool,
    /// The profile name under which the token was saved.
    pub profile: String,
}

/// Handles the `marmosyn login` subcommand.
///
/// Saves the provided token to the credentials file. If `use_password` is
/// true, prompts for a password and encrypts the token before saving.
///
/// # Flow
///
/// 1. Load existing credentials file (or create a new one).
/// 2. If `--password` is set, prompt for a password and encrypt the token.
/// 3. Save the credential entry under the specified profile.
/// 4. Write the credentials file with `0600` permissions.
pub fn handle_login(opts: &LoginOptions<'_>) -> Result<LoginResult> {
    let cred_path = match opts.credentials_path {
        Some(p) => p.to_path_buf(),
        None => default_credentials_path(),
    };

    // Load existing credentials (or start fresh)
    let mut creds = if cred_path.exists() {
        load_credentials(&cred_path).context("failed to load existing credentials file")?
    } else {
        CredentialsFile::default()
    };

    // Prepare the token value
    let token_value = if opts.use_password {
        let password = prompt_password_twice()?;
        let encrypted_b64 =
            encrypt_token(opts.token, &password).context("failed to encrypt token")?;
        format!("encrypted:{encrypted_b64}")
    } else {
        format!("plain:{}", opts.token)
    };

    // Insert or update the entry
    let entry = CredentialEntry {
        server: opts.server.to_string(),
        token: token_value,
    };

    creds.entries.insert(opts.profile.to_string(), entry);

    // Save the credentials file
    save_credentials(&cred_path, &creds).context("failed to save credentials file")?;

    info!(
        profile = opts.profile,
        path = %cred_path.display(),
        encrypted = opts.use_password,
        "credentials saved"
    );

    Ok(LoginResult {
        credentials_path: cred_path,
        encrypted: opts.use_password,
        profile: opts.profile.to_string(),
    })
}

/// Prints the login result to stdout for the user.
pub fn print_login_result(result: &LoginResult) {
    println!("✓ Token saved to: {}", result.credentials_path.display());
    println!("  Profile: {}", result.profile);
    if result.encrypted {
        println!("  Token is encrypted with your password.");
        println!("  You will need to enter the password when using CLI commands.");
    } else {
        println!("  Token is stored in plaintext.");
        println!("  Consider using --password for encrypted storage.");
    }
}

/// Prompts the user for a password twice and verifies they match.
///
/// Uses `rpassword` for secure terminal input. Falls back to
/// `$MARMOSYN_PASSWORD` environment variable if available (useful for
/// non-interactive contexts like CI).
fn prompt_password_twice() -> Result<String> {
    // Check environment variable first (for non-interactive use)
    if let Ok(pw) = std::env::var("MARMOSYN_PASSWORD")
        && !pw.is_empty()
    {
        return Ok(pw);
    }

    let password = rpassword::prompt_password("Enter password to encrypt token: ")
        .context("failed to read password from terminal")?;

    if password.is_empty() {
        anyhow::bail!("password cannot be empty");
    }

    let confirm = rpassword::prompt_password("Confirm password: ")
        .context("failed to read password confirmation from terminal")?;

    if password != confirm {
        anyhow::bail!("passwords do not match");
    }

    Ok(password)
}

/// Saves a plaintext token without any interactive prompts.
///
/// This is a convenience function for programmatic use (e.g. testing,
/// scripted setup). For interactive use, prefer [`handle_login`].
pub fn save_token_plain(
    server: &str,
    token: &str,
    profile: &str,
    credentials_path: Option<&Path>,
) -> Result<LoginResult> {
    let opts = LoginOptions {
        server,
        token,
        use_password: false,
        profile,
        credentials_path,
    };
    handle_login(&opts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::encrypt::decrypt_token;
    use crate::credentials::store::load_credentials;

    #[test]
    fn test_save_plain_token() {
        let dir = tempfile::tempdir().unwrap();
        let cred_path = dir.path().join("credentials.toml");

        let result = save_token_plain(
            "http://localhost:7855",
            "my-token",
            "default",
            Some(&cred_path),
        )
        .unwrap();

        assert_eq!(result.profile, "default");
        assert!(!result.encrypted);
        assert!(cred_path.exists());

        let creds = load_credentials(&cred_path).unwrap();
        assert_eq!(creds.entries.len(), 1);
        let entry = &creds.entries["default"];
        assert_eq!(entry.server, "http://localhost:7855");
        assert_eq!(entry.token, "plain:my-token");
    }

    #[test]
    fn test_save_encrypted_token_via_env() {
        let dir = tempfile::tempdir().unwrap();
        let cred_path = dir.path().join("credentials.toml");

        // Set the password via environment variable for non-interactive test
        // SAFETY: single-threaded test
        unsafe { std::env::set_var("MARMOSYN_PASSWORD", "test-password-123") };

        let opts = LoginOptions {
            server: "http://localhost:7855",
            token: "secret-token",
            use_password: true,
            profile: "test",
            credentials_path: Some(&cred_path),
        };
        let result = handle_login(&opts).unwrap();

        // Clean up env
        // SAFETY: single-threaded test
        unsafe { std::env::remove_var("MARMOSYN_PASSWORD") };

        assert!(result.encrypted);
        assert_eq!(result.profile, "test");

        let creds = load_credentials(&cred_path).unwrap();
        let entry = &creds.entries["test"];
        assert_eq!(entry.server, "http://localhost:7855");
        assert!(entry.token.starts_with("encrypted:"));

        // Verify we can decrypt the token
        let encrypted_b64 = entry.token.strip_prefix("encrypted:").unwrap();
        let decrypted = decrypt_token(encrypted_b64, "test-password-123").unwrap();
        assert_eq!(decrypted, "secret-token");
    }

    #[test]
    fn test_save_multiple_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let cred_path = dir.path().join("credentials.toml");

        save_token_plain(
            "http://localhost:7855",
            "token-a",
            "default",
            Some(&cred_path),
        )
        .unwrap();
        save_token_plain("http://office:7855", "token-b", "office", Some(&cred_path)).unwrap();

        let creds = load_credentials(&cred_path).unwrap();
        assert_eq!(creds.entries.len(), 2);
        assert_eq!(creds.entries["default"].server, "http://localhost:7855");
        assert_eq!(creds.entries["office"].server, "http://office:7855");
    }

    #[test]
    fn test_overwrite_existing_profile() {
        let dir = tempfile::tempdir().unwrap();
        let cred_path = dir.path().join("credentials.toml");

        save_token_plain(
            "http://localhost:7855",
            "old-token",
            "default",
            Some(&cred_path),
        )
        .unwrap();
        save_token_plain(
            "http://localhost:7855",
            "new-token",
            "default",
            Some(&cred_path),
        )
        .unwrap();

        let creds = load_credentials(&cred_path).unwrap();
        assert_eq!(creds.entries.len(), 1);
        assert_eq!(creds.entries["default"].token, "plain:new-token");
    }

    #[test]
    fn test_creates_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let cred_path = dir.path().join("sub/dir/credentials.toml");

        save_token_plain(
            "http://localhost:7855",
            "token",
            "default",
            Some(&cred_path),
        )
        .unwrap();

        assert!(cred_path.exists());
    }

    #[test]
    fn test_print_login_result_plain() {
        let result = LoginResult {
            credentials_path: std::path::PathBuf::from("/tmp/creds.toml"),
            encrypted: false,
            profile: "default".to_string(),
        };
        // Should not panic
        print_login_result(&result);
    }

    #[test]
    fn test_print_login_result_encrypted() {
        let result = LoginResult {
            credentials_path: std::path::PathBuf::from("/tmp/creds.toml"),
            encrypted: true,
            profile: "office".to_string(),
        };
        // Should not panic
        print_login_result(&result);
    }
}
