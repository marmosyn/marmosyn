// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Token resolution priority logic.
//!
//! Resolves the API token to use for CLI → Server communication by checking
//! the following sources in order:
//!
//! 1. `--token <token>` command-line flag
//! 2. `$MARMOSYN_API_TOKEN` environment variable
//! 3. `~/.config/marmosyn/credentials.toml` (with optional password decryption)
//!
//! If the token stored in the credentials file is encrypted (prefixed with
//! `encrypted:`), the user is prompted for a password via `rpassword`, or the
//! password is read from `$MARMOSYN_PASSWORD`.

use std::path::Path;

use crate::credentials::encrypt;
use crate::credentials::store;

/// Errors that can occur during token resolution.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// No token could be found from any source.
    #[error(
        "no API token found: provide --token, set $MARMOSYN_API_TOKEN, or run `marmosyn login`"
    )]
    NoTokenFound,

    /// The credentials file could not be read or parsed.
    #[error("failed to load credentials: {0}")]
    CredentialsError(#[from] store::StoreError),

    /// The encrypted token could not be decrypted.
    #[error("failed to decrypt token: {0}")]
    DecryptError(#[from] encrypt::EncryptError),

    /// A password is required but could not be obtained.
    #[error(
        "password required to decrypt token but none provided: set $MARMOSYN_PASSWORD or enter interactively"
    )]
    PasswordRequired,
}

/// Options that influence token resolution, typically derived from CLI arguments.
pub struct ResolveOptions<'a> {
    /// Explicit token from `--token` flag.
    pub token_flag: Option<&'a str>,
    /// Explicit server name/profile to look up in credentials.toml.
    pub profile: Option<&'a str>,
    /// Path to the credentials file (overrides default).
    pub credentials_path: Option<&'a Path>,
    /// Server URL to match against credentials entries.
    pub server_url: Option<&'a str>,
}

/// Resolved token ready for use in API requests.
pub struct ResolvedToken {
    /// The plaintext token value.
    pub token: String,
    /// Where the token was resolved from, for diagnostics.
    pub source: TokenSource,
}

/// Describes where a resolved token came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenSource {
    /// From the `--token` CLI flag.
    CliFlag,
    /// From the `$MARMOSYN_API_TOKEN` environment variable.
    EnvVar,
    /// From the credentials file (plaintext).
    CredentialsFilePlain,
    /// From the credentials file (decrypted).
    CredentialsFileEncrypted,
}

/// Resolves the API token using the priority chain.
///
/// The resolution order is:
/// 1. `--token` flag (from `opts.token_flag`)
/// 2. `$MARMOSYN_API_TOKEN` environment variable
/// 3. Credentials file lookup by profile or server URL
///
/// # Errors
///
/// Returns [`ResolveError::NoTokenFound`] if no token source yields a value.
/// Returns [`ResolveError::DecryptError`] if an encrypted token cannot be decrypted.
pub fn resolve_token(opts: &ResolveOptions<'_>) -> Result<ResolvedToken, ResolveError> {
    // 1. Explicit CLI flag
    if let Some(token) = opts.token_flag {
        return Ok(ResolvedToken {
            token: token.to_string(),
            source: TokenSource::CliFlag,
        });
    }

    // 2. Environment variable
    if let Ok(token) = std::env::var("MARMOSYN_API_TOKEN")
        && !token.is_empty()
    {
        return Ok(ResolvedToken {
            token,
            source: TokenSource::EnvVar,
        });
    }

    // 3. Credentials file
    resolve_from_credentials(opts)
}

/// Attempts to load and resolve a token from the credentials file.
fn resolve_from_credentials(opts: &ResolveOptions<'_>) -> Result<ResolvedToken, ResolveError> {
    let cred_path = match opts.credentials_path {
        Some(p) => p.to_path_buf(),
        None => {
            let defaults = crate::config::paths::DefaultPaths::detect();
            defaults.credentials_file
        }
    };

    if !cred_path.exists() {
        return Err(ResolveError::NoTokenFound);
    }

    let creds = store::load_credentials(&cred_path)?;

    // Try to find a matching entry by profile name or server URL
    let profile_name = opts.profile.unwrap_or("default");
    let entry = creds.entries.get(profile_name).or_else(|| {
        // Fall back to matching by server URL if a profile wasn't found
        opts.server_url
            .and_then(|url| creds.entries.values().find(|e| e.server == url))
    });

    let entry = match entry {
        Some(e) => e,
        None => return Err(ResolveError::NoTokenFound),
    };

    decode_token_value(&entry.token)
}

/// Decodes a token value string, handling the `plain:` and `encrypted:` prefixes.
fn decode_token_value(raw: &str) -> Result<ResolvedToken, ResolveError> {
    if let Some(plain) = raw.strip_prefix("plain:") {
        return Ok(ResolvedToken {
            token: plain.to_string(),
            source: TokenSource::CredentialsFilePlain,
        });
    }

    if let Some(encrypted_b64) = raw.strip_prefix("encrypted:") {
        let password = obtain_password()?;
        let token = encrypt::decrypt_token(encrypted_b64, &password)?;
        return Ok(ResolvedToken {
            token,
            source: TokenSource::CredentialsFileEncrypted,
        });
    }

    // No prefix — treat as plain token for backward compatibility
    Ok(ResolvedToken {
        token: raw.to_string(),
        source: TokenSource::CredentialsFilePlain,
    })
}

/// Obtains the decryption password from `$MARMOSYN_PASSWORD` or interactive prompt.
fn obtain_password() -> Result<String, ResolveError> {
    // Try environment variable first
    if let Ok(pw) = std::env::var("MARMOSYN_PASSWORD")
        && !pw.is_empty()
    {
        return Ok(pw);
    }

    // Try interactive prompt (only works with a TTY)
    match rpassword::prompt_password("Enter password to decrypt token: ") {
        Ok(pw) if !pw.is_empty() => Ok(pw),
        _ => Err(ResolveError::PasswordRequired),
    }
}
