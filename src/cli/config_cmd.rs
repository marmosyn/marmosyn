//! Handler for `config` subcommands: check, show, init.
//!
//! These commands work directly with the configuration file
//! and do not require a running server.

use std::path::Path;

use anyhow::{Context, Result};

use crate::config::loader::{discover_config_path, load_config_from_path};
use crate::config::paths::DefaultPaths;
use crate::config::validation::validate_config;

/// Handles `marmosyn config check [--config <path>]`.
///
/// Discovers the configuration file, parses it, and runs validation.
/// Prints the result to stdout.
pub fn handle_config_check(explicit_path: Option<&Path>) -> Result<()> {
    let config_path = match discover_config_path(explicit_path) {
        Ok(p) => p,
        Err(err) => {
            println!("✗ Configuration error: {err}");
            anyhow::bail!("{err}");
        }
    };

    println!("Found config: {}", config_path.display());

    let config = match load_config_from_path(&config_path) {
        Ok(c) => c,
        Err(err) => {
            println!("✗ Failed to parse config: {err}");
            anyhow::bail!("{err}");
        }
    };

    match validate_config(&config) {
        Ok(()) => {
            println!("✓ Configuration is valid.");
            println!(
                "  {} sync job(s), {} remote(s)",
                config.sync.len(),
                config.remote.len(),
            );
            if config.receiver.is_some() {
                println!("  Receiver: enabled");
            } else {
                println!("  Receiver: not configured");
            }
            Ok(())
        }
        Err(err) => {
            println!("✗ Validation error: {err}");
            anyhow::bail!("{err}");
        }
    }
}

/// Handles `marmosyn config show [--config <path>]`.
///
/// Discovers and loads the configuration file, then prints a human-readable
/// summary of its contents to stdout.
pub fn handle_config_show(explicit_path: Option<&Path>) -> Result<()> {
    let config_path =
        discover_config_path(explicit_path).context("could not find configuration file")?;

    let config =
        load_config_from_path(&config_path).context("could not load configuration file")?;

    println!("Configuration: {}", config_path.display());
    println!();

    // Server section
    println!("[server]");
    println!("  listen      = {}", config.server.listen);
    println!("  api_listen  = {}", config.server.api_listen);
    println!("  log_level   = {}", config.server.log_level);
    if let Some(ref dd) = config.server.data_dir {
        println!("  data_dir    = {}", dd.display());
    }
    if let Some(ref sd) = config.server.safety_dir {
        println!("  safety_dir  = {}", sd.display());
    }
    if config.server.auth_token.is_some() {
        println!("  auth_token  = ***");
    }
    println!();

    // Receiver section
    if let Some(ref recv) = config.receiver {
        println!("[receiver]");
        println!("  enabled     = {}", recv.enabled);
        println!("  auth_token  = ***");
        for ap in &recv.allowed_paths {
            let alias_str = ap
                .alias
                .as_deref()
                .map(|a| format!(" (alias: {a})"))
                .unwrap_or_default();
            println!("  allowed     = {}{}", ap.path.display(), alias_str);
        }
        println!();
    }

    // Encryption section
    if let Some(ref enc) = config.encryption {
        println!("[encryption]");
        println!("  algorithm   = {}", enc.algorithm);
        println!("  key_source  = {}", redact_key_source(&enc.key_source));
        println!();
    }

    // Remote nodes
    for remote in &config.remote {
        println!("[[remote]]");
        println!("  name        = {}", remote.name);
        println!("  host        = {}", remote.host);
        println!("  auth_token  = ***");
        if let Some(ref ca) = remote.tls_ca {
            println!("  tls_ca      = {}", ca.display());
        }
        if remote.allow_self_signed {
            println!("  allow_self_signed = true");
        }
        println!();
    }

    // Sync jobs
    for job in &config.sync {
        println!("[[sync]]");
        println!("  name        = {}", job.name);
        println!("  source      = {}", job.source.display());
        println!("  mode        = {}", job.mode);
        if !job.exclude.is_empty() {
            println!("  exclude     = {:?}", job.exclude);
        }
        if job.encrypt {
            println!("  encrypt     = true");
        }
        if let Some(ref sched) = job.schedule {
            println!("  schedule    = {sched}");
        }
        if let Some(ref dest) = job.dest {
            println!("  dest        = {dest}");
        }
        if let Some(ref dests) = job.dests {
            println!("  dests       = {:?}", dests);
        }
        if job.safety.enabled {
            println!("  [safety]");
            println!("    enabled   = true");
            if let Some(ref ret) = job.safety.retention {
                println!("    retention = {ret}");
            }
            if let Some(ref ms) = job.safety.max_size {
                println!("    max_size  = {ms}");
            }
        }
        println!();
    }

    Ok(())
}

/// Handles `marmosyn config init [--output <path>] [--force]`.
///
/// Generates a template configuration file at the specified path (or the
/// default path for the current UID). Refuses to overwrite an existing
/// file unless `--force` is set.
pub fn handle_config_init(output: Option<&Path>, force: bool) -> Result<()> {
    let target_path = match output {
        Some(p) => p.to_path_buf(),
        None => DefaultPaths::detect().config_file,
    };

    if target_path.exists() && !force {
        anyhow::bail!(
            "configuration file already exists at '{}'. \
             Use --force to overwrite.",
            target_path.display()
        );
    }

    // Ensure parent directory exists
    if let Some(parent) = target_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory '{}'", parent.display()))?;
    }

    std::fs::write(&target_path, config_template()).with_context(|| {
        format!(
            "failed to write config template to '{}'",
            target_path.display()
        )
    })?;

    println!(
        "✓ Configuration template written to: {}",
        target_path.display()
    );
    println!("  Edit the file and run `marmosyn config check` to validate.");

    Ok(())
}

/// Returns the default configuration template as a TOML string.
fn config_template() -> &'static str {
    r#"# MarmoSyn configuration file
# See documentation at https://github.com/marmosyn/marmosyn

[server]
# Transport protocol listen address
listen = "0.0.0.0:7854"
# HTTP API / Web UI listen address
api_listen = "127.0.0.1:7855"
# Log level: trace | debug | info | warn | error
log_level = "info"
# Internal data directory (auto-detected if omitted)
# data_dir = "/var/lib/marmosyn"
# Safety backup directory (auto: <data_dir>/safety/)
# safety_dir = "/var/lib/marmosyn/safety"
# Token for HTTP API authorization (leave empty to disable auth)
# auth_token = "your-secret-token"

# ─── Receiver (optional) ────────────────────────────────────────────────
# Uncomment to enable receiving files from remote senders.

# [receiver]
# enabled = true
# auth_token = "receiver-secret-token"
#
# [[receiver.allowed_paths]]
# path = "/mnt/backup"
# alias = "backup"

# ─── Encryption (optional) ──────────────────────────────────────────────
# Required if any sync job has encrypt = true.

# [encryption]
# algorithm = "chacha20-poly1305"
# key_source = "env:MARMOSYN_KEY"

# ─── Remote nodes ───────────────────────────────────────────────────────
# Define remote receiver servers referenced in sync job destinations.

# [[remote]]
# name = "office-server"
# host = "192.168.1.100:7854"
# auth_token = "remote-token"
# allow_self_signed = false

# ─── Sync jobs ──────────────────────────────────────────────────────────

[[sync]]
name = "example"
source = "/path/to/source"
mode = "manual"          # manual | watch | schedule
# schedule = "0 3 * * *"  # cron expression (required if mode = "schedule")
# exclude = ["*.tmp", ".cache/", "node_modules/"]
# encrypt = false
dest = "/path/to/destination"
# dests = ["/backup1", "remote:alias/subpath"]

# [sync.safety]
# enabled = true
# retention = "30d"
# max_size = "10GB"
"#
}

/// Redacts the key source for display, hiding raw keys but showing the type.
fn redact_key_source(source: &str) -> String {
    if source.starts_with("raw:") {
        "raw:***".to_string()
    } else {
        source.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_template_is_valid_toml_structure() {
        // The template should be parseable as TOML (even if values are
        // placeholders). It should at least have a [server] section and
        // a [[sync]] array.
        let template = config_template();
        assert!(template.contains("[server]"));
        assert!(template.contains("[[sync]]"));
        assert!(template.contains("listen"));
        assert!(template.contains("api_listen"));
    }

    #[test]
    fn test_config_template_parses_as_toml() {
        let template = config_template();
        let result: Result<toml::Value, _> = toml::from_str(template);
        assert!(
            result.is_ok(),
            "config template should be valid TOML: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_redact_key_source_raw() {
        assert_eq!(redact_key_source("raw:abc123"), "raw:***");
    }

    #[test]
    fn test_redact_key_source_env() {
        assert_eq!(redact_key_source("env:MARMOSYN_KEY"), "env:MARMOSYN_KEY");
    }

    #[test]
    fn test_redact_key_source_file() {
        assert_eq!(redact_key_source("file:/path/to/key"), "file:/path/to/key");
    }

    #[test]
    fn test_config_init_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "existing content").unwrap();

        let result = handle_config_init(Some(&path), false);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("already exists"));
    }

    #[test]
    fn test_config_init_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subdir/config.toml");

        let result = handle_config_init(Some(&path), false);
        assert!(result.is_ok());
        assert!(path.exists());

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("[server]"));
    }

    #[test]
    fn test_config_init_force_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "old content").unwrap();

        let result = handle_config_init(Some(&path), true);
        assert!(result.is_ok());

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("[server]"));
        assert!(!content.contains("old content"));
    }

    #[test]
    fn test_config_check_nonexistent_file() {
        let result = handle_config_check(Some(Path::new("/nonexistent/path/config.toml")));
        assert!(result.is_err());
    }

    #[test]
    fn test_config_check_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
[server]
listen = "0.0.0.0:7854"

[[sync]]
name = "test"
source = "/tmp/src"
mode = "manual"
dest = "/tmp/dest"
"#,
        )
        .unwrap();

        let result = handle_config_check(Some(&path));
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_check_invalid_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "this is not [[[valid toml").unwrap();

        let result = handle_config_check(Some(&path));
        assert!(result.is_err());
    }

    #[test]
    fn test_config_show_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
[server]
listen = "0.0.0.0:7854"
api_listen = "127.0.0.1:7855"

[[sync]]
name = "docs"
source = "/home/user/docs"
mode = "manual"
dest = "/backup/docs"
"#,
        )
        .unwrap();

        let result = handle_config_show(Some(&path));
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_show_nonexistent() {
        let result = handle_config_show(Some(Path::new("/nonexistent/config.toml")));
        assert!(result.is_err());
    }
}
