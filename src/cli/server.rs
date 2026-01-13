//! Handler for the `server` subcommand — starts the MarmoSyn server process.
//!
//! This module bridges the CLI layer to the server daemon. It converts CLI
//! arguments into `ServerOptions` and delegates to `daemon::run_server`.
//!
//! When the `--daemon` flag is set, the process is daemonized (double-fork on
//! Unix) before the tokio runtime is created, ensuring clean detachment from
//! the controlling terminal.

use std::path::PathBuf;

use anyhow::Result;

use crate::server::daemon::{self, ServerOptions};

/// Starts the MarmoSyn server with the given CLI arguments.
///
/// If `daemon_mode` is `true`, the process is daemonized before the async
/// runtime is started. On Unix this performs a double-fork; on other platforms
/// it is a no-op with a warning.
///
/// # Arguments
///
/// * `config_path` — optional path to the configuration file (from `--config` flag).
/// * `daemon_mode` — whether to run in background/daemon mode.
///
/// # Errors
///
/// Returns an error if daemonization fails or the server encounters a fatal
/// error during execution.
pub fn handle_server(config_path: Option<PathBuf>, daemon_mode: bool) -> Result<()> {
    // Daemonize before creating the tokio runtime.
    // fork() is not safe to call after threads have been spawned, so this
    // must happen first.
    if daemon_mode {
        eprintln!("MarmoSyn: starting in daemon mode...");
        daemon::daemonize()?;
        // After daemonize(), stdin/stdout/stderr are redirected to /dev/null
        // on Unix. All further output goes through the tracing/logging system.
    }

    let opts = ServerOptions {
        config_path,
        daemon: daemon_mode,
    };

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(daemon::run_server(opts))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_options_construction() {
        let opts = ServerOptions {
            config_path: Some(PathBuf::from("/etc/marmosyn/config.toml")),
            daemon: true,
        };

        assert_eq!(
            opts.config_path,
            Some(PathBuf::from("/etc/marmosyn/config.toml"))
        );
        assert!(opts.daemon);
    }

    #[test]
    fn test_server_options_no_config() {
        let opts = ServerOptions {
            config_path: None,
            daemon: false,
        };

        assert!(opts.config_path.is_none());
        assert!(!opts.daemon);
    }

    #[test]
    fn test_server_options_daemon_only() {
        let opts = ServerOptions {
            config_path: None,
            daemon: true,
        };

        assert!(opts.config_path.is_none());
        assert!(opts.daemon);
    }
}
