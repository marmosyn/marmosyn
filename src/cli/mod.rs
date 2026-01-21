// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! CLI module — command-line interface definition and subcommand handlers.
//!
//! Uses `clap` (derive) for argument parsing. All server management
//! operations go through the HTTP API via `api_client`.

pub mod api_client;
pub mod config_cmd;
pub mod jobs;
pub mod log_cmd;
pub mod login;
pub mod remotes;
pub mod server;
pub mod status;
pub mod sync_cmd;
pub mod version;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// MarmoSyn — unidirectional file synchronization and backup utility.
///
/// A single binary that serves as a server (sender + receiver), CLI client,
/// HTTP API, and web interface for file synchronization management.
#[derive(Debug, Parser)]
#[command(
    name = "marmosyn",
    version,
    about = "Unidirectional file synchronization and backup utility",
    long_about = "MarmoSyn is a cross-platform file synchronization tool. \
                  A single binary serves as server, CLI client, HTTP API, \
                  and web interface for management."
)]
pub struct Cli {
    /// Path to the configuration file.
    ///
    /// If not specified, the configuration file is searched in the following order:
    /// 1. `$MARMOSYN_CONFIG` environment variable
    /// 2. `./marmosyn.toml` (current directory)
    /// 3. Default path based on UID (root: /etc/marmosyn/config.toml, user: ~/.config/marmosyn/config.toml)
    #[arg(long, short = 'c', global = true, env = "MARMOSYN_CONFIG")]
    pub config: Option<PathBuf>,

    /// API server address (e.g. "http://127.0.0.1:7855").
    ///
    /// Overrides the server address from the configuration and credentials file.
    #[arg(long, global = true, env = "MARMOSYN_SERVER")]
    pub server: Option<String>,

    /// API authentication token.
    ///
    /// Overrides the token from the environment variable and credentials file.
    #[arg(long, global = true)]
    pub token: Option<String>,

    /// Output format: "text" (default) or "json".
    #[arg(long, global = true, default_value = "text")]
    pub format: OutputFormat,

    /// Increase log verbosity.
    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,

    /// The subcommand to execute.
    #[command(subcommand)]
    pub command: Command,
}

/// Output format for CLI commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Human-readable text output.
    Text,
    /// JSON output for programmatic consumption.
    Json,
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the MarmoSyn server (daemon mode).
    ///
    /// The server manages sync jobs (sender), accepts incoming files (receiver),
    /// serves the HTTP API, and hosts the web interface.
    Server(ServerArgs),

    /// Trigger manual synchronization of one or all jobs.
    ///
    /// When a server is running, this command operates via the HTTP API.
    /// Otherwise, it can perform a direct local sync using the core engine.
    Sync(SyncArgs),

    /// Display overall server status (sender + receiver).
    Status(StatusArgs),

    /// Manage sync jobs: list, info, sync, stop, history.
    #[command(subcommand)]
    Jobs(JobsCommand),

    /// Manage remote nodes: list, ping.
    #[command(subcommand)]
    Remotes(RemotesCommand),

    /// Configuration management: check, show, init.
    #[command(subcommand)]
    Config(ConfigCommand),

    /// Authenticate CLI with a server and save credentials.
    Login(LoginArgs),

    /// View server logs.
    Log(LogArgs),

    /// Display version and build information.
    Version,
}

// ─── Server ────────────────────────────────────────────────────────────────

/// Arguments for the `server` subcommand.
#[derive(Debug, clap::Args)]
pub struct ServerArgs {
    /// Start in background (detach from terminal).
    #[arg(long)]
    pub daemon: bool,
}

// ─── Sync ──────────────────────────────────────────────────────────────────

/// Arguments for the `sync` subcommand.
#[derive(Debug, clap::Args)]
pub struct SyncArgs {
    /// Name of the sync job to run. If omitted, use --all.
    pub job: Option<String>,

    /// Synchronize all configured jobs.
    #[arg(long)]
    pub all: bool,

    /// Only show what would be done without making changes.
    #[arg(long)]
    pub dry_run: bool,
}

// ─── Status ────────────────────────────────────────────────────────────────

/// Arguments for the `status` subcommand.
#[derive(Debug, clap::Args)]
pub struct StatusArgs {
    /// Output as JSON.
    #[arg(long)]
    pub json: bool,
}

// ─── Jobs ──────────────────────────────────────────────────────────────────

/// Subcommands for `jobs`.
#[derive(Debug, Subcommand)]
pub enum JobsCommand {
    /// List all configured sync jobs.
    List,

    /// Show detailed information about a specific job.
    Info(JobNameArg),

    /// Trigger manual synchronization of a specific job.
    Sync(JobNameArg),

    /// Stop the current synchronization of a specific job.
    Stop(JobNameArg),

    /// Show run history of a specific job.
    History(JobHistoryArgs),
}

/// A required job name argument.
#[derive(Debug, clap::Args)]
pub struct JobNameArg {
    /// Name of the sync job.
    pub name: String,
}

/// Arguments for `jobs history`.
#[derive(Debug, clap::Args)]
pub struct JobHistoryArgs {
    /// Name of the sync job.
    pub name: String,

    /// Maximum number of history entries to show.
    #[arg(long, short = 'n', default_value = "20")]
    pub limit: usize,
}

// ─── Remotes ───────────────────────────────────────────────────────────────

/// Subcommands for `remotes`.
#[derive(Debug, Subcommand)]
pub enum RemotesCommand {
    /// List all configured remote nodes.
    List,

    /// Check availability of a remote node.
    Ping(RemoteNameArg),
}

/// A required remote name argument.
#[derive(Debug, clap::Args)]
pub struct RemoteNameArg {
    /// Name of the remote node.
    pub name: String,
}

// ─── Config ────────────────────────────────────────────────────────────────

/// Subcommands for `config`.
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Validate the configuration file and report errors.
    ///
    /// This command reads the configuration file directly and does not
    /// require a running server.
    Check {
        /// Path to the configuration file to check.
        #[arg(long, short = 'p')]
        path: Option<PathBuf>,
    },

    /// Display the current configuration (with secrets redacted).
    ///
    /// When a server is running, this fetches the config via the API.
    /// Otherwise, it reads the configuration file directly.
    Show {
        /// Path to the configuration file to display.
        #[arg(long, short = 'p')]
        path: Option<PathBuf>,
    },

    /// Generate a configuration file template.
    ///
    /// Creates a new configuration file with example settings.
    /// The template varies depending on whether running as root or user.
    Init(ConfigInitArgs),
}

/// Arguments for `config init`.
#[derive(Debug, clap::Args)]
pub struct ConfigInitArgs {
    /// Output path for the generated template.
    /// If omitted, uses the default path based on UID.
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,

    /// Overwrite an existing configuration file.
    #[arg(long)]
    pub force: bool,
}

// ─── Login ─────────────────────────────────────────────────────────────────

/// Arguments for the `login` subcommand.
#[derive(Debug, clap::Args)]
pub struct LoginArgs {
    /// API server address (e.g. "http://127.0.0.1:7855").
    #[arg(long)]
    pub server: Option<String>,

    /// API authentication token. If omitted, you will be prompted interactively.
    #[arg(long)]
    pub token: Option<String>,

    /// Set a password to encrypt the stored token.
    ///
    /// When enabled, the token is encrypted with a password using
    /// Argon2id + ChaCha20-Poly1305 before being saved to credentials.toml.
    #[arg(long)]
    pub password: bool,

    /// Profile name for the credentials entry.
    #[arg(long)]
    pub profile: Option<String>,
}

// ─── Log ───────────────────────────────────────────────────────────────────

/// Arguments for the `log` subcommand.
#[derive(Debug, clap::Args)]
pub struct LogArgs {
    /// Name of the sync job to view logs for. If omitted, shows server-wide logs.
    pub job: Option<String>,

    /// Follow logs in real-time (like `tail -f`).
    #[arg(long, short = 'f')]
    pub follow: bool,

    /// Number of log lines to display.
    #[arg(long, short = 'n', default_value = "50")]
    pub lines: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    #[test]
    fn test_cli_parses_version() {
        // Verify the CLI structure is valid by building the command
        Cli::command().debug_assert();
    }

    #[test]
    fn test_cli_parse_server() {
        let cli = Cli::try_parse_from(["marmosyn", "server"]).unwrap();
        assert!(matches!(cli.command, Command::Server(_)));
    }

    #[test]
    fn test_cli_parse_server_daemon() {
        let cli = Cli::parse_from(["marmosyn", "server", "--daemon"]);
        match &cli.command {
            Command::Server(args) => assert!(args.daemon),
            _ => panic!("expected Server command"),
        }
    }

    #[test]
    fn test_cli_parse_sync_with_job() {
        let cli = Cli::parse_from(["marmosyn", "sync", "documents"]);
        match &cli.command {
            Command::Sync(args) => {
                assert_eq!(args.job.as_deref(), Some("documents"));
                assert!(!args.all);
                assert!(!args.dry_run);
            }
            _ => panic!("expected Sync command"),
        }
    }

    #[test]
    fn test_cli_parse_sync_all_dry_run() {
        let cli = Cli::parse_from(["marmosyn", "sync", "--all", "--dry-run"]);
        match &cli.command {
            Command::Sync(args) => {
                assert!(args.all);
                assert!(args.dry_run);
                assert!(args.job.is_none());
            }
            _ => panic!("expected Sync command"),
        }
    }

    #[test]
    fn test_cli_parse_status() {
        let cli = Cli::try_parse_from(["marmosyn", "status"]).unwrap();
        assert!(matches!(cli.command, Command::Status(_)));
    }

    #[test]
    fn test_cli_parse_status_json() {
        let cli = Cli::parse_from(["marmosyn", "status", "--json"]);
        match &cli.command {
            Command::Status(args) => assert!(args.json),
            _ => panic!("expected Status command"),
        }
    }

    #[test]
    fn test_cli_parse_jobs_list() {
        let cli = Cli::parse_from(["marmosyn", "jobs", "list"]);
        assert!(matches!(&cli.command, Command::Jobs(JobsCommand::List)));
    }

    #[test]
    fn test_cli_parse_jobs_info() {
        let cli = Cli::parse_from(["marmosyn", "jobs", "info", "docs"]);
        match &cli.command {
            Command::Jobs(JobsCommand::Info(arg)) => assert_eq!(arg.name, "docs"),
            _ => panic!("expected Jobs Info command"),
        }
    }

    #[test]
    fn test_cli_parse_jobs_stop() {
        let cli = Cli::parse_from(["marmosyn", "jobs", "stop", "backup"]);
        match &cli.command {
            Command::Jobs(JobsCommand::Stop(arg)) => assert_eq!(arg.name, "backup"),
            _ => panic!("expected Jobs Stop command"),
        }
    }

    #[test]
    fn test_cli_parse_jobs_sync() {
        let cli = Cli::parse_from(["marmosyn", "jobs", "sync", "photos"]);
        match &cli.command {
            Command::Jobs(JobsCommand::Sync(arg)) => assert_eq!(arg.name, "photos"),
            _ => panic!("expected Jobs Sync command"),
        }
    }

    #[test]
    fn test_cli_parse_jobs_history_default() {
        let cli = Cli::parse_from(["marmosyn", "jobs", "history", "docs"]);
        match &cli.command {
            Command::Jobs(JobsCommand::History(arg)) => {
                assert_eq!(arg.name, "docs");
            }
            _ => panic!("expected Jobs History command"),
        }
    }

    #[test]
    fn test_cli_parse_remotes_list() {
        let cli = Cli::parse_from(["marmosyn", "remotes", "list"]);
        assert!(matches!(
            &cli.command,
            Command::Remotes(RemotesCommand::List)
        ));
    }

    #[test]
    fn test_cli_parse_remotes_ping() {
        let cli = Cli::parse_from(["marmosyn", "remotes", "ping", "office"]);
        match &cli.command {
            Command::Remotes(RemotesCommand::Ping(arg)) => assert_eq!(arg.name, "office"),
            _ => panic!("expected Remotes Ping command"),
        }
    }

    #[test]
    fn test_cli_parse_config_check() {
        let cli = Cli::try_parse_from(["marmosyn", "config", "check"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Config(ConfigCommand::Check { .. })
        ));
    }

    #[test]
    fn test_cli_parse_config_show() {
        let cli = Cli::try_parse_from(["marmosyn", "config", "show"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Config(ConfigCommand::Show { .. })
        ));
    }

    #[test]
    fn test_cli_parse_config_init() {
        let cli = Cli::parse_from(["marmosyn", "config", "init"]);
        match &cli.command {
            Command::Config(ConfigCommand::Init(args)) => {
                assert!(args.output.is_none());
                assert!(!args.force);
            }
            _ => panic!("expected Config Init command"),
        }
    }

    #[test]
    fn test_cli_parse_config_init_with_output() {
        let cli = Cli::parse_from([
            "marmosyn",
            "config",
            "init",
            "--output",
            "/tmp/config.toml",
            "--force",
        ]);
        match &cli.command {
            Command::Config(ConfigCommand::Init(args)) => {
                assert_eq!(
                    args.output.as_deref(),
                    Some(std::path::Path::new("/tmp/config.toml"))
                );
                assert!(args.force);
            }
            _ => panic!("expected Config Init command"),
        }
    }

    #[test]
    fn test_cli_parse_login() {
        let cli = Cli::try_parse_from([
            "marmosyn",
            "login",
            "--server",
            "http://localhost:7855",
            "--token",
            "my-token",
        ])
        .unwrap();
        match cli.command {
            Command::Login(ref args) => {
                assert_eq!(args.server.as_deref(), Some("http://localhost:7855"));
                assert_eq!(args.token.as_deref(), Some("my-token"));
                assert!(!args.password);
                assert!(args.profile.is_none());
            }
            _ => panic!("expected Login command"),
        }
    }

    #[test]
    fn test_cli_parse_login_with_profile() {
        let cli = Cli::try_parse_from([
            "marmosyn",
            "login",
            "--server",
            "http://office:7855",
            "--token",
            "t",
            "--password",
            "--profile",
            "office",
        ])
        .unwrap();
        match cli.command {
            Command::Login(ref args) => {
                assert_eq!(args.server.as_deref(), Some("http://office:7855"));
                assert_eq!(args.token.as_deref(), Some("t"));
                assert!(args.password);
                assert_eq!(args.profile.as_deref(), Some("office"));
            }
            _ => panic!("expected Login command"),
        }
    }

    #[test]
    fn test_cli_parse_log() {
        let cli = Cli::parse_from(["marmosyn", "log"]);
        match &cli.command {
            Command::Log(args) => {
                assert!(args.job.is_none());
                assert!(!args.follow);
                assert_eq!(args.lines, 50);
            }
            _ => panic!("expected Log command"),
        }
    }

    #[test]
    fn test_cli_parse_log_with_options() {
        let cli = Cli::parse_from(["marmosyn", "log", "my-job", "--follow", "--lines", "100"]);
        match &cli.command {
            Command::Log(args) => {
                assert_eq!(args.job.as_deref(), Some("my-job"));
                assert!(args.follow);
                assert_eq!(args.lines, 100);
            }
            _ => panic!("expected Log command"),
        }
    }

    #[test]
    fn test_cli_parse_version() {
        let cli = Cli::try_parse_from(["marmosyn", "version"]).unwrap();
        assert!(matches!(cli.command, Command::Version));
    }

    #[test]
    fn test_cli_global_config_flag() {
        let cli = Cli::try_parse_from(["marmosyn", "-c", "/custom/config.toml", "status"]).unwrap();
        assert_eq!(
            cli.config.as_deref(),
            Some(std::path::Path::new("/custom/config.toml"))
        );
    }

    #[test]
    fn test_cli_global_server_and_token() {
        let cli = Cli::try_parse_from([
            "marmosyn",
            "--server",
            "http://remote:7855",
            "--token",
            "secret",
            "status",
        ])
        .unwrap();
        assert_eq!(cli.server.as_deref(), Some("http://remote:7855"));
        assert_eq!(cli.token.as_deref(), Some("secret"));
    }

    #[test]
    fn test_cli_verbose_flag() {
        let cli = Cli::try_parse_from(["marmosyn", "-v", "status"]).unwrap();
        assert!(cli.verbose);
    }

    #[test]
    fn test_cli_format_json() {
        let cli = Cli::try_parse_from(["marmosyn", "--format", "json", "status"]).unwrap();
        assert_eq!(cli.format, OutputFormat::Json);
    }

    #[test]
    fn test_cli_no_args_fails() {
        let result = Cli::try_parse_from(["marmosyn"]);
        assert!(result.is_err());
    }
}
