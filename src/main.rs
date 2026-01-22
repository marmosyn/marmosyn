// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! MarmoSyn — unidirectional file synchronization and backup utility.
//!
//! A single binary that serves as a server (sender + receiver), CLI client,
//! HTTP API, and web interface for management.

pub mod api;
pub mod cli;
pub mod config;
pub mod core;
pub mod credentials;
pub mod crypto;
pub mod db;
pub mod server;
pub mod transport;
pub mod web;

use std::path::PathBuf;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::cli::{Cli, Command, ConfigCommand, JobsCommand, OutputFormat, RemotesCommand};

/// Logging output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogFormat {
    /// Human-readable, colored output (default for interactive terminals).
    Pretty,
    /// Machine-readable JSON lines (one JSON object per log event).
    Json,
}

/// Sets up the tracing subscriber for structured logging.
///
/// Respects the `MARMOSYN_LOG` / `RUST_LOG` environment variables if set,
/// otherwise falls back to the given `default_level`.
///
/// # Format selection
///
/// - `LogFormat::Pretty` — compact, human-readable output with timestamps.
/// - `LogFormat::Json` — structured JSON lines, suitable for log aggregation
///   systems (e.g. journald, Loki, Elasticsearch).
///
/// The JSON format includes structured fields automatically:
/// ```json
/// {"timestamp":"...","level":"INFO","target":"marmosyn::server","message":"...","fields":{}}
/// ```
fn setup_tracing(default_level: &str, verbose: bool, format: LogFormat) {
    let level = if verbose { "debug" } else { default_level };

    let filter = EnvFilter::try_from_env("MARMOSYN_LOG")
        .or_else(|_| EnvFilter::try_from_env("RUST_LOG"))
        .unwrap_or_else(|_| EnvFilter::new(level));

    match format {
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .json()
                .with_current_span(true)
                .with_span_list(false)
                .with_target(true)
                .with_thread_ids(false)
                .with_file(false)
                .with_line_number(false)
                .flatten_event(true)
                .init();
        }
        LogFormat::Pretty => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(false)
                .with_thread_ids(false)
                .init();
        }
    }
}

/// Determines the appropriate log format based on command context.
///
/// - Server commands (especially daemon mode) use JSON for structured logging.
/// - CLI commands default to pretty output, unless `--format json` is set.
/// - The `MARMOSYN_LOG_FORMAT` environment variable overrides everything
///   (`json` or `pretty`).
fn detect_log_format(cli: &Cli) -> LogFormat {
    // Environment variable override
    if let Ok(fmt) = std::env::var("MARMOSYN_LOG_FORMAT") {
        match fmt.to_lowercase().as_str() {
            "json" => return LogFormat::Json,
            "pretty" | "text" => return LogFormat::Pretty,
            _ => {} // ignore invalid values, fall through
        }
    }

    // Server in daemon mode should use JSON (stdout goes to /dev/null anyway,
    // but if redirected to a file it should be structured)
    if let Command::Server(ref args) = cli.command
        && args.daemon
    {
        return LogFormat::Json;
    }

    // If CLI output format is JSON, use JSON logging too for consistency
    if cli.format == OutputFormat::Json {
        return LogFormat::Json;
    }

    LogFormat::Pretty
}

fn main() {
    let cli = Cli::parse();

    // Set up tracing early so all commands can use it.
    // For the `version` command we skip tracing setup entirely.
    let is_version = matches!(cli.command, Command::Version);
    if !is_version {
        let log_format = detect_log_format(&cli);
        setup_tracing("info", cli.verbose, log_format);
        tracing::debug!(
            version = env!("CARGO_PKG_VERSION"),
            command = %cli.command.name(),
            "MarmoSyn starting"
        );
    }

    let result = run(cli);

    if let Err(err) = result {
        // Log the error via tracing (for JSON consumers) and also print
        // to stderr (for interactive users).
        tracing::error!(error = %err, "command failed");
        eprintln!("Error: {err:#}");
        std::process::exit(1);
    }
}

/// Helper trait to get the command name for logging.
trait CommandName {
    /// Returns a short name string for the command, used in log messages.
    fn name(&self) -> &'static str;
}

impl CommandName for Command {
    fn name(&self) -> &'static str {
        match self {
            Command::Server(_) => "server",
            Command::Sync(_) => "sync",
            Command::Status(_) => "status",
            Command::Jobs(_) => "jobs",
            Command::Remotes(_) => "remotes",
            Command::Config(_) => "config",
            Command::Login(_) => "login",
            Command::Log(_) => "log",
            Command::Version => "version",
        }
    }
}

/// Dispatches the parsed CLI command to the appropriate handler.
fn run(cli: Cli) -> anyhow::Result<()> {
    let config_path: Option<PathBuf> = cli.config.clone();

    match cli.command {
        // ── Commands that work without a server ────────────────────────
        Command::Version => {
            cli::version::handle_version();
            Ok(())
        }

        Command::Config(config_cmd) => match config_cmd {
            ConfigCommand::Check { path } => {
                let p = path.or(config_path);
                cli::config_cmd::handle_config_check(p.as_deref())
            }
            ConfigCommand::Show { path } => {
                let p = path.or(config_path);
                cli::config_cmd::handle_config_show(p.as_deref())
            }
            ConfigCommand::Init(args) => {
                cli::config_cmd::handle_config_init(args.output.as_deref(), args.force)
            }
        },

        Command::Login(args) => {
            let server = args.server.as_deref().unwrap_or("http://127.0.0.1:7855");
            let token = match args.token.as_deref() {
                Some(t) => t.to_string(),
                None => {
                    // Prompt for token interactively
                    eprint!("Enter API token: ");
                    let mut token = String::new();
                    std::io::stdin().read_line(&mut token)?;
                    token.trim().to_string()
                }
            };

            if token.is_empty() {
                anyhow::bail!("token cannot be empty");
            }

            let profile = args.profile.as_deref().unwrap_or("default");
            let opts = cli::login::LoginOptions {
                server,
                token: &token,
                use_password: args.password,
                profile,
                credentials_path: None,
            };

            let result = cli::login::handle_login(&opts)?;
            cli::login::print_login_result(&result);
            Ok(())
        }

        // ── Commands that require a running server (via API) ───────────
        Command::Server(args) => {
            tracing::info!(daemon = args.daemon, "starting MarmoSyn server");

            let opts = server::daemon::ServerOptions {
                config_path,
                daemon: args.daemon,
            };

            let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            rt.block_on(server::daemon::run_server(opts))
        }

        Command::Sync(args) => {
            tracing::info!(
                job = args.job.as_deref().unwrap_or("(all)"),
                dry_run = args.dry_run,
                "sync requested"
            );

            let opts = cli::sync_cmd::SyncOptions {
                job_name: args.job.as_deref(),
                dry_run: args.dry_run,
                config_path: config_path.as_deref(),
                all: args.all,
            };

            cli::sync_cmd::handle_sync(&opts)
        }

        // ── Commands that talk to a running server via HTTP API ─────────
        Command::Status(_args) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let opts = cli::status::StatusOptions {
                    server: cli.server.as_deref(),
                    token: cli.token.as_deref(),
                    format: cli.format,
                };
                cli::status::handle_status(&opts).await
            })
        }

        Command::Jobs(jobs_cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let opts = cli::jobs::JobsOptions {
                    server: cli.server.as_deref(),
                    token: cli.token.as_deref(),
                    format: cli.format,
                };
                match jobs_cmd {
                    JobsCommand::List => cli::jobs::handle_list(&opts).await,
                    JobsCommand::Info(ref arg) => cli::jobs::handle_info(&arg.name, &opts).await,
                    JobsCommand::Sync(ref arg) => cli::jobs::handle_sync(&arg.name, &opts).await,
                    JobsCommand::Stop(ref arg) => cli::jobs::handle_stop(&arg.name, &opts).await,
                    JobsCommand::History(ref arg) => {
                        cli::jobs::handle_history(&arg.name, Some(arg.limit), &opts).await
                    }
                }
            })
        }

        Command::Remotes(remotes_cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let opts = cli::remotes::RemotesOptions {
                    server: cli.server.as_deref(),
                    token: cli.token.as_deref(),
                    format: cli.format,
                };
                match remotes_cmd {
                    RemotesCommand::List => cli::remotes::handle_list(&opts).await,
                    RemotesCommand::Ping(ref arg) => {
                        cli::remotes::handle_ping(&arg.name, &opts).await
                    }
                }
            })
        }

        Command::Log(args) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let opts = cli::log_cmd::LogOptions {
                    server: cli.server.as_deref(),
                    token: cli.token.as_deref(),
                    format: cli.format,
                    job: args.job.as_deref(),
                    follow: args.follow,
                    lines: args.lines,
                };
                cli::log_cmd::handle_log(&opts).await
            })
        }
    }
}
