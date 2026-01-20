// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Handler for the `marmosyn log` subcommand — view server logs.
//!
//! Implements `marmosyn log [JOB] [--follow] [--lines N]` which retrieves
//! logs from the server via the HTTP API endpoint `GET /api/v1/jobs/{name}/log`.
//!
//! In `--follow` mode, the command polls the server periodically and prints
//! new log lines as they appear.

use std::collections::HashSet;
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::debug;

use crate::cli::api_client::{ApiClient, ApiError};
use crate::cli::OutputFormat;

/// Default polling interval for `--follow` mode (in seconds).
const FOLLOW_POLL_INTERVAL_SECS: u64 = 3;

/// Options for the log command.
pub struct LogOptions<'a> {
    /// Server URL (from --server flag or default).
    pub server: Option<&'a str>,
    /// API token (from --token flag, env, or credentials).
    pub token: Option<&'a str>,
    /// Output format (text or json).
    pub format: OutputFormat,
    /// Optional job name to filter logs for.
    pub job: Option<&'a str>,
    /// Whether to follow (stream) new log entries.
    pub follow: bool,
    /// Number of recent log lines to display.
    pub lines: usize,
}

/// Handles the `marmosyn log` subcommand.
///
/// Connects to the server API and retrieves log lines for the specified job
/// (or lists available jobs if none specified). In `--follow` mode, the command
/// polls the server and prints new lines as they appear.
///
/// # Errors
///
/// Returns an error if the server is unreachable or the request fails.
pub async fn handle_log(opts: &LogOptions<'_>) -> Result<()> {
    // If no job name is specified, list available jobs and exit
    let job_name = match opts.job {
        Some(name) => name,
        None => {
            return handle_log_no_job(opts).await;
        }
    };

    // Build API client
    let client = match build_client(opts) {
        Ok(c) => c,
        Err(err) => {
            return handle_client_error(opts, err);
        }
    };

    if opts.follow {
        handle_log_follow(&client, job_name, opts).await
    } else {
        handle_log_once(&client, job_name, opts).await
    }
}

/// Fetches and displays log lines once (no follow).
async fn handle_log_once(client: &ApiClient, job_name: &str, opts: &LogOptions<'_>) -> Result<()> {
    let limit = opts.lines as u32;

    match client.get_job_log(job_name, Some(limit)).await {
        Ok(response) => match opts.format {
            OutputFormat::Json => {
                let json = serde_json::json!({
                    "job_name": response.job_name,
                    "lines": response.lines,
                    "total": response.total,
                });
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
            OutputFormat::Text => {
                if response.lines.is_empty() {
                    eprintln!("No log entries for job '{}'.", job_name);
                } else {
                    for line in &response.lines {
                        println!("{}", line);
                    }
                    if response.total > response.lines.len() {
                        eprintln!(
                            "\n({} of {} entries shown; use --lines to see more)",
                            response.lines.len(),
                            response.total
                        );
                    }
                }
            }
        },
        Err(err) => {
            return handle_api_error(job_name, err);
        }
    }

    Ok(())
}

/// Follows log output by polling the server periodically.
///
/// Keeps track of already-printed lines and only prints new ones.
/// Runs until interrupted (Ctrl+C) or until a server error occurs.
async fn handle_log_follow(
    client: &ApiClient,
    job_name: &str,
    opts: &LogOptions<'_>,
) -> Result<()> {
    let limit = opts.lines as u32;
    let poll_interval = Duration::from_secs(FOLLOW_POLL_INTERVAL_SECS);

    // Track lines we've already printed to avoid duplicates.
    // We use a set of line content strings for deduplication.
    let mut seen_lines: HashSet<String> = HashSet::new();
    let mut first_fetch = true;

    eprintln!(
        "Following logs for job '{}' (poll interval: {}s, Ctrl+C to stop)...",
        job_name, FOLLOW_POLL_INTERVAL_SECS
    );
    eprintln!();

    loop {
        match client.get_job_log(job_name, Some(limit)).await {
            Ok(response) => match opts.format {
                OutputFormat::Json => {
                    // In JSON follow mode, print each new batch as a JSON object
                    let new_lines: Vec<&String> = response
                        .lines
                        .iter()
                        .filter(|line| !seen_lines.contains(line.as_str()))
                        .collect();

                    if !new_lines.is_empty() {
                        let json = serde_json::json!({
                            "job_name": response.job_name,
                            "lines": new_lines,
                            "total": response.total,
                        });
                        println!("{}", serde_json::to_string(&json)?);
                    }

                    for line in &response.lines {
                        seen_lines.insert(line.clone());
                    }
                }
                OutputFormat::Text => {
                    if first_fetch {
                        // On first fetch, print all lines
                        for line in &response.lines {
                            println!("{}", line);
                            seen_lines.insert(line.clone());
                        }
                        first_fetch = false;
                    } else {
                        // On subsequent fetches, only print new lines
                        for line in &response.lines {
                            if seen_lines.insert(line.clone()) {
                                println!("{}", line);
                            }
                        }
                    }
                }
            },
            Err(err) => {
                debug!(error = %err, "follow poll error");
                eprintln!("Warning: failed to fetch logs: {}", err);
                // Continue polling despite transient errors
            }
        }

        // Wait for the poll interval, or exit on shutdown signal
        tokio::select! {
            _ = tokio::time::sleep(poll_interval) => {
                // Continue polling
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\nStopped following logs.");
                break;
            }
        }
    }

    Ok(())
}

/// Handles the case where no job name is specified — lists available jobs.
async fn handle_log_no_job(opts: &LogOptions<'_>) -> Result<()> {
    let client = match build_client(opts) {
        Ok(c) => c,
        Err(_) => {
            // If we can't connect, show help text
            match opts.format {
                OutputFormat::Json => {
                    let json = serde_json::json!({
                        "error": "no_job_specified",
                        "message": "specify a job name: marmosyn log <JOB>",
                    });
                    println!("{}", serde_json::to_string_pretty(&json)?);
                }
                OutputFormat::Text => {
                    eprintln!("Usage: marmosyn log <JOB_NAME> [--follow] [--lines N]");
                    eprintln!();
                    eprintln!("Could not connect to server to list available jobs.");
                    eprintln!("Ensure the server is running: marmosyn server");
                }
            }
            return Ok(());
        }
    };

    // Try to fetch the job list to display available jobs
    match client.list_jobs().await {
        Ok(response) => match opts.format {
            OutputFormat::Json => {
                let names: Vec<&str> = response.jobs.iter().map(|j| j.name.as_str()).collect();
                let json = serde_json::json!({
                    "error": "no_job_specified",
                    "message": "specify a job name",
                    "available_jobs": names,
                });
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
            OutputFormat::Text => {
                eprintln!("Usage: marmosyn log <JOB_NAME> [--follow] [--lines N]");
                eprintln!();
                if response.jobs.is_empty() {
                    eprintln!("No sync jobs configured on the server.");
                } else {
                    eprintln!("Available jobs:");
                    for job in &response.jobs {
                        eprintln!("  - {}", job.name);
                    }
                }
            }
        },
        Err(err) => {
            eprintln!("Usage: marmosyn log <JOB_NAME> [--follow] [--lines N]");
            eprintln!();
            eprintln!("Failed to list jobs: {}", err);
        }
    }

    Ok(())
}

/// Builds an API client from log options.
fn build_client(opts: &LogOptions<'_>) -> Result<ApiClient, ApiError> {
    ApiClient::new(opts.server, opts.token, None, None)
}

/// Handles an API client construction error (e.g. no token, unreachable server).
fn handle_client_error(opts: &LogOptions<'_>, err: ApiError) -> Result<()> {
    match opts.format {
        OutputFormat::Json => {
            let json = serde_json::json!({
                "error": "connection_failed",
                "message": format!("{}", err),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&json).context("failed to serialize error")?
            );
        }
        OutputFormat::Text => {
            let msg = crate::cli::api_client::format_connection_error(&err);
            eprintln!("{}", msg);
        }
    }
    Ok(())
}

/// Handles an API request error for log retrieval.
fn handle_api_error(job_name: &str, err: ApiError) -> Result<()> {
    match &err {
        ApiError::ServerError { status, message } if *status == 404 => {
            eprintln!("Job '{}' not found on the server.", job_name);
            if !message.is_empty() {
                eprintln!("  Detail: {}", message);
            }
        }
        ApiError::Unauthorized => {
            eprintln!("Authorization failed. Check your API token.");
            eprintln!(
                "Use `marmosyn login` to save a token, or pass --token on the command line."
            );
        }
        _ => {
            eprintln!("Failed to retrieve logs for '{}': {}", job_name, err);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_handle_log_no_job_no_server() {
        // With no job and no running server, should print usage without panic
        let opts = LogOptions {
            server: Some("http://127.0.0.1:1"), // unreachable port
            token: None,
            format: OutputFormat::Text,
            job: None,
            follow: false,
            lines: 50,
        };
        let result = handle_log(&opts).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_log_json_no_job_no_server() {
        let opts = LogOptions {
            server: Some("http://127.0.0.1:1"),
            token: None,
            format: OutputFormat::Json,
            job: None,
            follow: false,
            lines: 50,
        };
        let result = handle_log(&opts).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_log_options_construction() {
        let opts = LogOptions {
            server: Some("http://localhost:7855"),
            token: Some("my-token"),
            format: OutputFormat::Text,
            job: Some("backup"),
            follow: true,
            lines: 200,
        };

        assert_eq!(opts.server, Some("http://localhost:7855"));
        assert_eq!(opts.token, Some("my-token"));
        assert_eq!(opts.job, Some("backup"));
        assert!(opts.follow);
        assert_eq!(opts.lines, 200);
    }

    #[test]
    fn test_log_options_defaults() {
        let opts = LogOptions {
            server: None,
            token: None,
            format: OutputFormat::Text,
            job: None,
            follow: false,
            lines: 50,
        };

        assert!(opts.server.is_none());
        assert!(opts.token.is_none());
        assert!(opts.job.is_none());
        assert!(!opts.follow);
        assert_eq!(opts.lines, 50);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_follow_poll_interval() {
        // Sanity check that the polling interval is reasonable
        assert!(FOLLOW_POLL_INTERVAL_SECS >= 1);
        assert!(FOLLOW_POLL_INTERVAL_SECS <= 30);
    }
}
