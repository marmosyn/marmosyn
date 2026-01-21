// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Handler for the `marmosyn status` subcommand.
//!
//! Queries the running server via `GET /api/v1/status` and displays
//! overall server information: version, uptime, job count, remote count,
//! and receiver status.

use anyhow::Result;

use crate::api::models::StatusResponse;
use crate::cli::OutputFormat;
use crate::cli::api_client::{ApiClient, format_connection_error};

/// Options for the status command.
pub struct StatusOptions<'a> {
    /// Server URL (from --server flag or default).
    pub server: Option<&'a str>,
    /// API token (from --token flag, env, or credentials).
    pub token: Option<&'a str>,
    /// Output format (text or json).
    pub format: OutputFormat,
}

/// Handles the `status` subcommand.
///
/// Connects to the running MarmoSyn server via the HTTP API, retrieves
/// the current status, and displays it in the requested format.
pub async fn handle_status(opts: &StatusOptions<'_>) -> Result<()> {
    let client = build_client(opts)?;

    match client.get_status().await {
        Ok(status) => {
            match opts.format {
                OutputFormat::Json => {
                    let json = serde_json::to_string_pretty(&status)?;
                    println!("{}", json);
                }
                OutputFormat::Text => {
                    print_status_text(&status);
                }
            }
            Ok(())
        }
        Err(err) => {
            let msg = format_connection_error(&err);
            eprintln!("{}", msg);
            Err(err.into())
        }
    }
}

/// Prints the status in human-readable text format.
fn print_status_text(status: &StatusResponse) {
    println!("MarmoSyn Server Status");
    println!("─────────────────────────────");
    println!("  Version:          {}", status.version);
    println!("  Uptime:           {}", format_uptime(status.uptime_secs));
    println!("  Sync jobs:        {}", status.jobs_count);
    println!("  Remote nodes:     {}", status.remotes_count);
    println!(
        "  Receiver:         {}",
        if status.receiver_enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
}

/// Formats an uptime in seconds into a human-readable string.
fn format_uptime(secs: u64) -> String {
    if secs < 60 {
        return format!("{}s", secs);
    }

    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let remaining_secs = secs % 60;

    if days > 0 {
        format!("{}d {}h {}m {}s", days, hours, minutes, remaining_secs)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, remaining_secs)
    } else {
        format!("{}m {}s", minutes, remaining_secs)
    }
}

/// Builds an API client from the status options.
fn build_client(opts: &StatusOptions<'_>) -> Result<ApiClient> {
    let server = opts.server.unwrap_or("http://127.0.0.1:7855");
    let token = opts.token.unwrap_or("");
    let client = ApiClient::from_token(server, token)?;
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_uptime_seconds() {
        assert_eq!(format_uptime(0), "0s");
        assert_eq!(format_uptime(30), "30s");
        assert_eq!(format_uptime(59), "59s");
    }

    #[test]
    fn test_format_uptime_minutes() {
        assert_eq!(format_uptime(60), "1m 0s");
        assert_eq!(format_uptime(90), "1m 30s");
        assert_eq!(format_uptime(3599), "59m 59s");
    }

    #[test]
    fn test_format_uptime_hours() {
        assert_eq!(format_uptime(3600), "1h 0m 0s");
        assert_eq!(format_uptime(7261), "2h 1m 1s");
    }

    #[test]
    fn test_format_uptime_days() {
        assert_eq!(format_uptime(86400), "1d 0h 0m 0s");
        assert_eq!(format_uptime(90061), "1d 1h 1m 1s");
        assert_eq!(format_uptime(172800), "2d 0h 0m 0s");
    }

    #[test]
    fn test_print_status_text_does_not_panic() {
        let status = StatusResponse {
            version: "0.1.0".to_string(),
            uptime_secs: 3661,
            jobs_count: 3,
            remotes_count: 2,
            receiver_enabled: true,
        };
        // Should not panic
        print_status_text(&status);
    }

    #[test]
    fn test_print_status_text_receiver_disabled() {
        let status = StatusResponse {
            version: "0.1.0".to_string(),
            uptime_secs: 0,
            jobs_count: 0,
            remotes_count: 0,
            receiver_enabled: false,
        };
        print_status_text(&status);
    }

    #[test]
    fn test_build_client_default() {
        let opts = StatusOptions {
            server: None,
            token: None,
            format: OutputFormat::Text,
        };
        let client = build_client(&opts);
        assert!(client.is_ok());
    }

    #[test]
    fn test_build_client_with_token() {
        let opts = StatusOptions {
            server: Some("http://localhost:9000"),
            token: Some("my-token"),
            format: OutputFormat::Json,
        };
        let client = build_client(&opts);
        assert!(client.is_ok());
    }
}
