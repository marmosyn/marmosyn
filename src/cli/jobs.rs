// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Handlers for the `marmosyn jobs` subcommands.
//!
//! All subcommands communicate with the running server via the HTTP API:
//! - `jobs list`    → `GET /api/v1/jobs`
//! - `jobs info`    → `GET /api/v1/jobs/{name}`
//! - `jobs sync`    → `POST /api/v1/jobs/{name}/sync`
//! - `jobs stop`    → `POST /api/v1/jobs/{name}/stop`
//! - `jobs history` → `GET /api/v1/jobs/{name}/history`

use anyhow::Result;

use crate::api::models::{JobDetail, JobHistoryResponse, JobListResponse, SyncResponse};
use crate::cli::OutputFormat;
use crate::cli::api_client::{ApiClient, format_connection_error};

/// Common options shared by all jobs subcommands.
pub struct JobsOptions<'a> {
    /// Server URL (from --server flag or default).
    pub server: Option<&'a str>,
    /// API token (from --token flag, env, or credentials).
    pub token: Option<&'a str>,
    /// Output format (text or json).
    pub format: OutputFormat,
}

/// Handles `marmosyn jobs list`.
///
/// Fetches the list of all configured sync jobs from the server and displays
/// them in a table (text) or JSON format.
pub async fn handle_list(opts: &JobsOptions<'_>) -> Result<()> {
    let client = build_client(opts)?;

    match client.list_jobs().await {
        Ok(response) => {
            match opts.format {
                OutputFormat::Json => {
                    let json = serde_json::to_string_pretty(&response)?;
                    println!("{}", json);
                }
                OutputFormat::Text => {
                    print_job_list(&response);
                }
            }
            Ok(())
        }
        Err(err) => {
            eprintln!("{}", format_connection_error(&err));
            Err(err.into())
        }
    }
}

/// Handles `marmosyn jobs info <name>`.
///
/// Fetches detailed information about a specific sync job and displays it.
pub async fn handle_info(name: &str, opts: &JobsOptions<'_>) -> Result<()> {
    let client = build_client(opts)?;

    match client.get_job(name).await {
        Ok(response) => {
            match opts.format {
                OutputFormat::Json => {
                    let json = serde_json::to_string_pretty(&response)?;
                    println!("{}", json);
                }
                OutputFormat::Text => {
                    print_job_detail(&response.job);
                }
            }
            Ok(())
        }
        Err(err) => {
            eprintln!("{}", format_connection_error(&err));
            Err(err.into())
        }
    }
}

/// Handles `marmosyn jobs sync <name>`.
///
/// Triggers a manual synchronization for the named job via the API.
pub async fn handle_sync(name: &str, opts: &JobsOptions<'_>) -> Result<()> {
    let client = build_client(opts)?;

    match client.trigger_sync(name).await {
        Ok(response) => {
            match opts.format {
                OutputFormat::Json => {
                    let json = serde_json::to_string_pretty(&response)?;
                    println!("{}", json);
                }
                OutputFormat::Text => {
                    print_sync_response("Sync trigger", &response);
                }
            }
            Ok(())
        }
        Err(err) => {
            eprintln!("{}", format_connection_error(&err));
            Err(err.into())
        }
    }
}

/// Handles `marmosyn jobs stop <name>`.
///
/// Requests the server to stop the currently running sync for the named job.
pub async fn handle_stop(name: &str, opts: &JobsOptions<'_>) -> Result<()> {
    let client = build_client(opts)?;

    match client.stop_job(name).await {
        Ok(response) => {
            match opts.format {
                OutputFormat::Json => {
                    let json = serde_json::to_string_pretty(&response)?;
                    println!("{}", json);
                }
                OutputFormat::Text => {
                    print_sync_response("Stop", &response);
                }
            }
            Ok(())
        }
        Err(err) => {
            eprintln!("{}", format_connection_error(&err));
            Err(err.into())
        }
    }
}

/// Handles `marmosyn jobs history <name>`.
///
/// Fetches the synchronization history for the named job and displays it.
pub async fn handle_history(
    name: &str,
    limit: Option<usize>,
    opts: &JobsOptions<'_>,
) -> Result<()> {
    let client = build_client(opts)?;

    match client.get_job_history(name, limit.map(|l| l as u32)).await {
        Ok(response) => {
            match opts.format {
                OutputFormat::Json => {
                    let json = serde_json::to_string_pretty(&response)?;
                    println!("{}", json);
                }
                OutputFormat::Text => {
                    print_job_history(&response);
                }
            }
            Ok(())
        }
        Err(err) => {
            eprintln!("{}", format_connection_error(&err));
            Err(err.into())
        }
    }
}

// ─── Text formatting helpers ───────────────────────────────────────────────

/// Prints a list of jobs as a formatted text table.
fn print_job_list(response: &JobListResponse) {
    if response.jobs.is_empty() {
        println!("No sync jobs configured.");
        return;
    }

    // Header
    println!(
        "{:<20} {:<10} {:<10} {:<10}",
        "NAME", "STATUS", "MODE", "ENCRYPT"
    );
    println!("{}", "─".repeat(54));

    for job in &response.jobs {
        let encrypt_str = if job.encrypt { "yes" } else { "no" };
        println!(
            "{:<20} {:<10} {:<10} {:<10}",
            truncate_str(&job.name, 20),
            job.status,
            job.mode,
            encrypt_str,
        );
    }

    println!();
    println!("Total: {} job(s)", response.jobs.len());
}

/// Prints detailed information about a single job.
fn print_job_detail(detail: &JobDetail) {
    println!("Job: {}", detail.name);
    println!("─────────────────────────────");
    println!("  Source:      {}", detail.source);
    println!("  Mode:        {}", detail.mode);
    println!("  Status:      {}", detail.status);
    println!(
        "  Encrypt:     {}",
        if detail.encrypt { "yes" } else { "no" }
    );

    // Safety backup
    if detail.safety.enabled {
        println!("  Safety:      enabled");
        if let Some(ref ret) = detail.safety.retention {
            println!("    Retention: {}", ret);
        }
        if let Some(ref ms) = detail.safety.max_size {
            println!("    Max size:  {}", ms);
        }
        if let Some(size) = detail.safety.current_size {
            println!("    Current:   {} bytes", size);
        }
    } else {
        println!("  Safety:      disabled");
    }

    // Destinations
    if !detail.dests.is_empty() {
        println!("  Destinations:");
        for dest in &detail.dests {
            let remote_info = dest
                .remote_name
                .as_ref()
                .map(|r| format!(" (remote: {})", r))
                .unwrap_or_default();
            println!(
                "    - {} [{}] {}{}",
                dest.target, dest.dest_type, dest.status, remote_info
            );
        }
    }

    // Last sync
    if let Some(ref last) = detail.last_sync {
        println!("  Last sync:   {}", last);
    } else {
        println!("  Last sync:   never");
    }

    if let Some(ref result) = detail.last_result {
        println!("  Last result: {}", result);
    }

    if detail.files_synced > 0 || detail.bytes_transferred > 0 {
        println!(
            "  Files synced: {}, bytes: {}",
            detail.files_synced,
            format_bytes(detail.bytes_transferred)
        );
    }

    if let Some(ref next) = detail.next_scheduled {
        println!("  Next run:    {}", next);
    }
}

/// Prints a sync/stop response with a label prefix.
fn print_sync_response(label: &str, response: &SyncResponse) {
    if response.success {
        println!("✓ {}: {}", label, response.message);
    } else {
        println!("✗ {}: {}", label, response.message);
    }
}

/// Prints job history entries in a formatted table.
fn print_job_history(response: &JobHistoryResponse) {
    println!("Sync history for job '{}'", response.job_name);

    if response.entries.is_empty() {
        println!("  No history entries found.");
        return;
    }

    println!();
    println!(
        "{:<24} {:<24} {:<10} {:<8} {:<12}",
        "STARTED", "FINISHED", "STATUS", "FILES", "BYTES"
    );
    println!("{}", "─".repeat(80));

    for entry in &response.entries {
        let finished = entry.finished_at.as_deref().unwrap_or("(running)");

        let status_display = match entry.status.as_str() {
            "success" => "✓ ok",
            "failed" => "✗ fail",
            "running" => "⟳ run",
            "dry_run" => "~ dry",
            other => other,
        };

        println!(
            "{:<24} {:<24} {:<10} {:<8} {:<12}",
            truncate_str(&entry.started_at, 24),
            truncate_str(finished, 24),
            status_display,
            entry.files_synced,
            format_bytes(entry.bytes_transferred),
        );

        if let Some(ref err) = entry.error_message {
            println!("    Error: {}", err);
        }
    }

    println!();
    println!("Total: {} entries", response.entries.len());
}

// ─── Utility helpers ───────────────────────────────────────────────────────

/// Builds an API client from the jobs options.
fn build_client(opts: &JobsOptions<'_>) -> Result<ApiClient> {
    let server = opts.server.unwrap_or("http://127.0.0.1:7855");
    let token = opts.token.unwrap_or("");
    let client = ApiClient::from_token(server, token)?;
    Ok(client)
}

/// Formats a byte count into a human-readable string.
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Truncates a string to a maximum length, appending "…" if truncated.
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len > 1 {
        format!("{}…", &s[..max_len - 1])
    } else {
        "…".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::models::{DestInfo, HistoryEntry, JobSummary, SafetyInfo, SyncResponse};

    #[test]
    fn test_format_bytes_b() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn test_format_bytes_kb() {
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
    }

    #[test]
    fn test_format_bytes_mb() {
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 + 512 * 1024), "1.50 MB");
    }

    #[test]
    fn test_format_bytes_gb() {
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn test_truncate_str_short() {
        assert_eq!(truncate_str("hello", 10), "hello");
        assert_eq!(truncate_str("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_str_long() {
        assert_eq!(truncate_str("hello world", 5), "hell…");
        assert_eq!(truncate_str("abcdefgh", 3), "ab…");
    }

    #[test]
    fn test_truncate_str_edge() {
        assert_eq!(truncate_str("ab", 1), "…");
        assert_eq!(truncate_str("", 5), "");
    }

    #[test]
    fn test_print_job_list_empty() {
        let response = JobListResponse { jobs: vec![] };
        // Should not panic
        print_job_list(&response);
    }

    #[test]
    fn test_print_job_list_with_entries() {
        let response = JobListResponse {
            jobs: vec![
                JobSummary {
                    name: "documents".to_string(),
                    source: "/home/user/docs".to_string(),
                    status: "idle".to_string(),
                    mode: "manual".to_string(),
                    encrypt: false,
                },
                JobSummary {
                    name: "photos".to_string(),
                    source: "/home/user/photos".to_string(),
                    status: "running".to_string(),
                    mode: "watch".to_string(),
                    encrypt: true,
                },
            ],
        };
        // Should not panic
        print_job_list(&response);
    }

    #[test]
    fn test_print_job_detail_minimal() {
        let detail = JobDetail {
            name: "test-job".to_string(),
            source: "/tmp/src".to_string(),
            status: "idle".to_string(),
            mode: "manual".to_string(),
            encrypt: false,
            safety: SafetyInfo {
                enabled: false,
                retention: None,
                max_size: None,
                current_size: None,
            },
            last_sync: None,
            last_result: None,
            files_synced: 0,
            bytes_transferred: 0,
            next_scheduled: None,
            dests: vec![],
        };
        // Should not panic
        print_job_detail(&detail);
    }

    #[test]
    fn test_print_job_detail_full() {
        let detail = JobDetail {
            name: "documents".to_string(),
            source: "/home/user/Documents".to_string(),
            status: "idle".to_string(),
            mode: "watch".to_string(),
            encrypt: true,
            safety: SafetyInfo {
                enabled: true,
                retention: Some("30d".to_string()),
                max_size: Some("10GB".to_string()),
                current_size: Some(1024 * 1024 * 500),
            },
            last_sync: Some("2024-01-15T10:30:00Z".to_string()),
            last_result: Some("success".to_string()),
            files_synced: 42,
            bytes_transferred: 1024 * 1024 * 10,
            next_scheduled: Some("2024-01-16T03:00:00Z".to_string()),
            dests: vec![
                DestInfo {
                    target: "/mnt/backup/docs".to_string(),
                    dest_type: "local".to_string(),
                    remote_name: None,
                    status: "ok".to_string(),
                },
                DestInfo {
                    target: "office:backup/docs".to_string(),
                    dest_type: "remote".to_string(),
                    remote_name: Some("office".to_string()),
                    status: "unknown".to_string(),
                },
            ],
        };
        // Should not panic
        print_job_detail(&detail);
    }

    #[test]
    fn test_print_sync_response_success() {
        let response = SyncResponse {
            success: true,
            message: "sync triggered for job 'docs'".to_string(),
        };
        print_sync_response("Sync trigger", &response);
    }

    #[test]
    fn test_print_sync_response_failure() {
        let response = SyncResponse {
            success: false,
            message: "job is already running".to_string(),
        };
        print_sync_response("Sync trigger", &response);
    }

    #[test]
    fn test_print_stop_response() {
        let response = SyncResponse {
            success: true,
            message: "job 'docs' stopped".to_string(),
        };
        print_sync_response("Stop", &response);
    }

    #[test]
    fn test_print_job_history_empty() {
        let response = JobHistoryResponse {
            job_name: "test".to_string(),
            entries: vec![],
        };
        print_job_history(&response);
    }

    #[test]
    fn test_print_job_history_with_entries() {
        let response = JobHistoryResponse {
            job_name: "documents".to_string(),
            entries: vec![
                HistoryEntry {
                    started_at: "2024-01-15T10:30:00Z".to_string(),
                    finished_at: Some("2024-01-15T10:31:00Z".to_string()),
                    status: "success".to_string(),
                    files_synced: 42,
                    bytes_transferred: 1024 * 1024,
                    error_message: None,
                },
                HistoryEntry {
                    started_at: "2024-01-14T10:30:00Z".to_string(),
                    finished_at: Some("2024-01-14T10:30:05Z".to_string()),
                    status: "failed".to_string(),
                    files_synced: 0,
                    bytes_transferred: 0,
                    error_message: Some("source directory not found".to_string()),
                },
                HistoryEntry {
                    started_at: "2024-01-16T10:00:00Z".to_string(),
                    finished_at: None,
                    status: "running".to_string(),
                    files_synced: 10,
                    bytes_transferred: 512,
                    error_message: None,
                },
            ],
        };
        // Should not panic
        print_job_history(&response);
    }

    #[test]
    fn test_build_client_default() {
        let opts = JobsOptions {
            server: None,
            token: None,
            format: OutputFormat::Text,
        };
        let client = build_client(&opts);
        assert!(client.is_ok());
    }

    #[test]
    fn test_build_client_with_params() {
        let opts = JobsOptions {
            server: Some("http://localhost:9000"),
            token: Some("my-api-token"),
            format: OutputFormat::Json,
        };
        let client = build_client(&opts);
        assert!(client.is_ok());
    }
}
