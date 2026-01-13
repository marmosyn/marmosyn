//! Handlers for the `marmosyn remotes` subcommands.
//!
//! All subcommands communicate with the running server via the HTTP API:
//! - `remotes list` → `GET /api/v1/remotes`
//! - `remotes ping` → `GET /api/v1/remotes/{name}/ping`

use anyhow::Result;

use crate::api::models::{PingResponse, RemoteListResponse};
use crate::cli::api_client::{format_connection_error, ApiClient};
use crate::cli::OutputFormat;

/// Common options shared by all remotes subcommands.
pub struct RemotesOptions<'a> {
    /// Server URL (from --server flag or default).
    pub server: Option<&'a str>,
    /// API token (from --token flag, env, or credentials).
    pub token: Option<&'a str>,
    /// Output format (text or json).
    pub format: OutputFormat,
}

/// Handles `marmosyn remotes list`.
///
/// Fetches the list of all configured remote nodes from the server and
/// displays them in a table (text) or JSON format.
pub async fn handle_list(opts: &RemotesOptions<'_>) -> Result<()> {
    let client = build_client(opts)?;

    match client.list_remotes().await {
        Ok(response) => {
            match opts.format {
                OutputFormat::Json => {
                    let json = serde_json::to_string_pretty(&response)?;
                    println!("{}", json);
                }
                OutputFormat::Text => {
                    print_remote_list(&response);
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

/// Handles `marmosyn remotes ping <name>`.
///
/// Sends a ping request to the named remote node via the server API and
/// displays the connectivity result.
pub async fn handle_ping(name: &str, opts: &RemotesOptions<'_>) -> Result<()> {
    let client = build_client(opts)?;

    match client.ping_remote(name).await {
        Ok(response) => {
            match opts.format {
                OutputFormat::Json => {
                    let json = serde_json::to_string_pretty(&response)?;
                    println!("{}", json);
                }
                OutputFormat::Text => {
                    print_ping_result(&response.ping);
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

/// Prints a list of remote nodes as a formatted text table.
fn print_remote_list(response: &RemoteListResponse) {
    if response.remotes.is_empty() {
        println!("No remote nodes configured.");
        return;
    }

    // Header
    println!("{:<20} {:<30} {:<12}", "NAME", "HOST", "STATUS");
    println!("{}", "─".repeat(64));

    for remote in &response.remotes {
        let status_display = format_status(&remote.status);
        println!(
            "{:<20} {:<30} {:<12}",
            truncate_str(&remote.name, 20),
            truncate_str(&remote.host, 30),
            status_display,
        );
    }

    println!();
    println!("Total: {} remote(s)", response.remotes.len());
}

/// Prints the result of a remote ping check.
fn print_ping_result(response: &PingResponse) {
    if response.reachable {
        let latency = response
            .latency_ms
            .map(|ms| format!(" ({}ms)", ms))
            .unwrap_or_default();
        println!("✓ Remote '{}' is reachable{}", response.name, latency);
    } else {
        let error = response.error.as_deref().unwrap_or("unknown error");
        println!("✗ Remote '{}' is unreachable: {}", response.name, error);
    }
}

/// Formats a remote status string with an icon prefix.
fn format_status(status: &str) -> String {
    match status {
        "reachable" => "✓ reachable".to_string(),
        "unreachable" => "✗ unreachable".to_string(),
        "unknown" => "? unknown".to_string(),
        other => other.to_string(),
    }
}

// ─── Utility helpers ───────────────────────────────────────────────────────

/// Builds an API client from the remotes options.
fn build_client(opts: &RemotesOptions<'_>) -> Result<ApiClient> {
    let server = opts.server.unwrap_or("http://127.0.0.1:7855");
    let token = opts.token.unwrap_or("");
    let client = ApiClient::from_token(server, token)?;
    Ok(client)
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
    use crate::api::models::RemoteSummary;

    #[test]
    fn test_format_status_reachable() {
        assert_eq!(format_status("reachable"), "✓ reachable");
    }

    #[test]
    fn test_format_status_unreachable() {
        assert_eq!(format_status("unreachable"), "✗ unreachable");
    }

    #[test]
    fn test_format_status_unknown() {
        assert_eq!(format_status("unknown"), "? unknown");
    }

    #[test]
    fn test_format_status_other() {
        assert_eq!(format_status("checking"), "checking");
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
    fn test_print_remote_list_empty() {
        let response = RemoteListResponse { remotes: vec![] };
        // Should not panic
        print_remote_list(&response);
    }

    #[test]
    fn test_print_remote_list_with_entries() {
        let response = RemoteListResponse {
            remotes: vec![
                RemoteSummary {
                    name: "office".to_string(),
                    host: "192.168.1.100:7854".to_string(),
                    status: "reachable".to_string(),
                },
                RemoteSummary {
                    name: "cloud-backup".to_string(),
                    host: "backup.example.com:7854".to_string(),
                    status: "unknown".to_string(),
                },
                RemoteSummary {
                    name: "datacenter".to_string(),
                    host: "10.0.0.5:7854".to_string(),
                    status: "unreachable".to_string(),
                },
            ],
        };
        // Should not panic
        print_remote_list(&response);
    }

    #[test]
    fn test_print_ping_result_reachable() {
        let response = PingResponse {
            name: "office".to_string(),
            reachable: true,
            latency_ms: Some(12),
            error: None,
        };
        // Should not panic
        print_ping_result(&response);
    }

    #[test]
    fn test_print_ping_result_reachable_no_latency() {
        let response = PingResponse {
            name: "office".to_string(),
            reachable: true,
            latency_ms: None,
            error: None,
        };
        // Should not panic
        print_ping_result(&response);
    }

    #[test]
    fn test_print_ping_result_unreachable() {
        let response = PingResponse {
            name: "cloud".to_string(),
            reachable: false,
            latency_ms: None,
            error: Some("connection refused".to_string()),
        };
        // Should not panic
        print_ping_result(&response);
    }

    #[test]
    fn test_print_ping_result_unreachable_no_error() {
        let response = PingResponse {
            name: "cloud".to_string(),
            reachable: false,
            latency_ms: None,
            error: None,
        };
        // Should not panic
        print_ping_result(&response);
    }

    #[test]
    fn test_print_remote_list_long_names() {
        let response = RemoteListResponse {
            remotes: vec![RemoteSummary {
                name: "a-very-long-remote-name-that-exceeds-column-width".to_string(),
                host: "extremely-long-hostname.subdomain.example.com:7854".to_string(),
                status: "unknown".to_string(),
            }],
        };
        // Should not panic — long names get truncated
        print_remote_list(&response);
    }

    #[test]
    fn test_build_client_default() {
        let opts = RemotesOptions {
            server: None,
            token: None,
            format: OutputFormat::Text,
        };
        let client = build_client(&opts);
        assert!(client.is_ok());
    }

    #[test]
    fn test_build_client_with_params() {
        let opts = RemotesOptions {
            server: Some("http://localhost:9000"),
            token: Some("my-api-token"),
            format: OutputFormat::Json,
        };
        let client = build_client(&opts);
        assert!(client.is_ok());
    }
}
