// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Serializable response models for the HTTP API.
//!
//! These types are returned by API handlers and serialized to JSON.
//! They are kept separate from internal types to allow independent
//! evolution of the API contract.

use serde::{Deserialize, Serialize};

/// Response for `GET /api/v1/health`.
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Always `"ok"` when the server is running.
    pub status: String,
    /// Server version string.
    pub version: String,
}

/// Response for `GET /api/v1/status`.
#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    /// Server version.
    pub version: String,
    /// Server uptime in seconds.
    pub uptime_secs: u64,
    /// Number of configured sync jobs.
    pub jobs_count: usize,
    /// Number of configured remote nodes.
    pub remotes_count: usize,
    /// Whether the receiver is enabled.
    pub receiver_enabled: bool,
}

/// Summary information about a sync job, returned in list endpoints.
#[derive(Debug, Serialize, Deserialize)]
pub struct JobSummary {
    /// Unique job name.
    pub name: String,
    /// Source directory path.
    pub source: String,
    /// Current status: "idle", "running", "watching", "scheduled", "error".
    pub status: String,
    /// Synchronization mode: "manual", "schedule", "watch".
    pub mode: String,
    /// Whether per-job encryption is enabled.
    pub encrypt: bool,
}

/// Detailed information about a sync job.
#[derive(Debug, Serialize, Deserialize)]
pub struct JobDetail {
    /// Unique job name.
    pub name: String,
    /// Source directory path.
    pub source: String,
    /// Current status.
    pub status: String,
    /// Synchronization mode.
    pub mode: String,
    /// Whether per-job encryption is enabled.
    pub encrypt: bool,
    /// Safety backup configuration.
    pub safety: SafetyInfo,
    /// ISO 8601 timestamp of the last sync, if any.
    pub last_sync: Option<String>,
    /// Result of the last sync: "success", "failed", or null.
    pub last_result: Option<String>,
    /// Number of files synced in the last run.
    pub files_synced: u64,
    /// Bytes transferred in the last run.
    pub bytes_transferred: u64,
    /// Next scheduled run (ISO 8601), if applicable.
    pub next_scheduled: Option<String>,
    /// Destination details.
    pub dests: Vec<DestInfo>,
}

/// Safety backup information included in job detail responses.
#[derive(Debug, Serialize, Deserialize)]
pub struct SafetyInfo {
    /// Whether safety backup is enabled for this job.
    pub enabled: bool,
    /// Retention period string (e.g. "30d"), if configured.
    pub retention: Option<String>,
    /// Maximum size string (e.g. "10GB"), if configured.
    pub max_size: Option<String>,
    /// Current size of safety copies in bytes.
    pub current_size: Option<u64>,
}

/// Information about a single destination in a sync job.
#[derive(Debug, Serialize, Deserialize)]
pub struct DestInfo {
    /// The dest target string as configured.
    pub target: String,
    /// Destination type: "local" or "remote".
    #[serde(rename = "type")]
    pub dest_type: String,
    /// Remote name (only for remote dests).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_name: Option<String>,
    /// Current status of this dest: "ok", "error", "unreachable".
    pub status: String,
}

/// Response for triggering a manual sync.
#[derive(Debug, Serialize, Deserialize)]
pub struct SyncTriggerResponse {
    /// Whether the sync was successfully triggered.
    pub triggered: bool,
    /// Human-readable message.
    pub message: String,
}

/// Response for stopping a sync.
#[derive(Debug, Serialize, Deserialize)]
pub struct StopResponse {
    /// Whether the stop was successful.
    pub stopped: bool,
    /// Human-readable message.
    pub message: String,
}

/// A single entry in the sync history.
#[derive(Debug, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// ISO 8601 timestamp when the sync started.
    pub started_at: String,
    /// ISO 8601 timestamp when the sync finished, if completed.
    pub finished_at: Option<String>,
    /// Result status: "running", "success", "failed".
    pub status: String,
    /// Number of files synced.
    pub files_synced: u64,
    /// Bytes transferred.
    pub bytes_transferred: u64,
    /// Error message, if the sync failed.
    pub error_message: Option<String>,
}

/// Summary information about a remote node.
#[derive(Debug, Serialize, Deserialize)]
pub struct RemoteSummary {
    /// Remote name.
    pub name: String,
    /// Remote host address.
    pub host: String,
    /// Current status: "unknown", "reachable", "unreachable".
    pub status: String,
}

/// Response for a remote ping check.
#[derive(Debug, Serialize, Deserialize)]
pub struct PingResponse {
    /// Remote name.
    pub name: String,
    /// Whether the remote is reachable.
    pub reachable: bool,
    /// Round-trip latency in milliseconds, if reachable.
    pub latency_ms: Option<u64>,
    /// Error message, if unreachable.
    pub error: Option<String>,
}

/// Response for `GET /api/v1/receiver/status`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReceiverStatusResponse {
    /// Whether the receiver is enabled.
    pub enabled: bool,
    /// List of allowed paths with their usage.
    pub allowed_paths: Vec<AllowedPathInfo>,
    /// Number of currently active incoming connections.
    pub active_connections: u64,
    /// Total number of files received since server start.
    pub total_files_received: u64,
    /// Total bytes received since server start.
    pub total_bytes_received: u64,
}

/// Information about an allowed path on the receiver.
#[derive(Debug, Serialize, Deserialize)]
pub struct AllowedPathInfo {
    /// Absolute path on disk.
    pub path: String,
    /// Alias for this path, if configured.
    pub alias: Option<String>,
    /// Bytes currently used in this path.
    pub used_bytes: u64,
}

/// Response for `GET /api/v1/receiver/connections`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionsResponse {
    /// List of active incoming connections.
    pub connections: Vec<ConnectionInfo>,
}

/// Information about an active incoming connection.
#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionInfo {
    /// Remote address of the sender.
    pub remote_addr: String,
    /// ISO 8601 timestamp when the connection was established.
    pub connected_at: String,
    /// Number of files received on this connection so far.
    pub files_received: u64,
    /// Bytes received on this connection so far.
    pub bytes_received: u64,
}

/// Response for `GET /api/v1/config`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigResponse {
    /// The configuration in a sanitized form (secrets redacted).
    pub config: serde_json::Value,
}

/// Response for `POST /api/v1/config/reload`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReloadResponse {
    /// Whether the reload was successful.
    pub success: bool,
    /// Human-readable message.
    pub message: String,
}

/// Generic error response returned by the API.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// HTTP status code.
    pub status: u16,
    /// Error code string for programmatic use.
    pub error: String,
    /// Human-readable error message.
    pub message: String,
}

// ─── Type aliases used by ApiClient ────────────────────────────────────────
// These provide stable names that the CLI API client references.
// They map to the concrete response types defined above.

/// Alias for `StatusResponse` — used by `ApiClient::get_status()`.
pub type ServerStatusResponse = StatusResponse;

/// Response wrapper for `GET /api/v1/jobs` — list of job summaries.
#[derive(Debug, Serialize, Deserialize)]
pub struct JobListResponse {
    /// List of job summaries.
    pub jobs: Vec<JobSummary>,
}

/// Response wrapper for `GET /api/v1/jobs/{name}` — detailed job info.
#[derive(Debug, Serialize, Deserialize)]
pub struct JobInfoResponse {
    /// Detailed job information.
    pub job: JobDetail,
}

/// Response wrapper for sync trigger and stop operations.
#[derive(Debug, Serialize, Deserialize)]
pub struct SyncResponse {
    /// Whether the operation was successful.
    pub success: bool,
    /// Human-readable message.
    pub message: String,
}

/// Response wrapper for `GET /api/v1/jobs/{name}/history`.
#[derive(Debug, Serialize, Deserialize)]
pub struct JobHistoryResponse {
    /// Job name.
    pub job_name: String,
    /// List of history entries.
    pub entries: Vec<HistoryEntry>,
}

/// Response wrapper for `GET /api/v1/remotes`.
#[derive(Debug, Serialize, Deserialize)]
pub struct RemoteListResponse {
    /// List of remote node summaries.
    pub remotes: Vec<RemoteSummary>,
}

/// Response wrapper for `GET /api/v1/remotes/{name}/ping`.
#[derive(Debug, Serialize, Deserialize)]
pub struct RemotePingResponse {
    /// Ping result.
    #[serde(flatten)]
    pub ping: PingResponse,
}

/// Response for `GET /api/v1/jobs/{name}/log`.
#[derive(Debug, Serialize, Deserialize)]
pub struct JobLogResponse {
    /// Job name.
    pub job_name: String,
    /// Log lines (most recent sync history entries formatted as log lines).
    pub lines: Vec<String>,
    /// Total number of available log entries.
    pub total: usize,
}
