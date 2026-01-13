//! HTTP client for CLI → Server API communication.
//!
//! All CLI subcommands that manage the server use this client to send
//! requests to the MarmoSyn HTTP API. Token resolution is handled
//! via the `credentials` module.

use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest::{Client, Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tracing::{debug, trace};

use crate::api::models::{
    ConfigResponse, HealthResponse, JobHistoryResponse, JobInfoResponse, JobListResponse,
    JobLogResponse, RemoteListResponse, RemotePingResponse, ServerStatusResponse, SyncResponse,
};
use crate::credentials::resolve::{self, ResolveOptions, TokenSource};

/// Default request timeout for API calls.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default server URL if none is specified.
const DEFAULT_SERVER_URL: &str = "http://127.0.0.1:7855";

/// Errors specific to the API client.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// The server returned an HTTP error status.
    #[error("server returned {status}: {message}")]
    ServerError { status: StatusCode, message: String },

    /// The request failed (network error, timeout, etc.).
    #[error("request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),

    /// Failed to deserialize the server response.
    #[error("failed to parse server response: {0}")]
    DeserializeError(String),

    /// The server is not reachable.
    #[error("server is not reachable at {url}: {reason}")]
    Unreachable { url: String, reason: String },

    /// Authentication failed (401 Unauthorized).
    #[error("authentication failed: invalid or missing API token")]
    Unauthorized,

    /// Token resolution failed.
    #[error("failed to resolve API token: {0}")]
    TokenError(#[from] resolve::ResolveError),
}

/// HTTP client for communicating with the MarmoSyn server API.
///
/// All CLI subcommands (except `config check`, `config init`, and `version`)
/// use this client to interact with the running server.
pub struct ApiClient {
    /// Base URL of the server (e.g. `"http://127.0.0.1:7855"`).
    base_url: String,
    /// Resolved API token for authorization.
    token: String,
    /// Source of the resolved token (for diagnostics).
    token_source: TokenSource,
    /// The underlying HTTP client.
    http: Client,
}

impl ApiClient {
    /// Creates a new `ApiClient` by resolving the server URL and token
    /// from CLI arguments, environment variables, and credentials file.
    ///
    /// # Arguments
    ///
    /// * `server_url` — explicit `--server` flag value (overrides default).
    /// * `token_flag` — explicit `--token` flag value.
    /// * `profile` — credentials profile name (default: `"default"`).
    /// * `credentials_path` — explicit path to credentials file.
    ///
    /// # Errors
    ///
    /// Returns an error if the token cannot be resolved or the HTTP client
    /// cannot be created.
    pub fn new(
        server_url: Option<&str>,
        token_flag: Option<&str>,
        profile: Option<&str>,
        credentials_path: Option<&Path>,
    ) -> Result<Self, ApiError> {
        let base_url = resolve_server_url(server_url);

        let opts = ResolveOptions {
            token_flag,
            profile,
            credentials_path,
            server_url: Some(&base_url),
        };

        let resolved = resolve::resolve_token(&opts)?;

        debug!(
            server = %base_url,
            token_source = ?resolved.source,
            "API client initialized"
        );

        let http = Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .user_agent(format!("marmosyn-cli/{}", env!("CARGO_PKG_VERSION")))
            .build()?;

        Ok(Self {
            base_url,
            token: resolved.token,
            token_source: resolved.source,
            http,
        })
    }

    /// Creates an `ApiClient` from an already-known server URL and token.
    ///
    /// Useful for testing or when the token is already resolved.
    pub fn from_token(server_url: &str, token: &str) -> Result<Self, ApiError> {
        let http = Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .user_agent(format!("marmosyn-cli/{}", env!("CARGO_PKG_VERSION")))
            .build()?;

        Ok(Self {
            base_url: server_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            token_source: TokenSource::CliFlag,
            http,
        })
    }

    /// Returns the base URL of the server.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Returns the source of the resolved token.
    pub fn token_source(&self) -> TokenSource {
        self.token_source
    }

    // ─── API Methods ───────────────────────────────────────────────────

    /// `GET /api/v1/health` — check server health.
    pub async fn health(&self) -> Result<HealthResponse, ApiError> {
        self.get("/api/v1/health").await
    }

    /// `GET /api/v1/status` — get server status summary.
    pub async fn get_status(&self) -> Result<ServerStatusResponse, ApiError> {
        self.get("/api/v1/status").await
    }

    /// `GET /api/v1/jobs` — list all sync jobs.
    pub async fn list_jobs(&self) -> Result<JobListResponse, ApiError> {
        self.get("/api/v1/jobs").await
    }

    /// `GET /api/v1/jobs/{name}` — get detailed info about a specific job.
    pub async fn get_job(&self, name: &str) -> Result<JobInfoResponse, ApiError> {
        self.get(&format!("/api/v1/jobs/{}", encode_path(name)))
            .await
    }

    /// `POST /api/v1/jobs/{name}/sync` — trigger synchronization for a job.
    pub async fn trigger_sync(&self, name: &str) -> Result<SyncResponse, ApiError> {
        self.post_empty(&format!("/api/v1/jobs/{}/sync", encode_path(name)))
            .await
    }

    /// `POST /api/v1/jobs/{name}/stop` — stop a running sync job.
    pub async fn stop_job(&self, name: &str) -> Result<SyncResponse, ApiError> {
        self.post_empty(&format!("/api/v1/jobs/{}/stop", encode_path(name)))
            .await
    }

    /// `GET /api/v1/jobs/{name}/history` — get sync history for a job.
    pub async fn get_job_history(
        &self,
        name: &str,
        limit: Option<u32>,
    ) -> Result<JobHistoryResponse, ApiError> {
        let path = match limit {
            Some(n) => format!("/api/v1/jobs/{}/history?limit={}", encode_path(name), n),
            None => format!("/api/v1/jobs/{}/history", encode_path(name)),
        };
        self.get(&path).await
    }

    /// `GET /api/v1/jobs/{name}/log` — get formatted log lines for a job.
    pub async fn get_job_log(
        &self,
        name: &str,
        limit: Option<u32>,
    ) -> Result<JobLogResponse, ApiError> {
        let path = match limit {
            Some(n) => format!("/api/v1/jobs/{}/log?limit={}", encode_path(name), n),
            None => format!("/api/v1/jobs/{}/log", encode_path(name)),
        };
        self.get(&path).await
    }

    /// `GET /api/v1/remotes` — list all configured remote nodes.
    pub async fn list_remotes(&self) -> Result<RemoteListResponse, ApiError> {
        self.get("/api/v1/remotes").await
    }

    /// `GET /api/v1/remotes/{name}/ping` — ping a remote node.
    pub async fn ping_remote(&self, name: &str) -> Result<RemotePingResponse, ApiError> {
        self.get(&format!("/api/v1/remotes/{}/ping", encode_path(name)))
            .await
    }

    /// `GET /api/v1/config` — get current server configuration.
    pub async fn get_config(&self) -> Result<ConfigResponse, ApiError> {
        self.get("/api/v1/config").await
    }

    /// `POST /api/v1/config/reload` — trigger configuration reload.
    pub async fn reload_config(&self) -> Result<serde_json::Value, ApiError> {
        self.post_empty("/api/v1/config/reload").await
    }

    // ─── HTTP Primitives ───────────────────────────────────────────────

    /// Sends a GET request and deserializes the JSON response.
    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        let url = format!("{}{}", self.base_url, path);
        trace!(url = %url, "GET");

        let response = self
            .http
            .get(&url)
            .headers(self.auth_headers())
            .send()
            .await
            .map_err(|e| self.wrap_connection_error(e, &url))?;

        self.handle_response(response).await
    }

    /// Sends a POST request with a JSON body and deserializes the response.
    #[allow(dead_code)]
    async fn post<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ApiError> {
        let url = format!("{}{}", self.base_url, path);
        trace!(url = %url, "POST with body");

        let response = self
            .http
            .post(&url)
            .headers(self.auth_headers())
            .json(body)
            .send()
            .await
            .map_err(|e| self.wrap_connection_error(e, &url))?;

        self.handle_response(response).await
    }

    /// Sends a POST request with an empty body and deserializes the response.
    async fn post_empty<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        let url = format!("{}{}", self.base_url, path);
        trace!(url = %url, "POST empty");

        let response = self
            .http
            .post(&url)
            .headers(self.auth_headers())
            .send()
            .await
            .map_err(|e| self.wrap_connection_error(e, &url))?;

        self.handle_response(response).await
    }

    /// Constructs the authorization headers.
    fn auth_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if !self.token.is_empty() {
            if let Ok(val) = HeaderValue::from_str(&format!("Bearer {}", self.token)) {
                headers.insert(AUTHORIZATION, val);
            }
        }
        headers
    }

    /// Handles the HTTP response: checks status code and deserializes JSON.
    async fn handle_response<T: DeserializeOwned>(
        &self,
        response: Response,
    ) -> Result<T, ApiError> {
        let status = response.status();

        if status == StatusCode::UNAUTHORIZED {
            return Err(ApiError::Unauthorized);
        }

        if !status.is_success() {
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "no response body".to_string());
            return Err(ApiError::ServerError { status, message });
        }

        let body = response.text().await?;
        trace!(body_len = body.len(), "response received");

        serde_json::from_str::<T>(&body).map_err(|e| {
            ApiError::DeserializeError(format!(
                "failed to parse response as {}: {} (body: {})",
                std::any::type_name::<T>(),
                e,
                truncate_body(&body, 200),
            ))
        })
    }

    /// Wraps a reqwest connection error into a more descriptive `ApiError`.
    fn wrap_connection_error(&self, err: reqwest::Error, url: &str) -> ApiError {
        if err.is_connect() || err.is_timeout() {
            ApiError::Unreachable {
                url: url.to_string(),
                reason: err.to_string(),
            }
        } else {
            ApiError::RequestFailed(err)
        }
    }
}

impl std::fmt::Debug for ApiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiClient")
            .field("base_url", &self.base_url)
            .field("token_source", &self.token_source)
            .field("token", &"***")
            .finish()
    }
}

// ─── Helpers ───────────────────────────────────────────────────────────────

/// Resolves the server URL from the given option, environment variable,
/// or falls back to the default.
fn resolve_server_url(explicit: Option<&str>) -> String {
    if let Some(url) = explicit {
        return url.trim_end_matches('/').to_string();
    }

    if let Ok(url) = std::env::var("MARMOSYN_SERVER") {
        if !url.is_empty() {
            return url.trim_end_matches('/').to_string();
        }
    }

    DEFAULT_SERVER_URL.to_string()
}

/// URL-encodes a path segment (e.g. job name) for safe inclusion in URLs.
fn encode_path(segment: &str) -> String {
    // Simple percent-encoding for path segments.
    // Only encode characters that are problematic in URL paths.
    segment
        .chars()
        .map(|c| match c {
            '/' => "%2F".to_string(),
            ' ' => "%20".to_string(),
            '#' => "%23".to_string(),
            '?' => "%3F".to_string(),
            '&' => "%26".to_string(),
            '%' => "%25".to_string(),
            _ => c.to_string(),
        })
        .collect()
}

/// Truncates a body string for error messages.
fn truncate_body(body: &str, max_len: usize) -> &str {
    if body.len() <= max_len {
        body
    } else {
        &body[..max_len]
    }
}

/// Helper to format error messages when the server is unreachable.
///
/// Provides user-friendly suggestions based on the error type.
pub fn format_connection_error(err: &ApiError) -> String {
    match err {
        ApiError::Unreachable { url, reason } => {
            format!(
                "Cannot connect to MarmoSyn server at {url}\n\
                 Reason: {reason}\n\n\
                 Possible solutions:\n\
                 • Make sure the server is running: marmosyn server\n\
                 • Check the server URL: --server <url>\n\
                 • Check firewall settings"
            )
        }
        ApiError::Unauthorized => "Authentication failed.\n\n\
             Possible solutions:\n\
             • Run `marmosyn login` to save your token\n\
             • Provide a token with --token <token>\n\
             • Set the $MARMOSYN_API_TOKEN environment variable"
            .to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_server_url_explicit() {
        assert_eq!(
            resolve_server_url(Some("http://example.com:9000/")),
            "http://example.com:9000"
        );
    }

    #[test]
    fn test_resolve_server_url_default() {
        // Remove env var to ensure default is used
        std::env::remove_var("MARMOSYN_SERVER");
        assert_eq!(resolve_server_url(None), DEFAULT_SERVER_URL);
    }

    #[test]
    fn test_resolve_server_url_strips_trailing_slash() {
        assert_eq!(
            resolve_server_url(Some("http://localhost:7855/")),
            "http://localhost:7855"
        );
    }

    #[test]
    fn test_encode_path_simple() {
        assert_eq!(encode_path("documents"), "documents");
    }

    #[test]
    fn test_encode_path_with_special_chars() {
        assert_eq!(encode_path("my job"), "my%20job");
        assert_eq!(encode_path("a/b"), "a%2Fb");
        assert_eq!(encode_path("foo#bar"), "foo%23bar");
    }

    #[test]
    fn test_truncate_body_short() {
        assert_eq!(truncate_body("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_body_long() {
        let long = "a".repeat(300);
        let truncated = truncate_body(&long, 200);
        assert_eq!(truncated.len(), 200);
    }

    #[test]
    fn test_format_connection_error_unreachable() {
        let err = ApiError::Unreachable {
            url: "http://localhost:7855".to_string(),
            reason: "connection refused".to_string(),
        };
        let msg = format_connection_error(&err);
        assert!(msg.contains("Cannot connect"));
        assert!(msg.contains("connection refused"));
        assert!(msg.contains("marmosyn server"));
    }

    #[test]
    fn test_format_connection_error_unauthorized() {
        let err = ApiError::Unauthorized;
        let msg = format_connection_error(&err);
        assert!(msg.contains("Authentication failed"));
        assert!(msg.contains("marmosyn login"));
    }

    #[test]
    fn test_api_client_from_token() {
        let client = ApiClient::from_token("http://localhost:7855", "test-token").unwrap();
        assert_eq!(client.base_url(), "http://localhost:7855");
        assert_eq!(client.token_source(), TokenSource::CliFlag);
    }

    #[test]
    fn test_api_client_debug_hides_token() {
        let client = ApiClient::from_token("http://localhost:7855", "secret-token").unwrap();
        let debug = format!("{:?}", client);
        assert!(!debug.contains("secret-token"));
        assert!(debug.contains("***"));
    }

    #[test]
    fn test_api_error_display() {
        let err = ApiError::ServerError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "something went wrong".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("500"));
        assert!(msg.contains("something went wrong"));
    }
}
