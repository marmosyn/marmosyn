// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! HTTP API module — axum router, middleware, and request handlers.
//!
//! This module sets up the axum application with all API routes, shared state,
//! authorization middleware, and request tracing. The API is mounted under
//! `/api/v1/`.

pub mod auth;
pub mod handlers;
pub mod models;

use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::extract::Request;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use tokio::sync::broadcast;
use tokio::sync::RwLock;
use tracing::{debug, info_span, warn, Instrument};

use crate::config::types::AppConfig;
use crate::server::job_manager::JobManager;

/// Shared application state passed to all axum handlers.
#[derive(Clone)]
pub struct AppState {
    /// The central job manager for sync job lifecycle.
    pub job_manager: Arc<JobManager>,
    /// Shared, reloadable application configuration.
    pub config: Arc<RwLock<AppConfig>>,
    /// Server start time, used for uptime calculation.
    pub start_time: Instant,
    /// Broadcast sender for triggering graceful shutdown.
    pub shutdown_tx: broadcast::Sender<()>,
}

/// HTTP request tracing middleware.
///
/// Logs every incoming request with method, path, response status code, and
/// latency. Uses structured `tracing` fields so the output is machine-readable
/// when JSON logging is enabled.
///
/// Requests are logged at `DEBUG` level on success (2xx/3xx) and at `WARN`
/// level on client/server errors (4xx/5xx). This keeps normal operation quiet
/// while surfacing problems.
pub async fn request_tracing_middleware(request: Request<Body>, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let start = Instant::now();

    let span = info_span!(
        "http_request",
        method = %method,
        path = %path,
    );

    let response = next.run(request).instrument(span).await;

    let status = response.status().as_u16();
    let latency_ms = start.elapsed().as_millis();

    if response.status().is_client_error() || response.status().is_server_error() {
        warn!(
            method = %method,
            path = %path,
            status = status,
            latency_ms = latency_ms,
            "request completed with error"
        );
    } else {
        debug!(
            method = %method,
            path = %path,
            status = status,
            latency_ms = latency_ms,
            "request completed"
        );
    }

    response
}

/// Creates the full axum [`Router`] with all API routes and middleware.
///
/// Routes:
/// - `GET  /api/v1/health`                — healthcheck (no auth required)
/// - `GET  /api/v1/status`                — overall server status
/// - `GET  /api/v1/jobs`                  — list all sync jobs
/// - `GET  /api/v1/jobs/:name`            — get details for a specific job
/// - `POST /api/v1/jobs/:name/sync`       — trigger manual synchronization
/// - `POST /api/v1/jobs/:name/stop`       — stop current synchronization
/// - `GET  /api/v1/jobs/:name/history`    — get job run history
/// - `GET  /api/v1/remotes`               — list remote nodes
/// - `GET  /api/v1/remotes/:name/ping`    — ping a remote node
/// - `GET  /api/v1/receiver/status`       — receiver status
/// - `GET  /api/v1/receiver/connections`  — active incoming connections
/// - `GET  /api/v1/config`                — get sanitized configuration
/// - `POST /api/v1/config/reload`         — reload configuration from disk
pub fn create_router(state: AppState) -> Router {
    // Routes that require authorization
    let protected_api = Router::new()
        .route("/status", get(handlers::status::handle))
        .route("/jobs", get(handlers::jobs::list))
        .route("/jobs/{name}", get(handlers::jobs::get))
        .route("/jobs/{name}/sync", post(handlers::jobs::trigger_sync))
        .route("/jobs/{name}/stop", post(handlers::jobs::stop))
        .route("/jobs/{name}/history", get(handlers::jobs::history))
        .route("/jobs/{name}/log", get(handlers::jobs::log))
        .route("/remotes", get(handlers::remotes::list))
        .route("/remotes/{name}/ping", get(handlers::remotes::ping))
        .route("/receiver/status", get(handlers::receiver::status))
        .route(
            "/receiver/connections",
            get(handlers::receiver::connections),
        )
        .route("/config", get(handlers::config::get_config))
        .route("/config/reload", post(handlers::config::reload))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ));

    // Health endpoint is public (no auth)
    let public_api = Router::new().route("/health", get(handlers::health::handle));

    // Combine into /api/v1 prefix
    let api = Router::new().merge(public_api).merge(protected_api);

    // Web UI served at root, API takes priority via nesting order
    let web_ui = crate::web::create_web_router();

    Router::new()
        .nest("/api/v1", api)
        .merge(web_ui)
        .layer(middleware::from_fn(request_tracing_middleware))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{AppConfig, ServerConfig};
    use crate::db::migrations;
    use crate::server::job_manager::JobManager;
    use axum::http::{Request, StatusCode};
    use std::path::PathBuf;
    use tokio::sync::Mutex;
    use tower::ServiceExt;

    fn test_state() -> AppState {
        let config = AppConfig {
            server: ServerConfig {
                listen: "0.0.0.0:7854".to_string(),
                api_listen: "127.0.0.1:7855".to_string(),
                log_level: "info".to_string(),
                data_dir: None,
                safety_dir: None,
                auth_token: None,
                tls_cert: None,
                tls_key: None,
            },
            receiver: None,
            encryption: None,
            remote: vec![],
            sync: vec![],
        };

        let conn = rusqlite::Connection::open_in_memory().unwrap();
        migrations::run_migrations(&conn).unwrap();

        let (tx, _rx) = broadcast::channel(16);
        let config = Arc::new(RwLock::new(config));

        let job_manager = Arc::new(JobManager::new(
            Arc::clone(&config),
            Arc::new(Mutex::new(conn)),
            tx.clone(),
            PathBuf::from("/tmp/data"),
            PathBuf::from("/tmp/safety"),
        ));

        AppState {
            job_manager,
            config,
            start_time: Instant::now(),
            shutdown_tx: tx,
        }
    }

    #[tokio::test]
    async fn test_health_endpoint_no_auth() {
        let state = test_state();
        let router = create_router(state);

        let request = Request::builder()
            .uri("/api/v1/health")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_status_endpoint_no_auth_when_token_not_set() {
        let state = test_state();
        let router = create_router(state);

        let request = Request::builder()
            .uri("/api/v1/status")
            .body(Body::empty())
            .unwrap();

        // When auth_token is None in config, all requests pass auth
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_protected_endpoint_requires_auth_when_token_set() {
        let state = test_state();

        // Set an auth token
        {
            let mut config = state.config.write().await;
            config.server.auth_token = Some(crate::config::types::Secret::new("test-secret-token"));
        }

        let router = create_router(state);

        // Request without auth header should be rejected
        let request = Request::builder()
            .uri("/api/v1/status")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_protected_endpoint_with_valid_token() {
        let state = test_state();

        {
            let mut config = state.config.write().await;
            config.server.auth_token = Some(crate::config::types::Secret::new("test-secret-token"));
        }

        let router = create_router(state);

        let request = Request::builder()
            .uri("/api/v1/status")
            .header("Authorization", "Bearer test-secret-token")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_nonexistent_route_returns_404() {
        let state = test_state();
        let router = create_router(state);

        let request = Request::builder()
            .uri("/api/v1/nonexistent")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        // axum returns 404 for unmatched routes
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
