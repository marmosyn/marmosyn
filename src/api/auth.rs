//! Bearer token authorization middleware for the HTTP API.
//!
//! Validates the `Authorization: Bearer <token>` header against the
//! `[server].auth_token` value from the configuration. Requests to
//! `/api/v1/health` are exempt from authorization.
//!
//! If `auth_token` is not configured (None), all requests are allowed through.

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use tracing::{debug, warn};

use crate::api::models::ErrorResponse;
use crate::api::AppState;

/// axum middleware that validates Bearer token authorization.
///
/// If `[server].auth_token` is configured, every request (except health)
/// must include a valid `Authorization: Bearer <token>` header. If no
/// auth_token is configured, all requests pass through.
pub async fn auth_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Read the configured auth token
    let config = state.config.read().await;
    let expected_token = match &config.server.auth_token {
        Some(token) => token.expose().to_string(),
        None => {
            // No auth token configured — allow all requests
            drop(config);
            return next.run(request).await;
        }
    };
    drop(config);

    // Extract the Authorization header
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(header_value) => {
            // Expect "Bearer <token>" format
            if let Some(token) = header_value.strip_prefix("Bearer ") {
                if token == expected_token {
                    debug!("request authorized via Bearer token");
                    next.run(request).await
                } else {
                    warn!("invalid Bearer token provided");
                    unauthorized_response("invalid token")
                }
            } else {
                warn!(
                    header = %header_value,
                    "malformed Authorization header: expected 'Bearer <token>'"
                );
                unauthorized_response("malformed Authorization header: expected 'Bearer <token>'")
            }
        }
        None => {
            warn!(
                uri = %request.uri(),
                "missing Authorization header"
            );
            unauthorized_response("missing Authorization header")
        }
    }
}

/// Constructs a 401 Unauthorized JSON response.
fn unauthorized_response(message: &str) -> Response {
    let body = ErrorResponse {
        status: 401,
        error: "unauthorized".to_string(),
        message: message.to_string(),
    };
    (StatusCode::UNAUTHORIZED, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{create_router, AppState};
    use crate::config::types::{AppConfig, Secret, ServerConfig};
    use crate::db::migrations;
    use crate::server::job_manager::JobManager;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::{broadcast, Mutex, RwLock};
    use tower::ServiceExt;

    fn make_state(auth_token: Option<&str>) -> AppState {
        let config = AppConfig {
            server: ServerConfig {
                listen: "0.0.0.0:7854".to_string(),
                api_listen: "127.0.0.1:7855".to_string(),
                log_level: "info".to_string(),
                data_dir: None,
                safety_dir: None,
                auth_token: auth_token.map(Secret::new),
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
    async fn test_no_auth_token_configured_allows_all() {
        let state = make_state(None);
        let router = create_router(state);

        let request = Request::builder()
            .uri("/api/v1/status")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_valid_bearer_token() {
        let state = make_state(Some("my-secret-token"));
        let router = create_router(state);

        let request = Request::builder()
            .uri("/api/v1/status")
            .header("Authorization", "Bearer my-secret-token")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_invalid_bearer_token() {
        let state = make_state(Some("my-secret-token"));
        let router = create_router(state);

        let request = Request::builder()
            .uri("/api/v1/status")
            .header("Authorization", "Bearer wrong-token")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_missing_auth_header() {
        let state = make_state(Some("my-secret-token"));
        let router = create_router(state);

        let request = Request::builder()
            .uri("/api/v1/status")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_malformed_auth_header() {
        let state = make_state(Some("my-secret-token"));
        let router = create_router(state);

        let request = Request::builder()
            .uri("/api/v1/status")
            .header("Authorization", "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_health_endpoint_bypasses_auth() {
        let state = make_state(Some("my-secret-token"));
        let router = create_router(state);

        // Health endpoint is on the public router, not behind auth middleware
        let request = Request::builder()
            .uri("/api/v1/health")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_unauthorized_response_format() {
        let response = unauthorized_response("test error");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
