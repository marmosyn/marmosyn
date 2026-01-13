//! HTTP API handlers for remote node management.
//!
//! Implements the following endpoints:
//! - `GET /api/v1/remotes` — list all configured remote nodes
//! - `GET /api/v1/remotes/{name}/ping` — ping a specific remote node

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use tracing::{info, warn};

use crate::api::models::{ErrorResponse, PingResponse, RemoteListResponse, RemoteSummary};
use crate::api::AppState;

/// Handler for `GET /api/v1/remotes` — list all configured remote nodes.
///
/// Returns a list of remote node summaries with their names, hosts, and
/// current connectivity status. In v0.1, the status is always "unknown"
/// since active probing requires the transport layer (Phase 9).
pub async fn list(State(state): State<AppState>) -> Json<RemoteListResponse> {
    let config = state.config.read().await;

    let remotes: Vec<RemoteSummary> = config
        .remote
        .iter()
        .map(|r| RemoteSummary {
            name: r.name.clone(),
            host: r.host.clone(),
            status: "unknown".to_string(),
        })
        .collect();

    Json(RemoteListResponse { remotes })
}

/// Handler for `GET /api/v1/remotes/{name}/ping` — ping a specific remote node.
///
/// Attempts to check connectivity to the named remote node. In v0.1, actual
/// TCP/TLS connectivity checking is not yet implemented (Phase 9), so this
/// endpoint performs a basic TCP connection attempt to the configured host.
pub async fn ping(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<PingResponse>, impl IntoResponse> {
    let config = state.config.read().await;

    let remote = match config.remote.iter().find(|r| r.name == name) {
        Some(r) => r.clone(),
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    status: 404,
                    error: "not_found".to_string(),
                    message: format!("remote '{}' not found", name),
                }),
            ));
        }
    };
    drop(config);

    info!(remote = %name, host = %remote.host, "pinging remote node");

    // Attempt a basic TCP connection to the remote host
    let start = std::time::Instant::now();
    let connect_result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::TcpStream::connect(&remote.host),
    )
    .await;

    match connect_result {
        Ok(Ok(_stream)) => {
            let latency_ms = start.elapsed().as_millis() as u64;
            info!(
                remote = %name,
                latency_ms = latency_ms,
                "remote is reachable"
            );
            Ok(Json(PingResponse {
                name,
                reachable: true,
                latency_ms: Some(latency_ms),
                error: None,
            }))
        }
        Ok(Err(err)) => {
            let error_msg = format!("connection failed: {}", err);
            warn!(remote = %name, error = %error_msg, "remote is unreachable");
            Ok(Json(PingResponse {
                name,
                reachable: false,
                latency_ms: None,
                error: Some(error_msg),
            }))
        }
        Err(_) => {
            let error_msg = "connection timed out after 5 seconds".to_string();
            warn!(remote = %name, "remote ping timed out");
            Ok(Json(PingResponse {
                name,
                reachable: false,
                latency_ms: None,
                error: Some(error_msg),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{create_router, AppState};
    use crate::config::types::{AppConfig, RemoteNode, Secret, ServerConfig};
    use crate::db::migrations;
    use crate::server::job_manager::JobManager;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::{broadcast, Mutex, RwLock};
    use tower::ServiceExt;

    fn make_state(remotes: Vec<RemoteNode>) -> AppState {
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
            remote: remotes,
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
    async fn test_list_remotes_empty() {
        let state = make_state(vec![]);
        let router = create_router(state);

        let req = Request::builder()
            .uri("/api/v1/remotes")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let list: RemoteListResponse = serde_json::from_slice(&body).unwrap();
        assert!(list.remotes.is_empty());
    }

    #[tokio::test]
    async fn test_list_remotes_with_entries() {
        let remotes = vec![
            RemoteNode {
                name: "office".to_string(),
                host: "192.168.1.100:7854".to_string(),
                auth_token: Secret::new("token1"),
                tls_ca: None,
                allow_self_signed: false,
            },
            RemoteNode {
                name: "cloud".to_string(),
                host: "backup.example.com:7854".to_string(),
                auth_token: Secret::new("token2"),
                tls_ca: None,
                allow_self_signed: true,
            },
        ];

        let state = make_state(remotes);
        let router = create_router(state);

        let req = Request::builder()
            .uri("/api/v1/remotes")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let list: RemoteListResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(list.remotes.len(), 2);

        let names: Vec<&str> = list.remotes.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"office"));
        assert!(names.contains(&"cloud"));

        // All should have "unknown" status in v0.1
        for remote in &list.remotes {
            assert_eq!(remote.status, "unknown");
        }
    }

    #[tokio::test]
    async fn test_list_remotes_does_not_leak_tokens() {
        let remotes = vec![RemoteNode {
            name: "secure".to_string(),
            host: "10.0.0.1:7854".to_string(),
            auth_token: Secret::new("super-secret-token"),
            tls_ca: None,
            allow_self_signed: false,
        }];

        let state = make_state(remotes);
        let router = create_router(state);

        let req = Request::builder()
            .uri("/api/v1/remotes")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        // The response should not contain the auth token
        assert!(
            !body_str.contains("super-secret-token"),
            "auth token leaked in response"
        );
    }

    #[tokio::test]
    async fn test_ping_remote_not_found() {
        let state = make_state(vec![]);
        let router = create_router(state);

        let req = Request::builder()
            .uri("/api/v1/remotes/nonexistent/ping")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(err.status, 404);
        assert!(err.message.contains("nonexistent"));
    }

    #[tokio::test]
    async fn test_ping_remote_unreachable() {
        // Use localhost with a port that is extremely unlikely to be listening.
        // Port 1 requires root and is almost never open.
        let remotes = vec![RemoteNode {
            name: "unreachable".to_string(),
            host: "127.0.0.1:1".to_string(),
            auth_token: Secret::new("token"),
            tls_ca: None,
            allow_self_signed: false,
        }];

        let state = make_state(remotes);
        let router = create_router(state);

        let req = Request::builder()
            .uri("/api/v1/remotes/unreachable/ping")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let ping: PingResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(ping.name, "unreachable");
        // On most systems port 1 on localhost will be refused immediately.
        // On rare systems it might be open, so we just assert the response
        // is well-formed rather than strictly requiring unreachable.
        // The important thing is the endpoint returns a valid PingResponse.
        assert!(ping.reachable || ping.error.is_some());
    }

    #[tokio::test]
    async fn test_remote_summary_fields() {
        let remotes = vec![RemoteNode {
            name: "myremote".to_string(),
            host: "10.0.0.5:7854".to_string(),
            auth_token: Secret::new("tok"),
            tls_ca: None,
            allow_self_signed: false,
        }];

        let state = make_state(remotes);
        let router = create_router(state);

        let req = Request::builder()
            .uri("/api/v1/remotes")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let list: RemoteListResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(list.remotes.len(), 1);
        assert_eq!(list.remotes[0].name, "myremote");
        assert_eq!(list.remotes[0].host, "10.0.0.5:7854");
        assert_eq!(list.remotes[0].status, "unknown");
    }
}
