//! Handler for `GET /api/v1/status` — overall server status (sender + receiver).
//!
//! Returns a JSON response with server version, uptime, job count, remote count,
//! and receiver status.

use axum::extract::State;
use axum::Json;

use crate::api::models::StatusResponse;
use crate::api::AppState;

/// Handler for `GET /api/v1/status`.
///
/// Returns overall server status including version, uptime, configured job and
/// remote counts, and whether the receiver is enabled.
pub async fn handle(State(state): State<AppState>) -> Json<StatusResponse> {
    let config = state.config.read().await;

    let uptime_secs = state.start_time.elapsed().as_secs();
    let jobs_count = config.sync.len();
    let remotes_count = config.remote.len();
    let receiver_enabled = config.receiver.as_ref().map(|r| r.enabled).unwrap_or(false);

    Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs,
        jobs_count,
        remotes_count,
        receiver_enabled,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{create_router, AppState};
    use crate::config::types::{AppConfig, ReceiverConfig, Secret, ServerConfig};
    use crate::db::migrations;
    use crate::server::job_manager::JobManager;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::{broadcast, Mutex, RwLock};
    use tower::ServiceExt;

    fn make_state(sync_count: usize, remote_count: usize, receiver: bool) -> AppState {
        use crate::config::types::{RemoteNode, SyncJob, SyncMode};

        let mut syncs = Vec::new();
        for i in 0..sync_count {
            syncs.push(SyncJob {
                name: format!("job-{}", i),
                source: PathBuf::from("/tmp/src"),
                dest: Some("/tmp/dst".to_string()),
                dests: None,
                exclude: vec![],
                encrypt: false,
                mode: SyncMode::Manual,
                schedule: None,
                safety: Default::default(),
            });
        }

        let mut remotes = Vec::new();
        for i in 0..remote_count {
            remotes.push(RemoteNode {
                name: format!("remote-{}", i),
                host: format!("192.168.1.{}:7854", i + 1),
                auth_token: Secret::new("token"),
                tls_ca: None,
                allow_self_signed: false,
            });
        }

        let receiver_config = if receiver {
            Some(ReceiverConfig {
                enabled: true,
                auth_token: Secret::new("recv-token"),
                allowed_paths: vec![],
            })
        } else {
            None
        };

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
            receiver: receiver_config,
            encryption: None,
            remote: remotes,
            sync: syncs,
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
    async fn test_status_empty_config() {
        let state = make_state(0, 0, false);
        let router = create_router(state);

        let req = Request::builder()
            .uri("/api/v1/status")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let status: StatusResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(status.jobs_count, 0);
        assert_eq!(status.remotes_count, 0);
        assert!(!status.receiver_enabled);
        assert!(!status.version.is_empty());
    }

    #[tokio::test]
    async fn test_status_with_jobs_and_remotes() {
        let state = make_state(3, 2, true);
        let router = create_router(state);

        let req = Request::builder()
            .uri("/api/v1/status")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let status: StatusResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(status.jobs_count, 3);
        assert_eq!(status.remotes_count, 2);
        assert!(status.receiver_enabled);
    }

    #[tokio::test]
    async fn test_status_uptime_is_reasonable() {
        let state = make_state(0, 0, false);
        let router = create_router(state);

        let req = Request::builder()
            .uri("/api/v1/status")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let status: StatusResponse = serde_json::from_slice(&body).unwrap();

        // Uptime should be very small (just started)
        assert!(status.uptime_secs < 10);
    }
}
