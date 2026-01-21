// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! HTTP API handlers for the receiver subsystem.
//!
//! Implements the following endpoints:
//! - `GET /api/v1/receiver/status` — receiver status, allowed paths, and statistics
//! - `GET /api/v1/receiver/connections` — list active incoming connections

use axum::Json;
use axum::extract::State;

use crate::api::AppState;
use crate::api::models::{AllowedPathInfo, ConnectionsResponse, ReceiverStatusResponse};

/// Handler for `GET /api/v1/receiver/status`.
///
/// Returns the receiver's current state: whether it is enabled, the list of
/// allowed paths (with aliases and usage), active connection count, and
/// cumulative transfer statistics.
///
/// In v0.1, active connection tracking and per-path usage statistics are not
/// yet fully implemented (Phase 9). The endpoint returns configuration-based
/// data with zero counters as placeholders.
pub async fn status(State(state): State<AppState>) -> Json<ReceiverStatusResponse> {
    let config = state.config.read().await;

    let (enabled, allowed_paths) = match &config.receiver {
        Some(recv) => {
            let paths: Vec<AllowedPathInfo> = recv
                .allowed_paths
                .iter()
                .map(|ap| AllowedPathInfo {
                    path: ap.path.to_string_lossy().to_string(),
                    alias: ap.alias.clone(),
                    used_bytes: 0, // TODO: Phase 9 — compute actual disk usage
                })
                .collect();
            (recv.enabled, paths)
        }
        None => (false, vec![]),
    };

    // TODO: Phase 9 — track actual connection and transfer statistics
    // via the transport receiver module.
    let active_connections = 0;
    let total_files_received = 0;
    let total_bytes_received = 0;

    // Try to load cumulative stats from the database (best effort)
    let (db_files, db_bytes) = {
        let conn = state.job_manager.db().lock().await;
        load_receiver_totals(&conn)
    };

    Json(ReceiverStatusResponse {
        enabled,
        allowed_paths,
        active_connections,
        total_files_received: total_files_received + db_files,
        total_bytes_received: total_bytes_received + db_bytes,
    })
}

/// Handler for `GET /api/v1/receiver/connections`.
///
/// Returns the list of currently active incoming connections from remote senders.
///
/// In v0.1, the transport receiver is not yet implemented (Phase 9), so this
/// endpoint always returns an empty list.
pub async fn connections(State(_state): State<AppState>) -> Json<ConnectionsResponse> {
    // TODO: Phase 9 — populate from the transport receiver's connection tracker.
    Json(ConnectionsResponse {
        connections: vec![],
    })
}

/// Loads cumulative receiver statistics from the database.
///
/// Returns `(total_files_received, total_bytes_received)`.
/// On error, returns `(0, 0)`.
fn load_receiver_totals(conn: &rusqlite::Connection) -> (u64, u64) {
    let result = conn.query_row(
        "SELECT COALESCE(SUM(files_received), 0), COALESCE(SUM(bytes_received), 0) \
         FROM receiver_stats",
        [],
        |row| {
            let files: i64 = row.get(0)?;
            let bytes: i64 = row.get(1)?;
            Ok((files as u64, bytes as u64))
        },
    );

    result.unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{AppState, create_router};
    use crate::config::types::{AllowedPath, AppConfig, ReceiverConfig, Secret, ServerConfig};
    use crate::db::migrations;
    use crate::server::job_manager::JobManager;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::{Mutex, RwLock, broadcast};
    use tower::ServiceExt;

    fn make_state(receiver: Option<ReceiverConfig>) -> AppState {
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
            receiver,
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
    async fn test_receiver_status_disabled() {
        let state = make_state(None);
        let router = create_router(state);

        let req = Request::builder()
            .uri("/api/v1/receiver/status")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let status: ReceiverStatusResponse = serde_json::from_slice(&body).unwrap();

        assert!(!status.enabled);
        assert!(status.allowed_paths.is_empty());
        assert_eq!(status.active_connections, 0);
        assert_eq!(status.total_files_received, 0);
        assert_eq!(status.total_bytes_received, 0);
    }

    #[tokio::test]
    async fn test_receiver_status_enabled_with_paths() {
        let receiver = ReceiverConfig {
            enabled: true,
            auth_token: Secret::new("recv-token"),
            allowed_paths: vec![
                AllowedPath {
                    path: PathBuf::from("/mnt/backup"),
                    alias: Some("backup".to_string()),
                },
                AllowedPath {
                    path: PathBuf::from("/data/shared"),
                    alias: None,
                },
            ],
        };

        let state = make_state(Some(receiver));
        let router = create_router(state);

        let req = Request::builder()
            .uri("/api/v1/receiver/status")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let status: ReceiverStatusResponse = serde_json::from_slice(&body).unwrap();

        assert!(status.enabled);
        assert_eq!(status.allowed_paths.len(), 2);

        assert_eq!(status.allowed_paths[0].path, "/mnt/backup");
        assert_eq!(status.allowed_paths[0].alias.as_deref(), Some("backup"));
        assert_eq!(status.allowed_paths[0].used_bytes, 0);

        assert_eq!(status.allowed_paths[1].path, "/data/shared");
        assert!(status.allowed_paths[1].alias.is_none());
    }

    #[tokio::test]
    async fn test_receiver_status_does_not_leak_auth_token() {
        let receiver = ReceiverConfig {
            enabled: true,
            auth_token: Secret::new("super-secret-receiver-token"),
            allowed_paths: vec![],
        };

        let state = make_state(Some(receiver));
        let router = create_router(state);

        let req = Request::builder()
            .uri("/api/v1/receiver/status")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        assert!(
            !body_str.contains("super-secret-receiver-token"),
            "receiver auth token leaked in response body"
        );
    }

    #[tokio::test]
    async fn test_receiver_connections_empty() {
        let state = make_state(None);
        let router = create_router(state);

        let req = Request::builder()
            .uri("/api/v1/receiver/connections")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let conns: ConnectionsResponse = serde_json::from_slice(&body).unwrap();

        assert!(conns.connections.is_empty());
    }

    #[tokio::test]
    async fn test_receiver_status_enabled_false() {
        let receiver = ReceiverConfig {
            enabled: false,
            auth_token: Secret::new("token"),
            allowed_paths: vec![AllowedPath {
                path: PathBuf::from("/some/path"),
                alias: Some("alias".to_string()),
            }],
        };

        let state = make_state(Some(receiver));
        let router = create_router(state);

        let req = Request::builder()
            .uri("/api/v1/receiver/status")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let status: ReceiverStatusResponse = serde_json::from_slice(&body).unwrap();

        // Receiver section exists but enabled is false
        assert!(!status.enabled);
        // Allowed paths should still be listed (config data is shown)
        assert_eq!(status.allowed_paths.len(), 1);
    }

    #[tokio::test]
    async fn test_receiver_totals_from_db() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        migrations::run_migrations(&conn).unwrap();

        // Insert some receiver stats
        conn.execute(
            "INSERT INTO receiver_stats (remote_sender, dest_path, files_received, bytes_received) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["sender-a", "/backup", 10, 5000],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO receiver_stats (remote_sender, dest_path, files_received, bytes_received) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["sender-b", "/backup", 5, 3000],
        )
        .unwrap();

        let (files, bytes) = load_receiver_totals(&conn);
        assert_eq!(files, 15);
        assert_eq!(bytes, 8000);
    }

    #[tokio::test]
    async fn test_receiver_totals_empty_db() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        migrations::run_migrations(&conn).unwrap();

        let (files, bytes) = load_receiver_totals(&conn);
        assert_eq!(files, 0);
        assert_eq!(bytes, 0);
    }
}
