// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! HTTP API handlers for sync job management.
//!
//! Implements the following endpoints:
//! - `GET /api/v1/jobs` — list all sync jobs
//! - `GET /api/v1/jobs/{name}` — get details for a specific job
//! - `POST /api/v1/jobs/{name}/sync` — trigger manual synchronization
//! - `POST /api/v1/jobs/{name}/stop` — stop current synchronization
//! - `GET /api/v1/jobs/{name}/history` — get job run history
//! - `GET /api/v1/jobs/{name}/log` — get formatted log for a job

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use tracing::{info, warn};

use crate::api::models::{
    DestInfo, ErrorResponse, HistoryEntry, JobDetail, JobListResponse, JobLogResponse, JobSummary,
    SafetyInfo, SyncResponse,
};
use crate::api::AppState;
use crate::config::dest_parser;
use crate::server::job_manager::JobStatus;

/// Query parameters for the history endpoint.
#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    /// Maximum number of history entries to return (default: 20).
    pub limit: Option<usize>,
}

/// Handler for `GET /api/v1/jobs` — list all sync jobs.
pub async fn list(State(state): State<AppState>) -> Json<JobListResponse> {
    let jobs = state.job_manager.list_jobs().await;
    let config = state.config.read().await;

    let summaries: Vec<JobSummary> = config
        .sync
        .iter()
        .map(|sync_job| {
            let status_label = jobs
                .iter()
                .find(|(name, _, _)| name == &sync_job.name)
                .map(|(_, status, _)| status.label())
                .unwrap_or("idle");

            JobSummary {
                name: sync_job.name.clone(),
                source: sync_job.source.to_string_lossy().to_string(),
                status: status_label.to_string(),
                mode: sync_job.mode.to_string(),
                encrypt: sync_job.encrypt,
            }
        })
        .collect();

    Json(JobListResponse { jobs: summaries })
}

/// Handler for `GET /api/v1/jobs/{name}` — get details for a specific job.
pub async fn get(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<JobDetail>, impl IntoResponse> {
    let snapshot = match state.job_manager.get_job(&name).await {
        Some(s) => s,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    status: 404,
                    error: "not_found".to_string(),
                    message: format!("job '{}' not found", name),
                }),
            ));
        }
    };

    let _config = state.config.read().await;

    // Build dest info
    let dests: Vec<DestInfo> = snapshot
        .dests
        .iter()
        .map(|d| {
            let parsed = dest_parser::parse_dest(d);
            match parsed {
                dest_parser::ParsedDest::Local { .. } => DestInfo {
                    target: d.clone(),
                    dest_type: "local".to_string(),
                    remote_name: None,
                    status: "ok".to_string(),
                },
                dest_parser::ParsedDest::Remote {
                    ref remote_name, ..
                } => DestInfo {
                    target: d.clone(),
                    dest_type: "remote".to_string(),
                    remote_name: Some(remote_name.clone()),
                    status: "unknown".to_string(),
                },
            }
        })
        .collect();

    // Compute last sync info
    let (last_sync, last_result_str, files_synced, bytes_transferred) = match &snapshot.last_result
    {
        Some(r) => (
            Some(r.finished_at.to_rfc3339()),
            Some(if r.success {
                "success".to_string()
            } else {
                "failed".to_string()
            }),
            r.files_synced,
            r.bytes_transferred,
        ),
        None => (None, None, 0, 0),
    };

    // Compute next scheduled run
    let next_scheduled = match &snapshot.status {
        JobStatus::Scheduled { next_run } => Some(next_run.to_rfc3339()),
        _ => None,
    };

    // Compute safety current size (best effort — would need to walk safety_dir)
    let safety_current_size = None;

    let detail = JobDetail {
        name: snapshot.name,
        source: snapshot.source,
        status: snapshot.status.label().to_string(),
        mode: snapshot.mode.to_string(),
        encrypt: snapshot.encrypt,
        safety: SafetyInfo {
            enabled: snapshot.safety_enabled,
            retention: snapshot.safety_retention,
            max_size: snapshot.safety_max_size,
            current_size: safety_current_size,
        },
        last_sync,
        last_result: last_result_str,
        files_synced,
        bytes_transferred,
        next_scheduled,
        dests,
    };

    Ok(Json(detail))
}

/// Handler for `POST /api/v1/jobs/{name}/sync` — trigger manual synchronization.
pub async fn trigger_sync(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<SyncResponse>, impl IntoResponse> {
    info!(job = %name, "manual sync triggered via API");

    match state.job_manager.trigger_sync(&name).await {
        Ok(()) => Ok(Json(SyncResponse {
            success: true,
            message: format!("sync triggered for job '{}'", name),
        })),
        Err(err) => {
            let msg = format!("{err:#}");
            warn!(job = %name, error = %msg, "failed to trigger sync");

            // Determine appropriate status code
            let status = if msg.contains("not found") {
                StatusCode::NOT_FOUND
            } else if msg.contains("already running") {
                StatusCode::CONFLICT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };

            Err((
                status,
                Json(ErrorResponse {
                    status: status.as_u16(),
                    error: "sync_trigger_failed".to_string(),
                    message: msg,
                }),
            ))
        }
    }
}

/// Handler for `POST /api/v1/jobs/{name}/stop` — stop current synchronization.
pub async fn stop(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<SyncResponse>, impl IntoResponse> {
    info!(job = %name, "stop requested via API");

    match state.job_manager.stop_job(&name).await {
        Ok(()) => Ok(Json(SyncResponse {
            success: true,
            message: format!("job '{}' stopped", name),
        })),
        Err(err) => {
            let msg = format!("{err:#}");
            warn!(job = %name, error = %msg, "failed to stop job");

            let status = if msg.contains("not found") {
                StatusCode::NOT_FOUND
            } else if msg.contains("not currently running") {
                StatusCode::CONFLICT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };

            Err((
                status,
                Json(ErrorResponse {
                    status: status.as_u16(),
                    error: "stop_failed".to_string(),
                    message: msg,
                }),
            ))
        }
    }
}

/// Handler for `GET /api/v1/jobs/{name}/history` — get job run history.
pub async fn history(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<crate::api::models::JobHistoryResponse>, impl IntoResponse> {
    let limit = query.limit.unwrap_or(20);

    match state.job_manager.get_job_history(&name, Some(limit)).await {
        Ok(rows) => {
            let entries: Vec<HistoryEntry> = rows
                .into_iter()
                .map(|row| HistoryEntry {
                    started_at: row.started_at,
                    finished_at: row.finished_at,
                    status: row.status,
                    files_synced: row.files_synced as u64,
                    bytes_transferred: row.bytes_transferred as u64,
                    error_message: row.error_message,
                })
                .collect();

            Ok(Json(crate::api::models::JobHistoryResponse {
                job_name: name,
                entries,
            }))
        }
        Err(err) => {
            let msg = format!("{err:#}");
            let status = if msg.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };

            Err((
                status,
                Json(ErrorResponse {
                    status: status.as_u16(),
                    error: "history_error".to_string(),
                    message: msg,
                }),
            ))
        }
    }
}

/// Query parameters for the log endpoint.
#[derive(Debug, Deserialize)]
pub struct LogQuery {
    /// Maximum number of log entries to return (default: 50).
    pub limit: Option<usize>,
}

/// `GET /api/v1/jobs/{name}/log`
///
/// Returns formatted log lines for a sync job, derived from its history entries.
/// Each history entry is formatted as a human-readable log line with timestamp,
/// status, file count, and byte count.
pub async fn log(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<LogQuery>,
) -> Result<Json<JobLogResponse>, impl IntoResponse> {
    let limit = query.limit.unwrap_or(50);

    match state.job_manager.get_job_history(&name, Some(limit)).await {
        Ok(rows) => {
            let total = rows.len();
            let lines: Vec<String> = rows
                .into_iter()
                .map(|row| {
                    let finished = row.finished_at.as_deref().unwrap_or("in progress");
                    let error_part = match &row.error_message {
                        Some(msg) => format!(" error=\"{}\"", msg),
                        None => String::new(),
                    };
                    format!(
                        "[{}] status={} finished={} files={} bytes={}{}",
                        row.started_at,
                        row.status,
                        finished,
                        row.files_synced,
                        row.bytes_transferred,
                        error_part,
                    )
                })
                .collect();

            Ok(Json(JobLogResponse {
                job_name: name,
                lines,
                total,
            }))
        }
        Err(err) => {
            let msg = format!("{err:#}");
            let status = if msg.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };

            Err((
                status,
                Json(ErrorResponse {
                    status: status.as_u16(),
                    error: "log_error".to_string(),
                    message: msg,
                }),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{create_router, AppState};
    use crate::config::types::{AppConfig, SafetyConfig, ServerConfig, SyncJob, SyncMode};
    use crate::db::migrations;
    use crate::server::job_manager::JobManager;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::{broadcast, Mutex, RwLock};
    use tower::ServiceExt;

    fn make_state_with_jobs() -> AppState {
        let src = PathBuf::from("/tmp/src");
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
            sync: vec![
                SyncJob {
                    name: "documents".to_string(),
                    source: src.clone(),
                    dest: Some("/tmp/backup/docs".to_string()),
                    dests: None,
                    exclude: vec![],
                    encrypt: false,
                    mode: SyncMode::Manual,
                    schedule: None,
                    safety: SafetyConfig {
                        enabled: true,
                        retention: Some("7d".to_string()),
                        max_size: Some("1GB".to_string()),
                    },
                },
                SyncJob {
                    name: "photos".to_string(),
                    source: src,
                    dest: Some("/tmp/backup/photos".to_string()),
                    dests: None,
                    exclude: vec!["*.tmp".to_string()],
                    encrypt: false,
                    mode: SyncMode::Manual,
                    schedule: None,
                    safety: SafetyConfig::default(),
                },
            ],
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

    async fn init_jobs(state: &AppState) {
        state.job_manager.init_jobs().await.unwrap();
    }

    #[tokio::test]
    async fn test_list_jobs() {
        let state = make_state_with_jobs();
        init_jobs(&state).await;
        let router = create_router(state);

        let req = Request::builder()
            .uri("/api/v1/jobs")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let list: JobListResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(list.jobs.len(), 2);
        let names: Vec<&str> = list.jobs.iter().map(|j| j.name.as_str()).collect();
        assert!(names.contains(&"documents"));
        assert!(names.contains(&"photos"));
    }

    #[tokio::test]
    async fn test_list_jobs_empty() {
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
        let jm = Arc::new(JobManager::new(
            Arc::clone(&config),
            Arc::new(Mutex::new(conn)),
            tx.clone(),
            PathBuf::from("/tmp/data"),
            PathBuf::from("/tmp/safety"),
        ));
        jm.init_jobs().await.unwrap();

        let state = AppState {
            job_manager: jm,
            config,
            start_time: Instant::now(),
            shutdown_tx: tx,
        };

        let router = create_router(state);
        let req = Request::builder()
            .uri("/api/v1/jobs")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let list: JobListResponse = serde_json::from_slice(&body).unwrap();
        assert!(list.jobs.is_empty());
    }

    #[tokio::test]
    async fn test_get_job_found() {
        let state = make_state_with_jobs();
        init_jobs(&state).await;
        let router = create_router(state);

        let req = Request::builder()
            .uri("/api/v1/jobs/documents")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let detail: JobDetail = serde_json::from_slice(&body).unwrap();

        assert_eq!(detail.name, "documents");
        assert_eq!(detail.status, "idle");
        assert_eq!(detail.mode, "manual");
        assert!(!detail.encrypt);
        assert!(detail.safety.enabled);
        assert_eq!(detail.safety.retention.as_deref(), Some("7d"));
        assert_eq!(detail.safety.max_size.as_deref(), Some("1GB"));
        assert!(detail.last_sync.is_none());
        assert_eq!(detail.dests.len(), 1);
        assert_eq!(detail.dests[0].dest_type, "local");
    }

    #[tokio::test]
    async fn test_get_job_not_found() {
        let state = make_state_with_jobs();
        init_jobs(&state).await;
        let router = create_router(state);

        let req = Request::builder()
            .uri("/api/v1/jobs/nonexistent")
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
    async fn test_trigger_sync_not_found() {
        let state = make_state_with_jobs();
        init_jobs(&state).await;
        let router = create_router(state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/jobs/nonexistent/sync")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_stop_not_found() {
        let state = make_state_with_jobs();
        init_jobs(&state).await;
        let router = create_router(state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/jobs/nonexistent/stop")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_stop_not_running() {
        let state = make_state_with_jobs();
        init_jobs(&state).await;
        let router = create_router(state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/jobs/documents/stop")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_history_not_found() {
        let state = make_state_with_jobs();
        init_jobs(&state).await;
        let router = create_router(state);

        let req = Request::builder()
            .uri("/api/v1/jobs/nonexistent/history")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_history_empty() {
        let state = make_state_with_jobs();
        init_jobs(&state).await;
        let router = create_router(state);

        let req = Request::builder()
            .uri("/api/v1/jobs/documents/history")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let hist: crate::api::models::JobHistoryResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(hist.job_name, "documents");
        assert!(hist.entries.is_empty());
    }

    #[tokio::test]
    async fn test_history_with_limit() {
        let state = make_state_with_jobs();
        init_jobs(&state).await;
        let router = create_router(state);

        let req = Request::builder()
            .uri("/api/v1/jobs/documents/history?limit=5")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_list_jobs_status_field() {
        let state = make_state_with_jobs();
        init_jobs(&state).await;
        let router = create_router(state);

        let req = Request::builder()
            .uri("/api/v1/jobs")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let list: JobListResponse = serde_json::from_slice(&body).unwrap();

        for job in &list.jobs {
            // All jobs should have a valid status
            assert!(
                ["idle", "running", "watching", "scheduled", "error"]
                    .contains(&job.status.as_str()),
                "unexpected status: {}",
                job.status
            );
        }
    }

    #[tokio::test]
    async fn test_get_job_photos() {
        let state = make_state_with_jobs();
        init_jobs(&state).await;
        let router = create_router(state);

        let req = Request::builder()
            .uri("/api/v1/jobs/photos")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let detail: JobDetail = serde_json::from_slice(&body).unwrap();

        assert_eq!(detail.name, "photos");
        assert!(!detail.safety.enabled);
        assert!(detail.safety.retention.is_none());
        assert!(detail.safety.max_size.is_none());
    }
}
