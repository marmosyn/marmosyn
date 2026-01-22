// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Job manager — manages the lifecycle of sync jobs on the sender side.
//!
//! The `JobManager` is the central server component that starts, stops, and
//! monitors synchronization jobs. It maintains the state of each job and
//! coordinates with the watcher, scheduler, and sync engine.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use tokio::sync::{Mutex, RwLock, broadcast};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::config::dest_parser;
use crate::config::types::{AppConfig, SyncJob, SyncMode};
use crate::core::dest_router::{DestRouter, OnError, ProgressCallback};
use crate::core::diff::{self, DiffOptions};
use crate::core::excluder::Excluder;
use crate::core::scanner::{self, ScanOptions};
use crate::core::sync_plan::{SyncProgress, SyncResult};
use crate::db::history;

/// Progress information for an ongoing synchronization.
#[derive(Debug, Clone, Default)]
pub struct RunProgress {
    /// Number of files processed so far.
    pub files_done: u64,
    /// Total number of files to process.
    pub files_total: u64,
    /// Bytes transferred so far.
    pub bytes_done: u64,
    /// Total bytes to transfer.
    pub bytes_total: u64,
}

/// The current status of a sync job.
#[derive(Debug, Clone)]
pub enum JobStatus {
    /// Job is idle, waiting for a trigger.
    Idle,
    /// Job is currently running a synchronization.
    Running {
        /// When the current run started.
        started_at: DateTime<Utc>,
        /// Live progress information.
        progress: RunProgress,
    },
    /// Job is in watch mode, monitoring for filesystem changes.
    Watching,
    /// Job is scheduled and waiting for the next cron trigger.
    Scheduled {
        /// The next scheduled run time.
        next_run: DateTime<Utc>,
    },
    /// Job encountered an error.
    Error {
        /// Human-readable error description.
        message: String,
    },
}

impl JobStatus {
    /// Returns a short string label for the status.
    pub fn label(&self) -> &'static str {
        match self {
            JobStatus::Idle => "idle",
            JobStatus::Running { .. } => "running",
            JobStatus::Watching => "watching",
            JobStatus::Scheduled { .. } => "scheduled",
            JobStatus::Error { .. } => "error",
        }
    }
}

/// The last result of a completed sync operation.
#[derive(Debug, Clone)]
pub struct LastSyncResult {
    /// When the sync completed.
    pub finished_at: DateTime<Utc>,
    /// Whether the sync was successful.
    pub success: bool,
    /// Number of files synced (copied + updated).
    pub files_synced: u64,
    /// Number of files deleted.
    pub files_deleted: u64,
    /// Total bytes transferred.
    pub bytes_transferred: u64,
    /// Duration of the sync.
    pub duration_secs: f64,
    /// Error message, if the sync failed.
    pub error_message: Option<String>,
}

/// State of a single sync job managed by the server.
pub struct JobState {
    /// The job configuration.
    pub config: SyncJob,
    /// Current status.
    pub status: JobStatus,
    /// Result of the last completed sync.
    pub last_result: Option<LastSyncResult>,
    /// Handle for a currently running task (for cancellation).
    task_handle: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for JobState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobState")
            .field("name", &self.config.name)
            .field("status", &self.status)
            .field("last_result", &self.last_result)
            .finish()
    }
}

/// Central server component that manages the lifecycle of all sync jobs.
///
/// The `JobManager` holds the shared state for every configured `[[sync]]` job
/// and provides methods to trigger, stop, and query job status. It is designed
/// to be wrapped in `Arc` and shared across axum handlers and background tasks.
pub struct JobManager {
    /// Shared, reloadable application configuration.
    config: Arc<RwLock<AppConfig>>,
    /// SQLite database connection (mutex-protected for async safety).
    db: Arc<Mutex<rusqlite::Connection>>,
    /// Per-job state, keyed by job name.
    jobs: Arc<RwLock<HashMap<String, JobState>>>,
    /// Broadcast channel for signalling graceful shutdown.
    shutdown_tx: broadcast::Sender<()>,
    /// Base directory for safety backup copies.
    safety_dir: PathBuf,
    /// Base data directory (for resolving relative paths).
    data_dir: PathBuf,
}

impl JobManager {
    /// Creates a new `JobManager`, initializing job states from the configuration.
    ///
    /// # Arguments
    ///
    /// * `config` — shared application configuration.
    /// * `db` — initialized SQLite database connection.
    /// * `shutdown_tx` — broadcast sender for graceful shutdown signalling.
    /// * `data_dir` — base data directory.
    /// * `safety_dir` — directory for safety backup copies.
    pub fn new(
        config: Arc<RwLock<AppConfig>>,
        db: Arc<Mutex<rusqlite::Connection>>,
        shutdown_tx: broadcast::Sender<()>,
        data_dir: PathBuf,
        safety_dir: PathBuf,
    ) -> Self {
        Self {
            config,
            db,
            jobs: Arc::new(RwLock::new(HashMap::new())),
            shutdown_tx,
            safety_dir,
            data_dir,
        }
    }

    /// Initializes job states from the current configuration.
    ///
    /// This should be called once after construction and again after a
    /// configuration reload to pick up new/changed/removed jobs.
    pub async fn init_jobs(&self) -> Result<()> {
        let config = self.config.read().await;
        let mut jobs = self.jobs.write().await;

        // Mark stale running entries in the database
        {
            let conn = self.db.lock().await;
            if let Err(err) = history::fail_stale_running(&conn, "server restarted") {
                warn!(error = %err, "failed to mark stale running syncs");
            }
        }

        // Build initial job state for each configured sync job
        for sync_job in &config.sync {
            if jobs.contains_key(&sync_job.name) {
                debug!(job = %sync_job.name, "job already initialized, skipping");
                continue;
            }

            let initial_status = match sync_job.mode {
                SyncMode::Manual => JobStatus::Idle,
                SyncMode::Watch => JobStatus::Idle, // Watcher will transition to Watching
                SyncMode::Schedule => JobStatus::Idle, // Scheduler will set Scheduled
            };

            // Load last result from database
            let last_result = {
                let conn = self.db.lock().await;
                load_last_result(&conn, &sync_job.name)
            };

            info!(
                job = %sync_job.name,
                mode = %sync_job.mode,
                status = initial_status.label(),
                "initialized job state"
            );

            jobs.insert(
                sync_job.name.clone(),
                JobState {
                    config: sync_job.clone(),
                    status: initial_status,
                    last_result,
                    task_handle: None,
                },
            );
        }

        // Remove jobs that are no longer in config
        let config_names: Vec<&str> = config.sync.iter().map(|j| j.name.as_str()).collect();
        jobs.retain(|name, state| {
            if config_names.contains(&name.as_str()) {
                true
            } else {
                info!(job = %name, "removing job no longer in configuration");
                // Cancel any running task
                if let Some(handle) = state.task_handle.take() {
                    handle.abort();
                }
                false
            }
        });

        Ok(())
    }

    /// Returns a snapshot of all job names and their statuses.
    pub async fn list_jobs(&self) -> Vec<(String, JobStatus, Option<LastSyncResult>)> {
        let jobs = self.jobs.read().await;
        jobs.values()
            .map(|state| {
                (
                    state.config.name.clone(),
                    state.status.clone(),
                    state.last_result.clone(),
                )
            })
            .collect()
    }

    /// Returns a detailed snapshot of a specific job.
    pub async fn get_job(&self, name: &str) -> Option<JobSnapshot> {
        let jobs = self.jobs.read().await;
        jobs.get(name).map(|state| JobSnapshot {
            name: state.config.name.clone(),
            source: state.config.source.to_string_lossy().to_string(),
            mode: state.config.mode,
            encrypt: state.config.encrypt,
            status: state.status.clone(),
            last_result: state.last_result.clone(),
            safety_enabled: state.config.safety.enabled,
            safety_retention: state.config.safety.retention.clone(),
            safety_max_size: state.config.safety.max_size.clone(),
            dests: state
                .config
                .destinations()
                .iter()
                .map(|s| s.to_string())
                .collect(),
            exclude: state.config.exclude.clone(),
            schedule: state.config.schedule.clone(),
        })
    }

    /// Returns the names of all configured jobs.
    pub async fn job_names(&self) -> Vec<String> {
        let jobs = self.jobs.read().await;
        jobs.keys().cloned().collect()
    }

    /// Returns whether a job exists.
    pub async fn has_job(&self, name: &str) -> bool {
        let jobs = self.jobs.read().await;
        jobs.contains_key(name)
    }

    /// Returns the status of a specific job.
    pub async fn job_status(&self, name: &str) -> Option<JobStatus> {
        let jobs = self.jobs.read().await;
        jobs.get(name).map(|s| s.status.clone())
    }

    /// Triggers a manual synchronization for a specific job.
    ///
    /// Returns an error if the job is not found or is already running.
    pub async fn trigger_sync(&self, name: &str) -> Result<()> {
        // Check if job exists and is not already running
        {
            let jobs = self.jobs.read().await;
            let state = jobs
                .get(name)
                .with_context(|| format!("job '{}' not found", name))?;

            if matches!(state.status, JobStatus::Running { .. }) {
                anyhow::bail!("job '{}' is already running", name);
            }
        }

        // Set status to Running
        let job_config = {
            let mut jobs = self.jobs.write().await;
            let state = jobs.get_mut(name).context("job disappeared")?;
            state.status = JobStatus::Running {
                started_at: Utc::now(),
                progress: RunProgress::default(),
            };
            state.config.clone()
        };

        // Spawn the sync task
        let job_name = name.to_string();
        let config = Arc::clone(&self.config);
        let db = Arc::clone(&self.db);
        let jobs = Arc::clone(&self.jobs);
        let safety_dir = self.safety_dir.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        let handle = tokio::spawn(async move {
            let result = tokio::select! {
                res = run_sync_task(
                    &job_name,
                    &job_config,
                    config,
                    db.clone(),
                    &safety_dir,
                    jobs.clone(),
                ) => res,
                _ = shutdown_rx.recv() => {
                    info!(job = %job_name, "sync cancelled by shutdown signal");
                    Err(anyhow::anyhow!("cancelled by shutdown"))
                }
            };

            // Update job state with result
            let mut jobs_lock = jobs.write().await;
            if let Some(state) = jobs_lock.get_mut(&job_name) {
                match result {
                    Ok(sync_result) => {
                        let now = Utc::now();
                        let error_msg = if sync_result.errors.is_empty() {
                            None
                        } else {
                            let msgs: Vec<String> = sync_result
                                .errors
                                .iter()
                                .take(10)
                                .map(|e| e.to_string())
                                .collect();
                            Some(msgs.join("; "))
                        };

                        state.last_result = Some(LastSyncResult {
                            finished_at: now,
                            success: sync_result.success,
                            files_synced: sync_result.files_synced,
                            files_deleted: sync_result.files_deleted,
                            bytes_transferred: sync_result.bytes_transferred,
                            duration_secs: sync_result.duration.as_secs_f64(),
                            error_message: error_msg,
                        });

                        if sync_result.success {
                            state.status = JobStatus::Idle;
                        } else {
                            state.status = JobStatus::Error {
                                message: format!(
                                    "sync completed with {} errors",
                                    sync_result.errors.len()
                                ),
                            };
                        }

                        info!(
                            job = %job_name,
                            success = sync_result.success,
                            files = sync_result.files_synced,
                            deleted = sync_result.files_deleted,
                            bytes = sync_result.bytes_transferred,
                            duration_secs = sync_result.duration.as_secs_f64(),
                            "sync completed"
                        );
                    }
                    Err(err) => {
                        let msg = format!("{err:#}");
                        error!(job = %job_name, error = %msg, "sync task failed");

                        state.last_result = Some(LastSyncResult {
                            finished_at: Utc::now(),
                            success: false,
                            files_synced: 0,
                            files_deleted: 0,
                            bytes_transferred: 0,
                            duration_secs: 0.0,
                            error_message: Some(msg.clone()),
                        });
                        state.status = JobStatus::Error { message: msg };
                    }
                }
                state.task_handle = None;
            }
        });

        // Store the task handle for potential cancellation
        {
            let mut jobs = self.jobs.write().await;
            if let Some(state) = jobs.get_mut(name) {
                state.task_handle = Some(handle);
            }
        }

        Ok(())
    }

    /// Stops a currently running sync job.
    ///
    /// Returns an error if the job is not found or is not currently running.
    pub async fn stop_job(&self, name: &str) -> Result<()> {
        let mut jobs = self.jobs.write().await;
        let state = jobs
            .get_mut(name)
            .with_context(|| format!("job '{}' not found", name))?;

        if !matches!(state.status, JobStatus::Running { .. }) {
            anyhow::bail!("job '{}' is not currently running", name);
        }

        // Abort the running task
        if let Some(handle) = state.task_handle.take() {
            handle.abort();
            info!(job = %name, "aborted running sync task");
        }

        state.status = JobStatus::Idle;
        state.last_result = Some(LastSyncResult {
            finished_at: Utc::now(),
            success: false,
            files_synced: 0,
            files_deleted: 0,
            bytes_transferred: 0,
            duration_secs: 0.0,
            error_message: Some("stopped by user".to_string()),
        });

        Ok(())
    }

    /// Gets the sync history for a job from the database.
    pub async fn get_job_history(
        &self,
        name: &str,
        limit: Option<usize>,
    ) -> Result<Vec<history::SyncHistoryRow>> {
        if !self.has_job(name).await {
            anyhow::bail!("job '{}' not found", name);
        }

        let conn = self.db.lock().await;
        let entries = history::get_job_history(&conn, name, limit.map(|l| l as u32))?;
        Ok(entries)
    }

    /// Reloads configuration and re-initializes jobs.
    pub async fn reload_config(&self, new_config: AppConfig) -> Result<()> {
        {
            let mut config = self.config.write().await;
            *config = new_config;
        }
        self.init_jobs().await
    }

    /// Sends a shutdown signal to all running tasks.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
        info!("shutdown signal sent to all jobs");
    }

    /// Stops all running jobs and waits for them to complete.
    pub async fn stop_all(&self) {
        let mut jobs = self.jobs.write().await;
        for (name, state) in jobs.iter_mut() {
            if let Some(handle) = state.task_handle.take() {
                info!(job = %name, "stopping running job");
                handle.abort();
                state.status = JobStatus::Idle;
            }
        }
    }

    /// Returns a reference to the database connection.
    pub fn db(&self) -> &Arc<Mutex<rusqlite::Connection>> {
        &self.db
    }

    /// Returns a reference to the shared config.
    pub fn config(&self) -> &Arc<RwLock<AppConfig>> {
        &self.config
    }

    /// Returns the data directory path.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Returns the safety directory path.
    pub fn safety_dir(&self) -> &Path {
        &self.safety_dir
    }

    /// Returns the shutdown sender for cloning.
    pub fn shutdown_tx(&self) -> &broadcast::Sender<()> {
        &self.shutdown_tx
    }

    /// Returns a reference to the shared jobs map.
    ///
    /// Used by [`WatcherService`] and [`SchedulerService`] to update job
    /// statuses (e.g. transition to `Watching` or `Scheduled { next_run }`).
    pub fn jobs_handle(&self) -> &Arc<RwLock<HashMap<String, JobState>>> {
        &self.jobs
    }
}

/// A read-only snapshot of a job's state, safe to serialize.
#[derive(Debug, Clone)]
pub struct JobSnapshot {
    /// Job name.
    pub name: String,
    /// Source directory path.
    pub source: String,
    /// Sync mode.
    pub mode: SyncMode,
    /// Whether encryption is enabled.
    pub encrypt: bool,
    /// Current status.
    pub status: JobStatus,
    /// Last sync result.
    pub last_result: Option<LastSyncResult>,
    /// Whether safety backup is enabled.
    pub safety_enabled: bool,
    /// Safety retention period.
    pub safety_retention: Option<String>,
    /// Safety max size.
    pub safety_max_size: Option<String>,
    /// List of destination strings.
    pub dests: Vec<String>,
    /// Exclude patterns.
    pub exclude: Vec<String>,
    /// Cron schedule expression.
    pub schedule: Option<String>,
}

/// Runs a synchronization task for a single job.
///
/// This is the core sync pipeline: scan source → scan dest → diff → execute.
async fn run_sync_task(
    job_name: &str,
    job_config: &SyncJob,
    config: Arc<RwLock<AppConfig>>,
    db: Arc<Mutex<rusqlite::Connection>>,
    safety_dir: &Path,
    jobs: Arc<RwLock<HashMap<String, JobState>>>,
) -> Result<SyncResult> {
    let _started = Instant::now();

    // Record sync start in history
    let history_id = {
        let conn = db.lock().await;
        history::start_sync(&conn, job_name)?
    };

    let result = run_sync_pipeline(job_name, job_config, config, safety_dir, jobs).await;

    // Record sync completion in history
    {
        let conn = db.lock().await;
        match &result {
            Ok(sync_result) => {
                let error_msg = if sync_result.errors.is_empty() {
                    None
                } else {
                    let msgs: Vec<String> = sync_result
                        .errors
                        .iter()
                        .take(10)
                        .map(|e| e.to_string())
                        .collect();
                    Some(msgs.join("; "))
                };

                let status = if sync_result.success {
                    "success"
                } else {
                    "failed"
                };

                if let Err(err) = history::finish_sync(
                    &conn,
                    history_id,
                    status,
                    (sync_result.files_synced + sync_result.files_deleted) as i64,
                    sync_result.bytes_transferred as i64,
                    error_msg.as_deref(),
                ) {
                    warn!(error = %err, "failed to record sync completion");
                }
            }
            Err(err) => {
                if let Err(db_err) = history::finish_sync(
                    &conn,
                    history_id,
                    "failed",
                    0,
                    0,
                    Some(&format!("{err:#}")),
                ) {
                    warn!(error = %db_err, "failed to record sync failure");
                }
            }
        }
    }

    result
}

/// The actual sync pipeline: scan → diff → execute for each destination.
async fn run_sync_pipeline(
    job_name: &str,
    job_config: &SyncJob,
    config: Arc<RwLock<AppConfig>>,
    safety_dir: &Path,
    jobs: Arc<RwLock<HashMap<String, JobState>>>,
) -> Result<SyncResult> {
    let started = Instant::now();

    // Build excluder from job patterns
    let patterns: Vec<&str> = job_config.exclude.iter().map(|s| s.as_str()).collect();
    let excluder = Excluder::new(&patterns).context("failed to compile exclude patterns")?;

    // Collect destinations
    let dests = job_config.destinations();
    if dests.is_empty() {
        anyhow::bail!("job '{}' has no destinations configured", job_name);
    }

    // Read remotes and encryption config from config
    let (remotes, encryption_key) = {
        let cfg = config.read().await;
        let key = if job_config.encrypt {
            let enc_config = cfg.encryption.as_ref().with_context(|| {
                format!(
                    "job '{}' has encrypt=true but no [encryption] section in config",
                    job_name
                )
            })?;
            let key = crate::crypto::key::load_key(&enc_config.key_source)
                .with_context(|| format!("failed to load encryption key for job '{}'", job_name))?;
            info!(job = %job_name, "encryption enabled; key loaded");
            Some(key)
        } else {
            None
        };
        (cfg.remote.clone(), key)
    };

    // Scan source directory
    let source_path = job_config.source.clone();
    let excluder_clone = excluder.clone();
    let scan_opts = ScanOptions::default();

    info!(job = %job_name, source = %source_path.display(), "scanning source directory");

    let (source_root, source_tree) = tokio::task::spawn_blocking(move || {
        scanner::scan_directory(&source_path, &excluder_clone, &scan_opts)
    })
    .await
    .context("scanner task panicked")?
    .with_context(|| {
        format!(
            "failed to scan source directory '{}'",
            job_config.source.display()
        )
    })?;

    info!(
        job = %job_name,
        files = source_tree.len(),
        total_bytes = source_tree.total_size(),
        "source scan complete"
    );

    // Execute sync for each destination
    let mut combined = SyncResult {
        success: true,
        ..SyncResult::default()
    };

    for dest_str in &dests {
        info!(job = %job_name, dest = %dest_str, "syncing to destination");

        let single_router = DestRouter::new_with_encryption(
            &[dest_str],
            &remotes,
            Some(&job_config.safety),
            safety_dir,
            job_name,
            encryption_key.clone(),
        )
        .with_context(|| format!("failed to create router for dest '{}'", dest_str))?;

        // Scan destination
        let dest_tree = match scan_dest_for_router(dest_str).await {
            Ok(tree) => tree,
            Err(err) => {
                warn!(
                    dest = %dest_str,
                    error = %err,
                    "failed to scan destination; treating as empty"
                );
                crate::core::file_tree::FileTree::new()
            }
        };

        // Compute diff
        let diff_opts = DiffOptions {
            compare_by_hash: true,
            delete_orphans: true,
            dry_run: false,
        };

        let plan = diff::compute_diff(&source_tree, &dest_tree, &diff_opts);

        if plan.is_empty() {
            debug!(job = %job_name, dest = %dest_str, "already in sync");
            continue;
        }

        info!(
            job = %job_name,
            dest = %dest_str,
            copy = plan.to_copy.len(),
            update = plan.to_update.len(),
            delete = plan.to_delete.len(),
            "executing sync plan"
        );

        // Create a progress callback that updates job state
        let job_name_clone = job_name.to_string();
        let jobs_clone = Arc::clone(&jobs);
        let progress_cb: ProgressCallback = Box::new(move |progress: &SyncProgress| {
            let name = job_name_clone.clone();
            let jobs = Arc::clone(&jobs_clone);
            let p = RunProgress {
                files_done: progress.files_done,
                files_total: progress.files_total,
                bytes_done: progress.bytes_done,
                bytes_total: progress.bytes_total,
            };
            // Fire-and-forget update (non-blocking attempt)
            tokio::spawn(async move {
                let mut lock = jobs.write().await;
                if let Some(state) = lock.get_mut(&name)
                    && let JobStatus::Running {
                        ref mut progress, ..
                    } = state.status
                {
                    *progress = p;
                }
            });
        });

        let result = single_router
            .execute_plan(&plan, &source_root, OnError::Skip, Some(&progress_cb))
            .await;

        // Merge results
        combined.files_synced += result.files_synced;
        combined.files_deleted += result.files_deleted;
        combined.bytes_transferred += result.bytes_transferred;
        combined.errors.extend(result.errors);
        if !result.success {
            combined.success = false;
        }
    }

    combined.duration = started.elapsed();
    Ok(combined)
}

/// Scans a destination directory for its current file listing.
async fn scan_dest_for_router(dest_str: &str) -> Result<crate::core::file_tree::FileTree> {
    let parsed = dest_parser::parse_dest(dest_str);
    match parsed {
        dest_parser::ParsedDest::Local { path } => {
            if !path.exists() {
                debug!(
                    path = %path.display(),
                    "destination directory does not exist; treating as empty"
                );
                return Ok(crate::core::file_tree::FileTree::new());
            }

            let scan_opts = ScanOptions {
                compute_hashes: true,
                ..ScanOptions::default()
            };
            let excluder = Excluder::empty();
            let path_clone = path.clone();

            let (_root, tree) = tokio::task::spawn_blocking(move || {
                scanner::scan_directory(&path_clone, &excluder, &scan_opts)
            })
            .await
            .context("destination scan task panicked")?
            .with_context(|| {
                format!("failed to scan destination directory '{}'", path.display())
            })?;

            Ok(tree)
        }
        dest_parser::ParsedDest::Remote {
            remote_name,
            remote_path,
        } => {
            warn!(
                remote = %remote_name,
                path = %remote_path,
                "remote destination scanning not yet implemented; treating as empty"
            );
            Ok(crate::core::file_tree::FileTree::new())
        }
    }
}

/// Loads the last sync result from the database history.
fn load_last_result(conn: &rusqlite::Connection, job_name: &str) -> Option<LastSyncResult> {
    match history::get_last_sync(conn, job_name) {
        Ok(Some(row)) => {
            let finished_at = row
                .finished_at
                .as_deref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now);

            let success = row.status == "success";

            Some(LastSyncResult {
                finished_at,
                success,
                files_synced: row.files_synced as u64,
                files_deleted: 0, // Not tracked separately in history
                bytes_transferred: row.bytes_transferred as u64,
                duration_secs: 0.0, // Not stored in history yet
                error_message: row.error_message,
            })
        }
        Ok(None) => None,
        Err(err) => {
            warn!(
                job = %job_name,
                error = %err,
                "failed to load last sync result from database"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{SafetyConfig, ServerConfig};
    use crate::db::migrations;

    fn test_config(source: PathBuf, dest: String) -> AppConfig {
        AppConfig {
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
            sync: vec![SyncJob {
                name: "test-job".to_string(),
                source,
                dest: Some(dest),
                dests: None,
                exclude: vec![],
                encrypt: false,
                mode: SyncMode::Manual,
                schedule: None,
                safety: SafetyConfig::default(),
            }],
        }
    }

    fn setup_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        migrations::run_migrations(&conn).unwrap();
        conn
    }

    #[tokio::test]
    async fn test_job_manager_init() {
        let src = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        let config = test_config(
            src.path().to_path_buf(),
            dest.path().to_string_lossy().to_string(),
        );

        let conn = setup_db();
        let (tx, _rx) = broadcast::channel(1);

        let manager = JobManager::new(
            Arc::new(RwLock::new(config)),
            Arc::new(Mutex::new(conn)),
            tx,
            PathBuf::from("/tmp/data"),
            PathBuf::from("/tmp/safety"),
        );

        manager.init_jobs().await.unwrap();

        assert!(manager.has_job("test-job").await);
        assert!(!manager.has_job("nonexistent").await);

        let names = manager.job_names().await;
        assert_eq!(names.len(), 1);
        assert!(names.contains(&"test-job".to_string()));
    }

    #[tokio::test]
    async fn test_job_manager_list_jobs() {
        let src = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        let config = test_config(
            src.path().to_path_buf(),
            dest.path().to_string_lossy().to_string(),
        );

        let conn = setup_db();
        let (tx, _rx) = broadcast::channel(1);

        let manager = JobManager::new(
            Arc::new(RwLock::new(config)),
            Arc::new(Mutex::new(conn)),
            tx,
            PathBuf::from("/tmp/data"),
            PathBuf::from("/tmp/safety"),
        );

        manager.init_jobs().await.unwrap();

        let jobs = manager.list_jobs().await;
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].0, "test-job");
        assert_eq!(jobs[0].1.label(), "idle");
    }

    #[tokio::test]
    async fn test_job_manager_get_job() {
        let src = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        let config = test_config(
            src.path().to_path_buf(),
            dest.path().to_string_lossy().to_string(),
        );

        let conn = setup_db();
        let (tx, _rx) = broadcast::channel(1);

        let manager = JobManager::new(
            Arc::new(RwLock::new(config)),
            Arc::new(Mutex::new(conn)),
            tx,
            PathBuf::from("/tmp/data"),
            PathBuf::from("/tmp/safety"),
        );

        manager.init_jobs().await.unwrap();

        let snapshot = manager.get_job("test-job").await.unwrap();
        assert_eq!(snapshot.name, "test-job");
        assert_eq!(snapshot.mode, SyncMode::Manual);
        assert!(!snapshot.encrypt);
        assert!(!snapshot.safety_enabled);

        let missing = manager.get_job("nonexistent").await;
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_job_manager_trigger_sync() {
        let src = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();

        // Create a source file
        std::fs::write(src.path().join("test.txt"), "hello").unwrap();

        let config = test_config(
            src.path().to_path_buf(),
            dest.path().to_string_lossy().to_string(),
        );

        let conn = setup_db();
        let (tx, _rx) = broadcast::channel(16);

        let safety_dir = tempfile::tempdir().unwrap();

        let manager = Arc::new(JobManager::new(
            Arc::new(RwLock::new(config)),
            Arc::new(Mutex::new(conn)),
            tx,
            PathBuf::from("/tmp/data"),
            safety_dir.path().to_path_buf(),
        ));

        manager.init_jobs().await.unwrap();

        // Trigger sync
        manager.trigger_sync("test-job").await.unwrap();

        // Wait for the sync to complete
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        // Verify file was synced
        assert!(dest.path().join("test.txt").exists());
        assert_eq!(
            std::fs::read_to_string(dest.path().join("test.txt")).unwrap(),
            "hello"
        );

        // Verify job status is no longer running
        let status = manager.job_status("test-job").await.unwrap();
        assert!(
            matches!(status, JobStatus::Idle) || matches!(status, JobStatus::Error { .. }),
            "expected Idle or Error, got {:?}",
            status
        );
    }

    #[tokio::test]
    async fn test_job_manager_trigger_nonexistent() {
        let src = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        let config = test_config(
            src.path().to_path_buf(),
            dest.path().to_string_lossy().to_string(),
        );

        let conn = setup_db();
        let (tx, _rx) = broadcast::channel(1);

        let manager = JobManager::new(
            Arc::new(RwLock::new(config)),
            Arc::new(Mutex::new(conn)),
            tx,
            PathBuf::from("/tmp/data"),
            PathBuf::from("/tmp/safety"),
        );

        manager.init_jobs().await.unwrap();

        let result = manager.trigger_sync("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_job_manager_stop_not_running() {
        let src = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        let config = test_config(
            src.path().to_path_buf(),
            dest.path().to_string_lossy().to_string(),
        );

        let conn = setup_db();
        let (tx, _rx) = broadcast::channel(1);

        let manager = JobManager::new(
            Arc::new(RwLock::new(config)),
            Arc::new(Mutex::new(conn)),
            tx,
            PathBuf::from("/tmp/data"),
            PathBuf::from("/tmp/safety"),
        );

        manager.init_jobs().await.unwrap();

        // Stopping an idle job should fail
        let result = manager.stop_job("test-job").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_job_status_label() {
        assert_eq!(JobStatus::Idle.label(), "idle");
        assert_eq!(
            JobStatus::Running {
                started_at: Utc::now(),
                progress: RunProgress::default(),
            }
            .label(),
            "running"
        );
        assert_eq!(JobStatus::Watching.label(), "watching");
        assert_eq!(
            JobStatus::Scheduled {
                next_run: Utc::now(),
            }
            .label(),
            "scheduled"
        );
        assert_eq!(
            JobStatus::Error {
                message: "test".to_string(),
            }
            .label(),
            "error"
        );
    }

    #[tokio::test]
    async fn test_job_manager_stop_all() {
        let src = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        let config = test_config(
            src.path().to_path_buf(),
            dest.path().to_string_lossy().to_string(),
        );

        let conn = setup_db();
        let (tx, _rx) = broadcast::channel(1);

        let manager = JobManager::new(
            Arc::new(RwLock::new(config)),
            Arc::new(Mutex::new(conn)),
            tx,
            PathBuf::from("/tmp/data"),
            PathBuf::from("/tmp/safety"),
        );

        manager.init_jobs().await.unwrap();
        manager.stop_all().await;

        // Should not panic, all jobs should be idle
        let status = manager.job_status("test-job").await.unwrap();
        assert_eq!(status.label(), "idle");
    }

    #[tokio::test]
    async fn test_job_manager_reload_config() {
        let src = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        let config = test_config(
            src.path().to_path_buf(),
            dest.path().to_string_lossy().to_string(),
        );

        let conn = setup_db();
        let (tx, _rx) = broadcast::channel(1);

        let manager = JobManager::new(
            Arc::new(RwLock::new(config.clone())),
            Arc::new(Mutex::new(conn)),
            tx,
            PathBuf::from("/tmp/data"),
            PathBuf::from("/tmp/safety"),
        );

        manager.init_jobs().await.unwrap();
        assert_eq!(manager.job_names().await.len(), 1);

        // Reload with a config that has an additional job
        let mut new_config = config;
        new_config.sync.push(SyncJob {
            name: "new-job".to_string(),
            source: src.path().to_path_buf(),
            dest: Some(dest.path().to_string_lossy().to_string()),
            dests: None,
            exclude: vec![],
            encrypt: false,
            mode: SyncMode::Manual,
            schedule: None,
            safety: SafetyConfig::default(),
        });

        manager.reload_config(new_config).await.unwrap();
        assert_eq!(manager.job_names().await.len(), 2);
        assert!(manager.has_job("new-job").await);
    }

    #[tokio::test]
    async fn test_job_manager_get_history_nonexistent() {
        let src = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        let config = test_config(
            src.path().to_path_buf(),
            dest.path().to_string_lossy().to_string(),
        );

        let conn = setup_db();
        let (tx, _rx) = broadcast::channel(1);

        let manager = JobManager::new(
            Arc::new(RwLock::new(config)),
            Arc::new(Mutex::new(conn)),
            tx,
            PathBuf::from("/tmp/data"),
            PathBuf::from("/tmp/safety"),
        );

        manager.init_jobs().await.unwrap();

        let result = manager.get_job_history("nonexistent", None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_load_last_result_empty() {
        let conn = setup_db();
        let result = load_last_result(&conn, "no-such-job");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_load_last_result_with_history() {
        let conn = setup_db();
        let id = history::start_sync(&conn, "test-job").unwrap();
        history::finish_sync(&conn, id, "success", 5, 1024, None).unwrap();

        let result = load_last_result(&conn, "test-job");
        assert!(result.is_some());
        let r = result.unwrap();
        assert!(r.success);
        assert_eq!(r.files_synced, 5);
        assert_eq!(r.bytes_transferred, 1024);
        assert!(r.error_message.is_none());
    }
}
