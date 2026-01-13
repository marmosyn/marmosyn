//! Handler for the `sync` subcommand — triggers manual synchronization of one or all jobs.
//!
//! When a server is running, this command operates via the HTTP API.
//! Otherwise, it can perform a direct local sync using the core engine.
//!
//! Flow for direct local sync:
//! 1. Load and validate configuration
//! 2. Find the requested job(s)
//! 3. For each job: scan source → scan dest → compute diff → execute plan → record history

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use tracing::{debug, error, info, warn};

use crate::config::loader;
use crate::config::paths::DefaultPaths;
use crate::config::types::{AppConfig, SyncJob};
use crate::config::validation;
use crate::core::dest_router::{DestRouter, OnError, ProgressCallback};
use crate::core::diff::{self, DiffOptions};
use crate::core::excluder::Excluder;
use crate::core::scanner::{self, ScanOptions};
use crate::core::sync_plan::SyncResult;
use crate::crypto::key::EncryptionKey;
use crate::db::{history, migrations};

/// Options for the sync command, derived from CLI arguments.
pub struct SyncOptions<'a> {
    /// Name of a specific job to sync (None means all jobs).
    pub job_name: Option<&'a str>,
    /// If true, show what would be done without making changes.
    pub dry_run: bool,
    /// Path to the configuration file (from CLI --config flag).
    pub config_path: Option<&'a Path>,
    /// If true, sync all jobs regardless of mode.
    pub all: bool,
}

/// Result summary for a single job sync operation.
#[derive(Debug)]
pub struct JobSyncSummary {
    /// Job name.
    pub job_name: String,
    /// Whether the sync succeeded.
    pub success: bool,
    /// Number of files synced (copied + updated).
    pub files_synced: u64,
    /// Number of files deleted.
    pub files_deleted: u64,
    /// Bytes transferred.
    pub bytes_transferred: u64,
    /// Duration of the sync.
    pub duration: std::time::Duration,
    /// Number of errors encountered.
    pub error_count: usize,
}

/// Handles the `sync` subcommand — performs direct local synchronization.
///
/// This function loads config, finds the requested job(s), and runs the
/// full sync pipeline: scan → diff → execute → record history.
///
/// # Errors
///
/// Returns an error if the configuration cannot be loaded, the requested
/// job is not found, or a fatal sync error occurs.
pub fn handle_sync(opts: &SyncOptions<'_>) -> Result<()> {
    // Build a tokio runtime for async operations
    let rt = tokio::runtime::Runtime::new().context("failed to create tokio runtime")?;
    rt.block_on(handle_sync_async(opts))
}

/// Async implementation of the sync handler.
async fn handle_sync_async(opts: &SyncOptions<'_>) -> Result<()> {
    // 1. Load configuration
    let (config_path, config) =
        loader::load_config(opts.config_path).context("failed to load configuration")?;

    info!(
        config = %config_path.display(),
        "loaded configuration"
    );

    // 2. Validate configuration
    validation::validate_config(&config).context("configuration validation failed")?;

    // 3. Determine which jobs to sync
    let jobs_to_sync = select_jobs(&config, opts)?;

    if jobs_to_sync.is_empty() {
        eprintln!("No sync jobs found to execute.");
        return Ok(());
    }

    // 4. Resolve paths
    let defaults = DefaultPaths::detect();
    let data_dir = config
        .server
        .data_dir
        .clone()
        .unwrap_or_else(|| defaults.data_dir.clone());
    let safety_dir = config
        .server
        .safety_dir
        .clone()
        .unwrap_or_else(|| defaults.safety_dir.clone());

    // 5. Initialize database (for history recording)
    let db_path = data_dir.join("marmosyn.db");
    let db_conn = open_database(&db_path)?;
    let db_conn = Arc::new(tokio::sync::Mutex::new(db_conn));

    // 6. Execute each job
    let mut summaries: Vec<JobSyncSummary> = Vec::new();
    let mut any_failed = false;

    for job in &jobs_to_sync {
        eprintln!("─── Syncing job '{}' ───", job.name);
        eprintln!("  Source: {}", job.source.display());

        let result = run_job_sync(job, &config, &safety_dir, opts.dry_run, &db_conn).await;

        match result {
            Ok(summary) => {
                print_job_summary(&summary);
                if !summary.success {
                    any_failed = true;
                }
                summaries.push(summary);
            }
            Err(err) => {
                error!(job = %job.name, error = %err, "sync failed");
                eprintln!("  ERROR: {err:#}");
                any_failed = true;
                summaries.push(JobSyncSummary {
                    job_name: job.name.clone(),
                    success: false,
                    files_synced: 0,
                    files_deleted: 0,
                    bytes_transferred: 0,
                    duration: std::time::Duration::ZERO,
                    error_count: 1,
                });
            }
        }

        eprintln!();
    }

    // 7. Print overall summary
    print_overall_summary(&summaries);

    if any_failed {
        anyhow::bail!("one or more sync jobs failed");
    }

    Ok(())
}

/// Selects which jobs to run based on CLI arguments.
fn select_jobs<'a>(config: &'a AppConfig, opts: &SyncOptions<'_>) -> Result<Vec<&'a SyncJob>> {
    if let Some(name) = opts.job_name {
        // Sync a specific job by name
        let job = config
            .sync
            .iter()
            .find(|j| j.name == name)
            .with_context(|| {
                let available: Vec<&str> = config.sync.iter().map(|j| j.name.as_str()).collect();
                format!(
                    "sync job '{}' not found. Available jobs: {}",
                    name,
                    if available.is_empty() {
                        "(none)".to_string()
                    } else {
                        available.join(", ")
                    }
                )
            })?;
        Ok(vec![job])
    } else if opts.all {
        // Sync all jobs
        Ok(config.sync.iter().collect())
    } else {
        // Sync all manual jobs (or all if --all is implied)
        let jobs: Vec<&SyncJob> = config.sync.iter().collect();
        if jobs.is_empty() {
            eprintln!("No sync jobs defined in configuration.");
        }
        Ok(jobs)
    }
}

/// Opens (or creates) the SQLite database and runs migrations.
fn open_database(db_path: &Path) -> Result<rusqlite::Connection> {
    // Ensure parent directory exists
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("failed to create database directory '{}'", parent.display())
        })?;
    }

    let conn = rusqlite::Connection::open(db_path)
        .with_context(|| format!("failed to open database at '{}'", db_path.display()))?;

    migrations::run_migrations(&conn).context("failed to run database migrations")?;

    debug!(path = %db_path.display(), "database initialized");
    Ok(conn)
}

/// Runs the full sync pipeline for a single job.
///
/// Steps:
/// 1. Build excluder from job patterns
/// 2. Build DestRouter for all destinations
/// 3. For each destination: scan source, scan dest, compute diff, execute plan
/// 4. Record history to database
async fn run_job_sync(
    job: &SyncJob,
    config: &AppConfig,
    safety_dir: &Path,
    dry_run: bool,
    db_conn: &Arc<tokio::sync::Mutex<rusqlite::Connection>>,
) -> Result<JobSyncSummary> {
    let started = Instant::now();

    // Record sync start in history
    let history_id = {
        let conn = db_conn.lock().await;
        history::start_sync(&conn, &job.name)?
    };

    // Build excluder
    let excluder = Excluder::new(&job.exclude.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        .context("failed to compile exclude patterns")?;

    // Collect destinations
    let dests = job.destinations();
    if dests.is_empty() {
        anyhow::bail!("job '{}' has no destinations configured", job.name);
    }

    eprintln!("  Destinations: {}", dests.join(", "));

    // Load encryption key if job has encrypt = true
    let encryption_key: Option<EncryptionKey> = if job.encrypt {
        let enc_config = config.encryption.as_ref().with_context(|| {
            format!(
                "job '{}' has encrypt=true but no [encryption] section in config",
                job.name
            )
        })?;
        let key = crate::crypto::key::load_key(&enc_config.key_source)
            .with_context(|| format!("failed to load encryption key for job '{}'", job.name))?;
        eprintln!("  Encryption: enabled");
        info!(job = %job.name, "encryption enabled; key loaded");
        Some(key)
    } else {
        None
    };

    // Build DestRouter (with optional encryption)
    let _dest_router = DestRouter::new_with_encryption(
        &dests,
        &config.remote,
        Some(&job.safety),
        safety_dir,
        &job.name,
        encryption_key.clone(),
    )
    .with_context(|| format!("failed to create destination router for job '{}'", job.name))?;

    // Scan source directory (blocking I/O → spawn_blocking)
    let source_path = job.source.clone();
    let excluder_clone = excluder.clone();
    let scan_opts = ScanOptions::default();

    eprintln!("  Scanning source...");
    let (source_root, source_tree) = tokio::task::spawn_blocking(move || {
        scanner::scan_directory(&source_path, &excluder_clone, &scan_opts)
    })
    .await
    .context("scanner task panicked")?
    .with_context(|| format!("failed to scan source directory '{}'", job.source.display()))?;

    info!(
        job = %job.name,
        files = source_tree.len(),
        size = source_tree.total_size(),
        "source scan complete"
    );
    eprintln!(
        "  Source: {} files, {} bytes",
        source_tree.len(),
        format_bytes(source_tree.total_size())
    );

    // For each destination, scan and diff separately
    // (the DestRouter executes the plan on all dests, but we need to
    // scan each dest to produce accurate diffs)
    //
    // For local destinations, we can scan the dest. For remote destinations,
    // the RemoteExecutor.list_files() will handle this.
    // We use the executor's list_files() via the DestRouter pattern.

    // Scan destinations and compute a unified plan
    // We'll compute the diff against the first dest (for simplicity in v0.1,
    // each dest gets the same plan based on its own current state).

    // Actually, the proper approach is to execute per-destination:
    // each dest might have different current contents.
    // But DestRouter.execute_plan() applies the same plan to all.
    // For v0.1 we'll scan each dest individually and execute separately.

    let mut combined_result = SyncResult {
        success: true,
        ..SyncResult::default()
    };

    for (dest_idx, dest_str) in dests.iter().enumerate() {
        eprintln!("  Syncing to destination: {}", dest_str);

        let single_router = DestRouter::new_with_encryption(
            &[dest_str],
            &config.remote,
            Some(&job.safety),
            safety_dir,
            &job.name,
            encryption_key.clone(),
        )
        .with_context(|| format!("failed to create router for dest '{}'", dest_str))?;

        // Scan the destination via the executor
        let dest_tree = match scan_destination(&single_router, dest_idx).await {
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

        info!(
            dest = %dest_str,
            files = dest_tree.len(),
            "destination scan complete"
        );

        // Compute diff
        let diff_opts = DiffOptions {
            compare_by_hash: true,
            delete_orphans: true,
            dry_run,
        };

        let plan = diff::compute_diff(&source_tree, &dest_tree, &diff_opts);

        if plan.is_empty() {
            eprintln!("    Already in sync.");
            continue;
        }

        eprintln!(
            "    Plan: {} to copy, {} to update, {} to delete",
            plan.to_copy.len(),
            plan.to_update.len(),
            plan.to_delete.len()
        );

        if dry_run {
            let formatted = diff::format_dry_run(&plan);
            for line in formatted.lines() {
                eprintln!("    {}", line);
            }
            continue;
        }

        // Execute the plan
        let progress_cb: ProgressCallback = Box::new(|progress| {
            if progress.files_total > 0 {
                let pct = (progress.fraction() * 100.0) as u32;
                eprint!(
                    "\r    Progress: {}/{} files ({pct}%)  ",
                    progress.files_done, progress.files_total
                );
            }
        });

        let result = single_router
            .execute_plan(&plan, &source_root, OnError::Skip, Some(&progress_cb))
            .await;

        // Clear progress line
        eprint!("\r                                                        \r");

        // Merge results
        combined_result.files_synced += result.files_synced;
        combined_result.files_deleted += result.files_deleted;
        combined_result.bytes_transferred += result.bytes_transferred;
        combined_result.errors.extend(result.errors);
        if !result.success {
            combined_result.success = false;
        }
    }

    let duration = started.elapsed();
    combined_result.duration = duration;

    // Record history
    {
        let conn = db_conn.lock().await;
        let error_msg = if combined_result.errors.is_empty() {
            None
        } else {
            let msgs: Vec<String> = combined_result
                .errors
                .iter()
                .take(10)
                .map(|e| e.to_string())
                .collect();
            Some(msgs.join("; "))
        };

        let status = if dry_run {
            "dry_run"
        } else if combined_result.success {
            "success"
        } else {
            "failed"
        };

        if let Err(err) = history::finish_sync(
            &conn,
            history_id,
            status,
            (combined_result.files_synced + combined_result.files_deleted) as i64,
            combined_result.bytes_transferred as i64,
            error_msg.as_deref(),
        ) {
            warn!(error = %err, "failed to record sync history");
        }
    }

    Ok(JobSyncSummary {
        job_name: job.name.clone(),
        success: combined_result.success,
        files_synced: combined_result.files_synced,
        files_deleted: combined_result.files_deleted,
        bytes_transferred: combined_result.bytes_transferred,
        duration,
        error_count: combined_result.errors.len(),
    })
}

/// Scans a destination using the first executor in a DestRouter.
///
/// The executor's `list_files()` method returns the files currently at the
/// destination. For local executors this is a filesystem scan; for remote
/// executors it will use the transport protocol.
async fn scan_destination(
    router: &DestRouter,
    _dest_idx: usize,
) -> Result<crate::core::file_tree::FileTree> {
    // The DestRouter doesn't directly expose individual executors,
    // but we constructed it with a single dest, so we can use a
    // workaround: create a temporary plan to list files.
    //
    // Actually, we need a way to list dest files. Since DestRouter
    // wraps executors, and we cannot access them directly, we'll
    // scan the destination ourselves for local paths.

    let descs = router.dest_descriptions();
    if descs.is_empty() {
        return Ok(crate::core::file_tree::FileTree::new());
    }

    let dest_str = descs[0];

    // Parse the dest to determine if it's local
    let parsed = crate::config::dest_parser::parse_dest(dest_str);
    match parsed {
        crate::config::dest_parser::ParsedDest::Local { path } => {
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
        crate::config::dest_parser::ParsedDest::Remote {
            remote_name,
            remote_path,
        } => {
            // Remote scanning is not yet implemented (Phase 9).
            warn!(
                remote = %remote_name,
                path = %remote_path,
                "remote destination scanning not yet implemented; \
                 treating as empty (full sync will be performed)"
            );
            Ok(crate::core::file_tree::FileTree::new())
        }
    }
}

/// Prints a summary for a single job sync.
fn print_job_summary(summary: &JobSyncSummary) {
    let status = if summary.success { "OK" } else { "FAILED" };
    eprintln!("  Result: {status}");
    eprintln!(
        "  Files synced: {}, deleted: {}, bytes: {}",
        summary.files_synced,
        summary.files_deleted,
        format_bytes(summary.bytes_transferred)
    );
    eprintln!("  Duration: {:.2}s", summary.duration.as_secs_f64());
    if summary.error_count > 0 {
        eprintln!("  Errors: {}", summary.error_count);
    }
}

/// Prints the overall summary across all jobs.
fn print_overall_summary(summaries: &[JobSyncSummary]) {
    if summaries.len() <= 1 {
        return;
    }

    eprintln!("═══ Overall Summary ═══");
    let total_synced: u64 = summaries.iter().map(|s| s.files_synced).sum();
    let total_deleted: u64 = summaries.iter().map(|s| s.files_deleted).sum();
    let total_bytes: u64 = summaries.iter().map(|s| s.bytes_transferred).sum();
    let total_errors: usize = summaries.iter().map(|s| s.error_count).sum();
    let succeeded = summaries.iter().filter(|s| s.success).count();
    let failed = summaries.len() - succeeded;

    eprintln!(
        "  Jobs: {} succeeded, {} failed (of {} total)",
        succeeded,
        failed,
        summaries.len()
    );
    eprintln!(
        "  Files synced: {}, deleted: {}, bytes: {}",
        total_synced,
        total_deleted,
        format_bytes(total_bytes)
    );
    if total_errors > 0 {
        eprintln!("  Total errors: {total_errors}");
    }
}

/// Formats a byte count into a human-readable string.
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes_b() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(100), "100 B");
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn test_format_bytes_kb() {
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
    }

    #[test]
    fn test_format_bytes_mb() {
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
    }

    #[test]
    fn test_format_bytes_gb() {
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn test_select_jobs_by_name() {
        let config = test_config();
        let opts = SyncOptions {
            job_name: Some("docs"),
            dry_run: false,
            config_path: None,
            all: false,
        };
        let jobs = select_jobs(&config, &opts).unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].name, "docs");
    }

    #[test]
    fn test_select_jobs_not_found() {
        let config = test_config();
        let opts = SyncOptions {
            job_name: Some("nonexistent"),
            dry_run: false,
            config_path: None,
            all: false,
        };
        let result = select_jobs(&config, &opts);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("nonexistent"));
        assert!(err_msg.contains("docs"));
    }

    #[test]
    fn test_select_jobs_all() {
        let config = test_config_multi();
        let opts = SyncOptions {
            job_name: None,
            dry_run: false,
            config_path: None,
            all: true,
        };
        let jobs = select_jobs(&config, &opts).unwrap();
        assert_eq!(jobs.len(), 2);
    }

    #[test]
    fn test_select_jobs_none_specified() {
        let config = test_config_multi();
        let opts = SyncOptions {
            job_name: None,
            dry_run: false,
            config_path: None,
            all: false,
        };
        let jobs = select_jobs(&config, &opts).unwrap();
        // Returns all jobs when none specified and not --all
        assert_eq!(jobs.len(), 2);
    }

    #[test]
    fn test_select_jobs_empty_config() {
        let config = AppConfig {
            server: crate::config::types::ServerConfig {
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
        let opts = SyncOptions {
            job_name: None,
            dry_run: false,
            config_path: None,
            all: true,
        };
        let jobs = select_jobs(&config, &opts).unwrap();
        assert!(jobs.is_empty());
    }

    #[tokio::test]
    async fn test_open_database_creates_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("sub/dir/marmosyn.db");
        let conn = open_database(&db_path).unwrap();

        // Verify tables were created
        let count: i64 = conn
            .query_row("SELECT count(*) FROM sync_history", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_end_to_end_local_sync() {
        let src_dir = tempfile::tempdir().unwrap();
        let dest_dir = tempfile::tempdir().unwrap();
        let data_dir = tempfile::tempdir().unwrap();

        // Create source files
        std::fs::write(src_dir.path().join("file1.txt"), "hello").unwrap();
        std::fs::create_dir_all(src_dir.path().join("sub")).unwrap();
        std::fs::write(src_dir.path().join("sub/file2.txt"), "world").unwrap();

        // Create config
        let config = AppConfig {
            server: crate::config::types::ServerConfig {
                listen: "0.0.0.0:7854".to_string(),
                api_listen: "127.0.0.1:7855".to_string(),
                log_level: "info".to_string(),
                data_dir: Some(data_dir.path().to_path_buf()),
                safety_dir: Some(data_dir.path().join("safety")),
                auth_token: None,
                tls_cert: None,
                tls_key: None,
            },
            receiver: None,
            encryption: None,
            remote: vec![],
            sync: vec![SyncJob {
                name: "test-job".to_string(),
                source: src_dir.path().to_path_buf(),
                dest: Some(dest_dir.path().to_string_lossy().to_string()),
                dests: None,
                exclude: vec![],
                encrypt: false,
                mode: crate::config::types::SyncMode::Manual,
                schedule: None,
                safety: crate::config::types::SafetyConfig::default(),
            }],
        };

        let safety_dir = data_dir.path().join("safety");
        let db_path = data_dir.path().join("marmosyn.db");
        let conn = open_database(&db_path).unwrap();
        let db_conn = Arc::new(tokio::sync::Mutex::new(conn));

        let job = &config.sync[0];
        let summary = run_job_sync(job, &config, &safety_dir, false, &db_conn)
            .await
            .unwrap();

        assert!(summary.success);
        assert_eq!(summary.files_synced, 2);
        assert_eq!(summary.files_deleted, 0);
        assert!(summary.bytes_transferred > 0);
        assert_eq!(summary.error_count, 0);

        // Verify files were copied
        let dest_file1 = dest_dir.path().join("file1.txt");
        let dest_file2 = dest_dir.path().join("sub/file2.txt");
        assert!(dest_file1.exists());
        assert!(dest_file2.exists());
        assert_eq!(std::fs::read_to_string(dest_file1).unwrap(), "hello");
        assert_eq!(std::fs::read_to_string(dest_file2).unwrap(), "world");

        // Verify history was recorded
        {
            let conn = db_conn.lock().await;
            let entries = history::get_job_history(&conn, "test-job", Some(10)).unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].status, "success");
            assert_eq!(entries[0].files_synced, 2);
        }
    }

    #[tokio::test]
    async fn test_end_to_end_dry_run() {
        let src_dir = tempfile::tempdir().unwrap();
        let dest_dir = tempfile::tempdir().unwrap();
        let data_dir = tempfile::tempdir().unwrap();

        std::fs::write(src_dir.path().join("file.txt"), "content").unwrap();

        let config = AppConfig {
            server: crate::config::types::ServerConfig {
                listen: "0.0.0.0:7854".to_string(),
                api_listen: "127.0.0.1:7855".to_string(),
                log_level: "info".to_string(),
                data_dir: Some(data_dir.path().to_path_buf()),
                safety_dir: Some(data_dir.path().join("safety")),
                auth_token: None,
                tls_cert: None,
                tls_key: None,
            },
            receiver: None,
            encryption: None,
            remote: vec![],
            sync: vec![SyncJob {
                name: "dry-test".to_string(),
                source: src_dir.path().to_path_buf(),
                dest: Some(dest_dir.path().to_string_lossy().to_string()),
                dests: None,
                exclude: vec![],
                encrypt: false,
                mode: crate::config::types::SyncMode::Manual,
                schedule: None,
                safety: crate::config::types::SafetyConfig::default(),
            }],
        };

        let safety_dir = data_dir.path().join("safety");
        let db_path = data_dir.path().join("marmosyn.db");
        let conn = open_database(&db_path).unwrap();
        let db_conn = Arc::new(tokio::sync::Mutex::new(conn));

        let job = &config.sync[0];
        let summary = run_job_sync(job, &config, &safety_dir, true, &db_conn)
            .await
            .unwrap();

        // Dry run should succeed but not copy files
        assert!(summary.success);
        assert_eq!(summary.files_synced, 0);

        // File should NOT exist on dest
        assert!(!dest_dir.path().join("file.txt").exists());

        // History should record as dry_run
        {
            let conn = db_conn.lock().await;
            let entries = history::get_job_history(&conn, "dry-test", Some(10)).unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].status, "dry_run");
        }
    }

    #[tokio::test]
    async fn test_incremental_sync() {
        let src_dir = tempfile::tempdir().unwrap();
        let dest_dir = tempfile::tempdir().unwrap();
        let data_dir = tempfile::tempdir().unwrap();

        // First sync: create file
        std::fs::write(src_dir.path().join("file.txt"), "v1").unwrap();

        let config = AppConfig {
            server: crate::config::types::ServerConfig {
                listen: "0.0.0.0:7854".to_string(),
                api_listen: "127.0.0.1:7855".to_string(),
                log_level: "info".to_string(),
                data_dir: Some(data_dir.path().to_path_buf()),
                safety_dir: Some(data_dir.path().join("safety")),
                auth_token: None,
                tls_cert: None,
                tls_key: None,
            },
            receiver: None,
            encryption: None,
            remote: vec![],
            sync: vec![SyncJob {
                name: "incr-test".to_string(),
                source: src_dir.path().to_path_buf(),
                dest: Some(dest_dir.path().to_string_lossy().to_string()),
                dests: None,
                exclude: vec![],
                encrypt: false,
                mode: crate::config::types::SyncMode::Manual,
                schedule: None,
                safety: crate::config::types::SafetyConfig::default(),
            }],
        };

        let safety_dir = data_dir.path().join("safety");
        let db_path = data_dir.path().join("marmosyn.db");
        let conn = open_database(&db_path).unwrap();
        let db_conn = Arc::new(tokio::sync::Mutex::new(conn));

        let job = &config.sync[0];

        // First sync
        let s1 = run_job_sync(job, &config, &safety_dir, false, &db_conn)
            .await
            .unwrap();
        assert!(s1.success);
        assert_eq!(s1.files_synced, 1);

        // Second sync with no changes — should be a no-op
        let s2 = run_job_sync(job, &config, &safety_dir, false, &db_conn)
            .await
            .unwrap();
        assert!(s2.success);
        assert_eq!(s2.files_synced, 0);
        assert_eq!(s2.files_deleted, 0);

        // Modify file and sync again
        // Need a small delay so mtime differs
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(src_dir.path().join("file.txt"), "v2-updated-content").unwrap();

        let s3 = run_job_sync(job, &config, &safety_dir, false, &db_conn)
            .await
            .unwrap();
        assert!(s3.success);
        assert_eq!(s3.files_synced, 1); // updated
        assert_eq!(
            std::fs::read_to_string(dest_dir.path().join("file.txt")).unwrap(),
            "v2-updated-content"
        );

        // Delete source file and sync — should delete from dest
        std::fs::remove_file(src_dir.path().join("file.txt")).unwrap();

        let s4 = run_job_sync(job, &config, &safety_dir, false, &db_conn)
            .await
            .unwrap();
        assert!(s4.success);
        assert_eq!(s4.files_deleted, 1);
        assert!(!dest_dir.path().join("file.txt").exists());

        // Verify 4 history entries
        {
            let conn = db_conn.lock().await;
            let entries = history::get_job_history(&conn, "incr-test", Some(10)).unwrap();
            assert_eq!(entries.len(), 4);
        }
    }

    #[tokio::test]
    async fn test_sync_with_excludes() {
        let src_dir = tempfile::tempdir().unwrap();
        let dest_dir = tempfile::tempdir().unwrap();
        let data_dir = tempfile::tempdir().unwrap();

        std::fs::write(src_dir.path().join("keep.txt"), "keep").unwrap();
        std::fs::write(src_dir.path().join("skip.tmp"), "skip").unwrap();
        std::fs::write(src_dir.path().join("also.log"), "log").unwrap();

        let config = AppConfig {
            server: crate::config::types::ServerConfig {
                listen: "0.0.0.0:7854".to_string(),
                api_listen: "127.0.0.1:7855".to_string(),
                log_level: "info".to_string(),
                data_dir: Some(data_dir.path().to_path_buf()),
                safety_dir: Some(data_dir.path().join("safety")),
                auth_token: None,
                tls_cert: None,
                tls_key: None,
            },
            receiver: None,
            encryption: None,
            remote: vec![],
            sync: vec![SyncJob {
                name: "excl-test".to_string(),
                source: src_dir.path().to_path_buf(),
                dest: Some(dest_dir.path().to_string_lossy().to_string()),
                dests: None,
                exclude: vec!["*.tmp".to_string(), "*.log".to_string()],
                encrypt: false,
                mode: crate::config::types::SyncMode::Manual,
                schedule: None,
                safety: crate::config::types::SafetyConfig::default(),
            }],
        };

        let safety_dir = data_dir.path().join("safety");
        let db_path = data_dir.path().join("marmosyn.db");
        let conn = open_database(&db_path).unwrap();
        let db_conn = Arc::new(tokio::sync::Mutex::new(conn));

        let job = &config.sync[0];
        let summary = run_job_sync(job, &config, &safety_dir, false, &db_conn)
            .await
            .unwrap();

        assert!(summary.success);
        assert_eq!(summary.files_synced, 1); // only keep.txt

        assert!(dest_dir.path().join("keep.txt").exists());
        assert!(!dest_dir.path().join("skip.tmp").exists());
        assert!(!dest_dir.path().join("also.log").exists());
    }

    // ─── Test helpers ──────────────────────────────────────────────────

    fn test_config() -> AppConfig {
        use std::path::PathBuf;
        AppConfig {
            server: crate::config::types::ServerConfig {
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
                name: "docs".to_string(),
                source: PathBuf::from("/tmp/docs"),
                dest: Some("/tmp/backup".to_string()),
                dests: None,
                exclude: vec![],
                encrypt: false,
                mode: crate::config::types::SyncMode::Manual,
                schedule: None,
                safety: crate::config::types::SafetyConfig::default(),
            }],
        }
    }

    fn test_config_multi() -> AppConfig {
        use std::path::PathBuf;
        let mut config = test_config();
        config.sync.push(SyncJob {
            name: "photos".to_string(),
            source: PathBuf::from("/tmp/photos"),
            dest: Some("/tmp/photo-backup".to_string()),
            dests: None,
            exclude: vec![],
            encrypt: false,
            mode: crate::config::types::SyncMode::Manual,
            schedule: None,
            safety: crate::config::types::SafetyConfig::default(),
        });
        config
    }
}
