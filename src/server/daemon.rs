// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Server daemon process — startup, path selection, and graceful shutdown.
//!
//! This module implements the main server loop for `marmosyn server`:
//! UID detection, directory creation, configuration loading, tokio runtime
//! initialization, and signal handling for graceful shutdown.
//!
//! When started with `--daemon`, the process forks (on Unix) and the child
//! continues as a background daemon with stdin/stdout/stderr redirected to
//! /dev/null, while the parent exits immediately.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use tokio::sync::{Mutex, RwLock, broadcast};
use tracing::{debug, error, info, warn};

use crate::config::loader;
use crate::config::paths::DefaultPaths;
use crate::config::types::AppConfig;
use crate::config::validation;
use crate::db::migrations;
use crate::server::job_manager::JobManager;

/// Options for starting the server, derived from CLI arguments.
#[derive(Debug, Clone)]
pub struct ServerOptions {
    /// Path to the configuration file (from CLI --config flag).
    pub config_path: Option<PathBuf>,
    /// Whether to run in daemon (background) mode.
    pub daemon: bool,
}

/// Resolved filesystem paths for the server process.
#[derive(Debug, Clone)]
pub struct ServerPaths {
    /// Path to the loaded configuration file.
    pub config_file: PathBuf,
    /// Directory for internal data (SQLite DB, etc.).
    pub data_dir: PathBuf,
    /// Directory for safety backup copies.
    pub safety_dir: PathBuf,
    /// Path to the PID file.
    pub pid_file: PathBuf,
    /// Directory for log files.
    pub log_dir: PathBuf,
}

impl ServerPaths {
    /// Resolves server paths from configuration and UID-based defaults.
    pub fn resolve(config: &AppConfig, defaults: &DefaultPaths) -> Self {
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

        Self {
            config_file: defaults.config_file.clone(),
            data_dir,
            safety_dir,
            pid_file: defaults.pid_file.clone(),
            log_dir: defaults.log_dir.clone(),
        }
    }

    /// Returns the path to the SQLite database file.
    pub fn db_file(&self) -> PathBuf {
        self.data_dir.join("marmosyn.db")
    }
}

/// Creates all necessary directories with appropriate permissions.
///
/// For root: directories get 0755 (data) or 0750 (safety).
/// For regular users: directories get 0700.
pub fn create_server_directories(paths: &ServerPaths) -> Result<()> {
    let dirs_to_create = [
        (&paths.data_dir, "data"),
        (&paths.safety_dir, "safety"),
        (&paths.log_dir, "log"),
    ];

    for (dir, label) in &dirs_to_create {
        if !dir.exists() {
            std::fs::create_dir_all(dir).with_context(|| {
                format!("failed to create {} directory '{}'", label, dir.display())
            })?;

            #[cfg(unix)]
            {
                set_directory_permissions(dir, label)?;
            }

            info!(path = %dir.display(), "created {} directory", label);
        }
    }

    // Ensure PID file parent directory exists
    if let Some(pid_parent) = paths.pid_file.parent()
        && !pid_parent.exists()
    {
        std::fs::create_dir_all(pid_parent).with_context(|| {
            format!(
                "failed to create PID file directory '{}'",
                pid_parent.display()
            )
        })?;
    }

    Ok(())
}

/// Sets Unix permissions on a directory based on UID.
#[cfg(unix)]
fn set_directory_permissions(dir: &Path, label: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let is_root = crate::config::paths::is_root();
    let mode = if is_root {
        if label == "safety" { 0o750 } else { 0o755 }
    } else {
        0o700
    };

    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(dir, perms).with_context(|| {
        format!(
            "failed to set permissions on {} directory '{}'",
            label,
            dir.display()
        )
    })?;

    debug!(
        path = %dir.display(),
        mode = format!("{:o}", mode),
        "set directory permissions"
    );

    Ok(())
}

/// Writes the current process PID to the PID file.
///
/// Returns an error if a PID file already exists and the referenced process
/// is still running.
pub fn write_pid_file(pid_path: &Path) -> Result<()> {
    // Check if a PID file already exists
    if pid_path.exists() {
        let existing_pid = std::fs::read_to_string(pid_path).with_context(|| {
            format!("failed to read existing PID file '{}'", pid_path.display())
        })?;

        let existing_pid = existing_pid.trim();
        if !existing_pid.is_empty() {
            if let Ok(pid) = existing_pid.parse::<u32>()
                && is_process_running(pid)
            {
                anyhow::bail!(
                    "another MarmoSyn server is already running (PID {}). \
                     PID file: {}",
                    pid,
                    pid_path.display()
                );
            }
            // Stale PID file — overwrite it
            warn!(
                pid_file = %pid_path.display(),
                old_pid = %existing_pid,
                "removing stale PID file"
            );
        }
    }

    let pid = std::process::id();
    std::fs::write(pid_path, format!("{}\n", pid))
        .with_context(|| format!("failed to write PID file '{}'", pid_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o644);
        let _ = std::fs::set_permissions(pid_path, perms);
    }

    info!(pid = pid, path = %pid_path.display(), "wrote PID file");
    Ok(())
}

/// Removes the PID file if it exists.
pub fn remove_pid_file(pid_path: &Path) {
    if pid_path.exists() {
        if let Err(err) = std::fs::remove_file(pid_path) {
            warn!(
                path = %pid_path.display(),
                error = %err,
                "failed to remove PID file"
            );
        } else {
            debug!(path = %pid_path.display(), "removed PID file");
        }
    }
}

/// Checks whether a process with the given PID is currently running.
#[cfg(unix)]
fn is_process_running(pid: u32) -> bool {
    // Sending signal 0 checks if the process exists without actually sending a signal.
    // SAFETY: kill with signal 0 is a standard POSIX mechanism for process existence checks.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

#[cfg(not(unix))]
fn is_process_running(_pid: u32) -> bool {
    // On non-Unix platforms, assume not running (conservative).
    false
}

/// Opens (or creates) the SQLite database and runs migrations.
fn open_database(db_path: &Path) -> Result<rusqlite::Connection> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("failed to create database directory '{}'", parent.display())
        })?;
    }

    let conn = rusqlite::Connection::open(db_path)
        .with_context(|| format!("failed to open database at '{}'", db_path.display()))?;

    // Enable WAL mode for better concurrent read performance
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;

    migrations::run_migrations(&conn).context("failed to run database migrations")?;

    info!(path = %db_path.display(), "database initialized");
    Ok(conn)
}

/// Main entry point for the server process.
///
/// This function:
/// 1. Detects UID and selects default paths
/// 2. Loads and validates configuration
/// 3. Creates necessary directories
/// 4. Writes PID file
/// 5. Initializes the database
/// 6. Creates the JobManager
/// 7. Starts the HTTP API server
/// 8. Waits for shutdown signals (SIGTERM/SIGINT)
/// 9. Cleans up (removes PID file, stops jobs)
///
/// # Errors
///
/// Returns an error if any step in the startup sequence fails.
/// Daemonizes the current process on Unix systems.
///
/// Performs a double-fork to fully detach from the controlling terminal:
/// 1. First fork — parent exits, child continues.
/// 2. Call `setsid()` to create a new session.
/// 3. Second fork — first child exits, grandchild continues.
/// 4. Redirect stdin/stdout/stderr to /dev/null.
///
/// On non-Unix platforms this is a no-op and returns `Ok(())`.
///
/// # Errors
///
/// Returns an error if fork or setsid fails.
pub fn daemonize() -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::io::AsRawFd;

        // First fork
        // SAFETY: fork() is a standard POSIX call. We immediately exit in the
        // parent and continue only in the child. No async runtime is active yet
        // at this point (daemonize is called before tokio starts).
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            anyhow::bail!("first fork failed: {}", std::io::Error::last_os_error());
        }
        if pid > 0 {
            // Parent process — exit successfully
            std::process::exit(0);
        }

        // Child: create a new session
        // SAFETY: setsid() is a standard POSIX call.
        if unsafe { libc::setsid() } < 0 {
            anyhow::bail!("setsid failed: {}", std::io::Error::last_os_error());
        }

        // Second fork to prevent the daemon from acquiring a controlling terminal
        // SAFETY: fork() — same rationale as above.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            anyhow::bail!("second fork failed: {}", std::io::Error::last_os_error());
        }
        if pid > 0 {
            // First child exits; grandchild continues as the daemon
            std::process::exit(0);
        }

        // Redirect stdin/stdout/stderr to /dev/null
        let devnull = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .context("failed to open /dev/null")?;

        let null_fd = devnull.as_raw_fd();

        // SAFETY: dup2 is a standard POSIX call; we are redirecting the
        // standard file descriptors to /dev/null which is always valid.
        unsafe {
            libc::dup2(null_fd, libc::STDIN_FILENO);
            libc::dup2(null_fd, libc::STDOUT_FILENO);
            libc::dup2(null_fd, libc::STDERR_FILENO);
        }

        // Change working directory to / to avoid holding a mount busy
        let _ = std::env::set_current_dir("/");

        debug!("daemonized successfully (PID {})", std::process::id());
    }

    #[cfg(not(unix))]
    {
        // Daemon mode is not supported on non-Unix platforms
        warn!("daemon mode is not supported on this platform; running in foreground");
    }

    Ok(())
}

pub async fn run_server(opts: ServerOptions) -> Result<()> {
    // Handle daemon mode before starting the async runtime fully.
    // Note: the actual fork happens in handle_server() *before* the tokio
    // runtime is created. By the time we reach here, the process is already
    // daemonized if --daemon was specified. We log it for clarity.
    if opts.daemon {
        debug!("server starting in daemon mode");
    }

    let start_time = Instant::now();

    // 1. Detect UID and default paths
    let defaults = DefaultPaths::detect();
    info!(
        is_root = crate::config::paths::is_root(),
        config_path = %defaults.config_file.display(),
        data_dir = %defaults.data_dir.display(),
        "detected default paths"
    );

    // 2. Load configuration
    let (config_path, config) =
        loader::load_config(opts.config_path.as_deref()).context("failed to load configuration")?;

    info!(config = %config_path.display(), "loaded configuration");

    // 3. Validate configuration
    validation::validate_config(&config).context("configuration validation failed")?;

    info!("configuration validated successfully");

    // 4. Resolve paths
    let paths = ServerPaths::resolve(&config, &defaults);

    // 5. Create directories
    create_server_directories(&paths)?;

    // 6. Write PID file
    write_pid_file(&paths.pid_file)?;

    // Ensure PID file is cleaned up on exit
    let pid_path_cleanup = paths.pid_file.clone();
    let _pid_guard = scopeguard::guard((), move |_| {
        remove_pid_file(&pid_path_cleanup);
    });

    // 7. Initialize database
    let conn = open_database(&paths.db_file())?;

    // 8. Create shared state
    let (shutdown_tx, _shutdown_rx) = broadcast::channel::<()>(16);
    let config = Arc::new(RwLock::new(config));
    let db = Arc::new(Mutex::new(conn));

    // 9. Create JobManager
    let job_manager = Arc::new(JobManager::new(
        Arc::clone(&config),
        Arc::clone(&db),
        shutdown_tx.clone(),
        paths.data_dir.clone(),
        paths.safety_dir.clone(),
    ));

    job_manager
        .init_jobs()
        .await
        .context("failed to initialize jobs")?;

    info!("job manager initialized");

    // 10. Start WatcherService for `mode = "watch"` jobs
    let mut watcher_service = crate::server::watcher::WatcherService::new();
    watcher_service
        .start_all(Arc::clone(&job_manager), shutdown_tx.clone())
        .await
        .context("failed to start filesystem watchers")?;

    let watcher_count = watcher_service.active_count();
    if watcher_count > 0 {
        info!(count = watcher_count, "filesystem watchers started");
    }

    // 11. Start SchedulerService for `mode = "schedule"` jobs
    let mut scheduler_service = crate::server::scheduler::SchedulerService::new();
    scheduler_service
        .start_all(Arc::clone(&job_manager), shutdown_tx.clone())
        .await
        .context("failed to start cron schedulers")?;

    let scheduler_count = scheduler_service.active_count();
    if scheduler_count > 0 {
        info!(count = scheduler_count, "cron schedulers started");
    }

    // 12. Build the application state for axum
    let app_state = crate::api::AppState {
        job_manager: Arc::clone(&job_manager),
        config: Arc::clone(&config),
        start_time,
        shutdown_tx: shutdown_tx.clone(),
    };

    // 13. Start HTTP API server
    let api_listen = {
        let cfg = config.read().await;
        cfg.server.api_listen.clone()
    };

    let router = crate::api::create_router(app_state);

    let listener = tokio::net::TcpListener::bind(&api_listen)
        .await
        .with_context(|| format!("failed to bind HTTP API to '{}'", api_listen))?;

    let local_addr = listener.local_addr()?;
    info!(
        address = %local_addr,
        "HTTP API server listening"
    );

    eprintln!("MarmoSyn server v{} started", env!("CARGO_PKG_VERSION"));
    eprintln!("  HTTP API: http://{}", local_addr);
    eprintln!("  PID file: {}", paths.pid_file.display());
    eprintln!("  Data dir: {}", paths.data_dir.display());
    if watcher_count > 0 {
        eprintln!("  Watchers: {} job(s)", watcher_count);
    }
    if scheduler_count > 0 {
        eprintln!("  Schedulers: {} job(s)", scheduler_count);
    }
    eprintln!("  Press Ctrl+C to stop.");

    // 14. Serve HTTP with graceful shutdown
    let mut shutdown_rx = shutdown_tx.subscribe();

    let server = axum::serve(listener, router).with_graceful_shutdown(async move {
        // Wait for either a shutdown signal from the channel or OS signals
        tokio::select! {
            _ = signal_shutdown() => {
                info!("received OS shutdown signal");
            }
            _ = shutdown_rx.recv() => {
                info!("received internal shutdown signal");
            }
        }
    });

    // Run the server
    if let Err(err) = server.await {
        error!(error = %err, "HTTP server error");
    }

    // 15. Graceful shutdown
    info!("shutting down...");
    eprintln!("\nShutting down...");

    // Signal all tasks to stop
    let _ = shutdown_tx.send(());

    // Stop watchers and schedulers first (they may trigger syncs)
    watcher_service.stop_all().await;
    scheduler_service.stop_all().await;
    debug!("watchers and schedulers stopped");

    // Stop all running jobs
    job_manager.stop_all().await;

    info!(
        uptime_secs = start_time.elapsed().as_secs(),
        "server stopped"
    );
    eprintln!("Server stopped.");

    Ok(())
}

/// Waits for an OS shutdown signal (SIGTERM or SIGINT on Unix, Ctrl+C elsewhere).
async fn signal_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
        let mut sigint =
            signal(SignalKind::interrupt()).expect("failed to register SIGINT handler");
        let mut sighup = signal(SignalKind::hangup()).expect("failed to register SIGHUP handler");

        tokio::select! {
            _ = sigterm.recv() => {
                info!("received SIGTERM");
            }
            _ = sigint.recv() => {
                info!("received SIGINT");
            }
            _ = sighup.recv() => {
                // SIGHUP traditionally means config reload. For now, treat as shutdown.
                // TODO: Phase 6 Task 605 — implement hot config reload on SIGHUP.
                info!("received SIGHUP (treating as shutdown; config reload not yet implemented)");
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to register Ctrl+C handler");
        info!("received Ctrl+C");
    }
}

#[cfg(test)]
#[cfg(unix)]
mod daemon_tests {
    use super::daemonize;

    #[test]
    fn test_daemonize_function_exists() {
        // We can't actually test fork in a unit test (it would exit the
        // test process), but we verify the function compiles and is callable.
        // The actual daemonization is tested via integration / manual testing.
        let _ = daemonize;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_paths_resolve_defaults() {
        let config: AppConfig = toml::from_str("[server]\n").unwrap();
        let defaults = DefaultPaths::detect();
        let paths = ServerPaths::resolve(&config, &defaults);

        assert_eq!(paths.data_dir, defaults.data_dir);
        assert_eq!(paths.safety_dir, defaults.safety_dir);
        assert_eq!(paths.pid_file, defaults.pid_file);
        assert_eq!(paths.log_dir, defaults.log_dir);
    }

    #[test]
    fn test_server_paths_resolve_custom() {
        let toml_str = r#"
[server]
data_dir = "/custom/data"
safety_dir = "/custom/safety"
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        let defaults = DefaultPaths::detect();
        let paths = ServerPaths::resolve(&config, &defaults);

        assert_eq!(paths.data_dir, PathBuf::from("/custom/data"));
        assert_eq!(paths.safety_dir, PathBuf::from("/custom/safety"));
        // pid_file and log_dir still come from defaults
        assert_eq!(paths.pid_file, defaults.pid_file);
    }

    #[test]
    fn test_server_paths_db_file() {
        let config: AppConfig = toml::from_str("[server]\n").unwrap();
        let defaults = DefaultPaths::detect();
        let paths = ServerPaths::resolve(&config, &defaults);

        let db_file = paths.db_file();
        assert!(db_file.starts_with(&paths.data_dir));
        assert_eq!(
            db_file.file_name().and_then(|f| f.to_str()),
            Some("marmosyn.db")
        );
    }

    #[test]
    fn test_create_server_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = ServerPaths {
            config_file: tmp.path().join("config.toml"),
            data_dir: tmp.path().join("data"),
            safety_dir: tmp.path().join("data/safety"),
            pid_file: tmp.path().join("run/marmosyn.pid"),
            log_dir: tmp.path().join("logs"),
        };

        create_server_directories(&paths).unwrap();

        assert!(paths.data_dir.is_dir());
        assert!(paths.safety_dir.is_dir());
        assert!(paths.log_dir.is_dir());
        // PID file parent should exist
        assert!(paths.pid_file.parent().unwrap().is_dir());
    }

    #[test]
    fn test_create_server_directories_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = ServerPaths {
            config_file: tmp.path().join("config.toml"),
            data_dir: tmp.path().join("data"),
            safety_dir: tmp.path().join("data/safety"),
            pid_file: tmp.path().join("run/marmosyn.pid"),
            log_dir: tmp.path().join("logs"),
        };

        create_server_directories(&paths).unwrap();
        create_server_directories(&paths).unwrap(); // Should not fail
    }

    #[test]
    fn test_write_and_remove_pid_file() {
        let tmp = tempfile::tempdir().unwrap();
        let pid_path = tmp.path().join("test.pid");

        write_pid_file(&pid_path).unwrap();
        assert!(pid_path.exists());

        let content = std::fs::read_to_string(&pid_path).unwrap();
        let pid: u32 = content.trim().parse().unwrap();
        assert_eq!(pid, std::process::id());

        remove_pid_file(&pid_path);
        assert!(!pid_path.exists());
    }

    #[test]
    fn test_write_pid_file_stale() {
        let tmp = tempfile::tempdir().unwrap();
        let pid_path = tmp.path().join("test.pid");

        // Write a stale PID (very unlikely to be a running process)
        std::fs::write(&pid_path, "999999999\n").unwrap();

        // Should succeed (overwriting stale PID)
        write_pid_file(&pid_path).unwrap();

        let content = std::fs::read_to_string(&pid_path).unwrap();
        let pid: u32 = content.trim().parse().unwrap();
        assert_eq!(pid, std::process::id());
    }

    #[test]
    fn test_write_pid_file_self_running() {
        let tmp = tempfile::tempdir().unwrap();
        let pid_path = tmp.path().join("test.pid");

        // Write our own PID (which IS running)
        std::fs::write(&pid_path, format!("{}\n", std::process::id())).unwrap();

        // Should fail because our own process is running
        let result = write_pid_file(&pid_path);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("already running"));
    }

    #[test]
    fn test_remove_pid_file_nonexistent() {
        let tmp = tempfile::tempdir().unwrap();
        let pid_path = tmp.path().join("nonexistent.pid");

        // Should not panic
        remove_pid_file(&pid_path);
    }

    #[test]
    fn test_open_database() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("sub/dir/test.db");

        let conn = open_database(&db_path).unwrap();

        // Verify tables exist
        let count: i64 = conn
            .query_row("SELECT count(*) FROM sync_history", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[cfg(unix)]
    #[test]
    fn test_is_process_running_self() {
        let pid = std::process::id();
        assert!(is_process_running(pid));
    }

    #[cfg(unix)]
    #[test]
    fn test_is_process_running_nonexistent() {
        // PID 999999999 is very unlikely to exist
        assert!(!is_process_running(999_999_999));
    }

    #[test]
    fn test_server_options_debug() {
        let opts = ServerOptions {
            config_path: Some(PathBuf::from("/etc/marmosyn/config.toml")),
            daemon: false,
        };
        let debug_str = format!("{:?}", opts);
        assert!(debug_str.contains("config_path"));
        assert!(debug_str.contains("daemon"));
    }
}
