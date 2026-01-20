// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Filesystem watcher service for `mode = "watch"` sync jobs.
//!
//! Uses the `notify` crate to subscribe to filesystem events on source directories,
//! applies debounce logic to coalesce rapid changes, filters events through exclude
//! patterns, and triggers synchronization via the [`JobManager`].
//!
//! The watcher runs as a background task per job and respects graceful shutdown
//! via a broadcast channel.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, info, trace, warn};

use crate::core::excluder::Excluder;
use crate::server::job_manager::JobManager;

/// Default debounce interval in seconds.
const DEFAULT_DEBOUNCE_SECS: u64 = 2;

/// Manages filesystem watchers for all `mode = "watch"` jobs.
///
/// Each watched job gets its own `notify` watcher and a background tokio task
/// that debounces events and triggers synchronization through the [`JobManager`].
pub struct WatcherService {
    /// Handles to spawned watcher tasks so they can be cancelled on shutdown.
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl Default for WatcherService {
    fn default() -> Self {
        Self::new()
    }
}

impl WatcherService {
    /// Creates a new, empty `WatcherService`.
    pub fn new() -> Self {
        Self {
            handles: Vec::new(),
        }
    }

    /// Starts filesystem watchers for all `mode = "watch"` jobs in the configuration.
    ///
    /// For each qualifying job a background task is spawned that:
    /// 1. Subscribes to filesystem events on the job's source directory.
    /// 2. Filters events through the job's exclude patterns.
    /// 3. Applies debounce logic (waits for a quiet period after the last event).
    /// 4. Triggers a sync via the [`JobManager`] when the debounce timer fires.
    ///
    /// The tasks are cancelled when the shutdown signal is received or when
    /// [`stop_all`] is called.
    pub async fn start_all(
        &mut self,
        job_manager: Arc<JobManager>,
        shutdown_tx: broadcast::Sender<()>,
    ) -> Result<()> {
        let config = job_manager.config().read().await;
        let jobs: Vec<_> = config
            .sync
            .iter()
            .filter(|j| j.mode == crate::config::types::SyncMode::Watch)
            .cloned()
            .collect();
        drop(config);

        for job in jobs {
            let source = job.source.clone();
            let job_name = job.name.clone();
            let exclude_patterns = job.exclude.clone();

            let jm = Arc::clone(&job_manager);
            let mut shutdown_rx = shutdown_tx.subscribe();

            let handle = tokio::spawn(async move {
                info!(
                    job = %job_name,
                    source = %source.display(),
                    "starting filesystem watcher"
                );

                // Update job status to Watching
                {
                    let mut jobs_lock = jm.jobs_handle().write().await;
                    if let Some(state) = jobs_lock.get_mut(&job_name) {
                        state.status = crate::server::job_manager::JobStatus::Watching;
                    }
                }

                if let Err(err) = run_watcher_loop(
                    &job_name,
                    &source,
                    &exclude_patterns,
                    Arc::clone(&jm),
                    &mut shutdown_rx,
                )
                .await
                {
                    error!(
                        job = %job_name,
                        error = %err,
                        "watcher loop exited with error"
                    );

                    // Set job status to Error
                    let mut jobs_lock = jm.jobs_handle().write().await;
                    if let Some(state) = jobs_lock.get_mut(&job_name) {
                        state.status = crate::server::job_manager::JobStatus::Error {
                            message: format!("watcher error: {err:#}"),
                        };
                    }
                }

                info!(job = %job_name, "filesystem watcher stopped");
            });

            self.handles.push(handle);
        }

        Ok(())
    }

    /// Stops all running watcher tasks by aborting their handles.
    pub async fn stop_all(&mut self) {
        for handle in self.handles.drain(..) {
            handle.abort();
        }
    }

    /// Returns the number of active watcher tasks.
    pub fn active_count(&self) -> usize {
        self.handles.iter().filter(|h| !h.is_finished()).count()
    }
}

/// The main watcher loop for a single job.
///
/// Sets up a `notify` watcher on the source directory, receives raw events
/// via an mpsc channel, filters them through exclude patterns, and uses a
/// debounce timer to coalesce rapid changes before triggering a sync.
async fn run_watcher_loop(
    job_name: &str,
    source: &Path,
    exclude_patterns: &[String],
    job_manager: Arc<JobManager>,
    shutdown_rx: &mut broadcast::Receiver<()>,
) -> Result<()> {
    // Build excluder from job patterns
    let excluder = Excluder::new(exclude_patterns)
        .context("failed to compile exclude patterns for watcher")?;

    // Create an async-compatible channel for notify events
    let (event_tx, mut event_rx) = mpsc::channel::<notify::Result<Event>>(256);

    // Create the watcher — must be kept alive for the duration of watching
    let mut watcher = RecommendedWatcher::new(
        move |res: notify::Result<Event>| {
            // This callback runs on notify's internal thread; forward to async
            if event_tx.blocking_send(res).is_err() {
                // Channel closed — watcher task has been shut down
            }
        },
        Config::default(),
    )
    .context("failed to create filesystem watcher")?;

    // Canonicalize source so relative-path computation works correctly
    let source_canonical = source
        .canonicalize()
        .with_context(|| format!("failed to canonicalize source path '{}'", source.display()))?;

    watcher
        .watch(&source_canonical, RecursiveMode::Recursive)
        .with_context(|| format!("failed to watch directory '{}'", source_canonical.display()))?;

    info!(
        job = %job_name,
        path = %source_canonical.display(),
        "filesystem watcher registered"
    );

    // Debounce state: we accumulate changed relative paths and wait for a quiet
    // period before triggering a sync.
    let debounce_duration = Duration::from_secs(DEFAULT_DEBOUNCE_SECS);
    let mut pending_changes: HashSet<PathBuf> = HashSet::new();
    let mut debounce_deadline: Option<tokio::time::Instant> = None;

    loop {
        // Determine how long to wait:
        // - If we have pending changes, wait until the debounce deadline
        // - Otherwise, wait indefinitely for new events
        let sleep_future = match debounce_deadline {
            Some(deadline) => tokio::time::sleep_until(deadline),
            None => {
                // Sleep "forever" — we'll be woken by an event or shutdown
                tokio::time::sleep(Duration::from_secs(86400 * 365))
            }
        };

        tokio::select! {
            biased;

            // Shutdown signal — exit immediately
            _ = shutdown_rx.recv() => {
                debug!(job = %job_name, "watcher received shutdown signal");
                break;
            }

            // New filesystem event
            maybe_event = event_rx.recv() => {
                match maybe_event {
                    Some(Ok(event)) => {
                        let changed = process_event(
                            &event,
                            &source_canonical,
                            &excluder,
                            job_name,
                        );
                        if !changed.is_empty() {
                            trace!(
                                job = %job_name,
                                count = changed.len(),
                                "new filesystem changes detected"
                            );
                            pending_changes.extend(changed);
                            // Reset the debounce timer
                            debounce_deadline = Some(
                                tokio::time::Instant::now() + debounce_duration,
                            );
                        }
                    }
                    Some(Err(err)) => {
                        warn!(
                            job = %job_name,
                            error = %err,
                            "filesystem watcher error"
                        );
                    }
                    None => {
                        // Channel closed — watcher was dropped
                        warn!(job = %job_name, "watcher event channel closed");
                        break;
                    }
                }
            }

            // Debounce timer fired — trigger sync
            _ = sleep_future, if debounce_deadline.is_some() => {
                if !pending_changes.is_empty() {
                    let count = pending_changes.len();
                    info!(
                        job = %job_name,
                        changed_files = count,
                        "debounce timer fired; triggering sync"
                    );

                    // Clear state before triggering (so new events during sync
                    // will start a fresh debounce cycle)
                    pending_changes.clear();
                    debounce_deadline = None;

                    // Trigger sync via JobManager (non-blocking)
                    match job_manager.trigger_sync(job_name).await {
                        Ok(()) => {
                            debug!(
                                job = %job_name,
                                "sync triggered successfully by watcher"
                            );
                        }
                        Err(err) => {
                            // Job might already be running — that's OK, we just
                            // log and continue watching
                            warn!(
                                job = %job_name,
                                error = %err,
                                "failed to trigger sync from watcher"
                            );
                        }
                    }
                } else {
                    debounce_deadline = None;
                }
            }
        }
    }

    // Explicitly drop the watcher to unsubscribe from FS events
    drop(watcher);

    Ok(())
}

/// Processes a single `notify` event and returns the set of relative paths
/// that changed and are not excluded.
///
/// Returns an empty set if all paths in the event are excluded or cannot be
/// resolved to a relative path under the source root.
fn process_event(
    event: &Event,
    source_root: &Path,
    excluder: &Excluder,
    job_name: &str,
) -> HashSet<PathBuf> {
    let mut changed = HashSet::new();

    for path in &event.paths {
        // Compute the relative path from source root
        let rel_path = match path.strip_prefix(source_root) {
            Ok(rel) => rel.to_path_buf(),
            Err(_) => {
                // Try canonicalizing the event path first (symlinks, etc.)
                match path.canonicalize() {
                    Ok(canonical) => match canonical.strip_prefix(source_root) {
                        Ok(rel) => rel.to_path_buf(),
                        Err(_) => {
                            trace!(
                                job = %job_name,
                                path = %path.display(),
                                "event path outside source root; ignoring"
                            );
                            continue;
                        }
                    },
                    Err(_) => {
                        // File may have been deleted — try to reconstruct
                        // the relative path from the raw path
                        if let Ok(rel) = path.strip_prefix(source_root) {
                            rel.to_path_buf()
                        } else {
                            trace!(
                                job = %job_name,
                                path = %path.display(),
                                "cannot compute relative path; ignoring"
                            );
                            continue;
                        }
                    }
                }
            }
        };

        // Skip empty relative paths (the root itself)
        if rel_path.as_os_str().is_empty() {
            continue;
        }

        // Apply exclude filter
        if excluder.is_excluded(&rel_path) {
            trace!(
                job = %job_name,
                path = %rel_path.display(),
                "change excluded by pattern"
            );
            continue;
        }

        changed.insert(rel_path);
    }

    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_process_event_included_file() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().canonicalize().unwrap();
        let excluder = Excluder::empty();

        let file_path = source.join("test.txt");
        fs::write(&file_path, "data").unwrap();

        let event = Event {
            kind: notify::EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Content,
            )),
            paths: vec![file_path],
            attrs: Default::default(),
        };

        let changed = process_event(&event, &source, &excluder, "test-job");
        assert_eq!(changed.len(), 1);
        assert!(changed.contains(&PathBuf::from("test.txt")));
    }

    #[test]
    fn test_process_event_excluded_file() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().canonicalize().unwrap();
        let excluder = Excluder::new(&["*.tmp"]).unwrap();

        let file_path = source.join("cache.tmp");
        fs::write(&file_path, "data").unwrap();

        let event = Event {
            kind: notify::EventKind::Create(notify::event::CreateKind::File),
            paths: vec![file_path],
            attrs: Default::default(),
        };

        let changed = process_event(&event, &source, &excluder, "test-job");
        assert!(changed.is_empty());
    }

    #[test]
    fn test_process_event_outside_source() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().canonicalize().unwrap();
        let excluder = Excluder::empty();

        let event = Event {
            kind: notify::EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Content,
            )),
            paths: vec![PathBuf::from("/some/other/path/file.txt")],
            attrs: Default::default(),
        };

        let changed = process_event(&event, &source, &excluder, "test-job");
        assert!(changed.is_empty());
    }

    #[test]
    fn test_process_event_nested_file() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().canonicalize().unwrap();
        let excluder = Excluder::empty();

        let nested_dir = source.join("sub").join("dir");
        fs::create_dir_all(&nested_dir).unwrap();
        let file_path = nested_dir.join("deep.txt");
        fs::write(&file_path, "deep").unwrap();

        let event = Event {
            kind: notify::EventKind::Create(notify::event::CreateKind::File),
            paths: vec![file_path],
            attrs: Default::default(),
        };

        let changed = process_event(&event, &source, &excluder, "test-job");
        assert_eq!(changed.len(), 1);
        assert!(changed.contains(&PathBuf::from("sub/dir/deep.txt")));
    }

    #[test]
    fn test_process_event_multiple_paths() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().canonicalize().unwrap();
        let excluder = Excluder::new(&["*.log"]).unwrap();

        let file_a = source.join("a.txt");
        let file_b = source.join("b.log");
        let file_c = source.join("c.rs");
        fs::write(&file_a, "a").unwrap();
        fs::write(&file_b, "b").unwrap();
        fs::write(&file_c, "c").unwrap();

        let event = Event {
            kind: notify::EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Content,
            )),
            paths: vec![file_a, file_b, file_c],
            attrs: Default::default(),
        };

        let changed = process_event(&event, &source, &excluder, "test-job");
        // b.log should be excluded
        assert_eq!(changed.len(), 2);
        assert!(changed.contains(&PathBuf::from("a.txt")));
        assert!(changed.contains(&PathBuf::from("c.rs")));
    }

    #[test]
    fn test_process_event_root_path_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().canonicalize().unwrap();
        let excluder = Excluder::empty();

        // Event on the root directory itself
        let event = Event {
            kind: notify::EventKind::Modify(notify::event::ModifyKind::Name(
                notify::event::RenameMode::Any,
            )),
            paths: vec![source.clone()],
            attrs: Default::default(),
        };

        let changed = process_event(&event, &source, &excluder, "test-job");
        assert!(changed.is_empty());
    }

    #[test]
    fn test_process_event_deleted_file() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().canonicalize().unwrap();
        let excluder = Excluder::empty();

        // Simulate a delete event — the file no longer exists on disk
        let file_path = source.join("deleted.txt");
        // Don't create the file — it's been deleted

        let event = Event {
            kind: notify::EventKind::Remove(notify::event::RemoveKind::File),
            paths: vec![file_path],
            attrs: Default::default(),
        };

        let changed = process_event(&event, &source, &excluder, "test-job");
        assert_eq!(changed.len(), 1);
        assert!(changed.contains(&PathBuf::from("deleted.txt")));
    }

    #[test]
    fn test_watcher_service_new() {
        let service = WatcherService::new();
        assert_eq!(service.active_count(), 0);
    }
}
