//! Cron-based scheduler service for `mode = "schedule"` sync jobs.
//!
//! Parses cron expressions and computes the next run time, then waits
//! using `tokio::time::sleep_until` before triggering a full job sync
//! via the [`JobManager`].
//!
//! Each scheduled job gets its own background tokio task that loops:
//! 1. Compute the next scheduled time from the cron expression.
//! 2. Sleep until that time (or until shutdown).
//! 3. Trigger a sync via the [`JobManager`].
//! 4. Wait for the sync to complete, then go back to step 1.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use cron::Schedule;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use crate::server::job_manager::{JobManager, JobStatus};

/// Manages cron-based scheduler tasks for all `mode = "schedule"` jobs.
///
/// Each scheduled job runs in its own tokio task that sleeps until the next
/// cron-determined time, triggers a sync, and then repeats.
pub struct SchedulerService {
    /// Handles to spawned scheduler tasks so they can be cancelled on shutdown.
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl Default for SchedulerService {
    fn default() -> Self {
        Self::new()
    }
}

impl SchedulerService {
    /// Creates a new, empty `SchedulerService`.
    pub fn new() -> Self {
        Self {
            handles: Vec::new(),
        }
    }

    /// Starts scheduler tasks for all `mode = "schedule"` jobs in the configuration.
    ///
    /// For each qualifying job a background task is spawned that:
    /// 1. Parses the cron expression from the job's `schedule` field.
    /// 2. Computes the next run time.
    /// 3. Updates the job's status to `Scheduled { next_run }`.
    /// 4. Sleeps until the next run time (or until shutdown).
    /// 5. Triggers a sync via the [`JobManager`].
    /// 6. Waits for the sync to finish, then loops back to step 2.
    pub async fn start_all(
        &mut self,
        job_manager: Arc<JobManager>,
        shutdown_tx: broadcast::Sender<()>,
    ) -> Result<()> {
        let config = job_manager.config().read().await;
        let jobs: Vec<_> = config
            .sync
            .iter()
            .filter(|j| j.mode == crate::config::types::SyncMode::Schedule)
            .cloned()
            .collect();
        drop(config);

        for job in jobs {
            let job_name = job.name.clone();
            let schedule_expr = match &job.schedule {
                Some(expr) => expr.clone(),
                None => {
                    warn!(
                        job = %job_name,
                        "schedule mode job has no cron expression; skipping"
                    );
                    continue;
                }
            };

            let jm = Arc::clone(&job_manager);
            let mut shutdown_rx = shutdown_tx.subscribe();

            let handle = tokio::spawn(async move {
                info!(
                    job = %job_name,
                    schedule = %schedule_expr,
                    "starting cron scheduler"
                );

                if let Err(err) =
                    run_scheduler_loop(&job_name, &schedule_expr, Arc::clone(&jm), &mut shutdown_rx)
                        .await
                {
                    error!(
                        job = %job_name,
                        error = %err,
                        "scheduler loop exited with error"
                    );

                    // Set job status to Error
                    let mut jobs_lock = jm.jobs_handle().write().await;
                    if let Some(state) = jobs_lock.get_mut(&job_name) {
                        state.status = JobStatus::Error {
                            message: format!("scheduler error: {err:#}"),
                        };
                    }
                }

                info!(job = %job_name, "cron scheduler stopped");
            });

            self.handles.push(handle);
        }

        Ok(())
    }

    /// Stops all running scheduler tasks by aborting their handles.
    pub async fn stop_all(&mut self) {
        for handle in self.handles.drain(..) {
            handle.abort();
        }
    }

    /// Returns the number of active scheduler tasks.
    pub fn active_count(&self) -> usize {
        self.handles.iter().filter(|h| !h.is_finished()).count()
    }
}

/// The main scheduler loop for a single job.
///
/// Parses the cron expression, computes the next fire time, sleeps until then,
/// triggers a sync, and repeats until shutdown.
async fn run_scheduler_loop(
    job_name: &str,
    schedule_expr: &str,
    job_manager: Arc<JobManager>,
    shutdown_rx: &mut broadcast::Receiver<()>,
) -> Result<()> {
    let schedule = Schedule::from_str(schedule_expr).with_context(|| {
        format!(
            "invalid cron expression '{}' for job '{}'",
            schedule_expr, job_name
        )
    })?;

    loop {
        // Compute the next run time
        let now = Utc::now();
        let next_run = match schedule.upcoming(Utc).next() {
            Some(t) => t,
            None => {
                warn!(
                    job = %job_name,
                    "cron schedule has no upcoming runs; stopping scheduler"
                );
                break;
            }
        };

        let wait_duration = (next_run - now).to_std().unwrap_or(Duration::ZERO);

        info!(
            job = %job_name,
            next_run = %next_run.format("%Y-%m-%d %H:%M:%S UTC"),
            wait_secs = wait_duration.as_secs(),
            "scheduled next sync"
        );

        // Update job status to Scheduled
        {
            let mut jobs_lock = job_manager.jobs_handle().write().await;
            if let Some(state) = jobs_lock.get_mut(job_name) {
                state.status = JobStatus::Scheduled { next_run };
            }
        }

        // Sleep until the next run time, or until shutdown
        let sleep = tokio::time::sleep(wait_duration);
        tokio::select! {
            biased;

            _ = shutdown_rx.recv() => {
                debug!(job = %job_name, "scheduler received shutdown signal");
                return Ok(());
            }

            _ = sleep => {
                debug!(job = %job_name, "cron timer fired; triggering sync");
            }
        }

        // Trigger sync via JobManager
        match job_manager.trigger_sync(job_name).await {
            Ok(()) => {
                info!(job = %job_name, "scheduled sync triggered successfully");
            }
            Err(err) => {
                // Job might already be running (from a manual trigger or previous
                // slow run). Log a warning and continue to the next scheduled time.
                warn!(
                    job = %job_name,
                    error = %err,
                    "failed to trigger scheduled sync"
                );
                continue;
            }
        }

        // Wait for the sync to complete before computing the next run time.
        // This prevents overlapping runs for slow syncs.
        wait_for_sync_completion(job_name, &job_manager, shutdown_rx).await?;
    }

    Ok(())
}

/// Polls the job status until the sync is no longer in the `Running` state,
/// or until a shutdown signal is received.
async fn wait_for_sync_completion(
    job_name: &str,
    job_manager: &JobManager,
    shutdown_rx: &mut broadcast::Receiver<()>,
) -> Result<()> {
    // Poll interval for checking sync completion
    let poll_interval = Duration::from_millis(500);

    loop {
        let is_running = {
            let jobs_lock = job_manager.jobs_handle().read().await;
            matches!(
                jobs_lock.get(job_name).map(|s| &s.status),
                Some(JobStatus::Running { .. })
            )
        };

        if !is_running {
            debug!(job = %job_name, "scheduled sync completed");
            return Ok(());
        }

        // Wait a bit before checking again, or bail on shutdown
        tokio::select! {
            biased;

            _ = shutdown_rx.recv() => {
                debug!(job = %job_name, "scheduler shutdown during sync wait");
                return Ok(());
            }

            _ = tokio::time::sleep(poll_interval) => {
                // Continue polling
            }
        }
    }
}

/// Parses a cron expression and returns the next upcoming time, or an error.
///
/// This is a utility function for validation — e.g., during config validation
/// to check that a schedule expression is valid.
pub fn next_run_time(cron_expr: &str) -> Result<chrono::DateTime<Utc>> {
    let schedule = Schedule::from_str(cron_expr)
        .with_context(|| format!("invalid cron expression '{}'", cron_expr))?;

    schedule
        .upcoming(Utc)
        .next()
        .context("cron expression has no upcoming runs")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next_run_time_valid_expression() {
        // Every minute
        let result = next_run_time("0 * * * * *");
        assert!(result.is_ok());
        let next = result.unwrap();
        assert!(next > Utc::now());
    }

    #[test]
    fn test_next_run_time_standard_cron() {
        // Standard 5-field: every day at 3:00 AM
        // The `cron` crate requires 6 or 7 fields (with seconds), so we use
        // "0 0 3 * * *" which is seconds=0, minutes=0, hours=3, every day.
        let result = next_run_time("0 0 3 * * *");
        assert!(result.is_ok());
    }

    #[test]
    fn test_next_run_time_invalid_expression() {
        let result = next_run_time("not a cron expression");
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("invalid cron expression"));
    }

    #[test]
    fn test_next_run_time_every_5_minutes() {
        // Every 5 minutes
        let result = next_run_time("0 */5 * * * *");
        assert!(result.is_ok());
        let next = result.unwrap();
        assert!(next > Utc::now());
        // The next run should be at most ~5 minutes away
        let diff = next - Utc::now();
        assert!(diff.num_seconds() <= 300);
    }

    #[test]
    fn test_next_run_time_at_midnight() {
        // At midnight every day: second=0, minute=0, hour=0
        let result = next_run_time("0 0 0 * * *");
        assert!(result.is_ok());
    }

    #[test]
    fn test_scheduler_service_new() {
        let service = SchedulerService::new();
        assert_eq!(service.active_count(), 0);
    }

    #[tokio::test]
    async fn test_scheduler_service_stop_all_empty() {
        let mut service = SchedulerService::new();
        // Should not panic on empty service
        service.stop_all().await;
        assert_eq!(service.active_count(), 0);
    }

    #[test]
    fn test_next_run_time_weekly() {
        // Every Sunday at 2:30 AM
        let result = next_run_time("0 30 2 * * SUN");
        assert!(result.is_ok());
    }

    #[test]
    fn test_next_run_time_is_in_the_future() {
        let result = next_run_time("0 * * * * *");
        assert!(result.is_ok());
        let next = result.unwrap();
        // Should be in the future (or very close to now)
        let diff = next - Utc::now();
        assert!(diff.num_seconds() >= -1);
    }
}
