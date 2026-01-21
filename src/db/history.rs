// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! CRUD operations for the `sync_history` table.
//!
//! Records the outcome of each synchronization run: start/finish times,
//! status (running / success / failed), file and byte counts, and any
//! error message. Used by the API to expose job history and by the CLI
//! `jobs history` subcommand.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use tracing::debug;

/// A single row in the `sync_history` table.
#[derive(Debug, Clone)]
pub struct SyncHistoryRow {
    /// Auto-incremented primary key.
    pub id: i64,
    /// Name of the sync job.
    pub job_name: String,
    /// ISO 8601 timestamp when the sync started.
    pub started_at: String,
    /// ISO 8601 timestamp when the sync finished (None if still running).
    pub finished_at: Option<String>,
    /// Status: "running", "success", or "failed".
    pub status: String,
    /// Number of files successfully synced.
    pub files_synced: i64,
    /// Total bytes transferred.
    pub bytes_transferred: i64,
    /// Error message if the sync failed.
    pub error_message: Option<String>,
}

/// Inserts a new sync history entry with status "running".
///
/// Returns the row ID of the inserted entry. The caller should later call
/// [`finish_sync`] to update the status and record the outcome.
pub fn start_sync(conn: &Connection, job_name: &str) -> Result<i64> {
    let started_at = Utc::now().to_rfc3339();

    conn.execute(
        "INSERT INTO sync_history (job_name, started_at, status)
         VALUES (?1, ?2, 'running')",
        params![job_name, started_at],
    )
    .context("failed to insert sync_history row")?;

    let id = conn.last_insert_rowid();

    debug!(
        id = id,
        job_name = job_name,
        started_at = %started_at,
        "sync history entry created"
    );

    Ok(id)
}

/// Updates an existing sync history entry to mark it as finished.
///
/// Sets the `finished_at` timestamp, final status, file/byte counts, and
/// an optional error message.
pub fn finish_sync(
    conn: &Connection,
    id: i64,
    status: &str,
    files_synced: i64,
    bytes_transferred: i64,
    error_message: Option<&str>,
) -> Result<()> {
    let finished_at = Utc::now().to_rfc3339();

    let rows_updated = conn
        .execute(
            "UPDATE sync_history
             SET finished_at = ?1,
                 status = ?2,
                 files_synced = ?3,
                 bytes_transferred = ?4,
                 error_message = ?5
             WHERE id = ?6",
            params![
                finished_at,
                status,
                files_synced,
                bytes_transferred,
                error_message,
                id,
            ],
        )
        .context("failed to update sync_history row")?;

    if rows_updated == 0 {
        anyhow::bail!("sync_history row with id {} not found", id);
    }

    debug!(
        id = id,
        status = status,
        files = files_synced,
        bytes = bytes_transferred,
        "sync history entry updated"
    );

    Ok(())
}

/// Retrieves a single sync history entry by ID.
pub fn get_by_id(conn: &Connection, id: i64) -> Result<Option<SyncHistoryRow>> {
    let row = conn
        .query_row(
            "SELECT id, job_name, started_at, finished_at, status,
                    files_synced, bytes_transferred, error_message
             FROM sync_history
             WHERE id = ?1",
            params![id],
            row_to_history,
        )
        .optional()
        .context("failed to query sync_history by id")?;

    Ok(row)
}

/// Retrieves the most recent sync history entries for a given job.
///
/// Results are ordered by `started_at` descending. If `limit` is `None`,
/// all entries are returned.
pub fn get_job_history(
    conn: &Connection,
    job_name: &str,
    limit: Option<u32>,
) -> Result<Vec<SyncHistoryRow>> {
    let limit_val = limit.unwrap_or(u32::MAX) as i64;

    let mut stmt = conn
        .prepare(
            "SELECT id, job_name, started_at, finished_at, status,
                    files_synced, bytes_transferred, error_message
             FROM sync_history
             WHERE job_name = ?1
             ORDER BY started_at DESC
             LIMIT ?2",
        )
        .context("failed to prepare get_job_history query")?;

    let rows = stmt
        .query_map(params![job_name, limit_val], row_to_history)
        .context("failed to execute get_job_history query")?
        .collect::<Result<Vec<_>, _>>()
        .context("failed to read sync_history rows")?;

    Ok(rows)
}

/// Retrieves the last sync history entry for a given job (most recent by start time).
pub fn get_last_sync(conn: &Connection, job_name: &str) -> Result<Option<SyncHistoryRow>> {
    let row = conn
        .query_row(
            "SELECT id, job_name, started_at, finished_at, status,
                    files_synced, bytes_transferred, error_message
             FROM sync_history
             WHERE job_name = ?1
             ORDER BY started_at DESC
             LIMIT 1",
            params![job_name],
            row_to_history,
        )
        .optional()
        .context("failed to query last sync for job")?;

    Ok(row)
}

/// Returns the total number of sync history entries for a given job.
pub fn count_job_history(conn: &Connection, job_name: &str) -> Result<i64> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sync_history WHERE job_name = ?1",
            params![job_name],
            |row| row.get(0),
        )
        .context("failed to count sync_history rows")?;

    Ok(count)
}

/// Returns all currently running syncs (status = "running").
pub fn get_running_syncs(conn: &Connection) -> Result<Vec<SyncHistoryRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, job_name, started_at, finished_at, status,
                    files_synced, bytes_transferred, error_message
             FROM sync_history
             WHERE status = 'running'
             ORDER BY started_at DESC",
        )
        .context("failed to prepare get_running_syncs query")?;

    let rows = stmt
        .query_map([], row_to_history)
        .context("failed to execute get_running_syncs query")?
        .collect::<Result<Vec<_>, _>>()
        .context("failed to read running sync rows")?;

    Ok(rows)
}

/// Marks all currently running syncs as failed with the given error message.
///
/// This is useful on server startup to clean up stale "running" entries from
/// a previous crash.
pub fn fail_stale_running(conn: &Connection, error_message: &str) -> Result<usize> {
    let finished_at = Utc::now().to_rfc3339();

    let count = conn
        .execute(
            "UPDATE sync_history
             SET status = 'failed',
                 finished_at = ?1,
                 error_message = ?2
             WHERE status = 'running'",
            params![finished_at, error_message],
        )
        .context("failed to update stale running syncs")?;

    if count > 0 {
        debug!(count = count, "marked stale running syncs as failed");
    }

    Ok(count)
}

/// Deletes sync history entries older than the given cutoff date for a job.
///
/// Returns the number of rows deleted.
pub fn delete_old_history(
    conn: &Connection,
    job_name: &str,
    cutoff: &DateTime<Utc>,
) -> Result<usize> {
    let cutoff_str = cutoff.to_rfc3339();

    let count = conn
        .execute(
            "DELETE FROM sync_history
             WHERE job_name = ?1 AND started_at < ?2",
            params![job_name, cutoff_str],
        )
        .context("failed to delete old sync_history rows")?;

    debug!(
        job_name = job_name,
        cutoff = %cutoff_str,
        deleted = count,
        "old history entries deleted"
    );

    Ok(count)
}

/// Deletes all sync history for a given job.
///
/// Returns the number of rows deleted.
pub fn delete_job_history(conn: &Connection, job_name: &str) -> Result<usize> {
    let count = conn
        .execute(
            "DELETE FROM sync_history WHERE job_name = ?1",
            params![job_name],
        )
        .context("failed to delete job sync_history")?;

    Ok(count)
}

// ─── Internal helpers ──────────────────────────────────────────────────────

/// Maps a `rusqlite::Row` to a [`SyncHistoryRow`].
fn row_to_history(row: &rusqlite::Row<'_>) -> rusqlite::Result<SyncHistoryRow> {
    Ok(SyncHistoryRow {
        id: row.get(0)?,
        job_name: row.get(1)?,
        started_at: row.get(2)?,
        finished_at: row.get(3)?,
        status: row.get(4)?,
        files_synced: row.get(5)?,
        bytes_transferred: row.get(6)?,
        error_message: row.get(7)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::migrations::run_migrations;

    /// Helper: create an in-memory DB with migrations applied.
    fn test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        conn
    }

    #[test]
    fn test_start_sync_creates_running_entry() {
        let conn = test_db();

        let id = start_sync(&conn, "my_job").unwrap();
        assert!(id > 0);

        let row = get_by_id(&conn, id).unwrap().expect("row should exist");
        assert_eq!(row.job_name, "my_job");
        assert_eq!(row.status, "running");
        assert!(row.finished_at.is_none());
        assert_eq!(row.files_synced, 0);
        assert_eq!(row.bytes_transferred, 0);
        assert!(row.error_message.is_none());
    }

    #[test]
    fn test_finish_sync_success() {
        let conn = test_db();

        let id = start_sync(&conn, "job1").unwrap();
        finish_sync(&conn, id, "success", 42, 1024 * 1024, None).unwrap();

        let row = get_by_id(&conn, id).unwrap().expect("row should exist");
        assert_eq!(row.status, "success");
        assert!(row.finished_at.is_some());
        assert_eq!(row.files_synced, 42);
        assert_eq!(row.bytes_transferred, 1024 * 1024);
        assert!(row.error_message.is_none());
    }

    #[test]
    fn test_finish_sync_failed() {
        let conn = test_db();

        let id = start_sync(&conn, "job1").unwrap();
        finish_sync(&conn, id, "failed", 5, 500, Some("disk full")).unwrap();

        let row = get_by_id(&conn, id).unwrap().expect("row should exist");
        assert_eq!(row.status, "failed");
        assert_eq!(row.error_message.as_deref(), Some("disk full"));
    }

    #[test]
    fn test_finish_sync_nonexistent_id_fails() {
        let conn = test_db();

        let result = finish_sync(&conn, 9999, "success", 0, 0, None);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("not found"));
    }

    #[test]
    fn test_get_by_id_nonexistent() {
        let conn = test_db();

        let row = get_by_id(&conn, 12345).unwrap();
        assert!(row.is_none());
    }

    #[test]
    fn test_get_job_history_ordering() {
        let conn = test_db();

        let id1 = start_sync(&conn, "job1").unwrap();
        finish_sync(&conn, id1, "success", 10, 100, None).unwrap();

        let id2 = start_sync(&conn, "job1").unwrap();
        finish_sync(&conn, id2, "success", 20, 200, None).unwrap();

        let id3 = start_sync(&conn, "job1").unwrap();
        finish_sync(&conn, id3, "failed", 5, 50, Some("error")).unwrap();

        let history = get_job_history(&conn, "job1", None).unwrap();
        assert_eq!(history.len(), 3);

        // Most recent first
        assert_eq!(history[0].id, id3);
        assert_eq!(history[1].id, id2);
        assert_eq!(history[2].id, id1);
    }

    #[test]
    fn test_get_job_history_with_limit() {
        let conn = test_db();

        for _ in 0..5 {
            let id = start_sync(&conn, "job1").unwrap();
            finish_sync(&conn, id, "success", 1, 10, None).unwrap();
        }

        let history = get_job_history(&conn, "job1", Some(3)).unwrap();
        assert_eq!(history.len(), 3);
    }

    #[test]
    fn test_get_job_history_empty() {
        let conn = test_db();

        let history = get_job_history(&conn, "nonexistent_job", None).unwrap();
        assert!(history.is_empty());
    }

    #[test]
    fn test_get_job_history_isolates_jobs() {
        let conn = test_db();

        let id1 = start_sync(&conn, "job_a").unwrap();
        finish_sync(&conn, id1, "success", 1, 10, None).unwrap();

        let id2 = start_sync(&conn, "job_b").unwrap();
        finish_sync(&conn, id2, "success", 2, 20, None).unwrap();

        let history_a = get_job_history(&conn, "job_a", None).unwrap();
        assert_eq!(history_a.len(), 1);
        assert_eq!(history_a[0].job_name, "job_a");

        let history_b = get_job_history(&conn, "job_b", None).unwrap();
        assert_eq!(history_b.len(), 1);
        assert_eq!(history_b[0].job_name, "job_b");
    }

    #[test]
    fn test_get_last_sync() {
        let conn = test_db();

        let id1 = start_sync(&conn, "job1").unwrap();
        finish_sync(&conn, id1, "success", 10, 100, None).unwrap();

        let id2 = start_sync(&conn, "job1").unwrap();
        finish_sync(&conn, id2, "failed", 5, 50, Some("oops")).unwrap();

        let last = get_last_sync(&conn, "job1").unwrap().expect("should exist");
        assert_eq!(last.id, id2);
        assert_eq!(last.status, "failed");
    }

    #[test]
    fn test_get_last_sync_empty() {
        let conn = test_db();

        let last = get_last_sync(&conn, "no_such_job").unwrap();
        assert!(last.is_none());
    }

    #[test]
    fn test_count_job_history() {
        let conn = test_db();

        assert_eq!(count_job_history(&conn, "job1").unwrap(), 0);

        for _ in 0..4 {
            let id = start_sync(&conn, "job1").unwrap();
            finish_sync(&conn, id, "success", 1, 10, None).unwrap();
        }

        assert_eq!(count_job_history(&conn, "job1").unwrap(), 4);
    }

    #[test]
    fn test_get_running_syncs() {
        let conn = test_db();

        let _id1 = start_sync(&conn, "job_a").unwrap();
        let id2 = start_sync(&conn, "job_b").unwrap();
        finish_sync(&conn, id2, "success", 1, 10, None).unwrap();
        let _id3 = start_sync(&conn, "job_c").unwrap();

        let running = get_running_syncs(&conn).unwrap();
        assert_eq!(running.len(), 2);

        let names: Vec<&str> = running.iter().map(|r| r.job_name.as_str()).collect();
        assert!(names.contains(&"job_a"));
        assert!(names.contains(&"job_c"));
    }

    #[test]
    fn test_fail_stale_running() {
        let conn = test_db();

        let _id1 = start_sync(&conn, "job_a").unwrap();
        let _id2 = start_sync(&conn, "job_b").unwrap();
        let id3 = start_sync(&conn, "job_c").unwrap();
        finish_sync(&conn, id3, "success", 1, 10, None).unwrap();

        let count = fail_stale_running(&conn, "server restarted").unwrap();
        assert_eq!(count, 2);

        let running = get_running_syncs(&conn).unwrap();
        assert!(running.is_empty());

        let history_a = get_job_history(&conn, "job_a", None).unwrap();
        assert_eq!(history_a[0].status, "failed");
        assert_eq!(
            history_a[0].error_message.as_deref(),
            Some("server restarted")
        );
    }

    #[test]
    fn test_fail_stale_running_no_running() {
        let conn = test_db();

        let id = start_sync(&conn, "job1").unwrap();
        finish_sync(&conn, id, "success", 1, 10, None).unwrap();

        let count = fail_stale_running(&conn, "restart").unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_delete_job_history() {
        let conn = test_db();

        for _ in 0..3 {
            let id = start_sync(&conn, "job1").unwrap();
            finish_sync(&conn, id, "success", 1, 10, None).unwrap();
        }
        let id_other = start_sync(&conn, "job2").unwrap();
        finish_sync(&conn, id_other, "success", 1, 10, None).unwrap();

        let deleted = delete_job_history(&conn, "job1").unwrap();
        assert_eq!(deleted, 3);

        assert_eq!(count_job_history(&conn, "job1").unwrap(), 0);
        assert_eq!(count_job_history(&conn, "job2").unwrap(), 1);
    }

    #[test]
    fn test_delete_old_history() {
        let conn = test_db();

        // Insert entries with manually set timestamps
        conn.execute(
            "INSERT INTO sync_history (job_name, started_at, status, files_synced, bytes_transferred)
             VALUES ('job1', '2024-01-01T00:00:00+00:00', 'success', 1, 10)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sync_history (job_name, started_at, status, files_synced, bytes_transferred)
             VALUES ('job1', '2024-06-15T00:00:00+00:00', 'success', 2, 20)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sync_history (job_name, started_at, status, files_synced, bytes_transferred)
             VALUES ('job1', '2024-12-01T00:00:00+00:00', 'success', 3, 30)",
            [],
        )
        .unwrap();

        // Delete entries before mid-year
        let cutoff = "2024-06-01T00:00:00+00:00"
            .parse::<DateTime<Utc>>()
            .unwrap();
        let deleted = delete_old_history(&conn, "job1", &cutoff).unwrap();
        assert_eq!(deleted, 1);

        let remaining = get_job_history(&conn, "job1", None).unwrap();
        assert_eq!(remaining.len(), 2);
    }

    #[test]
    fn test_started_at_is_valid_rfc3339() {
        let conn = test_db();

        let id = start_sync(&conn, "job1").unwrap();
        let row = get_by_id(&conn, id).unwrap().unwrap();

        // Should parse as a valid DateTime
        let parsed = DateTime::parse_from_rfc3339(&row.started_at);
        assert!(
            parsed.is_ok(),
            "started_at should be valid RFC 3339: {}",
            row.started_at
        );
    }

    #[test]
    fn test_finished_at_is_valid_rfc3339() {
        let conn = test_db();

        let id = start_sync(&conn, "job1").unwrap();
        finish_sync(&conn, id, "success", 0, 0, None).unwrap();

        let row = get_by_id(&conn, id).unwrap().unwrap();
        let finished = row.finished_at.as_ref().expect("should have finished_at");
        let parsed = DateTime::parse_from_rfc3339(finished);
        assert!(
            parsed.is_ok(),
            "finished_at should be valid RFC 3339: {}",
            finished
        );
    }
}
