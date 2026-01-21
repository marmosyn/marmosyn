// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! CRUD operations for the `receiver_stats` table.
//!
//! Tracks statistics about files received from remote senders, including
//! file counts, byte counts, and timestamps of last received data.

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};
use tracing::debug;

/// A single row in the `receiver_stats` table.
#[derive(Debug, Clone)]
pub struct ReceiverStatsRow {
    /// Auto-incremented primary key.
    pub id: i64,
    /// Identification of the remote sender (e.g. IP address or node name).
    pub remote_sender: String,
    /// The destination path on the receiver where files are written.
    pub dest_path: String,
    /// Total number of files received from this sender to this path.
    pub files_received: i64,
    /// Total bytes received from this sender to this path.
    pub bytes_received: i64,
    /// ISO 8601 timestamp of the last received file (None if never received).
    pub last_received_at: Option<String>,
}

/// Records a file reception event, updating the running totals for the
/// given (remote_sender, dest_path) pair.
///
/// If no row exists yet for the pair, a new one is created. Otherwise the
/// existing row is updated with incremented counters and a fresh timestamp.
pub fn record_reception(
    conn: &Connection,
    remote_sender: &str,
    dest_path: &str,
    files: i64,
    bytes: i64,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    let existing = get_by_sender_and_path(conn, remote_sender, dest_path)?;

    if let Some(row) = existing {
        conn.execute(
            "UPDATE receiver_stats
             SET files_received = files_received + ?1,
                 bytes_received = bytes_received + ?2,
                 last_received_at = ?3
             WHERE id = ?4",
            params![files, bytes, now, row.id],
        )
        .context("failed to update receiver_stats row")?;

        debug!(
            remote = remote_sender,
            dest = dest_path,
            files_added = files,
            bytes_added = bytes,
            "receiver stats updated"
        );
    } else {
        conn.execute(
            "INSERT INTO receiver_stats
                 (remote_sender, dest_path, files_received, bytes_received, last_received_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![remote_sender, dest_path, files, bytes, now],
        )
        .context("failed to insert receiver_stats row")?;

        debug!(
            remote = remote_sender,
            dest = dest_path,
            files = files,
            bytes = bytes,
            "receiver stats entry created"
        );
    }

    Ok(())
}

/// Retrieves stats for a specific (remote_sender, dest_path) pair.
pub fn get_by_sender_and_path(
    conn: &Connection,
    remote_sender: &str,
    dest_path: &str,
) -> Result<Option<ReceiverStatsRow>> {
    let row = conn
        .query_row(
            "SELECT id, remote_sender, dest_path, files_received,
                    bytes_received, last_received_at
             FROM receiver_stats
             WHERE remote_sender = ?1 AND dest_path = ?2",
            params![remote_sender, dest_path],
            row_to_stats,
        )
        .optional()
        .context("failed to query receiver_stats by sender and path")?;

    Ok(row)
}

/// Retrieves a single receiver stats row by ID.
pub fn get_by_id(conn: &Connection, id: i64) -> Result<Option<ReceiverStatsRow>> {
    let row = conn
        .query_row(
            "SELECT id, remote_sender, dest_path, files_received,
                    bytes_received, last_received_at
             FROM receiver_stats
             WHERE id = ?1",
            params![id],
            row_to_stats,
        )
        .optional()
        .context("failed to query receiver_stats by id")?;

    Ok(row)
}

/// Retrieves all stats rows for a given remote sender.
pub fn get_by_sender(conn: &Connection, remote_sender: &str) -> Result<Vec<ReceiverStatsRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, remote_sender, dest_path, files_received,
                    bytes_received, last_received_at
             FROM receiver_stats
             WHERE remote_sender = ?1
             ORDER BY last_received_at DESC",
        )
        .context("failed to prepare get_by_sender query")?;

    let rows = stmt
        .query_map(params![remote_sender], row_to_stats)
        .context("failed to execute get_by_sender query")?
        .collect::<Result<Vec<_>, _>>()
        .context("failed to read receiver_stats rows")?;

    Ok(rows)
}

/// Retrieves all stats rows for a given destination path.
pub fn get_by_dest_path(conn: &Connection, dest_path: &str) -> Result<Vec<ReceiverStatsRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, remote_sender, dest_path, files_received,
                    bytes_received, last_received_at
             FROM receiver_stats
             WHERE dest_path = ?1
             ORDER BY last_received_at DESC",
        )
        .context("failed to prepare get_by_dest_path query")?;

    let rows = stmt
        .query_map(params![dest_path], row_to_stats)
        .context("failed to execute get_by_dest_path query")?
        .collect::<Result<Vec<_>, _>>()
        .context("failed to read receiver_stats rows")?;

    Ok(rows)
}

/// Retrieves all receiver stats rows.
pub fn get_all(conn: &Connection) -> Result<Vec<ReceiverStatsRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, remote_sender, dest_path, files_received,
                    bytes_received, last_received_at
             FROM receiver_stats
             ORDER BY last_received_at DESC",
        )
        .context("failed to prepare get_all receiver_stats query")?;

    let rows = stmt
        .query_map([], row_to_stats)
        .context("failed to execute get_all receiver_stats query")?
        .collect::<Result<Vec<_>, _>>()
        .context("failed to read receiver_stats rows")?;

    Ok(rows)
}

/// Returns the total number of files received across all senders and paths.
pub fn total_files_received(conn: &Connection) -> Result<i64> {
    let total: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(files_received), 0) FROM receiver_stats",
            [],
            |row| row.get(0),
        )
        .context("failed to sum total files received")?;

    Ok(total)
}

/// Returns the total number of bytes received across all senders and paths.
pub fn total_bytes_received(conn: &Connection) -> Result<i64> {
    let total: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(bytes_received), 0) FROM receiver_stats",
            [],
            |row| row.get(0),
        )
        .context("failed to sum total bytes received")?;

    Ok(total)
}

/// Resets (zeroes out) the stats for a specific (remote_sender, dest_path) pair.
///
/// The row is kept but counters are set to zero and `last_received_at` is cleared.
/// Returns `true` if a row was found and reset, `false` if no matching row existed.
pub fn reset_stats(conn: &Connection, remote_sender: &str, dest_path: &str) -> Result<bool> {
    let rows_updated = conn
        .execute(
            "UPDATE receiver_stats
             SET files_received = 0,
                 bytes_received = 0,
                 last_received_at = NULL
             WHERE remote_sender = ?1 AND dest_path = ?2",
            params![remote_sender, dest_path],
        )
        .context("failed to reset receiver_stats")?;

    Ok(rows_updated > 0)
}

/// Deletes all stats for a given remote sender.
///
/// Returns the number of rows deleted.
pub fn delete_by_sender(conn: &Connection, remote_sender: &str) -> Result<usize> {
    let count = conn
        .execute(
            "DELETE FROM receiver_stats WHERE remote_sender = ?1",
            params![remote_sender],
        )
        .context("failed to delete receiver_stats by sender")?;

    Ok(count)
}

/// Deletes all receiver stats.
///
/// Returns the number of rows deleted.
pub fn delete_all(conn: &Connection) -> Result<usize> {
    let count = conn
        .execute("DELETE FROM receiver_stats", [])
        .context("failed to delete all receiver_stats")?;

    Ok(count)
}

// ─── Internal helpers ──────────────────────────────────────────────────────

/// Maps a `rusqlite::Row` to a [`ReceiverStatsRow`].
fn row_to_stats(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReceiverStatsRow> {
    Ok(ReceiverStatsRow {
        id: row.get(0)?,
        remote_sender: row.get(1)?,
        dest_path: row.get(2)?,
        files_received: row.get(3)?,
        bytes_received: row.get(4)?,
        last_received_at: row.get(5)?,
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
    fn test_record_reception_creates_new_row() {
        let conn = test_db();

        record_reception(&conn, "sender-1", "/mnt/backup", 10, 1024).unwrap();

        let row = get_by_sender_and_path(&conn, "sender-1", "/mnt/backup")
            .unwrap()
            .expect("row should exist");

        assert_eq!(row.remote_sender, "sender-1");
        assert_eq!(row.dest_path, "/mnt/backup");
        assert_eq!(row.files_received, 10);
        assert_eq!(row.bytes_received, 1024);
        assert!(row.last_received_at.is_some());
    }

    #[test]
    fn test_record_reception_updates_existing_row() {
        let conn = test_db();

        record_reception(&conn, "sender-1", "/mnt/backup", 5, 500).unwrap();
        record_reception(&conn, "sender-1", "/mnt/backup", 3, 300).unwrap();

        let row = get_by_sender_and_path(&conn, "sender-1", "/mnt/backup")
            .unwrap()
            .expect("row should exist");

        assert_eq!(row.files_received, 8);
        assert_eq!(row.bytes_received, 800);
    }

    #[test]
    fn test_record_reception_different_pairs_are_isolated() {
        let conn = test_db();

        record_reception(&conn, "sender-a", "/path-1", 10, 100).unwrap();
        record_reception(&conn, "sender-a", "/path-2", 20, 200).unwrap();
        record_reception(&conn, "sender-b", "/path-1", 30, 300).unwrap();

        let row_a1 = get_by_sender_and_path(&conn, "sender-a", "/path-1")
            .unwrap()
            .unwrap();
        assert_eq!(row_a1.files_received, 10);

        let row_a2 = get_by_sender_and_path(&conn, "sender-a", "/path-2")
            .unwrap()
            .unwrap();
        assert_eq!(row_a2.files_received, 20);

        let row_b1 = get_by_sender_and_path(&conn, "sender-b", "/path-1")
            .unwrap()
            .unwrap();
        assert_eq!(row_b1.files_received, 30);
    }

    #[test]
    fn test_get_by_sender_and_path_nonexistent() {
        let conn = test_db();

        let row = get_by_sender_and_path(&conn, "no-one", "/nowhere").unwrap();
        assert!(row.is_none());
    }

    #[test]
    fn test_get_by_id() {
        let conn = test_db();

        record_reception(&conn, "sender-1", "/backup", 1, 10).unwrap();

        let row = get_by_sender_and_path(&conn, "sender-1", "/backup")
            .unwrap()
            .unwrap();
        let fetched = get_by_id(&conn, row.id).unwrap().expect("should exist");
        assert_eq!(fetched.remote_sender, "sender-1");
    }

    #[test]
    fn test_get_by_id_nonexistent() {
        let conn = test_db();

        let row = get_by_id(&conn, 99999).unwrap();
        assert!(row.is_none());
    }

    #[test]
    fn test_get_by_sender() {
        let conn = test_db();

        record_reception(&conn, "sender-a", "/path-1", 1, 10).unwrap();
        record_reception(&conn, "sender-a", "/path-2", 2, 20).unwrap();
        record_reception(&conn, "sender-b", "/path-1", 3, 30).unwrap();

        let rows = get_by_sender(&conn, "sender-a").unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.remote_sender == "sender-a"));
    }

    #[test]
    fn test_get_by_sender_empty() {
        let conn = test_db();

        let rows = get_by_sender(&conn, "nonexistent").unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn test_get_by_dest_path() {
        let conn = test_db();

        record_reception(&conn, "sender-a", "/shared", 1, 10).unwrap();
        record_reception(&conn, "sender-b", "/shared", 2, 20).unwrap();
        record_reception(&conn, "sender-c", "/other", 3, 30).unwrap();

        let rows = get_by_dest_path(&conn, "/shared").unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.dest_path == "/shared"));
    }

    #[test]
    fn test_get_all() {
        let conn = test_db();

        record_reception(&conn, "s1", "/p1", 1, 10).unwrap();
        record_reception(&conn, "s2", "/p2", 2, 20).unwrap();
        record_reception(&conn, "s3", "/p3", 3, 30).unwrap();

        let rows = get_all(&conn).unwrap();
        assert_eq!(rows.len(), 3);
    }

    #[test]
    fn test_get_all_empty() {
        let conn = test_db();

        let rows = get_all(&conn).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn test_total_files_received() {
        let conn = test_db();

        assert_eq!(total_files_received(&conn).unwrap(), 0);

        record_reception(&conn, "s1", "/p1", 10, 100).unwrap();
        record_reception(&conn, "s2", "/p2", 20, 200).unwrap();

        assert_eq!(total_files_received(&conn).unwrap(), 30);
    }

    #[test]
    fn test_total_bytes_received() {
        let conn = test_db();

        assert_eq!(total_bytes_received(&conn).unwrap(), 0);

        record_reception(&conn, "s1", "/p1", 1, 500).unwrap();
        record_reception(&conn, "s2", "/p2", 2, 1500).unwrap();

        assert_eq!(total_bytes_received(&conn).unwrap(), 2000);
    }

    #[test]
    fn test_reset_stats() {
        let conn = test_db();

        record_reception(&conn, "sender-1", "/backup", 10, 1024).unwrap();

        let reset = reset_stats(&conn, "sender-1", "/backup").unwrap();
        assert!(reset);

        let row = get_by_sender_and_path(&conn, "sender-1", "/backup")
            .unwrap()
            .expect("row should still exist");
        assert_eq!(row.files_received, 0);
        assert_eq!(row.bytes_received, 0);
        assert!(row.last_received_at.is_none());
    }

    #[test]
    fn test_reset_stats_nonexistent() {
        let conn = test_db();

        let reset = reset_stats(&conn, "no-one", "/nowhere").unwrap();
        assert!(!reset);
    }

    #[test]
    fn test_delete_by_sender() {
        let conn = test_db();

        record_reception(&conn, "sender-a", "/p1", 1, 10).unwrap();
        record_reception(&conn, "sender-a", "/p2", 2, 20).unwrap();
        record_reception(&conn, "sender-b", "/p1", 3, 30).unwrap();

        let deleted = delete_by_sender(&conn, "sender-a").unwrap();
        assert_eq!(deleted, 2);

        let remaining = get_all(&conn).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].remote_sender, "sender-b");
    }

    #[test]
    fn test_delete_by_sender_nonexistent() {
        let conn = test_db();

        let deleted = delete_by_sender(&conn, "nobody").unwrap();
        assert_eq!(deleted, 0);
    }

    #[test]
    fn test_delete_all() {
        let conn = test_db();

        record_reception(&conn, "s1", "/p1", 1, 10).unwrap();
        record_reception(&conn, "s2", "/p2", 2, 20).unwrap();

        let deleted = delete_all(&conn).unwrap();
        assert_eq!(deleted, 2);

        let rows = get_all(&conn).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn test_delete_all_empty() {
        let conn = test_db();

        let deleted = delete_all(&conn).unwrap();
        assert_eq!(deleted, 0);
    }

    #[test]
    fn test_last_received_at_is_valid_rfc3339() {
        let conn = test_db();

        record_reception(&conn, "sender", "/path", 1, 10).unwrap();

        let row = get_by_sender_and_path(&conn, "sender", "/path")
            .unwrap()
            .unwrap();
        let ts = row
            .last_received_at
            .as_ref()
            .expect("should have timestamp");
        let parsed = chrono::DateTime::parse_from_rfc3339(ts);
        assert!(
            parsed.is_ok(),
            "last_received_at should be valid RFC 3339: {}",
            ts
        );
    }

    #[test]
    fn test_record_reception_updates_timestamp() {
        let conn = test_db();

        record_reception(&conn, "sender", "/path", 1, 10).unwrap();
        let row1 = get_by_sender_and_path(&conn, "sender", "/path")
            .unwrap()
            .unwrap();
        let ts1 = row1.last_received_at.clone().unwrap();

        // Small delay to ensure timestamp differs
        std::thread::sleep(std::time::Duration::from_millis(10));

        record_reception(&conn, "sender", "/path", 1, 10).unwrap();
        let row2 = get_by_sender_and_path(&conn, "sender", "/path")
            .unwrap()
            .unwrap();
        let ts2 = row2.last_received_at.clone().unwrap();

        assert!(
            ts2 >= ts1,
            "timestamp should be updated: {} >= {}",
            ts2,
            ts1
        );
    }
}
