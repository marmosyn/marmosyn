// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Database schema migrations for MarmoSyn.
//!
//! Creates and updates SQLite tables used for persisting file metadata,
//! synchronization history, and receiver statistics. The database path
//! is automatically determined by UID (root vs user).

use anyhow::{Context, Result};
use rusqlite::Connection;
use tracing::info;

/// Current schema version. Increment when adding new migrations.
const SCHEMA_VERSION: u32 = 1;

/// Initializes the database schema, running any pending migrations.
///
/// This function is idempotent — it can be called on every startup and will
/// only apply migrations that have not yet been run.
///
/// # Errors
///
/// Returns an error if the database connection fails or a migration cannot
/// be applied.
pub fn run_migrations(conn: &Connection) -> Result<()> {
    // Ensure the migrations tracking table exists
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER NOT NULL
        );",
    )
    .context("failed to create schema_version table")?;

    let current_version = get_current_version(conn)?;

    if current_version < 1 {
        migrate_v1(conn).context("failed to apply migration v1")?;
        set_version(conn, 1)?;
    }

    info!(version = SCHEMA_VERSION, "database schema is up to date");

    Ok(())
}

/// Returns the current schema version from the database.
/// Returns 0 if no version has been recorded yet.
fn get_current_version(conn: &Connection) -> Result<u32> {
    let mut stmt =
        conn.prepare("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1")?;
    let version = stmt.query_row([], |row| row.get::<_, u32>(0)).unwrap_or(0);
    Ok(version)
}

/// Records a schema version in the database.
fn set_version(conn: &Connection, version: u32) -> Result<()> {
    conn.execute(
        "INSERT INTO schema_version (version) VALUES (?1)",
        [version],
    )?;
    Ok(())
}

/// Migration v1: initial schema — file_metadata, sync_history, receiver_stats.
fn migrate_v1(conn: &Connection) -> Result<()> {
    info!("applying database migration v1: initial schema");

    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS file_metadata (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_name TEXT NOT NULL,
            rel_path TEXT NOT NULL,
            size INTEGER NOT NULL,
            mtime_secs INTEGER NOT NULL,
            mtime_nanos INTEGER NOT NULL,
            blake3_hash TEXT NOT NULL,
            UNIQUE(job_name, rel_path)
        );

        CREATE TABLE IF NOT EXISTS sync_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_name TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT NOT NULL,
            files_synced INTEGER DEFAULT 0,
            bytes_transferred INTEGER DEFAULT 0,
            error_message TEXT
        );

        CREATE TABLE IF NOT EXISTS receiver_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            remote_sender TEXT NOT NULL,
            dest_path TEXT NOT NULL,
            files_received INTEGER DEFAULT 0,
            bytes_received INTEGER DEFAULT 0,
            last_received_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_file_meta_job
            ON file_metadata(job_name);
        CREATE INDEX IF NOT EXISTS idx_sync_history_job
            ON sync_history(job_name, started_at);
        CREATE INDEX IF NOT EXISTS idx_receiver_stats
            ON receiver_stats(remote_sender, dest_path);
        ",
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn test_run_migrations_creates_tables() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();

        // Verify tables exist by querying them
        conn.query_row("SELECT count(*) FROM file_metadata", [], |row| {
            row.get::<_, i64>(0)
        })
        .expect("file_metadata table should exist");
        conn.query_row("SELECT count(*) FROM sync_history", [], |row| {
            row.get::<_, i64>(0)
        })
        .expect("sync_history table should exist");
        conn.query_row("SELECT count(*) FROM receiver_stats", [], |row| {
            row.get::<_, i64>(0)
        })
        .expect("receiver_stats table should exist");
    }

    #[test]
    fn test_run_migrations_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        run_migrations(&conn).unwrap(); // Should not fail on second run
    }

    #[test]
    fn test_schema_version_is_recorded() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();

        let version = get_current_version(&conn).unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn test_file_metadata_unique_constraint() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();

        conn.execute(
            "INSERT INTO file_metadata (job_name, rel_path, size, mtime_secs, mtime_nanos, blake3_hash)
             VALUES ('job1', 'file.txt', 100, 1000, 0, 'hash1')",
            [],
        )
        .unwrap();

        // Duplicate should fail
        let result = conn.execute(
            "INSERT INTO file_metadata (job_name, rel_path, size, mtime_secs, mtime_nanos, blake3_hash)
             VALUES ('job1', 'file.txt', 200, 2000, 0, 'hash2')",
            [],
        );
        assert!(result.is_err());

        // Same path in a different job should succeed
        conn.execute(
            "INSERT INTO file_metadata (job_name, rel_path, size, mtime_secs, mtime_nanos, blake3_hash)
             VALUES ('job2', 'file.txt', 200, 2000, 0, 'hash2')",
            [],
        )
        .unwrap();
    }
}
