//! CRUD operations for the `file_metadata` table.
//!
//! This module provides functions to create, read, update, and delete file
//! metadata records in the SQLite database. File metadata is used to track
//! the state of synchronized files across runs, enabling incremental sync
//! by comparing stored metadata against the current filesystem state.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};

/// A row in the `file_metadata` table.
#[derive(Debug, Clone)]
pub struct FileMetaRow {
    /// Auto-incremented row ID.
    pub id: i64,
    /// Name of the sync job this entry belongs to.
    pub job_name: String,
    /// Relative path of the file within the source directory.
    pub rel_path: PathBuf,
    /// File size in bytes.
    pub size: u64,
    /// Modification time — seconds since UNIX epoch.
    pub mtime_secs: i64,
    /// Modification time — nanosecond component.
    pub mtime_nanos: u32,
    /// BLAKE3 hash of the file contents.
    pub blake3_hash: String,
}

/// Inserts or replaces a file metadata record for the given job and path.
pub fn upsert_file_meta(conn: &Connection, row: &FileMetaRow) -> Result<()> {
    conn.execute(
        "INSERT INTO file_metadata (job_name, rel_path, size, mtime_secs, mtime_nanos, blake3_hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(job_name, rel_path) DO UPDATE SET
             size = excluded.size,
             mtime_secs = excluded.mtime_secs,
             mtime_nanos = excluded.mtime_nanos,
             blake3_hash = excluded.blake3_hash",
        params![
            row.job_name,
            row.rel_path.to_string_lossy().as_ref(),
            row.size as i64,
            row.mtime_secs,
            row.mtime_nanos,
            row.blake3_hash,
        ],
    )?;
    Ok(())
}

/// Retrieves a single file metadata record by job name and relative path.
pub fn get_file_meta(
    conn: &Connection,
    job_name: &str,
    rel_path: &Path,
) -> Result<Option<FileMetaRow>> {
    let row = conn
        .query_row(
            "SELECT id, job_name, rel_path, size, mtime_secs, mtime_nanos, blake3_hash
             FROM file_metadata
             WHERE job_name = ?1 AND rel_path = ?2",
            params![job_name, rel_path.to_string_lossy().as_ref()],
            |row| {
                Ok(FileMetaRow {
                    id: row.get(0)?,
                    job_name: row.get(1)?,
                    rel_path: PathBuf::from(row.get::<_, String>(2)?),
                    size: row.get::<_, i64>(3)? as u64,
                    mtime_secs: row.get(4)?,
                    mtime_nanos: row.get::<_, u32>(5)?,
                    blake3_hash: row.get(6)?,
                })
            },
        )
        .optional()?;
    Ok(row)
}

/// Retrieves all file metadata records for a given job.
pub fn list_file_meta(conn: &Connection, job_name: &str) -> Result<Vec<FileMetaRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, job_name, rel_path, size, mtime_secs, mtime_nanos, blake3_hash
         FROM file_metadata
         WHERE job_name = ?1
         ORDER BY rel_path",
    )?;

    let rows = stmt
        .query_map(params![job_name], |row| {
            Ok(FileMetaRow {
                id: row.get(0)?,
                job_name: row.get(1)?,
                rel_path: PathBuf::from(row.get::<_, String>(2)?),
                size: row.get::<_, i64>(3)? as u64,
                mtime_secs: row.get(4)?,
                mtime_nanos: row.get::<_, u32>(5)?,
                blake3_hash: row.get(6)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(rows)
}

/// Deletes a file metadata record for the given job and relative path.
pub fn delete_file_meta(conn: &Connection, job_name: &str, rel_path: &Path) -> Result<bool> {
    let count = conn.execute(
        "DELETE FROM file_metadata WHERE job_name = ?1 AND rel_path = ?2",
        params![job_name, rel_path.to_string_lossy().as_ref()],
    )?;
    Ok(count > 0)
}

/// Deletes all file metadata records for the given job.
pub fn delete_all_file_meta(conn: &Connection, job_name: &str) -> Result<u64> {
    let count = conn.execute(
        "DELETE FROM file_metadata WHERE job_name = ?1",
        params![job_name],
    )?;
    Ok(count as u64)
}

/// Returns the total number of file metadata records for a given job.
pub fn count_file_meta(conn: &Connection, job_name: &str) -> Result<u64> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM file_metadata WHERE job_name = ?1",
        params![job_name],
        |row| row.get(0),
    )?;
    Ok(count as u64)
}

/// Converts a `SystemTime` into `(secs, nanos)` for storage.
pub fn system_time_to_parts(time: SystemTime) -> (i64, u32) {
    match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(dur) => (dur.as_secs() as i64, dur.subsec_nanos()),
        Err(_) => (0, 0),
    }
}

/// Converts stored `(secs, nanos)` back into a `SystemTime`.
pub fn parts_to_system_time(secs: i64, nanos: u32) -> SystemTime {
    if secs >= 0 {
        SystemTime::UNIX_EPOCH + std::time::Duration::new(secs as u64, nanos)
    } else {
        SystemTime::UNIX_EPOCH
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::migrations;

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        migrations::run_migrations(&conn).unwrap();
        conn
    }

    #[test]
    fn test_upsert_and_get() {
        let conn = setup_db();
        let row = FileMetaRow {
            id: 0,
            job_name: "docs".to_string(),
            rel_path: PathBuf::from("readme.txt"),
            size: 1024,
            mtime_secs: 1_700_000_000,
            mtime_nanos: 500_000,
            blake3_hash: "abc123".to_string(),
        };

        upsert_file_meta(&conn, &row).unwrap();

        let found = get_file_meta(&conn, "docs", Path::new("readme.txt"))
            .unwrap()
            .expect("should find record");
        assert_eq!(found.job_name, "docs");
        assert_eq!(found.rel_path, PathBuf::from("readme.txt"));
        assert_eq!(found.size, 1024);
        assert_eq!(found.blake3_hash, "abc123");
    }

    #[test]
    fn test_upsert_updates_existing() {
        let conn = setup_db();
        let mut row = FileMetaRow {
            id: 0,
            job_name: "docs".to_string(),
            rel_path: PathBuf::from("file.txt"),
            size: 100,
            mtime_secs: 1_700_000_000,
            mtime_nanos: 0,
            blake3_hash: "hash1".to_string(),
        };

        upsert_file_meta(&conn, &row).unwrap();

        row.size = 200;
        row.blake3_hash = "hash2".to_string();
        upsert_file_meta(&conn, &row).unwrap();

        let found = get_file_meta(&conn, "docs", Path::new("file.txt"))
            .unwrap()
            .expect("should find record");
        assert_eq!(found.size, 200);
        assert_eq!(found.blake3_hash, "hash2");

        // Should still be only one record
        assert_eq!(count_file_meta(&conn, "docs").unwrap(), 1);
    }

    #[test]
    fn test_get_nonexistent() {
        let conn = setup_db();
        let found = get_file_meta(&conn, "docs", Path::new("nope.txt")).unwrap();
        assert!(found.is_none());
    }

    #[test]
    fn test_list_file_meta() {
        let conn = setup_db();

        for name in &["a.txt", "c.txt", "b.txt"] {
            let row = FileMetaRow {
                id: 0,
                job_name: "job1".to_string(),
                rel_path: PathBuf::from(name),
                size: 10,
                mtime_secs: 0,
                mtime_nanos: 0,
                blake3_hash: "h".to_string(),
            };
            upsert_file_meta(&conn, &row).unwrap();
        }

        let list = list_file_meta(&conn, "job1").unwrap();
        assert_eq!(list.len(), 3);
        // Should be sorted by rel_path
        assert_eq!(list[0].rel_path, PathBuf::from("a.txt"));
        assert_eq!(list[1].rel_path, PathBuf::from("b.txt"));
        assert_eq!(list[2].rel_path, PathBuf::from("c.txt"));
    }

    #[test]
    fn test_delete_file_meta() {
        let conn = setup_db();
        let row = FileMetaRow {
            id: 0,
            job_name: "job1".to_string(),
            rel_path: PathBuf::from("file.txt"),
            size: 10,
            mtime_secs: 0,
            mtime_nanos: 0,
            blake3_hash: "h".to_string(),
        };
        upsert_file_meta(&conn, &row).unwrap();

        let deleted = delete_file_meta(&conn, "job1", Path::new("file.txt")).unwrap();
        assert!(deleted);

        let deleted_again = delete_file_meta(&conn, "job1", Path::new("file.txt")).unwrap();
        assert!(!deleted_again);
    }

    #[test]
    fn test_delete_all_file_meta() {
        let conn = setup_db();
        for i in 0..5 {
            let row = FileMetaRow {
                id: 0,
                job_name: "job1".to_string(),
                rel_path: PathBuf::from(format!("file{i}.txt")),
                size: 10,
                mtime_secs: 0,
                mtime_nanos: 0,
                blake3_hash: "h".to_string(),
            };
            upsert_file_meta(&conn, &row).unwrap();
        }

        let count = delete_all_file_meta(&conn, "job1").unwrap();
        assert_eq!(count, 5);
        assert_eq!(count_file_meta(&conn, "job1").unwrap(), 0);
    }

    #[test]
    fn test_count_file_meta() {
        let conn = setup_db();
        assert_eq!(count_file_meta(&conn, "job1").unwrap(), 0);

        let row = FileMetaRow {
            id: 0,
            job_name: "job1".to_string(),
            rel_path: PathBuf::from("f.txt"),
            size: 1,
            mtime_secs: 0,
            mtime_nanos: 0,
            blake3_hash: "h".to_string(),
        };
        upsert_file_meta(&conn, &row).unwrap();
        assert_eq!(count_file_meta(&conn, "job1").unwrap(), 1);
    }

    #[test]
    fn test_system_time_roundtrip() {
        let now = SystemTime::now();
        let (secs, nanos) = system_time_to_parts(now);
        let restored = parts_to_system_time(secs, nanos);

        let diff = now
            .duration_since(restored)
            .or_else(|_| restored.duration_since(now))
            .unwrap();
        // Should be within 1 microsecond (nanos are preserved exactly)
        assert!(diff.as_micros() < 1);
    }

    #[test]
    fn test_system_time_epoch() {
        let (secs, nanos) = system_time_to_parts(SystemTime::UNIX_EPOCH);
        assert_eq!(secs, 0);
        assert_eq!(nanos, 0);
        let restored = parts_to_system_time(0, 0);
        assert_eq!(restored, SystemTime::UNIX_EPOCH);
    }
}
