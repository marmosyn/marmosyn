//! Core synchronization engine.
//!
//! This module contains the fundamental building blocks for file synchronization:
//! - File tree scanning and metadata collection
//! - Exclude pattern filtering (gitignore-style)
//! - Diff computation between source and destination
//! - Sync plan generation and execution
//! - Destination routing (local and remote)
//! - Safety backup handling
//! - BLAKE3 file hashing

pub mod dest_router;
pub mod diff;
pub mod excluder;
pub mod executor;
pub mod file_tree;
pub mod hasher;
pub mod remote_executor;
pub mod safety;
pub mod scanner;
pub mod sync_plan;
