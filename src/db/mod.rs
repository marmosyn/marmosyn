// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Database module — SQLite state storage for sync metadata and history.
//!
//! This module provides persistent storage for file metadata, synchronization
//! history, and receiver statistics using an embedded SQLite database.

pub mod file_meta;
pub mod history;
pub mod migrations;
pub mod receiver_stats;
