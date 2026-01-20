// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! HTTP API request handlers.
//!
//! Each submodule implements handlers for a specific API resource group.

pub mod config;
pub mod health;
pub mod jobs;
pub mod receiver;
pub mod remotes;
pub mod status;
