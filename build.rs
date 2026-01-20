// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Build script for MarmoSyn.
//!
//! Sets compile-time environment variables used by the binary.

fn main() {
    // Expose the target triple so it can be read via env!("TARGET") in code.
    println!(
        "cargo:rustc-env=TARGET={}",
        std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string())
    );
}
