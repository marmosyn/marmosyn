// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Handler for `GET /api/v1/health` — simple healthcheck endpoint.
//!
//! Returns a 200 OK response with a JSON body indicating the server is running.
//! This endpoint does not require authentication.

use axum::Json;
use serde::Serialize;

/// Response body for the health check endpoint.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Always `"ok"` when the server is running.
    pub status: &'static str,
    /// The server version string.
    pub version: &'static str,
}

/// Handler for `GET /api/v1/health`.
pub async fn handle() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_returns_ok() {
        let Json(response) = handle().await;
        assert_eq!(response.status, "ok");
        assert!(!response.version.is_empty());
    }
}
