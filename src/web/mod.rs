//! Web UI module — serves embedded static files (HTML/CSS/JS) for the web interface.
//!
//! Uses `rust-embed` to bundle the `web/` directory into the binary at compile time.
//! Static files are served at the root path (`/`) with appropriate MIME types.
//! The `index.html` is served for both `/` and any unmatched path to support
//! client-side hash-based routing.

use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use rust_embed::Embed;

/// Embedded web assets from the `web/` directory.
///
/// At compile time, all files under `web/` are bundled into the binary.
/// In debug builds, files are read from disk for easier development.
#[derive(Embed)]
#[folder = "web/"]
struct WebAssets;

/// Creates the axum [`Router`] for serving the embedded web UI.
///
/// Routes:
/// - `GET /` — serves `index.html`
/// - `GET /*path` — serves the requested static file, or falls back to `index.html`
///   for client-side routing support.
///
/// This router should be merged into the main application router at a lower
/// priority than the `/api/v1/` routes so that API requests are not intercepted.
pub fn create_web_router<S: Clone + Send + Sync + 'static>() -> Router<S> {
    Router::new()
        .route("/", get(serve_index))
        .fallback(get(serve_static))
}

/// Serves the `index.html` file.
async fn serve_index() -> Response {
    match WebAssets::get("index.html") {
        Some(content) => Html(content.data.to_vec()).into_response(),
        None => (StatusCode::NOT_FOUND, "index.html not found").into_response(),
    }
}

/// Serves a static file by path, falling back to `index.html` for SPA routing.
///
/// If the requested path matches an embedded file, it is served with the
/// appropriate `Content-Type` header. Otherwise, `index.html` is returned
/// to support the client-side hash router.
async fn serve_static(uri: axum::http::Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    // Don't serve static files for API paths (shouldn't happen due to routing
    // priority, but guard against it).
    if path.starts_with("api/") {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }

    // Try to find the exact file
    if let Some(content) = WebAssets::get(path) {
        let mime = mime_type_for(path);
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, mime)],
            content.data.to_vec(),
        )
            .into_response();
    }

    // Fallback to index.html for client-side routing
    match WebAssets::get("index.html") {
        Some(content) => Html(content.data.to_vec()).into_response(),
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

/// Returns the MIME type string for a file based on its extension.
fn mime_type_for(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("txt") => "text/plain; charset=utf-8",
        Some("xml") => "application/xml; charset=utf-8",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mime_type_html() {
        assert_eq!(mime_type_for("index.html"), "text/html; charset=utf-8");
        assert_eq!(mime_type_for("page.htm"), "text/html; charset=utf-8");
    }

    #[test]
    fn test_mime_type_css() {
        assert_eq!(mime_type_for("style.css"), "text/css; charset=utf-8");
    }

    #[test]
    fn test_mime_type_js() {
        assert_eq!(
            mime_type_for("app.js"),
            "application/javascript; charset=utf-8"
        );
    }

    #[test]
    fn test_mime_type_json() {
        assert_eq!(
            mime_type_for("data.json"),
            "application/json; charset=utf-8"
        );
    }

    #[test]
    fn test_mime_type_images() {
        assert_eq!(mime_type_for("logo.png"), "image/png");
        assert_eq!(mime_type_for("photo.jpg"), "image/jpeg");
        assert_eq!(mime_type_for("photo.jpeg"), "image/jpeg");
        assert_eq!(mime_type_for("anim.gif"), "image/gif");
        assert_eq!(mime_type_for("icon.svg"), "image/svg+xml");
        assert_eq!(mime_type_for("favicon.ico"), "image/x-icon");
    }

    #[test]
    fn test_mime_type_fonts() {
        assert_eq!(mime_type_for("font.woff"), "font/woff");
        assert_eq!(mime_type_for("font.woff2"), "font/woff2");
        assert_eq!(mime_type_for("font.ttf"), "font/ttf");
    }

    #[test]
    fn test_mime_type_unknown() {
        assert_eq!(mime_type_for("file.xyz"), "application/octet-stream");
        assert_eq!(mime_type_for("noext"), "application/octet-stream");
    }

    #[test]
    fn test_embedded_index_html_exists() {
        // The web/ directory should contain index.html at compile time
        let asset = WebAssets::get("index.html");
        assert!(asset.is_some(), "index.html should be embedded");
    }

    #[test]
    fn test_embedded_index_html_content() {
        let asset = WebAssets::get("index.html").unwrap();
        let content = std::str::from_utf8(&asset.data).unwrap();
        assert!(
            content.contains("MarmoSyn"),
            "index.html should contain MarmoSyn"
        );
        assert!(
            content.contains("<!DOCTYPE html>"),
            "index.html should be a valid HTML document"
        );
    }

    #[test]
    fn test_mime_type_for_nested_path() {
        assert_eq!(
            mime_type_for("assets/css/main.css"),
            "text/css; charset=utf-8"
        );
        assert_eq!(
            mime_type_for("deep/nested/script.js"),
            "application/javascript; charset=utf-8"
        );
    }
}
