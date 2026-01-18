# MarmoSyn — Copilot Instructions

## Build, Test, and Lint

```bash
# Build
cargo build
cargo build --release

# Run all tests (unit + integration)
cargo test --all-targets

# Run a single test by name
cargo test test_secret_debug_does_not_leak
cargo test --test <integration_test_name>

# Run doc tests
cargo test --doc

# Lint
cargo clippy --all-targets -- -W clippy::all

# Format check
cargo fmt --check

# Format (apply)
cargo fmt
```

CI enforces `RUSTFLAGS="-D warnings"` — all clippy warnings are errors in CI.

The `MARMOSYN_LOG` / `RUST_LOG` env vars control log level at runtime. `MARMOSYN_LOG_FORMAT=json|pretty` overrides log format.

## Architecture

MarmoSyn is a **single binary** (`marmosyn`) that acts as:

1. **Sender** — scans source, computes diffs, pushes file deltas to destinations.
2. **Receiver** — listens on a TCP/TLS port (default `0.0.0.0:7854`) and accepts incoming files.
3. **HTTP API + Web UI** — axum server on `127.0.0.1:7855` (`/api/v1/*` + embedded SPA at `/`).
4. **CLI client** — subcommands that talk to a running server via its HTTP API.

### Module map

| Module | Role |
|---|---|
| `src/config/` | TOML config types (`AppConfig`), loader, path resolution, validation |
| `src/core/` | Sync engine: scan → diff → plan → execute. Local and remote executors. |
| `src/transport/` | Custom binary protocol (TCP/TLS) between sender and receiver |
| `src/server/` | Daemon startup, `JobManager`, scheduler (cron), filesystem watcher |
| `src/api/` | axum router, auth middleware, request handlers, shared `AppState` |
| `src/web/` | `rust-embed` static file server for the SPA |
| `src/cli/` | Clap CLI definitions and per-command handlers |
| `src/db/` | SQLite via rusqlite: file metadata, run history, migrations |
| `src/crypto/` | ChaCha20-Poly1305 per-file encryption; Argon2id key derivation |
| `src/credentials/` | CLI token storage (`~/.config/marmosyn/credentials.toml`), optional password encryption |

### Sync data flow

```
source dir
  └─ scanner (walkdir) → FileTree
         ↓
  excluder (gitignore patterns via `ignore` crate)
         ↓
  diff vs. dest FileTree → SyncPlan { to_copy, to_update, to_delete }
         ↓
  DestRouter
    ├─ local path  → SyncExecutor (std::fs)
    └─ "remote:path" → RemoteExecutor → transport::client (TCP/TLS)
```

Remote destinations use the format `"remote_name:path"` or `"alias/subpath"`. The receiver enforces `allowed_paths` and resolves aliases defined in `[[receiver.allowed_paths]]`.

### Transport protocol

Custom length-prefixed binary framing (`MSYN` magic, 4-byte BE length, 1-byte message type, JSON payload). Defined in `src/transport/protocol.rs`. TLS is optional — enabled when `tls_cert` + `tls_key` are both set in config.

### Server runtime

`server::daemon::run_server` creates a `tokio::Runtime`, starts both TCP listener and axum HTTP server, and spins up a `JobManager`. Jobs can run in three modes: `manual`, `schedule` (cron via the `cron` crate), or `watch` (filesystem events via `notify`/`notify-debouncer-full`). Graceful shutdown is coordinated through a `tokio::sync::broadcast` channel stored in `AppState`.

### HTTP API auth

Bearer token auth (`Authorization: Bearer <token>`). When `server.auth_token` is not set in config, all requests pass. The `/api/v1/health` endpoint is always public.

### Web assets

`web/index.html` (and any other files under `web/`) are embedded into the binary at compile time via `rust-embed`. In debug builds, files are read from disk. The SPA uses hash-based routing; any unmatched path falls back to `index.html`.

## Key Conventions

### `Secret` wrapper
Sensitive strings (auth tokens, keys) use `config::types::Secret`. Never log or `format!` a `Secret` directly — use `.expose()` only where the raw value is needed. `Debug` and `Display` always print `***`.

### Destination strings
A destination is one of:
- An absolute local path: `/mnt/backup/docs`
- A remote reference: `remote_name:path` or `remote_name:alias/subpath`

Parsed by `config::dest_parser`. Validated in `config::validation` — a job must have exactly one of `dest` (string) or `dests` (array), not both.

### Config file location
Resolved by `config::paths`: `--config` flag → `$MARMOSYN_CONFIG` env → `~/.config/marmosyn/config.toml` → `/etc/marmosyn/config.toml`. Default ports: `0.0.0.0:7854` (transport) and `127.0.0.1:7855` (HTTP API).

### Error handling
Use `anyhow::Result` for application-level errors (CLI, main dispatch). Use `thiserror`-derived error enums for library-level errors within modules.

### Testing patterns
- Unit tests live in `#[cfg(test)]` blocks at the bottom of each source file.
- Integration tests are in `tests/`.
- Test fixtures (TLS cert/key for transport tests) are in `tests/fixtures/`.
- axum handler tests use `tower::ServiceExt::oneshot` to drive the router directly without binding a port (see `src/api/mod.rs`).
- DB tests use `rusqlite::Connection::open_in_memory()`.
