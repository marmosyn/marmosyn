# MarmoSyn

> Unidirectional file synchronization and backup utility

A single statically-linked binary that simultaneously acts as a **sync server** (sender + receiver), **CLI client**, **HTTP API**, and **web interface** for management.

---

## Features

- **Unidirectional sync** — source is always the single source of truth (no conflicts)
- **Three sync modes** per job: `manual`, `schedule` (cron), `watch` (filesystem events)
- **Safety backup** — saves a copy of every file before overwriting or deleting it, with configurable retention period and size limits
- **Per-job file encryption** using ChaCha20-Poly1305 (AEAD)
- **Remote sync** over a custom binary protocol with optional TLS — no SSH or rsync required
- **Delta sync** — transfers only changed blocks (rolling checksum)
- **Gitignore-style exclude patterns** per job
- **BLAKE3** file hashing for fast change detection
- **Embedded Web UI** — served directly from the binary, no separate deployment
- **HTTP API** (axum) with Bearer token authentication
- **Structured logging** — pretty for terminals, JSON for log aggregators
- Works correctly as both **root** and a **regular user** (paths resolved automatically)

---

## Installation

### From source

Requires Rust 1.75+ (stable toolchain).

```bash
git clone https://github.com/marmosyn/marmosyn.git
cd marmosyn
cargo build --release
# Binary at: target/release/marmosyn
```

### Install to system

```bash
cargo install --path .
```

---

## Quick Start

**1. Generate a config file:**

```bash
marmosyn config init
```

**2. Edit the config** (`~/.config/marmosyn/config.toml` or `/etc/marmosyn/config.toml` for root):

```toml
[server]
listen     = "0.0.0.0:7854"   # transport protocol port
api_listen = "127.0.0.1:7855" # HTTP API / Web UI port
auth_token = "your-secret-token"

[[sync]]
name   = "documents"
source = "/home/alice/Documents"
dest   = "/mnt/backup/documents"
mode   = "watch"

[safety]
enabled   = true
retention = "30d"
max_size  = "2GB"
```

**3. Start the server:**

```bash
marmosyn server
# or as a daemon:
marmosyn server --daemon
```

**4. Trigger a sync manually:**

```bash
marmosyn sync documents
# or sync all jobs:
marmosyn sync --all
```

**5. Open the Web UI:**

Navigate to `http://127.0.0.1:7855` in your browser.

---

## Configuration Reference

The config file is searched in this order:

1. `--config` flag / `$MARMOSYN_CONFIG` env var
2. `./marmosyn.toml` (current directory)
3. `~/.config/marmosyn/config.toml` (regular user)
4. `/etc/marmosyn/config.toml` (root)

### `[server]`

| Field        | Default               | Description                                    |
|--------------|-----------------------|------------------------------------------------|
| `listen`     | `0.0.0.0:7854`        | Transport protocol listener address            |
| `api_listen` | `127.0.0.1:7855`      | HTTP API + Web UI listener address             |
| `log_level`  | `info`                | Log level: `trace`, `debug`, `info`, `warn`, `error` |
| `auth_token` | *(none)*              | Bearer token for HTTP API auth (optional)      |
| `data_dir`   | *(auto)*              | Directory for internal state and SQLite DB     |
| `safety_dir` | `<data_dir>/safety/`  | Root directory for safety backup copies        |
| `tls_cert`   | *(none)*              | PEM certificate for transport TLS              |
| `tls_key`    | *(none)*              | PEM private key for transport TLS              |

### `[receiver]`

Enables the node to accept incoming files from remote senders.

```toml
[receiver]
enabled    = true
auth_token = "receiver-secret"

[[receiver.allowed_paths]]
path  = "/var/backups/photos"
alias = "photos"

[[receiver.allowed_paths]]
path  = "/var/backups/docs"
alias = "docs"
```

### `[[remote]]`

Defines a named remote receiver node.

```toml
[[remote]]
name       = "office-server"
host       = "192.168.1.100:7854"
auth_token = "receiver-secret"
# tls_ca            = "/etc/marmosyn/ca.pem"  # optional
# allow_self_signed = true                     # optional
```

### `[[sync]]`

Defines a synchronization job (sender side).

```toml
[[sync]]
name    = "photos"
source  = "/home/alice/Photos"
dest    = "office-server:photos"   # remote alias
# dests = ["/mnt/local", "office-server:photos"]  # multiple destinations
mode    = "schedule"
schedule = "0 2 * * *"             # cron: every day at 02:00
exclude  = ["*.tmp", ".DS_Store"]
encrypt  = false

[sync.safety]
enabled   = true
retention = "7d"
max_size  = "500MB"
```

**Destination formats:**
- `/local/absolute/path` — local filesystem
- `remote_name:path` — remote node (absolute path on receiver)
- `remote_name:alias` — receiver alias
- `remote_name:alias/subpath` — alias with subdirectory

**Sync modes:**

| Mode       | Trigger                              |
|------------|--------------------------------------|
| `manual`   | Explicit `marmosyn sync <job>` call  |
| `schedule` | Cron expression (requires `schedule`)|
| `watch`    | Filesystem events on `source` dir    |

### `[encryption]`

Required when any `[[sync]]` job has `encrypt = true`.

```toml
[encryption]
algorithm  = "chacha20-poly1305"
key_source = "env:MARMOSYN_KEY"
# key_source = "file:/etc/marmosyn/keyfile"
# key_source = "raw:base64encodedkey..."
```

---

## CLI Reference

```
marmosyn [OPTIONS] <COMMAND>

Options:
  -c, --config <FILE>    Config file path (env: MARMOSYN_CONFIG)
      --server <URL>     API server URL (env: MARMOSYN_SERVER)
      --token <TOKEN>    API auth token
      --format <FMT>     Output format: text | json  [default: text]
  -v, --verbose          Increase log verbosity

Commands:
  server    Start the MarmoSyn server
  sync      Trigger manual synchronization
  status    Show server status (sender + receiver)
  jobs      Manage sync jobs (list, info, sync, stop, history)
  remotes   Manage remote nodes (list, ping)
  config    Configuration management (check, show, init)
  login     Save API credentials
  log       View server logs
  version   Show version and build info
```

### Examples

```bash
# Start server in foreground
marmosyn server

# Start server as a daemon
marmosyn server --daemon

# Dry-run a specific job
marmosyn sync photos --dry-run

# List all jobs and their status
marmosyn jobs list

# Show job details
marmosyn jobs info photos

# Trigger a job via API
marmosyn jobs sync photos

# Ping a remote node
marmosyn remotes ping office-server

# Follow live logs
marmosyn log --follow

# Save token for a server
marmosyn login --server http://192.168.1.10:7855 --token my-token

# Validate config file
marmosyn config check

# Show effective config
marmosyn config show

# Output as JSON (for scripting)
marmosyn jobs list --format json
```

---

## HTTP API

Base URL: `http://127.0.0.1:7855/api/v1`

Authentication: `Authorization: Bearer <token>` (not required if `auth_token` is unset in config).

| Method | Endpoint                        | Description                      |
|--------|---------------------------------|----------------------------------|
| GET    | `/health`                       | Health check (always public)     |
| GET    | `/status`                       | Server status (sender + receiver)|
| GET    | `/jobs`                         | List all sync jobs               |
| GET    | `/jobs/:name`                   | Job details                      |
| POST   | `/jobs/:name/sync`              | Trigger job sync                 |
| POST   | `/jobs/:name/stop`              | Stop running job                 |
| GET    | `/jobs/:name/history`           | Sync history for a job           |
| GET    | `/remotes`                      | List configured remote nodes     |
| GET    | `/remotes/:name/ping`           | Ping a remote node               |
| GET    | `/receiver/status`              | Receiver status and stats        |
| GET    | `/config`                       | Current effective configuration  |

---

## Environment Variables

| Variable              | Description                                              |
|-----------------------|----------------------------------------------------------|
| `MARMOSYN_CONFIG`     | Path to config file                                      |
| `MARMOSYN_SERVER`     | API server URL for CLI commands                          |
| `MARMOSYN_LOG`        | Log filter (same syntax as `RUST_LOG`)                   |
| `MARMOSYN_LOG_FORMAT` | Log output format: `json` or `pretty`                    |
| `RUST_LOG`            | Fallback log filter (used if `MARMOSYN_LOG` is not set)  |

---

## Architecture

```
marmosyn (single binary)
├── Sender      — scans source, diffs against dest, pushes changes
├── Receiver    — TCP/TLS listener, validates allowed_paths, writes files
├── HTTP API    — axum REST API (port 7855)
└── Web UI      — embedded SPA, served from binary (port 7855)
```

### Sync data flow

```
source dir
  └─ scanner (walkdir + BLAKE3) → FileTree
         │
  excluder (gitignore patterns)
         │
  diff vs. dest FileTree → SyncPlan { to_copy, to_update, to_delete }
         │
  DestRouter
    ├─ local path      → LocalExecutor (std::fs)
    └─ remote:path     → RemoteExecutor → transport client (TCP/TLS)
```

### Transport protocol

Custom length-prefixed binary framing (`MSYN` magic + JSON payload). Delta sync uses rolling checksums to minimize transferred bytes. TLS is enabled automatically when `tls_cert` and `tls_key` are set.

---

## Building and Testing

```bash
# Build
cargo build
cargo build --release

# Run all tests
cargo test --all-targets

# Lint
cargo clippy --all-targets -- -W clippy::all

# Format
cargo fmt
```

---

## Data Storage

| Path (user)                              | Path (root)                    | Contents                    |
|------------------------------------------|--------------------------------|-----------------------------|
| `~/.local/share/marmosyn/marmosyn.db`   | `/var/lib/marmosyn/marmosyn.db`| SQLite: metadata, history   |
| `~/.local/share/marmosyn/safety/`       | `/var/lib/marmosyn/safety/`    | Safety backup copies        |
| `~/.config/marmosyn/config.toml`         | `/etc/marmosyn/config.toml`    | Configuration file          |
| `~/.config/marmosyn/credentials.toml`   | —                              | Saved API credentials       |

---

## License

MIT
