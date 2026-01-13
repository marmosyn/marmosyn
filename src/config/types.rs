//! Configuration types — all structs for TOML deserialization.
//!
//! These types represent the full MarmoSyn configuration file structure,
//! including server settings, receiver config, remote nodes, sync jobs,
//! safety backup, and encryption settings.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

// ─── Default value functions ───────────────────────────────────────────────

fn default_listen() -> String {
    "0.0.0.0:7854".to_string()
}

fn default_api_listen() -> String {
    "127.0.0.1:7855".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_true() -> bool {
    true
}

fn default_algorithm() -> String {
    "chacha20-poly1305".to_string()
}

// ─── Secret wrapper ────────────────────────────────────────────────────────

/// A wrapper type that prevents secrets from leaking into logs or Debug output.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    /// Creates a new secret from a string value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the secret value. Use with care — do not log the result.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret(***)")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "***")
    }
}

// ─── Top-level config ──────────────────────────────────────────────────────

/// Top-level application configuration, deserialized from TOML.
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    /// Global server settings.
    pub server: ServerConfig,

    /// Receiver configuration (optional — if absent, the server does not accept incoming files).
    #[serde(default)]
    pub receiver: Option<ReceiverConfig>,

    /// Encryption key management (required if any sync job has `encrypt = true`).
    #[serde(default)]
    pub encryption: Option<EncryptionConfig>,

    /// Remote nodes (receiver servers) referenced by sync jobs.
    #[serde(default, rename = "remote")]
    pub remote: Vec<RemoteNode>,

    /// Sync job definitions (sender side).
    #[serde(default, rename = "sync")]
    pub sync: Vec<SyncJob>,
}

// ─── Server config ─────────────────────────────────────────────────────────

/// `[server]` section — global server settings.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Address and port for the sync transport protocol.
    #[serde(default = "default_listen")]
    pub listen: String,

    /// Address for the HTTP API / Web UI.
    #[serde(default = "default_api_listen")]
    pub api_listen: String,

    /// Log level: trace | debug | info | warn | error.
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Directory for internal data (auto-detected by UID if None).
    pub data_dir: Option<PathBuf>,

    /// Directory for safety copies (auto: `<data_dir>/safety/` if None).
    pub safety_dir: Option<PathBuf>,

    /// Token for HTTP API request authorization.
    #[serde(default)]
    pub auth_token: Option<Secret>,

    /// Path to TLS certificate file (PEM format) for the transport listener.
    /// When both `tls_cert` and `tls_key` are set, the transport listener
    /// uses TLS; otherwise it falls back to plain TCP.
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,

    /// Path to TLS private key file (PEM format) for the transport listener.
    #[serde(default)]
    pub tls_key: Option<PathBuf>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            api_listen: default_api_listen(),
            log_level: default_log_level(),
            data_dir: None,
            safety_dir: None,
            auth_token: None,
            tls_cert: None,
            tls_key: None,
        }
    }
}

// ─── Receiver config ───────────────────────────────────────────────────────

/// `[receiver]` section — file receiver settings.
#[derive(Debug, Clone, Deserialize)]
pub struct ReceiverConfig {
    /// Whether the receiver is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Token that the sender must provide when connecting.
    pub auth_token: Secret,

    /// Allowed directories for saving incoming files.
    #[serde(default)]
    pub allowed_paths: Vec<AllowedPath>,
}

/// A single allowed path entry for the receiver.
#[derive(Debug, Clone, Deserialize)]
pub struct AllowedPath {
    /// Absolute path on disk where the receiver may write files.
    pub path: PathBuf,

    /// Optional short alias that senders can use in dest strings.
    pub alias: Option<String>,
}

// ─── Remote node ───────────────────────────────────────────────────────────

/// `[[remote]]` section — a named remote MarmoSyn receiver node.
#[derive(Debug, Clone, Deserialize)]
pub struct RemoteNode {
    /// Unique name used in dest strings: `"name:path"`.
    pub name: String,

    /// Host and port of the remote receiver: `"192.168.1.100:7854"`.
    pub host: String,

    /// Token for authentication on the receiver.
    pub auth_token: Secret,

    /// Optional path to a CA certificate for TLS verification.
    pub tls_ca: Option<PathBuf>,

    /// Allow self-signed certificates on the remote.
    #[serde(default)]
    pub allow_self_signed: bool,
}

// ─── Sync job ──────────────────────────────────────────────────────────────

/// `[[sync]]` section — a single synchronization job (sender side).
#[derive(Debug, Clone, Deserialize)]
pub struct SyncJob {
    /// Unique job name.
    pub name: String,

    /// Source directory to synchronize from.
    pub source: PathBuf,

    /// Exclusion patterns in gitignore format.
    #[serde(default)]
    pub exclude: Vec<String>,

    /// Per-job encryption flag. If true, files are encrypted before writing to dest.
    /// Key is loaded from the `[encryption]` section.
    #[serde(default)]
    pub encrypt: bool,

    /// Synchronization mode.
    pub mode: SyncMode,

    /// Cron expression (required if `mode = "schedule"`).
    pub schedule: Option<String>,

    /// Per-job safety backup configuration.
    #[serde(default)]
    pub safety: SafetyConfig,

    /// Single destination (string). Cannot be specified together with `dests`.
    pub dest: Option<String>,

    /// Multiple destinations (array of strings). Cannot be specified together with `dest`.
    pub dests: Option<Vec<String>>,
}

impl Default for SyncJob {
    fn default() -> Self {
        Self {
            name: String::new(),
            source: std::path::PathBuf::new(),
            exclude: vec![],
            encrypt: false,
            mode: SyncMode::Manual,
            schedule: None,
            safety: SafetyConfig::default(),
            dest: None,
            dests: None,
        }
    }
}

impl SyncJob {
    /// Returns a unified list of destination strings for this job.
    /// Called after validation, so exactly one of `dest` / `dests` is set.
    pub fn destinations(&self) -> Vec<&str> {
        if let Some(ref single) = self.dest {
            vec![single.as_str()]
        } else if let Some(ref multi) = self.dests {
            multi.iter().map(|s| s.as_str()).collect()
        } else {
            vec![]
        }
    }
}

// ─── Sync mode ─────────────────────────────────────────────────────────────

/// Synchronization mode for a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SyncMode {
    /// Triggered only by explicit user request.
    Manual,
    /// Runs on a cron schedule.
    Schedule,
    /// Monitors the source directory for filesystem events.
    Watch,
}

impl fmt::Display for SyncMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncMode::Manual => write!(f, "manual"),
            SyncMode::Schedule => write!(f, "schedule"),
            SyncMode::Watch => write!(f, "watch"),
        }
    }
}

// ─── Safety config ─────────────────────────────────────────────────────────

/// `[sync.safety]` section — per-job safety backup configuration.
///
/// Before overwriting or deleting a file on the destination, the old version
/// is copied to `<safety_dir>/<job_name>/<timestamp>/<rel_path>`.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct SafetyConfig {
    /// Whether safety backup is enabled for this job (default: false).
    #[serde(default)]
    pub enabled: bool,

    /// Retention period for safety copies.
    /// Format: `"7d"` (days), `"24h"` (hours), `"4w"` (weeks).
    /// If not set, copies are kept indefinitely.
    pub retention: Option<String>,

    /// Maximum total size of safety copies for this job.
    /// Format: `"500MB"`, `"10GB"`.
    /// If not set, no size limit is enforced.
    pub max_size: Option<String>,
}

// ─── Encryption config ─────────────────────────────────────────────────────

/// `[encryption]` section — key management for per-job file encryption.
///
/// This section describes only the algorithm and the key source.
/// Encryption is toggled per-job via `encrypt = true` in `[[sync]]`.
#[derive(Debug, Clone, Deserialize)]
pub struct EncryptionConfig {
    /// Encryption algorithm (only `"chacha20-poly1305"` supported in v0.1).
    #[serde(default = "default_algorithm")]
    pub algorithm: String,

    /// Key source: `"env:VAR_NAME"` | `"file:/path/to/keyfile"` | `"raw:base64key"`.
    pub key_source: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_debug_does_not_leak() {
        let s = Secret::new("super-secret");
        let debug = format!("{:?}", s);
        assert!(!debug.contains("super-secret"));
        assert!(debug.contains("***"));
    }

    #[test]
    fn test_secret_display_does_not_leak() {
        let s = Secret::new("super-secret");
        let display = format!("{}", s);
        assert_eq!(display, "***");
    }

    #[test]
    fn test_secret_expose_returns_value() {
        let s = Secret::new("super-secret");
        assert_eq!(s.expose(), "super-secret");
    }

    #[test]
    fn test_sync_mode_display() {
        assert_eq!(SyncMode::Manual.to_string(), "manual");
        assert_eq!(SyncMode::Schedule.to_string(), "schedule");
        assert_eq!(SyncMode::Watch.to_string(), "watch");
    }

    #[test]
    fn test_sync_job_destinations_single() {
        let job = SyncJob {
            name: "test".to_string(),
            source: PathBuf::from("/src"),
            exclude: vec![],
            encrypt: false,
            mode: SyncMode::Manual,
            schedule: None,
            safety: SafetyConfig::default(),
            dest: Some("/mnt/backup".to_string()),
            dests: None,
        };
        assert_eq!(job.destinations(), vec!["/mnt/backup"]);
    }

    #[test]
    fn test_sync_job_destinations_multiple() {
        let job = SyncJob {
            name: "test".to_string(),
            source: PathBuf::from("/src"),
            exclude: vec![],
            encrypt: false,
            mode: SyncMode::Manual,
            schedule: None,
            safety: SafetyConfig::default(),
            dest: None,
            dests: Some(vec!["/a".to_string(), "/b".to_string()]),
        };
        assert_eq!(job.destinations(), vec!["/a", "/b"]);
    }

    #[test]
    fn test_sync_job_destinations_empty() {
        let job = SyncJob {
            name: "test".to_string(),
            source: PathBuf::from("/src"),
            exclude: vec![],
            encrypt: false,
            mode: SyncMode::Manual,
            schedule: None,
            safety: SafetyConfig::default(),
            dest: None,
            dests: None,
        };
        assert!(job.destinations().is_empty());
    }

    #[test]
    fn test_safety_config_default() {
        let sc = SafetyConfig::default();
        assert!(!sc.enabled);
        assert!(sc.retention.is_none());
        assert!(sc.max_size.is_none());
    }

    #[test]
    fn test_deserialize_minimal_config() {
        let toml_str = r#"
[server]

[[sync]]
name = "docs"
source = "/home/user/docs"
mode = "manual"
dest = "/backup/docs"
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server.listen, "0.0.0.0:7854");
        assert_eq!(config.server.api_listen, "127.0.0.1:7855");
        assert_eq!(config.server.log_level, "info");
        assert!(config.receiver.is_none());
        assert!(config.encryption.is_none());
        assert!(config.remote.is_empty());
        assert_eq!(config.sync.len(), 1);
        assert_eq!(config.sync[0].name, "docs");
        assert!(!config.sync[0].encrypt);
        assert!(!config.sync[0].safety.enabled);
    }

    #[test]
    fn test_deserialize_full_config() {
        let toml_str = r#"
[server]
listen = "0.0.0.0:9000"
api_listen = "0.0.0.0:9001"
log_level = "debug"
data_dir = "/var/lib/marmosyn"
safety_dir = "/var/lib/marmosyn/safety"
auth_token = "my-api-token"

[receiver]
auth_token = "receiver-secret"
enabled = true

[[receiver.allowed_paths]]
path = "/mnt/backup"
alias = "backup"

[[receiver.allowed_paths]]
path = "/data/shared"

[encryption]
algorithm = "chacha20-poly1305"
key_source = "env:MARMOSYN_KEY"

[[remote]]
name = "office"
host = "192.168.1.100:7854"
auth_token = "office-token"

[[remote]]
name = "cloud"
host = "backup.example.com:7854"
auth_token = "cloud-token"
allow_self_signed = true

[[sync]]
name = "documents"
source = "/home/user/Documents"
exclude = ["*.tmp", ".cache/"]
encrypt = true
mode = "watch"
dests = ["/mnt/backup/docs", "office:backup/docs"]

[sync.safety]
enabled = true
retention = "30d"
max_size = "10GB"

[[sync]]
name = "photos"
source = "/home/user/Photos"
mode = "schedule"
schedule = "0 3 * * *"
dest = "/mnt/nas/photos"
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server.listen, "0.0.0.0:9000");
        assert_eq!(config.server.api_listen, "0.0.0.0:9001");
        assert_eq!(config.server.log_level, "debug");
        assert!(config.server.auth_token.is_some());

        let recv = config.receiver.as_ref().unwrap();
        assert!(recv.enabled);
        assert_eq!(recv.allowed_paths.len(), 2);
        assert_eq!(recv.allowed_paths[0].alias.as_deref(), Some("backup"));
        assert!(recv.allowed_paths[1].alias.is_none());

        let enc = config.encryption.as_ref().unwrap();
        assert_eq!(enc.algorithm, "chacha20-poly1305");
        assert_eq!(enc.key_source, "env:MARMOSYN_KEY");

        assert_eq!(config.remote.len(), 2);
        assert_eq!(config.remote[0].name, "office");
        assert!(!config.remote[0].allow_self_signed);
        assert!(config.remote[1].allow_self_signed);

        assert_eq!(config.sync.len(), 2);

        let docs = &config.sync[0];
        assert_eq!(docs.name, "documents");
        assert!(docs.encrypt);
        assert_eq!(docs.mode, SyncMode::Watch);
        assert!(docs.safety.enabled);
        assert_eq!(docs.safety.retention.as_deref(), Some("30d"));
        assert_eq!(docs.safety.max_size.as_deref(), Some("10GB"));
        assert!(docs.dest.is_none());
        assert_eq!(docs.dests.as_ref().unwrap().len(), 2);

        let photos = &config.sync[1];
        assert_eq!(photos.name, "photos");
        assert!(!photos.encrypt);
        assert_eq!(photos.mode, SyncMode::Schedule);
        assert_eq!(photos.schedule.as_deref(), Some("0 3 * * *"));
        assert_eq!(photos.dest.as_deref(), Some("/mnt/nas/photos"));
        assert!(photos.dests.is_none());
        assert!(!photos.safety.enabled);
    }
}
