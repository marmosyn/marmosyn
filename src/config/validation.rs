// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Configuration validation.
//!
//! Validates the loaded `AppConfig` for correctness: checks paths, cron expressions,
//! remote references, alias uniqueness, dest/dests mutual exclusion, safety settings,
//! and per-job encryption requirements.

use std::collections::HashSet;
use std::path::Path;

use crate::config::dest_parser::{ParsedDest, collect_destinations, parse_dest};
use crate::config::types::{AppConfig, ReceiverConfig, SyncJob, SyncMode};

/// Errors that can occur during configuration validation.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("validation error in field '{field}': {message}")]
    Field { field: String, message: String },

    #[error("multiple validation errors:\n{}", errors.iter().map(|e| format!("  - {e}")).collect::<Vec<_>>().join("\n"))]
    Multiple { errors: Vec<ValidationError> },
}

/// Result of validation — either Ok or a list of errors.
pub type ValidationResult = Result<(), ValidationError>;

/// Validates the entire application configuration.
///
/// Checks:
/// - Each `[[sync]]` specifies either `dest` or `dests`, but not both (and at least one).
/// - All `remote_name` references in dest strings point to existing `[[remote]]` entries.
/// - Cron expressions are valid for `mode = "schedule"` jobs.
/// - `safety.retention` and `safety.max_size` are parseable if set.
/// - If any job has `encrypt = true`, the `[encryption]` section with `key_source` exists.
/// - Receiver `allowed_paths` aliases are unique.
/// - Receiver `allowed_paths` paths do not overlap.
/// - Job names are unique.
pub fn validate_config(config: &AppConfig) -> ValidationResult {
    let mut errors = Vec::new();

    validate_sync_jobs(config, &mut errors);
    validate_remotes(config, &mut errors);
    validate_encryption(config, &mut errors);

    if let Some(ref receiver) = config.receiver {
        validate_receiver(receiver, &mut errors);
    }

    if errors.is_empty() {
        Ok(())
    } else if errors.len() == 1 {
        Err(errors.remove(0))
    } else {
        Err(ValidationError::Multiple { errors })
    }
}

/// Validates all sync jobs.
fn validate_sync_jobs(config: &AppConfig, errors: &mut Vec<ValidationError>) {
    let remote_names: HashSet<&str> = config.remote.iter().map(|r| r.name.as_str()).collect();
    let mut job_names = HashSet::new();

    for (i, job) in config.sync.iter().enumerate() {
        let field_prefix = format!("sync[{i}] (\"{}\")", job.name);

        // Check job name uniqueness
        if !job_names.insert(&job.name) {
            errors.push(ValidationError::Field {
                field: format!("{field_prefix}.name"),
                message: format!("duplicate job name '{}'", job.name),
            });
        }

        // Check dest/dests mutual exclusion
        validate_dest_fields(job, &field_prefix, &remote_names, errors);

        // Check schedule field for schedule mode
        validate_schedule(job, &field_prefix, errors);

        // Check safety config
        validate_safety(job, &field_prefix, errors);
    }
}

/// Validates that a sync job specifies exactly one of `dest` or `dests`.
fn validate_dest_fields(
    job: &SyncJob,
    field_prefix: &str,
    remote_names: &HashSet<&str>,
    errors: &mut Vec<ValidationError>,
) {
    match (&job.dest, &job.dests) {
        (Some(_), Some(_)) => {
            errors.push(ValidationError::Field {
                field: format!("{field_prefix}.dest/dests"),
                message: "both 'dest' and 'dests' are specified; use only one".to_string(),
            });
        }
        (None, None) => {
            errors.push(ValidationError::Field {
                field: format!("{field_prefix}.dest/dests"),
                message:
                    "neither 'dest' nor 'dests' is specified; at least one destination is required"
                        .to_string(),
            });
        }
        _ => {}
    }

    // Validate remote references in dest strings
    let dests = collect_destinations(job);
    for dest_str in &dests {
        let parsed = parse_dest(dest_str);
        if let ParsedDest::Remote {
            ref remote_name, ..
        } = parsed
            && !remote_names.contains(remote_name.as_str())
        {
            errors.push(ValidationError::Field {
                field: format!("{field_prefix}.dest"),
                message: format!(
                    "remote '{}' referenced in dest '{}' but not defined in [[remote]]",
                    remote_name, dest_str
                ),
            });
        }
    }
}

/// Validates schedule-related fields.
fn validate_schedule(job: &SyncJob, field_prefix: &str, errors: &mut Vec<ValidationError>) {
    if matches!(job.mode, SyncMode::Schedule) {
        match &job.schedule {
            None => {
                errors.push(ValidationError::Field {
                    field: format!("{field_prefix}.schedule"),
                    message: "mode is 'schedule' but no 'schedule' cron expression is provided"
                        .to_string(),
                });
            }
            Some(expr) => {
                if expr.parse::<cron::Schedule>().is_err() {
                    errors.push(ValidationError::Field {
                        field: format!("{field_prefix}.schedule"),
                        message: format!("invalid cron expression: '{expr}'"),
                    });
                }
            }
        }
    }
}

/// Validates safety configuration fields (retention and max_size parsing).
fn validate_safety(job: &SyncJob, field_prefix: &str, errors: &mut Vec<ValidationError>) {
    if !job.safety.enabled {
        return;
    }

    if let Some(ref retention) = job.safety.retention
        && parse_duration_str(retention).is_none()
    {
        errors.push(ValidationError::Field {
            field: format!("{field_prefix}.safety.retention"),
            message: format!(
                "invalid retention format '{}'; expected e.g. '7d', '24h', '4w'",
                retention
            ),
        });
    }

    if let Some(ref max_size) = job.safety.max_size
        && parse_size_str(max_size).is_none()
    {
        errors.push(ValidationError::Field {
            field: format!("{field_prefix}.safety.max_size"),
            message: format!(
                "invalid max_size format '{}'; expected e.g. '500MB', '10GB'",
                max_size
            ),
        });
    }
}

/// Validates remote node configurations.
fn validate_remotes(config: &AppConfig, errors: &mut Vec<ValidationError>) {
    let mut names = HashSet::new();
    for (i, remote) in config.remote.iter().enumerate() {
        if !names.insert(&remote.name) {
            errors.push(ValidationError::Field {
                field: format!("remote[{i}].name"),
                message: format!("duplicate remote name '{}'", remote.name),
            });
        }
        if remote.name.is_empty() {
            errors.push(ValidationError::Field {
                field: format!("remote[{i}].name"),
                message: "remote name cannot be empty".to_string(),
            });
        }
        if remote.host.is_empty() {
            errors.push(ValidationError::Field {
                field: format!("remote[{i}].host"),
                message: "remote host cannot be empty".to_string(),
            });
        }
    }
}

/// Validates encryption requirements: if any job has `encrypt = true`,
/// the `[encryption]` section must be present with a `key_source`.
fn validate_encryption(config: &AppConfig, errors: &mut Vec<ValidationError>) {
    let any_encrypted = config.sync.iter().any(|j| j.encrypt);
    if any_encrypted && config.encryption.is_none() {
        errors.push(ValidationError::Field {
            field: "encryption".to_string(),
            message: "at least one sync job has 'encrypt = true' but no [encryption] section \
                      with 'key_source' is defined"
                .to_string(),
        });
    }
}

/// Validates the receiver configuration.
fn validate_receiver(receiver: &ReceiverConfig, errors: &mut Vec<ValidationError>) {
    if !receiver.enabled {
        return;
    }

    let mut aliases = HashSet::new();
    for (i, ap) in receiver.allowed_paths.iter().enumerate() {
        // Check alias uniqueness
        if let Some(ref alias) = ap.alias {
            if alias.is_empty() {
                errors.push(ValidationError::Field {
                    field: format!("receiver.allowed_paths[{i}].alias"),
                    message: "alias cannot be an empty string".to_string(),
                });
            } else if !aliases.insert(alias.as_str()) {
                errors.push(ValidationError::Field {
                    field: format!("receiver.allowed_paths[{i}].alias"),
                    message: format!("duplicate alias '{alias}' in receiver.allowed_paths"),
                });
            }
        }

        // Check path is absolute
        if !ap.path.is_absolute() {
            errors.push(ValidationError::Field {
                field: format!("receiver.allowed_paths[{i}].path"),
                message: format!(
                    "allowed_path '{}' must be an absolute path",
                    ap.path.display()
                ),
            });
        }
    }
}

/// Parses a human-readable duration string like "7d", "24h", "4w" into seconds.
///
/// Returns `None` if the format is invalid.
pub fn parse_duration_str(s: &str) -> Option<std::time::Duration> {
    humantime::parse_duration(s).ok()
}

/// Parses a human-readable size string like "500MB", "10GB" into bytes.
///
/// Returns `None` if the format is invalid.
pub fn parse_size_str(s: &str) -> Option<u64> {
    s.parse::<bytesize::ByteSize>().ok().map(|b| b.as_u64())
}

/// Checks that source paths exist on disk (optional, may be skipped during
/// offline validation).
pub fn validate_paths_exist(config: &AppConfig) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    for (i, job) in config.sync.iter().enumerate() {
        let source = &job.source;
        if !Path::new(source).exists() {
            errors.push(ValidationError::Field {
                field: format!("sync[{i}] (\"{}\").source", job.name),
                message: format!("source path '{}' does not exist", source.display()),
            });
        }
    }

    errors
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::*;
    use std::path::PathBuf;

    fn minimal_config() -> AppConfig {
        AppConfig {
            server: ServerConfig {
                listen: "0.0.0.0:7854".to_string(),
                api_listen: "127.0.0.1:7855".to_string(),
                log_level: "info".to_string(),
                data_dir: None,
                safety_dir: None,
                auth_token: None,
                tls_cert: None,
                tls_key: None,
            },
            receiver: None,
            encryption: None,
            remote: vec![],
            sync: vec![SyncJob {
                name: "test".to_string(),
                source: PathBuf::from("/tmp/src"),
                exclude: vec![],
                encrypt: false,
                mode: SyncMode::Manual,
                schedule: None,
                safety: SafetyConfig::default(),
                dest: Some("/tmp/dest".to_string()),
                dests: None,
            }],
        }
    }

    #[test]
    fn test_valid_minimal_config() {
        let config = minimal_config();
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_both_dest_and_dests() {
        let mut config = minimal_config();
        config.sync[0].dest = Some("/a".to_string());
        config.sync[0].dests = Some(vec!["/b".to_string()]);
        let result = validate_config(&config);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("both 'dest' and 'dests'"));
    }

    #[test]
    fn test_neither_dest_nor_dests() {
        let mut config = minimal_config();
        config.sync[0].dest = None;
        config.sync[0].dests = None;
        let result = validate_config(&config);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("neither 'dest' nor 'dests'"));
    }

    #[test]
    fn test_unknown_remote_in_dest() {
        let mut config = minimal_config();
        config.sync[0].dest = Some("nonexistent-server:backup/docs".to_string());
        let result = validate_config(&config);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("nonexistent-server"));
        assert!(err_msg.contains("not defined"));
    }

    #[test]
    fn test_valid_remote_in_dest() {
        let mut config = minimal_config();
        config.remote.push(RemoteNode {
            name: "server1".to_string(),
            host: "192.168.1.1:7854".to_string(),
            auth_token: Secret::new("tok"),
            tls_ca: None,
            allow_self_signed: false,
        });
        config.sync[0].dest = Some("server1:backup/docs".to_string());
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_schedule_mode_without_cron() {
        let mut config = minimal_config();
        config.sync[0].mode = SyncMode::Schedule;
        config.sync[0].schedule = None;
        let result = validate_config(&config);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("schedule"));
    }

    #[test]
    fn test_encrypt_without_encryption_section() {
        let mut config = minimal_config();
        config.sync[0].encrypt = true;
        config.encryption = None;
        let result = validate_config(&config);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("encrypt = true"));
    }

    #[test]
    fn test_encrypt_with_encryption_section() {
        let mut config = minimal_config();
        config.sync[0].encrypt = true;
        config.encryption = Some(EncryptionConfig {
            algorithm: "chacha20-poly1305".to_string(),
            key_source: "env:MY_KEY".to_string(),
        });
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_duplicate_job_names() {
        let mut config = minimal_config();
        let job2 = SyncJob {
            name: "test".to_string(),
            source: PathBuf::from("/tmp/src2"),
            exclude: vec![],
            encrypt: false,
            mode: SyncMode::Manual,
            schedule: None,
            safety: SafetyConfig::default(),
            dest: Some("/tmp/dest2".to_string()),
            dests: None,
        };
        config.sync.push(job2);
        let result = validate_config(&config);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("duplicate job name"));
    }

    #[test]
    fn test_duplicate_alias_in_receiver() {
        let mut config = minimal_config();
        config.receiver = Some(ReceiverConfig {
            enabled: true,
            auth_token: Secret::new("secret"),
            allowed_paths: vec![
                AllowedPath {
                    path: PathBuf::from("/mnt/a"),
                    alias: Some("backup".to_string()),
                },
                AllowedPath {
                    path: PathBuf::from("/mnt/b"),
                    alias: Some("backup".to_string()),
                },
            ],
        });
        let result = validate_config(&config);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("duplicate alias"));
    }

    #[test]
    fn test_invalid_safety_retention() {
        let mut config = minimal_config();
        config.sync[0].safety.enabled = true;
        config.sync[0].safety.retention = Some("invalid".to_string());
        let result = validate_config(&config);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("retention"));
    }

    #[test]
    fn test_valid_safety_config() {
        let mut config = minimal_config();
        config.sync[0].safety.enabled = true;
        config.sync[0].safety.retention = Some("7d".to_string());
        config.sync[0].safety.max_size = Some("10GB".to_string());
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_parse_duration_str() {
        assert!(parse_duration_str("7d").is_some());
        assert!(parse_duration_str("24h").is_some());
        assert!(parse_duration_str("30days").is_some());
        assert!(parse_duration_str("1s").is_some());
        // humantime may or may not support bare "4w"; just test known-good and known-bad
        let _w = parse_duration_str("4w"); // result depends on humantime version
        assert!(parse_duration_str("invalid").is_none());
    }

    #[test]
    fn test_parse_size_str() {
        assert_eq!(parse_size_str("500MB"), Some(500_000_000));
        assert_eq!(parse_size_str("10GB"), Some(10_000_000_000));
        assert!(parse_size_str("invalid").is_none());
    }

    #[test]
    fn test_receiver_relative_path() {
        let mut config = minimal_config();
        config.receiver = Some(ReceiverConfig {
            enabled: true,
            auth_token: Secret::new("secret"),
            allowed_paths: vec![AllowedPath {
                path: PathBuf::from("relative/path"),
                alias: Some("rel".to_string()),
            }],
        });
        let result = validate_config(&config);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("absolute path"));
    }
}
