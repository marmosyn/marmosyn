//! Binary protocol message definitions for remote synchronization.
//!
//! Defines the wire format for sender ↔ receiver communication over TCP/TLS.
//! Messages use a length-prefixed frame format:
//!
//! ```text
//! ┌────────────┬──────────┬─────────────┐
//! │ Length (4B) │ Type (1B)│ Payload (N) │
//! │ u32 BE     │ u8       │ bytes       │
//! └────────────┴──────────┴─────────────┘
//! ```
//!
//! The `Length` field covers `Type` + `Payload` (i.e. total frame size minus 4).

use serde::{Deserialize, Serialize};

/// Protocol version for the handshake negotiation.
pub const PROTOCOL_VERSION: u8 = 1;

/// Magic bytes identifying a MarmoSyn protocol frame: "MSYN".
pub const PROTOCOL_MAGIC: [u8; 4] = [0x4D, 0x53, 0x59, 0x4E];

/// Maximum allowed frame payload size (16 MiB).
pub const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;

/// Message types exchanged between sender and receiver.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// Sender → receiver: protocol version + auth_token.
    Handshake = 0x01,
    /// Receiver → sender: handshake acknowledgement (ok/error).
    HandshakeAck = 0x02,
    /// Sender → receiver: resolve an alias to an absolute path.
    ResolveAlias = 0x03,
    /// Receiver → sender: resolved path or FORBIDDEN.
    ResolveAck = 0x04,
    /// Sender → receiver: request file list at a given path.
    ListRequest = 0x05,
    /// Receiver → sender: file list with metadata.
    ListResponse = 0x06,
    /// Sender → receiver: request rolling checksums for delta-sync.
    ChecksumReq = 0x07,
    /// Receiver → sender: rolling checksums response.
    ChecksumResp = 0x08,
    /// Sender → receiver: push file data (unidirectional transfer).
    PushFile = 0x09,
    /// Receiver → sender: push acknowledgement (ok/error).
    PushAck = 0x0A,
    /// Sender → receiver: request file deletion.
    DeleteRequest = 0x0B,
    /// Receiver → sender: deletion acknowledgement (ok/error).
    DeleteAck = 0x0C,
    /// Either direction: status request.
    StatusRequest = 0x0D,
    /// Either direction: status response.
    StatusResp = 0x0E,
    /// Either direction: error message.
    Error = 0xFF,
}

impl MessageType {
    /// Converts a raw `u8` to a `MessageType`, returning `None` for unknown values.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Handshake),
            0x02 => Some(Self::HandshakeAck),
            0x03 => Some(Self::ResolveAlias),
            0x04 => Some(Self::ResolveAck),
            0x05 => Some(Self::ListRequest),
            0x06 => Some(Self::ListResponse),
            0x07 => Some(Self::ChecksumReq),
            0x08 => Some(Self::ChecksumResp),
            0x09 => Some(Self::PushFile),
            0x0A => Some(Self::PushAck),
            0x0B => Some(Self::DeleteRequest),
            0x0C => Some(Self::DeleteAck),
            0x0D => Some(Self::StatusRequest),
            0x0E => Some(Self::StatusResp),
            0xFF => Some(Self::Error),
            _ => None,
        }
    }
}

// ─── Payload structs ───────────────────────────────────────────────────────

/// Handshake payload sent by the sender to initiate a connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakePayload {
    /// Protocol version supported by the sender.
    pub version: u8,
    /// Authentication token (must match `[receiver].auth_token`).
    pub auth_token: String,
}

/// Handshake acknowledgement from the receiver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeAckPayload {
    /// Whether the handshake was accepted.
    pub accepted: bool,
    /// Optional reason for rejection.
    pub reason: Option<String>,
}

/// Request to resolve an alias or path on the receiver side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveAliasPayload {
    /// The path or alias string to resolve (e.g. "backup/docs").
    pub remote_path: String,
}

/// Response to an alias resolution request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveAckPayload {
    /// Whether the resolution succeeded.
    pub success: bool,
    /// The resolved absolute path on the receiver (if successful).
    pub resolved_path: Option<String>,
    /// Error reason if the resolution failed (e.g. FORBIDDEN).
    pub reason: Option<String>,
}

/// Request for a file listing at a specific path on the receiver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRequestPayload {
    /// Absolute path on the receiver to list.
    pub path: String,
}

/// File entry returned in a list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntryPayload {
    /// Relative path from the listed directory.
    pub rel_path: String,
    /// File size in bytes.
    pub size: u64,
    /// Last modification time as seconds since UNIX epoch.
    pub mtime_secs: i64,
    /// Nanosecond component of the modification time.
    pub mtime_nanos: u32,
    /// BLAKE3 hash of the file contents, if available.
    pub hash: Option<String>,
    /// Whether this entry is a directory.
    pub is_dir: bool,
}

/// Response containing a list of files at the requested path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResponsePayload {
    /// The file entries at the requested path.
    pub entries: Vec<FileEntryPayload>,
}

/// Push a file from sender to receiver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushFileHeader {
    /// Relative path where the file should be written on the receiver.
    pub rel_path: String,
    /// Total size of the file data that follows.
    pub size: u64,
    /// BLAKE3 hash of the file contents for integrity verification.
    pub hash: String,
    /// Unix permission bits (optional).
    pub permissions: Option<u32>,
}

/// Acknowledgement for a push operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushAckPayload {
    /// Whether the file was successfully received and written.
    pub success: bool,
    /// Error message if the operation failed.
    pub error: Option<String>,
}

/// Request to delete a file on the receiver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRequestPayload {
    /// Relative path of the file to delete.
    pub rel_path: String,
    /// Whether this is a directory deletion.
    pub is_dir: bool,
}

/// Acknowledgement for a delete operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteAckPayload {
    /// Whether the deletion succeeded.
    pub success: bool,
    /// Error message if the operation failed.
    pub error: Option<String>,
}

/// Generic error payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPayload {
    /// Error code (application-defined).
    pub code: u16,
    /// Human-readable error message.
    pub message: String,
}

/// Well-known error codes.
pub mod error_codes {
    /// Authentication failed (invalid token).
    pub const AUTH_FAILED: u16 = 1001;
    /// The requested path is forbidden (not in allowed_paths).
    pub const FORBIDDEN: u16 = 1002;
    /// The requested alias could not be resolved.
    pub const ALIAS_NOT_FOUND: u16 = 1003;
    /// Protocol version mismatch.
    pub const VERSION_MISMATCH: u16 = 1004;
    /// An internal server error occurred on the receiver.
    pub const INTERNAL_ERROR: u16 = 1005;
    /// Path traversal attempt detected.
    pub const PATH_TRAVERSAL: u16 = 1006;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_roundtrip() {
        let variants = [
            MessageType::Handshake,
            MessageType::HandshakeAck,
            MessageType::ResolveAlias,
            MessageType::ResolveAck,
            MessageType::ListRequest,
            MessageType::ListResponse,
            MessageType::ChecksumReq,
            MessageType::ChecksumResp,
            MessageType::PushFile,
            MessageType::PushAck,
            MessageType::DeleteRequest,
            MessageType::DeleteAck,
            MessageType::StatusRequest,
            MessageType::StatusResp,
            MessageType::Error,
        ];

        for variant in &variants {
            let byte = *variant as u8;
            let parsed = MessageType::from_u8(byte);
            assert_eq!(parsed, Some(*variant), "roundtrip failed for {variant:?}");
        }
    }

    #[test]
    fn test_unknown_message_type() {
        assert_eq!(MessageType::from_u8(0x00), None);
        assert_eq!(MessageType::from_u8(0x42), None);
        assert_eq!(MessageType::from_u8(0xFE), None);
    }

    #[test]
    fn test_protocol_magic() {
        assert_eq!(&PROTOCOL_MAGIC, b"MSYN");
    }

    #[test]
    fn test_handshake_payload_serde() {
        let payload = HandshakePayload {
            version: PROTOCOL_VERSION,
            auth_token: "test-token".to_string(),
        };
        let json = serde_json::to_string(&payload).unwrap();
        let deserialized: HandshakePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.version, PROTOCOL_VERSION);
        assert_eq!(deserialized.auth_token, "test-token");
    }

    #[test]
    fn test_error_payload_serde() {
        let payload = ErrorPayload {
            code: error_codes::FORBIDDEN,
            message: "path not allowed".to_string(),
        };
        let json = serde_json::to_string(&payload).unwrap();
        let deserialized: ErrorPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.code, error_codes::FORBIDDEN);
        assert_eq!(deserialized.message, "path not allowed");
    }
}
