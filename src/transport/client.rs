// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! TCP/TLS client for sender → remote receiver communication.
//!
//! This module implements the transport client that connects to a remote
//! MarmoSyn receiver over TCP/TLS, performs the handshake (authentication),
//! and provides methods for sending protocol messages (RESOLVE_ALIAS, LIST,
//! PUSH, DELETE, STATUS, etc.).
//!
//! The client is used by `RemoteExecutor` to implement the `SyncExecutor`
//! trait for remote destinations.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::transport::codec::{self, CodecError, Frame};
use crate::transport::protocol::*;

/// Configuration for connecting to a remote receiver.
#[derive(Debug, Clone)]
pub struct TransportClientConfig {
    /// Host and port of the remote receiver (e.g. "192.168.1.100:7854").
    pub host: String,

    /// Authentication token for the receiver.
    pub auth_token: String,

    /// Connection timeout duration.
    pub connect_timeout: Duration,

    /// Read/write timeout for individual operations.
    pub io_timeout: Duration,

    /// Whether to use TLS for the connection.
    pub use_tls: bool,

    /// Optional path to a custom CA certificate (PEM) to trust.
    pub tls_ca: Option<PathBuf>,

    /// Allow self-signed certificates on the remote (disables verification).
    pub allow_self_signed: bool,

    /// Server name for TLS SNI (defaults to the host part of `host`).
    /// Only relevant when `use_tls` is `true`.
    pub tls_server_name: Option<String>,
}

impl Default for TransportClientConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            auth_token: String::new(),
            connect_timeout: Duration::from_secs(30),
            io_timeout: Duration::from_secs(120),
            use_tls: false,
            tls_ca: None,
            allow_self_signed: false,
            tls_server_name: None,
        }
    }
}

/// Transport client for communicating with a remote MarmoSyn receiver.
///
/// Manages a TCP connection (optionally wrapped in TLS) and provides
/// high-level methods for all protocol operations:
/// - Handshake (authentication)
/// - Alias resolution
/// - File listing
/// - File push (upload)
/// - File deletion
/// - Status queries
pub struct TransportClient {
    /// The underlying stream (either raw TCP or TLS-wrapped).
    stream: Box<dyn AsyncStream>,

    /// Remote address for logging.
    remote_addr: String,

    /// Whether the handshake has been completed successfully.
    handshake_done: bool,

    /// The resolved base path on the receiver (set after RESOLVE_ALIAS).
    resolved_base: Option<String>,
}

/// Trait alias for async read+write streams that are Send + Unpin.
trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncStream for T {}

impl TransportClient {
    /// Connects to a remote receiver and performs the handshake.
    ///
    /// # Arguments
    ///
    /// * `config` — connection configuration (host, token, timeouts).
    ///
    /// # Errors
    ///
    /// Returns an error if the connection cannot be established or
    /// the handshake is rejected by the receiver.
    pub async fn connect(config: &TransportClientConfig) -> Result<Self> {
        if config.use_tls {
            return Self::connect_tls(config).await;
        }

        debug!(
            host = %config.host,
            tls = false,
            "connecting to remote receiver"
        );

        let stream = tokio::time::timeout(config.connect_timeout, TcpStream::connect(&config.host))
            .await
            .context("connection timed out")?
            .with_context(|| {
                format!("failed to connect to remote receiver at '{}'", config.host)
            })?;

        // Disable Nagle's algorithm for lower latency
        stream.set_nodelay(true).ok();

        let remote_addr = config.host.clone();
        let mut client = Self {
            stream: Box::new(stream),
            remote_addr,
            handshake_done: false,
            resolved_base: None,
        };

        // Perform the handshake
        client.perform_handshake(&config.auth_token).await?;

        Ok(client)
    }

    /// Connects to a remote receiver over TLS and performs the handshake.
    ///
    /// Establishes a TCP connection, upgrades it to TLS using `rustls`,
    /// and then performs the MarmoSyn handshake protocol.
    ///
    /// # Arguments
    ///
    /// * `config` — connection configuration (host, token, TLS settings).
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP connection, TLS negotiation, or
    /// handshake fails.
    pub async fn connect_tls(config: &TransportClientConfig) -> Result<Self> {
        debug!(
            host = %config.host,
            tls = true,
            allow_self_signed = config.allow_self_signed,
            "connecting to remote receiver with TLS"
        );

        let tcp_stream =
            tokio::time::timeout(config.connect_timeout, TcpStream::connect(&config.host))
                .await
                .context("TLS connection timed out")?
                .with_context(|| {
                    format!("failed to connect to remote receiver at '{}'", config.host)
                })?;

        tcp_stream.set_nodelay(true).ok();

        // Build the rustls client config
        let tls_config = crate::transport::tls::build_client_config(
            config.tls_ca.as_deref(),
            config.allow_self_signed,
        )
        .context("failed to build TLS client configuration")?;

        let connector = tokio_rustls::TlsConnector::from(tls_config);

        // Determine the server name for SNI
        let server_name_str = config
            .tls_server_name
            .as_deref()
            .or_else(|| {
                // Extract the hostname part (without port) from config.host
                config.host.split(':').next()
            })
            .unwrap_or("localhost");

        let server_name = rustls::pki_types::ServerName::try_from(server_name_str.to_string())
            .with_context(|| format!("invalid TLS server name: '{server_name_str}'"))?;

        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .context("TLS handshake failed")?;

        info!(
            host = %config.host,
            "TLS connection established"
        );

        let remote_addr = config.host.clone();
        let mut client = Self {
            stream: Box::new(tls_stream),
            remote_addr,
            handshake_done: false,
            resolved_base: None,
        };

        // Perform the MarmoSyn protocol handshake
        client.perform_handshake(&config.auth_token).await?;

        Ok(client)
    }

    /// Creates a transport client from an already-connected stream.
    ///
    /// This is useful for testing or when the stream is set up externally
    /// (e.g. with TLS already negotiated).
    ///
    /// The handshake is NOT performed automatically — call
    /// `perform_handshake()` manually.
    pub fn from_stream(
        stream: impl AsyncRead + AsyncWrite + Send + Unpin + 'static,
        remote_addr: String,
    ) -> Self {
        Self {
            stream: Box::new(stream),
            remote_addr,
            handshake_done: false,
            resolved_base: None,
        }
    }

    /// Performs the initial handshake with the receiver.
    ///
    /// Sends the protocol version and authentication token.
    /// On success, the connection is ready for commands.
    ///
    /// # Errors
    ///
    /// Returns an error if the handshake is rejected (wrong token,
    /// version mismatch, etc.).
    pub async fn perform_handshake(&mut self, auth_token: &str) -> Result<()> {
        debug!(
            remote = %self.remote_addr,
            "performing handshake"
        );

        let handshake = HandshakePayload {
            version: PROTOCOL_VERSION,
            auth_token: auth_token.to_string(),
        };

        let frame = Frame::from_payload(MessageType::Handshake, &handshake)
            .context("failed to serialize handshake")?;
        self.write_frame(&frame).await?;

        let ack_frame = self.read_frame().await?;

        if ack_frame.msg_type == MessageType::Error {
            let error: ErrorPayload = ack_frame.decode_payload().unwrap_or(ErrorPayload {
                code: 0,
                message: "unknown error".to_string(),
            });
            anyhow::bail!(
                "handshake rejected by receiver: [{}] {}",
                error.code,
                error.message
            );
        }

        if ack_frame.msg_type != MessageType::HandshakeAck {
            anyhow::bail!("unexpected response to handshake: {:?}", ack_frame.msg_type);
        }

        let ack: HandshakeAckPayload = ack_frame
            .decode_payload()
            .map_err(|e| anyhow::anyhow!("invalid handshake ack: {e}"))?;

        if !ack.accepted {
            let reason = ack.reason.unwrap_or_else(|| "no reason given".to_string());
            anyhow::bail!("handshake rejected: {}", reason);
        }

        self.handshake_done = true;
        info!(
            remote = %self.remote_addr,
            "handshake successful"
        );

        Ok(())
    }

    /// Resolves a remote path or alias on the receiver.
    ///
    /// Sends a RESOLVE_ALIAS message and returns the resolved absolute
    /// path on the receiver filesystem.
    ///
    /// # Arguments
    ///
    /// * `remote_path` — the alias or path to resolve (e.g. "backup/docs").
    ///
    /// # Returns
    ///
    /// The resolved absolute path on the receiver, or an error if the
    /// alias is unknown or the path is forbidden.
    pub async fn resolve_alias(&mut self, remote_path: &str) -> Result<String> {
        self.ensure_handshake()?;

        debug!(
            remote = %self.remote_addr,
            path = %remote_path,
            "resolving alias"
        );

        let payload = ResolveAliasPayload {
            remote_path: remote_path.to_string(),
        };

        let frame = Frame::from_payload(MessageType::ResolveAlias, &payload)
            .context("failed to serialize ResolveAlias")?;
        self.write_frame(&frame).await?;

        let response = self.read_frame().await?;
        self.check_for_error(&response)?;

        if response.msg_type != MessageType::ResolveAck {
            anyhow::bail!(
                "unexpected response to ResolveAlias: {:?}",
                response.msg_type
            );
        }

        let ack: ResolveAckPayload = response
            .decode_payload()
            .map_err(|e| anyhow::anyhow!("invalid ResolveAck: {e}"))?;

        if !ack.success {
            let reason = ack.reason.unwrap_or_else(|| "unknown error".to_string());
            anyhow::bail!("alias resolution failed for '{}': {}", remote_path, reason);
        }

        let resolved = ack
            .resolved_path
            .ok_or_else(|| anyhow::anyhow!("ResolveAck success but no path returned"))?;

        debug!(
            remote = %self.remote_addr,
            alias = %remote_path,
            resolved = %resolved,
            "alias resolved"
        );

        self.resolved_base = Some(resolved.clone());
        Ok(resolved)
    }

    /// Lists files at the given path on the receiver.
    ///
    /// Sends a LIST request and returns the receiver's file listing.
    ///
    /// # Arguments
    ///
    /// * `path` — absolute path on the receiver to list (typically obtained
    ///   from a previous `resolve_alias()` call).
    ///
    /// # Returns
    ///
    /// A list of file entries with metadata (relative paths, sizes, hashes).
    pub async fn list_files(&mut self, path: &str) -> Result<Vec<FileEntryPayload>> {
        self.ensure_handshake()?;

        debug!(
            remote = %self.remote_addr,
            path = %path,
            "requesting file list"
        );

        let payload = ListRequestPayload {
            path: path.to_string(),
        };

        let frame = Frame::from_payload(MessageType::ListRequest, &payload)
            .context("failed to serialize ListRequest")?;
        self.write_frame(&frame).await?;

        let response = self.read_frame().await?;
        self.check_for_error(&response)?;

        if response.msg_type != MessageType::ListResponse {
            anyhow::bail!(
                "unexpected response to ListRequest: {:?}",
                response.msg_type
            );
        }

        let list: ListResponsePayload = response
            .decode_payload()
            .map_err(|e| anyhow::anyhow!("invalid ListResponse: {e}"))?;

        debug!(
            remote = %self.remote_addr,
            path = %path,
            count = list.entries.len(),
            "received file list"
        );

        Ok(list.entries)
    }

    /// Pushes (uploads) a file to the receiver.
    ///
    /// The push protocol:
    /// 1. Send a PushFile header frame with metadata (rel_path, size, hash).
    /// 2. Send a second PushFile frame with the raw file data.
    /// 3. Receive a PushAck response indicating success or failure.
    ///
    /// # Arguments
    ///
    /// * `resolved_base` — the resolved base path on the receiver (from
    ///   `resolve_alias()`). Used to construct the full receiver-side path.
    /// * `rel_path` — relative path of the file within the sync root.
    /// * `src_path` — absolute path to the source file on the sender.
    /// * `hash` — BLAKE3 hash of the file for integrity verification.
    ///
    /// # Returns
    ///
    /// The number of bytes transferred on success.
    pub async fn push_file(
        &mut self,
        resolved_base: &str,
        rel_path: &Path,
        src_path: &Path,
        hash: &str,
    ) -> Result<u64> {
        self.ensure_handshake()?;

        // Build the full remote path: resolved_base + "/" + rel_path
        let remote_rel = format!(
            "{}/{}",
            resolved_base.trim_end_matches('/'),
            rel_path.to_string_lossy()
        );

        // Read file metadata
        let metadata = tokio::fs::metadata(src_path)
            .await
            .with_context(|| format!("failed to read metadata for '{}'", src_path.display()))?;
        let file_size = metadata.len();

        // Read unix permissions
        #[cfg(unix)]
        let permissions = {
            use std::os::unix::fs::PermissionsExt;
            Some(metadata.permissions().mode())
        };
        #[cfg(not(unix))]
        let permissions: Option<u32> = None;

        debug!(
            remote = %self.remote_addr,
            remote_path = %remote_rel,
            local_path = %src_path.display(),
            size = file_size,
            "pushing file"
        );

        // Step 1: Send the PushFile header
        let header = PushFileHeader {
            rel_path: remote_rel,
            size: file_size,
            hash: hash.to_string(),
            permissions,
        };

        let header_frame = Frame::from_payload(MessageType::PushFile, &header)
            .context("failed to serialize PushFile header")?;
        self.write_frame(&header_frame).await?;

        // Step 2: Send the file data as a raw PushFile frame
        let file_data = tokio::fs::read(src_path)
            .await
            .with_context(|| format!("failed to read file '{}'", src_path.display()))?;

        let data_frame = Frame::new(MessageType::PushFile, file_data);
        self.write_frame(&data_frame).await?;

        // Step 3: Read the PushAck
        let response = self.read_frame().await?;
        self.check_for_error(&response)?;

        if response.msg_type != MessageType::PushAck {
            anyhow::bail!("unexpected response to PushFile: {:?}", response.msg_type);
        }

        let ack: PushAckPayload = response
            .decode_payload()
            .map_err(|e| anyhow::anyhow!("invalid PushAck: {e}"))?;

        if !ack.success {
            let error_msg = ack.error.unwrap_or_else(|| "unknown error".to_string());
            anyhow::bail!("push rejected for '{}': {}", rel_path.display(), error_msg);
        }

        debug!(
            remote = %self.remote_addr,
            path = %rel_path.display(),
            size = file_size,
            "file pushed successfully"
        );

        Ok(file_size)
    }

    /// Pushes raw data to the receiver (for encrypted or in-memory content).
    ///
    /// Similar to `push_file()` but takes data bytes directly instead of
    /// reading from a file path.
    ///
    /// # Arguments
    ///
    /// * `resolved_base` — the resolved base path on the receiver.
    /// * `rel_path` — relative path of the file within the sync root.
    /// * `data` — the raw file data to send.
    /// * `hash` — BLAKE3 hash of the data for integrity verification.
    /// * `permissions` — optional Unix permission bits.
    ///
    /// # Returns
    ///
    /// The number of bytes transferred on success.
    pub async fn push_data(
        &mut self,
        resolved_base: &str,
        rel_path: &Path,
        data: Vec<u8>,
        hash: &str,
        permissions: Option<u32>,
    ) -> Result<u64> {
        self.ensure_handshake()?;

        let remote_rel = format!(
            "{}/{}",
            resolved_base.trim_end_matches('/'),
            rel_path.to_string_lossy()
        );
        let data_size = data.len() as u64;

        debug!(
            remote = %self.remote_addr,
            remote_path = %remote_rel,
            size = data_size,
            "pushing data"
        );

        let header = PushFileHeader {
            rel_path: remote_rel,
            size: data_size,
            hash: hash.to_string(),
            permissions,
        };

        let header_frame = Frame::from_payload(MessageType::PushFile, &header)
            .context("failed to serialize PushFile header")?;
        self.write_frame(&header_frame).await?;

        let data_frame = Frame::new(MessageType::PushFile, data);
        self.write_frame(&data_frame).await?;

        let response = self.read_frame().await?;
        self.check_for_error(&response)?;

        if response.msg_type != MessageType::PushAck {
            anyhow::bail!("unexpected response to PushFile: {:?}", response.msg_type);
        }

        let ack: PushAckPayload = response
            .decode_payload()
            .map_err(|e| anyhow::anyhow!("invalid PushAck: {e}"))?;

        if !ack.success {
            let error_msg = ack.error.unwrap_or_else(|| "unknown error".to_string());
            anyhow::bail!("push rejected for '{}': {}", rel_path.display(), error_msg);
        }

        Ok(data_size)
    }

    /// Requests deletion of a file or directory on the receiver.
    ///
    /// # Arguments
    ///
    /// * `resolved_base` — the resolved base path on the receiver.
    /// * `rel_path` — relative path of the file to delete.
    /// * `is_dir` — whether the entry is a directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is forbidden or the deletion fails.
    pub async fn delete_file(
        &mut self,
        resolved_base: &str,
        rel_path: &Path,
        is_dir: bool,
    ) -> Result<()> {
        self.ensure_handshake()?;

        let remote_rel = format!(
            "{}/{}",
            resolved_base.trim_end_matches('/'),
            rel_path.to_string_lossy()
        );

        debug!(
            remote = %self.remote_addr,
            path = %remote_rel,
            is_dir = is_dir,
            "requesting file deletion"
        );

        let payload = DeleteRequestPayload {
            rel_path: remote_rel.clone(),
            is_dir,
        };

        let frame = Frame::from_payload(MessageType::DeleteRequest, &payload)
            .context("failed to serialize DeleteRequest")?;
        self.write_frame(&frame).await?;

        let response = self.read_frame().await?;
        self.check_for_error(&response)?;

        if response.msg_type != MessageType::DeleteAck {
            anyhow::bail!(
                "unexpected response to DeleteRequest: {:?}",
                response.msg_type
            );
        }

        let ack: DeleteAckPayload = response
            .decode_payload()
            .map_err(|e| anyhow::anyhow!("invalid DeleteAck: {e}"))?;

        if !ack.success {
            let error_msg = ack.error.unwrap_or_else(|| "unknown error".to_string());
            anyhow::bail!("delete failed for '{}': {}", remote_rel, error_msg);
        }

        debug!(
            remote = %self.remote_addr,
            path = %remote_rel,
            "file deleted on receiver"
        );

        Ok(())
    }

    /// Requests the connection status from the receiver.
    ///
    /// # Returns
    ///
    /// A JSON value containing status information (files_received, bytes_received, etc.).
    pub async fn status(&mut self) -> Result<serde_json::Value> {
        self.ensure_handshake()?;

        debug!(
            remote = %self.remote_addr,
            "requesting status"
        );

        let frame = Frame::empty(MessageType::StatusRequest);
        self.write_frame(&frame).await?;

        let response = self.read_frame().await?;
        self.check_for_error(&response)?;

        if response.msg_type != MessageType::StatusResp {
            anyhow::bail!(
                "unexpected response to StatusRequest: {:?}",
                response.msg_type
            );
        }

        let status: serde_json::Value =
            serde_json::from_slice(&response.payload).context("failed to parse status response")?;

        Ok(status)
    }

    /// Sends an error message to the receiver and closes the connection.
    pub async fn send_error(&mut self, code: u16, message: &str) -> Result<()> {
        let payload = ErrorPayload {
            code,
            message: message.to_string(),
        };
        let frame = Frame::from_payload(MessageType::Error, &payload)
            .context("failed to serialize error")?;
        self.write_frame(&frame).await?;
        Ok(())
    }

    /// Gracefully disconnects from the receiver by sending an error
    /// frame with a "disconnect" message.
    pub async fn disconnect(mut self) -> Result<()> {
        debug!(
            remote = %self.remote_addr,
            "disconnecting"
        );

        // Send a clean disconnect by sending an Error frame. The receiver
        // treats this as the client closing the connection.
        let _ = self.send_error(0, "client disconnecting").await;
        let _ = self.stream.shutdown().await;

        info!(
            remote = %self.remote_addr,
            "disconnected"
        );

        Ok(())
    }

    /// Returns the remote address this client is connected to.
    pub fn remote_addr(&self) -> &str {
        &self.remote_addr
    }

    /// Returns the resolved base path on the receiver, if set.
    pub fn resolved_base(&self) -> Option<&str> {
        self.resolved_base.as_deref()
    }

    /// Returns whether the handshake has been completed.
    pub fn is_connected(&self) -> bool {
        self.handshake_done
    }

    // ─── Internal helpers ──────────────────────────────────────────────

    /// Ensures the handshake has been completed before sending commands.
    fn ensure_handshake(&self) -> Result<()> {
        if !self.handshake_done {
            anyhow::bail!(
                "handshake not completed; call connect() or \
                 perform_handshake() first"
            );
        }
        Ok(())
    }

    /// Reads a single frame from the stream.
    async fn read_frame(&mut self) -> Result<Frame> {
        codec::read_frame(&mut self.stream)
            .await
            .map_err(|e| match e {
                CodecError::Io(ref io_err)
                    if io_err.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    anyhow::anyhow!("connection to '{}' closed unexpectedly", self.remote_addr)
                }
                other => anyhow::anyhow!(
                    "failed to read frame from '{}': {}",
                    self.remote_addr,
                    other
                ),
            })
    }

    /// Writes a single frame to the stream.
    async fn write_frame(&mut self, frame: &Frame) -> Result<()> {
        codec::write_frame(&mut self.stream, frame)
            .await
            .map_err(|e| anyhow::anyhow!("failed to write frame to '{}': {}", self.remote_addr, e))
    }

    /// Checks if a received frame is an Error message, and if so,
    /// returns an appropriate error.
    fn check_for_error(&self, frame: &Frame) -> Result<()> {
        if frame.msg_type == MessageType::Error {
            let error: ErrorPayload = frame.decode_payload().unwrap_or(ErrorPayload {
                code: 0,
                message: "unknown error from receiver".to_string(),
            });

            match error.code {
                error_codes::AUTH_FAILED => {
                    anyhow::bail!(
                        "authentication failed on '{}': {}",
                        self.remote_addr,
                        error.message
                    );
                }
                error_codes::FORBIDDEN => {
                    anyhow::bail!("forbidden on '{}': {}", self.remote_addr, error.message);
                }
                error_codes::ALIAS_NOT_FOUND => {
                    anyhow::bail!(
                        "alias not found on '{}': {}",
                        self.remote_addr,
                        error.message
                    );
                }
                error_codes::PATH_TRAVERSAL => {
                    anyhow::bail!(
                        "path traversal rejected by '{}': {}",
                        self.remote_addr,
                        error.message
                    );
                }
                error_codes::VERSION_MISMATCH => {
                    anyhow::bail!(
                        "protocol version mismatch with '{}': {}",
                        self.remote_addr,
                        error.message
                    );
                }
                _ => {
                    anyhow::bail!(
                        "receiver '{}' error [{}]: {}",
                        self.remote_addr,
                        error.code,
                        error.message
                    );
                }
            }
        }
        Ok(())
    }
}

impl std::fmt::Debug for TransportClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportClient")
            .field("remote_addr", &self.remote_addr)
            .field("handshake_done", &self.handshake_done)
            .field("resolved_base", &self.resolved_base)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::AllowedPath;
    use crate::transport::receiver::ReceiverGuard;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use tokio::io::duplex;
    use tokio::net::TcpListener;

    /// Spawns a minimal receiver that handles handshake, resolve, list,
    /// push, and delete for testing purposes.
    async fn spawn_test_receiver(
        auth_token: &str,
        allowed_paths: Vec<AllowedPath>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let token = auth_token.to_string();

        let handle = tokio::spawn(async move {
            let (mut stream, _addr) = listener.accept().await.unwrap();

            // Handle handshake
            let frame = codec::read_frame(&mut stream).await.unwrap();
            assert_eq!(frame.msg_type, MessageType::Handshake);
            let hs: HandshakePayload = frame.decode_payload().unwrap();
            assert_eq!(hs.version, PROTOCOL_VERSION);

            let accepted = hs.auth_token == token;
            let ack = HandshakeAckPayload {
                accepted,
                reason: if accepted {
                    None
                } else {
                    Some("bad token".to_string())
                },
            };
            let ack_frame = Frame::from_payload(MessageType::HandshakeAck, &ack).unwrap();
            codec::write_frame(&mut stream, &ack_frame).await.unwrap();

            if !accepted {
                return;
            }

            let guard = ReceiverGuard::new(&allowed_paths);

            // Command loop
            loop {
                let frame = match codec::read_frame(&mut stream).await {
                    Ok(f) => f,
                    Err(_) => break,
                };

                match frame.msg_type {
                    MessageType::ResolveAlias => {
                        let payload: ResolveAliasPayload = frame.decode_payload().unwrap();
                        match guard.resolve_path(&payload.remote_path) {
                            Ok(resolved) => {
                                let ack = ResolveAckPayload {
                                    success: true,
                                    resolved_path: Some(resolved.to_string_lossy().to_string()),
                                    reason: None,
                                };
                                let resp =
                                    Frame::from_payload(MessageType::ResolveAck, &ack).unwrap();
                                codec::write_frame(&mut stream, &resp).await.unwrap();
                            }
                            Err(e) => {
                                let ack = ResolveAckPayload {
                                    success: false,
                                    resolved_path: None,
                                    reason: Some(e.to_string()),
                                };
                                let resp =
                                    Frame::from_payload(MessageType::ResolveAck, &ack).unwrap();
                                codec::write_frame(&mut stream, &resp).await.unwrap();
                            }
                        }
                    }
                    MessageType::ListRequest => {
                        let payload: ListRequestPayload = frame.decode_payload().unwrap();
                        // Return an empty list for simplicity
                        let _ = payload.path;
                        let resp_payload = ListResponsePayload { entries: vec![] };
                        let resp =
                            Frame::from_payload(MessageType::ListResponse, &resp_payload).unwrap();
                        codec::write_frame(&mut stream, &resp).await.unwrap();
                    }
                    MessageType::PushFile => {
                        let header: PushFileHeader = frame.decode_payload().unwrap();

                        // Read the data frame
                        let data_frame = codec::read_frame(&mut stream).await.unwrap();
                        assert_eq!(data_frame.msg_type, MessageType::PushFile);

                        let _data = data_frame.payload;
                        let _ = header.size;

                        // Attempt to resolve the path for validation
                        let success = guard.resolve_path(&header.rel_path).is_ok();

                        let ack = PushAckPayload {
                            success,
                            error: if success {
                                None
                            } else {
                                Some("path validation failed".to_string())
                            },
                        };
                        let resp = Frame::from_payload(MessageType::PushAck, &ack).unwrap();
                        codec::write_frame(&mut stream, &resp).await.unwrap();
                    }
                    MessageType::DeleteRequest => {
                        let payload: DeleteRequestPayload = frame.decode_payload().unwrap();
                        let success = guard.resolve_path(&payload.rel_path).is_ok();

                        let ack = DeleteAckPayload {
                            success,
                            error: if success {
                                None
                            } else {
                                Some("path validation failed".to_string())
                            },
                        };
                        let resp = Frame::from_payload(MessageType::DeleteAck, &ack).unwrap();
                        codec::write_frame(&mut stream, &resp).await.unwrap();
                    }
                    MessageType::StatusRequest => {
                        let status = serde_json::json!({
                            "status": "ok",
                            "files_received": 0,
                            "bytes_received": 0,
                        });
                        let payload = serde_json::to_vec(&status).unwrap();
                        let resp = Frame::new(MessageType::StatusResp, payload);
                        codec::write_frame(&mut stream, &resp).await.unwrap();
                    }
                    MessageType::Error => {
                        // Client is disconnecting
                        break;
                    }
                    _ => {
                        break;
                    }
                }
            }
        });

        (addr, handle)
    }

    #[tokio::test]
    async fn test_connect_and_handshake() {
        let allowed = vec![AllowedPath {
            path: PathBuf::from("/tmp/test-recv"),
            alias: Some("backup".to_string()),
        }];

        let (addr, _handle) = spawn_test_receiver("test-token-123", allowed).await;

        let config = TransportClientConfig {
            host: addr.to_string(),
            auth_token: "test-token-123".to_string(),
            ..Default::default()
        };

        let client = TransportClient::connect(&config).await.unwrap();
        assert!(client.is_connected());
        assert_eq!(client.remote_addr(), addr.to_string());
    }

    #[tokio::test]
    async fn test_handshake_wrong_token() {
        let allowed = vec![AllowedPath {
            path: PathBuf::from("/tmp/test-recv"),
            alias: Some("backup".to_string()),
        }];

        let (addr, _handle) = spawn_test_receiver("correct-token", allowed).await;

        let config = TransportClientConfig {
            host: addr.to_string(),
            auth_token: "wrong-token".to_string(),
            ..Default::default()
        };

        let result = TransportClient::connect(&config).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("rejected"),
            "expected rejection error, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_resolve_alias() {
        let allowed = vec![AllowedPath {
            path: PathBuf::from("/tmp/test-recv"),
            alias: Some("backup".to_string()),
        }];

        let (addr, _handle) = spawn_test_receiver("token-abc", allowed).await;

        let config = TransportClientConfig {
            host: addr.to_string(),
            auth_token: "token-abc".to_string(),
            ..Default::default()
        };

        let mut client = TransportClient::connect(&config).await.unwrap();
        let resolved = client.resolve_alias("backup/docs").await.unwrap();
        assert_eq!(resolved, "/tmp/test-recv/docs");
        assert_eq!(client.resolved_base(), Some("/tmp/test-recv/docs"));
    }

    #[tokio::test]
    async fn test_resolve_alias_forbidden() {
        let allowed = vec![AllowedPath {
            path: PathBuf::from("/tmp/test-recv"),
            alias: Some("backup".to_string()),
        }];

        let (addr, _handle) = spawn_test_receiver("token-abc", allowed).await;

        let config = TransportClientConfig {
            host: addr.to_string(),
            auth_token: "token-abc".to_string(),
            ..Default::default()
        };

        let mut client = TransportClient::connect(&config).await.unwrap();
        let result = client.resolve_alias("forbidden/path").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_files() {
        let allowed = vec![AllowedPath {
            path: PathBuf::from("/tmp/test-recv"),
            alias: Some("backup".to_string()),
        }];

        let (addr, _handle) = spawn_test_receiver("token-abc", allowed).await;

        let config = TransportClientConfig {
            host: addr.to_string(),
            auth_token: "token-abc".to_string(),
            ..Default::default()
        };

        let mut client = TransportClient::connect(&config).await.unwrap();
        let files = client.list_files("/tmp/test-recv").await.unwrap();
        assert!(files.is_empty()); // The test receiver returns empty list
    }

    #[tokio::test]
    async fn test_push_file_with_allowed_path() {
        let tmp = tempfile::tempdir().unwrap();
        let recv_dir = tmp.path().join("recv");
        std::fs::create_dir_all(&recv_dir).unwrap();

        let allowed = vec![AllowedPath {
            path: recv_dir.clone(),
            alias: Some("backup".to_string()),
        }];

        let (addr, _handle) = spawn_test_receiver("token-push", allowed).await;

        let config = TransportClientConfig {
            host: addr.to_string(),
            auth_token: "token-push".to_string(),
            ..Default::default()
        };

        let mut client = TransportClient::connect(&config).await.unwrap();

        // Create a test source file
        let src_file = tmp.path().join("source.txt");
        tokio::fs::write(&src_file, b"hello remote world")
            .await
            .unwrap();

        let hash = crate::core::hasher::hash_bytes(b"hello remote world");
        let resolved_base = recv_dir.to_string_lossy().to_string();

        let bytes = client
            .push_file(&resolved_base, Path::new("source.txt"), &src_file, &hash)
            .await
            .unwrap();

        assert_eq!(bytes, 18);
    }

    #[tokio::test]
    async fn test_delete_file_with_allowed_path() {
        let tmp = tempfile::tempdir().unwrap();
        let recv_dir = tmp.path().join("recv");
        std::fs::create_dir_all(&recv_dir).unwrap();

        let allowed = vec![AllowedPath {
            path: recv_dir.clone(),
            alias: Some("backup".to_string()),
        }];

        let (addr, _handle) = spawn_test_receiver("token-del", allowed).await;

        let config = TransportClientConfig {
            host: addr.to_string(),
            auth_token: "token-del".to_string(),
            ..Default::default()
        };

        let mut client = TransportClient::connect(&config).await.unwrap();

        let resolved_base = recv_dir.to_string_lossy().to_string();
        client
            .delete_file(&resolved_base, Path::new("old.txt"), false)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_status() {
        let allowed = vec![AllowedPath {
            path: PathBuf::from("/tmp/test-recv"),
            alias: Some("backup".to_string()),
        }];

        let (addr, _handle) = spawn_test_receiver("token-status", allowed).await;

        let config = TransportClientConfig {
            host: addr.to_string(),
            auth_token: "token-status".to_string(),
            ..Default::default()
        };

        let mut client = TransportClient::connect(&config).await.unwrap();
        let status = client.status().await.unwrap();
        assert_eq!(status["status"], "ok");
        assert_eq!(status["files_received"], 0);
    }

    #[tokio::test]
    async fn test_disconnect() {
        let allowed = vec![AllowedPath {
            path: PathBuf::from("/tmp/test-recv"),
            alias: Some("backup".to_string()),
        }];

        let (addr, handle) = spawn_test_receiver("token-disc", allowed).await;

        let config = TransportClientConfig {
            host: addr.to_string(),
            auth_token: "token-disc".to_string(),
            ..Default::default()
        };

        let client = TransportClient::connect(&config).await.unwrap();
        assert!(client.is_connected());

        client.disconnect().await.unwrap();

        // The test receiver should exit gracefully after disconnect
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_ensure_handshake_fails_without_connect() {
        let (client_stream, _server_stream) = duplex(1024);
        let mut client = TransportClient::from_stream(client_stream, "test".to_string());

        assert!(!client.is_connected());

        // Any command should fail because handshake was not done
        let result = client.status().await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("handshake not completed"),
            "expected handshake error, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_push_data() {
        let tmp = tempfile::tempdir().unwrap();
        let recv_dir = tmp.path().join("recv");
        std::fs::create_dir_all(&recv_dir).unwrap();

        let allowed = vec![AllowedPath {
            path: recv_dir.clone(),
            alias: Some("backup".to_string()),
        }];

        let (addr, _handle) = spawn_test_receiver("token-data", allowed).await;

        let config = TransportClientConfig {
            host: addr.to_string(),
            auth_token: "token-data".to_string(),
            ..Default::default()
        };

        let mut client = TransportClient::connect(&config).await.unwrap();

        let data = b"encrypted content here".to_vec();
        let hash = crate::core::hasher::hash_bytes(&data);
        let resolved_base = recv_dir.to_string_lossy().to_string();

        let bytes = client
            .push_data(
                &resolved_base,
                Path::new("encrypted.bin"),
                data.clone(),
                &hash,
                Some(0o644),
            )
            .await
            .unwrap();

        assert_eq!(bytes, data.len() as u64);
    }

    #[tokio::test]
    async fn test_connect_timeout_invalid_host() {
        let config = TransportClientConfig {
            host: "192.0.2.1:1".to_string(), // TEST-NET, should be unreachable
            auth_token: "token".to_string(),
            connect_timeout: Duration::from_millis(100),
            ..Default::default()
        };

        let result = TransportClient::connect(&config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_client_debug_format() {
        let (client_stream, _server_stream) = duplex(1024);
        let client = TransportClient::from_stream(client_stream, "127.0.0.1:1234".to_string());

        let debug_str = format!("{:?}", client);
        assert!(debug_str.contains("TransportClient"));
        assert!(debug_str.contains("127.0.0.1:1234"));
        assert!(debug_str.contains("handshake_done: false"));
    }

    #[tokio::test]
    async fn test_default_transport_config() {
        let config = TransportClientConfig::default();
        assert!(config.host.is_empty());
        assert!(config.auth_token.is_empty());
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
        assert_eq!(config.io_timeout, Duration::from_secs(120));
    }
}
