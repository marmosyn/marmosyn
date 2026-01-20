// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! TCP/TLS listener for the receiver side of the transport protocol.
//!
//! This module implements the server-side network listener that accepts
//! incoming connections from remote senders. It handles authentication
//! via the handshake protocol, alias resolution, and dispatches incoming
//! messages (LIST, PUSH, DELETE) to the receiver logic for processing.
//!
//! The listener binds to the address configured in `[server].listen` and
//! validates incoming connections against `[receiver].auth_token`.
//!
//! When TLS is configured (via `tls_cert` and `tls_key` in `[server]`),
//! incoming TCP connections are upgraded to TLS before the protocol
//! handshake. Otherwise, plain TCP is used.

use std::net::SocketAddr;

use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info, warn};

use crate::config::types::{AppConfig, ReceiverConfig};
use crate::core::excluder::Excluder;
use crate::core::scanner::{self, ScanOptions};
use crate::transport::codec::{self, CodecError, Frame};
use crate::transport::protocol::*;
use crate::transport::receiver::ReceiverGuard;
use crate::transport::tls;

/// Active connection tracking information.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Remote address of the sender.
    pub remote_addr: SocketAddr,
    /// When the connection was established.
    pub connected_at: Instant,
    /// Number of files received on this connection.
    pub files_received: u64,
    /// Bytes received on this connection.
    pub bytes_received: u64,
}

/// Shared state for the transport server.
pub struct TransportServerState {
    /// Application configuration (for receiver settings).
    pub config: Arc<RwLock<AppConfig>>,
    /// Active connections (for status reporting).
    pub connections: Arc<RwLock<Vec<ConnectionInfo>>>,
    /// Broadcast sender for shutdown signalling.
    pub shutdown_tx: broadcast::Sender<()>,
    /// Optional TLS acceptor (set when TLS is configured).
    pub tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
}

impl TransportServerState {
    /// Creates a new transport server state without TLS.
    pub fn new(config: Arc<RwLock<AppConfig>>, shutdown_tx: broadcast::Sender<()>) -> Self {
        Self {
            config,
            connections: Arc::new(RwLock::new(Vec::new())),
            shutdown_tx,
            tls_acceptor: None,
        }
    }

    /// Creates a new transport server state with TLS support.
    ///
    /// Loads the TLS certificate and key from the paths specified in the
    /// server configuration and builds a `TlsAcceptor`.
    pub fn new_with_tls(
        config: Arc<RwLock<AppConfig>>,
        shutdown_tx: broadcast::Sender<()>,
        tls_acceptor: tokio_rustls::TlsAcceptor,
    ) -> Self {
        Self {
            config,
            connections: Arc::new(RwLock::new(Vec::new())),
            shutdown_tx,
            tls_acceptor: Some(tls_acceptor),
        }
    }

    /// Returns the number of active connections.
    pub async fn active_connection_count(&self) -> usize {
        self.connections.read().await.len()
    }

    /// Returns a snapshot of active connections.
    pub async fn active_connections(&self) -> Vec<ConnectionInfo> {
        self.connections.read().await.clone()
    }
}

/// Starts the transport TCP/TLS listener for accepting incoming sync connections.
///
/// This function binds to the configured listen address and spawns a new
/// tokio task for each incoming connection. Each connection task handles
/// the optional TLS upgrade, protocol handshake, alias resolution, and
/// command dispatch.
///
/// When `state.tls_acceptor` is `Some`, incoming connections are upgraded
/// to TLS before protocol handling. Otherwise, plain TCP is used.
///
/// The listener runs until a shutdown signal is received.
///
/// # Arguments
///
/// * `state` — shared transport server state.
///
/// # Errors
///
/// Returns an error if the listener cannot bind to the configured address.
pub async fn run_transport_listener(state: Arc<TransportServerState>) -> Result<()> {
    let listen_addr = {
        let config = state.config.read().await;
        config.server.listen.clone()
    };

    let listener = TcpListener::bind(&listen_addr)
        .await
        .with_context(|| format!("failed to bind transport listener to '{}'", listen_addr))?;

    let local_addr = listener.local_addr()?;
    let tls_enabled = state.tls_acceptor.is_some();
    info!(
        address = %local_addr,
        tls = tls_enabled,
        "transport listener started"
    );

    let mut shutdown_rx = state.shutdown_tx.subscribe();

    loop {
        tokio::select! {
            biased;

            _ = shutdown_rx.recv() => {
                info!("transport listener received shutdown signal");
                break;
            }

            accept_result = listener.accept() => {
                match accept_result {
                    Ok((tcp_stream, addr)) => {
                        info!(
                            remote = %addr,
                            tls = tls_enabled,
                            "accepted incoming connection"
                        );

                        let conn_state = Arc::clone(&state);

                        if let Some(ref acceptor) = state.tls_acceptor {
                            // TLS mode: upgrade the connection before handling
                            let acceptor = acceptor.clone();
                            tokio::spawn(async move {
                                match acceptor.accept(tcp_stream).await {
                                    Ok(tls_stream) => {
                                        debug!(
                                            remote = %addr,
                                            "TLS handshake completed"
                                        );
                                        if let Err(err) =
                                            handle_connection_generic(
                                                tls_stream, addr, conn_state,
                                            )
                                            .await
                                        {
                                            warn!(
                                                remote = %addr,
                                                error = %err,
                                                "connection handler error"
                                            );
                                        }
                                    }
                                    Err(err) => {
                                        warn!(
                                            remote = %addr,
                                            error = %err,
                                            "TLS handshake failed"
                                        );
                                    }
                                }
                            });
                        } else {
                            // Plain TCP mode
                            tokio::spawn(async move {
                                if let Err(err) =
                                    handle_connection_generic(
                                        tcp_stream, addr, conn_state,
                                    )
                                    .await
                                {
                                    warn!(
                                        remote = %addr,
                                        error = %err,
                                        "connection handler error"
                                    );
                                }
                            });
                        }
                    }
                    Err(err) => {
                        warn!(error = %err, "failed to accept connection");
                    }
                }
            }
        }
    }

    info!("transport listener stopped");
    Ok(())
}

/// Builds the TLS acceptor from server configuration, if TLS is configured.
///
/// Returns `Some(TlsAcceptor)` when both `tls_cert` and `tls_key` are set
/// and the files exist and are valid. Returns `None` otherwise (plain TCP).
pub fn build_tls_acceptor_from_config(
    config: &AppConfig,
) -> Result<Option<tokio_rustls::TlsAcceptor>> {
    let tls_paths = tls::check_server_tls_config(
        config.server.tls_cert.as_deref(),
        config.server.tls_key.as_deref(),
    );

    match tls_paths {
        Some((cert_path, key_path)) => {
            let server_config = tls::build_server_config(cert_path, key_path)
                .context("failed to build TLS server configuration")?;
            Ok(Some(tokio_rustls::TlsAcceptor::from(server_config)))
        }
        None => Ok(None),
    }
}

/// Handles a single incoming connection (TCP or TLS) from a remote sender.
///
/// This is a generic wrapper that accepts any async read+write stream.
///
/// The connection lifecycle:
/// 1. Perform handshake (authenticate the sender).
/// 2. Enter the command loop: process RESOLVE_ALIAS, LIST, PUSH, DELETE, etc.
/// 3. Clean up on disconnect or error.
async fn handle_connection_generic<S>(
    mut stream: S,
    addr: SocketAddr,
    state: Arc<TransportServerState>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let started = Instant::now();

    // Track this connection
    let conn_info = ConnectionInfo {
        remote_addr: addr,
        connected_at: started,
        files_received: 0,
        bytes_received: 0,
    };

    {
        let mut conns = state.connections.write().await;
        conns.push(conn_info);
    }

    // Ensure we remove the connection tracking on exit
    let cleanup_state = Arc::clone(&state);
    let cleanup_addr = addr;
    let _guard = scopeguard::guard((), move |_| {
        let state = cleanup_state;
        let addr = cleanup_addr;
        tokio::spawn(async move {
            let mut conns = state.connections.write().await;
            conns.retain(|c| c.remote_addr != addr);
        });
    });

    // Step 1: Read and verify handshake
    let receiver_config = {
        let config = state.config.read().await;
        config.receiver.clone()
    };

    let receiver_config = match receiver_config {
        Some(cfg) if cfg.enabled => cfg,
        _ => {
            debug!(remote = %addr, "receiver is disabled; rejecting connection");
            send_handshake_reject(&mut stream, "receiver is disabled").await?;
            return Ok(());
        }
    };

    let guard = match perform_handshake(&mut stream, &receiver_config, addr).await {
        Ok(guard) => guard,
        Err(err) => {
            warn!(
                remote = %addr,
                error = %err,
                "handshake failed"
            );
            return Ok(());
        }
    };

    info!(remote = %addr, "handshake successful; entering command loop");

    // Step 2: Enter the command loop
    let mut shutdown_rx = state.shutdown_tx.subscribe();
    let mut files_received: u64 = 0;
    let mut bytes_received: u64 = 0;

    loop {
        let frame = tokio::select! {
            biased;

            _ = shutdown_rx.recv() => {
                debug!(remote = %addr, "connection shutdown signal");
                break;
            }

            result = codec::read_frame(&mut stream) => {
                match result {
                    Ok(frame) => frame,
                    Err(CodecError::Io(ref e))
                        if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                    {
                        debug!(remote = %addr, "client disconnected");
                        break;
                    }
                    Err(err) => {
                        warn!(
                            remote = %addr,
                            error = %err,
                            "error reading frame"
                        );
                        break;
                    }
                }
            }
        };

        debug!(
            remote = %addr,
            msg_type = ?frame.msg_type,
            payload_len = frame.payload.len(),
            "received command"
        );

        match frame.msg_type {
            MessageType::ResolveAlias => {
                handle_resolve_alias(&mut stream, &guard, &frame, addr).await?;
            }
            MessageType::ListRequest => {
                handle_list_request(&mut stream, &guard, &frame, addr).await?;
            }
            MessageType::PushFile => {
                let (files, bytes) = handle_push_file(&mut stream, &guard, &frame, addr).await?;
                files_received += files;
                bytes_received += bytes;

                // Update connection stats
                let mut conns = state.connections.write().await;
                if let Some(conn) = conns.iter_mut().find(|c| c.remote_addr == addr) {
                    conn.files_received = files_received;
                    conn.bytes_received = bytes_received;
                }
            }
            MessageType::DeleteRequest => {
                handle_delete_request(&mut stream, &guard, &frame, addr).await?;
            }
            MessageType::StatusRequest => {
                handle_status_request(&mut stream, addr, files_received, bytes_received).await?;
            }
            MessageType::Error => {
                let payload: ErrorPayload = frame.decode_payload().unwrap_or(ErrorPayload {
                    code: 0,
                    message: "unknown error from client".to_string(),
                });
                warn!(
                    remote = %addr,
                    code = payload.code,
                    message = %payload.message,
                    "received error from client"
                );
                break;
            }
            other => {
                warn!(
                    remote = %addr,
                    msg_type = ?other,
                    "unexpected message type in command loop"
                );
                let error_frame = Frame::from_payload(
                    MessageType::Error,
                    &ErrorPayload {
                        code: error_codes::INTERNAL_ERROR,
                        message: format!("unexpected message type: {:?}", other),
                    },
                )?;
                codec::write_frame(&mut stream, &error_frame).await?;
            }
        }
    }

    info!(
        remote = %addr,
        duration_secs = started.elapsed().as_secs(),
        files = files_received,
        bytes = bytes_received,
        "connection closed"
    );

    Ok(())
}

/// Performs the initial handshake with a remote sender.
///
/// Reads the handshake frame, validates the protocol version and auth token,
/// and sends an acknowledgement. Returns a [`ReceiverGuard`] configured with
/// the receiver's allowed paths for subsequent path validation.
async fn perform_handshake<S>(
    stream: &mut S,
    receiver_config: &ReceiverConfig,
    addr: SocketAddr,
) -> Result<ReceiverGuard>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Read the handshake frame
    let frame = codec::read_frame(stream)
        .await
        .context("failed to read handshake frame")?;

    if frame.msg_type != MessageType::Handshake {
        send_handshake_reject(stream, "expected Handshake message").await?;
        anyhow::bail!("expected Handshake message, got {:?}", frame.msg_type);
    }

    let handshake: HandshakePayload = frame
        .decode_payload()
        .map_err(|e| anyhow::anyhow!("invalid handshake payload: {e}"))?;

    debug!(
        remote = %addr,
        version = handshake.version,
        "received handshake"
    );

    // Verify protocol version
    if handshake.version != PROTOCOL_VERSION {
        send_handshake_reject(
            stream,
            &format!(
                "protocol version mismatch: expected {}, got {}",
                PROTOCOL_VERSION, handshake.version
            ),
        )
        .await?;
        anyhow::bail!(
            "protocol version mismatch: expected {}, got {}",
            PROTOCOL_VERSION,
            handshake.version
        );
    }

    // Verify auth token
    if handshake.auth_token != receiver_config.auth_token.expose() {
        send_handshake_reject(stream, "authentication failed").await?;
        warn!(remote = %addr, "authentication failed");
        anyhow::bail!("authentication failed for {}", addr);
    }

    // Build the ReceiverGuard from allowed_paths
    let guard = ReceiverGuard::new(&receiver_config.allowed_paths);

    // Send success acknowledgement
    let ack = HandshakeAckPayload {
        accepted: true,
        reason: None,
    };
    let ack_frame = Frame::from_payload(MessageType::HandshakeAck, &ack)?;
    codec::write_frame(stream, &ack_frame).await?;

    info!(remote = %addr, "handshake accepted");
    Ok(guard)
}

/// Sends a handshake rejection to the client.
async fn send_handshake_reject<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    reason: &str,
) -> Result<()> {
    let ack = HandshakeAckPayload {
        accepted: false,
        reason: Some(reason.to_string()),
    };
    let frame = Frame::from_payload(MessageType::HandshakeAck, &ack)?;
    codec::write_frame(stream, &frame).await?;
    Ok(())
}

/// Handles a RESOLVE_ALIAS command from the sender.
///
/// Resolves the alias/path using the [`ReceiverGuard`] and sends back the
/// resolved absolute path or an error.
async fn handle_resolve_alias<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    guard: &ReceiverGuard,
    frame: &Frame,
    addr: SocketAddr,
) -> Result<()> {
    let payload: ResolveAliasPayload = frame
        .decode_payload()
        .map_err(|e| anyhow::anyhow!("invalid ResolveAlias payload: {e}"))?;

    debug!(
        remote = %addr,
        path = %payload.remote_path,
        "resolving alias"
    );

    match guard.resolve_path(&payload.remote_path) {
        Ok(resolved) => {
            let ack = ResolveAckPayload {
                success: true,
                resolved_path: Some(resolved.to_string_lossy().to_string()),
                reason: None,
            };
            let response = Frame::from_payload(MessageType::ResolveAck, &ack)?;
            codec::write_frame(stream, &response).await?;

            info!(
                remote = %addr,
                alias = %payload.remote_path,
                resolved = %resolved.display(),
                "alias resolved"
            );
        }
        Err(err) => {
            let ack = ResolveAckPayload {
                success: false,
                resolved_path: None,
                reason: Some(format!("{err}")),
            };
            let response = Frame::from_payload(MessageType::ResolveAck, &ack)?;
            codec::write_frame(stream, &response).await?;

            warn!(
                remote = %addr,
                alias = %payload.remote_path,
                error = %err,
                "alias resolution failed"
            );
        }
    }

    Ok(())
}

/// Handles a LIST command from the sender.
///
/// Scans the requested directory on the receiver and sends back the file
/// listing with metadata.
async fn handle_list_request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    guard: &ReceiverGuard,
    frame: &Frame,
    addr: SocketAddr,
) -> Result<()> {
    let payload: ListRequestPayload = frame
        .decode_payload()
        .map_err(|e| anyhow::anyhow!("invalid ListRequest payload: {e}"))?;

    debug!(
        remote = %addr,
        path = %payload.path,
        "list request"
    );

    // Validate the path through the guard
    let resolved_path = match guard.resolve_path(&payload.path) {
        Ok(p) => p,
        Err(err) => {
            let error_resp = Frame::from_payload(
                MessageType::Error,
                &ErrorPayload {
                    code: error_codes::FORBIDDEN,
                    message: format!("path validation failed: {err}"),
                },
            )?;
            codec::write_frame(stream, &error_resp).await?;
            return Ok(());
        }
    };

    // Scan the directory
    let entries = match scan_directory_for_list(&resolved_path).await {
        Ok(entries) => entries,
        Err(err) => {
            warn!(
                remote = %addr,
                path = %resolved_path.display(),
                error = %err,
                "failed to scan directory for LIST"
            );
            // Send an empty list rather than an error — the directory
            // might not exist yet (first sync)
            Vec::new()
        }
    };

    let response_payload = ListResponsePayload { entries };
    let response = Frame::from_payload(MessageType::ListResponse, &response_payload)?;
    codec::write_frame(stream, &response).await?;

    debug!(
        remote = %addr,
        path = %resolved_path.display(),
        count = response_payload.entries.len(),
        "sent file listing"
    );

    Ok(())
}

/// Scans a directory and returns file entries for the LIST response.
async fn scan_directory_for_list(path: &std::path::Path) -> Result<Vec<FileEntryPayload>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let path_clone = path.to_path_buf();
    let scan_opts = ScanOptions {
        compute_hashes: true,
        ..ScanOptions::default()
    };
    let excluder = Excluder::empty();

    let (_root, tree) = tokio::task::spawn_blocking(move || {
        scanner::scan_directory(&path_clone, &excluder, &scan_opts)
    })
    .await
    .context("scan task panicked")?
    .context("failed to scan directory")?;

    let entries: Vec<FileEntryPayload> = tree
        .values()
        .map(|meta| {
            let mtime_secs = meta
                .mtime
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let mtime_nanos = meta
                .mtime
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);

            FileEntryPayload {
                rel_path: meta.rel_path.to_string_lossy().to_string(),
                size: meta.size,
                mtime_secs,
                mtime_nanos,
                hash: meta.hash.clone(),
                is_dir: meta.is_dir,
            }
        })
        .collect();

    Ok(entries)
}

/// Handles a PUSH command from the sender.
///
/// Reads the push header, then reads the file data from the stream and
/// writes it to the resolved path on the receiver. Sends an acknowledgement
/// when complete.
///
/// Returns `(files_received_increment, bytes_received_increment)`.
async fn handle_push_file<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    guard: &ReceiverGuard,
    frame: &Frame,
    addr: SocketAddr,
) -> Result<(u64, u64)> {
    let header: PushFileHeader = frame
        .decode_payload()
        .map_err(|e| anyhow::anyhow!("invalid PushFile header: {e}"))?;

    debug!(
        remote = %addr,
        rel_path = %header.rel_path,
        size = header.size,
        "receiving file"
    );

    // We need the resolved base path. The rel_path in the header is relative
    // to the destination that was previously resolved via RESOLVE_ALIAS.
    // For the push protocol, the sender should have already resolved the alias
    // and the rel_path is relative to that resolved path.
    //
    // The sender passes the base resolved path as part of the connection context.
    // For simplicity in v0.1, we'll accept the file at any allowed path that
    // the guard validates as the parent.
    //
    // We treat the rel_path as needing validation against allowed paths.
    let dest_path = match guard.resolve_path(&header.rel_path) {
        Ok(p) => p,
        Err(err) => {
            // Send rejection
            let ack = PushAckPayload {
                success: false,
                error: Some(format!("path validation failed: {err}")),
            };
            let response = Frame::from_payload(MessageType::PushAck, &ack)?;
            codec::write_frame(stream, &response).await?;

            // We still need to consume the file data from the stream
            // to avoid desynchronizing the protocol.
            drain_file_data(stream, header.size).await?;

            return Ok((0, 0));
        }
    };

    // Ensure parent directory exists
    if let Some(parent) = dest_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create parent directory '{}'", parent.display()))?;
    }

    // Read the file data: after the PushFile header frame, the sender sends
    // a raw data frame with the actual file contents.
    let data_frame = codec::read_frame(stream)
        .await
        .context("failed to read file data frame")?;

    if data_frame.msg_type != MessageType::PushFile {
        warn!(
            remote = %addr,
            expected = ?MessageType::PushFile,
            got = ?data_frame.msg_type,
            "unexpected message type for file data"
        );
        let ack = PushAckPayload {
            success: false,
            error: Some("expected PushFile data frame".to_string()),
        };
        let response = Frame::from_payload(MessageType::PushAck, &ack)?;
        codec::write_frame(stream, &response).await?;
        return Ok((0, 0));
    }

    let file_data = data_frame.payload;
    let received_size = file_data.len() as u64;

    // Verify size matches
    if received_size != header.size {
        warn!(
            remote = %addr,
            expected = header.size,
            received = received_size,
            "file size mismatch"
        );
    }

    // Write to a temp file and then rename (atomic write)
    let parent = dest_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let temp_file =
        tempfile::NamedTempFile::new_in(parent).context("failed to create temp file for push")?;
    let temp_path = temp_file.path().to_path_buf();

    tokio::fs::write(&temp_path, &file_data)
        .await
        .with_context(|| format!("failed to write temp file '{}'", temp_path.display()))?;

    // Set permissions if provided
    #[cfg(unix)]
    if let Some(perms) = header.permissions {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(perms);
        let _ = tokio::fs::set_permissions(&temp_path, permissions).await;
    }

    // Atomic rename
    tokio::fs::rename(&temp_path, &dest_path)
        .await
        .with_context(|| format!("failed to rename temp file to '{}'", dest_path.display()))?;

    // Keep the temp file handle so it's not cleaned up
    temp_file.into_temp_path().keep()?;

    // Verify hash if provided
    let hash_ok = if !header.hash.is_empty() {
        let dest_clone = dest_path.clone();
        let expected_hash = header.hash.clone();
        match tokio::task::spawn_blocking(move || {
            crate::core::hasher::hash_file_blocking(&dest_clone)
        })
        .await
        {
            Ok(Ok(actual_hash)) => {
                if actual_hash != expected_hash {
                    warn!(
                        remote = %addr,
                        expected = %expected_hash,
                        actual = %actual_hash,
                        "hash mismatch for pushed file"
                    );
                    false
                } else {
                    true
                }
            }
            _ => {
                warn!(remote = %addr, "failed to verify hash of pushed file");
                true // Accept anyway — hash verification is best-effort
            }
        }
    } else {
        true
    };

    // Send acknowledgement
    let ack = PushAckPayload {
        success: hash_ok,
        error: if hash_ok {
            None
        } else {
            Some("hash verification failed".to_string())
        },
    };
    let response = Frame::from_payload(MessageType::PushAck, &ack)?;
    codec::write_frame(stream, &response).await?;

    if hash_ok {
        info!(
            remote = %addr,
            path = %dest_path.display(),
            size = received_size,
            "file received and written"
        );
    }

    Ok((1, received_size))
}

/// Drains file data from the stream to keep the protocol synchronized
/// after rejecting a push.
async fn drain_file_data<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    _expected_size: u64,
) -> Result<()> {
    // Read and discard the data frame
    let _ = codec::read_frame(stream).await;
    Ok(())
}

/// Handles a DELETE command from the sender.
///
/// Deletes the specified file or directory on the receiver after validating
/// the path through the [`ReceiverGuard`].
async fn handle_delete_request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    guard: &ReceiverGuard,
    frame: &Frame,
    addr: SocketAddr,
) -> Result<()> {
    let payload: DeleteRequestPayload = frame
        .decode_payload()
        .map_err(|e| anyhow::anyhow!("invalid DeleteRequest payload: {e}"))?;

    debug!(
        remote = %addr,
        path = %payload.rel_path,
        is_dir = payload.is_dir,
        "delete request"
    );

    let resolved_path = match guard.resolve_path(&payload.rel_path) {
        Ok(p) => p,
        Err(err) => {
            let ack = DeleteAckPayload {
                success: false,
                error: Some(format!("path validation failed: {err}")),
            };
            let response = Frame::from_payload(MessageType::DeleteAck, &ack)?;
            codec::write_frame(stream, &response).await?;
            return Ok(());
        }
    };

    let result = if payload.is_dir {
        tokio::fs::remove_dir_all(&resolved_path).await
    } else {
        tokio::fs::remove_file(&resolved_path).await
    };

    let (success, error) = match result {
        Ok(()) => {
            info!(
                remote = %addr,
                path = %resolved_path.display(),
                "file deleted"
            );
            (true, None)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // File already gone — treat as success
            debug!(
                remote = %addr,
                path = %resolved_path.display(),
                "file already deleted"
            );
            (true, None)
        }
        Err(err) => {
            warn!(
                remote = %addr,
                path = %resolved_path.display(),
                error = %err,
                "failed to delete file"
            );
            (false, Some(format!("delete failed: {err}")))
        }
    };

    let ack = DeleteAckPayload { success, error };
    let response = Frame::from_payload(MessageType::DeleteAck, &ack)?;
    codec::write_frame(stream, &response).await?;

    Ok(())
}

/// Handles a STATUS command from the sender.
///
/// Returns basic status information about this receiver connection.
async fn handle_status_request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    addr: SocketAddr,
    files_received: u64,
    bytes_received: u64,
) -> Result<()> {
    debug!(remote = %addr, "status request");

    let status = serde_json::json!({
        "status": "ok",
        "files_received": files_received,
        "bytes_received": bytes_received,
    });

    let payload = serde_json::to_vec(&status).context("failed to serialize status")?;
    let response = Frame::new(MessageType::StatusResp, payload);
    codec::write_frame(stream, &response).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use crate::config::types::{AllowedPath, AppConfig, ReceiverConfig, Secret, ServerConfig};
    use tokio::net::{TcpListener, TcpStream};

    fn test_config(listen_addr: &str, auth_token: &str, allowed_path: &str) -> AppConfig {
        AppConfig {
            server: ServerConfig {
                listen: listen_addr.to_string(),
                api_listen: "127.0.0.1:0".to_string(),
                log_level: "debug".to_string(),
                data_dir: None,
                safety_dir: None,
                auth_token: None,
                tls_cert: None,
                tls_key: None,
            },
            receiver: Some(ReceiverConfig {
                enabled: true,
                auth_token: Secret::new(auth_token),
                allowed_paths: vec![AllowedPath {
                    path: std::path::PathBuf::from(allowed_path),
                    alias: Some("backup".to_string()),
                }],
            }),
            encryption: None,
            remote: vec![],
            sync: vec![],
        }
    }

    #[test]
    fn test_connection_info_clone() {
        let info = ConnectionInfo {
            remote_addr: "127.0.0.1:12345".parse().unwrap(),
            connected_at: Instant::now(),
            files_received: 5,
            bytes_received: 1024,
        };
        let cloned = info.clone();
        assert_eq!(cloned.remote_addr, info.remote_addr);
        assert_eq!(cloned.files_received, info.files_received);
        assert_eq!(cloned.bytes_received, info.bytes_received);
    }

    #[tokio::test]
    async fn test_transport_server_state_new() {
        let config = Arc::new(RwLock::new(test_config(
            "127.0.0.1:0",
            "test-token",
            "/tmp",
        )));
        let (tx, _rx) = broadcast::channel(16);
        let state = TransportServerState::new(config, tx);

        assert_eq!(state.active_connection_count().await, 0);
        assert!(state.active_connections().await.is_empty());
    }

    #[tokio::test]
    async fn test_handshake_valid_token() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config("127.0.0.1:0", "correct-token", dir.path().to_str().unwrap());

        let receiver_config = config.receiver.clone().unwrap();

        // Start a listener on a random port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a server task that accepts one connection and handshakes
        let server_task = tokio::spawn(async move {
            let (mut stream, client_addr) = listener.accept().await.unwrap();
            let result = perform_handshake(&mut stream, &receiver_config, client_addr).await;
            result.is_ok()
        });

        // Connect as a client and send a valid handshake
        let mut client = TcpStream::connect(addr).await.unwrap();
        let handshake = HandshakePayload {
            version: PROTOCOL_VERSION,
            auth_token: "correct-token".to_string(),
        };
        let frame = Frame::from_payload(MessageType::Handshake, &handshake).unwrap();
        codec::write_frame(&mut client, &frame).await.unwrap();

        // Read the ack
        let ack_frame = codec::read_frame(&mut client).await.unwrap();
        assert_eq!(ack_frame.msg_type, MessageType::HandshakeAck);
        let ack: HandshakeAckPayload = ack_frame.decode_payload().unwrap();
        assert!(ack.accepted);

        let server_ok = server_task.await.unwrap();
        assert!(server_ok);
    }

    #[tokio::test]
    async fn test_handshake_wrong_token() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config("127.0.0.1:0", "correct-token", dir.path().to_str().unwrap());
        let receiver_config = config.receiver.clone().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (mut stream, client_addr) = listener.accept().await.unwrap();
            let result = perform_handshake(&mut stream, &receiver_config, client_addr).await;
            result.is_err() // Should fail
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let handshake = HandshakePayload {
            version: PROTOCOL_VERSION,
            auth_token: "wrong-token".to_string(),
        };
        let frame = Frame::from_payload(MessageType::Handshake, &handshake).unwrap();
        codec::write_frame(&mut client, &frame).await.unwrap();

        // Read the rejection ack
        let ack_frame = codec::read_frame(&mut client).await.unwrap();
        let ack: HandshakeAckPayload = ack_frame.decode_payload().unwrap();
        assert!(!ack.accepted);
        assert!(ack.reason.unwrap().contains("authentication"));

        let server_failed = server_task.await.unwrap();
        assert!(server_failed);
    }

    #[tokio::test]
    async fn test_handshake_wrong_version() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config("127.0.0.1:0", "token", dir.path().to_str().unwrap());
        let receiver_config = config.receiver.clone().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (mut stream, client_addr) = listener.accept().await.unwrap();
            let result = perform_handshake(&mut stream, &receiver_config, client_addr).await;
            result.is_err()
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let handshake = HandshakePayload {
            version: 99, // Wrong version
            auth_token: "correct-token".to_string(),
        };
        let frame = Frame::from_payload(MessageType::Handshake, &handshake).unwrap();
        codec::write_frame(&mut client, &frame).await.unwrap();

        let ack_frame = codec::read_frame(&mut client).await.unwrap();
        let ack: HandshakeAckPayload = ack_frame.decode_payload().unwrap();
        assert!(!ack.accepted);
        assert!(ack.reason.unwrap().contains("version"));

        assert!(server_task.await.unwrap());
    }

    #[tokio::test]
    async fn test_scan_directory_for_list_nonexistent() {
        let path = PathBuf::from("/tmp/marmosyn_nonexistent_dir_for_test");
        let entries = scan_directory_for_list(&path).await.unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn test_scan_directory_for_list_with_files() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("file1.txt"), b"hello")
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("file2.txt"), b"world")
            .await
            .unwrap();

        let path = dir.path().to_path_buf();
        let entries = scan_directory_for_list(&path).await.unwrap();
        assert_eq!(entries.len(), 2);

        let names: Vec<&str> = entries.iter().map(|e| e.rel_path.as_str()).collect();
        assert!(names.contains(&"file1.txt"));
        assert!(names.contains(&"file2.txt"));
    }
}
