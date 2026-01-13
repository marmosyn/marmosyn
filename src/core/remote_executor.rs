//! Remote executor: implements [`SyncExecutor`] for remote destinations
//! by communicating with a MarmoSyn receiver over the transport protocol.
//!
//! [`RemoteExecutor`] connects to a remote receiver, resolves the destination
//! alias/path, and performs file operations (copy, delete, list) over the
//! binary protocol defined in [`crate::transport::protocol`].

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use super::executor::SyncExecutor;
use super::file_tree::FileMetadata;
use crate::config::types::RemoteNode;
use crate::transport::client::{TransportClient, TransportClientConfig};

/// Remote executor — sends files to a remote receiver over the transport protocol.
///
/// Implements [`SyncExecutor`] by delegating all file operations to a
/// [`TransportClient`] connected to the remote receiver. The connection
/// is established lazily on the first operation, and the alias/path is
/// resolved during connection setup.
///
/// The client connection is wrapped in a `Mutex` because the transport
/// protocol is sequential (one command at a time per connection).
pub struct RemoteExecutor {
    /// The transport client, lazily initialized and protected by a mutex
    /// since the underlying TCP stream is not cloneable.
    client: Arc<Mutex<Option<TransportClient>>>,

    /// Configuration for connecting to the remote receiver.
    client_config: TransportClientConfig,

    /// The remote path component from the dest string (e.g. "backup/docs").
    /// This is sent to the receiver for alias resolution.
    remote_path: String,

    /// The resolved absolute path on the receiver filesystem.
    /// Set after the first successful alias resolution.
    resolved_base: Arc<Mutex<Option<String>>>,

    /// Human-readable description for logging.
    desc: String,
}

impl RemoteExecutor {
    /// Creates a new `RemoteExecutor` for the given remote node and path.
    ///
    /// The actual TCP connection is not established until the first
    /// operation is performed (lazy connection).
    ///
    /// # Arguments
    ///
    /// * `remote` — the remote node configuration (host, token, TLS settings).
    /// * `remote_path` — the path/alias component from the dest string.
    pub fn new(remote: &RemoteNode, remote_path: String) -> Self {
        let desc = format!("remote:{}:{}", remote.name, remote_path);

        let client_config = TransportClientConfig {
            host: remote.host.clone(),
            auth_token: remote.auth_token.expose().to_string(),
            connect_timeout: Duration::from_secs(30),
            io_timeout: Duration::from_secs(120),
            use_tls: remote.tls_ca.is_some() || remote.allow_self_signed,
            tls_ca: remote.tls_ca.clone(),
            allow_self_signed: remote.allow_self_signed,
            tls_server_name: None,
        };

        Self {
            client: Arc::new(Mutex::new(None)),
            client_config,
            remote_path,
            resolved_base: Arc::new(Mutex::new(None)),
            desc,
        }
    }

    /// Creates a `RemoteExecutor` with a custom client configuration.
    ///
    /// Useful for testing or when non-default timeouts are needed.
    pub fn with_config(
        client_config: TransportClientConfig,
        remote_name: &str,
        remote_path: String,
    ) -> Self {
        let desc = format!("remote:{}:{}", remote_name, remote_path);

        Self {
            client: Arc::new(Mutex::new(None)),
            client_config,
            remote_path,
            resolved_base: Arc::new(Mutex::new(None)),
            desc,
        }
    }

    /// Ensures the transport client is connected and the alias is resolved.
    ///
    /// If the client is not yet connected, establishes a new connection,
    /// performs the handshake, and resolves the remote path alias.
    ///
    /// Returns the resolved base path on the receiver.
    async fn ensure_connected(&self) -> Result<String> {
        // Check if we already have a resolved base
        {
            let resolved = self.resolved_base.lock().await;
            if let Some(ref base) = *resolved {
                // Also check the client is still alive
                let client_guard = self.client.lock().await;
                if client_guard.is_some() {
                    return Ok(base.clone());
                }
            }
        }

        // Need to connect
        debug!(
            host = %self.client_config.host,
            remote_path = %self.remote_path,
            "establishing connection to remote receiver"
        );

        let mut client = TransportClient::connect(&self.client_config)
            .await
            .with_context(|| {
                format!(
                    "failed to connect to remote receiver at '{}'",
                    self.client_config.host
                )
            })?;

        // Resolve the alias/path
        let resolved = client
            .resolve_alias(&self.remote_path)
            .await
            .with_context(|| {
                format!(
                    "failed to resolve remote path '{}' on '{}'",
                    self.remote_path, self.client_config.host
                )
            })?;

        info!(
            host = %self.client_config.host,
            remote_path = %self.remote_path,
            resolved = %resolved,
            "connected and alias resolved"
        );

        // Store the client and resolved base
        {
            let mut client_guard = self.client.lock().await;
            *client_guard = Some(client);
        }
        {
            let mut resolved_guard = self.resolved_base.lock().await;
            *resolved_guard = Some(resolved.clone());
        }

        Ok(resolved)
    }

    /// Reconnects to the remote receiver if the connection was lost.
    ///
    /// Clears the existing client and resolved base, forcing `ensure_connected`
    /// to establish a fresh connection on the next call.
    #[allow(dead_code)]
    async fn reconnect(&self) -> Result<String> {
        {
            let mut client_guard = self.client.lock().await;
            *client_guard = None;
        }
        {
            let mut resolved_guard = self.resolved_base.lock().await;
            *resolved_guard = None;
        }

        self.ensure_connected().await
    }

    /// Executes an operation with automatic reconnection on connection errors.
    ///
    /// If the first attempt fails with a connection-related error, the client
    /// reconnects and retries once.
    #[allow(dead_code)]
    async fn with_retry<F, Fut, T>(&self, operation: F) -> Result<T>
    where
        F: Fn(String) -> Fut + Send,
        Fut: std::future::Future<Output = Result<T>> + Send,
    {
        let resolved = self.ensure_connected().await?;

        match operation(resolved).await {
            Ok(val) => Ok(val),
            Err(err) => {
                let err_str = err.to_string();
                if err_str.contains("closed unexpectedly")
                    || err_str.contains("broken pipe")
                    || err_str.contains("connection reset")
                {
                    warn!(
                        host = %self.client_config.host,
                        error = %err,
                        "connection lost, attempting reconnect"
                    );
                    let resolved = self.reconnect().await?;
                    operation(resolved).await
                } else {
                    Err(err)
                }
            }
        }
    }
}

#[async_trait]
impl SyncExecutor for RemoteExecutor {
    /// Copies a file from the local source path to the remote receiver.
    ///
    /// Reads the file, computes its BLAKE3 hash, and pushes it over the
    /// transport protocol. The receiver validates the path and hash.
    async fn copy_file(&self, src: &Path, rel_path: &Path) -> Result<u64> {
        let src_path = src.to_path_buf();
        let rel = rel_path.to_path_buf();
        let client_arc = Arc::clone(&self.client);

        // Compute hash in a blocking task
        let hash_path = src_path.clone();
        let hash = tokio::task::spawn_blocking(move || {
            crate::core::hasher::hash_file_blocking(&hash_path)
        })
        .await
        .context("hash computation task panicked")?
        .with_context(|| format!("failed to hash file '{}'", src.display()))?;

        let resolved = self.ensure_connected().await?;
        let mut client_guard = client_arc.lock().await;

        let client = client_guard
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("transport client not connected"))?;

        let bytes = client
            .push_file(&resolved, &rel, &src_path, &hash)
            .await
            .with_context(|| format!("failed to push file '{}' to remote", rel.display()))?;

        debug!(
            remote = %self.desc,
            path = %rel.display(),
            bytes = bytes,
            "file copied to remote"
        );

        Ok(bytes)
    }

    /// Deletes a file on the remote receiver.
    async fn delete_file(&self, rel_path: &Path) -> Result<()> {
        let rel = rel_path.to_path_buf();
        let client_arc = Arc::clone(&self.client);

        let resolved = self.ensure_connected().await?;
        let mut client_guard = client_arc.lock().await;

        let client = client_guard
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("transport client not connected"))?;

        client
            .delete_file(&resolved, &rel, false)
            .await
            .with_context(|| format!("failed to delete file '{}' on remote", rel.display()))?;

        debug!(
            remote = %self.desc,
            path = %rel.display(),
            "file deleted on remote"
        );

        Ok(())
    }

    /// Creates a directory on the remote receiver.
    ///
    /// Directories are implicitly created by the receiver when pushing
    /// files, so this is a no-op for remote destinations. We still log
    /// the operation for debugging purposes.
    async fn create_dir(&self, rel_path: &Path) -> Result<()> {
        // Directories are created implicitly on the receiver side when
        // files are pushed (the receiver creates parent directories).
        // We log it but don't send a separate command.
        debug!(
            remote = %self.desc,
            path = %rel_path.display(),
            "directory creation on remote (implicit via push)"
        );
        Ok(())
    }

    /// Lists all files on the remote destination.
    ///
    /// Sends a LIST request to the receiver and converts the response
    /// into [`FileMetadata`] entries.
    async fn list_files(&self) -> Result<Vec<FileMetadata>> {
        let client_arc = Arc::clone(&self.client);

        let resolved = self.ensure_connected().await?;
        let mut client_guard = client_arc.lock().await;

        let client = client_guard
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("transport client not connected"))?;

        let entries = client
            .list_files(&resolved)
            .await
            .with_context(|| format!("failed to list files on remote at '{}'", resolved))?;

        debug!(
            remote = %self.desc,
            count = entries.len(),
            "received file list from remote"
        );

        // Convert FileEntryPayload to FileMetadata
        let metadata: Vec<FileMetadata> = entries
            .into_iter()
            .map(|entry| {
                let mtime = if entry.mtime_secs >= 0 {
                    UNIX_EPOCH
                        + Duration::from_secs(entry.mtime_secs as u64)
                        + Duration::from_nanos(entry.mtime_nanos as u64)
                } else {
                    // For negative timestamps (before epoch), use epoch as fallback
                    UNIX_EPOCH
                };

                FileMetadata {
                    rel_path: PathBuf::from(&entry.rel_path),
                    size: entry.size,
                    mtime,
                    hash: entry.hash,
                    is_dir: entry.is_dir,
                    permissions: None,
                }
            })
            .collect();

        Ok(metadata)
    }

    /// Returns a human-readable description of this executor's target.
    fn description(&self) -> &str {
        &self.desc
    }
}

impl Drop for RemoteExecutor {
    fn drop(&mut self) {
        // We can't do async operations in Drop, so we just log.
        // The underlying TCP connection will be closed when the stream
        // is dropped.
        debug!(
            remote = %self.desc,
            "remote executor dropped; connection will be closed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{AllowedPath, Secret};
    use crate::transport::client::TransportClientConfig;
    use crate::transport::codec::{self, Frame};
    use crate::transport::protocol::*;
    use crate::transport::receiver::ReceiverGuard;
    use std::path::PathBuf;
    use tokio::net::TcpListener;

    /// Spawns a minimal test receiver that handles all protocol commands.
    async fn spawn_test_receiver(
        auth_token: &str,
        allowed_paths: Vec<AllowedPath>,
        dest_dir: PathBuf,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let token = auth_token.to_string();

        let handle = tokio::spawn(async move {
            let (mut stream, _addr) = listener.accept().await.unwrap();

            // Handshake
            let frame = codec::read_frame(&mut stream).await.unwrap();
            let hs: HandshakePayload = frame.decode_payload().unwrap();
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
                        let _payload: ListRequestPayload = frame.decode_payload().unwrap();

                        // Scan the dest_dir and return real entries
                        let mut entries = Vec::new();
                        if dest_dir.exists() {
                            if let Ok(mut read_dir) = tokio::fs::read_dir(&dest_dir).await {
                                while let Ok(Some(entry)) = read_dir.next_entry().await {
                                    if let Ok(meta) = entry.metadata().await {
                                        let rel = entry.file_name().to_string_lossy().to_string();
                                        let mtime_secs = meta
                                            .modified()
                                            .ok()
                                            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                                            .map(|d| d.as_secs() as i64)
                                            .unwrap_or(0);
                                        entries.push(FileEntryPayload {
                                            rel_path: rel,
                                            size: meta.len(),
                                            mtime_secs,
                                            mtime_nanos: 0,
                                            hash: None,
                                            is_dir: meta.is_dir(),
                                        });
                                    }
                                }
                            }
                        }

                        let resp_payload = ListResponsePayload { entries };
                        let resp =
                            Frame::from_payload(MessageType::ListResponse, &resp_payload).unwrap();
                        codec::write_frame(&mut stream, &resp).await.unwrap();
                    }
                    MessageType::PushFile => {
                        let header: PushFileHeader = frame.decode_payload().unwrap();

                        // Read the data frame
                        let data_frame = codec::read_frame(&mut stream).await.unwrap();

                        // Resolve and write the file
                        match guard.resolve_path(&header.rel_path) {
                            Ok(dest_path) => {
                                if let Some(parent) = dest_path.parent() {
                                    let _ = tokio::fs::create_dir_all(parent).await;
                                }
                                let _ = tokio::fs::write(&dest_path, &data_frame.payload).await;

                                let ack = PushAckPayload {
                                    success: true,
                                    error: None,
                                };
                                let resp = Frame::from_payload(MessageType::PushAck, &ack).unwrap();
                                codec::write_frame(&mut stream, &resp).await.unwrap();
                            }
                            Err(e) => {
                                let ack = PushAckPayload {
                                    success: false,
                                    error: Some(format!("path validation failed: {e}")),
                                };
                                let resp = Frame::from_payload(MessageType::PushAck, &ack).unwrap();
                                codec::write_frame(&mut stream, &resp).await.unwrap();
                            }
                        }
                    }
                    MessageType::DeleteRequest => {
                        let payload: DeleteRequestPayload = frame.decode_payload().unwrap();

                        match guard.resolve_path(&payload.rel_path) {
                            Ok(resolved) => {
                                let result = if payload.is_dir {
                                    tokio::fs::remove_dir_all(&resolved).await
                                } else {
                                    tokio::fs::remove_file(&resolved).await
                                };
                                let (success, error) = match result {
                                    Ok(()) => (true, None),
                                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                                        (true, None)
                                    }
                                    Err(e) => (false, Some(format!("delete failed: {e}"))),
                                };
                                let ack = DeleteAckPayload { success, error };
                                let resp =
                                    Frame::from_payload(MessageType::DeleteAck, &ack).unwrap();
                                codec::write_frame(&mut stream, &resp).await.unwrap();
                            }
                            Err(e) => {
                                let ack = DeleteAckPayload {
                                    success: false,
                                    error: Some(format!("path validation failed: {e}")),
                                };
                                let resp =
                                    Frame::from_payload(MessageType::DeleteAck, &ack).unwrap();
                                codec::write_frame(&mut stream, &resp).await.unwrap();
                            }
                        }
                    }
                    MessageType::Error => {
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
    async fn test_remote_executor_copy_file() {
        let tmp = tempfile::tempdir().unwrap();
        let recv_dir = tmp.path().join("recv");
        std::fs::create_dir_all(&recv_dir).unwrap();

        let allowed = vec![AllowedPath {
            path: recv_dir.clone(),
            alias: Some("backup".to_string()),
        }];

        let (addr, _handle) = spawn_test_receiver("test-token", allowed, recv_dir.clone()).await;

        let config = TransportClientConfig {
            host: addr.to_string(),
            auth_token: "test-token".to_string(),
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(10),
            ..Default::default()
        };

        let executor = RemoteExecutor::with_config(config, "test-server", "backup".to_string());

        // Create a source file
        let src_file = tmp.path().join("source.txt");
        tokio::fs::write(&src_file, b"hello remote world")
            .await
            .unwrap();

        let bytes = executor
            .copy_file(&src_file, Path::new("source.txt"))
            .await
            .unwrap();

        assert_eq!(bytes, 18);

        // Verify the file was written on the receiver side
        let dest_content = tokio::fs::read_to_string(recv_dir.join("source.txt"))
            .await
            .unwrap();
        assert_eq!(dest_content, "hello remote world");
    }

    #[tokio::test]
    async fn test_remote_executor_copy_nested_file() {
        let tmp = tempfile::tempdir().unwrap();
        let recv_dir = tmp.path().join("recv");
        std::fs::create_dir_all(&recv_dir).unwrap();

        let allowed = vec![AllowedPath {
            path: recv_dir.clone(),
            alias: Some("backup".to_string()),
        }];

        let (addr, _handle) = spawn_test_receiver("test-token", allowed, recv_dir.clone()).await;

        let config = TransportClientConfig {
            host: addr.to_string(),
            auth_token: "test-token".to_string(),
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(10),
            ..Default::default()
        };

        let executor = RemoteExecutor::with_config(config, "test-server", "backup".to_string());

        let src_file = tmp.path().join("nested.txt");
        tokio::fs::write(&src_file, b"nested content")
            .await
            .unwrap();

        let bytes = executor
            .copy_file(&src_file, Path::new("sub/dir/nested.txt"))
            .await
            .unwrap();

        assert_eq!(bytes, 14);

        let dest_content = tokio::fs::read_to_string(recv_dir.join("sub/dir/nested.txt"))
            .await
            .unwrap();
        assert_eq!(dest_content, "nested content");
    }

    #[tokio::test]
    async fn test_remote_executor_delete_file() {
        let tmp = tempfile::tempdir().unwrap();
        let recv_dir = tmp.path().join("recv");
        std::fs::create_dir_all(&recv_dir).unwrap();

        // Create a file to delete
        let to_delete = recv_dir.join("old.txt");
        tokio::fs::write(&to_delete, b"old data").await.unwrap();

        let allowed = vec![AllowedPath {
            path: recv_dir.clone(),
            alias: Some("backup".to_string()),
        }];

        let (addr, _handle) = spawn_test_receiver("test-token", allowed, recv_dir.clone()).await;

        let config = TransportClientConfig {
            host: addr.to_string(),
            auth_token: "test-token".to_string(),
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(10),
            ..Default::default()
        };

        let executor = RemoteExecutor::with_config(config, "test-server", "backup".to_string());

        executor.delete_file(Path::new("old.txt")).await.unwrap();

        assert!(!to_delete.exists());
    }

    #[tokio::test]
    async fn test_remote_executor_list_files() {
        let tmp = tempfile::tempdir().unwrap();
        let recv_dir = tmp.path().join("recv");
        std::fs::create_dir_all(&recv_dir).unwrap();

        // Create some files in the receiver directory
        tokio::fs::write(recv_dir.join("a.txt"), b"aaa")
            .await
            .unwrap();
        tokio::fs::write(recv_dir.join("b.txt"), b"bbb")
            .await
            .unwrap();

        let allowed = vec![AllowedPath {
            path: recv_dir.clone(),
            alias: Some("backup".to_string()),
        }];

        let (addr, _handle) = spawn_test_receiver("test-token", allowed, recv_dir.clone()).await;

        let config = TransportClientConfig {
            host: addr.to_string(),
            auth_token: "test-token".to_string(),
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(10),
            ..Default::default()
        };

        let executor = RemoteExecutor::with_config(config, "test-server", "backup".to_string());

        let files = executor.list_files().await.unwrap();

        // Should have at least the two files we created
        assert!(files.len() >= 2);

        let names: Vec<String> = files
            .iter()
            .map(|f| f.rel_path.to_string_lossy().to_string())
            .collect();
        assert!(names.contains(&"a.txt".to_string()));
        assert!(names.contains(&"b.txt".to_string()));
    }

    #[tokio::test]
    async fn test_remote_executor_create_dir_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let recv_dir = tmp.path().join("recv");
        std::fs::create_dir_all(&recv_dir).unwrap();

        let allowed = vec![AllowedPath {
            path: recv_dir.clone(),
            alias: Some("backup".to_string()),
        }];

        let (addr, _handle) = spawn_test_receiver("test-token", allowed, recv_dir.clone()).await;

        let config = TransportClientConfig {
            host: addr.to_string(),
            auth_token: "test-token".to_string(),
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(10),
            ..Default::default()
        };

        let executor = RemoteExecutor::with_config(config, "test-server", "backup".to_string());

        // create_dir should succeed silently (it's a no-op for remote)
        executor.create_dir(Path::new("new/sub/dir")).await.unwrap();
    }

    #[tokio::test]
    async fn test_remote_executor_description() {
        let remote = RemoteNode {
            name: "office-server".to_string(),
            host: "192.168.1.100:7854".to_string(),
            auth_token: Secret::new("secret"),
            tls_ca: None,
            allow_self_signed: false,
        };

        let executor = RemoteExecutor::new(&remote, "backup/docs".to_string());
        assert_eq!(executor.description(), "remote:office-server:backup/docs");
    }

    #[tokio::test]
    async fn test_remote_executor_connection_failure() {
        let config = TransportClientConfig {
            host: "127.0.0.1:1".to_string(), // Almost certainly not listening
            auth_token: "token".to_string(),
            connect_timeout: Duration::from_millis(100),
            io_timeout: Duration::from_millis(100),
            ..Default::default()
        };

        let executor = RemoteExecutor::with_config(config, "bad-server", "backup".to_string());

        let src_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(src_file.path(), b"test data").unwrap();

        let result = executor
            .copy_file(src_file.path(), Path::new("test.txt"))
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_remote_executor_auth_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let recv_dir = tmp.path().join("recv");
        std::fs::create_dir_all(&recv_dir).unwrap();

        let allowed = vec![AllowedPath {
            path: recv_dir.clone(),
            alias: Some("backup".to_string()),
        }];

        let (addr, _handle) = spawn_test_receiver("correct-token", allowed, recv_dir).await;

        let config = TransportClientConfig {
            host: addr.to_string(),
            auth_token: "wrong-token".to_string(),
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(10),
            ..Default::default()
        };

        let executor = RemoteExecutor::with_config(config, "test-server", "backup".to_string());

        let src_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(src_file.path(), b"test data").unwrap();

        let result = executor
            .copy_file(src_file.path(), Path::new("test.txt"))
            .await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("rejected") || err_msg.contains("failed"),
            "expected auth error, got: {err_msg}"
        );
    }
}
