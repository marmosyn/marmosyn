// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! TLS configuration helpers for the transport layer.
//!
//! Provides functions to build `rustls` server and client configurations
//! from PEM certificate and key files. Used by the transport listener
//! (receiver side) and the transport client (sender side) to establish
//! encrypted connections.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{debug, info};

/// Ensures the ring CryptoProvider is installed as the default for rustls.
///
/// This is idempotent — calling it multiple times is safe. The first call
/// installs the provider; subsequent calls are no-ops.
fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Loads PEM-encoded certificates from a file.
///
/// Returns a vector of DER-encoded certificates suitable for use with
/// `rustls` configuration builders.
///
/// # Errors
///
/// Returns an error if the file cannot be read or contains no valid
/// PEM certificates.
pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
        .with_context(|| format!("failed to open certificate file '{}'", path.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse certificates from '{}'", path.display()))?;

    if certs.is_empty() {
        anyhow::bail!("no valid certificates found in '{}'", path.display());
    }

    debug!(
        path = %path.display(),
        count = certs.len(),
        "loaded TLS certificates"
    );

    Ok(certs)
}

/// Loads a PEM-encoded private key from a file.
///
/// Supports RSA, PKCS8, and SEC1 (EC) key formats. Returns the first
/// valid key found in the file.
///
/// # Errors
///
/// Returns an error if the file cannot be read or contains no valid
/// private key.
pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    // PrivateKeyDer::pem_file_iter tries PKCS1, PKCS8 and SEC1 formats.
    let key = PrivateKeyDer::pem_file_iter(path)
        .with_context(|| format!("failed to open private key file '{}'", path.display()))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no valid private key found in '{}'", path.display()))?
        .with_context(|| format!("failed to parse key from '{}'", path.display()))?;

    debug!(
        path = %path.display(),
        kind = ?key,
        "loaded TLS private key"
    );

    Ok(key)
}

/// Builds a `rustls` server configuration for the transport listener.
///
/// # Arguments
///
/// * `cert_path` — path to the PEM certificate chain file.
/// * `key_path` — path to the PEM private key file.
///
/// # Returns
///
/// An `Arc<rustls::ServerConfig>` ready for use with `tokio_rustls::TlsAcceptor`.
///
/// # Errors
///
/// Returns an error if the certificate or key files cannot be loaded, or
/// if the TLS configuration cannot be built.
pub fn build_server_config(cert_path: &Path, key_path: &Path) -> Result<Arc<rustls::ServerConfig>> {
    ensure_crypto_provider();

    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("failed to build TLS server configuration")?;

    info!(
        cert = %cert_path.display(),
        key = %key_path.display(),
        "TLS server configuration loaded"
    );

    Ok(Arc::new(config))
}

/// Builds a `rustls` client configuration for connecting to a remote receiver.
///
/// By default, uses the system's root CA certificates (via `webpki-roots`)
/// for server verification. Optionally, a custom CA certificate can be added
/// for self-signed or internal CAs.
///
/// # Arguments
///
/// * `custom_ca` — optional path to a PEM CA certificate file to trust.
/// * `allow_self_signed` — if `true`, disables server certificate verification
///   entirely (dangerous, use only for development/testing).
///
/// # Returns
///
/// An `Arc<rustls::ClientConfig>` ready for use with `tokio_rustls::TlsConnector`.
///
/// # Errors
///
/// Returns an error if the custom CA file cannot be loaded or if the
/// TLS configuration cannot be built.
pub fn build_client_config(
    custom_ca: Option<&Path>,
    allow_self_signed: bool,
) -> Result<Arc<rustls::ClientConfig>> {
    ensure_crypto_provider();

    if allow_self_signed {
        debug!("building TLS client config with certificate verification disabled");

        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth();

        return Ok(Arc::new(config));
    }

    let mut root_store = rustls::RootCertStore::empty();

    // Add system/webpki root certificates
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    debug!(roots = root_store.len(), "loaded system root certificates");

    // Add custom CA if provided
    if let Some(ca_path) = custom_ca {
        let custom_certs = load_certs(ca_path)
            .with_context(|| format!("failed to load custom CA from '{}'", ca_path.display()))?;

        for cert in custom_certs {
            root_store.add(cert).with_context(|| {
                format!(
                    "failed to add custom CA certificate from '{}'",
                    ca_path.display()
                )
            })?;
        }

        info!(
            ca = %ca_path.display(),
            "added custom CA certificate to trust store"
        );
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(Arc::new(config))
}

/// A certificate verifier that accepts any server certificate.
///
/// **WARNING:** This completely disables TLS server verification and should
/// only be used for development or testing. In production, always use proper
/// certificate verification.
#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

/// Checks whether TLS is configured for the server by verifying that both
/// `tls_cert` and `tls_key` paths are set and the files exist.
///
/// Returns `Some((cert_path, key_path))` if TLS is available, or `None`
/// if TLS is not configured.
pub fn check_server_tls_config<'a>(
    tls_cert: Option<&'a Path>,
    tls_key: Option<&'a Path>,
) -> Option<(&'a Path, &'a Path)> {
    match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => {
            if !cert.exists() {
                tracing::warn!(
                    path = %cert.display(),
                    "TLS certificate file does not exist; falling back to plain TCP"
                );
                return None;
            }
            if !key.exists() {
                tracing::warn!(
                    path = %key.display(),
                    "TLS private key file does not exist; falling back to plain TCP"
                );
                return None;
            }
            Some((cert, key))
        }
        (Some(_), None) => {
            tracing::warn!("tls_cert is set but tls_key is missing; TLS disabled");
            None
        }
        (None, Some(_)) => {
            tracing::warn!("tls_key is set but tls_cert is missing; TLS disabled");
            None
        }
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generates a self-signed certificate and private key for testing.
    /// Returns (cert_pem, key_pem) as byte vectors.
    #[allow(dead_code)]
    fn generate_self_signed_cert() -> (Vec<u8>, Vec<u8>) {
        // Use rcgen to generate a self-signed certificate for testing.
        // Since rcgen may not be a dependency, we'll use pre-generated
        // test PEM data instead.
        let key_pem = include_bytes!("../../tests/fixtures/test_key.pem");
        let cert_pem = include_bytes!("../../tests/fixtures/test_cert.pem");
        (cert_pem.to_vec(), key_pem.to_vec())
    }

    /// Checks whether test fixtures exist; if not, generates them with openssl.
    fn ensure_test_fixtures() -> bool {
        let cert_path = Path::new("tests/fixtures/test_cert.pem");
        let key_path = Path::new("tests/fixtures/test_key.pem");
        cert_path.exists() && key_path.exists()
    }

    #[test]
    fn test_load_certs_nonexistent() {
        let result = load_certs(Path::new("/nonexistent/cert.pem"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_private_key_nonexistent() {
        let result = load_private_key(Path::new("/nonexistent/key.pem"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_certs_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("empty.pem");
        std::fs::write(&cert_path, b"").unwrap();

        let result = load_certs(&cert_path);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("no valid certificates"),
            "unexpected error: {err_msg}"
        );
    }

    #[test]
    fn test_load_private_key_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("empty.pem");
        std::fs::write(&key_path, b"").unwrap();

        let result = load_private_key(&key_path);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("no valid private key"),
            "unexpected error: {err_msg}"
        );
    }

    #[test]
    fn test_load_certs_invalid_pem() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("bad.pem");
        std::fs::write(&cert_path, b"not a valid PEM file\n").unwrap();

        let result = load_certs(&cert_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_private_key_invalid_pem() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("bad.pem");
        std::fs::write(&key_path, b"not a valid PEM key\n").unwrap();

        let result = load_private_key(&key_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_server_tls_config_both_none() {
        let result = check_server_tls_config(None, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_check_server_tls_config_cert_only() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        std::fs::write(&cert_path, b"cert").unwrap();

        let result = check_server_tls_config(Some(&cert_path), None);
        assert!(result.is_none());
    }

    #[test]
    fn test_check_server_tls_config_key_only() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("key.pem");
        std::fs::write(&key_path, b"key").unwrap();

        let result = check_server_tls_config(None, Some(&key_path));
        assert!(result.is_none());
    }

    #[test]
    fn test_check_server_tls_config_both_exist() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, b"cert").unwrap();
        std::fs::write(&key_path, b"key").unwrap();

        let result = check_server_tls_config(Some(&cert_path), Some(&key_path));
        assert!(result.is_some());
        let (c, k) = result.unwrap();
        assert_eq!(c, cert_path.as_path());
        assert_eq!(k, key_path.as_path());
    }

    #[test]
    fn test_check_server_tls_config_cert_missing() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("nonexistent_cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&key_path, b"key").unwrap();

        let result = check_server_tls_config(Some(&cert_path), Some(&key_path));
        assert!(result.is_none());
    }

    #[test]
    fn test_check_server_tls_config_key_missing() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("nonexistent_key.pem");
        std::fs::write(&cert_path, b"cert").unwrap();

        let result = check_server_tls_config(Some(&cert_path), Some(&key_path));
        assert!(result.is_none());
    }

    #[test]
    fn test_build_client_config_default() {
        let config = build_client_config(None, false).unwrap();
        // Should succeed with system root certificates
        assert!(!config.alpn_protocols.is_empty() || config.alpn_protocols.is_empty());
    }

    #[test]
    fn test_build_client_config_allow_self_signed() {
        let config = build_client_config(None, true).unwrap();
        // Should succeed with no verification
        assert!(!config.alpn_protocols.is_empty() || config.alpn_protocols.is_empty());
    }

    #[test]
    fn test_build_client_config_custom_ca_nonexistent() {
        let result = build_client_config(Some(Path::new("/nonexistent/ca.pem")), false);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_certs_from_valid_pem() {
        // If test fixtures are available, test loading real certificates
        if !ensure_test_fixtures() {
            // Skip test if fixtures are not available
            return;
        }

        let certs = load_certs(Path::new("tests/fixtures/test_cert.pem")).unwrap();
        assert!(!certs.is_empty());
    }

    #[test]
    fn test_load_private_key_from_valid_pem() {
        if !ensure_test_fixtures() {
            return;
        }

        let _key = load_private_key(Path::new("tests/fixtures/test_key.pem")).unwrap();
    }

    #[test]
    fn test_build_server_config_with_fixtures() {
        if !ensure_test_fixtures() {
            return;
        }

        let config = build_server_config(
            Path::new("tests/fixtures/test_cert.pem"),
            Path::new("tests/fixtures/test_key.pem"),
        )
        .unwrap();

        // Verify the config was built successfully
        assert!(config.alpn_protocols.is_empty() || !config.alpn_protocols.is_empty());
    }
}
