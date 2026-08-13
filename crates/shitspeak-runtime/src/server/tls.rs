use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
use rustls::version::{TLS12, TLS13};
use tokio_rustls::TlsAcceptor;

use crate::client_certificate_verifier::ClientCertificateVerifier;
use shitspeak_runtime_config::Config;

use super::extensions::{ALPN_MUMBLE, ServerExtensions};

fn startup_file_error(
    config_key: &str,
    path: &str,
    action: &str,
    source: impl std::fmt::Display,
) -> Box<dyn std::error::Error> {
    std::io::Error::other(format!(
        "{action} failed for {config_key}={path:?}: {source}"
    ))
    .into()
}

pub(super) fn c2s_pfs_tls_provider() -> CryptoProvider {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites.retain(c2s_cipher_suite_provides_pfs);
    provider
}

pub(super) fn c2s_cipher_suite_provides_pfs(suite: &rustls::SupportedCipherSuite) -> bool {
    matches!(
        suite.suite(),
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
            | rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
            | rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
            | rustls::CipherSuite::TLS13_AES_128_CCM_SHA256
            | rustls::CipherSuite::TLS13_AES_128_CCM_8_SHA256
            | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    )
}

pub(super) fn load_c2s_tls_config(
    config: &Config,
    extensions: &ServerExtensions,
    bans: Arc<shitspeak_state::BanRepository>,
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error>> {
    let certificate = CertificateDer::pem_file_iter(&config.cert_path)
        .map_err(|e| startup_file_error("cert_path", &config.cert_path, "read TLS certificate", e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            startup_file_error("cert_path", &config.cert_path, "parse TLS certificate", e)
        })?;
    let private_key = PrivateKeyDer::from_pem_file(&config.key_path)
        .map_err(|e| startup_file_error("key_path", &config.key_path, "read TLS private key", e))?;

    let client_cert_verifier = Arc::new(ClientCertificateVerifier::new(bans));

    let mut tls_config =
        rustls::ServerConfig::builder_with_provider(Arc::new(c2s_pfs_tls_provider()))
            .with_protocol_versions(&[&TLS13, &TLS12])?
            .with_client_cert_verifier(client_cert_verifier)
            .with_single_cert(certificate, private_key)?;
    tls_config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    tls_config.send_tls13_tickets = 0;
    tls_config
        .alpn_protocols
        .extend(extensions.c2s_alpn_protocols());
    tls_config.alpn_protocols.push(ALPN_MUMBLE.to_vec());

    Ok(tls_config)
}

pub(super) fn load_c2s_tls_acceptor(
    config: &Config,
    extensions: &ServerExtensions,
    bans: Arc<shitspeak_state::BanRepository>,
) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    let tls_config = load_c2s_tls_config(config, extensions, bans)?;
    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}

pub(super) fn validate_privacy_config(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    if config.privacy.protect_certificate_hashes()
        && config
            .privacy
            .certificate_hash_secret()
            .map(str::trim)
            .filter(|secret| !secret.is_empty())
            .is_none()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "privacy.protect_certificate_hashes requires privacy.certificate_hash_secret when set to true, \"irreversible\", or \"reversible\"",
        )
        .into());
    }
    Ok(())
}
