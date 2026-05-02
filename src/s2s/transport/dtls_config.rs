//! Bridge between our shared `NodeIdentity` (loaded from PEM) and the config
//! types `webrtc-dtls` expects, so the DTLS UDP path uses exactly the same CA
//! trust root, certificate, and private key as the stream transports.

use std::time::Duration;

use rustls::RootCertStore;
use webrtc_dtls::config::{ClientAuthType, Config as DtlsConfig, ExtendedMasterSecretType};
use webrtc_dtls::crypto::{Certificate as DtlsCertificate, CryptoPrivateKey};

use super::error::ConfigError;
use super::identity::NodeIdentity;

/// Build a `webrtc-dtls` `Certificate` from our loaded identity. The cert
/// chain is reused as-is and the private key is converted via `rcgen::KeyPair`,
/// which webrtc-dtls accepts directly.
pub(crate) fn make_dtls_certificate(identity: &NodeIdentity) -> Result<DtlsCertificate, ConfigError> {
    let key_pair = rcgen::KeyPair::try_from(identity.key())
        .map_err(|e| ConfigError::X509(format!("rcgen keypair: {e}")))?;
    let private_key = CryptoPrivateKey::from_key_pair(&key_pair)
        .map_err(|e| ConfigError::X509(format!("dtls private key: {e}")))?;
    Ok(DtlsCertificate {
        certificate: identity.chain().to_vec(),
        private_key,
    })
}

/// Server-side DTLS Config: requires client cert, validates against our CA.
pub(crate) fn build_server_dtls_config(
    identity: &NodeIdentity,
    udp_mtu: usize,
) -> Result<DtlsConfig, ConfigError> {
    let cert = make_dtls_certificate(identity)?;
    let mut cfg = DtlsConfig {
        certificates: vec![cert],
        client_auth: ClientAuthType::RequireAndVerifyClientCert,
        client_cas: clone_root_store(identity.roots().as_ref()),
        roots_cas: clone_root_store(identity.roots().as_ref()),
        extended_master_secret: ExtendedMasterSecretType::Require,
        flight_interval: Duration::from_millis(200),
        mtu: udp_mtu,
        ..Default::default()
    };
    // Server side does not present a server_name; client sends SNI.
    cfg.server_name.clear();
    Ok(cfg)
}

/// Client-side DTLS Config: trusts our CA, presents our cert.
pub(crate) fn build_client_dtls_config(
    identity: &NodeIdentity,
    server_name: String,
    udp_mtu: usize,
) -> Result<DtlsConfig, ConfigError> {
    let cert = make_dtls_certificate(identity)?;
    let cfg = DtlsConfig {
        certificates: vec![cert],
        client_auth: ClientAuthType::NoClientCert, // not relevant for client side
        client_cas: clone_root_store(identity.roots().as_ref()),
        roots_cas: clone_root_store(identity.roots().as_ref()),
        extended_master_secret: ExtendedMasterSecretType::Require,
        flight_interval: Duration::from_millis(200),
        mtu: udp_mtu,
        server_name,
        ..Default::default()
    };
    Ok(cfg)
}

fn clone_root_store(roots: &RootCertStore) -> RootCertStore {
    let mut out = RootCertStore::empty();
    for ta in roots.roots.iter() {
        out.roots.push(ta.clone());
    }
    out
}

/// Extract the peer's `NodeIdentifier` from a `DTLSConn`'s post-handshake
/// state. The cert chain is `Vec<Vec<u8>>` of DER-encoded X.509 certs;
/// we parse the leaf and read its CN.
pub(crate) async fn peer_node_id_from_dtls(
    conn: &webrtc_dtls::conn::DTLSConn,
) -> Result<crate::types::NodeIdentifier, ConfigError> {
    let state = conn.connection_state().await;
    let chain_der: Vec<rustls_pki_types::CertificateDer<'static>> = state
        .peer_certificates
        .into_iter()
        .map(rustls_pki_types::CertificateDer::from)
        .collect();
    super::identity::parse_peer_cn(&chain_der)
}
