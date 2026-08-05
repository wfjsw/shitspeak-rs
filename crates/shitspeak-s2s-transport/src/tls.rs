//! Peer-symmetric mTLS configs.
//!
//! Both ends of every stream connection authenticate via certificates rooted
//! in a shared CA. Identity is taken from the certificate's Subject Common
//! Name (parsed as a `u16` `NodeIdentifier`) — the connection's directionality
//! at the TCP layer carries no semantic weight above this module.
//!
//! We deliberately bypass DNS hostname verification on the client side because
//! peers are referenced by `(SocketAddr, NodeIdentifier)` and do not have
//! stable DNS names. CA chain validation is fully enforced.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

use super::error::ConfigError;
use super::identity::NodeIdentity;

fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// Build the mTLS pair (server, client) used by all stream transports.
pub fn build_tls_configs(
    identity: &NodeIdentity,
) -> Result<(Arc<ServerConfig>, Arc<ClientConfig>), ConfigError> {
    let server = build_server(identity)?;
    let client = build_client(identity)?;
    Ok((Arc::new(server), Arc::new(client)))
}

pub(crate) fn verify_peer_cert_chain(
    roots: Arc<RootCertStore>,
    chain: &[CertificateDer<'static>],
) -> Result<(), rustls::Error> {
    let Some((end_entity, intermediates)) = chain.split_first() else {
        return Err(rustls::Error::General(
            "peer certificate chain was empty".into(),
        ));
    };
    let verifier = CaPinnedVerifier::new(roots);
    let server_name = ServerName::try_from("invalid.s2s.local").expect("static name parses");
    verifier
        .verify_server_cert(
            end_entity,
            intermediates,
            &server_name,
            &[],
            UnixTime::now(),
        )
        .map(|_| ())
}

fn build_server(identity: &NodeIdentity) -> Result<ServerConfig, ConfigError> {
    let verifier =
        WebPkiClientVerifier::builder_with_provider(identity.roots().clone(), crypto_provider())
            .build()
            .map_err(|e| ConfigError::X509(format!("client verifier: {e}")))?;

    let key = clone_key(identity.key());
    let chain = identity.chain().to_vec();

    let cfg = ServerConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)?;
    Ok(cfg)
}

fn build_client(identity: &NodeIdentity) -> Result<ClientConfig, ConfigError> {
    let verifier = Arc::new(CaPinnedVerifier::new(identity.roots().clone()));
    let key = clone_key(identity.key());
    let chain = identity.chain().to_vec();

    let cfg = ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(chain, key)?;
    Ok(cfg)
}

/// `PrivateKeyDer` is not `Clone` directly. Clone via reference into the right
/// arm — works because the loaded keys are always one of the three flavors
/// returned by `rustls_pemfile::private_key`.
fn clone_key(
    k: &rustls_pki_types::PrivateKeyDer<'static>,
) -> rustls_pki_types::PrivateKeyDer<'static> {
    use rustls_pki_types::PrivateKeyDer;
    match k {
        PrivateKeyDer::Pkcs1(d) => PrivateKeyDer::Pkcs1(d.clone_key()),
        PrivateKeyDer::Pkcs8(d) => PrivateKeyDer::Pkcs8(d.clone_key()),
        PrivateKeyDer::Sec1(d) => PrivateKeyDer::Sec1(d.clone_key()),
        _ => unreachable!("unexpected PrivateKeyDer variant"),
    }
}

/// Verifies the peer's cert chain against the shared CA via `rustls`'s
/// built-in webpki backend, but skips SNI hostname matching. Identity is
/// asserted at the application layer by reading the peer's CN.
#[derive(Debug)]
struct CaPinnedVerifier {
    inner: Arc<dyn ServerCertVerifier>,
}

impl CaPinnedVerifier {
    fn new(roots: Arc<RootCertStore>) -> Self {
        let inner =
            rustls::client::WebPkiServerVerifier::builder_with_provider(roots, crypto_provider())
                .build()
                .expect("server verifier builder");
        Self { inner }
    }
}

impl ServerCertVerifier for CaPinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Use a placeholder server name that webpki will accept syntactically;
        // we cannot bypass SNI in the inner verifier, but we *can* point it at
        // a name we know exists in the cert by way of the SAN list.
        //
        // Because rcgen-issued certs always include a SAN, the simplest robust
        // approach is to extract the *first* DNS SAN from the end-entity cert
        // and feed it to the inner verifier. If no SAN exists, fall back to a
        // dummy name and rely on the inner verifier's chain-of-trust check
        // (it will fail name verification, so we manually re-validate the
        // chain instead).
        let server_name = first_dns_san(end_entity).unwrap_or_else(|| {
            ServerName::try_from("invalid.s2s.local").expect("static name parses")
        });

        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            &server_name,
            ocsp_response,
            now,
        ) {
            Ok(v) => Ok(v),
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName))
            | Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForNameContext { .. },
            )) => {
                // Chain validated, but the SAN didn't match the dummy name —
                // accept anyway; identity is asserted via CN at the app layer.
                Ok(ServerCertVerified::assertion())
            }
            Err(e) => Err(e),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn first_dns_san(cert: &CertificateDer<'_>) -> Option<ServerName<'static>> {
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    use x509_parser::prelude::{FromDer, X509Certificate};

    let (_, parsed) = X509Certificate::from_der(cert.as_ref()).ok()?;
    for ext in parsed.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                if let GeneralName::DNSName(s) = name {
                    if let Ok(parsed) = ServerName::try_from(s.to_string()) {
                        return Some(parsed);
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::super::identity::NodeIdentity;
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    fn mint(dir: &TempDir, cn: &str) -> NodeIdentity {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(vec!["s2s-test-ca".to_string()]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "s2s-test-ca");
        ca_params.distinguished_name = dn;
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let node_key = KeyPair::generate().unwrap();
        let mut node_params = CertificateParams::new(vec![format!("node-{cn}")]).unwrap();
        let mut node_dn = DistinguishedName::new();
        node_dn.push(DnType::CommonName, cn);
        node_params.distinguished_name = node_dn;
        let node_cert = node_params.signed_by(&node_key, &ca_cert, &ca_key).unwrap();

        let ca_path = dir.path().join(format!("ca-{cn}.pem"));
        let cert_path = dir.path().join(format!("cert-{cn}.pem"));
        let key_path = dir.path().join(format!("key-{cn}.pem"));
        File::create(&ca_path)
            .unwrap()
            .write_all(ca_cert.pem().as_bytes())
            .unwrap();
        File::create(&cert_path)
            .unwrap()
            .write_all(node_cert.pem().as_bytes())
            .unwrap();
        File::create(&key_path)
            .unwrap()
            .write_all(node_key.serialize_pem().as_bytes())
            .unwrap();

        NodeIdentity::load(&ca_path, &cert_path, &key_path).unwrap()
    }

    #[test]
    fn build_configs_succeeds_without_process_default_crypto_provider() {
        let dir = TempDir::new().unwrap();
        let id = mint(&dir, "10");
        let (_server, _client) = build_tls_configs(&id).unwrap();
    }

    #[test]
    fn peer_chain_must_be_signed_by_configured_s2s_ca() {
        let trusted_dir = TempDir::new().unwrap();
        let untrusted_dir = TempDir::new().unwrap();
        let trusted = mint(&trusted_dir, "10");
        let untrusted_peer = mint(&untrusted_dir, "11");

        assert!(
            verify_peer_cert_chain(trusted.roots().clone(), untrusted_peer.chain()).is_err(),
            "S2S peer certificates must chain to the configured s2s.ca_path only"
        );
    }
}
