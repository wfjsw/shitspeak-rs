use std::sync::Arc;

use rustls::{
    DigitallySignedStruct, DistinguishedName, Error, SignatureScheme,
    client::danger::HandshakeSignatureValid,
    pki_types::{CertificateDer, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use shitspeak_state::BanRepository;

pub struct ClientCertificateVerifier {
    bans: Arc<BanRepository>,
}

impl std::fmt::Debug for ClientCertificateVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientCertificateVerifier")
            .finish_non_exhaustive()
    }
}

impl ClientCertificateVerifier {
    pub fn new(bans: Arc<BanRepository>) -> Self {
        Self { bans }
    }
}

impl ClientCertVerifier for ClientCertificateVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        let certificate_hash = hex::encode(
            aws_lc_rs::digest::digest(
                &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
                end_entity.as_ref(),
            )
            .as_ref(),
        );
        if self.bans.is_identity_banned(Some(&certificate_hash), None) {
            return Err(Error::General("client certificate is banned".to_owned()));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }

    // Provided methods
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn requires_raw_public_keys(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use super::*;
    use rustls::RootCertStore;
    use rustls::pki_types::{PrivateKeyDer, ServerName, pem::PemObject as _};
    use shitspeak_state::BanEntry;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    #[tokio::test]
    async fn banned_certificate_is_rejected_during_tls_client_verification() {
        let repository = BanRepository::new_in_memory(1);
        let certificate = rcgen::generate_simple_self_signed(vec!["test-client".to_owned()])
            .expect("generate client certificate");
        let certificate_der = CertificateDer::from(certificate.cert.der().to_vec());
        let certificate_hash = hex::encode(
            aws_lc_rs::digest::digest(
                &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
                certificate_der.as_ref(),
            )
            .as_ref(),
        );
        repository
            .add_ban(BanEntry {
                address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                mask: 0,
                name: None,
                hash: Some(certificate_hash),
                ban_certificate: true,
                ban_ip: false,
                reason: None,
                start: 0,
                duration: 0,
            })
            .await
            .expect("add certificate ban");

        let verifier = ClientCertificateVerifier::new(repository);
        assert!(
            verifier
                .verify_client_cert(
                    &certificate_der,
                    &[],
                    UnixTime::since_unix_epoch(Duration::ZERO),
                )
                .is_err()
        );
    }

    #[tokio::test]
    async fn banned_certificate_fails_tls_establishment() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let repository = BanRepository::new_in_memory(1);
        let client_certificate = rcgen::generate_simple_self_signed(vec!["test-client".to_owned()])
            .expect("generate client certificate");
        let client_certificate_der = CertificateDer::from(client_certificate.cert.der().to_vec());
        let client_certificate_hash = hex::encode(
            aws_lc_rs::digest::digest(
                &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
                client_certificate_der.as_ref(),
            )
            .as_ref(),
        );
        repository
            .add_ban(BanEntry {
                address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                mask: 0,
                name: None,
                hash: Some(client_certificate_hash),
                ban_certificate: true,
                ban_ip: false,
                reason: None,
                start: 0,
                duration: 0,
            })
            .await
            .expect("add certificate ban");

        let server_certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate server certificate");
        let server_certificate_der = CertificateDer::from(server_certificate.cert.der().to_vec());
        let server_key =
            PrivateKeyDer::from_pem_slice(server_certificate.key_pair.serialize_pem().as_bytes())
                .expect("parse server key");
        let server_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(Arc::new(ClientCertificateVerifier::new(repository)))
            .with_single_cert(vec![server_certificate_der.clone()], server_key)
            .expect("build server TLS config");

        let mut roots = RootCertStore::empty();
        roots
            .add(server_certificate_der)
            .expect("trust server certificate");
        let client_key =
            PrivateKeyDer::from_pem_slice(client_certificate.key_pair.serialize_pem().as_bytes())
                .expect("parse client key");
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![client_certificate_der], client_key)
            .expect("build client TLS config");

        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let connector = TlsConnector::from(Arc::new(client_config));
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (server_result, _client_result) = tokio::join!(
            acceptor.accept(server_io),
            connector.connect(
                ServerName::try_from("localhost").expect("server name"),
                client_io,
            ),
        );

        assert!(server_result.is_err(), "server must reject the certificate");
    }
}
