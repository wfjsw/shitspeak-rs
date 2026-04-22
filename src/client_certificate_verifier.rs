use rustls::{DigitallySignedStruct, DistinguishedName, Error, SignatureScheme, client::danger::HandshakeSignatureValid, pki_types::{CertificateDer, UnixTime}, server::danger::{ClientCertVerified, ClientCertVerifier}};

#[derive(Debug)]
pub struct ClientCertificateVerifier;

impl ClientCertificateVerifier {
    pub fn new() -> Self {
        ClientCertificateVerifier
    }
}

impl ClientCertVerifier for ClientCertificateVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        Ok(ClientCertVerified::assertion())
    }
    
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
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
