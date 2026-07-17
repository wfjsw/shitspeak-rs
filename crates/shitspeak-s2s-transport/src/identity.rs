//! Loads and caches the local node's identity material:
//!  * trust root (CA bundle) shared by every peer
//!  * own X.509 certificate chain
//!  * own private key
//!  * the local `NodeIdentifier` parsed out of the cert's numeric Subject CN.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use aws_lc_rs::signature;
use rustls::RootCertStore;
use rustls::SignatureScheme;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::types::NodeIdentifier;

use super::error::ConfigError;
use super::tls;

const ORIGIN_SIGNATURE_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ED25519,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA256,
];

/// Detached proof made with the node certificate key.
///
/// The certificate chain is intentionally included because a routed overlay
/// frame can arrive through a relay that has no direct TLS session with the
/// logical origin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginSignature {
    signature_scheme: u16,
    certificate_chain: Vec<Vec<u8>>,
    signature: Vec<u8>,
}

impl OriginSignature {
    pub fn signature_scheme(&self) -> u16 {
        self.signature_scheme
    }

    pub fn certificate_chain(&self) -> &[Vec<u8>] {
        &self.certificate_chain
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Largest detached-signature length this transport supports for the
    /// selected scheme. This is used to reserve wire space before a message
    /// is signed; ECDSA DER encodings vary by a few bytes between signatures.
    pub fn maximum_signature_len(&self) -> usize {
        match self.signature_scheme {
            // ASN.1 DER sequence maxima for P-256, P-384, and P-521.
            0x0403 => 72,
            0x0503 => 104,
            0x0603 => 141,
            0x0807 => 64,
            // RSA signatures have fixed modulus length. Keep the observed
            // length for the two RSA schemes we advertise.
            0x0401 | 0x0804 => self.signature.len(),
            _ => self.signature.len(),
        }
        .max(self.signature.len())
    }

    pub fn from_parts(
        signature_scheme: u16,
        certificate_chain: Vec<Vec<u8>>,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            signature_scheme,
            certificate_chain,
            signature,
        }
    }
}

#[derive(Debug, Error)]
pub enum OriginAuthenticationError {
    #[error("transport identity is unavailable")]
    IdentityUnavailable,
    #[error("origin certificate chain is empty")]
    CertificateChainEmpty,
    #[error("origin certificate chain validation failed: {0}")]
    CertificateChain(String),
    #[error("origin certificate identity validation failed: {0}")]
    CertificateIdentity(String),
    #[error("origin certificate node {actual} does not match claimed node {expected}")]
    NodeMismatch {
        expected: NodeIdentifier,
        actual: NodeIdentifier,
    },
    #[error("origin certificate parse failed: {0}")]
    CertificateParse(String),
    #[error("origin signature scheme is unsupported")]
    UnsupportedSignatureScheme,
    #[error("origin signature is invalid")]
    InvalidSignature,
    #[error("origin signature operation failed: {0}")]
    Signing(String),
}

/// Loaded once at manager start; cloned cheaply through the rest of the system.
#[derive(Clone)]
pub struct NodeIdentity {
    node_id: NodeIdentifier,
    roots: Arc<RootCertStore>,
    chain: Vec<CertificateDer<'static>>,
    key: Arc<PrivateKeyDer<'static>>,
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("node_id", &self.node_id)
            .field("chain_len", &self.chain.len())
            .finish()
    }
}

impl NodeIdentity {
    pub fn load(ca_path: &Path, cert_path: &Path, key_path: &Path) -> Result<Self, ConfigError> {
        let roots = load_roots(ca_path)?;
        let chain = load_certs(cert_path)?;
        let key = load_private_key(key_path)?;
        let node_id = node_id_from_cert(&chain[0], cert_path)?;

        Ok(Self {
            node_id,
            roots: Arc::new(roots),
            chain,
            key: Arc::new(key),
        })
    }

    pub fn node_id(&self) -> NodeIdentifier {
        self.node_id
    }

    pub fn roots(&self) -> &Arc<RootCertStore> {
        &self.roots
    }

    pub fn chain(&self) -> &[CertificateDer<'static>] {
        &self.chain
    }

    pub fn key(&self) -> &PrivateKeyDer<'static> {
        &self.key
    }

    pub(crate) fn sign_origin_payload(
        &self,
        payload: &[u8],
    ) -> Result<OriginSignature, OriginAuthenticationError> {
        let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(self.key())
            .map_err(|error| OriginAuthenticationError::Signing(error.to_string()))?;
        let signer = signing_key
            .choose_scheme(ORIGIN_SIGNATURE_SCHEMES)
            .ok_or(OriginAuthenticationError::UnsupportedSignatureScheme)?;
        let signature_scheme = signature_scheme_code(signer.scheme())?;
        let signature = signer
            .sign(payload)
            .map_err(|error| OriginAuthenticationError::Signing(error.to_string()))?;
        Ok(OriginSignature::from_parts(
            signature_scheme,
            self.chain
                .iter()
                .map(|cert| cert.as_ref().to_vec())
                .collect(),
            signature,
        ))
    }

    pub(crate) fn verify_origin_payload(
        &self,
        expected_node: NodeIdentifier,
        proof: &OriginSignature,
        payload: &[u8],
    ) -> Result<(), OriginAuthenticationError> {
        if proof.certificate_chain.is_empty() {
            return Err(OriginAuthenticationError::CertificateChainEmpty);
        }
        let chain: Vec<CertificateDer<'static>> = proof
            .certificate_chain
            .iter()
            .cloned()
            .map(CertificateDer::from)
            .collect();
        tls::verify_peer_cert_chain(self.roots.clone(), &chain)
            .map_err(|error| OriginAuthenticationError::CertificateChain(error.to_string()))?;
        let actual_node = parse_peer_cn(&chain)
            .map_err(|error| OriginAuthenticationError::CertificateIdentity(error.to_string()))?;
        if actual_node != expected_node {
            return Err(OriginAuthenticationError::NodeMismatch {
                expected: expected_node,
                actual: actual_node,
            });
        }
        let leaf = chain
            .first()
            .ok_or(OriginAuthenticationError::CertificateChainEmpty)?;
        let (_, certificate) = X509Certificate::from_der(leaf.as_ref())
            .map_err(|error| OriginAuthenticationError::CertificateParse(error.to_string()))?;
        let algorithm = signature_verification_algorithm(proof.signature_scheme)?;
        let public_key = &certificate
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data;
        signature::UnparsedPublicKey::new(algorithm, public_key)
            .verify(payload, &proof.signature)
            .map_err(|_| OriginAuthenticationError::InvalidSignature)
    }
}

fn signature_scheme_code(scheme: SignatureScheme) -> Result<u16, OriginAuthenticationError> {
    match scheme {
        SignatureScheme::RSA_PKCS1_SHA256 => Ok(0x0401),
        SignatureScheme::ECDSA_NISTP256_SHA256 => Ok(0x0403),
        SignatureScheme::ECDSA_NISTP384_SHA384 => Ok(0x0503),
        SignatureScheme::ECDSA_NISTP521_SHA512 => Ok(0x0603),
        SignatureScheme::RSA_PSS_SHA256 => Ok(0x0804),
        SignatureScheme::ED25519 => Ok(0x0807),
        _ => Err(OriginAuthenticationError::UnsupportedSignatureScheme),
    }
}

fn signature_verification_algorithm(
    scheme: u16,
) -> Result<&'static dyn signature::VerificationAlgorithm, OriginAuthenticationError> {
    match scheme {
        0x0401 => Ok(&signature::RSA_PKCS1_2048_8192_SHA256),
        0x0403 => Ok(&signature::ECDSA_P256_SHA256_ASN1),
        0x0503 => Ok(&signature::ECDSA_P384_SHA384_ASN1),
        0x0603 => Ok(&signature::ECDSA_P521_SHA512_ASN1),
        0x0804 => Ok(&signature::RSA_PSS_2048_8192_SHA256),
        0x0807 => Ok(&signature::ED25519),
        _ => Err(OriginAuthenticationError::UnsupportedSignatureScheme),
    }
}

pub fn node_id_from_cert_file(path: &Path) -> Result<NodeIdentifier, ConfigError> {
    let chain = load_certs(path)?;
    node_id_from_cert(&chain[0], path)
}

fn load_roots(path: &Path) -> Result<RootCertStore, ConfigError> {
    let mut reader = BufReader::new(File::open(path).map_err(|e| ConfigError::CaRead {
        path: path.display().to_string(),
        source: e,
    })?);

    let mut roots = RootCertStore::empty();
    let mut count = 0usize;
    for cert in rustls_pemfile::certs(&mut reader) {
        let cert = cert.map_err(|e| ConfigError::CaRead {
            path: path.display().to_string(),
            source: e,
        })?;
        roots.add(cert)?;
        count += 1;
    }
    if count == 0 {
        return Err(ConfigError::CaEmpty {
            path: path.display().to_string(),
        });
    }
    Ok(roots)
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, ConfigError> {
    let mut reader = BufReader::new(File::open(path).map_err(|e| ConfigError::CertRead {
        path: path.display().to_string(),
        source: e,
    })?);

    let mut chain = Vec::new();
    for cert in rustls_pemfile::certs(&mut reader) {
        let cert = cert.map_err(|e| ConfigError::CertRead {
            path: path.display().to_string(),
            source: e,
        })?;
        chain.push(cert);
    }
    if chain.is_empty() {
        return Err(ConfigError::CertEmpty {
            path: path.display().to_string(),
        });
    }
    Ok(chain)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, ConfigError> {
    let mut reader = BufReader::new(File::open(path).map_err(|e| ConfigError::KeyRead {
        path: path.display().to_string(),
        source: e,
    })?);

    if let Some(key) =
        rustls_pemfile::private_key(&mut reader).map_err(|e| ConfigError::KeyRead {
            path: path.display().to_string(),
            source: e,
        })?
    {
        return Ok(key);
    }

    Err(ConfigError::KeyEmpty {
        path: path.display().to_string(),
    })
}

/// Extracts the Subject Common Name from a DER-encoded cert and parses it as a
/// decimal `u16` `NodeIdentifier`.
pub fn node_id_from_cert(
    cert_der: &CertificateDer<'_>,
    cert_path_for_diag: &Path,
) -> Result<NodeIdentifier, ConfigError> {
    let (_, parsed) = X509Certificate::from_der(cert_der.as_ref())
        .map_err(|e| ConfigError::X509(format!("{e}")))?;

    let cn = parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .ok_or_else(|| ConfigError::CnMissing {
            path: cert_path_for_diag.display().to_string(),
        })?
        .trim()
        .to_owned();

    cn.parse::<NodeIdentifier>()
        .map_err(|_| ConfigError::CnNotNumeric { cn })
}

/// Extract the peer's `NodeIdentifier` from the first cert in the peer's
/// certificate chain (post TLS handshake). Used by both client and server
/// after `peer_certificates()` is available.
pub fn parse_peer_cn(chain: &[CertificateDer<'_>]) -> Result<NodeIdentifier, ConfigError> {
    let first = chain.first().ok_or(ConfigError::CertEmpty {
        path: "<peer-chain>".to_string(),
    })?;
    node_id_from_cert(first, Path::new("<peer-chain>"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
    use std::io::Write;
    use tempfile::TempDir;

    /// Mints a self-signed CA + a node cert with CN=`node_cn`, all written to
    /// PEM files inside `dir`. Returns (ca.pem, cert.pem, key.pem).
    fn mint_identity(
        dir: &TempDir,
        node_cn: &str,
    ) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(vec!["s2s-test-ca".to_string()]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "s2s-test-ca");
        ca_params.distinguished_name = dn;
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let node_key = KeyPair::generate().unwrap();
        let mut node_params = CertificateParams::new(vec![format!("node-{node_cn}")]).unwrap();
        let mut node_dn = DistinguishedName::new();
        node_dn.push(DnType::CommonName, node_cn);
        node_params.distinguished_name = node_dn;
        let node_cert = node_params.signed_by(&node_key, &ca_cert, &ca_key).unwrap();

        let ca_path = dir.path().join("ca.pem");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        let mut ca_f = File::create(&ca_path).unwrap();
        ca_f.write_all(ca_cert.pem().as_bytes()).unwrap();
        let mut cert_f = File::create(&cert_path).unwrap();
        cert_f.write_all(node_cert.pem().as_bytes()).unwrap();
        let mut key_f = File::create(&key_path).unwrap();
        key_f
            .write_all(node_key.serialize_pem().as_bytes())
            .unwrap();

        (ca_path, cert_path, key_path)
    }

    #[test]
    fn loads_and_parses_cn() {
        let dir = TempDir::new().unwrap();
        let (ca, cert, key) = mint_identity(&dir, "42");
        let id = NodeIdentity::load(&ca, &cert, &key).unwrap();
        assert_eq!(id.node_id, 42);
        assert!(!id.chain.is_empty());
    }

    #[test]
    fn rejects_non_numeric_cn() {
        let dir = TempDir::new().unwrap();
        let (ca, cert, key) = mint_identity(&dir, "alpha");
        let err = NodeIdentity::load(&ca, &cert, &key).unwrap_err();
        match err {
            ConfigError::CnNotNumeric { cn } => assert_eq!(cn, "alpha"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn detached_origin_proof_binds_node_and_payload() {
        let dir = TempDir::new().unwrap();
        let (ca, cert, key) = mint_identity(&dir, "42");
        let identity = NodeIdentity::load(&ca, &cert, &key).unwrap();
        let payload = b"strict-origin-proof";
        let proof = identity.sign_origin_payload(payload).unwrap();

        identity.verify_origin_payload(42, &proof, payload).unwrap();
        assert!(matches!(
            identity.verify_origin_payload(7, &proof, payload),
            Err(OriginAuthenticationError::NodeMismatch { .. })
        ));
        assert!(matches!(
            identity.verify_origin_payload(42, &proof, b"modified"),
            Err(OriginAuthenticationError::InvalidSignature)
        ));
    }
}
