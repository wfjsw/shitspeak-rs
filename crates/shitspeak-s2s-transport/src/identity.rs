//! Loads and caches the local node's identity material:
//!  * trust root (CA bundle) shared by every peer
//!  * own X.509 certificate chain
//!  * own private key
//!  * the local `NodeIdentifier` parsed out of the cert's numeric Subject CN.

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::{digest, signature};
use parking_lot::{Mutex, RwLock};
use rustls::RootCertStore;
use rustls::SignatureScheme;
use rustls::sign::SigningKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

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

const ORIGIN_CERTIFICATE_CACHE_CAPACITY: usize = 256;
const ORIGIN_CERTIFICATE_VALIDATION_LOCK_STRIPES: usize = 64;

type LeafCertificateFingerprint = [u8; digest::SHA256_OUTPUT_LEN];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginSignatureMetadata {
    signature_scheme: u16,
    certificate_chain: Arc<[Vec<u8>]>,
    maximum_signature_len: usize,
}

impl OriginSignatureMetadata {
    pub fn signature_scheme(&self) -> u16 {
        self.signature_scheme
    }

    pub fn certificate_chain(&self) -> &[Vec<u8>] {
        &self.certificate_chain
    }

    pub fn maximum_signature_len(&self) -> usize {
        self.maximum_signature_len
    }
}

#[derive(Clone)]
struct ValidatedOriginCertificate {
    node_id: NodeIdentifier,
    public_key: Arc<[u8]>,
    leaf_not_before_unix: i64,
    leaf_not_after_unix: i64,
    revalidate_after_unix: i64,
}

impl ValidatedOriginCertificate {
    fn leaf_is_valid_at(&self, now_unix: i64) -> bool {
        now_unix >= self.leaf_not_before_unix && now_unix <= self.leaf_not_after_unix
    }
}

#[derive(Default)]
struct OriginCertificateCache {
    entries: HashMap<LeafCertificateFingerprint, ValidatedOriginCertificate>,
    insertion_order: VecDeque<LeafCertificateFingerprint>,
}

enum OriginCertificateCacheLookup {
    Valid(ValidatedOriginCertificate),
    KnownOutsideValidity,
    Absent,
}

impl OriginCertificateCache {
    fn lookup(
        &self,
        fingerprint: &LeafCertificateFingerprint,
        now_unix: i64,
    ) -> OriginCertificateCacheLookup {
        let Some(entry) = self.entries.get(fingerprint) else {
            return OriginCertificateCacheLookup::Absent;
        };
        if !entry.leaf_is_valid_at(now_unix) {
            OriginCertificateCacheLookup::KnownOutsideValidity
        } else if now_unix > entry.revalidate_after_unix {
            OriginCertificateCacheLookup::Absent
        } else {
            OriginCertificateCacheLookup::Valid(entry.clone())
        }
    }

    fn insert(
        &mut self,
        fingerprint: LeafCertificateFingerprint,
        certificate: ValidatedOriginCertificate,
    ) {
        if self.entries.contains_key(&fingerprint) {
            self.entries.insert(fingerprint, certificate);
            return;
        }
        while self.entries.len() >= ORIGIN_CERTIFICATE_CACHE_CAPACITY {
            if let Some(oldest) = self.insertion_order.pop_front() {
                self.entries.remove(&oldest);
            } else {
                break;
            }
        }
        self.insertion_order.push_back(fingerprint);
        self.entries.insert(fingerprint, certificate);
    }
}

/// Detached proof made with the node certificate key.
///
/// The certificate chain is intentionally included because a routed overlay
/// frame can arrive through a relay that has no direct TLS session with the
/// logical origin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginSignature {
    signature_scheme: u16,
    certificate_chain: Arc<[Vec<u8>]>,
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
        Self::from_shared_parts(signature_scheme, certificate_chain.into(), signature)
    }

    fn from_shared_parts(
        signature_scheme: u16,
        certificate_chain: Arc<[Vec<u8>]>,
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
    signing_key: Arc<dyn SigningKey>,
    origin_signature_metadata: OriginSignatureMetadata,
    origin_certificate_cache: Arc<RwLock<OriginCertificateCache>>,
    origin_certificate_validation_locks:
        Arc<[Mutex<()>; ORIGIN_CERTIFICATE_VALIDATION_LOCK_STRIPES]>,
    #[cfg(test)]
    signing_key_parse_count: Arc<AtomicUsize>,
    #[cfg(test)]
    certificate_validation_count: Arc<AtomicUsize>,
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
        #[cfg(test)]
        let signing_key_parse_count = Arc::new(AtomicUsize::new(0));
        let signing_key = parse_signing_key(
            &key,
            #[cfg(test)]
            &signing_key_parse_count,
        )?;
        let signer = signing_key
            .choose_scheme(ORIGIN_SIGNATURE_SCHEMES)
            .ok_or_else(|| rustls::Error::General("unsupported origin signing key".to_string()))?;
        let signature_scheme = signature_scheme_code(signer.scheme())
            .map_err(|error| rustls::Error::General(error.to_string()))?;
        let certificate_chain = chain
            .iter()
            .map(|cert| cert.as_ref().to_vec())
            .collect::<Vec<_>>()
            .into();
        let maximum_signature_len =
            maximum_signature_len_for_certificate(signature_scheme, &chain[0])
                .map_err(|error| rustls::Error::General(error.to_string()))?;

        Ok(Self {
            node_id,
            roots: Arc::new(roots),
            chain,
            key: Arc::new(key),
            signing_key,
            origin_signature_metadata: OriginSignatureMetadata {
                signature_scheme,
                certificate_chain,
                maximum_signature_len,
            },
            origin_certificate_cache: Arc::new(RwLock::new(OriginCertificateCache::default())),
            origin_certificate_validation_locks: Arc::new(std::array::from_fn(|_| Mutex::new(()))),
            #[cfg(test)]
            signing_key_parse_count,
            #[cfg(test)]
            certificate_validation_count: Arc::new(AtomicUsize::new(0)),
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

    pub(crate) fn origin_signature_metadata(&self) -> &OriginSignatureMetadata {
        &self.origin_signature_metadata
    }

    pub(crate) fn sign_origin_payload(
        &self,
        payload: &[u8],
    ) -> Result<OriginSignature, OriginAuthenticationError> {
        let signer = self
            .signing_key
            .choose_scheme(ORIGIN_SIGNATURE_SCHEMES)
            .ok_or(OriginAuthenticationError::UnsupportedSignatureScheme)?;
        let signature_scheme = signature_scheme_code(signer.scheme())?;
        let signature = signer
            .sign(payload)
            .map_err(|error| OriginAuthenticationError::Signing(error.to_string()))?;
        Ok(OriginSignature::from_shared_parts(
            signature_scheme,
            self.origin_signature_metadata.certificate_chain.clone(),
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
        let algorithm = signature_verification_algorithm(proof.signature_scheme)?;
        let fingerprint = leaf_certificate_fingerprint(&proof.certificate_chain[0]);
        let now_unix = current_unix_time();
        match self
            .origin_certificate_cache
            .read()
            .lookup(&fingerprint, now_unix)
        {
            OriginCertificateCacheLookup::Valid(certificate) => {
                return verify_with_validated_certificate(
                    expected_node,
                    &certificate,
                    algorithm,
                    payload,
                    &proof.signature,
                );
            }
            OriginCertificateCacheLookup::KnownOutsideValidity => {
                return Err(OriginAuthenticationError::CertificateChain(
                    "origin certificate chain is outside its validity interval".to_string(),
                ));
            }
            OriginCertificateCacheLookup::Absent => {}
        }

        // Serialize cold validation for the same fingerprint. The fixed-size
        // stripe set bounds memory even when an attacker supplies arbitrary
        // certificate chains. Recheck after locking because another verifier
        // may have populated the cache while this caller was waiting.
        let validation_lock_index = certificate_validation_lock_index(&fingerprint);
        let validation_guard =
            self.origin_certificate_validation_locks[validation_lock_index].lock();
        match self
            .origin_certificate_cache
            .read()
            .lookup(&fingerprint, current_unix_time())
        {
            OriginCertificateCacheLookup::Valid(certificate) => {
                // Chain validation is the only operation serialized by the
                // stripe. Signature checks are independent and can proceed
                // concurrently once the cache has been populated.
                drop(validation_guard);
                return verify_with_validated_certificate(
                    expected_node,
                    &certificate,
                    algorithm,
                    payload,
                    &proof.signature,
                );
            }
            OriginCertificateCacheLookup::KnownOutsideValidity => {
                return Err(OriginAuthenticationError::CertificateChain(
                    "origin certificate chain is outside its validity interval".to_string(),
                ));
            }
            OriginCertificateCacheLookup::Absent => {}
        }

        let chain: Vec<CertificateDer<'static>> = proof
            .certificate_chain
            .iter()
            .cloned()
            .map(CertificateDer::from)
            .collect();
        #[cfg(test)]
        self.certificate_validation_count
            .fetch_add(1, Ordering::Relaxed);
        tls::verify_peer_cert_chain(self.roots.clone(), &chain)
            .map_err(|error| OriginAuthenticationError::CertificateChain(error.to_string()))?;
        let actual_node = parse_peer_cn(&chain)
            .map_err(|error| OriginAuthenticationError::CertificateIdentity(error.to_string()))?;
        let validated_at = current_unix_time();
        let certificate = validated_origin_certificate(actual_node, &chain, validated_at)?;
        self.origin_certificate_cache
            .write()
            .insert(fingerprint, certificate.clone());
        drop(validation_guard);
        if !certificate.leaf_is_valid_at(validated_at) {
            return Err(OriginAuthenticationError::CertificateChain(
                "origin leaf certificate is outside its validity interval".to_string(),
            ));
        }
        verify_with_validated_certificate(
            expected_node,
            &certificate,
            algorithm,
            payload,
            &proof.signature,
        )
    }
}

fn parse_signing_key(
    key: &PrivateKeyDer<'_>,
    #[cfg(test)] parse_count: &AtomicUsize,
) -> Result<Arc<dyn SigningKey>, rustls::Error> {
    #[cfg(test)]
    parse_count.fetch_add(1, Ordering::Relaxed);
    rustls::crypto::aws_lc_rs::sign::any_supported_type(key)
}

fn maximum_signature_len_for_certificate(
    scheme: u16,
    leaf: &CertificateDer<'_>,
) -> Result<usize, OriginAuthenticationError> {
    match scheme {
        0x0403 => Ok(72),
        0x0503 => Ok(104),
        0x0603 => Ok(141),
        0x0807 => Ok(64),
        0x0401 | 0x0804 => {
            let (_, certificate) = X509Certificate::from_der(leaf.as_ref())
                .map_err(|error| OriginAuthenticationError::CertificateParse(error.to_string()))?;
            match certificate.tbs_certificate.subject_pki.parsed() {
                Ok(PublicKey::RSA(key)) => {
                    Ok(key.modulus.strip_prefix(&[0]).unwrap_or(key.modulus).len())
                }
                _ => Err(OriginAuthenticationError::CertificateParse(
                    "RSA signing key does not match certificate public key".to_string(),
                )),
            }
        }
        _ => Err(OriginAuthenticationError::UnsupportedSignatureScheme),
    }
}

fn leaf_certificate_fingerprint(certificate: &[u8]) -> LeafCertificateFingerprint {
    let digest = digest::digest(&digest::SHA256, certificate);
    let mut fingerprint = [0; digest::SHA256_OUTPUT_LEN];
    fingerprint.copy_from_slice(digest.as_ref());
    fingerprint
}

fn certificate_validation_lock_index(fingerprint: &LeafCertificateFingerprint) -> usize {
    let mut prefix = [0; 8];
    prefix.copy_from_slice(&fingerprint[..8]);
    (u64::from_be_bytes(prefix) as usize) % ORIGIN_CERTIFICATE_VALIDATION_LOCK_STRIPES
}

fn current_unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(-1)
}

fn validated_origin_certificate(
    node_id: NodeIdentifier,
    chain: &[CertificateDer<'_>],
    validated_at_unix: i64,
) -> Result<ValidatedOriginCertificate, OriginAuthenticationError> {
    let mut leaf_not_before_unix = None;
    let mut leaf_not_after_unix = None;
    let mut revalidate_after_unix = i64::MAX;
    let mut public_key = None;
    for (index, certificate_der) in chain.iter().enumerate() {
        let (_, certificate) = X509Certificate::from_der(certificate_der.as_ref())
            .map_err(|error| OriginAuthenticationError::CertificateParse(error.to_string()))?;
        let not_before_unix = certificate.validity().not_before.timestamp();
        let not_after_unix = certificate.validity().not_after.timestamp();
        if validated_at_unix >= not_before_unix && validated_at_unix <= not_after_unix {
            revalidate_after_unix = revalidate_after_unix.min(not_after_unix);
        }
        if index == 0 {
            leaf_not_before_unix = Some(not_before_unix);
            leaf_not_after_unix = Some(not_after_unix);
            public_key = Some(Arc::<[u8]>::from(
                certificate
                    .tbs_certificate
                    .subject_pki
                    .subject_public_key
                    .data
                    .as_ref(),
            ));
        }
    }
    Ok(ValidatedOriginCertificate {
        node_id,
        public_key: public_key.ok_or(OriginAuthenticationError::CertificateChainEmpty)?,
        leaf_not_before_unix: leaf_not_before_unix
            .ok_or(OriginAuthenticationError::CertificateChainEmpty)?,
        leaf_not_after_unix: leaf_not_after_unix
            .ok_or(OriginAuthenticationError::CertificateChainEmpty)?,
        revalidate_after_unix,
    })
}

fn verify_with_validated_certificate(
    expected_node: NodeIdentifier,
    certificate: &ValidatedOriginCertificate,
    algorithm: &'static dyn signature::VerificationAlgorithm,
    payload: &[u8],
    signature_bytes: &[u8],
) -> Result<(), OriginAuthenticationError> {
    if certificate.node_id != expected_node {
        return Err(OriginAuthenticationError::NodeMismatch {
            expected: expected_node,
            actual: certificate.node_id,
        });
    }
    signature::UnparsedPublicKey::new(algorithm, certificate.public_key.as_ref())
        .verify(payload, signature_bytes)
        .map_err(|_| OriginAuthenticationError::InvalidSignature)
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
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, date_time_ymd};
    use std::io::Write;
    use std::sync::Barrier;
    use std::thread;
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

    fn mint_unused_self_signed_certificate(common_name: &str, expired: bool) -> Vec<u8> {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![common_name.to_string()]).unwrap();
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, common_name);
        params.distinguished_name = distinguished_name;
        if expired {
            params.not_before = date_time_ymd(2000, 1, 1);
            params.not_after = date_time_ymd(2001, 1, 1);
        }
        params.self_signed(&key).unwrap().der().to_vec()
    }

    fn origin_proof_with_suffix(proof: &OriginSignature, suffix: Vec<u8>) -> OriginSignature {
        let mut certificate_chain = proof.certificate_chain().to_vec();
        certificate_chain.push(suffix);
        OriginSignature::from_parts(
            proof.signature_scheme(),
            certificate_chain,
            proof.signature().to_vec(),
        )
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

    #[test]
    fn repeated_origin_signing_reuses_parsed_private_key() {
        let dir = TempDir::new().unwrap();
        let (ca, cert, key) = mint_identity(&dir, "42");
        let identity = NodeIdentity::load(&ca, &cert, &key).unwrap();

        assert_eq!(identity.signing_key_parse_count.load(Ordering::Relaxed), 1);
        let first = identity.sign_origin_payload(b"first").unwrap();
        let second = identity.sign_origin_payload(b"second").unwrap();

        assert_eq!(identity.signing_key_parse_count.load(Ordering::Relaxed), 1);
        assert!(Arc::ptr_eq(
            &first.certificate_chain,
            &second.certificate_chain
        ));
        assert!(Arc::ptr_eq(
            &first.certificate_chain,
            &identity.origin_signature_metadata.certificate_chain
        ));
        identity
            .verify_origin_payload(42, &first, b"first")
            .unwrap();
        identity
            .verify_origin_payload(42, &second, b"second")
            .unwrap();
    }

    #[test]
    fn repeated_origin_verification_reuses_validated_chain() {
        let dir = TempDir::new().unwrap();
        let (ca, cert, key) = mint_identity(&dir, "42");
        let identity = NodeIdentity::load(&ca, &cert, &key).unwrap();
        let first = identity.sign_origin_payload(b"first").unwrap();
        let second = identity.sign_origin_payload(b"second").unwrap();

        identity
            .verify_origin_payload(42, &first, b"first")
            .unwrap();
        identity
            .verify_origin_payload(42, &second, b"second")
            .unwrap();

        assert_eq!(
            identity
                .certificate_validation_count
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn unused_certificate_suffixes_share_leaf_validation_cache() {
        let dir = TempDir::new().unwrap();
        let (ca, cert, key) = mint_identity(&dir, "42");
        let identity = NodeIdentity::load(&ca, &cert, &key).unwrap();
        let payload = b"suffix-independent-proof";
        let proof = identity.sign_origin_payload(payload).unwrap();
        let expired = origin_proof_with_suffix(
            &proof,
            mint_unused_self_signed_certificate("expired-unused", true),
        );
        let first_valid = origin_proof_with_suffix(
            &proof,
            mint_unused_self_signed_certificate("valid-unused-one", false),
        );
        let second_valid = origin_proof_with_suffix(
            &proof,
            mint_unused_self_signed_certificate("valid-unused-two", false),
        );

        identity
            .verify_origin_payload(42, &expired, payload)
            .unwrap();
        identity
            .verify_origin_payload(42, &expired, payload)
            .unwrap();
        identity
            .verify_origin_payload(42, &first_valid, payload)
            .unwrap();
        identity
            .verify_origin_payload(42, &second_valid, payload)
            .unwrap();

        assert_eq!(
            identity
                .certificate_validation_count
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(identity.origin_certificate_cache.read().entries.len(), 1);
    }

    #[test]
    fn concurrent_cold_certificate_cache_miss_validates_chain_once() {
        const THREAD_COUNT: usize = 4;

        let dir = TempDir::new().unwrap();
        let (ca, cert, key) = mint_identity(&dir, "42");
        let identity = Arc::new(NodeIdentity::load(&ca, &cert, &key).unwrap());
        let proof = Arc::new(
            identity
                .sign_origin_payload(b"cold-shared-payload")
                .unwrap(),
        );
        let barrier = Arc::new(Barrier::new(THREAD_COUNT + 1));
        let threads = (0..THREAD_COUNT)
            .map(|_| {
                let identity = identity.clone();
                let proof = proof.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    identity.verify_origin_payload(42, &proof, b"cold-shared-payload")
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        for thread in threads {
            thread.join().unwrap().unwrap();
        }

        assert_eq!(
            identity
                .certificate_validation_count
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn warm_certificate_cache_still_checks_node_payload_and_scheme() {
        let dir = TempDir::new().unwrap();
        let (ca, cert, key) = mint_identity(&dir, "42");
        let identity = NodeIdentity::load(&ca, &cert, &key).unwrap();
        let proof = identity.sign_origin_payload(b"payload").unwrap();
        identity
            .verify_origin_payload(42, &proof, b"payload")
            .unwrap();

        assert!(matches!(
            identity.verify_origin_payload(7, &proof, b"payload"),
            Err(OriginAuthenticationError::NodeMismatch {
                expected: 7,
                actual: 42
            })
        ));
        assert!(matches!(
            identity.verify_origin_payload(42, &proof, b"altered"),
            Err(OriginAuthenticationError::InvalidSignature)
        ));
        let mut unsupported = proof.clone();
        unsupported.signature_scheme = 0xffff;
        assert!(matches!(
            identity.verify_origin_payload(42, &unsupported, b"payload"),
            Err(OriginAuthenticationError::UnsupportedSignatureScheme)
        ));
        assert_eq!(
            identity
                .certificate_validation_count
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn untrusted_origin_chain_is_never_cached() {
        let trusted_dir = TempDir::new().unwrap();
        let (trusted_ca, trusted_cert, trusted_key) = mint_identity(&trusted_dir, "42");
        let verifier = NodeIdentity::load(&trusted_ca, &trusted_cert, &trusted_key).unwrap();
        let untrusted_dir = TempDir::new().unwrap();
        let (untrusted_ca, untrusted_cert, untrusted_key) = mint_identity(&untrusted_dir, "7");
        let signer = NodeIdentity::load(&untrusted_ca, &untrusted_cert, &untrusted_key).unwrap();
        let proof = signer.sign_origin_payload(b"payload").unwrap();

        for _ in 0..2 {
            assert!(matches!(
                verifier.verify_origin_payload(7, &proof, b"payload"),
                Err(OriginAuthenticationError::CertificateChain(_))
            ));
        }
        assert_eq!(
            verifier
                .certificate_validation_count
                .load(Ordering::Relaxed),
            2
        );
    }

    #[test]
    fn unused_expired_certificate_is_ignored_and_cached_by_leaf() {
        let dir = TempDir::new().unwrap();
        let (ca, cert, key) = mint_identity(&dir, "42");

        // WebPKI treats the supplied intermediates as path-building
        // candidates and can ignore an unrelated certificate. Include an
        // expired candidate to ensure leaf-scoped trust ignores unused chain
        // suffixes consistently on both cold and warm paths.
        let expired_key = KeyPair::generate().unwrap();
        let mut expired_params =
            CertificateParams::new(vec!["expired-unused".to_string()]).unwrap();
        expired_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        expired_params.not_after = rcgen::date_time_ymd(2020, 1, 2);
        let expired_cert = expired_params.self_signed(&expired_key).unwrap();
        let mut cert_file = std::fs::OpenOptions::new()
            .append(true)
            .open(&cert)
            .unwrap();
        cert_file.write_all(b"\n").unwrap();
        cert_file.write_all(expired_cert.pem().as_bytes()).unwrap();

        let identity = NodeIdentity::load(&ca, &cert, &key).unwrap();
        tls::verify_peer_cert_chain(identity.roots().clone(), identity.chain()).unwrap();
        let proof = identity.sign_origin_payload(b"payload").unwrap();

        for _ in 0..2 {
            identity
                .verify_origin_payload(42, &proof, b"payload")
                .unwrap();
        }
        assert_eq!(identity.origin_certificate_cache.read().entries.len(), 1);
        assert_eq!(
            identity
                .certificate_validation_count
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn origin_signature_metadata_does_not_sign_or_reparse_key() {
        let dir = TempDir::new().unwrap();
        let (ca, cert, key) = mint_identity(&dir, "42");
        let identity = NodeIdentity::load(&ca, &cert, &key).unwrap();
        let metadata = identity.origin_signature_metadata();

        assert_eq!(metadata.signature_scheme(), 0x0403);
        assert_eq!(metadata.certificate_chain().len(), 1);
        assert_eq!(metadata.maximum_signature_len(), 72);
        assert_eq!(identity.signing_key_parse_count.load(Ordering::Relaxed), 1);
        assert_eq!(
            identity
                .certificate_validation_count
                .load(Ordering::Relaxed),
            0
        );
    }

    fn synthetic_validated_certificate(
        not_before_unix: i64,
        not_after_unix: i64,
    ) -> ValidatedOriginCertificate {
        ValidatedOriginCertificate {
            node_id: 42,
            public_key: Arc::from(&b"public-key"[..]),
            leaf_not_before_unix: not_before_unix,
            leaf_not_after_unix: not_after_unix,
            revalidate_after_unix: not_after_unix,
        }
    }

    #[test]
    fn origin_certificate_cache_is_bounded_and_evicts_oldest() {
        let mut cache = OriginCertificateCache::default();
        for index in 0..=ORIGIN_CERTIFICATE_CACHE_CAPACITY {
            let mut fingerprint = [0; digest::SHA256_OUTPUT_LEN];
            fingerprint[..8].copy_from_slice(&(index as u64).to_be_bytes());
            cache.insert(fingerprint, synthetic_validated_certificate(0, i64::MAX));
        }

        assert_eq!(cache.entries.len(), ORIGIN_CERTIFICATE_CACHE_CAPACITY);
        assert_eq!(
            cache.insertion_order.len(),
            ORIGIN_CERTIFICATE_CACHE_CAPACITY
        );
        assert!(!cache.entries.contains_key(&[0; digest::SHA256_OUTPUT_LEN]));
        let mut newest = [0; digest::SHA256_OUTPUT_LEN];
        newest[..8].copy_from_slice(&(ORIGIN_CERTIFICATE_CACHE_CAPACITY as u64).to_be_bytes());
        assert!(cache.entries.contains_key(&newest));
    }

    #[test]
    fn origin_certificate_cache_enforces_validity_range_on_hits() {
        let mut cache = OriginCertificateCache::default();
        let valid_fingerprint = [1; digest::SHA256_OUTPUT_LEN];
        cache.insert(valid_fingerprint, synthetic_validated_certificate(10, 20));
        assert!(matches!(
            cache.lookup(&valid_fingerprint, 10),
            OriginCertificateCacheLookup::Valid(_)
        ));
        assert!(matches!(
            cache.lookup(&valid_fingerprint, 20),
            OriginCertificateCacheLookup::Valid(_)
        ));
        assert!(matches!(
            cache.lookup(&valid_fingerprint, 21),
            OriginCertificateCacheLookup::KnownOutsideValidity
        ));
        assert!(cache.entries.contains_key(&valid_fingerprint));

        let future_fingerprint = [2; digest::SHA256_OUTPUT_LEN];
        cache.insert(future_fingerprint, synthetic_validated_certificate(30, 40));
        assert!(matches!(
            cache.lookup(&future_fingerprint, 29),
            OriginCertificateCacheLookup::KnownOutsideValidity
        ));
        assert!(cache.entries.contains_key(&future_fingerprint));
        assert!(matches!(
            cache.lookup(&[3; digest::SHA256_OUTPUT_LEN], 35),
            OriginCertificateCacheLookup::Absent
        ));

        let revalidation_fingerprint = [4; digest::SHA256_OUTPUT_LEN];
        let mut revalidation_entry = synthetic_validated_certificate(10, 40);
        revalidation_entry.revalidate_after_unix = 20;
        cache.insert(revalidation_fingerprint, revalidation_entry);
        assert!(matches!(
            cache.lookup(&revalidation_fingerprint, 20),
            OriginCertificateCacheLookup::Valid(_)
        ));
        assert!(matches!(
            cache.lookup(&revalidation_fingerprint, 21),
            OriginCertificateCacheLookup::Absent
        ));
    }
}
