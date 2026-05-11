//! Loads and caches the local node's identity material:
//!  * trust root (CA bundle) shared by every peer
//!  * own X.509 certificate chain
//!  * own private key
//!  * the local `NodeIdentifier` parsed out of the cert's Subject CN.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::types::NodeIdentifier;

use super::error::ConfigError;

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
        let node_id = parse_cn_node_id(&chain[0], cert_path)?;

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
pub fn parse_cn_node_id(
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
    let (_, parsed) =
        X509Certificate::from_der(first.as_ref()).map_err(|e| ConfigError::X509(format!("{e}")))?;
    let cn = parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .ok_or_else(|| ConfigError::CnMissing {
            path: "<peer-chain>".to_string(),
        })?
        .trim()
        .to_owned();
    cn.parse::<NodeIdentifier>()
        .map_err(|_| ConfigError::CnNotNumeric { cn })
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
}
