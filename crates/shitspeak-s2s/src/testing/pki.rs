//! Per-test PKI: a CA + per-node certificates in a tempdir.

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Once;

use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, KeyPair};
use tempfile::TempDir;

/// Install rustls' aws-lc-rs default crypto provider exactly once across
/// all tests in the binary.
pub fn install_provider_once() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Per-test PKI: one CA + one cert/key per node, all in a tempdir.
pub struct Pki {
    _dir: TempDir,
    pub ca_path: PathBuf,
    pub nodes: Vec<(PathBuf, PathBuf)>,
}

/// Mint a CA and one cert/key pair per node CN. CNs are written into the
/// certificate's `CommonName`; SAN is `node-{cn}`. Files live in a
/// `TempDir` that's dropped with the `Pki` value.
pub fn mint_pki(node_cns: &[u16]) -> Pki {
    let dir = TempDir::new().unwrap();
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(vec!["s2s-overlay-test-ca".into()]).unwrap();
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "s2s-overlay-test-ca");
    ca_params.distinguished_name = ca_dn;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert: Certificate = ca_params.self_signed(&ca_key).unwrap();

    let ca_path = dir.path().join("ca.pem");
    File::create(&ca_path)
        .unwrap()
        .write_all(ca_cert.pem().as_bytes())
        .unwrap();

    let mut nodes = Vec::new();
    for cn in node_cns {
        let node_key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec![format!("node-{cn}")]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn.to_string());
        p.distinguished_name = dn;
        let node_cert = p.signed_by(&node_key, &ca_cert, &ca_key).unwrap();

        let cert_path = dir.path().join(format!("cert-{cn}.pem"));
        let key_path = dir.path().join(format!("key-{cn}.pem"));
        File::create(&cert_path)
            .unwrap()
            .write_all(node_cert.pem().as_bytes())
            .unwrap();
        File::create(&key_path)
            .unwrap()
            .write_all(node_key.serialize_pem().as_bytes())
            .unwrap();
        nodes.push((cert_path, key_path));
    }

    Pki {
        _dir: dir,
        ca_path,
        nodes,
    }
}
