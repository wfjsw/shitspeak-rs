//! Shared test utilities for S2S transport consumers.
//!
//! This module owns the generic network-test scaffolding: short-lived PKI,
//! loopback port allocation, and the process-wide guard that serializes tests
//! which reserve ports before their listeners start.

use std::fs::File;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Once, OnceLock};
use std::time::Duration;

use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, KeyPair};
use tempfile::TempDir;
use tokio::sync::{Mutex, OwnedMutexGuard};

use shitspeak_core::NodeIdentifier;

use crate::metrics::{DatagramPathHealthReason, DatagramPathHealthSnapshot, DatagramPathHealthState};
use crate::service_level::DeliveryPath;

/// Install rustls' aws-lc-rs default crypto provider exactly once across all
/// tests in the process.
pub fn install_provider_once() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Per-test PKI: one CA and one certificate/key pair per node.
pub struct Pki {
    _dir: TempDir,
    pub ca_path: PathBuf,
    pub nodes: Vec<(PathBuf, PathBuf)>,
}

/// Mint a CA and one certificate/key pair per node CN.
///
/// Node CNs are written to each certificate's `CommonName`; files live in a
/// `TempDir` owned by the returned [`Pki`].
pub fn mint_pki(node_cns: &[u16]) -> Pki {
    let dir = TempDir::new().unwrap();
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(vec!["s2s-transport-test-ca".into()]).unwrap();
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "s2s-transport-test-ca");
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
        let mut params = CertificateParams::new(vec![format!("node-{cn}")]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn.to_string());
        params.distinguished_name = dn;
        let node_cert = params.signed_by(&node_key, &ca_cert, &ca_key).unwrap();

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

/// Build a 127.0.0.1:`port` socket address.
pub fn loopback(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

/// Bind an ephemeral TCP port, drop the listener, and return its port number.
///
/// There is an inherent race before the real listener binds; acquire
/// [`s2s_network_test_guard`] when allocating multiple test ports.
pub async fn pick_free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// Bind an ephemeral UDP port, drop the socket, and return its port number.
pub async fn pick_free_udp_port() -> u16 {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.local_addr().unwrap().port()
}

static S2S_NETWORK_TEST_LOCK: OnceLock<Arc<Mutex<()>>> = OnceLock::new();

fn s2s_network_test_lock() -> Arc<Mutex<()>> {
    S2S_NETWORK_TEST_LOCK
        .get_or_init(|| Arc::new(Mutex::new(())))
        .clone()
}

/// Serialize tests that bring up real S2S transports.
///
/// These tests reserve known ports before listeners are started. Running them
/// concurrently can cause socket races and scheduler pressure that makes
/// short convergence deadlines flaky.
pub async fn s2s_network_test_guard() -> OwnedMutexGuard<()> {
    s2s_network_test_lock().lock_owned().await
}

/// Build a [`DatagramPathHealthSnapshot`] for tests without driving a real
/// transport path. Unset fields take neutral defaults (zero counters, fresh
/// observations, full confidence).
pub fn datagram_path_health_snapshot(
    peer: NodeIdentifier,
    path: DeliveryPath,
    state: DatagramPathHealthState,
    effective_loss_ppm: Option<u32>,
    loss_samples: u64,
) -> DatagramPathHealthSnapshot {
    DatagramPathHealthSnapshot::new(
        peer,
        path,
        state,
        DatagramPathHealthReason::WithinThreshold,
        effective_loss_ppm,
        None,
        loss_samples,
        0,
        Duration::ZERO,
        Duration::ZERO,
        None,
        None,
        None,
        1_000_000,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        Duration::ZERO,
        false,
    )
}
