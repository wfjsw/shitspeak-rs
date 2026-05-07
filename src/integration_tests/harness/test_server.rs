//! Spin up a real [`Server`] on `127.0.0.1:0` for in-process integration tests.
//!
//! Builds an in-memory configuration (no persistent blob storage, no S2S
//! cluster activity), generates a single-cert PKI via [`mint_pki`], hands
//! a [`AuthenticatorAdapter`] to `Server::new`, and spawns `Server::run` on a
//! tokio task. Dropping the [`TestServer`] drops the shutdown channel, which
//! causes `Server::run` to exit cleanly.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::config::{Config, S2sConfig};
use crate::integration_tests::harness::{AuthenticatorAdapter, TestAuthenticator};
use crate::s2s::testing::pki::{install_provider_once, mint_pki, Pki};
use crate::server::Server;

#[derive(Debug, Clone)]
pub struct TestServerOpts {
    pub max_users: u64,
    pub cert_required: bool,
    pub welcome_text: Option<String>,
    pub udp_voice_enabled: bool,
    pub udp_ping_enabled: bool,
    pub default_channel: u32,
    pub send_permission_info: bool,
}

impl Default for TestServerOpts {
    fn default() -> Self {
        Self {
            max_users: 100,
            cert_required: false,
            welcome_text: Some("test-welcome".into()),
            udp_voice_enabled: true,
            udp_ping_enabled: true,
            default_channel: 0,
            send_permission_info: false,
        }
    }
}

pub struct TestServer {
    pub server: Arc<Box<Server>>,
    pub addr: SocketAddr,
    pub udp_addr: SocketAddr,
    pub pki: Pki,
    pub authenticator: Arc<TestAuthenticator>,
    shutdown_tx: watch::Sender<()>,
    run_handle: Option<JoinHandle<()>>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        // Closing the watch sender triggers Server::run's `shutdown_tx.closed()`
        // branch, which stops the accept loops and lets the run task exit.
        // We can't await the JoinHandle from Drop, so we abort it as a fallback;
        // the run task will already have noticed the shutdown signal.
        let _ = self.shutdown_tx.send(());
        if let Some(h) = self.run_handle.take() {
            h.abort();
        }
    }
}

pub async fn spawn_test_server(opts: TestServerOpts) -> TestServer {
    install_provider_once();

    let pki = mint_pki(&[1]);
    let (cert_path, key_path) = pki.nodes[0].clone();

    let config = Config {
        node_id: 1,
        listen: "127.0.0.1:0".into(),
        register_name: "test".into(),
        register_password: None,
        register_url: None,
        register_hostname: None,
        register_location: None,
        cert_path: cert_path.to_string_lossy().into_owned(),
        key_path: key_path.to_string_lossy().into_owned(),
        send_version: false,
        send_build_info: false,
        send_os_info: false,
        allowed_proxies: Vec::new(),
        min_client_version: 0,
        max_users: opts.max_users,
        welcome_text: opts.welcome_text.clone(),
        max_bandwidth: 72_000,
        allow_html: true,
        max_text_message_length: 5_000,
        max_image_message_length: 131_072,
        default_channel: opts.default_channel,
        cert_required: opts.cert_required,
        blob_storage_dir: None,
        channel_log_max_entries: 10_000,
        client_log_max_entries: 10_000,
        channel_snapshot_every_ops: 10,
        channel_snapshot_every_secs: 60,
        channel_wal_compaction_expire_count: 2_000,
        udp_voice_enabled: opts.udp_voice_enabled,
        udp_ping_enabled: opts.udp_ping_enabled,
        udp_channel_size: 2_048,
        client_idle_timeout_secs: 30,
        required_groups: Vec::new(),
        send_permission_info: opts.send_permission_info,
        s2s: S2sConfig::default(),
    };

    let authenticator = Arc::new(TestAuthenticator::new());
    let adapter = AuthenticatorAdapter(Arc::clone(&authenticator));

    let server = Server::new(config, adapter)
        .await
        .expect("Server::new failed");

    let addr = server.local_addr().expect("local_addr");
    let udp_addr = server.local_udp_addr().expect("local_udp_addr");

    let (shutdown_tx, _shutdown_rx) = watch::channel(());

    let run_handle = tokio::spawn({
        let server = Arc::clone(&server);
        let tx = shutdown_tx.clone();
        async move {
            let _ = server.run(tx).await;
        }
    });

    TestServer {
        server,
        addr,
        udp_addr,
        pki,
        authenticator,
        shutdown_tx,
        run_handle: Some(run_handle),
    }
}
