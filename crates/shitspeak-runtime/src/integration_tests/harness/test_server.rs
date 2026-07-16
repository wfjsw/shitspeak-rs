//! Spin up a real [`Server`] on `127.0.0.1:0` for in-process integration tests.
//!
//! Builds an in-memory configuration (no persistent blob storage, no S2S
//! cluster activity), generates a single-cert PKI via [`mint_pki`], hands
//! a [`AuthenticatorAdapter`] to `Server::new`, and spawns `Server::run` on a
//! tokio task. Dropping the [`TestServer`] triggers server shutdown, which
//! causes `Server::run` to exit cleanly.

use std::net::SocketAddr;
use std::sync::Arc;

use tempfile::TempDir;
use tokio::task::JoinHandle;

use crate::constants::APP_PROTO_VER;
use crate::integration_tests::harness::{AuthenticatorAdapter, TestAuthenticator};
use crate::protocol_version::ProtocolVersion;
use crate::server::Server;
use shitspeak_runtime_config::{
    AuthenticatorConfig, Config, PrivacyConfig, S2sConfig, S2sSeedAddressConfig,
    UdpPingUserCountScope, WebConfig,
};
use shitspeak_s2s::testing::LinkChaos;
use shitspeak_s2s::testing::pki::{Pki, install_provider_once, mint_pki};

#[derive(Debug, Clone)]
pub struct TestServerOpts {
    pub max_users: u64,
    pub cert_required: bool,
    pub welcome_text: Option<String>,
    pub udp_voice_enabled: bool,
    pub udp_ping_enabled: bool,
    pub default_channel: u32,
    pub send_permission_info: bool,
    pub hide_users_without_traverse: bool,
    pub hide_channels_without_traverse: bool,
    pub show_node_id_for_superusers: bool,
    pub debug_acl_enter: bool,
    pub explicit_enter_deny_overrides_write: bool,
    pub preserve_write_acl_on_edit: bool,
    pub grant_temp_channel_creator_acl: bool,
    pub reevaluate_speak_on_acl_change: bool,
    pub privacy: PrivacyConfig,
    pub server_protocol_version: ProtocolVersion,
    pub channel_log_max_entries: usize,
    pub client_idle_timeout_secs: u64,
    pub authenticate_timeout_ms: u64,
    pub auth_finalization_concurrency: usize,
    pub s2s_inbound_chaos: Option<LinkChaos>,
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
            hide_users_without_traverse: false,
            hide_channels_without_traverse: false,
            show_node_id_for_superusers: true,
            debug_acl_enter: true,
            explicit_enter_deny_overrides_write: false,
            preserve_write_acl_on_edit: true,
            grant_temp_channel_creator_acl: true,
            reevaluate_speak_on_acl_change: false,
            privacy: PrivacyConfig::default(),
            server_protocol_version: APP_PROTO_VER,
            channel_log_max_entries: 10_000,
            client_idle_timeout_secs: 30,
            authenticate_timeout_ms: 30_000,
            auth_finalization_concurrency: 4,
            s2s_inbound_chaos: None,
        }
    }
}

pub struct TestServer {
    pub server: Arc<Box<Server>>,
    pub addr: SocketAddr,
    pub udp_addr: SocketAddr,
    pub pki: Arc<Pki>,
    pub authenticator: Arc<TestAuthenticator>,
    run_handle: Option<JoinHandle<()>>,
    _s2s_persistence_dir: Option<TempDir>,
}

impl TestServer {
    pub async fn shutdown_gracefully(mut self) {
        self.server.shutdown();
        if let Some(h) = self.run_handle.take() {
            let _ = h.await;
        }
    }

    pub fn s2s_inbound_chaos(&self) -> Option<LinkChaos> {
        self.server.s2s_manager().test_inbound_chaos()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        // Trigger shutdown so Server::run stops accept loops and can exit.
        //
        // Do not abort the run task here. `Server::run` owns the join handle
        // for the independently spawned S2S runtime; aborting it would drop
        // that handle without running the runtime's shutdown sequence, which
        // leaves S2S transports/replication tasks alive after a panic. Detach
        // the task instead and let it observe the shutdown watch and join its
        // children. Tests that complete normally use `shutdown_gracefully`
        // and still await this handle directly.
        self.server.shutdown();
        let _ = self.run_handle.take();
    }
}

#[derive(Debug, Clone)]
pub struct TestS2sServerOpts {
    pub node_id: u16,
    pub cert_index: usize,
    pub tcp_listen: SocketAddr,
    pub seed_addresses: Vec<S2sSeedAddressConfig>,
}

pub async fn spawn_test_server(opts: TestServerOpts) -> TestServer {
    install_provider_once();

    let pki = Arc::new(mint_pki(&[1]));
    spawn_test_server_with_pki(opts, Arc::clone(&pki), 1, 0, S2sConfig::default(), None).await
}

pub async fn spawn_s2s_test_server(
    opts: TestServerOpts,
    pki: Arc<Pki>,
    s2s_opts: TestS2sServerOpts,
) -> TestServer {
    install_provider_once();

    let persistence_dir = TempDir::new().expect("s2s persistence dir");
    let (cert_path, key_path) = pki.nodes[s2s_opts.cert_index].clone();
    let s2s = S2sConfig {
        enabled: true,
        ca_path: Some(pki.ca_path.clone()),
        cert_path: Some(cert_path.clone()),
        key_path: Some(key_path.clone()),
        tcp_listen: vec![s2s_opts.tcp_listen],
        persistence_dir: Some(persistence_dir.path().to_path_buf()),
        seed_addresses: s2s_opts.seed_addresses,
        ..S2sConfig::default()
    };

    spawn_test_server_with_pki(
        opts,
        pki,
        s2s_opts.node_id,
        s2s_opts.cert_index,
        s2s,
        Some(persistence_dir),
    )
    .await
}

pub async fn spawn_s2s_test_server_with_config(
    opts: TestServerOpts,
    pki: Arc<Pki>,
    node_id: u16,
    cert_index: usize,
    mut s2s: S2sConfig,
) -> TestServer {
    install_provider_once();

    let persistence_dir = TempDir::new().expect("s2s persistence dir");
    let (cert_path, key_path) = pki.nodes[cert_index].clone();
    s2s.enabled = true;
    s2s.ca_path = Some(pki.ca_path.clone());
    s2s.cert_path = Some(cert_path);
    s2s.key_path = Some(key_path);
    s2s.persistence_dir = Some(persistence_dir.path().to_path_buf());

    spawn_test_server_with_pki(opts, pki, node_id, cert_index, s2s, Some(persistence_dir)).await
}

async fn spawn_test_server_with_pki(
    opts: TestServerOpts,
    pki: Arc<Pki>,
    _node_id: u16,
    cert_index: usize,
    s2s: S2sConfig,
    s2s_persistence_dir: Option<TempDir>,
) -> TestServer {
    let (cert_path, key_path) = pki.nodes[cert_index].clone();

    let config = Config {
        listen: "127.0.0.1:0".into(),
        server_entrypoints: Vec::new(),
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
        server_protocol_version: opts.server_protocol_version,
        allowed_proxies: Vec::new(),
        min_client_version: 0,
        max_users: opts.max_users,
        authenticator: AuthenticatorConfig::default(),
        observability: shitspeak_runtime_config::ObservabilityConfig::default(),
        geoip: shitspeak_runtime_config::GeoIpConfig::default(),
        welcome_text: opts.welcome_text.clone(),
        max_bandwidth: 72_000,
        allow_html: true,
        max_text_message_length: 5_000,
        max_image_message_length: 131_072,
        root_channel_name: "Root".into(),
        default_channel: opts.default_channel,
        cert_required: opts.cert_required,
        blob_storage_dir: None,
        channel_log_max_entries: opts.channel_log_max_entries,
        client_log_max_entries: 10_000,
        channel_snapshot_every_ops: 10,
        channel_snapshot_every_secs: 60,
        channel_wal_compaction_expire_count: 2_000,
        udp_voice_enabled: opts.udp_voice_enabled,
        udp_ping_enabled: opts.udp_ping_enabled,
        udp_ping_user_count_scope: UdpPingUserCountScope::Cluster,
        udp_channel_size: 2_048,
        voice: shitspeak_runtime_config::VoiceTuning::default(),
        client_idle_timeout_secs: opts.client_idle_timeout_secs,
        authenticate_timeout_ms: opts.authenticate_timeout_ms,
        auth_finalization_concurrency: opts.auth_finalization_concurrency,
        pending_delete_timeout_ms: 5_000,
        required_groups: Vec::new(),
        send_permission_info: opts.send_permission_info,
        hide_users_without_traverse: opts.hide_users_without_traverse,
        hide_channels_without_traverse: opts.hide_channels_without_traverse,
        show_node_id_for_superusers: opts.show_node_id_for_superusers,
        acl: shitspeak_runtime_config::AclConfig::with_acl_behavior_and_speak_reevaluation(
            opts.debug_acl_enter,
            opts.explicit_enter_deny_overrides_write,
            opts.preserve_write_acl_on_edit,
            opts.grant_temp_channel_creator_acl,
            opts.reevaluate_speak_on_acl_change,
        ),
        privacy: opts.privacy,
        s2s,
        web: WebConfig::default(),
    };

    let authenticator = Arc::new(TestAuthenticator::new());
    let adapter = AuthenticatorAdapter(Arc::clone(&authenticator));

    let server = Server::new(config, adapter)
        .await
        .expect("Server::new failed");
    if let Some(chaos) = opts.s2s_inbound_chaos {
        server.s2s_manager().install_test_inbound_chaos(chaos);
    }

    let addr = server.local_addr().expect("local_addr");
    let udp_addr = server.local_udp_addr().expect("local_udp_addr");

    let run_handle = tokio::spawn({
        let server = Arc::clone(&server);
        async move {
            let _ = server.run().await;
        }
    });

    TestServer {
        server,
        addr,
        udp_addr,
        pki,
        authenticator,
        run_handle: Some(run_handle),
        _s2s_persistence_dir: s2s_persistence_dir,
    }
}
