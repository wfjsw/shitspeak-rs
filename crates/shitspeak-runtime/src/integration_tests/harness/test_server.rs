//! Spin up a real [`Server`] on `127.0.0.1:0` for in-process integration tests.
//!
//! Builds an in-memory configuration (no persistent blob storage, no S2S
//! cluster activity), generates a single-cert PKI via [`mint_pki`], hands
//! a [`AuthenticatorAdapter`] to `Server::new`, and spawns `Server::run` on a
//! tokio task. Dropping the [`TestServer`] triggers server shutdown, which
//! causes `Server::run` to exit cleanly.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
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
use shitspeak_s2s::testing::{Pki, install_provider_once, mint_pki};

const CHANNEL_SNAPSHOT_FILE: &str = "channels.snapshot.json";
const CHANNEL_WAL_FILE: &str = "channels.wal.jsonl";
const CHANNEL_TERMINAL_FIXTURE_FILE: &str = "terminal-channels.sqlite3";
const STRICT_TERMINAL_JOURNAL_DIRECTORY: &str = "strict-terminal-journal";
const CHANNEL_REPLICATION_TOPIC: &str = "channels";

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
    pub allow_move_without_traverse: bool,
    pub reveal_users_in_current_and_linked_channels_without_traverse: bool,
    pub privacy: PrivacyConfig,
    pub server_protocol_version: ProtocolVersion,
    pub user_channel_cache_record_remote_sessions: bool,
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
            allow_move_without_traverse: false,
            reveal_users_in_current_and_linked_channels_without_traverse: false,
            privacy: PrivacyConfig::default(),
            server_protocol_version: APP_PROTO_VER,
            user_channel_cache_record_remote_sessions: false,
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
    _blob_storage_dir: Option<TempDir>,
}

impl TestServer {
    pub async fn shutdown_gracefully(mut self) {
        self.server.shutdown();
        if let Some(h) = self.run_handle.take() {
            let _ = h.await;
        }
    }

    pub async fn shutdown_gracefully_and_capture_strict_state(
        mut self,
        destination: impl AsRef<Path>,
    ) -> std::io::Result<()> {
        let blob_storage_directory = self
            .blob_storage_dir()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "test server has no durable channel repository directory",
                )
            })?
            .to_path_buf();
        let terminal_journal_path =
            self.strict_channel_terminal_journal_path().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "test server has no durable strict terminal journal directory",
                )
            })?;

        self.server.shutdown();
        if let Some(handle) = self.run_handle.take() {
            let _ = handle.await;
        }

        capture_strict_state_files(
            &blob_storage_directory,
            &terminal_journal_path,
            destination.as_ref(),
        )
    }

    pub fn s2s_inbound_chaos(&self) -> Option<LinkChaos> {
        self.server.s2s_manager().test_inbound_chaos()
    }

    pub fn s2s_persistence_dir(&self) -> Option<&Path> {
        self._s2s_persistence_dir.as_ref().map(TempDir::path)
    }

    pub fn blob_storage_dir(&self) -> Option<&Path> {
        self._blob_storage_dir.as_ref().map(TempDir::path)
    }

    pub fn strict_channel_terminal_journal_path(&self) -> Option<PathBuf> {
        self.s2s_persistence_dir()
            .map(|directory| directory.join(strict_channel_terminal_journal_relative_path()))
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

/// Production channel state copied through SSH for a strict-replication
/// reproduction. Other repository, client, and transport state is ignored.
#[derive(Debug, Clone)]
pub struct TestStrictReplicationState {
    source_directory: PathBuf,
}

impl TestStrictReplicationState {
    pub fn from_directory(source_directory: impl Into<PathBuf>) -> Self {
        Self {
            source_directory: source_directory.into(),
        }
    }

    fn stage_into(
        &self,
        blob_storage_directory: &Path,
        s2s_persistence_directory: &Path,
    ) -> std::io::Result<()> {
        copy_fixture_file(
            &self.source_directory,
            CHANNEL_SNAPSHOT_FILE,
            blob_storage_directory.join(CHANNEL_SNAPSHOT_FILE),
        )?;
        copy_fixture_file(
            &self.source_directory,
            CHANNEL_WAL_FILE,
            blob_storage_directory.join(CHANNEL_WAL_FILE),
        )?;

        let terminal_path =
            s2s_persistence_directory.join(strict_channel_terminal_journal_relative_path());
        let terminal_directory = terminal_path
            .parent()
            .expect("strict channel terminal journal has a parent directory");
        std::fs::create_dir_all(&terminal_directory)?;
        copy_fixture_file(
            &self.source_directory,
            CHANNEL_TERMINAL_FIXTURE_FILE,
            terminal_path,
        )?;
        Ok(())
    }
}

fn strict_channel_terminal_journal_relative_path() -> PathBuf {
    PathBuf::from(STRICT_TERMINAL_JOURNAL_DIRECTORY).join(format!(
        "topic-{}.sqlite3",
        hex::encode(CHANNEL_REPLICATION_TOPIC.as_bytes())
    ))
}

fn copy_fixture_file(
    source_directory: &Path,
    source_file_name: &str,
    destination: PathBuf,
) -> std::io::Result<()> {
    std::fs::copy(source_directory.join(source_file_name), destination)?;
    Ok(())
}

fn capture_strict_state_files(
    blob_storage_directory: &Path,
    terminal_journal_path: &Path,
    destination: &Path,
) -> std::io::Result<()> {
    std::fs::create_dir_all(destination)?;
    std::fs::copy(
        blob_storage_directory.join(CHANNEL_SNAPSHOT_FILE),
        destination.join(CHANNEL_SNAPSHOT_FILE),
    )?;
    std::fs::copy(
        blob_storage_directory.join(CHANNEL_WAL_FILE),
        destination.join(CHANNEL_WAL_FILE),
    )?;
    let connection = rusqlite::Connection::open_with_flags(
        terminal_journal_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(std::io::Error::other)?;
    let terminal_image = connection
        .serialize(rusqlite::MAIN_DB)
        .map_err(std::io::Error::other)?;
    std::fs::write(
        destination.join(CHANNEL_TERMINAL_FIXTURE_FILE),
        &*terminal_image,
    )?;
    Ok(())
}

pub async fn spawn_test_server(opts: TestServerOpts) -> TestServer {
    install_provider_once();

    let pki = Arc::new(mint_pki(&[1]));
    spawn_test_server_with_pki(
        opts,
        Arc::clone(&pki),
        1,
        0,
        S2sConfig::default(),
        None,
        None,
    )
    .await
}

pub async fn spawn_s2s_test_server(
    opts: TestServerOpts,
    pki: Arc<Pki>,
    s2s_opts: TestS2sServerOpts,
) -> TestServer {
    install_provider_once();

    let persistence_dir = TempDir::new().expect("s2s persistence dir");
    let blob_storage_dir = TempDir::new().expect("s2s blob storage dir");
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
        Some(blob_storage_dir),
    )
    .await
}

pub async fn spawn_s2s_test_server_with_config(
    opts: TestServerOpts,
    pki: Arc<Pki>,
    node_id: u16,
    cert_index: usize,
    s2s: S2sConfig,
) -> TestServer {
    spawn_s2s_test_server_with_config_and_optional_state(opts, pki, node_id, cert_index, s2s, None)
        .await
}

pub async fn spawn_s2s_test_server_with_state(
    opts: TestServerOpts,
    pki: Arc<Pki>,
    node_id: u16,
    cert_index: usize,
    s2s: S2sConfig,
    state: TestStrictReplicationState,
) -> TestServer {
    spawn_s2s_test_server_with_config_and_optional_state(
        opts,
        pki,
        node_id,
        cert_index,
        s2s,
        Some(state),
    )
    .await
}

async fn spawn_s2s_test_server_with_config_and_optional_state(
    opts: TestServerOpts,
    pki: Arc<Pki>,
    node_id: u16,
    cert_index: usize,
    mut s2s: S2sConfig,
    state: Option<TestStrictReplicationState>,
) -> TestServer {
    install_provider_once();

    let persistence_dir = TempDir::new().expect("s2s persistence dir");
    let blob_storage_dir = TempDir::new().expect("s2s blob storage dir");
    let (cert_path, key_path) = pki.nodes[cert_index].clone();
    s2s.enabled = true;
    s2s.ca_path = Some(pki.ca_path.clone());
    s2s.cert_path = Some(cert_path);
    s2s.key_path = Some(key_path);
    s2s.persistence_dir = Some(persistence_dir.path().to_path_buf());
    assert_eq!(
        s2s.local_node_id().expect("test S2S node identity"),
        node_id,
        "test fixture node ID must match its certificate"
    );
    if let Some(state) = state {
        state
            .stage_into(blob_storage_dir.path(), persistence_dir.path())
            .expect("stage strict replication state fixture");
    }

    spawn_test_server_with_pki(
        opts,
        pki,
        node_id,
        cert_index,
        s2s,
        Some(persistence_dir),
        Some(blob_storage_dir),
    )
    .await
}

async fn spawn_test_server_with_pki(
    opts: TestServerOpts,
    pki: Arc<Pki>,
    _node_id: u16,
    cert_index: usize,
    s2s: S2sConfig,
    s2s_persistence_dir: Option<TempDir>,
    blob_storage_dir: Option<TempDir>,
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
        blob_storage_dir: blob_storage_dir
            .as_ref()
            .map(|directory| directory.path().to_path_buf()),
        session_blob_cache_budget_bytes: 256 * 1024 * 1024,
        user_channel_cache_record_remote_sessions: opts.user_channel_cache_record_remote_sessions,
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
        // Integration tests connect hundreds of clients from 127.0.0.1 in a
        // burst; disable the per-IP/per-account auth rate limits so the
        // abuse protections never skew test outcomes.
        auth_rate_limit_per_ip_per_second: 0.0,
        auth_rate_limit_ip_burst: 0.0,
        auth_rate_limit_per_account_per_second: 0.0,
        auth_rate_limit_account_burst: 0.0,
        pending_delete_timeout_ms: 5_000,
        required_groups: Default::default(),
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
        )
        .with_allow_move_without_traverse(opts.allow_move_without_traverse)
        .with_reveal_users_in_current_and_linked_channels_without_traverse(
            opts.reveal_users_in_current_and_linked_channels_without_traverse,
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
        _blob_storage_dir: blob_storage_dir,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_replication_state_stages_only_channel_and_terminal_state() {
        let source = TempDir::new().unwrap();
        std::fs::write(source.path().join(CHANNEL_SNAPSHOT_FILE), b"snapshot").unwrap();
        std::fs::write(source.path().join(CHANNEL_WAL_FILE), b"wal").unwrap();
        std::fs::write(
            source.path().join(CHANNEL_TERMINAL_FIXTURE_FILE),
            b"terminal",
        )
        .unwrap();
        std::fs::write(source.path().join("clients.snapshot.json"), b"ignored").unwrap();

        let blob_storage = TempDir::new().unwrap();
        let s2s_persistence = TempDir::new().unwrap();
        TestStrictReplicationState::from_directory(source.path())
            .stage_into(blob_storage.path(), s2s_persistence.path())
            .unwrap();

        let mut blob_entries = std::fs::read_dir(blob_storage.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        blob_entries.sort();
        assert_eq!(
            blob_entries,
            [
                std::ffi::OsString::from(CHANNEL_SNAPSHOT_FILE),
                std::ffi::OsString::from(CHANNEL_WAL_FILE),
            ]
        );
        assert_eq!(
            std::fs::read(blob_storage.path().join(CHANNEL_SNAPSHOT_FILE)).unwrap(),
            b"snapshot"
        );
        assert_eq!(
            std::fs::read(blob_storage.path().join(CHANNEL_WAL_FILE)).unwrap(),
            b"wal"
        );

        let terminal_directory = s2s_persistence
            .path()
            .join(STRICT_TERMINAL_JOURNAL_DIRECTORY);
        let terminal_entries = std::fs::read_dir(&terminal_directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(
            terminal_entries,
            [std::ffi::OsString::from(format!(
                "topic-{}.sqlite3",
                hex::encode(CHANNEL_REPLICATION_TOPIC.as_bytes())
            ))]
        );
        assert_eq!(
            std::fs::read(terminal_directory.join(&terminal_entries[0])).unwrap(),
            b"terminal"
        );
        assert_eq!(
            std::fs::read(source.path().join(CHANNEL_SNAPSHOT_FILE)).unwrap(),
            b"snapshot"
        );
        assert_eq!(
            std::fs::read(source.path().join(CHANNEL_WAL_FILE)).unwrap(),
            b"wal"
        );
        assert_eq!(
            std::fs::read(source.path().join(CHANNEL_TERMINAL_FIXTURE_FILE)).unwrap(),
            b"terminal"
        );
        assert_eq!(
            std::fs::read(source.path().join("clients.snapshot.json")).unwrap(),
            b"ignored"
        );
    }

    #[test]
    fn strict_state_capture_writes_only_restart_fixture_files() {
        let blob_storage = TempDir::new().unwrap();
        std::fs::write(blob_storage.path().join(CHANNEL_SNAPSHOT_FILE), b"snapshot").unwrap();
        std::fs::write(blob_storage.path().join(CHANNEL_WAL_FILE), b"wal").unwrap();
        std::fs::write(blob_storage.path().join("bans.snapshot.json"), b"ignored").unwrap();

        let persistence = TempDir::new().unwrap();
        let terminal_path = persistence
            .path()
            .join(strict_channel_terminal_journal_relative_path());
        std::fs::create_dir_all(terminal_path.parent().unwrap()).unwrap();
        let terminal_connection = rusqlite::Connection::open(&terminal_path).unwrap();
        terminal_connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA wal_autocheckpoint = 0;
                 CREATE TABLE terminal_state (value TEXT NOT NULL);
                 PRAGMA wal_checkpoint(TRUNCATE);
                 INSERT INTO terminal_state VALUES ('terminal');",
            )
            .unwrap();
        assert!(
            std::fs::metadata(terminal_path.with_extension("sqlite3-wal"))
                .unwrap()
                .len()
                > 32,
            "terminal row must remain in the live WAL before capture"
        );
        std::fs::write(persistence.path().join("boot-epoch"), b"ignored").unwrap();

        let destination_root = TempDir::new().unwrap();
        let destination = destination_root.path().join("captured");
        capture_strict_state_files(blob_storage.path(), &terminal_path, &destination).unwrap();

        let mut captured_entries = std::fs::read_dir(destination)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        captured_entries.sort();
        assert_eq!(
            captured_entries,
            [
                std::ffi::OsString::from(CHANNEL_SNAPSHOT_FILE),
                std::ffi::OsString::from(CHANNEL_WAL_FILE),
                std::ffi::OsString::from(CHANNEL_TERMINAL_FIXTURE_FILE),
            ]
        );
        let captured_terminal = rusqlite::Connection::open(
            destination_root
                .path()
                .join("captured")
                .join(CHANNEL_TERMINAL_FIXTURE_FILE),
        )
        .unwrap();
        assert_eq!(
            captured_terminal
                .query_row("SELECT value FROM terminal_state", [], |row| {
                    row.get::<_, String>(0)
                })
                .unwrap(),
            "terminal"
        );
    }
}
