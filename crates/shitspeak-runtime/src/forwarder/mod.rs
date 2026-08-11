use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use crate::blob_store::ChannelBlobStore;
use crate::logging;
use crate::observability::{self, S2sMetricsSource, S2sTopologyMetricsSource};
use crate::s2s::{
    BanReplicationAdapter, ChannelBlobReplicationAdapter, ChannelReplicationAdapter,
    install_channel_blob_replication_resolver, install_channel_replication_resolver,
    start_observability_geo_resolution,
};
use crate::types::{DEFAULT_SERVER_ID, NodeIdentifier};
use serde::Deserialize;
use serde::de::Error as _;
use shitspeak_runtime_config::{ObservabilityConfig, S2sConfig};
use shitspeak_s2s::overlay::{ApplicationServices, OverlayNetwork, ReplicationServices};
use shitspeak_s2s::replications::channel_topics::{
    channel_blob_topic, channel_topic, server_id_from_channel_blob_topic,
    server_id_from_channel_topic,
};
use shitspeak_s2s::replications::{
    ReplicationConfig, ReplicationManager, encode_replication_upper_layer_capabilities,
};
use shitspeak_s2s::status;
use shitspeak_s2s_transport::{ConnectionManager, TransportConfig};
use shitspeak_state::BanRepository;
use shitspeak_state::{ChannelRepoTuning, ChannelRepository, ChannelRootConfig};
use tokio::sync::watch;
use tracing::{info, warn};

#[derive(Debug, Deserialize)]
struct ForwarderConfig {
    #[serde(default)]
    register_hostname: Option<String>,
    #[serde(default)]
    s2s: S2sConfig,
    #[serde(default)]
    observability: ObservabilityConfig,
    #[serde(default)]
    replication: ForwarderReplicationConfig,
}

impl ForwarderConfig {
    fn auto_advertise_host(&self) -> Option<&str> {
        self.register_hostname
            .as_deref()
            .map(str::trim)
            .filter(|host| !host.is_empty())
    }

    fn transport_config(&self) -> Result<Option<TransportConfig>, String> {
        self.s2s
            .transport_config_with_auto_advertise_host(self.auto_advertise_host())
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
struct ForwarderReplicationConfig {
    /// Enables local replication participants and repositories. This setting
    /// does not control opaque strict-frame transit: the overlay advertises
    /// its transport capability independently, so a replication-disabled
    /// forwarder can still relay v2 frames safely.
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    storage_dir: Option<PathBuf>,
    #[serde(default)]
    repository: ForwarderReplicationRepositoryConfig,
    #[serde(default)]
    strict: ForwarderStrictReplicationConfig,
    #[serde(default, alias = "blob")]
    content: ForwarderContentReplicationConfig,
}

#[derive(Debug, Deserialize, Clone)]
struct ForwarderStrictReplicationConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(
        default = "default_strict_topics",
        deserialize_with = "deserialize_topic_list"
    )]
    topics: Vec<String>,
}

impl Default for ForwarderStrictReplicationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            topics: default_strict_topics(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
struct ForwarderContentReplicationConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(
        default = "default_content_topics",
        deserialize_with = "deserialize_topic_list"
    )]
    topics: Vec<String>,
}

impl Default for ForwarderContentReplicationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            topics: default_content_topics(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
struct ForwarderReplicationRepositoryConfig {
    #[serde(default = "default_root_channel_name")]
    root_channel_name: String,
    #[serde(default = "default_channel_log_max_entries")]
    channel_log_max_entries: usize,
    #[serde(default = "default_channel_snapshot_every_ops")]
    channel_snapshot_every_ops: u64,
    #[serde(default = "default_channel_snapshot_every_secs")]
    channel_snapshot_every_secs: i64,
    #[serde(default = "default_channel_wal_compaction_expire_count")]
    channel_wal_compaction_expire_count: usize,
}

impl Default for ForwarderReplicationRepositoryConfig {
    fn default() -> Self {
        Self {
            root_channel_name: default_root_channel_name(),
            channel_log_max_entries: default_channel_log_max_entries(),
            channel_snapshot_every_ops: default_channel_snapshot_every_ops(),
            channel_snapshot_every_secs: default_channel_snapshot_every_secs(),
            channel_wal_compaction_expire_count: default_channel_wal_compaction_expire_count(),
        }
    }
}

impl ForwarderReplicationRepositoryConfig {
    fn channel_root_config(&self) -> ChannelRootConfig {
        ChannelRootConfig::new(self.root_channel_name.clone())
    }

    fn channel_tuning(&self) -> ChannelRepoTuning {
        ChannelRepoTuning {
            log_max_entries: self.channel_log_max_entries.max(1),
            snapshot_every_ops: self.channel_snapshot_every_ops.max(1),
            snapshot_every_secs: self.channel_snapshot_every_secs.max(1),
            wal_compaction_expire_count: self.channel_wal_compaction_expire_count,
        }
    }
}

struct ResolvedForwarderReplicationConfig {
    storage_dir: PathBuf,
    services: ReplicationServices,
    strict_topics: Vec<String>,
    content_topics: Vec<String>,
}

impl ResolvedForwarderReplicationConfig {
    fn runs_manager(&self) -> bool {
        self.services.strict() || self.services.content()
    }
}

struct ForwarderRepositories {
    channels: Arc<ChannelRepository>,
    blobs: Arc<ChannelBlobStore>,
    bans: Arc<BanRepository>,
}

pub async fn run_forwarder(config_path: impl AsRef<Path>) -> Result<(), Box<dyn Error>> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let _logging_guard = logging::init("s2s-forwarder")?;

    run(config_path).await
}

async fn run(config_path: impl AsRef<Path>) -> Result<(), Box<dyn Error>> {
    let config = load_config(config_path)?;
    if !config.s2s.is_enabled() {
        return Err("s2s-forwarder requires [s2s].enabled = true".into());
    }

    let transport_config = config
        .transport_config()?
        .ok_or("s2s-forwarder requires an S2S transport config")?;

    let mut overlay_config = config.s2s.overlay_config();
    if !overlay_config.route_transit_messages() {
        warn!("s2s-forwarder forces overlay transit routing on");
        overlay_config = overlay_config.with_route_transit_messages(true);
    }
    let replication_config = config
        .replication
        .resolve(config.s2s.persistence_dir.as_deref())?;

    let (transport, inbound) = ConnectionManager::start(transport_config).await?;
    let repositories = if replication_config.runs_manager() {
        Some(
            open_forwarder_repositories(
                transport.local_node_id(),
                &replication_config.storage_dir,
                &config.replication.repository,
            )
            .await?,
        )
    } else {
        None
    };
    let initial_replication_capabilities = encode_replication_upper_layer_capabilities(
        replication_config.services.strict(),
        replication_config.services.content(),
        replication_config.services.owner(),
        0,
    );
    let overlay =
        OverlayNetwork::start_with_max_users_replication_application_and_upper_layer_capabilities(
            transport.clone(),
            inbound,
            overlay_config,
            Arc::new(AtomicU64::new(0)),
            replication_config.services,
            ApplicationServices::NONE,
            Some(initial_replication_capabilities),
        )
        .await?;
    let channel_repository = repositories
        .as_ref()
        .map(|repositories| Arc::clone(&repositories.channels));
    let replication_manager = match repositories {
        Some(repositories) => Some(start_forwarder_replications(
            overlay.clone(),
            config.s2s.replications.clone().into(),
            &replication_config,
            repositories,
        )?),
        None => None,
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let (local_geo, geo_retry_task) =
        start_observability_geo_resolution(config.s2s.geo.manual_geo(), shutdown_rx.clone());
    let mut metrics_source =
        S2sTopologyMetricsSource::new(overlay.clone(), transport.clone(), local_geo.clone());
    if let Some(channels) = channel_repository {
        metrics_source = metrics_source.with_channel_repository(channels);
    }
    let metrics_source: Arc<dyn S2sMetricsSource> = Arc::new(metrics_source);
    let status_task = config.s2s.status_http_listen.and_then(|listen| {
        match status::spawn_status_server(
            listen,
            overlay.clone(),
            transport.clone(),
            local_geo.clone(),
            shutdown_rx.clone(),
        ) {
            Ok(task) => Some(task),
            Err(error) => {
                warn!(%listen, %error, "s2s topology HTTP server startup failed");
                None
            }
        }
    });
    let observability_metrics_task = {
        let metrics = config.observability.metrics.clone();
        if metrics.enabled {
            metrics.listen.and_then(|listen| {
                match observability::spawn_metrics_server(
                    listen,
                    metrics.path.clone(),
                    metrics_source.clone(),
                    shutdown_rx.clone(),
                ) {
                    Ok(task) => Some(task),
                    Err(error) => {
                        warn!(
                            %listen,
                            %error,
                            "observability metrics HTTP server startup failed"
                        );
                        None
                    }
                }
            })
        } else {
            None
        }
    };
    let observability_remote_write_task = observability::spawn_remote_write(
        config.observability.metrics.remote_write.clone(),
        metrics_source,
        shutdown_rx.clone(),
    );

    info!(
        node = overlay.local_node_id(),
        strict_replication = replication_config.services.strict(),
        content_replication = replication_config.services.content(),
        "s2s overlay forwarder started"
    );

    let ctrl_c_result = tokio::signal::ctrl_c().await;
    match &ctrl_c_result {
        Ok(()) => info!("received Ctrl-C, shutting down s2s overlay forwarder"),
        Err(error) => warn!(%error, "Ctrl-C listener failed; shutting down s2s overlay forwarder"),
    }

    let _ = shutdown_tx.send(());
    if let Some(task) = geo_retry_task {
        let _ = task.await;
    }
    if let Some(task) = status_task {
        let _ = task.await;
    }
    if let Some(task) = observability_metrics_task {
        let _ = task.await;
    }
    if let Some(task) = observability_remote_write_task {
        let _ = task.await;
    }
    if let Some(manager) = replication_manager {
        manager.shutdown().await;
    }
    overlay.shutdown().await;
    transport.shutdown().await;

    info!("s2s overlay forwarder stopped");
    ctrl_c_result?;
    Ok(())
}

fn load_config(config_path: impl AsRef<Path>) -> Result<ForwarderConfig, Box<dyn Error>> {
    Ok(config::Config::builder()
        .add_source(config::File::from(config_path.as_ref().to_path_buf()))
        .add_source(config::Environment::with_prefix("SHITSPEAK").separator("_"))
        .build()?
        .try_deserialize()?)
}

impl ForwarderReplicationConfig {
    fn resolve(
        &self,
        s2s_persistence_dir: Option<&Path>,
    ) -> Result<ResolvedForwarderReplicationConfig, Box<dyn Error>> {
        let strict_enabled = self.enabled && self.strict.enabled;
        let content_enabled = self.enabled && self.content.enabled;
        let services = ReplicationServices::new(strict_enabled, content_enabled, false);
        let storage_dir = self
            .storage_dir
            .clone()
            .or_else(|| s2s_persistence_dir.map(|dir| dir.join("forwarder-replication")));

        if (strict_enabled || content_enabled) && storage_dir.is_none() {
            return Err(
                "s2s-forwarder replication requires replication.storage_dir or s2s.persistence_dir"
                    .into(),
            );
        }

        Ok(ResolvedForwarderReplicationConfig {
            storage_dir: storage_dir.unwrap_or_default(),
            services,
            strict_topics: normalize_topics(&self.strict.topics),
            content_topics: normalize_topics(&self.content.topics),
        })
    }
}

async fn open_forwarder_repositories(
    node_id: NodeIdentifier,
    storage_dir: &Path,
    config: &ForwarderReplicationRepositoryConfig,
) -> Result<ForwarderRepositories, Box<dyn Error>> {
    let channels = ChannelRepository::open(
        node_id,
        storage_dir,
        config.channel_root_config(),
        config.channel_tuning(),
    )
    .await?;
    let blobs = Arc::new(ChannelBlobStore::open(storage_dir).await?);
    let bans = BanRepository::open(node_id, storage_dir).await?;
    Ok(ForwarderRepositories {
        channels,
        blobs,
        bans,
    })
}

fn start_forwarder_replications(
    overlay: OverlayNetwork,
    manager_config: ReplicationConfig,
    config: &ResolvedForwarderReplicationConfig,
    repositories: ForwarderRepositories,
) -> Result<Arc<ReplicationManager>, Box<dyn Error>> {
    let manager = ReplicationManager::with_config(overlay, manager_config);
    if config.services.strict() {
        manager.set_expected_strict_topics(config.strict_topics.iter().cloned());
        let install_channel_resolver =
            register_strict_topics(&manager, &repositories, &config.strict_topics)?;
        if !manager.strict_capability_activation_ready() {
            warn!(
                expected_topics = ?config.strict_topics,
                "forwarder strict replication remains at v0 until every configured repository and its authenticated v2 frame prerequisites are ready"
            );
        }
        if install_channel_resolver {
            install_channel_replication_resolver(&manager, repositories.channels.clone());
        }
    }
    if config.services.content() {
        register_content_topics(&manager, &repositories, &config.content_topics)?;
    }
    Ok(manager)
}

fn register_strict_topics(
    manager: &Arc<ReplicationManager>,
    repositories: &ForwarderRepositories,
    topics: &[String],
) -> Result<bool, Box<dyn Error>> {
    let install_channel_resolver = topics
        .iter()
        .any(|topic| server_id_from_channel_topic(topic).is_some());
    for topic in topics {
        if topic == "bans" {
            let repo = Arc::new(BanReplicationAdapter::new(repositories.bans.clone()));
            manager.register_strict(topic.clone(), repo)?;
        } else if let Some(server_id) = server_id_from_channel_topic(topic) {
            let repo = Arc::new(ChannelReplicationAdapter::new(
                server_id,
                repositories.channels.clone(),
                None,
            ));
            manager.register_strict(topic.clone(), repo)?;
        } else {
            return Err(format!(
                "unsupported s2s-forwarder strict replication topic {topic:?}; supported topics are \"bans\", \"channels\", and \"channels:<server_id>\""
            )
            .into());
        }
    }
    Ok(install_channel_resolver)
}

fn register_content_topics(
    manager: &Arc<ReplicationManager>,
    repositories: &ForwarderRepositories,
    topics: &[String],
) -> Result<(), Box<dyn Error>> {
    if topics
        .iter()
        .any(|topic| server_id_from_channel_blob_topic(topic).is_some())
    {
        install_channel_blob_replication_resolver(
            manager,
            repositories.blobs.clone(),
            repositories.channels.clone(),
        );
    }
    for topic in topics {
        let Some(server_id) = server_id_from_channel_blob_topic(topic) else {
            return Err(format!(
                "unsupported s2s-forwarder content replication topic {topic:?}; supported topics are \"channel_blobs\" and \"channel_blobs:<server_id>\""
            )
            .into());
        };
        manager.register_blob(
            topic.clone(),
            Arc::new(ChannelBlobReplicationAdapter::new(
                server_id,
                repositories.blobs.clone(),
                repositories.channels.clone(),
            )),
        )?;
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(untagged)]
enum TopicList {
    One(String),
    Many(Vec<String>),
}

fn deserialize_topic_list<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = TopicList::deserialize(deserializer)?;
    let topics = match raw {
        TopicList::One(topic) => vec![topic],
        TopicList::Many(topics) => topics,
    };
    let topics = normalize_topics(&topics);
    if topics.is_empty() {
        return Err(D::Error::custom("topic list must not be empty"));
    }
    Ok(topics)
}

fn normalize_topics(topics: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for topic in topics {
        let topic = topic.trim();
        if !topic.is_empty() && !out.iter().any(|existing| existing == topic) {
            out.push(topic.to_owned());
        }
    }
    out
}

fn default_true() -> bool {
    true
}

fn default_strict_topics() -> Vec<String> {
    vec![channel_topic(DEFAULT_SERVER_ID), "bans".to_owned()]
}

fn default_content_topics() -> Vec<String> {
    vec![channel_blob_topic(DEFAULT_SERVER_ID)]
}

fn default_root_channel_name() -> String {
    "Root".to_owned()
}

fn default_channel_log_max_entries() -> usize {
    300
}

fn default_channel_snapshot_every_ops() -> u64 {
    10
}

fn default_channel_snapshot_every_secs() -> i64 {
    60
}

fn default_channel_wal_compaction_expire_count() -> usize {
    2_000
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_forwarder_config(raw: &str) -> ForwarderConfig {
        config::Config::builder()
            .add_source(config::File::from_str(raw, config::FileFormat::Toml))
            .build()
            .expect("forwarder config builds")
            .try_deserialize()
            .expect("forwarder config deserializes")
    }

    #[test]
    fn register_hostname_can_be_omitted() {
        let config = parse_forwarder_config(
            r#"
            [s2s]
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            tcp_listen = "0.0.0.0:64739"
            "#,
        );

        assert_eq!(config.auto_advertise_host(), None);
        let transport = config
            .transport_config()
            .expect("omitted register_hostname is accepted")
            .expect("s2s enabled");
        assert!(transport.tcp_advertise().is_empty());
    }

    #[test]
    fn register_hostname_uses_soft_implicit_s2s_advertise() {
        let config = parse_forwarder_config(
            r#"
            register_hostname = "localhost"

            [s2s]
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            tcp_listen = "0.0.0.0:64739"
            "#,
        );

        let transport = config
            .transport_config()
            .expect("unroutable register_hostname is ignored")
            .expect("s2s enabled");
        assert!(transport.tcp_advertise().is_empty());
        assert_eq!(transport.implicit_advertise_failures().len(), 1);
    }

    #[test]
    fn manual_geo_config_is_available_for_status_metrics() {
        let config = parse_forwarder_config(
            r#"
            [s2s]
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            tcp_listen = "0.0.0.0:64739"

            [s2s.geo]
            latitude = 32.7767
            longitude = -96.7970
            city = "Dallas"
            region = "TX"
            country = "US"
            source = "operator"
            "#,
        );

        let geo = config.s2s.geo.manual_geo().expect("forwarder manual geo");
        assert_eq!(geo.latitude(), 32.7767);
        assert_eq!(geo.longitude(), -96.7970);
        assert_eq!(geo.city(), Some("Dallas"));
    }

    #[test]
    fn observability_remote_write_config_is_available() {
        let config = parse_forwarder_config(
            r#"
            [s2s]
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            tcp_listen = "0.0.0.0:64739"

            [observability.metrics]
            enabled = true
            listen = "127.0.0.1:64751"
            path = "/s2s/metrics"

            [observability.metrics.remote_write]
            enabled = true
            url = "http://127.0.0.1:9009/api/v1/push"
            tenant_id = "tenant-a"
            labels = { role = "forwarder" }
            "#,
        );

        assert!(config.observability.metrics.enabled);
        assert_eq!(config.observability.metrics.path, "/s2s/metrics");
        assert!(config.observability.metrics.remote_write.enabled);
        assert_eq!(
            config.observability.metrics.remote_write.url.as_deref(),
            Some("http://127.0.0.1:9009/api/v1/push")
        );
        assert_eq!(
            config
                .observability
                .metrics
                .remote_write
                .labels
                .get("role")
                .map(String::as_str),
            Some("forwarder")
        );
    }

    #[test]
    fn replication_disabled_forwarder_needs_no_storage_or_manager() {
        let config = parse_forwarder_config(
            r#"
            [s2s]
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            tcp_listen = "0.0.0.0:64739"
            "#,
        );

        let resolved = config
            .replication
            .resolve(None)
            .expect("disabled replication does not require persistence");
        assert!(!resolved.runs_manager());
        assert!(!resolved.services.strict());
        assert!(!resolved.services.content());
    }
}
