use std::path::Path;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::pki_types::{pem::PemObject as _, CertificateDer};
use tokio::task::JoinHandle;
use tokio::time::{self, Duration};

use crate::config::Config;
use crate::constants::MAX_NODE_ID;
use crate::types::NodeIdentifier;

use super::core::overlay::api::Overlay;
use super::core::overlay::{ClusterEvent, ClusterView, SharedClusterView};
use super::core::transport::{NetworkRuntime, Transport};
use super::core::NodeId;
use super::identity;
use super::integration::{
    BanReplicationHandler, ChannelReplicationHandler, ClientReplicationHandler,
    ReplicationDispatchContext, ReplicationEnvelope, ReplicationHandlerRegistry, RepositoryKind,
    S2SOrchestrator,
};

static BOOT_COUNTER: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Public state types
// ---------------------------------------------------------------------------
#[derive(Clone)]
pub struct S2SEnabledState {
    pub node_id: NodeIdentifier,
    pub boot_id: String,
    pub bootstrap_nodes: Vec<String>,
    pub quic_listen: Option<String>,
    pub tcp_listen: Option<String>,
    pub probe_interval_ms: u64,
    pub network_runtime: Arc<NetworkRuntime>,
    pub cluster_view: Arc<SharedClusterView>,
    pub orchestrator: S2SOrchestrator,
    pub replication_handlers: ReplicationHandlerRegistry,
}

impl std::fmt::Debug for S2SEnabledState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S2SEnabledState")
            .field("node_id", &self.node_id)
            .field("boot_id", &self.boot_id)
            .field("bootstrap_nodes", &self.bootstrap_nodes)
            .field("quic_listen", &self.quic_listen)
            .field("tcp_listen", &self.tcp_listen)
            .field("probe_interval_ms", &self.probe_interval_ms)
            .field("alive_peers", &self.cluster_view.alive_nodes_excluding_self().len())
            .field("replication_handlers", &self.replication_handlers.handler_count())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub enum S2SState {
    Enabled(Arc<S2SEnabledState>),
    Disabled(String),
}

#[derive(Debug, Clone)]
pub struct S2SManager {
    state: S2SState,
}

impl S2SManager {
    pub fn initialize(config: &Config) -> Self {
        let s2s = &config.s2s;
        if !s2s.enabled {
            return Self::disabled("S2S disabled by config".to_owned());
        }

        for (label, path) in [
            ("s2s.cert_path", s2s.cert_path.as_str()),
            ("s2s.key_path", s2s.key_path.as_str()),
            ("s2s.ca_cert_path", s2s.ca_cert_path.as_str()),
        ] {
            if !Path::new(path).exists() {
                return Self::disabled(format!(
                    "{} does not exist: {} (server continues with S2S disabled)",
                    label, path
                ));
            }
        }

        let certificate = match load_first_certificate(&s2s.cert_path) {
            Ok(cert) => cert,
            Err(err) => {
                return Self::disabled(format!(
                    "failed to parse s2s.cert_path: {} (server continues with S2S disabled)",
                    err
                ));
            }
        };

        let cert_node_id = match identity::extract_node_id_from_cert(
            certificate.as_ref(),
            &s2s.node_id_extension_oid,
        ) {
            Ok(Some(id)) => id,
            Ok(None) if s2s.require_node_id_extension => {
                return Self::disabled(format!(
                    "node-id extension {} missing in S2S certificate; S2S disabled",
                    s2s.node_id_extension_oid
                ));
            }
            Ok(None) => {
                return Self::disabled(
                    "S2S node-id extension missing and S2S identity cannot be derived".to_owned(),
                );
            }
            Err(err) => {
                return Self::disabled(format!(
                    "invalid S2S certificate node-id extension: {}",
                    err
                ));
            }
        };

        if cert_node_id > MAX_NODE_ID {
            return Self::disabled(format!(
                "S2S cert node-id out of range: {} > {}",
                cert_node_id, MAX_NODE_ID
            ));
        }

        if cert_node_id != config.node_id {
            return Self::disabled(format!(
                "S2S cert node-id {} does not match configured node_id {}",
                cert_node_id, config.node_id
            ));
        }

        let boot_id = generate_boot_id(cert_node_id);

        // Build transport and overlay.
        let (network_runtime_raw, inbound_rx) = NetworkRuntime::new(1024);
        let network_runtime = Arc::new(network_runtime_raw);
        let cluster_view = Arc::new(SharedClusterView::new(cert_node_id));
        let cluster_view_trait: Arc<dyn ClusterView> = cluster_view.clone();
        let (overlay, _raw_rx) = Overlay::new(network_runtime.clone(), cluster_view_trait);
        let _overlay_inbound_task = overlay.attach_transport_inbound(inbound_rx);
        let orchestrator = S2SOrchestrator::new(overlay);
        let replication_handlers = ReplicationHandlerRegistry::new();
        let dispatch_context = ReplicationDispatchContext::new();
        replication_handlers.register(
            RepositoryKind::Channel,
            Arc::new(ChannelReplicationHandler::new(dispatch_context.clone())),
        );
        replication_handlers.register(
            RepositoryKind::Ban,
            Arc::new(BanReplicationHandler::new(dispatch_context.clone())),
        );
        replication_handlers.register(
            RepositoryKind::Client,
            Arc::new(ClientReplicationHandler::new(dispatch_context)),
        );

        let enabled = Arc::new(S2SEnabledState {
            node_id: cert_node_id,
            boot_id: boot_id.clone(),
            bootstrap_nodes: s2s.bootstrap_nodes.clone(),
            quic_listen: s2s.quic_listen.clone(),
            tcp_listen: s2s.tcp_listen.clone(),
            probe_interval_ms: s2s.probe_interval_ms,
            network_runtime,
            cluster_view,
            orchestrator,
            replication_handlers,
        });

        tracing::info!(
            node_id = enabled.node_id,
            boot_id = %enabled.boot_id,
            bootstrap_nodes = enabled.bootstrap_nodes.len(),
            probe_interval_ms = enabled.probe_interval_ms,
            "S2S initialized"
        );

        Self {
            state: S2SState::Enabled(enabled),
        }
    }

    pub fn is_enabled(&self) -> bool {
        matches!(self.state, S2SState::Enabled(_))
    }

    pub fn state(&self) -> &S2SState {
        &self.state
    }

    pub fn log_startup_summary(&self) {
        match &self.state {
            S2SState::Enabled(state) => {
                tracing::info!(
                    node_id = state.node_id,
                    boot_id = %state.boot_id,
                    peers = state.bootstrap_nodes.len(),
                    probe_interval_ms = state.probe_interval_ms,
                    "S2S startup summary"
                );
            }
            S2SState::Disabled(reason) => {
                tracing::warn!(reason = %reason, "S2S is disabled");
            }
        }
    }

    pub fn dispatch_replication_envelope(&self, bytes: &[u8]) -> Result<(), String> {
        let S2SState::Enabled(state) = &self.state else {
            return Err("S2S is disabled".to_owned());
        };

        let envelope = ReplicationEnvelope::decode(bytes)?;
        state.replication_handlers.dispatch(envelope)
    }

    pub async fn note_peer_heartbeat(&self, node_id: NodeIdentifier, boot_id: String) {
        let S2SState::Enabled(state) = &self.state else {
            return;
        };

        if node_id == state.node_id {
            return;
        }

        state.cluster_view.mark_alive(node_id);
        state.cluster_view.set_route(node_id, node_id);
        state.cluster_view.set_direct_hop(node_id, node_id);
        state
            .orchestrator
            .overlay()
            .emit_event(ClusterEvent::MemberAlive { node: node_id, boot_id });
    }

    /// Spawns the S2S background runtime task.
    ///
    /// Currently runs a minimal heartbeat loop. Membership (SWIM), consensus
    /// (Tempo), WAL replication, and relay forwarding are not yet wired —
    /// see the limitations section.
    pub fn spawn_runtime_task(
        self: Arc<Self>,
        mut shutdown: tokio::sync::watch::Receiver<()>,
    ) -> Option<JoinHandle<()>> {
        let S2SState::Enabled(state) = self.state.clone() else {
            return None;
        };

        Some(tokio::spawn(async move {
            tracing::info!(
                node_id = state.node_id,
                boot_id = %state.boot_id,
                "S2S runtime task started (local-only mode)"
            );

            if let Some(listen) = state.quic_listen.as_deref() {
                match state.orchestrator.overlay().bind_udp_transport(listen) {
                    Ok(bound) => {
                        tracing::info!(node_id = state.node_id, udp_listen = %bound, "S2S UDP transport bound");
                    }
                    Err(err) => {
                        tracing::warn!(node_id = state.node_id, %err, "S2S UDP transport bind failed");
                    }
                }
            }

            for bootstrap in &state.bootstrap_nodes {
                if let Some((node_id, addr)) = parse_bootstrap_node(bootstrap) {
                    if let Err(err) = state.orchestrator.overlay().register_peer_addr(node_id, addr) {
                        tracing::warn!(node_id = state.node_id, peer = %bootstrap, %err, "S2S bootstrap peer registration failed");
                        continue;
                    }
                    state.cluster_view.mark_alive(node_id);
                    state.cluster_view.set_route(node_id, node_id);
                    state.cluster_view.set_direct_hop(node_id, node_id);
                    let _worker = state
                        .network_runtime
                        .register_peer_udp_worker(node_id, 1024)
                        .await;
                    state.orchestrator.overlay().emit_event(ClusterEvent::MemberAlive {
                        node: node_id,
                        boot_id: "bootstrap".to_owned(),
                    });
                } else {
                    tracing::debug!(node_id = state.node_id, peer = %bootstrap, "S2S bootstrap peer ignored (expected node@addr)");
                }
            }

            if let Err(err) = state.orchestrator.start().await {
                tracing::error!(node_id = state.node_id, %err, "S2S orchestrator start failed");
            }

            let mut ticker = time::interval(Duration::from_millis(state.probe_interval_ms.max(100)));

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        state.cluster_view.mark_alive(state.node_id);
                        state.orchestrator.overlay().emit_event(ClusterEvent::MemberAlive {
                            node: state.node_id,
                            boot_id: state.boot_id.clone(),
                        });

                        // Placeholder tick — real membership probing, transport
                        // receive/drain, and consensus ticks are still pending.
                        tracing::trace!(node_id = state.node_id, "S2S tick");
                    }
                    _ = shutdown.changed() => {
                        tracing::info!(node_id = state.node_id, "S2S runtime task stopping");
                        if let Err(err) = state.orchestrator.shutdown().await {
                            tracing::warn!(node_id = state.node_id, %err, "S2S orchestrator shutdown error");
                        }
                        break;
                    }
                }
            }
        }))
    }

    fn disabled(reason: String) -> Self {
        tracing::warn!(reason = %reason, "S2S initialization disabled");
        Self {
            state: S2SState::Disabled(reason),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn generate_boot_id(node_id: NodeId) -> String {
    let counter = BOOT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("{node_id:04x}-{ts:016x}-{counter:04x}")
}

fn load_first_certificate(pem_path: &str) -> Result<CertificateDer<'static>, String> {
    CertificateDer::pem_file_iter(pem_path)
        .map_err(|e| format!("PEM open error: {e}"))?
        .next()
        .ok_or_else(|| "no certificate found in PEM file".to_owned())?
        .map_err(|e| format!("PEM read error: {e}"))
}

fn parse_bootstrap_node(raw: &str) -> Option<(NodeId, SocketAddr)> {
    let (node_part, addr_part) = raw.split_once('@')?;
    let node_id: NodeId = node_part.parse().ok()?;
    let addr: SocketAddr = addr_part.parse().ok()?;
    Some((node_id, addr))
}
