use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::pki_types::{pem::PemObject as _, CertificateDer};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::{self, Duration};

use crate::config::Config;
use crate::constants::MAX_NODE_ID;
use crate::types::NodeIdentifier;

use super::base_consensus::{
    decode_replicated_command, encode_replicated_command, InMemoryStateEngine,
    JsonFileSnapshotStore, JsonFileWalStorage, PartitionPolicy, PartitionRole,
    ReplicatedCommand, ReplicatedStateEngine, StrictReplicationRuntime,
    StrictReplicationStorage, StrictState, TempoCore, WalFrame, WalStorage,
};
use super::identity;
use super::layer3::S2SLayer3Transport;
use super::overlay_network::{
    ApplicationLayer3Message, ClusterEnvelope, ClusterMessage, ConsensusLayer2Message,
    LinkQualitySample, MemberState, MembershipEvent, MembershipTable, MessageMode,
    NodePresenceMap, OverlayNetwork, OverlaySocketRuntime, PeerLink, RouteClass, RoutePath,
    SwimState, TransportCapabilities,
};

static BOOT_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct S2SStrictStorage {
    pub wal: JsonFileWalStorage,
    pub snapshot: JsonFileSnapshotStore,
    pub engine: InMemoryStateEngine,
}

impl StrictReplicationStorage for S2SStrictStorage {
    type Wal = JsonFileWalStorage;
    type Snapshot = JsonFileSnapshotStore;
    type Engine = InMemoryStateEngine;

    fn wal_mut(&mut self) -> &mut Self::Wal {
        &mut self.wal
    }

    fn snapshot_ref(&self) -> &Self::Snapshot {
        &self.snapshot
    }

    fn snapshot_mut(&mut self) -> &mut Self::Snapshot {
        &mut self.snapshot
    }

    fn engine_ref(&self) -> &Self::Engine {
        &self.engine
    }

    fn engine_mut(&mut self) -> &mut Self::Engine {
        &mut self.engine
    }
}

#[derive(Debug)]
pub struct S2SEnabledState {
    pub node_id: NodeIdentifier,
    pub boot_id: String,
    pub bootstrap_nodes: Vec<String>,
    pub quic_listen: Option<String>,
    pub tcp_listen: Option<String>,
    pub probe_interval_ms: u64,
    pub probe_timeout_ms: u64,
    pub suspect_timeout_ms: u64,
    pub dead_timeout_ms: u64,
    pub anti_entropy_interval_ms: u64,
    pub full_digest_interval_ms: u64,
    pub quality_stale_after_ms: u64,
    pub membership: Arc<RwLock<MembershipTable>>,
    pub node_presence: Arc<RwLock<NodePresenceMap>>,
    pub strict_runtime: Arc<RwLock<StrictReplicationRuntime>>,
    pub strict_state: Arc<RwLock<StrictState>>,
    pub partition_policy: Arc<RwLock<PartitionPolicy>>,
    pub swim_state: Arc<RwLock<SwimState>>,
    pub consensus_core: Arc<RwLock<TempoCore>>,
    pub strict_storage: Arc<RwLock<S2SStrictStorage>>,
    pub layer3_transport: Arc<S2SLayer3Transport>,
    pub layer2_outbound: Arc<RwLock<Vec<ClusterEnvelope>>>,
    pub overlay: Arc<RwLock<OverlayNetwork>>,
    pub transport_capabilities: TransportCapabilities,
    pub expected_cluster_size: usize,
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
        let now_ms = unix_ms_now();

        let mut membership = MembershipTable::new(s2s.suspect_timeout_ms, s2s.dead_timeout_ms);
        let _ = membership.upsert_alive(cert_node_id, boot_id.clone(), now_ms);

        let transport_capabilities = TransportCapabilities::default();
        let strict_wal_path = Path::new("data").join("strict_state.wal.jsonl");
        let strict_snapshot_path = Path::new("data").join("strict_state.snapshot.json");
        let expected_cluster_size = 1 + s2s.bootstrap_nodes.len();

        let enabled = Arc::new(S2SEnabledState {
            node_id: cert_node_id,
            boot_id,
            bootstrap_nodes: s2s.bootstrap_nodes.clone(),
            quic_listen: s2s.quic_listen.clone(),
            tcp_listen: s2s.tcp_listen.clone(),
            probe_interval_ms: s2s.probe_interval_ms,
            probe_timeout_ms: s2s.probe_timeout_ms,
            suspect_timeout_ms: s2s.suspect_timeout_ms,
            dead_timeout_ms: s2s.dead_timeout_ms,
            anti_entropy_interval_ms: s2s.anti_entropy_interval_ms,
            full_digest_interval_ms: s2s.full_digest_interval_ms,
            quality_stale_after_ms: s2s.quality_stale_after_ms,
            membership: Arc::new(RwLock::new(membership)),
            node_presence: Arc::new(RwLock::new(NodePresenceMap::default())),
            strict_runtime: Arc::new(RwLock::new(StrictReplicationRuntime::new(cert_node_id))),
            strict_state: Arc::new(RwLock::new(StrictState::default())),
            partition_policy: Arc::new(RwLock::new(PartitionPolicy::default())),
            swim_state: Arc::new(RwLock::new(SwimState::new(cert_node_id))),
            consensus_core: Arc::new(RwLock::new(TempoCore::new(cert_node_id))),
            strict_storage: Arc::new(RwLock::new(S2SStrictStorage {
                wal: JsonFileWalStorage::new(strict_wal_path),
                snapshot: JsonFileSnapshotStore::new(strict_snapshot_path),
                engine: InMemoryStateEngine::default(),
            })),
            layer3_transport: Arc::new(S2SLayer3Transport::new(cert_node_id)),
            layer2_outbound: Arc::new(RwLock::new(Vec::new())),
            overlay: Arc::new(RwLock::new(OverlayNetwork::new(
                cert_node_id,
                transport_capabilities.clone(),
            ))),
            transport_capabilities,
            expected_cluster_size,
        });

        enabled
            .strict_runtime
            .blocking_write()
            .update_partition_role(1, enabled.expected_cluster_size);

        tracing::info!(
            node_id = enabled.node_id,
            boot_id = %enabled.boot_id,
            bootstrap_nodes = enabled.bootstrap_nodes.len(),
            probe_interval_ms = enabled.probe_interval_ms,
            probe_timeout_ms = enabled.probe_timeout_ms,
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
                    probe_timeout_ms = state.probe_timeout_ms,
                    suspect_timeout_ms = state.suspect_timeout_ms,
                    dead_timeout_ms = state.dead_timeout_ms,
                    "S2S startup summary"
                );
            }
            S2SState::Disabled(reason) => {
                tracing::warn!(reason = %reason, "S2S is disabled");
            }
        }
    }

    pub async fn note_peer_heartbeat(&self, node_id: NodeIdentifier, boot_id: String) {
        let S2SState::Enabled(state) = &self.state else {
            return;
        };

        let now_ms = unix_ms_now();
        let events = state
            .membership
            .write()
            .await
            .upsert_alive(node_id, boot_id.clone(), now_ms);

        for event in events {
            match event {
                MembershipEvent::NodeRestarted {
                    node_id,
                    previous_boot_id,
                    new_boot_id,
                } => {
                    tracing::info!(
                        node_id,
                        previous_boot_id = %previous_boot_id,
                        new_boot_id = %new_boot_id,
                        "S2S peer restart detected"
                    );
                }
                MembershipEvent::StateChanged { node_id, from, to } => {
                    tracing::debug!(node_id, ?from, ?to, "S2S membership state changed");
                }
            }
        }
    }

    pub fn spawn_runtime_task(
        self: Arc<Self>,
        mut shutdown: tokio::sync::watch::Receiver<()>,
    ) -> Option<JoinHandle<()>> {
        let S2SState::Enabled(state) = self.state.clone() else {
            return None;
        };

        Some(tokio::spawn(async move {
            if let Err(err) = recover_strict_state(&state).await {
                tracing::error!(node_id = state.node_id, %err, "S2S strict-state recovery failed");
            }

            let overlay_runtime = match OverlaySocketRuntime::bind(
                state.node_id,
                state.quic_listen.as_deref(),
                state.tcp_listen.as_deref(),
                &state.bootstrap_nodes,
            )
            .await
            {
                Ok(runtime) => {
                    tracing::info!(
                        node_id = state.node_id,
                        quic_listen = ?state.quic_listen,
                        tcp_listen = ?state.tcp_listen,
                        bootstrap_peers = state.bootstrap_nodes.len(),
                        "S2S overlay socket runtime started"
                    );
                    Some(runtime)
                }
                Err(err) => {
                    tracing::warn!(
                        node_id = state.node_id,
                        %err,
                        "S2S overlay socket runtime disabled; running in local-only mode"
                    );
                    None
                }
            };

            let mut probe_ticker =
                time::interval(Duration::from_millis(state.probe_interval_ms.max(1)));
            let mut repair_ticker =
                time::interval(Duration::from_millis(state.anti_entropy_interval_ms.max(1)));
            let mut digest_ticker =
                time::interval(Duration::from_millis(state.full_digest_interval_ms.max(1)));

            loop {
                tokio::select! {
                    _ = probe_ticker.tick() => {
                        let now_ms = unix_ms_now();
                        let events = state.membership.write().await.tick(now_ms);
                        if !events.is_empty() {
                            let mut swim = state.swim_state.write().await;
                            for event in events {
                                match event {
                                    MembershipEvent::StateChanged { node_id, from, to } => {
                                        if to == MemberState::Dead {
                                            tracing::warn!(
                                                node_id,
                                                ?from,
                                                ?to,
                                                "S2S member marked dead"
                                            );
                                        } else {
                                            tracing::debug!(node_id, ?from, ?to, "S2S membership transition");
                                        }
                                        swim.record_membership_state(node_id, to, 0);
                                    }
                                    MembershipEvent::NodeRestarted { node_id, previous_boot_id, new_boot_id } => {
                                        tracing::info!(
                                            node_id,
                                            previous_boot_id = %previous_boot_id,
                                            new_boot_id = %new_boot_id,
                                            "S2S member restart processed"
                                        );
                                    }
                                }
                            }
                        }

                        let overdue = state
                            .swim_state
                            .read()
                            .await
                            .overdue_probes(now_ms, state.probe_timeout_ms);
                        if !overdue.is_empty() {
                            let helpers = state.membership.read().await.alive_nodes();
                            let swim = state.swim_state.read().await;
                            for (seq, target) in overdue {
                                let requests = swim.build_indirect_requests(seq, target, &helpers);
                                tracing::trace!(
                                    node_id = state.node_id,
                                    target,
                                    sequence = seq,
                                    helpers = requests.len(),
                                    "S2S indirect probe requests scheduled"
                                );
                            }
                        }

                        let purged = state
                            .membership
                            .write()
                            .await
                            .purge_expired_tombstones(now_ms, 60_000);
                        if !purged.is_empty() {
                            tracing::trace!(
                                node_id = state.node_id,
                                purged = purged.len(),
                                "S2S tombstones purged"
                            );
                        }

                        if let Some(runtime) = &overlay_runtime {
                            if let Err(err) = drain_overlay_incoming(runtime, &state, now_ms).await {
                                tracing::trace!(node_id = state.node_id, %err, "S2S overlay inbound processing failed");
                            }

                            if let Err(err) = broadcast_overlay_heartbeat(runtime, &state).await {
                                tracing::trace!(node_id = state.node_id, %err, "S2S heartbeat broadcast failed");
                            }

                            if let Err(err) = flush_layer3_overlay_outbound(runtime, &state).await {
                                tracing::trace!(node_id = state.node_id, %err, "S2S layer3 overlay flush failed");
                            }

                            if let Err(err) = flush_layer2_overlay_outbound(runtime, &state).await {
                                tracing::trace!(node_id = state.node_id, %err, "S2S layer2 overlay flush failed");
                            }
                        }
                    }
                    _ = repair_ticker.tick() => {
                        let alive_nodes = state.membership.read().await.alive_nodes();
                        let probe_plan = state.swim_state.write().await.next_probe_plan(&alive_nodes, 3);
                        let digest = state.node_presence.read().await.digest();
                        let reconcile = state.node_presence.read().await.stale_nodes_against(&digest);
                        let transport_pair = state.overlay.read().await.choose_transport_for_class(RouteClass::ReliableLowLatency);
                        tracing::trace!(
                            node_id = state.node_id,
                            alive_nodes = alive_nodes.len(),
                            probe_target = ?probe_plan.direct_target,
                            digest_entries = digest.len(),
                            reconcile_deltas = reconcile.len(),
                            has_transport_pair = transport_pair.is_some(),
                            "S2S anti-entropy repair tick"
                        );
                    }
                    _ = digest_ticker.tick() => {
                        let alive = state.membership.read().await.alive_nodes().len();

                        let (role, partition_mode) = {
                            let mut runtime = state.strict_runtime.write().await;
                            let role = runtime.update_partition_role(alive, state.expected_cluster_size);
                            (role, runtime.partition_policy.strict_state_mode())
                        };

                        state.partition_policy.write().await.set_role(role);
                        state.strict_state.write().await.set_mode(partition_mode);

                        if role == PartitionRole::Majority {
                            if let Err(err) = compact_strict_state_if_needed(&state).await {
                                tracing::error!(node_id = state.node_id, %err, "S2S strict-state snapshot compaction failed");
                            }
                        }

                        tracing::trace!(
                            node_id = state.node_id,
                            alive_nodes = alive,
                            ?role,
                            ?partition_mode,
                            "S2S full digest tick"
                        );
                    }
                    _ = shutdown.changed() => {
                        tracing::info!(node_id = state.node_id, "S2S runtime task stopping");
                        break;
                    }
                }
            }
        }))
    }

    pub async fn submit_strict_command(
        &self,
        command: ReplicatedCommand,
    ) -> Result<WalFrame<ReplicatedCommand>, String> {
        let S2SState::Enabled(state) = &self.state else {
            return Err("S2S disabled".to_owned());
        };

        let mut runtime = state.strict_runtime.write().await;
        let mut strict_storage = state.strict_storage.write().await;

        let frame = runtime.propose_with_storage(command, &mut *strict_storage)?;

        {
            let mut strict_state = state.strict_state.write().await;
            strict_state.applied_index = frame.index;
            strict_state.set_mode(runtime.strict_state.mode);
        }

        {
            let mut consensus = state.consensus_core.write().await;
            *consensus = runtime.tempo.clone();
        }

        enqueue_layer2_replication_frame(state, &frame).await?;

        Ok(frame)
    }

    pub async fn apply_remote_committed_frames(
        &self,
        mut frames: Vec<WalFrame<ReplicatedCommand>>,
    ) -> Result<usize, String> {
        let S2SState::Enabled(state) = &self.state else {
            return Err("S2S disabled".to_owned());
        };
        apply_committed_frames_to_state(state, &mut frames).await
    }

    fn disabled(reason: String) -> Self {
        tracing::warn!(reason = %reason, "S2S initialization disabled");
        Self {
            state: S2SState::Disabled(reason),
        }
    }
}

async fn drain_overlay_incoming(
    runtime: &OverlaySocketRuntime,
    state: &Arc<S2SEnabledState>,
    now_ms: u64,
) -> Result<(), String> {
    let inbound = runtime.drain_incoming(256).await;
    for packet in inbound {
        runtime.register_peer_addr(packet.source).await;

        let from = packet.envelope.from;
        let allowed = state
            .overlay
            .write()
            .await
            .allow_incoming_frame(from, packet.frame_len, now_ms);
        if !allowed {
            continue;
        }

        state.overlay.write().await.update_link(PeerLink {
            node_id: from,
            path: RoutePath::Direct { target: from },
            quality: LinkQualitySample {
                latency_ms: 1.0,
                jitter_ms: 0.0,
                loss_ratio: 0.0,
                bandwidth_kbps: 10_000.0,
                updated_at_ms: now_ms,
            },
        });

        let message = packet.envelope.body;
        match message {
            ClusterMessage::Heartbeat { boot_id, .. } => {
                let events = state
                    .membership
                    .write()
                    .await
                    .upsert_alive(from, boot_id, now_ms);
                if !events.is_empty() {
                    let mut swim = state.swim_state.write().await;
                    for event in events {
                        if let MembershipEvent::StateChanged { node_id, to, .. } = event {
                            swim.record_membership_state(node_id, to, 0);
                        }
                    }
                }
            }
            ClusterMessage::MembershipUpdate { record } => match record.state {
                MemberState::Alive | MemberState::Suspect => {
                    let _ = state.membership.write().await.upsert_alive(
                        record.node_id,
                        record.boot_id,
                        record.last_seen_ms,
                    );
                }
                MemberState::Dead | MemberState::Left => {
                    let _ = state.membership.write().await.mark_left(record.node_id);
                }
            },
            ClusterMessage::NodePresence { delta } => {
                state.node_presence.write().await.apply_delta(delta);
            }
            ClusterMessage::PeerList { peers } => {
                for peer in peers {
                    if let Ok(addr) = peer.parse() {
                        runtime.register_peer_addr(addr).await;
                    }
                }
            }
            ClusterMessage::DataForward { .. } => {
                tracing::trace!(node_id = state.node_id, from, "S2S data-forward frame received");
            }
            ClusterMessage::Layer2 { message } => {
                if let Err(err) = handle_layer2_consensus_message(state, from, message).await {
                    tracing::trace!(
                        node_id = state.node_id,
                        from,
                        %err,
                        "S2S layer2 inbound message apply failed"
                    );
                }
            }
        }
    }

    Ok(())
}

async fn handle_layer2_consensus_message(
    state: &Arc<S2SEnabledState>,
    from: NodeIdentifier,
    message: ConsensusLayer2Message,
) -> Result<(), String> {
    match message {
        ConsensusLayer2Message::ReplicatedFrame {
            index,
            term,
            payload,
        } => {
            let command = decode_replicated_command(&payload)?;
            let mut frames = vec![WalFrame {
                index,
                term,
                payload: command,
            }];
            let applied = apply_committed_frames_to_state(state, &mut frames).await?;
            tracing::trace!(
                node_id = state.node_id,
                from,
                index,
                term,
                applied,
                "S2S layer2 replicated frame processed"
            );
        }
        ConsensusLayer2Message::Layer3 { message } => {
            handle_layer3_application_message(state, message).await?;
        }
    }
    Ok(())
}

async fn apply_committed_frames_to_state(
    state: &Arc<S2SEnabledState>,
    frames: &mut Vec<WalFrame<ReplicatedCommand>>,
) -> Result<usize, String> {
    frames.sort_by_key(|f| f.index);
    let mut applied = 0_usize;

    let mut runtime = state.strict_runtime.write().await;
    let mut strict_storage = state.strict_storage.write().await;

    for frame in frames.iter() {
        if frame.index <= runtime.tempo.committed_index {
            continue;
        }

        let payload = serde_json::to_vec(&frame.payload)
            .map_err(|e| format!("encode remote strict frame failed: {e}"))?;
        strict_storage.wal.append_frame(frame.index, frame.term, &payload)?;
        strict_storage.engine.apply_committed(frame.index, &payload)?;

        runtime.strict_state.applied_index = runtime.strict_state.applied_index.max(frame.index);
        runtime.tempo.observe_remote_index(frame.index);
        applied = applied.saturating_add(1);
    }

    {
        let mut strict_state = state.strict_state.write().await;
        strict_state.applied_index = runtime.strict_state.applied_index;
        strict_state.set_mode(runtime.strict_state.mode);
    }

    {
        let mut consensus = state.consensus_core.write().await;
        *consensus = runtime.tempo.clone();
    }

    Ok(applied)
}

async fn handle_layer3_application_message(
    state: &Arc<S2SEnabledState>,
    message: ApplicationLayer3Message,
) -> Result<(), String> {
    let _ = state.layer3_transport.ingest_layer3_message(message).await?;
    Ok(())
}

async fn broadcast_overlay_heartbeat(
    runtime: &OverlaySocketRuntime,
    state: &Arc<S2SEnabledState>,
) -> Result<(), String> {
    let members_seen = state.membership.read().await.alive_nodes().len();
    let envelope = ClusterEnvelope {
        version: 1,
        feature_bitmap: 0,
        from: state.node_id,
        seq: unix_ms_now(),
        mode: MessageMode::Broadcast,
        body: ClusterMessage::Heartbeat {
            boot_id: state.boot_id.clone(),
            members_seen,
        },
    };

    let selected = state
        .overlay
        .read()
        .await
        .choose_transport_for_class(RouteClass::ReliableLowLatency);
    let _ = runtime
        .send_envelope(&envelope, RouteClass::ReliableLowLatency, selected)
        .await?;
    Ok(())
}

async fn flush_layer3_overlay_outbound(
    runtime: &OverlaySocketRuntime,
    state: &Arc<S2SEnabledState>,
) -> Result<(), String> {
    let envelopes = state.layer3_transport.drain_outbound_envelopes().await;
    if envelopes.is_empty() {
        return Ok(());
    }

    let selected = state
        .overlay
        .read()
        .await
        .choose_transport_for_class(RouteClass::ReliableLowLatency);

    for envelope in envelopes {
        let _ = runtime
            .send_envelope(&envelope, RouteClass::ReliableLowLatency, selected)
            .await?;
    }

    Ok(())
}

async fn enqueue_layer2_replication_frame(
    state: &Arc<S2SEnabledState>,
    frame: &WalFrame<ReplicatedCommand>,
) -> Result<(), String> {
    let payload = encode_replicated_command(&frame.payload)?;
    let envelope = ClusterEnvelope {
        version: 1,
        feature_bitmap: 0,
        from: state.node_id,
        seq: unix_ms_now(),
        mode: MessageMode::Broadcast,
        body: ClusterMessage::Layer2 {
            message: ConsensusLayer2Message::ReplicatedFrame {
                index: frame.index,
                term: frame.term,
                payload,
            },
        },
    };

    state.layer2_outbound.write().await.push(envelope);
    Ok(())
}

async fn flush_layer2_overlay_outbound(
    runtime: &OverlaySocketRuntime,
    state: &Arc<S2SEnabledState>,
) -> Result<(), String> {
    let envelopes = {
        let mut out = state.layer2_outbound.write().await;
        std::mem::take(&mut *out)
    };

    if envelopes.is_empty() {
        return Ok(());
    }

    let selected = state
        .overlay
        .read()
        .await
        .choose_transport_for_class(RouteClass::Reliable);

    for envelope in envelopes {
        let _ = runtime
            .send_envelope(&envelope, RouteClass::Reliable, selected)
            .await?;
    }

    Ok(())
}

fn load_first_certificate(path: &str) -> Result<CertificateDer<'static>, String> {
    let mut iter = CertificateDer::pem_file_iter(path).map_err(|e| e.to_string())?;
    match iter.next() {
        Some(Ok(cert)) => Ok(cert),
        Some(Err(err)) => Err(err.to_string()),
        None => Err("certificate file is empty".to_owned()),
    }
}

fn generate_boot_id(node_id: NodeIdentifier) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let counter = BOOT_COUNTER.fetch_add(1, Ordering::Relaxed) as u128;
    let pid = std::process::id() as u128;
    format!("{:x}-{:03x}-{:x}", now, node_id, counter ^ pid)
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

async fn recover_strict_state(state: &Arc<S2SEnabledState>) -> Result<(), String> {
    {
        let mut runtime = state.strict_runtime.write().await;
        let mut strict_storage = state.strict_storage.write().await;
        let restored = runtime.install_snapshot_from_storage(&mut *strict_storage)?;
        if let Some(index) = restored {
            tracing::info!(
                node_id = state.node_id,
                restored_index = index,
                "S2S strict-state restored from snapshot"
            );
        }
    }

    {
        let mut runtime = state.strict_runtime.write().await;
        let frames = {
            let strict_storage = state.strict_storage.read().await;
            strict_storage.wal.read_all_frames()?
        };
        let mut strict_storage = state.strict_storage.write().await;
        let restored = runtime.replay_wal(&frames, &mut strict_storage.engine)?;
        if restored > 0 {
            tracing::info!(
                node_id = state.node_id,
                restored_frames = restored,
                commit_index = runtime.tempo.committed_index,
                "S2S strict-state replayed from WAL"
            );
        }
    }

    {
        let runtime = state.strict_runtime.read().await;
        let mut strict_state = state.strict_state.write().await;
        strict_state.applied_index = runtime.strict_state.applied_index;
        strict_state.set_mode(runtime.strict_state.mode);
    }

    {
        let runtime = state.strict_runtime.read().await;
        let mut consensus = state.consensus_core.write().await;
        *consensus = runtime.tempo.clone();
    }

    Ok(())
}

async fn compact_strict_state_if_needed(state: &Arc<S2SEnabledState>) -> Result<(), String> {
    let should_compact = {
        let strict_state = state.strict_state.read().await;
        let consensus = state.consensus_core.read().await;
        strict_state.applied_index > 0 && consensus.committed_ops > 0 && consensus.committed_ops % 64 == 0
    };

    if !should_compact {
        return Ok(());
    }

    let mut runtime = state.strict_runtime.write().await;
    let mut strict_storage = state.strict_storage.write().await;

    if let Some(last_index) = runtime.compact_with_storage(&mut *strict_storage)? {
        tracing::trace!(
            node_id = state.node_id,
            snapshot_index = last_index,
            "S2S strict-state compacted to snapshot"
        );
    }

    Ok(())
}
