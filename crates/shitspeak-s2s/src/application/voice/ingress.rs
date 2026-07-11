//! Inbound `VoiceFrame` decode + central dispatch task, and the
//! speaker-side public API (`VoiceService`).
//!
//! The dispatch task decodes `VoiceFrame`s, applies the reorder gate, and
//! hands emitted frames to the installed audio sink. The speaker-side API
//! wraps already-encoded audio payloads with unresolved routing intent.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use parking_lot::RwLock;
use scc::HashMap as SccMap;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::trace;

use crate::application::config::{DeliveryStrategy, VoiceConfig};
use crate::application::error::ApplicationError;
use crate::application::proto::{
    self, VoiceFrame, VoiceIntent, VoiceIntentKind, VoiceIntentNormal, VoiceRepairRequest,
};
use crate::application::voice::metrics;
use crate::application::voice::metrics::{
    VoiceReceiveResult, VoiceRepairResult, VoiceSendMode, VoiceSendResult,
};
use crate::application::voice::reorder::{self, GapReport, Reorderer, VoiceRouteHint};
use crate::application::voice::repair::{RepairCache, RepairFrame};
use crate::application::voice::send::{self, OverlayVoiceTransport, VoiceTransport};
use crate::application::voice::sink::AudioSink;
use crate::application::voice::targeted::{RecipientIndex, RemoteNodeLookup};
use crate::overlay::{OverlayInboundMessage, OverlayNetwork, ServiceInbound};
use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::TransportKind;

type AudioSinkSlot = Arc<RwLock<Option<Arc<dyn AudioSink>>>>;
type RecipientIndexSlot = Arc<RwLock<Option<Arc<RecipientIndex>>>>;

const ADAPTIVE_REPAIR_CACHE_MARGIN_MS: u64 = 80;
const DISTANT_REPAIR_PATH_LATENCY_US: u64 = 150_000;

/// Decoded inbound voice frame along with the immediate sender (next-hop
/// peer that delivered the overlay frame, not necessarily the originator).
#[derive(Debug, Clone)]
pub struct VoiceDelivery {
    pub from: NodeIdentifier,
    pub frame: VoiceFrame,
}

/// Multiplexed event the dispatch task drains. Inbound frames feed
/// through the reorder gate; deadline fires drain the gate's expired
/// pending. Routing both through one mpsc keeps `AudioSink::deliver`
/// calls strictly serialized.
#[derive(Debug)]
enum DispatchEvent {
    Inbound(VoiceDelivery),
    DeadlineFired,
}

/// Central handle for the voice L3 service.
///
/// Owns:
/// * the inbound mpsc + dispatch task (receiver side),
/// * the outbound `VoiceTransport` (sender side),
/// * the per-(sender_session) sequence counter,
/// * the swappable [`AudioSink`] the dispatch task delivers to.
///
/// `sender_epoch` is captured once at construction from the overlay's
/// `local_boot_epoch`, since it's stable for the process lifetime.
pub struct VoiceService {
    transport: Arc<dyn VoiceTransport>,
    cfg: VoiceConfig,
    _shutdown: CancellationToken,
    inbox_tx: mpsc::UnboundedSender<DispatchEvent>,

    /// Set once at construction from the overlay's `local_boot_epoch`.
    sender_epoch: u64,

    /// Per-local-sender-session monotonic counter for `s2s_seq`. Keyed
    /// by composite `ClientSessionIdentifier::to_u32()`.
    seq_counters: Arc<SccMap<u32, AtomicU64>>,

    /// Receiver-side delivery callback. Hot-swappable so the `Server`
    /// can install its sink after construction. `None` until set —
    /// frames are decoded and dropped (with a trace) until then.
    audio_sink: AudioSinkSlot,

    /// Per-(sender, epoch) reorder gate.
    _reorderer: Arc<Reorderer>,

    /// Recently-originated voice frames available for best-effort repair.
    repair_cache: Arc<RepairCache>,

    /// Resolved delivery strategy parsed from config (cached).
    delivery_strategy: DeliveryStrategy,

    /// Channel→nodes index used by `send_for_channel` under the
    /// `"targeted"` strategy. `None` until populated; targeted mode
    /// degrades to broadcast when the index is empty.
    recipient_index: RecipientIndexSlot,
}

impl VoiceService {
    pub fn new(
        overlay: OverlayNetwork,
        cfg: VoiceConfig,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        let sender_epoch = overlay.local_boot_epoch();
        let transport: Arc<dyn VoiceTransport> = Arc::new(OverlayVoiceTransport { overlay });
        Self::new_with_transport(transport, cfg, shutdown, sender_epoch)
    }

    /// Constructor used by unit tests to inject a fake transport.
    pub fn new_with_transport(
        transport: Arc<dyn VoiceTransport>,
        cfg: VoiceConfig,
        shutdown: CancellationToken,
        sender_epoch: u64,
    ) -> Arc<Self> {
        let (inbox_tx, inbox_rx) = mpsc::unbounded_channel::<DispatchEvent>();
        let audio_sink: AudioSinkSlot = Arc::new(RwLock::new(None));
        let reorderer = Reorderer::new(cfg.clone());
        let repair_cache = Arc::new(RepairCache::new(Duration::from_millis(cfg.repair_cache_ms)));
        spawn_dispatch_task(
            inbox_rx,
            shutdown.clone(),
            audio_sink.clone(),
            reorderer.clone(),
            transport.clone(),
            cfg.clone(),
        );
        let nudge_tx = inbox_tx.clone();
        reorder::spawn_deadline_task(reorderer.clone(), shutdown.clone(), move || {
            let _ = nudge_tx.send(DispatchEvent::DeadlineFired);
        });
        let delivery_strategy = DeliveryStrategy::parse(&cfg.delivery_strategy);
        Arc::new(Self {
            transport,
            cfg,
            _shutdown: shutdown,
            inbox_tx,
            sender_epoch,
            seq_counters: Arc::new(SccMap::new()),
            audio_sink,
            _reorderer: reorderer,
            repair_cache,
            delivery_strategy,
            recipient_index: Arc::new(RwLock::new(None)),
        })
    }

    pub fn delivery_strategy(&self) -> DeliveryStrategy {
        self.delivery_strategy
    }

    /// Install (or replace) the recipient index used by targeted mode.
    /// No-op for broadcast mode (the index is consulted only when
    /// `delivery_strategy == Targeted`).
    pub fn set_recipient_index(&self, index: Arc<RecipientIndex>) {
        *self.recipient_index.write() = Some(index);
    }

    pub fn clear_recipient_index(&self) {
        *self.recipient_index.write() = None;
    }

    /// Install (or replace) the receiver-side delivery sink. The
    /// dispatch task picks up the new sink on its next inbound frame.
    pub fn set_audio_sink(&self, sink: Arc<dyn AudioSink>) {
        *self.audio_sink.write() = Some(sink);
    }

    /// Remove any installed sink. Subsequent frames are decoded and
    /// dropped until a new sink is installed.
    pub fn clear_audio_sink(&self) {
        *self.audio_sink.write() = None;
    }

    /// `ServiceInbound` impl that decodes envelope bytes and pushes onto
    /// the central dispatch mpsc.
    pub fn inbound_handler(&self) -> Arc<dyn ServiceInbound> {
        Arc::new(VoiceInbound {
            inbox_tx: self.inbox_tx.clone(),
        })
    }

    pub fn repair_inbound_handler(&self) -> Arc<dyn ServiceInbound> {
        Arc::new(VoiceRepairInbound {
            transport: self.transport.clone(),
            cfg: self.cfg.clone(),
            repair_cache: self.repair_cache.clone(),
        })
    }

    pub fn config(&self) -> &VoiceConfig {
        &self.cfg
    }

    pub fn local_node_id(&self) -> NodeIdentifier {
        self.transport.local_node_id()
    }

    /// Allocate the next monotonic `s2s_seq` for `sender_session`. Per
    /// the wire-envelope contract, this is independent of the in-payload
    /// Mumble `frame_number`.
    pub fn next_seq(&self, sender_session: u32) -> u64 {
        self.seq_counters
            .entry_sync(sender_session)
            .or_insert_with(|| AtomicU64::new(0))
            .get()
            .fetch_add(1, Ordering::Relaxed)
    }

    /// Reset the per-session counter when a local client disconnects.
    /// Optional; harmless to skip — the counter just stays around.
    pub fn drop_session(&self, sender_session: u32) {
        let _ = self.seq_counters.remove_sync(&sender_session);
    }

    /// Broadcast a voice frame to every alive node (other than self).
    /// `payload` is the already-encoded UDP audio body — receivers do
    /// not re-encode, they hand it directly to local fan-out.
    pub async fn send_broadcast(
        &self,
        sender_session: u32,
        server_id: String,
        target_kind: u32,
        is_terminator: bool,
        payload: Bytes,
        intent: VoiceIntent,
    ) -> Result<(), ApplicationError> {
        let dsts = self.remote_voice_members();
        if dsts.is_empty() {
            metrics::record_send(
                self.transport.local_node_id(),
                VoiceSendMode::Broadcast,
                0,
                payload.len(),
                VoiceSendResult::Noop,
            );
            return Ok(());
        }
        let (bytes, seq) = self.encode(
            sender_session,
            server_id,
            target_kind,
            is_terminator,
            payload,
            intent,
        )?;
        let result = self
            .transport
            .send_multicast(&dsts, bytes.clone(), self.cfg.transport_ttl())
            .await;
        metrics::record_send(
            self.transport.local_node_id(),
            VoiceSendMode::Broadcast,
            dsts.len(),
            bytes.len(),
            if result.is_ok() {
                VoiceSendResult::Sent
            } else {
                VoiceSendResult::Failed
            },
        );
        self.cache_and_send_proactive_repairs(sender_session, seq, bytes, &dsts)
            .await;
        result?;
        Ok(())
    }

    /// Multicast to a specific node set (used by whisper-to-direct-session
    /// and by the opt-in `"targeted"` mode).
    pub async fn send_multicast(
        &self,
        sender_session: u32,
        server_id: String,
        target_kind: u32,
        is_terminator: bool,
        payload: Bytes,
        intent: VoiceIntent,
        dsts: &[NodeIdentifier],
    ) -> Result<(), ApplicationError> {
        if dsts.is_empty() {
            metrics::record_send(
                self.transport.local_node_id(),
                VoiceSendMode::Multicast,
                0,
                payload.len(),
                VoiceSendResult::Noop,
            );
            return Ok(());
        }
        let (bytes, seq) = self.encode(
            sender_session,
            server_id,
            target_kind,
            is_terminator,
            payload,
            intent,
        )?;
        let result = self
            .transport
            .send_multicast(dsts, bytes.clone(), self.cfg.transport_ttl())
            .await;
        metrics::record_send(
            self.transport.local_node_id(),
            VoiceSendMode::Multicast,
            dsts.len(),
            bytes.len(),
            if result.is_ok() {
                VoiceSendResult::Sent
            } else {
                VoiceSendResult::Failed
            },
        );
        self.cache_and_send_proactive_repairs(sender_session, seq, bytes, dsts)
            .await;
        result?;
        Ok(())
    }

    /// Channel-aware send: routes the frame according to the
    /// configured `delivery_strategy`.
    ///
    /// * `Broadcast` — calls `send_broadcast` (overlay broadcast to
    ///   every alive peer; receivers filter locally).
    /// * `Targeted` — looks up `channel_id` in the recipient index
    ///   and multicasts to the resulting node set (excluding self).
    ///   Falls back to broadcast when the index has no entry for
    ///   the channel (cold start, sparse population).
    ///
    /// `channel_id` is the speaker's *current* channel id — the same
    /// channel that drives local fan-out's "in same channel?" check.
    pub async fn send_for_channel(
        &self,
        sender_session: u32,
        server_id: String,
        channel_id: u32,
        is_terminator: bool,
        payload: Bytes,
    ) -> Result<(), ApplicationError> {
        let payload_len = payload.len();
        let intent = normal_intent(channel_id);
        match self.delivery_strategy {
            DeliveryStrategy::Broadcast => {
                self.send_broadcast(sender_session, server_id, 0, is_terminator, payload, intent)
                    .await
            }
            DeliveryStrategy::Targeted => {
                let local = self.transport.local_node_id();
                let lookup = self.recipient_index.read().as_ref().map(|idx| {
                    idx.lookup_remote_nodes_for_in_server(&server_id, channel_id, local)
                });
                match lookup {
                    Some(RemoteNodeLookup::Nodes(dsts)) => {
                        if dsts.is_empty() {
                            // Index exists but only the speaker is in the
                            // channel; nothing to do for cross-node delivery.
                            metrics::record_send(
                                self.transport.local_node_id(),
                                VoiceSendMode::TargetedNoop,
                                0,
                                payload_len,
                                VoiceSendResult::Noop,
                            );
                            return Ok(());
                        }
                        let result = self
                            .send_multicast(
                                sender_session,
                                server_id,
                                0,
                                is_terminator,
                                payload,
                                intent,
                                &dsts,
                            )
                            .await;
                        metrics::record_send(
                            self.transport.local_node_id(),
                            VoiceSendMode::Targeted,
                            dsts.len(),
                            payload_len,
                            if result.is_ok() {
                                VoiceSendResult::Sent
                            } else {
                                VoiceSendResult::Failed
                            },
                        );
                        result
                    }
                    Some(RemoteNodeLookup::Missing { .. }) | None => {
                        // No index entry yet — degrade safely to broadcast.
                        trace!(
                            server_id = %server_id,
                            channel_id,
                            "voice targeted: no index entry; falling back to broadcast"
                        );
                        let result = self
                            .send_broadcast(
                                sender_session,
                                server_id,
                                0,
                                is_terminator,
                                payload,
                                intent,
                            )
                            .await;
                        metrics::record_send(
                            self.transport.local_node_id(),
                            VoiceSendMode::TargetedFallback,
                            0,
                            payload_len,
                            if result.is_ok() {
                                VoiceSendResult::Sent
                            } else {
                                VoiceSendResult::Failed
                            },
                        );
                        result
                    }
                }
            }
        }
    }

    /// Channel-aware send that preserves the original target kind and intent
    /// while reusing the targeted delivery strategy's recipient-index
    /// multicast path. Normal speech may supply its source channel together
    /// with Speak-authorized linked channels.
    pub async fn send_for_target_channels(
        &self,
        sender_session: u32,
        server_id: String,
        channel_ids: Arc<[u32]>,
        target_kind: u32,
        is_terminator: bool,
        payload: Bytes,
        intent: VoiceIntent,
    ) -> Result<(), ApplicationError> {
        let payload_len = payload.len();
        match self.delivery_strategy {
            DeliveryStrategy::Broadcast => {
                self.send_broadcast(
                    sender_session,
                    server_id,
                    target_kind,
                    is_terminator,
                    payload,
                    intent,
                )
                .await
            }
            DeliveryStrategy::Targeted => {
                let local = self.transport.local_node_id();
                let voice_members = self.remote_voice_members();
                let lookup = self.recipient_index.read().as_ref().map(|idx| {
                    if channel_ids.is_empty() {
                        idx.lookup_remote_nodes_for_server_in_server(
                            &server_id,
                            local,
                            &voice_members,
                        )
                    } else {
                        idx.lookup_remote_nodes_for_complete_shared_channels_in_server(
                            &server_id,
                            channel_ids.clone(),
                            local,
                            &voice_members,
                        )
                    }
                });
                let dsts = match lookup {
                    Some(RemoteNodeLookup::Nodes(dsts)) => dsts,
                    Some(RemoteNodeLookup::Missing { channel_id }) => {
                        trace!(
                            server_id = %server_id,
                            channel_id,
                            "voice targeted: incomplete target channel index; falling back to broadcast"
                        );
                        let result = self
                            .send_broadcast(
                                sender_session,
                                server_id,
                                target_kind,
                                is_terminator,
                                payload,
                                intent,
                            )
                            .await;
                        metrics::record_send(
                            self.transport.local_node_id(),
                            VoiceSendMode::TargetedFallback,
                            0,
                            payload_len,
                            if result.is_ok() {
                                VoiceSendResult::Sent
                            } else {
                                VoiceSendResult::Failed
                            },
                        );
                        return result;
                    }
                    None => {
                        let channel_id = channel_ids.first().copied().unwrap_or(0);
                        trace!(
                            server_id = %server_id,
                            channel_id,
                            "voice targeted: incomplete target channel index; falling back to broadcast"
                        );
                        let result = self
                            .send_broadcast(
                                sender_session,
                                server_id,
                                target_kind,
                                is_terminator,
                                payload,
                                intent,
                            )
                            .await;
                        metrics::record_send(
                            self.transport.local_node_id(),
                            VoiceSendMode::TargetedFallback,
                            0,
                            payload_len,
                            if result.is_ok() {
                                VoiceSendResult::Sent
                            } else {
                                VoiceSendResult::Failed
                            },
                        );
                        return result;
                    }
                };
                if dsts.is_empty() {
                    metrics::record_send(
                        self.transport.local_node_id(),
                        VoiceSendMode::TargetedNoop,
                        0,
                        payload_len,
                        VoiceSendResult::Noop,
                    );
                    return Ok(());
                }
                let result = self
                    .send_multicast(
                        sender_session,
                        server_id,
                        target_kind,
                        is_terminator,
                        payload,
                        intent,
                        &dsts,
                    )
                    .await;
                metrics::record_send(
                    self.transport.local_node_id(),
                    VoiceSendMode::Targeted,
                    dsts.len(),
                    payload_len,
                    if result.is_ok() {
                        VoiceSendResult::Sent
                    } else {
                        VoiceSendResult::Failed
                    },
                );
                result
            }
        }
    }

    pub async fn send_for_server(
        &self,
        sender_session: u32,
        server_id: String,
        target_kind: u32,
        is_terminator: bool,
        payload: Bytes,
        intent: VoiceIntent,
    ) -> Result<(), ApplicationError> {
        self.send_for_target_channels(
            sender_session,
            server_id,
            Arc::from([]),
            target_kind,
            is_terminator,
            payload,
            intent,
        )
        .await
    }

    /// Unicast to a single peer.
    pub async fn send_unicast(
        &self,
        sender_session: u32,
        server_id: String,
        target_kind: u32,
        is_terminator: bool,
        payload: Bytes,
        intent: VoiceIntent,
        dst: NodeIdentifier,
    ) -> Result<(), ApplicationError> {
        let (bytes, seq) = self.encode(
            sender_session,
            server_id,
            target_kind,
            is_terminator,
            payload,
            intent,
        )?;
        let result = self
            .transport
            .send_unicast(dst, bytes.clone(), self.cfg.transport_ttl())
            .await;
        metrics::record_send(
            self.transport.local_node_id(),
            VoiceSendMode::Unicast,
            1,
            bytes.len(),
            if result.is_ok() {
                VoiceSendResult::Sent
            } else {
                VoiceSendResult::Failed
            },
        );
        result?;
        self.cache_and_send_proactive_repairs(sender_session, seq, bytes, &[dst])
            .await;
        Ok(())
    }

    fn encode(
        &self,
        sender_session: u32,
        server_id: String,
        target_kind: u32,
        is_terminator: bool,
        payload: Bytes,
        intent: VoiceIntent,
    ) -> Result<(Bytes, u64), ApplicationError> {
        let seq = self.next_seq(sender_session);
        let bytes = send::build_envelope(
            sender_session,
            server_id,
            self.sender_epoch,
            seq,
            target_kind,
            is_terminator,
            payload,
            intent,
        )?;
        Ok((bytes, seq))
    }

    fn remote_voice_members(&self) -> Vec<NodeIdentifier> {
        let local = self.transport.local_node_id();
        self.transport
            .voice_members()
            .into_iter()
            .filter(|node| *node != local)
            .collect()
    }

    async fn cache_and_send_proactive_repairs(
        &self,
        sender_session: u32,
        s2s_seq: u64,
        body: Bytes,
        dsts: &[NodeIdentifier],
    ) {
        if !self.cfg.repair_enabled {
            return;
        }
        for &dst in dsts {
            if dst == self.transport.local_node_id() {
                continue;
            }
            let quality = self.transport.voice_route_quality(dst);
            let avoid_first_hop = quality.map(|q| q.next_hop());
            let transport_ttl = adaptive_repair_transport_ttl(&self.cfg, quality);
            let cache_ttl = adaptive_repair_cache_ttl(&self.cfg, quality, transport_ttl);
            self.repair_cache.insert_with_cache_ttl(
                RepairFrame::new(
                    dst,
                    sender_session,
                    self.sender_epoch,
                    s2s_seq,
                    body.clone(),
                    avoid_first_hop,
                    transport_ttl,
                ),
                cache_ttl,
            );
            let extra_copies = proactive_repair_score_micros(&self.cfg, quality)
                .map(|score| {
                    proactive_repair_extra_copy_count(
                        self.cfg.repair_max_extra_copies_per_frame,
                        score,
                        proactive_repair_sample(dst, s2s_seq),
                    )
                })
                .unwrap_or(0);
            for _ in 0..extra_copies {
                if self
                    .transport
                    .send_repair_frame(dst, body.clone(), avoid_first_hop, transport_ttl)
                    .await
                    .is_ok()
                {
                    metrics::record_repair(
                        self.transport.local_node_id(),
                        dst,
                        VoiceRepairResult::ProactiveCopySent,
                        1,
                    );
                }
            }
        }
    }
}

fn proactive_repair_score_micros(
    cfg: &VoiceConfig,
    quality: Option<crate::overlay::VoiceRouteQuality>,
) -> Option<u64> {
    let quality = quality?;
    if quality.transport() != TransportKind::Udp {
        return None;
    }
    if quality.loss_ppm() >= cfg.repair_full_dup_loss_ppm {
        return Some(1_000_000);
    }
    let distant_path = quality.path_latency_us() >= DISTANT_REPAIR_PATH_LATENCY_US;
    let distant_loss_start_ppm = cfg.repair_loss_start_ppm.saturating_div(4).max(1);
    let distant_full_dup_loss_ppm = cfg
        .repair_loss_start_ppm
        .saturating_div(2)
        .max(distant_loss_start_ppm)
        .min(cfg.repair_full_dup_loss_ppm.max(1));
    if distant_path && quality.loss_ppm() >= distant_full_dup_loss_ppm {
        return Some(1_000_000);
    }
    let jitter_start_us = cfg.repair_jitter_start_ms.saturating_mul(1_000);
    let distant_jitter_start_us = jitter_start_us.saturating_div(2).max(1);
    let normal_trigger =
        quality.loss_ppm() >= cfg.repair_loss_start_ppm || quality.jitter_us() >= jitter_start_us;
    let distant_trigger = distant_path
        && (quality.loss_ppm() >= distant_loss_start_ppm
            || quality.jitter_us() >= distant_jitter_start_us);
    if !normal_trigger && !distant_trigger {
        return None;
    }

    let full_loss = if distant_trigger {
        distant_full_dup_loss_ppm
    } else {
        cfg.repair_full_dup_loss_ppm.max(1)
    };
    let loss_score = (u64::from(quality.loss_ppm()).saturating_mul(1_000_000))
        .saturating_div(u64::from(full_loss));
    let jitter_denominator = if distant_trigger {
        distant_jitter_start_us.saturating_mul(2).max(1)
    } else {
        jitter_start_us.saturating_mul(3).max(1)
    };
    let jitter_score = if jitter_start_us == 0 {
        1_000_000
    } else {
        quality
            .jitter_us()
            .saturating_mul(1_000_000)
            .saturating_div(jitter_denominator)
    };
    let distant_score = if distant_trigger { 500_000 } else { 0 };
    Some(
        loss_score
            .max(jitter_score)
            .max(distant_score)
            .clamp(1, 1_000_000),
    )
}

fn proactive_repair_extra_copy_count(
    max_extra_copies: usize,
    score_micros: u64,
    sample: u64,
) -> usize {
    if max_extra_copies == 0 || score_micros == 0 {
        return 0;
    }
    let max_extra_copies_u64 = max_extra_copies as u64;
    let scaled = score_micros
        .min(1_000_000)
        .saturating_mul(max_extra_copies_u64);
    let guaranteed = scaled / 1_000_000;
    let fractional = u64::from(sample < scaled % 1_000_000);
    guaranteed
        .saturating_add(fractional)
        .min(max_extra_copies_u64) as usize
}

fn proactive_repair_sample(dst: NodeIdentifier, s2s_seq: u64) -> u64 {
    let mut x = (u64::from(u32::from(dst)) << 32) ^ s2s_seq;
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
    x ^= x >> 33;
    x % 1_000_000
}

fn route_hint_from_quality(quality: crate::overlay::VoiceRouteQuality) -> VoiceRouteHint {
    VoiceRouteHint::new(
        quality.path_latency_us(),
        quality.jitter_us(),
        quality.loss_ppm(),
    )
}

fn adaptive_repair_transport_ttl(
    cfg: &VoiceConfig,
    quality: Option<crate::overlay::VoiceRouteQuality>,
) -> Duration {
    let base = cfg.repair_transport_ttl_ms;
    let adaptive = quality
        .map(route_hint_from_quality)
        .map(|hint| Reorderer::route_repair_delay_ms_for_config(cfg, hint))
        .unwrap_or(base);
    Duration::from_millis(base.max(adaptive))
}

fn adaptive_repair_cache_ttl(
    cfg: &VoiceConfig,
    quality: Option<crate::overlay::VoiceRouteQuality>,
    transport_ttl: Duration,
) -> Duration {
    let base = cfg.repair_cache_ms;
    let route_delay = quality
        .map(route_hint_from_quality)
        .map(|hint| Reorderer::route_repair_delay_ms_for_config(cfg, hint))
        .unwrap_or(0);
    let transport_ttl_ms = transport_ttl.as_millis().min(u128::from(u64::MAX)) as u64;
    let adaptive = route_delay
        .saturating_add(transport_ttl_ms)
        .saturating_add(cfg.repair_nack_delay_ms)
        .saturating_add(ADAPTIVE_REPAIR_CACHE_MARGIN_MS);
    Duration::from_millis(base.max(adaptive))
}

fn normal_intent(channel_id: u32) -> VoiceIntent {
    VoiceIntent {
        kind: Some(VoiceIntentKind::Normal(VoiceIntentNormal {
            source_channel: channel_id,
        })),
    }
}

pub struct VoiceInbound {
    inbox_tx: mpsc::UnboundedSender<DispatchEvent>,
}

impl ServiceInbound for VoiceInbound {
    fn handle(&self, msg: OverlayInboundMessage) {
        match proto::decode_voice(&msg.body) {
            Ok(frame) => {
                let _ = self.inbox_tx.send(DispatchEvent::Inbound(VoiceDelivery {
                    from: msg.from,
                    frame,
                }));
            }
            Err(e) => {
                trace!(error=%e, from=%msg.from, "voice: decode failed");
            }
        }
    }
}

struct VoiceRepairInbound {
    transport: Arc<dyn VoiceTransport>,
    cfg: VoiceConfig,
    repair_cache: Arc<RepairCache>,
}

impl ServiceInbound for VoiceRepairInbound {
    fn handle(&self, msg: OverlayInboundMessage) {
        if !self.cfg.repair_enabled {
            return;
        }
        let source = self.transport.local_node_id();
        let request = match proto::decode_voice_repair_request(&msg.body) {
            Ok(request) => request,
            Err(e) => {
                trace!(error=%e, from=%msg.from, "voice repair: decode failed");
                return;
            }
        };
        if repair_request_is_stale(&request) {
            metrics::record_repair(source, msg.from, VoiceRepairResult::RequestSuppressed, 1);
            trace!(from=%msg.from, "voice repair: dropping stale request");
            return;
        }
        let frames = self.repair_cache.lookup_range(
            msg.from,
            request.sender_session,
            request.sender_epoch,
            request.first_seq,
            request.last_seq,
        );
        if frames.is_empty() {
            metrics::record_repair(source, msg.from, VoiceRepairResult::FrameMissed, 1);
            return;
        }
        metrics::record_repair(
            source,
            msg.from,
            VoiceRepairResult::FrameServed,
            frames.len(),
        );
        let transport = self.transport.clone();
        let ttl = Duration::from_millis(self.cfg.repair_transport_ttl_ms);
        tokio::spawn(async move {
            for frame in frames {
                let _ = transport
                    .send_repair_frame(
                        frame.dst(),
                        frame.body().clone(),
                        frame.avoid_first_hop(),
                        frame.transport_ttl().max(ttl),
                    )
                    .await;
            }
        });
    }
}

fn spawn_dispatch_task(
    mut rx: mpsc::UnboundedReceiver<DispatchEvent>,
    shutdown: CancellationToken,
    audio_sink: AudioSinkSlot,
    reorderer: Arc<Reorderer>,
    transport: Arc<dyn VoiceTransport>,
    cfg: VoiceConfig,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                next = rx.recv() => {
                    let Some(ev) = next else { return };
                    let source = transport.local_node_id();
                    let (report, inbound_labels) = match ev {
                        DispatchEvent::Inbound(d) => {
                            let frame_for_gap = d.frame.clone();
                            let origin_node =
                                shitspeak_core::ClientSessionIdentifier::from(
                                    frame_for_gap.sender_session,
                                )
                                .get_node_id();
                            let route_hint =
                                transport.voice_route_quality(d.from).map(route_hint_from_quality);
                            let report =
                                reorderer.push_with_route_hint_report(d.from, d.frame, route_hint);
                            let gap = cfg
                                .repair_enabled
                                .then(|| reorderer.gap_for_frame(d.from, &frame_for_gap))
                                .flatten();
                            if let Some(gap) = gap {
                                metrics::record_repair(
                                    source,
                                    gap.from,
                                    VoiceRepairResult::GapDetected,
                                    1,
                                );
                                schedule_gap_repair(
                                    reorderer.clone(),
                                    transport.clone(),
                                    cfg.repair_nack_delay_ms,
                                    cfg.repair_request_ttl_ms,
                                    gap,
                                );
                            }
                            (report, Some((origin_node, d.from)))
                        }
                        DispatchEvent::DeadlineFired => {
                            (reorderer.drain_expired_report(), None)
                        }
                    };
                    metrics::set_reorder_pending(source, report.pending_total());
                    if let Some((origin_node, from_immediate)) = inbound_labels {
                        for result in report.result_counts() {
                            metrics::record_receive(
                                source,
                                origin_node,
                                from_immediate,
                                result.result(),
                                result.count(),
                            );
                        }
                    }
                    let emits = report.into_emissions();
                    if inbound_labels.is_none() {
                        for (from, frame) in &emits {
                            let origin_node =
                                shitspeak_core::ClientSessionIdentifier::from(frame.sender_session)
                                    .get_node_id();
                            metrics::record_receive(
                                source,
                                origin_node,
                                *from,
                                VoiceReceiveResult::DeadlineFlush,
                                1,
                            );
                        }
                    }
                    if emits.is_empty() {
                        continue;
                    }
                    let sink = audio_sink.read().clone();
                    match sink {
                        Some(sink) => {
                            for (from, frame) in emits {
                                sink.deliver(from, frame).await;
                            }
                        }
                        None => {
                            for (from, frame) in &emits {
                                let origin_node =
                                    shitspeak_core::ClientSessionIdentifier::from(
                                        frame.sender_session,
                                    )
                                    .get_node_id();
                                metrics::record_receive(
                                    source,
                                    origin_node,
                                    *from,
                                    VoiceReceiveResult::NoSinkDrop,
                                    1,
                                );
                            }
                            trace!(
                                n = emits.len(),
                                "voice: no audio sink installed; dropping emit batch",
                            )
                        }
                    }
                }
            }
        }
    });
}

fn schedule_gap_repair(
    reorderer: Arc<Reorderer>,
    transport: Arc<dyn VoiceTransport>,
    delay_ms: u64,
    request_ttl_ms: u64,
    gap: GapReport,
) {
    let source = transport.local_node_id();
    if gap.from == source {
        metrics::record_repair(source, gap.from, VoiceRepairResult::RequestSuppressed, 1);
        return;
    }
    metrics::record_repair(source, gap.from, VoiceRepairResult::RequestScheduled, 1);
    tokio::spawn(async move {
        if delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }
        if !reorderer.gap_still_missing(gap) {
            metrics::record_repair(source, gap.from, VoiceRepairResult::RequestSuppressed, 1);
            return;
        }
        let request = VoiceRepairRequest {
            sender_session: gap.sender_session,
            sender_epoch: gap.sender_epoch,
            first_seq: gap.first_seq,
            last_seq: gap.last_seq,
            request_sent_unix_ms: unix_time_ms(),
            request_ttl_ms: request_ttl_ms.min(u64::from(u32::MAX)) as u32,
        };
        match proto::encode_voice_repair_request(&request) {
            Ok(body) => {
                if transport
                    .send_repair_request(gap.from, body, Duration::from_millis(request_ttl_ms))
                    .await
                    .is_ok()
                {
                    metrics::record_repair(source, gap.from, VoiceRepairResult::RequestSent, 1);
                } else {
                    metrics::record_repair(
                        source,
                        gap.from,
                        VoiceRepairResult::RequestSuppressed,
                        1,
                    );
                }
            }
            Err(e) => {
                metrics::record_repair(source, gap.from, VoiceRepairResult::RequestSuppressed, 1);
                trace!(error=%e, "voice repair: encode request failed")
            }
        }
    });
}

fn repair_request_is_stale(request: &VoiceRepairRequest) -> bool {
    if request.request_sent_unix_ms == 0 || request.request_ttl_ms == 0 {
        return false;
    }
    let deadline = request
        .request_sent_unix_ms
        .saturating_add(u64::from(request.request_ttl_ms));
    unix_time_ms() > deadline
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    use crate::application::voice::send::testing::{FakeCall, FakeVoiceTransport};
    use crate::application::voice::sink::testing::RecordingSink;

    fn make_service(transport: Arc<FakeVoiceTransport>) -> Arc<VoiceService> {
        VoiceService::new_with_transport(
            transport,
            VoiceConfig::default(),
            CancellationToken::new(),
            42,
        )
    }

    #[tokio::test]
    async fn broadcast_emits_envelope_and_advances_seq() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service(transport.clone());

        let payload = Bytes::from_static(b"opus-1");
        svc.send_broadcast(
            0xABC,
            shitspeak_core::default_server_id(),
            0,
            false,
            payload.clone(),
            normal_intent(5),
        )
        .await
        .unwrap();
        svc.send_broadcast(
            0xABC,
            shitspeak_core::default_server_id(),
            0,
            true,
            Bytes::from_static(b"opus-2"),
            normal_intent(5),
        )
        .await
        .unwrap();

        let calls = transport.calls();
        assert_eq!(calls.len(), 2);
        let first = match &calls[0] {
            FakeCall::Multicast { dsts, body, ttl } => {
                assert_eq!(dsts.as_slice(), &[1, 2, 3]);
                assert_eq!(*ttl, VoiceConfig::default().transport_ttl());
                proto::decode_voice(body.as_ref()).unwrap()
            }
            other => panic!("expected Multicast, got {other:?}"),
        };
        let second = match &calls[1] {
            FakeCall::Multicast { dsts, body, ttl } => {
                assert_eq!(dsts.as_slice(), &[1, 2, 3]);
                assert_eq!(*ttl, VoiceConfig::default().transport_ttl());
                proto::decode_voice(body.as_ref()).unwrap()
            }
            other => panic!("expected Multicast, got {other:?}"),
        };
        assert_eq!(first.sender_session, 0xABC);
        assert_eq!(first.sender_epoch, 42);
        assert_eq!(first.s2s_seq, 0);
        assert_eq!(first.payload, b"opus-1".as_ref());
        assert!(!first.is_terminator);
        assert_eq!(second.s2s_seq, 1);
        assert_eq!(second.payload, b"opus-2".as_ref());
        assert!(second.is_terminator);
    }

    #[tokio::test]
    async fn broadcast_uses_voice_members_not_all_alive_members() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3, 4]);
        transport.set_voice_members(vec![2, 4, 7]);
        let svc = make_service(transport.clone());

        svc.send_broadcast(
            0xABC,
            shitspeak_core::default_server_id(),
            0,
            false,
            Bytes::from_static(b"x"),
            normal_intent(5),
        )
        .await
        .unwrap();

        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        match &calls[0] {
            FakeCall::Multicast { dsts, .. } => assert_eq!(dsts.as_slice(), &[2, 4]),
            other => panic!("expected Multicast, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn multicast_skips_when_dsts_empty() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service(transport.clone());
        svc.send_multicast(
            0xABC,
            shitspeak_core::default_server_id(),
            2,
            false,
            Bytes::from_static(b"x"),
            normal_intent(5),
            &[],
        )
        .await
        .unwrap();
        assert!(transport.calls().is_empty());
    }

    #[tokio::test]
    async fn multicast_emits_envelope_with_dsts() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service(transport.clone());
        svc.send_multicast(
            0xABC,
            shitspeak_core::default_server_id(),
            2,
            false,
            Bytes::from_static(b"whisper"),
            normal_intent(5),
            &[1, 3],
        )
        .await
        .unwrap();
        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        match &calls[0] {
            FakeCall::Multicast { dsts, body, ttl } => {
                assert_eq!(dsts.as_slice(), &[1, 3]);
                assert_eq!(*ttl, VoiceConfig::default().transport_ttl());
                let f = proto::decode_voice(body.as_ref()).unwrap();
                assert_eq!(f.target_kind, 2);
                assert_eq!(f.payload, b"whisper".as_ref());
            }
            other => panic!("expected Multicast, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unicast_emits_to_single_dst() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service(transport.clone());
        svc.send_unicast(
            0xABC,
            shitspeak_core::default_server_id(),
            2,
            true,
            Bytes::from_static(b"end"),
            normal_intent(5),
            5,
        )
        .await
        .unwrap();
        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        match &calls[0] {
            FakeCall::Unicast { dst, body, ttl } => {
                assert_eq!(*dst, 5);
                assert_eq!(*ttl, VoiceConfig::default().transport_ttl());
                let f = proto::decode_voice(body.as_ref()).unwrap();
                assert!(f.is_terminator);
            }
            other => panic!("expected Unicast, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn normal_sends_use_configured_transport_ttl() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let mut cfg = VoiceConfig::default();
        cfg.set_transport_ttl_ms(180);
        let svc =
            VoiceService::new_with_transport(transport.clone(), cfg, CancellationToken::new(), 42);

        svc.send_multicast(
            0xABC,
            shitspeak_core::default_server_id(),
            2,
            false,
            Bytes::from_static(b"ttl"),
            normal_intent(5),
            &[1, 3],
        )
        .await
        .unwrap();
        svc.send_unicast(
            0xABC,
            shitspeak_core::default_server_id(),
            2,
            false,
            Bytes::from_static(b"ttl"),
            normal_intent(5),
            3,
        )
        .await
        .unwrap();

        let calls = transport.calls();
        assert_eq!(calls.len(), 2);
        for call in calls {
            let ttl = match call {
                FakeCall::Multicast { ttl, .. } | FakeCall::Unicast { ttl, .. } => ttl,
                other => panic!("expected normal voice send, got {other:?}"),
            };
            assert_eq!(ttl, Duration::from_millis(180));
        }
    }

    fn make_service_with_strategy(
        transport: Arc<FakeVoiceTransport>,
        strategy: &str,
    ) -> Arc<VoiceService> {
        let mut cfg = VoiceConfig::default();
        cfg.delivery_strategy = strategy.to_string();
        VoiceService::new_with_transport(transport, cfg, CancellationToken::new(), 42)
    }

    async fn wait_for_call_count(transport: &FakeVoiceTransport, count: usize) -> Vec<FakeCall> {
        for _ in 0..50 {
            let calls = transport.calls();
            if calls.len() >= count {
                return calls;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        transport.calls()
    }

    #[test]
    fn adaptive_repair_ttls_expand_for_far_lossy_route() {
        let cfg = VoiceConfig::default();
        let quality = crate::overlay::VoiceRouteQuality::new(
            2,
            shitspeak_s2s_transport::TransportKind::Udp,
            90_000,
            20_000,
            30_000,
        );

        let transport_ttl = adaptive_repair_transport_ttl(&cfg, Some(quality));
        let cache_ttl = adaptive_repair_cache_ttl(&cfg, Some(quality), transport_ttl);

        assert!(transport_ttl > Duration::from_millis(cfg.repair_transport_ttl_ms));
        assert!(cache_ttl > Duration::from_millis(cfg.repair_cache_ms));
    }

    #[test]
    fn proactive_repair_copy_count_honors_zero_limit() {
        assert_eq!(proactive_repair_extra_copy_count(0, 1_000_000, 0), 0);
        assert_eq!(proactive_repair_extra_copy_count(0, 500_000, 0), 0);
    }

    #[test]
    fn proactive_repair_copy_count_matches_old_single_copy_threshold() {
        assert_eq!(proactive_repair_extra_copy_count(1, 500_000, 499_999), 1);
        assert_eq!(proactive_repair_extra_copy_count(1, 500_000, 500_000), 0);
    }

    #[test]
    fn proactive_repair_copy_count_scales_above_one() {
        assert_eq!(proactive_repair_extra_copy_count(3, 400_000, 200_000), 1);
        assert_eq!(proactive_repair_extra_copy_count(3, 400_000, 199_999), 2);
        assert_eq!(proactive_repair_extra_copy_count(3, 900_000, 699_999), 3);
    }

    #[test]
    fn proactive_repair_copy_count_full_score_reaches_limit() {
        assert_eq!(proactive_repair_extra_copy_count(3, 1_000_000, 999_999), 3);
    }

    #[tokio::test]
    async fn distant_lossy_udp_path_gets_proactive_repair_below_generic_threshold() {
        let transport = FakeVoiceTransport::new(7, vec![2]);
        transport.set_voice_route_quality(
            2,
            crate::overlay::VoiceRouteQuality::new(2, TransportKind::Udp, 200_000, 5_000, 0),
        );
        let svc = make_service(transport.clone());

        svc.send_unicast(
            0xABC,
            shitspeak_core::default_server_id(),
            0,
            false,
            Bytes::from_static(b"opus"),
            normal_intent(5),
            2,
        )
        .await
        .unwrap();

        let calls = transport.calls();
        assert_eq!(calls.len(), 2);
        assert!(matches!(calls[0], FakeCall::Unicast { .. }));
        match &calls[1] {
            FakeCall::RepairFrame {
                dst,
                avoid_first_hop,
                ..
            } => {
                assert_eq!(*dst, 2);
                assert_eq!(*avoid_first_hop, Some(2));
            }
            other => panic!("expected proactive repair frame, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn high_loss_udp_path_sends_configured_extra_repair_copies() {
        let transport = FakeVoiceTransport::new(7, vec![2]);
        let mut cfg = VoiceConfig::default();
        cfg.repair_max_extra_copies_per_frame = 3;
        transport.set_voice_route_quality(
            2,
            crate::overlay::VoiceRouteQuality::new(
                2,
                TransportKind::Udp,
                20_000,
                cfg.repair_full_dup_loss_ppm,
                0,
            ),
        );
        let svc =
            VoiceService::new_with_transport(transport.clone(), cfg, CancellationToken::new(), 42);

        svc.send_unicast(
            0xABC,
            shitspeak_core::default_server_id(),
            0,
            false,
            Bytes::from_static(b"opus"),
            normal_intent(5),
            2,
        )
        .await
        .unwrap();

        let calls = transport.calls();
        assert_eq!(calls.len(), 4);
        assert!(matches!(calls[0], FakeCall::Unicast { .. }));
        assert_eq!(
            calls
                .iter()
                .filter(|call| matches!(call, FakeCall::RepairFrame { .. }))
                .count(),
            3
        );
    }

    #[tokio::test]
    async fn high_loss_udp_path_suppresses_proactive_repair_when_limit_is_zero() {
        let transport = FakeVoiceTransport::new(7, vec![2]);
        let mut cfg = VoiceConfig::default();
        cfg.repair_max_extra_copies_per_frame = 0;
        transport.set_voice_route_quality(
            2,
            crate::overlay::VoiceRouteQuality::new(
                2,
                TransportKind::Udp,
                20_000,
                cfg.repair_full_dup_loss_ppm,
                0,
            ),
        );
        let svc =
            VoiceService::new_with_transport(transport.clone(), cfg, CancellationToken::new(), 42);

        svc.send_unicast(
            0xABC,
            shitspeak_core::default_server_id(),
            0,
            false,
            Bytes::from_static(b"opus"),
            normal_intent(5),
            2,
        )
        .await
        .unwrap();

        assert_eq!(transport.calls().len(), 1);
    }

    #[tokio::test]
    async fn nearby_subthreshold_udp_loss_stays_primary_only() {
        let transport = FakeVoiceTransport::new(7, vec![2]);
        transport.set_voice_route_quality(
            2,
            crate::overlay::VoiceRouteQuality::new(2, TransportKind::Udp, 20_000, 5_000, 0),
        );
        let svc = make_service(transport.clone());

        svc.send_unicast(
            0xABC,
            shitspeak_core::default_server_id(),
            0,
            false,
            Bytes::from_static(b"opus"),
            normal_intent(5),
            2,
        )
        .await
        .unwrap();

        assert_eq!(transport.calls().len(), 1);
    }

    #[tokio::test]
    async fn send_for_channel_broadcast_strategy_multicasts_to_voice_members() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service_with_strategy(transport.clone(), "broadcast");
        svc.send_for_channel(
            0xABC,
            shitspeak_core::default_server_id(),
            /*channel=*/ 5,
            false,
            Bytes::from_static(b"x"),
        )
        .await
        .unwrap();
        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        assert!(matches!(calls[0], FakeCall::Multicast { .. }));
    }

    #[tokio::test]
    async fn send_for_channel_targeted_falls_back_to_voice_member_multicast_when_no_index() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service_with_strategy(transport.clone(), "targeted");
        svc.send_for_channel(
            0xABC,
            shitspeak_core::default_server_id(),
            5,
            false,
            Bytes::from_static(b"x"),
        )
        .await
        .unwrap();
        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        assert!(matches!(calls[0], FakeCall::Multicast { .. }));
    }

    #[tokio::test]
    async fn send_for_channel_targeted_uses_index() {
        use crate::application::voice::targeted::RecipientIndex;
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service_with_strategy(transport.clone(), "targeted");
        let idx = RecipientIndex::new();
        idx.add(5, 1);
        idx.add(5, 2);
        idx.add(5, 7); // self — must be filtered out
        svc.set_recipient_index(idx);
        svc.send_for_channel(
            0xABC,
            shitspeak_core::default_server_id(),
            5,
            false,
            Bytes::from_static(b"x"),
        )
        .await
        .unwrap();
        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        match &calls[0] {
            FakeCall::Multicast { dsts, .. } => {
                let mut sorted = dsts.clone();
                sorted.sort();
                assert_eq!(sorted, vec![1, 2]);
            }
            other => panic!("expected Multicast, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_for_channel_targeted_scopes_index_by_server_id() {
        use crate::application::voice::targeted::RecipientIndex;
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service_with_strategy(transport.clone(), "targeted");
        let idx = RecipientIndex::new();
        idx.add_in_server("alpha", 5, 1);
        idx.add_in_server("beta", 5, 2);
        idx.add_in_server("beta", 5, 7);
        svc.set_recipient_index(idx);

        svc.send_for_channel(0xABC, "beta".to_owned(), 5, false, Bytes::from_static(b"x"))
            .await
            .unwrap();

        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        match &calls[0] {
            FakeCall::Multicast { dsts, body, .. } => {
                assert_eq!(dsts, &vec![2]);
                let frame = proto::decode_voice(body.as_ref()).unwrap();
                assert_eq!(frame.server_id, "beta");
            }
            other => panic!("expected Multicast, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_for_target_channels_targeted_preserves_shout_intent() {
        use crate::application::proto::{VoiceIntentKind, VoiceIntentTarget, VoiceTargetChannel};
        use crate::application::voice::targeted::{
            RecipientIndex, RecipientIndexKey, RecipientIndexSnapshot, RecipientIndexUpdate,
        };

        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service_with_strategy(transport.clone(), "targeted");
        let idx = RecipientIndex::new();
        let mut snapshot = RecipientIndexSnapshot::new();
        snapshot.insert(
            RecipientIndexKey::new(shitspeak_core::default_server_id(), 5),
            [1].into_iter().collect(),
        );
        snapshot.insert(
            RecipientIndexKey::new(shitspeak_core::default_server_id(), 6),
            [2, 7].into_iter().collect(),
        );
        idx.replace_all_complete(RecipientIndexUpdate::new(
            snapshot,
            [shitspeak_core::default_server_id()].into_iter().collect(),
            [1, 2, 3, 7].into_iter().collect(),
        ));
        svc.set_recipient_index(idx);

        let intent = VoiceIntent {
            kind: Some(VoiceIntentKind::Target(VoiceIntentTarget {
                source_channel: 5,
                sessions: Vec::new(),
                channels: vec![VoiceTargetChannel {
                    id: 5,
                    children: false,
                    links: true,
                    group: String::new(),
                }],
            })),
        };
        svc.send_for_target_channels(
            0xABC,
            shitspeak_core::default_server_id(),
            Arc::from([5, 6]),
            1,
            false,
            Bytes::from_static(b"shout"),
            intent,
        )
        .await
        .unwrap();

        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        match &calls[0] {
            FakeCall::Multicast { dsts, body, .. } => {
                let mut sorted = dsts.clone();
                sorted.sort();
                assert_eq!(sorted, vec![1, 2]);
                let frame = proto::decode_voice(body.as_ref()).unwrap();
                assert_eq!(frame.target_kind, 1);
                assert!(matches!(
                    frame.intent.and_then(|intent| intent.kind),
                    Some(VoiceIntentKind::Target(_))
                ));
            }
            other => panic!("expected Multicast, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_for_target_channels_targeted_preserves_normal_intent() {
        use crate::application::proto::VoiceIntentKind;
        use crate::application::voice::targeted::{
            RecipientIndex, RecipientIndexKey, RecipientIndexSnapshot, RecipientIndexUpdate,
        };

        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service_with_strategy(transport.clone(), "targeted");
        let idx = RecipientIndex::new();
        let mut snapshot = RecipientIndexSnapshot::new();
        snapshot.insert(
            RecipientIndexKey::new(shitspeak_core::default_server_id(), 5),
            [1].into_iter().collect(),
        );
        snapshot.insert(
            RecipientIndexKey::new(shitspeak_core::default_server_id(), 6),
            [2, 7].into_iter().collect(),
        );
        idx.replace_all_complete(RecipientIndexUpdate::new(
            snapshot,
            [shitspeak_core::default_server_id()].into_iter().collect(),
            [1, 2, 3, 7].into_iter().collect(),
        ));
        svc.set_recipient_index(idx);

        svc.send_for_target_channels(
            0xABC,
            shitspeak_core::default_server_id(),
            Arc::from([5, 6]),
            0,
            false,
            Bytes::from_static(b"normal"),
            normal_intent(5),
        )
        .await
        .unwrap();

        match &transport.calls()[0] {
            FakeCall::Multicast { dsts, body, .. } => {
                let mut sorted = dsts.clone();
                sorted.sort();
                assert_eq!(sorted, vec![1, 2]);
                let frame = proto::decode_voice(body.as_ref()).unwrap();
                assert_eq!(frame.target_kind, 0);
                assert!(matches!(
                    frame.intent.and_then(|intent| intent.kind),
                    Some(VoiceIntentKind::Normal(normal)) if normal.source_channel == 5
                ));
            }
            other => panic!("expected Multicast, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_for_server_targeted_uses_complete_server_membership() {
        use crate::application::proto::{VoiceIntentKind, VoiceIntentTarget, VoiceTargetChannel};
        use crate::application::voice::targeted::{
            RecipientIndex, RecipientIndexKey, RecipientIndexSnapshot, RecipientIndexUpdate,
        };

        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service_with_strategy(transport.clone(), "targeted");
        let idx = RecipientIndex::new();
        let mut snapshot = RecipientIndexSnapshot::new();
        snapshot.insert(
            RecipientIndexKey::new("alpha", 5),
            [1, 2].into_iter().collect(),
        );
        idx.replace_all_complete(RecipientIndexUpdate::new(
            snapshot,
            ["alpha".to_owned()].into_iter().collect(),
            [1, 2, 3, 7].into_iter().collect(),
        ));
        svc.set_recipient_index(idx);
        let intent = VoiceIntent {
            kind: Some(VoiceIntentKind::Target(VoiceIntentTarget {
                source_channel: 0,
                sessions: Vec::new(),
                channels: vec![VoiceTargetChannel {
                    id: 0,
                    children: true,
                    links: false,
                    group: String::new(),
                }],
            })),
        };

        svc.send_for_server(
            0xABC,
            "alpha".to_owned(),
            1,
            false,
            Bytes::from_static(b"server"),
            intent,
        )
        .await
        .unwrap();

        match &transport.calls()[0] {
            FakeCall::Multicast { dsts, .. } => assert_eq!(dsts, &vec![1, 2]),
            other => panic!("expected server-scoped multicast, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_for_target_channels_falls_back_when_any_channel_missing() {
        use crate::application::proto::{VoiceIntentKind, VoiceIntentTarget, VoiceTargetChannel};
        use crate::application::voice::targeted::RecipientIndex;

        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service_with_strategy(transport.clone(), "targeted");
        let idx = RecipientIndex::new();
        idx.add(5, 1);
        svc.set_recipient_index(idx);

        let intent = VoiceIntent {
            kind: Some(VoiceIntentKind::Target(VoiceIntentTarget {
                source_channel: 5,
                sessions: Vec::new(),
                channels: vec![VoiceTargetChannel {
                    id: 5,
                    children: false,
                    links: true,
                    group: String::new(),
                }],
            })),
        };
        svc.send_for_target_channels(
            0xABC,
            shitspeak_core::default_server_id(),
            Arc::from([5, 6]),
            1,
            false,
            Bytes::from_static(b"shout"),
            intent,
        )
        .await
        .unwrap();

        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        assert!(matches!(calls[0], FakeCall::Multicast { .. }));
    }

    #[tokio::test]
    async fn normal_channel_set_falls_back_when_linked_channel_is_missing() {
        use crate::application::proto::VoiceIntentKind;
        use crate::application::voice::targeted::RecipientIndex;

        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service_with_strategy(transport.clone(), "targeted");
        let idx = RecipientIndex::new();
        idx.add(5, 1);
        svc.set_recipient_index(idx);

        svc.send_for_target_channels(
            0xABC,
            shitspeak_core::default_server_id(),
            Arc::from([5, 6]),
            0,
            false,
            Bytes::from_static(b"normal"),
            normal_intent(5),
        )
        .await
        .unwrap();

        match &transport.calls()[0] {
            FakeCall::Multicast { dsts, body, .. } => {
                assert_eq!(dsts, &vec![1, 2, 3]);
                let frame = proto::decode_voice(body.as_ref()).unwrap();
                assert!(matches!(
                    frame.intent.and_then(|intent| intent.kind),
                    Some(VoiceIntentKind::Normal(normal)) if normal.source_channel == 5
                ));
            }
            other => panic!("expected broadcast fallback, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_for_target_channels_targeted_missing_channel_is_server_scoped() {
        use crate::application::proto::{VoiceIntentKind, VoiceIntentTarget, VoiceTargetChannel};
        use crate::application::voice::targeted::RecipientIndex;

        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service_with_strategy(transport.clone(), "targeted");
        let idx = RecipientIndex::new();
        idx.add_in_server("alpha", 5, 1);
        idx.add_in_server("alpha", 6, 1);
        idx.add_in_server("beta", 5, 2);
        svc.set_recipient_index(idx);

        let intent = VoiceIntent {
            kind: Some(VoiceIntentKind::Target(VoiceIntentTarget {
                source_channel: 5,
                sessions: Vec::new(),
                channels: vec![VoiceTargetChannel {
                    id: 5,
                    children: false,
                    links: false,
                    group: String::new(),
                }],
            })),
        };
        svc.send_for_target_channels(
            0xABC,
            "beta".to_owned(),
            Arc::from([5, 6]),
            1,
            false,
            Bytes::from_static(b"shout"),
            intent,
        )
        .await
        .unwrap();

        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        assert!(
            matches!(calls[0], FakeCall::Multicast { .. }),
            "missing beta channel 6 should fall back despite alpha channel 6 existing"
        );
    }

    #[tokio::test]
    async fn send_for_channel_targeted_no_op_when_only_self_in_channel() {
        use crate::application::voice::targeted::RecipientIndex;
        let transport = FakeVoiceTransport::new(7, vec![1, 2]);
        let svc = make_service_with_strategy(transport.clone(), "targeted");
        let idx = RecipientIndex::new();
        idx.add(5, 7); // only self
        svc.set_recipient_index(idx);
        svc.send_for_channel(
            0xABC,
            shitspeak_core::default_server_id(),
            5,
            false,
            Bytes::from_static(b"x"),
        )
        .await
        .unwrap();
        // No cross-node calls — speaker is the only channel resident.
        assert!(transport.calls().is_empty());
    }

    #[tokio::test]
    async fn ingress_dispatches_decoded_frame_to_installed_sink() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service(transport);
        let sink = RecordingSink::new();
        svc.set_audio_sink(sink.clone());

        // Synthesize an inbound overlay message and feed it through the
        // production decode path.
        let envelope = send::build_envelope(
            0xABC,
            shitspeak_core::default_server_id(),
            42,
            5,
            0,
            true,
            Bytes::from_static(b"opus-bytes"),
            normal_intent(5),
        )
        .unwrap();
        svc.inbound_handler().handle(OverlayInboundMessage {
            from: 11,
            level: shitspeak_s2s_transport::ServiceLevel::BestEffort,
            class: shitspeak_s2s_transport::MessageClass::HighPriority,
            body: envelope,
        });

        // Dispatch task is async; poll with a small bounded retry.
        for _ in 0..50 {
            if sink.len() > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let received = sink.snapshot();
        assert_eq!(received.len(), 1);
        let (from, frame) = &received[0];
        assert_eq!(*from, 11);
        assert_eq!(frame.sender_session, 0xABC);
        assert_eq!(frame.s2s_seq, 5);
        assert!(frame.is_terminator);
        assert_eq!(frame.payload, b"opus-bytes".as_ref());
    }

    #[tokio::test]
    async fn ingress_drops_when_no_sink_installed() {
        let transport = FakeVoiceTransport::new(7, vec![1]);
        let svc = make_service(transport);
        let envelope = send::build_envelope(
            0xABC,
            shitspeak_core::default_server_id(),
            42,
            0,
            0,
            false,
            Bytes::from_static(b"x"),
            normal_intent(5),
        )
        .unwrap();
        svc.inbound_handler().handle(OverlayInboundMessage {
            from: 1,
            level: shitspeak_s2s_transport::ServiceLevel::BestEffort,
            class: shitspeak_s2s_transport::MessageClass::HighPriority,
            body: envelope,
        });
        // Give the dispatch task a chance to run; verify it doesn't panic.
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    #[tokio::test]
    async fn ingress_gap_requests_repair_after_delay() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let mut cfg = VoiceConfig::default();
        cfg.repair_nack_delay_ms = 1;
        let svc =
            VoiceService::new_with_transport(transport.clone(), cfg, CancellationToken::new(), 42);
        let inbound = svc.inbound_handler();

        for seq in [0, 2] {
            let envelope = send::build_envelope(
                0xABC,
                shitspeak_core::default_server_id(),
                42,
                seq,
                0,
                false,
                Bytes::from(format!("opus-{seq}").into_bytes()),
                normal_intent(5),
            )
            .unwrap();
            inbound.handle(OverlayInboundMessage {
                from: 11,
                level: shitspeak_s2s_transport::ServiceLevel::BestEffort,
                class: shitspeak_s2s_transport::MessageClass::HighPriority,
                body: envelope,
            });
        }

        let calls = wait_for_call_count(&transport, 1).await;
        match &calls[0] {
            FakeCall::RepairRequest { dst, body, ttl } => {
                assert_eq!(*dst, 11);
                assert_eq!(
                    *ttl,
                    Duration::from_millis(VoiceConfig::default().repair_request_ttl_ms)
                );
                let request = proto::decode_voice_repair_request(body.as_ref()).unwrap();
                assert_eq!(request.sender_session, 0xABC);
                assert_eq!(request.sender_epoch, 42);
                assert_eq!(request.first_seq, 1);
                assert_eq!(request.last_seq, 1);
                assert!(request.request_sent_unix_ms > 0);
                assert_eq!(
                    request.request_ttl_ms,
                    VoiceConfig::default().repair_request_ttl_ms as u32
                );
            }
            other => panic!("expected RepairRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ingress_gap_suppresses_repair_when_missing_frame_arrives() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let mut cfg = VoiceConfig::default();
        cfg.repair_nack_delay_ms = 20;
        let svc =
            VoiceService::new_with_transport(transport.clone(), cfg, CancellationToken::new(), 42);
        let inbound = svc.inbound_handler();

        for seq in [0, 2, 1] {
            let envelope = send::build_envelope(
                0xABC,
                shitspeak_core::default_server_id(),
                42,
                seq,
                0,
                false,
                Bytes::from(format!("opus-{seq}").into_bytes()),
                normal_intent(5),
            )
            .unwrap();
            inbound.handle(OverlayInboundMessage {
                from: 11,
                level: shitspeak_s2s_transport::ServiceLevel::BestEffort,
                class: shitspeak_s2s_transport::MessageClass::HighPriority,
                body: envelope,
            });
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            transport
                .calls()
                .iter()
                .all(|call| !matches!(call, FakeCall::RepairRequest { .. }))
        );
    }

    #[tokio::test]
    async fn repair_handler_replays_cached_exact_frame() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service(transport.clone());
        svc.send_unicast(
            0xABC,
            shitspeak_core::default_server_id(),
            0,
            false,
            Bytes::from_static(b"opus-exact"),
            normal_intent(5),
            2,
        )
        .await
        .unwrap();
        let original = match &transport.calls()[0] {
            FakeCall::Unicast { body, .. } => body.clone(),
            other => panic!("expected Unicast, got {other:?}"),
        };
        let request = VoiceRepairRequest {
            sender_session: 0xABC,
            sender_epoch: 42,
            first_seq: 0,
            last_seq: 0,
            request_sent_unix_ms: 0,
            request_ttl_ms: 0,
        };
        let request_body = proto::encode_voice_repair_request(&request).unwrap();
        svc.repair_inbound_handler().handle(OverlayInboundMessage {
            from: 2,
            level: shitspeak_s2s_transport::ServiceLevel::ReliableLowLatency,
            class: shitspeak_s2s_transport::MessageClass::HighPriority,
            body: request_body,
        });

        let calls = wait_for_call_count(&transport, 2).await;
        match &calls[1] {
            FakeCall::RepairFrame { dst, body, ttl, .. } => {
                assert_eq!(*dst, 2);
                assert_eq!(body, &original);
                assert_eq!(
                    *ttl,
                    Duration::from_millis(VoiceConfig::default().repair_transport_ttl_ms)
                );
            }
            other => panic!("expected RepairFrame, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn repair_handler_drops_stale_timestamped_request() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service(transport.clone());
        svc.send_unicast(
            0xABC,
            shitspeak_core::default_server_id(),
            0,
            false,
            Bytes::from_static(b"opus-exact"),
            normal_intent(5),
            2,
        )
        .await
        .unwrap();
        let request = VoiceRepairRequest {
            sender_session: 0xABC,
            sender_epoch: 42,
            first_seq: 0,
            last_seq: 0,
            request_sent_unix_ms: unix_time_ms().saturating_sub(10_000),
            request_ttl_ms: 1,
        };
        let request_body = proto::encode_voice_repair_request(&request).unwrap();
        svc.repair_inbound_handler().handle(OverlayInboundMessage {
            from: 2,
            level: shitspeak_s2s_transport::ServiceLevel::BestEffort,
            class: shitspeak_s2s_transport::MessageClass::HighPriority,
            body: request_body,
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(transport.calls().len(), 1);
    }

    #[tokio::test]
    async fn per_session_counters_independent() {
        let transport = FakeVoiceTransport::new(7, vec![1]);
        let svc = make_service(transport.clone());
        for session in [0xAAA, 0xBBB] {
            for _ in 0..3 {
                svc.send_broadcast(
                    session,
                    shitspeak_core::default_server_id(),
                    0,
                    false,
                    Bytes::from_static(b"x"),
                    normal_intent(5),
                )
                .await
                .unwrap();
            }
        }
        let calls = transport.calls();
        assert_eq!(calls.len(), 6);
        let seqs: Vec<(u32, u64)> = calls
            .iter()
            .map(|c| match c {
                FakeCall::Multicast { body, .. } => {
                    let f = proto::decode_voice(body.as_ref()).unwrap();
                    (f.sender_session, f.s2s_seq)
                }
                _ => panic!(),
            })
            .collect();
        assert_eq!(
            seqs,
            vec![
                (0xAAA, 0),
                (0xAAA, 1),
                (0xAAA, 2),
                (0xBBB, 0),
                (0xBBB, 1),
                (0xBBB, 2),
            ]
        );
    }
}
