//! Inbound `VoiceFrame` decode + central dispatch task, and the
//! speaker-side public API (`VoiceService`).
//!
//! Phase 1: dispatch task is a no-op stub that only logs.
//! Phase 2: speaker-side `send_*` API + per-(sender_session) sequence
//!          counter for the wire envelope's `s2s_seq`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::RwLock;
use scc::HashMap as SccMap;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::trace;

use crate::s2s::application::config::{DeliveryStrategy, VoiceConfig};
use crate::s2s::application::error::ApplicationError;
use crate::s2s::application::proto::{self, VoiceFrame};
use crate::s2s::application::voice::reorder::{self, Reorderer};
use crate::s2s::application::voice::send::{self, OverlayVoiceTransport, VoiceTransport};
use crate::s2s::application::voice::sink::AudioSink;
use crate::s2s::application::voice::targeted::RecipientIndex;
use crate::s2s::overlay::{OverlayInboundMessage, OverlayNetwork, ServiceInbound};
use crate::types::NodeIdentifier;

type AudioSinkSlot = Arc<RwLock<Option<Arc<dyn AudioSink>>>>;
type RecipientIndexSlot = Arc<RwLock<Option<Arc<RecipientIndex>>>>;

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
    shutdown: CancellationToken,
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
    reorderer: Arc<Reorderer>,

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
        spawn_dispatch_task(
            inbox_rx,
            shutdown.clone(),
            audio_sink.clone(),
            reorderer.clone(),
        );
        let nudge_tx = inbox_tx.clone();
        reorder::spawn_deadline_task(reorderer.clone(), shutdown.clone(), move || {
            let _ = nudge_tx.send(DispatchEvent::DeadlineFired);
        });
        let delivery_strategy = DeliveryStrategy::parse(&cfg.delivery_strategy);
        Arc::new(Self {
            transport,
            cfg,
            shutdown,
            inbox_tx,
            sender_epoch,
            seq_counters: Arc::new(SccMap::new()),
            audio_sink,
            reorderer,
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
            .entry(sender_session)
            .or_insert_with(|| AtomicU64::new(0))
            .get()
            .fetch_add(1, Ordering::Relaxed)
    }

    /// Reset the per-session counter when a local client disconnects.
    /// Optional; harmless to skip — the counter just stays around.
    pub fn drop_session(&self, sender_session: u32) {
        let _ = self.seq_counters.remove(&sender_session);
    }

    /// Broadcast a voice frame to every alive node (other than self).
    /// `payload` is the already-encoded UDP audio body — receivers do
    /// not re-encode, they hand it directly to local fan-out.
    pub async fn send_broadcast(
        &self,
        sender_session: u32,
        target_kind: u32,
        is_terminator: bool,
        payload: Bytes,
    ) -> Result<(), ApplicationError> {
        let bytes = self.encode(sender_session, target_kind, is_terminator, payload)?;
        self.transport.send_broadcast(bytes).await
    }

    /// Multicast to a specific node set (used by whisper-to-direct-session
    /// and by the opt-in `"targeted"` mode).
    pub async fn send_multicast(
        &self,
        sender_session: u32,
        target_kind: u32,
        is_terminator: bool,
        payload: Bytes,
        dsts: &[NodeIdentifier],
    ) -> Result<(), ApplicationError> {
        if dsts.is_empty() {
            return Ok(());
        }
        let bytes = self.encode(sender_session, target_kind, is_terminator, payload)?;
        self.transport.send_multicast(dsts, bytes).await
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
        channel_id: u32,
        is_terminator: bool,
        payload: Bytes,
    ) -> Result<(), ApplicationError> {
        match self.delivery_strategy {
            DeliveryStrategy::Broadcast => {
                self.send_broadcast(sender_session, 0, is_terminator, payload)
                    .await
            }
            DeliveryStrategy::Targeted => {
                let nodes = self
                    .recipient_index
                    .read()
                    .as_ref()
                    .and_then(|idx| idx.lookup_nodes_for(channel_id));
                match nodes {
                    Some(nodes) if !nodes.is_empty() => {
                        let local = self.transport.local_node_id();
                        let dsts: Vec<NodeIdentifier> =
                            nodes.into_iter().filter(|n| *n != local).collect();
                        if dsts.is_empty() {
                            // Index exists but only the speaker is in the
                            // channel; nothing to do for cross-node delivery.
                            return Ok(());
                        }
                        self.send_multicast(sender_session, 0, is_terminator, payload, &dsts)
                            .await
                    }
                    _ => {
                        // No index entry yet — degrade safely to broadcast.
                        trace!(
                            channel_id,
                            "voice targeted: no index entry; falling back to broadcast"
                        );
                        self.send_broadcast(sender_session, 0, is_terminator, payload)
                            .await
                    }
                }
            }
        }
    }

    /// Unicast to a single peer.
    pub async fn send_unicast(
        &self,
        sender_session: u32,
        target_kind: u32,
        is_terminator: bool,
        payload: Bytes,
        dst: NodeIdentifier,
    ) -> Result<(), ApplicationError> {
        let bytes = self.encode(sender_session, target_kind, is_terminator, payload)?;
        self.transport.send_unicast(dst, bytes).await
    }

    fn encode(
        &self,
        sender_session: u32,
        target_kind: u32,
        is_terminator: bool,
        payload: Bytes,
    ) -> Result<Bytes, ApplicationError> {
        let seq = self.next_seq(sender_session);
        let bytes = send::build_envelope(
            sender_session,
            self.sender_epoch,
            seq,
            target_kind,
            is_terminator,
            payload,
        )?;
        Ok(bytes)
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

fn spawn_dispatch_task(
    mut rx: mpsc::UnboundedReceiver<DispatchEvent>,
    shutdown: CancellationToken,
    audio_sink: AudioSinkSlot,
    reorderer: Arc<Reorderer>,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                next = rx.recv() => {
                    let Some(ev) = next else { return };
                    let emits = match ev {
                        DispatchEvent::Inbound(d) => reorderer.push(d.from, d.frame),
                        DispatchEvent::DeadlineFired => reorderer.drain_expired(),
                    };
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
                        None => trace!(
                            n = emits.len(),
                            "voice: no audio sink installed; dropping emit batch",
                        ),
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    use crate::s2s::application::voice::send::testing::{FakeCall, FakeVoiceTransport};
    use crate::s2s::application::voice::sink::testing::RecordingSink;

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
        svc.send_broadcast(0xABC, 0, false, payload.clone())
            .await
            .unwrap();
        svc.send_broadcast(0xABC, 0, true, Bytes::from_static(b"opus-2"))
            .await
            .unwrap();

        let calls = transport.calls();
        assert_eq!(calls.len(), 2);
        let first = match &calls[0] {
            FakeCall::Broadcast { body } => proto::decode_voice(body).unwrap(),
            other => panic!("expected Broadcast, got {other:?}"),
        };
        let second = match &calls[1] {
            FakeCall::Broadcast { body } => proto::decode_voice(body).unwrap(),
            other => panic!("expected Broadcast, got {other:?}"),
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
    async fn multicast_skips_when_dsts_empty() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service(transport.clone());
        svc.send_multicast(0xABC, 2, false, Bytes::from_static(b"x"), &[])
            .await
            .unwrap();
        assert!(transport.calls().is_empty());
    }

    #[tokio::test]
    async fn multicast_emits_envelope_with_dsts() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service(transport.clone());
        svc.send_multicast(0xABC, 2, false, Bytes::from_static(b"whisper"), &[1, 3])
            .await
            .unwrap();
        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        match &calls[0] {
            FakeCall::Multicast { dsts, body } => {
                assert_eq!(dsts, &vec![1, 3]);
                let f = proto::decode_voice(body).unwrap();
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
        svc.send_unicast(0xABC, 2, true, Bytes::from_static(b"end"), 5)
            .await
            .unwrap();
        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        match &calls[0] {
            FakeCall::Unicast { dst, body } => {
                assert_eq!(*dst, 5);
                let f = proto::decode_voice(body).unwrap();
                assert!(f.is_terminator);
            }
            other => panic!("expected Unicast, got {other:?}"),
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

    #[tokio::test]
    async fn send_for_channel_broadcast_strategy_calls_broadcast() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service_with_strategy(transport.clone(), "broadcast");
        svc.send_for_channel(0xABC, /*channel=*/ 5, false, Bytes::from_static(b"x"))
            .await
            .unwrap();
        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        assert!(matches!(calls[0], FakeCall::Broadcast { .. }));
    }

    #[tokio::test]
    async fn send_for_channel_targeted_falls_back_to_broadcast_when_no_index() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service_with_strategy(transport.clone(), "targeted");
        svc.send_for_channel(0xABC, 5, false, Bytes::from_static(b"x"))
            .await
            .unwrap();
        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        assert!(matches!(calls[0], FakeCall::Broadcast { .. }));
    }

    #[tokio::test]
    async fn send_for_channel_targeted_uses_index() {
        use crate::s2s::application::voice::targeted::RecipientIndex;
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service_with_strategy(transport.clone(), "targeted");
        let idx = RecipientIndex::new();
        idx.add(5, 1);
        idx.add(5, 2);
        idx.add(5, 7); // self — must be filtered out
        svc.set_recipient_index(idx);
        svc.send_for_channel(0xABC, 5, false, Bytes::from_static(b"x"))
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
    async fn send_for_channel_targeted_no_op_when_only_self_in_channel() {
        use crate::s2s::application::voice::targeted::RecipientIndex;
        let transport = FakeVoiceTransport::new(7, vec![1, 2]);
        let svc = make_service_with_strategy(transport.clone(), "targeted");
        let idx = RecipientIndex::new();
        idx.add(5, 7); // only self
        svc.set_recipient_index(idx);
        svc.send_for_channel(0xABC, 5, false, Bytes::from_static(b"x"))
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
        let envelope =
            send::build_envelope(0xABC, 42, 5, 0, true, Bytes::from_static(b"opus-bytes")).unwrap();
        svc.inbound_handler().handle(OverlayInboundMessage {
            from: 11,
            level: crate::s2s::transport::ServiceLevel::BestEffort,
            class: crate::s2s::transport::MessageClass::HighPriority,
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
        let envelope =
            send::build_envelope(0xABC, 42, 0, 0, false, Bytes::from_static(b"x")).unwrap();
        svc.inbound_handler().handle(OverlayInboundMessage {
            from: 1,
            level: crate::s2s::transport::ServiceLevel::BestEffort,
            class: crate::s2s::transport::MessageClass::HighPriority,
            body: envelope,
        });
        // Give the dispatch task a chance to run; verify it doesn't panic.
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    #[tokio::test]
    async fn per_session_counters_independent() {
        let transport = FakeVoiceTransport::new(7, vec![1]);
        let svc = make_service(transport.clone());
        for session in [0xAAA, 0xBBB] {
            for _ in 0..3 {
                svc.send_broadcast(session, 0, false, Bytes::from_static(b"x"))
                    .await
                    .unwrap();
            }
        }
        let calls = transport.calls();
        assert_eq!(calls.len(), 6);
        let seqs: Vec<(u32, u64)> = calls
            .iter()
            .map(|c| match c {
                FakeCall::Broadcast { body } => {
                    let f = proto::decode_voice(body).unwrap();
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
