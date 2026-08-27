//! Speaker-side send primitives for the voice service.
//!
//! `VoiceTransport` is the narrow interface the rest of the codebase
//! talks to. The production impl wraps [`OverlayNetwork`]; tests can
//! substitute a recording fake to assert the dispatch shape (level,
//! class, recipients, encoded bytes) without standing up a cluster.

use async_trait::async_trait;
use bytes::Bytes;
use std::time::Duration;

use crate::application::error::ApplicationError;
use crate::application::proto::{
    self, VOICE_PATH_FEEDBACK_SERVICE_TAG, VOICE_REPAIR_SERVICE_TAG, VOICE_SERVICE_TAG,
    VoiceIntent, VoicePathFeedback,
};
use crate::application::voice::fec::FecSendOutcome;
use crate::overlay::{OverlayNetwork, OverlaySendOptions, RoutingMetric, VoiceRouteQuality};
use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::{MessageClass, ServiceLevel};

/// Voice frames are best-effort by design (drop tolerated, latency
/// critical) and run on the high-priority receiver queue.
pub const VOICE_LEVEL: ServiceLevel = ServiceLevel::BestEffort;
pub const VOICE_CLASS: MessageClass = MessageClass::HighPriority;
pub const VOICE_ROUTING_METRIC: RoutingMetric = RoutingMetric::ConversationalQuality;
pub const VOICE_REPAIR_LEVEL: ServiceLevel = ServiceLevel::BestEffort;
pub const VOICE_REPAIR_CLASS: MessageClass = MessageClass::Control;
pub const VOICE_REPAIR_ROUTING_METRIC: RoutingMetric = RoutingMetric::ConversationalQuality;

/// Stable identity of a recipient group passed to the generic distribution
/// transport. The recipient set itself is represented by `version`; callers
/// retain the same group ID while its membership is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DistributionGroup {
    id: u64,
    version: u64,
    kind: DistributionGroupKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistributionGroupKind {
    Broadcast,
    Targeted,
    RecipientSnapshot,
}

impl DistributionGroup {
    pub const fn broadcast() -> Self {
        Self {
            id: 0,
            version: 0,
            kind: DistributionGroupKind::Broadcast,
        }
    }

    /// Build a stable group for a server-scoped channel target. Channel order
    /// and duplicate channel IDs do not affect the group identity.
    pub fn targeted(server_id: &str, channel_ids: &[u32], recipients: &[NodeIdentifier]) -> Self {
        let mut channels = channel_ids.to_vec();
        channels.sort_unstable();
        channels.dedup();
        Self {
            id: hash_group_identity(server_id, &channels),
            version: hash_recipient_snapshot(recipients),
            kind: DistributionGroupKind::Targeted,
        }
    }

    /// Use the recipient set itself as the identity for an ad-hoc multicast
    /// that has no durable server/channel target.
    pub fn recipient_snapshot(recipients: &[NodeIdentifier]) -> Self {
        let version = hash_recipient_snapshot(recipients);
        Self {
            id: version,
            version,
            kind: DistributionGroupKind::RecipientSnapshot,
        }
    }

    pub const fn id(self) -> u64 {
        self.id
    }

    pub const fn version(self) -> u64 {
        self.version
    }

    pub const fn kind(self) -> DistributionGroupKind {
        self.kind
    }
}

fn hash_group_identity(server_id: &str, channel_ids: &[u32]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    hash_bytes(&mut hash, b"shitspeak.voice.targeted-group.v1");
    hash_bytes(&mut hash, server_id.as_bytes());
    hash_word(&mut hash, channel_ids.len() as u64);
    for channel_id in channel_ids {
        hash_word(&mut hash, u64::from(*channel_id));
    }
    hash.max(1)
}

fn hash_recipient_snapshot(recipients: &[NodeIdentifier]) -> u64 {
    let mut nodes: Vec<_> = recipients.iter().copied().collect();
    nodes.sort_unstable();
    nodes.dedup();

    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    hash_bytes(&mut hash, b"shitspeak.voice.recipient-snapshot.v1");
    hash_word(&mut hash, nodes.len() as u64);
    for node in nodes {
        hash_word(&mut hash, u64::from(node));
    }
    hash.max(1)
}

fn hash_bytes(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
}

fn hash_word(hash: &mut u64, value: u64) {
    hash_bytes(hash, &value.to_le_bytes());
}

/// Narrow send-only interface used by the voice service. Production
/// impl: [`OverlayVoiceTransport`]. Test impl: see the unit tests below.
#[async_trait]
pub trait VoiceTransport: Send + Sync + 'static {
    async fn send_unicast(
        &self,
        dst: NodeIdentifier,
        body: Bytes,
        ttl: Duration,
    ) -> Result<(), ApplicationError>;

    async fn send_multicast(
        &self,
        dsts: &[NodeIdentifier],
        body: Bytes,
        ttl: Duration,
    ) -> Result<(), ApplicationError>;

    /// Send a multicast through the generic source-rooted tree path. The
    /// default keeps test transports and mixed-version deployments on the
    /// legacy path until the production transport opts in.
    async fn send_tree_multicast(
        &self,
        dsts: &[NodeIdentifier],
        group: DistributionGroup,
        body: Bytes,
        ttl: Duration,
    ) -> Result<(), ApplicationError> {
        let _ = group;
        self.send_multicast(dsts, body, ttl).await
    }

    async fn send_broadcast(&self, body: Bytes, ttl: Duration) -> Result<(), ApplicationError>;

    async fn send_repair_request(
        &self,
        dst: NodeIdentifier,
        body: Bytes,
        ttl: Duration,
    ) -> Result<(), ApplicationError>;

    async fn send_path_feedback(
        &self,
        _dst: NodeIdentifier,
        _feedback: VoicePathFeedback,
    ) -> Result<(), ApplicationError> {
        Err(ApplicationError::Unavailable)
    }

    fn record_path_feedback(&self, _from: NodeIdentifier, _feedback: VoicePathFeedback) {}

    async fn send_repair_frame(
        &self,
        dst: NodeIdentifier,
        body: Bytes,
        avoid_first_hop: Option<NodeIdentifier>,
        ttl: Duration,
    ) -> Result<(), ApplicationError>;

    /// Send an already-marked proactive alternate copy. The caller is
    /// responsible for deriving it from the original envelope once and may
    /// reuse those bytes for every proactive destination.
    async fn send_proactive_repair_frame(
        &self,
        dst: NodeIdentifier,
        body: Bytes,
        avoid_first_hop: Option<NodeIdentifier>,
        ttl: Duration,
    ) -> Result<(), ApplicationError>;

    /// Emit one FEC parity frame toward every receiver in `dsts`, all of
    /// which share `first_hop`. The production transport rate-limits per
    /// `first_hop` against the overlay's lane-headroom budget and reports
    /// whether the frame was admitted (`Sent`) or shed (`Shed`) before
    /// leaving. The default keeps test transports on the plain multicast
    /// path.
    async fn send_fec_frame(
        &self,
        dsts: &[NodeIdentifier],
        first_hop: Option<NodeIdentifier>,
        body: Bytes,
        ttl: Duration,
    ) -> FecSendOutcome {
        let _ = first_hop;
        match self.send_multicast(dsts, body, ttl).await {
            Ok(()) => FecSendOutcome::Sent,
            Err(_) => FecSendOutcome::Shed,
        }
    }

    fn alive_members(&self) -> Vec<NodeIdentifier>;

    fn voice_members(&self) -> Vec<NodeIdentifier> {
        self.alive_members()
    }

    fn local_node_id(&self) -> NodeIdentifier;

    fn voice_route_quality(&self, dst: NodeIdentifier) -> Option<VoiceRouteQuality>;

    /// Return route quality for each destination in the same order as
    /// `dsts`. Production transports can override this to share work across
    /// destinations whose routes use the same next hop.
    fn voice_route_qualities(&self, dsts: &[NodeIdentifier]) -> Vec<Option<VoiceRouteQuality>> {
        dsts.iter()
            .map(|&dst| self.voice_route_quality(dst))
            .collect()
    }

    /// Whether the best-effort datagram lane to `first_hop` is currently
    /// evicting at the send path. The FEC sender skips parity while true — the
    /// parity would be shed before the wire too. Test transports default to
    /// `false`.
    fn datagram_lane_shedding(&self, first_hop: NodeIdentifier) -> bool {
        let _ = first_hop;
        false
    }
}

/// Production `VoiceTransport` impl backed by the overlay network.
pub struct OverlayVoiceTransport {
    pub overlay: OverlayNetwork,
}

#[async_trait]
impl VoiceTransport for OverlayVoiceTransport {
    async fn send_unicast(
        &self,
        dst: NodeIdentifier,
        body: Bytes,
        ttl: Duration,
    ) -> Result<(), ApplicationError> {
        let options = OverlaySendOptions::default().expire_after(ttl);
        self.overlay
            .send_unicast_unordered_with_routing_metric_and_options(
                dst,
                VOICE_SERVICE_TAG,
                VOICE_LEVEL,
                VOICE_ROUTING_METRIC,
                VOICE_CLASS,
                body,
                options,
            )
            .await?;
        Ok(())
    }

    async fn send_multicast(
        &self,
        dsts: &[NodeIdentifier],
        body: Bytes,
        ttl: Duration,
    ) -> Result<(), ApplicationError> {
        if dsts.is_empty() {
            return Ok(());
        }
        let options = OverlaySendOptions::default().expire_after(ttl);
        self.overlay
            .send_multicast_unordered_with_routing_metric_and_options(
                dsts,
                VOICE_SERVICE_TAG,
                VOICE_LEVEL,
                VOICE_ROUTING_METRIC,
                VOICE_CLASS,
                body,
                options,
            )
            .await?;
        Ok(())
    }

    async fn send_tree_multicast(
        &self,
        dsts: &[NodeIdentifier],
        group: DistributionGroup,
        body: Bytes,
        ttl: Duration,
    ) -> Result<(), ApplicationError> {
        if dsts.is_empty() {
            return Ok(());
        }
        let options = OverlaySendOptions::default().expire_after(ttl);
        self.overlay
            .send_multicast_tree_unordered_with_routing_metric_and_group_options(
                dsts,
                group.id(),
                group.version(),
                VOICE_SERVICE_TAG,
                VOICE_LEVEL,
                VOICE_ROUTING_METRIC,
                VOICE_CLASS,
                body,
                options,
            )
            .await?;
        Ok(())
    }

    async fn send_broadcast(&self, body: Bytes, ttl: Duration) -> Result<(), ApplicationError> {
        let local = self.overlay.local_node_id();
        let dsts: Vec<NodeIdentifier> = self
            .overlay
            .voice_members()
            .into_iter()
            .filter(|node| *node != local)
            .collect();
        if dsts.is_empty() {
            return Ok(());
        }
        let options = OverlaySendOptions::default().expire_after(ttl);
        self.overlay
            .send_multicast_unordered_with_routing_metric_and_options(
                &dsts,
                VOICE_SERVICE_TAG,
                VOICE_LEVEL,
                VOICE_ROUTING_METRIC,
                VOICE_CLASS,
                body,
                options,
            )
            .await?;
        Ok(())
    }

    async fn send_repair_request(
        &self,
        dst: NodeIdentifier,
        body: Bytes,
        ttl: Duration,
    ) -> Result<(), ApplicationError> {
        let options = OverlaySendOptions::default().expire_after(ttl);
        self.overlay
            .send_unicast_unordered_with_routing_metric_and_options(
                dst,
                VOICE_REPAIR_SERVICE_TAG,
                VOICE_REPAIR_LEVEL,
                VOICE_REPAIR_ROUTING_METRIC,
                VOICE_REPAIR_CLASS,
                body,
                options,
            )
            .await?;
        Ok(())
    }

    async fn send_path_feedback(
        &self,
        dst: NodeIdentifier,
        feedback: VoicePathFeedback,
    ) -> Result<(), ApplicationError> {
        let body = proto::encode_voice_path_feedback(&feedback)?;
        self.overlay
            .send_unicast_unordered_with_routing_metric_and_options(
                dst,
                VOICE_PATH_FEEDBACK_SERVICE_TAG,
                VOICE_REPAIR_LEVEL,
                VOICE_REPAIR_ROUTING_METRIC,
                VOICE_REPAIR_CLASS,
                body,
                OverlaySendOptions::default().expire_after(Duration::from_secs(1)),
            )
            .await?;
        Ok(())
    }

    fn record_path_feedback(&self, from: NodeIdentifier, feedback: VoicePathFeedback) {
        self.overlay.record_voice_path_feedback(from, feedback);
    }

    async fn send_repair_frame(
        &self,
        dst: NodeIdentifier,
        body: Bytes,
        avoid_first_hop: Option<NodeIdentifier>,
        ttl: Duration,
    ) -> Result<(), ApplicationError> {
        let mut options = OverlaySendOptions::default()
            .expire_after(ttl)
            .as_distribution_repair();
        if let Some(first_hop) = avoid_first_hop {
            options = options.avoid_first_hop(first_hop);
        }
        self.overlay
            .send_unicast_unordered_with_routing_metric_and_options(
                dst,
                VOICE_SERVICE_TAG,
                VOICE_LEVEL,
                VOICE_ROUTING_METRIC,
                VOICE_REPAIR_CLASS,
                body,
                options,
            )
            .await?;
        Ok(())
    }

    async fn send_proactive_repair_frame(
        &self,
        dst: NodeIdentifier,
        body: Bytes,
        avoid_first_hop: Option<NodeIdentifier>,
        ttl: Duration,
    ) -> Result<(), ApplicationError> {
        let mut options = OverlaySendOptions::default().expire_after(ttl);
        if let Some(first_hop) = avoid_first_hop {
            options = options.avoid_first_hop(first_hop);
        }
        self.overlay
            .send_unicast_unordered_with_routing_metric_and_options(
                dst,
                VOICE_SERVICE_TAG,
                VOICE_LEVEL,
                VOICE_ROUTING_METRIC,
                VOICE_CLASS,
                body,
                options,
            )
            .await?;
        Ok(())
    }

    async fn send_fec_frame(
        &self,
        dsts: &[NodeIdentifier],
        first_hop: Option<NodeIdentifier>,
        body: Bytes,
        ttl: Duration,
    ) -> FecSendOutcome {
        if dsts.is_empty() {
            return FecSendOutcome::Shed;
        }
        // Without a known first hop there is no lane budget to hold the
        // parity against; fall back to the plain multicast path.
        let Some(first_hop) = first_hop else {
            return match self.send_multicast(dsts, body, ttl).await {
                Ok(()) => FecSendOutcome::Sent,
                Err(_) => FecSendOutcome::Shed,
            };
        };
        let bytes = body.len();
        if !self.overlay.try_reserve_fec_headroom(first_hop, bytes) {
            return FecSendOutcome::Shed;
        }
        let options = OverlaySendOptions::default().expire_after(ttl);
        let result = self
            .overlay
            .send_multicast_unordered_with_routing_metric_and_options(
                dsts,
                VOICE_SERVICE_TAG,
                VOICE_LEVEL,
                VOICE_ROUTING_METRIC,
                VOICE_CLASS,
                body,
                options,
            )
            .await;
        self.overlay
            .release_fec_headroom(first_hop, bytes, result.is_ok());
        match result {
            Ok(()) => FecSendOutcome::Sent,
            Err(_) => FecSendOutcome::Shed,
        }
    }

    fn alive_members(&self) -> Vec<NodeIdentifier> {
        self.overlay.alive_members()
    }

    fn voice_members(&self) -> Vec<NodeIdentifier> {
        self.overlay.voice_members()
    }

    fn local_node_id(&self) -> NodeIdentifier {
        self.overlay.local_node_id()
    }

    fn voice_route_quality(&self, dst: NodeIdentifier) -> Option<VoiceRouteQuality> {
        self.overlay.voice_route_quality(dst)
    }

    fn voice_route_qualities(&self, dsts: &[NodeIdentifier]) -> Vec<Option<VoiceRouteQuality>> {
        self.overlay.voice_route_qualities(dsts)
    }

    fn datagram_lane_shedding(&self, first_hop: NodeIdentifier) -> bool {
        self.overlay.datagram_lane_shedding(first_hop)
    }
}

/// A voice envelope prepared for ordinary delivery and, if admitted, one
/// proactive alternate copy.
///
/// The unmarked body is encoded when this value is created so callers can
/// send and cache it immediately. The marked proactive body is encoded only
/// on the first [`Self::proactive_body`] call, directly from the retained
/// [`proto::VoiceFrame`]. This keeps NACK replay on the original body and
/// avoids decoding that cached wire representation to create a proactive
/// copy.
pub struct PreparedVoiceEnvelope {
    frame: proto::VoiceFrame,
    original_body: Bytes,
    proactive_body: Option<Bytes>,
}

impl PreparedVoiceEnvelope {
    /// Prepare an unmarked voice envelope from an already-built frame.
    ///
    /// A caller cannot accidentally cache a proactive-marked frame: the
    /// ordinary representation is always encoded with the marker clear.
    pub fn from_frame(mut frame: proto::VoiceFrame) -> Result<Self, prost::EncodeError> {
        frame.proactive_copy = false;
        let original_body = proto::encode_voice(&frame)?;
        Ok(Self {
            frame,
            original_body,
            proactive_body: None,
        })
    }

    /// Construct a prepared envelope from the normal voice send fields.
    pub fn new(
        sender_session: u32,
        server_id: String,
        sender_epoch: u64,
        s2s_seq: u64,
        target_kind: u32,
        is_terminator: bool,
        payload: Bytes,
        intent: VoiceIntent,
    ) -> Result<Self, prost::EncodeError> {
        Self::from_frame(proto::VoiceFrame {
            sender_session,
            server_id,
            sender_epoch,
            s2s_seq,
            target_kind,
            is_terminator,
            payload,
            intent: Some(intent),
            proactive_copy: false,
            fec_parity: false,
            fec_member_seqs: Vec::new(),
            fec_terminator_mask: 0,
            fec_parity_index: 0,
        })
    }

    /// Return a cheap clone of the unmarked body for ordinary send or repair
    /// cache insertion.
    pub fn original_body(&self) -> Bytes {
        self.original_body.clone()
    }

    /// Cheap clone of the raw audio payload. Used by the FEC sender to build
    /// parity without re-decoding the encoded body.
    pub fn payload(&self) -> Bytes {
        self.frame.payload.clone()
    }

    /// Lazily encode and cache the one marked proactive alternate body.
    ///
    /// Subsequent calls clone the cached [`Bytes`] allocation. The retained
    /// ordinary frame is temporarily marked for serialization and restored
    /// before this method returns, so the original cache can never acquire
    /// the proactive marker.
    pub fn proactive_body(&mut self) -> Result<Bytes, prost::EncodeError> {
        if let Some(body) = &self.proactive_body {
            return Ok(body.clone());
        }

        self.frame.proactive_copy = true;
        let encoded = proto::encode_voice(&self.frame);
        self.frame.proactive_copy = false;
        let body = encoded?;
        self.proactive_body = Some(body.clone());
        Ok(body)
    }
}

/// Build the wire envelope and encode it. Pulled out so unit tests can
/// reach in without a transport.
pub fn build_envelope(
    sender_session: u32,
    server_id: String,
    sender_epoch: u64,
    s2s_seq: u64,
    target_kind: u32,
    is_terminator: bool,
    payload: Bytes,
    intent: VoiceIntent,
) -> Result<Bytes, prost::EncodeError> {
    PreparedVoiceEnvelope::new(
        sender_session,
        server_id,
        sender_epoch,
        s2s_seq,
        target_kind,
        is_terminator,
        payload,
        intent,
    )
    .map(|envelope| envelope.original_body())
}

/// Derive the wire envelope for a proactive alternate copy without changing
/// the cached original used by NACK repair. This marker distinguishes an
/// early duplicate from a true original at the receiver.
pub fn mark_proactive_copy(body: &Bytes) -> Result<Bytes, ApplicationError> {
    let mut frame = proto::decode_voice(body)?;
    frame.proactive_copy = true;
    Ok(proto::encode_voice(&frame)?)
}

#[cfg(test)]
pub(crate) mod testing {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    /// Recording fake for asserting send shape in unit tests.
    #[derive(Debug, Default)]
    pub struct FakeVoiceTransport {
        pub local_node: NodeIdentifier,
        pub alive: Vec<NodeIdentifier>,
        pub calls: Mutex<Vec<FakeCall>>,
        voice_members: Mutex<Option<Vec<NodeIdentifier>>>,
        route_qualities: Mutex<HashMap<NodeIdentifier, VoiceRouteQuality>>,
        route_quality_scalar_calls: AtomicU64,
        route_quality_batches: Mutex<Vec<Vec<NodeIdentifier>>>,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum FakeCall {
        Unicast {
            dst: NodeIdentifier,
            body: Bytes,
            ttl: Duration,
        },
        Multicast {
            dsts: Vec<NodeIdentifier>,
            body: Bytes,
            ttl: Duration,
        },
        TreeMulticast {
            dsts: Vec<NodeIdentifier>,
            group: DistributionGroup,
            body: Bytes,
            ttl: Duration,
        },
        Broadcast {
            body: Bytes,
            ttl: Duration,
        },
        RepairRequest {
            dst: NodeIdentifier,
            body: Bytes,
            ttl: Duration,
        },
        RepairFrame {
            dst: NodeIdentifier,
            body: Bytes,
            avoid_first_hop: Option<NodeIdentifier>,
            ttl: Duration,
            is_repair: bool,
        },
    }

    impl FakeVoiceTransport {
        pub fn new(local_node: NodeIdentifier, alive: Vec<NodeIdentifier>) -> Arc<Self> {
            Arc::new(Self {
                local_node,
                alive,
                calls: Mutex::new(Vec::new()),
                voice_members: Mutex::new(None),
                route_qualities: Mutex::new(HashMap::new()),
                route_quality_scalar_calls: AtomicU64::new(0),
                route_quality_batches: Mutex::new(Vec::new()),
            })
        }

        pub fn calls(&self) -> Vec<FakeCall> {
            self.calls.lock().unwrap().clone()
        }

        pub fn set_voice_route_quality(&self, dst: NodeIdentifier, quality: VoiceRouteQuality) {
            self.route_qualities.lock().unwrap().insert(dst, quality);
        }

        pub fn set_voice_members(&self, nodes: Vec<NodeIdentifier>) {
            *self.voice_members.lock().unwrap() = Some(nodes);
        }

        pub fn route_quality_scalar_calls(&self) -> u64 {
            self.route_quality_scalar_calls.load(Ordering::SeqCst)
        }

        pub fn route_quality_batches(&self) -> Vec<Vec<NodeIdentifier>> {
            self.route_quality_batches.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl VoiceTransport for FakeVoiceTransport {
        async fn send_unicast(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.calls
                .lock()
                .unwrap()
                .push(FakeCall::Unicast { dst, body, ttl });
            Ok(())
        }

        async fn send_multicast(
            &self,
            dsts: &[NodeIdentifier],
            body: Bytes,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.calls.lock().unwrap().push(FakeCall::Multicast {
                dsts: dsts.to_vec(),
                body,
                ttl,
            });
            Ok(())
        }

        async fn send_tree_multicast(
            &self,
            dsts: &[NodeIdentifier],
            group: DistributionGroup,
            body: Bytes,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.calls.lock().unwrap().push(FakeCall::TreeMulticast {
                dsts: dsts.to_vec(),
                group,
                body,
                ttl,
            });
            Ok(())
        }

        async fn send_broadcast(&self, body: Bytes, ttl: Duration) -> Result<(), ApplicationError> {
            self.calls
                .lock()
                .unwrap()
                .push(FakeCall::Broadcast { body, ttl });
            Ok(())
        }

        async fn send_repair_request(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.calls
                .lock()
                .unwrap()
                .push(FakeCall::RepairRequest { dst, body, ttl });
            Ok(())
        }

        async fn send_repair_frame(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            avoid_first_hop: Option<NodeIdentifier>,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.calls.lock().unwrap().push(FakeCall::RepairFrame {
                dst,
                body,
                avoid_first_hop,
                ttl,
                is_repair: true,
            });
            Ok(())
        }

        async fn send_proactive_repair_frame(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            avoid_first_hop: Option<NodeIdentifier>,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.calls.lock().unwrap().push(FakeCall::RepairFrame {
                dst,
                body,
                avoid_first_hop,
                ttl,
                is_repair: false,
            });
            Ok(())
        }

        fn alive_members(&self) -> Vec<NodeIdentifier> {
            self.alive.clone()
        }

        fn voice_members(&self) -> Vec<NodeIdentifier> {
            self.voice_members
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| self.alive.clone())
        }

        fn local_node_id(&self) -> NodeIdentifier {
            self.local_node
        }

        fn voice_route_quality(&self, dst: NodeIdentifier) -> Option<VoiceRouteQuality> {
            self.route_quality_scalar_calls
                .fetch_add(1, Ordering::SeqCst);
            self.route_qualities.lock().unwrap().get(&dst).copied()
        }

        fn voice_route_qualities(&self, dsts: &[NodeIdentifier]) -> Vec<Option<VoiceRouteQuality>> {
            self.route_quality_batches
                .lock()
                .unwrap()
                .push(dsts.to_vec());
            let qualities = self.route_qualities.lock().unwrap();
            dsts.iter().map(|dst| qualities.get(dst).copied()).collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    struct ScalarOnlyVoiceTransport {
        qualities: HashMap<NodeIdentifier, VoiceRouteQuality>,
        quality_calls: Mutex<Vec<NodeIdentifier>>,
    }

    #[async_trait]
    impl VoiceTransport for ScalarOnlyVoiceTransport {
        async fn send_unicast(
            &self,
            _dst: NodeIdentifier,
            _body: Bytes,
            _ttl: Duration,
        ) -> Result<(), ApplicationError> {
            Ok(())
        }

        async fn send_multicast(
            &self,
            _dsts: &[NodeIdentifier],
            _body: Bytes,
            _ttl: Duration,
        ) -> Result<(), ApplicationError> {
            Ok(())
        }

        async fn send_broadcast(
            &self,
            _body: Bytes,
            _ttl: Duration,
        ) -> Result<(), ApplicationError> {
            Ok(())
        }

        async fn send_repair_request(
            &self,
            _dst: NodeIdentifier,
            _body: Bytes,
            _ttl: Duration,
        ) -> Result<(), ApplicationError> {
            Ok(())
        }

        async fn send_repair_frame(
            &self,
            _dst: NodeIdentifier,
            _body: Bytes,
            _avoid_first_hop: Option<NodeIdentifier>,
            _ttl: Duration,
        ) -> Result<(), ApplicationError> {
            Ok(())
        }

        async fn send_proactive_repair_frame(
            &self,
            _dst: NodeIdentifier,
            _body: Bytes,
            _avoid_first_hop: Option<NodeIdentifier>,
            _ttl: Duration,
        ) -> Result<(), ApplicationError> {
            Ok(())
        }

        fn alive_members(&self) -> Vec<NodeIdentifier> {
            Vec::new()
        }

        fn local_node_id(&self) -> NodeIdentifier {
            1
        }

        fn voice_route_quality(&self, dst: NodeIdentifier) -> Option<VoiceRouteQuality> {
            self.quality_calls.lock().unwrap().push(dst);
            self.qualities.get(&dst).copied()
        }
    }

    #[test]
    fn default_quality_batch_preserves_alignment_and_scalar_fallback_behavior() {
        let quality_two =
            VoiceRouteQuality::new(2, shitspeak_s2s_transport::TransportKind::Tcp, 10, 20, 30)
                .with_alternate_route_quality(
                    3,
                    40,
                    shitspeak_s2s_transport::TransportKind::Udp,
                    50,
                    60,
                );
        let quality_four =
            VoiceRouteQuality::new(4, shitspeak_s2s_transport::TransportKind::Udp, 40, 50, 60);
        let transport = ScalarOnlyVoiceTransport {
            qualities: HashMap::from([(2, quality_two), (4, quality_four)]),
            quality_calls: Mutex::new(Vec::new()),
        };

        assert_eq!(
            transport.voice_route_qualities(&[2, 3, 2, 4]),
            vec![
                Some(quality_two),
                None,
                Some(quality_two),
                Some(quality_four)
            ],
        );
        assert_eq!(*transport.quality_calls.lock().unwrap(), vec![2, 3, 2, 4]);
        assert_eq!(quality_two.alternate_next_hop(), Some(3));
        assert_eq!(quality_two.alternate_path_latency_us(), Some(40));
        assert_eq!(
            quality_two.alternate_transport(),
            Some(shitspeak_s2s_transport::TransportKind::Udp)
        );
        assert_eq!(quality_two.alternate_loss_ppm(), Some(50));
        assert_eq!(quality_two.alternate_jitter_us(), Some(60));
    }

    #[test]
    fn envelope_roundtrip() {
        let payload = Bytes::from_static(b"opus-bytes-here");
        let bytes = build_envelope(
            0xABC_12345,
            shitspeak_core::default_server_id(),
            1_700_000_000_000_000,
            42,
            0,
            false,
            payload.clone(),
            VoiceIntent {
                kind: Some(proto::VoiceIntentKind::Normal(proto::VoiceIntentNormal {
                    source_channel: 5,
                })),
            },
        )
        .unwrap();
        let decoded = proto::decode_voice(&bytes).unwrap();
        assert_eq!(decoded.sender_session, 0xABC_12345);
        assert_eq!(decoded.server_id, shitspeak_core::default_server_id());
        assert_eq!(decoded.sender_epoch, 1_700_000_000_000_000);
        assert_eq!(decoded.s2s_seq, 42);
        assert_eq!(decoded.target_kind, 0);
        assert!(!decoded.is_terminator);
        assert!(!decoded.proactive_copy);
        assert_eq!(decoded.payload, payload.as_ref());
        assert!(matches!(
            decoded.intent.and_then(|i| i.kind),
            Some(proto::VoiceIntentKind::Normal(n)) if n.source_channel == 5
        ));
    }

    #[test]
    fn proactive_copy_has_a_distinct_wire_marker_without_changing_the_original() {
        let original = build_envelope(
            7,
            shitspeak_core::default_server_id(),
            11,
            13,
            0,
            false,
            Bytes::from_static(b"opus"),
            VoiceIntent {
                kind: Some(proto::VoiceIntentKind::Normal(proto::VoiceIntentNormal {
                    source_channel: 5,
                })),
            },
        )
        .unwrap();

        let proactive = mark_proactive_copy(&original).unwrap();
        assert!(!proto::decode_voice(&original).unwrap().proactive_copy);

        let mut marked = proto::decode_voice(&proactive).unwrap();
        assert!(marked.proactive_copy);
        marked.proactive_copy = false;
        assert_eq!(marked, proto::decode_voice(&original).unwrap());
    }

    #[test]
    fn prepared_envelope_caches_one_lazy_proactive_body_without_decoding_original() {
        let mut envelope = PreparedVoiceEnvelope::new(
            7,
            shitspeak_core::default_server_id(),
            11,
            13,
            0,
            false,
            Bytes::from_static(b"opus"),
            VoiceIntent {
                kind: Some(proto::VoiceIntentKind::Normal(proto::VoiceIntentNormal {
                    source_channel: 5,
                })),
            },
        )
        .unwrap();

        let original = envelope.original_body();
        assert!(!proto::decode_voice(&original).unwrap().proactive_copy);
        assert!(envelope.proactive_body.is_none());

        let first = envelope.proactive_body().unwrap();
        assert!(proto::decode_voice(&first).unwrap().proactive_copy);
        assert_eq!(envelope.proactive_body.as_ref(), Some(&first));

        let second = envelope.proactive_body().unwrap();
        assert_eq!(first, second);
        assert_eq!(envelope.proactive_body.as_ref(), Some(&second));
        assert!(
            !proto::decode_voice(&envelope.original_body())
                .unwrap()
                .proactive_copy
        );
    }

    #[test]
    fn prepared_envelope_normalizes_a_pre_marked_input_frame() {
        let mut envelope = PreparedVoiceEnvelope::from_frame(proto::VoiceFrame {
            sender_session: 7,
            server_id: shitspeak_core::default_server_id(),
            sender_epoch: 11,
            s2s_seq: 13,
            target_kind: 0,
            is_terminator: false,
            payload: Bytes::from_static(b"opus"),
            intent: Some(VoiceIntent {
                kind: Some(proto::VoiceIntentKind::Normal(proto::VoiceIntentNormal {
                    source_channel: 5,
                })),
            }),
            proactive_copy: true,
            fec_parity: false,
            fec_member_seqs: Vec::new(),
            fec_terminator_mask: 0,
            fec_parity_index: 0,
        })
        .unwrap();

        assert!(
            !proto::decode_voice(&envelope.original_body())
                .unwrap()
                .proactive_copy
        );
        assert!(
            proto::decode_voice(&envelope.proactive_body().unwrap())
                .unwrap()
                .proactive_copy
        );
    }

    #[tokio::test]
    async fn proactive_send_keeps_the_marked_copy_while_nack_replay_keeps_the_cached_original() {
        let transport = testing::FakeVoiceTransport::new(1, vec![1, 2]);
        let original = build_envelope(
            7,
            shitspeak_core::default_server_id(),
            11,
            13,
            0,
            false,
            Bytes::from_static(b"opus"),
            VoiceIntent {
                kind: Some(proto::VoiceIntentKind::Normal(proto::VoiceIntentNormal {
                    source_channel: 5,
                })),
            },
        )
        .unwrap();

        let marked = mark_proactive_copy(&original).unwrap();
        transport
            .send_proactive_repair_frame(2, marked.clone(), None, Duration::from_millis(40))
            .await
            .unwrap();
        transport
            .send_repair_frame(2, original.clone(), None, Duration::from_millis(40))
            .await
            .unwrap();

        let calls = transport.calls();
        let testing::FakeCall::RepairFrame {
            body: sent_proactive,
            is_repair: false,
            ..
        } = &calls[0]
        else {
            panic!("expected marked proactive copy");
        };
        assert_eq!(sent_proactive, &marked);
        assert!(proto::decode_voice(sent_proactive).unwrap().proactive_copy);

        let testing::FakeCall::RepairFrame {
            body: reactive,
            is_repair: true,
            ..
        } = &calls[1]
        else {
            panic!("expected unmodified NACK replay");
        };
        assert_eq!(reactive, &original);
        assert!(!proto::decode_voice(reactive).unwrap().proactive_copy);
    }

    #[test]
    fn broadcast_distribution_group_is_reserved() {
        let group = DistributionGroup::broadcast();
        assert_eq!(group.id(), 0);
        assert_eq!(group.version(), 0);
        assert_eq!(group.kind(), DistributionGroupKind::Broadcast);
    }

    #[test]
    fn targeted_distribution_group_keeps_identity_when_membership_is_unchanged() {
        let first = DistributionGroup::targeted("tenant-a", &[9, 5, 9], &[7, 2, 7]);
        let reordered = DistributionGroup::targeted("tenant-a", &[5, 9], &[2, 7]);
        let changed_members = DistributionGroup::targeted("tenant-a", &[5, 9], &[2, 3]);

        assert_eq!(first.kind(), DistributionGroupKind::Targeted);
        assert_eq!(first.id(), reordered.id());
        assert_eq!(first.version(), reordered.version());
        assert_eq!(first.id(), changed_members.id());
        assert_ne!(first.version(), changed_members.version());
    }
}
