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
use crate::application::proto::{self, VOICE_REPAIR_SERVICE_TAG, VOICE_SERVICE_TAG, VoiceIntent};
use crate::overlay::{OverlayNetwork, OverlaySendOptions, RoutingMetric, VoiceRouteQuality};
use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::{MessageClass, ServiceLevel};

/// Voice frames are best-effort by design (drop tolerated, latency
/// critical) and run on the high-priority receiver queue.
pub const VOICE_LEVEL: ServiceLevel = ServiceLevel::BestEffort;
pub const VOICE_CLASS: MessageClass = MessageClass::HighPriority;
pub const VOICE_ROUTING_METRIC: RoutingMetric = RoutingMetric::ConversationalQuality;
pub const VOICE_REPAIR_LEVEL: ServiceLevel = ServiceLevel::BestEffort;
pub const VOICE_REPAIR_CLASS: MessageClass = MessageClass::HighPriority;
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

    async fn send_repair_frame(
        &self,
        dst: NodeIdentifier,
        body: Bytes,
        avoid_first_hop: Option<NodeIdentifier>,
        ttl: Duration,
    ) -> Result<(), ApplicationError>;

    fn alive_members(&self) -> Vec<NodeIdentifier>;

    fn voice_members(&self) -> Vec<NodeIdentifier> {
        self.alive_members()
    }

    fn local_node_id(&self) -> NodeIdentifier;

    fn voice_route_quality(&self, dst: NodeIdentifier) -> Option<VoiceRouteQuality>;
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

    async fn send_repair_frame(
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
    let frame = proto::VoiceFrame {
        sender_session,
        server_id,
        sender_epoch,
        s2s_seq,
        target_kind,
        is_terminator,
        payload,
        intent: Some(intent),
    };
    proto::encode_voice(&frame)
}

#[cfg(test)]
pub(crate) mod testing {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::Mutex;

    use super::*;

    /// Recording fake for asserting send shape in unit tests.
    #[derive(Debug, Default)]
    pub struct FakeVoiceTransport {
        pub local_node: NodeIdentifier,
        pub alive: Vec<NodeIdentifier>,
        pub calls: Mutex<Vec<FakeCall>>,
        voice_members: Mutex<Option<Vec<NodeIdentifier>>>,
        route_qualities: Mutex<HashMap<NodeIdentifier, VoiceRouteQuality>>,
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
            self.route_qualities.lock().unwrap().get(&dst).copied()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(decoded.payload, payload.as_ref());
        assert!(matches!(
            decoded.intent.and_then(|i| i.kind),
            Some(proto::VoiceIntentKind::Normal(n)) if n.source_channel == 5
        ));
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
