//! End-to-end ordered overlay lanes and repair bookkeeping.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::{Mutex, MutexGuard};
use tracing::warn;

use crate::overlay::LaneId;
use crate::overlay::config::OverlayConfig;
use shitspeak_core::NodeIdentifier;
use shitspeak_proto::s2s_overlay_proto as pb;
use shitspeak_s2s_transport::{MessageClass, ServiceLevel};

use super::super::proto::level_from_wire;

const UNORDERED_DELIVERY_DEDUPE_CAP: usize = 4096;
const UNORDERED_FORWARD_DEDUPE_CAP: usize = 16384;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct OutboundKey {
    dst: NodeIdentifier,
    lane: LaneId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct InboundKey {
    src: NodeIdentifier,
    boot_epoch: u64,
    dst: NodeIdentifier,
    lane: LaneId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RemoteLaneKey {
    src: NodeIdentifier,
    boot_epoch: u64,
    dst: NodeIdentifier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RepairKey {
    origin: NodeIdentifier,
    boot_epoch: u64,
    final_dst: NodeIdentifier,
    lane: LaneId,
    seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DeliveryKey {
    origin: NodeIdentifier,
    boot_epoch: u64,
    message_id: u64,
    service_tag: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UnorderedForwardKey {
    origin: NodeIdentifier,
    boot_epoch: u64,
    message_id: u64,
    service_tag: u32,
    final_dst: NodeIdentifier,
}

#[derive(Debug, Clone)]
struct PendingPacket {
    data: pb::OverlayData,
    first_sent_at: Instant,
    next_retry_at: Instant,
    retry_delay: Duration,
    retry_attempts: u32,
}

#[derive(Debug, Default)]
struct InboundState {
    next_seq: u64,
    buffered: BTreeMap<u64, OrderedDelivery>,
}

#[derive(Debug, Default)]
struct RepairCache {
    cap: usize,
    order: VecDeque<RepairKey>,
    packets: HashMap<RepairKey, pb::OverlayData>,
}

impl RepairCache {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            order: VecDeque::with_capacity(cap),
            packets: HashMap::new(),
        }
    }

    fn insert(&mut self, key: RepairKey, packet: pb::OverlayData) {
        if self.cap == 0 {
            return;
        }
        if self.packets.contains_key(&key) {
            self.packets.insert(key, packet);
            return;
        }
        while self.order.len() >= self.cap {
            if let Some(old) = self.order.pop_front() {
                self.packets.remove(&old);
            } else {
                break;
            }
        }
        self.order.push_back(key);
        self.packets.insert(key, packet);
    }

    fn range(
        &self,
        origin: NodeIdentifier,
        boot_epoch: u64,
        final_dst: NodeIdentifier,
        lane: LaneId,
        first: u64,
        last: u64,
    ) -> Vec<pb::OverlayData> {
        (first..=last)
            .filter_map(|seq| {
                self.packets
                    .get(&RepairKey {
                        origin,
                        boot_epoch,
                        final_dst,
                        lane,
                        seq,
                    })
                    .cloned()
            })
            .collect()
    }

    fn retain_peer(&mut self, peer: NodeIdentifier) {
        self.order.retain(|key| {
            if key.origin == peer || key.final_dst == peer {
                self.packets.remove(key);
                false
            } else {
                true
            }
        });
    }
}

#[derive(Debug)]
struct BoundedDedupe<K> {
    cap: usize,
    order: VecDeque<K>,
    seen: HashSet<K>,
}

impl<K> BoundedDedupe<K>
where
    K: Copy + Eq + Hash,
{
    fn new(cap: usize) -> Self {
        Self {
            cap,
            order: VecDeque::with_capacity(cap),
            seen: HashSet::with_capacity(cap),
        }
    }

    fn insert(&mut self, key: K) -> bool {
        if self.cap == 0 {
            return true;
        }
        if self.seen.contains(&key) {
            return false;
        }
        while self.order.len() >= self.cap {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        self.order.push_back(key);
        self.seen.insert(key);
        true
    }
}

#[derive(Debug)]
pub(crate) struct OverlayOrdering {
    outbound_send: Mutex<()>,
    outbound_next: Mutex<HashMap<OutboundKey, u64>>,
    pending: Mutex<HashMap<OutboundKey, BTreeMap<u64, PendingPacket>>>,
    inbound: Mutex<HashMap<InboundKey, InboundState>>,
    local_lanes: Mutex<HashSet<LaneId>>,
    remote_lanes: Mutex<HashMap<RemoteLaneKey, HashSet<LaneId>>>,
    repair_cache: Mutex<RepairCache>,
    unordered_delivered_seen: Mutex<BoundedDedupe<DeliveryKey>>,
    ordered_transit_seen: Mutex<BoundedDedupe<DeliveryKey>>,
    unordered_forwarded_seen: Mutex<BoundedDedupe<UnorderedForwardKey>>,
    origin_message_id: AtomicU64,
    lane_cap: NonZeroUsize,
    pending_window_packets: usize,
    reorder_buffer_packets: usize,
    retry_initial: Duration,
    retry_max: Duration,
    retry_max_age: Duration,
    retry_max_attempts: u32,
}

impl OverlayOrdering {
    pub(crate) fn new(cfg: &OverlayConfig) -> Self {
        Self {
            outbound_send: Mutex::new(()),
            outbound_next: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            inbound: Mutex::new(HashMap::new()),
            local_lanes: Mutex::new(HashSet::new()),
            remote_lanes: Mutex::new(HashMap::new()),
            repair_cache: Mutex::new(RepairCache::new(cfg.ordered_repair_cache_packets())),
            unordered_delivered_seen: Mutex::new(BoundedDedupe::new(UNORDERED_DELIVERY_DEDUPE_CAP)),
            ordered_transit_seen: Mutex::new(BoundedDedupe::new(UNORDERED_DELIVERY_DEDUPE_CAP)),
            unordered_forwarded_seen: Mutex::new(BoundedDedupe::new(UNORDERED_FORWARD_DEDUPE_CAP)),
            origin_message_id: AtomicU64::new(1),
            lane_cap: cfg.ordered_lane_cap(),
            pending_window_packets: cfg.ordered_pending_window_packets(),
            reorder_buffer_packets: cfg.ordered_reorder_buffer_packets(),
            retry_initial: cfg.ordered_retry_initial(),
            retry_max: cfg.ordered_retry_max(),
            retry_max_age: cfg.ordered_retry_max_age(),
            retry_max_attempts: cfg.ordered_retry_max_attempts(),
        }
    }

    pub(crate) async fn outbound_send_guard(&self) -> MutexGuard<'_, ()> {
        self.outbound_send.lock().await
    }

    pub(crate) fn next_origin_message_id(&self) -> u64 {
        self.origin_message_id.fetch_add(1, Ordering::Relaxed)
    }

    pub(crate) async fn activate_local_lane(&self, lane: LaneId) {
        let mut lanes = self.local_lanes.lock().await;
        if lanes.contains(&lane) {
            return;
        }
        assert!(
            lanes.len() < self.lane_cap.get(),
            "ordered overlay lane cap {} exceeded",
            self.lane_cap
        );
        lanes.insert(lane);
    }

    async fn activate_remote_lane(
        &self,
        src: NodeIdentifier,
        boot_epoch: u64,
        dst: NodeIdentifier,
        lane: LaneId,
    ) -> bool {
        let mut lanes = self.remote_lanes.lock().await;
        let active = lanes
            .entry(RemoteLaneKey {
                src,
                boot_epoch,
                dst,
            })
            .or_default();
        if active.contains(&lane) {
            return true;
        }
        if active.len() >= self.lane_cap.get() {
            return false;
        }
        active.insert(lane);
        true
    }

    pub(crate) async fn can_store_pending(
        &self,
        dsts: &[NodeIdentifier],
        lane: LaneId,
    ) -> Result<(), (NodeIdentifier, LaneId)> {
        let pending = self.pending.lock().await;
        for dst in dsts {
            let key = OutboundKey { dst: *dst, lane };
            let current = pending.get(&key).map_or(0, BTreeMap::len);
            if current >= self.pending_window_packets {
                return Err((*dst, lane));
            }
        }
        Ok(())
    }

    pub(crate) async fn next_outbound_seq(&self, dst: NodeIdentifier, lane: LaneId) -> u64 {
        let mut outbound = self.outbound_next.lock().await;
        let seq = outbound.entry(OutboundKey { dst, lane }).or_insert(0);
        let current = *seq;
        *seq = seq.saturating_add(1);
        current
    }

    pub(crate) async fn store_pending(&self, lane: LaneId, data: pb::OverlayData) {
        let Ok(dst) = NodeIdentifier::try_from(data.ordering_dst) else {
            return;
        };
        let key = OutboundKey { dst, lane };
        let mut pending = self.pending.lock().await;
        let packets = pending.entry(key).or_default();
        let now = Instant::now();
        packets.insert(
            data.ordering_seq,
            PendingPacket {
                data,
                first_sent_at: now,
                next_retry_at: now + self.retry_initial,
                retry_delay: self.retry_initial,
                retry_attempts: 0,
            },
        );
    }

    pub(crate) async fn apply_ack(&self, final_dst: NodeIdentifier, lane: LaneId, next_seq: u64) {
        let mut pending = self.pending.lock().await;
        let key = OutboundKey {
            dst: final_dst,
            lane,
        };
        if let Some(packets) = pending.get_mut(&key) {
            let remove: Vec<u64> = packets
                .keys()
                .take_while(|seq| **seq < next_seq)
                .copied()
                .collect();
            for seq in remove {
                packets.remove(&seq);
            }
            if packets.is_empty() {
                pending.remove(&key);
            }
        }
    }

    pub(crate) async fn pending_range(
        &self,
        final_dst: NodeIdentifier,
        lane: LaneId,
        first: u64,
        last: u64,
    ) -> Vec<pb::OverlayData> {
        let pending = self.pending.lock().await;
        pending
            .get(&OutboundKey {
                dst: final_dst,
                lane,
            })
            .map(|packets| {
                (first..=last)
                    .filter_map(|seq| packets.get(&seq).map(|p| p.data.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn max_repair_request_packets(&self) -> usize {
        self.reorder_buffer_packets
    }

    pub(crate) async fn due_retransmits(&self, now: Instant) -> Vec<pb::OverlayData> {
        let mut pending = self.pending.lock().await;
        let mut due = Vec::new();
        let mut empty_keys = Vec::new();
        for (key, packets) in pending.iter_mut() {
            let mut expired = Vec::new();
            for (seq, packet) in packets.iter_mut() {
                let age = now.saturating_duration_since(packet.first_sent_at);
                // Both reliable service levels are an end-to-end contract.
                // Keep retrying until an ACK arrives or membership observes a
                // replacement boot epoch; transport/session timeouts are not
                // delivery. Capacity admission remains bounded separately.
                let retain_until_ack = matches!(
                    level_from_wire(packet.data.service_level),
                    Some(ServiceLevel::Reliable | ServiceLevel::ReliableLowLatency)
                );
                let expired_by_age = !retain_until_ack && age >= self.retry_max_age;
                let expired_by_attempts =
                    !retain_until_ack && packet.retry_attempts >= self.retry_max_attempts;
                if expired_by_age || expired_by_attempts {
                    warn!(
                        dst = %key.dst,
                        lane = key.lane.get(),
                        seq,
                        age_ms = age.as_millis(),
                        attempts = packet.retry_attempts,
                        max_age_ms = self.retry_max_age.as_millis(),
                        max_attempts = self.retry_max_attempts,
                        expired_by_age,
                        expired_by_attempts,
                        "ordered overlay pending packet retry limit reached; dropping"
                    );
                    expired.push(*seq);
                    continue;
                }
                if now >= packet.next_retry_at {
                    due.push(packet.data.clone());
                    packet.retry_attempts = packet.retry_attempts.saturating_add(1);
                    packet.retry_delay = packet.retry_delay.saturating_mul(2).min(self.retry_max);
                    packet.next_retry_at = now + packet.retry_delay;
                }
            }
            for seq in expired {
                packets.remove(&seq);
            }
            if packets.is_empty() {
                empty_keys.push(*key);
            }
        }
        for key in empty_keys {
            pending.remove(&key);
        }
        due
    }

    pub(crate) async fn cache_ordered_packet(&self, data: &pb::OverlayData) {
        let Some(lane) = data.lane_id.and_then(|id| LaneId::try_from(id).ok()) else {
            return;
        };
        let Ok(origin) = NodeIdentifier::try_from(data.src) else {
            return;
        };
        let Ok(final_dst) = NodeIdentifier::try_from(data.ordering_dst) else {
            return;
        };
        let key = RepairKey {
            origin,
            boot_epoch: data.origin_boot_epoch,
            final_dst,
            lane,
            seq: data.ordering_seq,
        };
        self.repair_cache.lock().await.insert(key, data.clone());
    }

    pub(crate) async fn cached_range(
        &self,
        origin: NodeIdentifier,
        boot_epoch: u64,
        final_dst: NodeIdentifier,
        lane: LaneId,
        first: u64,
        last: u64,
    ) -> Vec<pb::OverlayData> {
        self.repair_cache
            .lock()
            .await
            .range(origin, boot_epoch, final_dst, lane, first, last)
    }

    pub(crate) async fn accept_inbound(
        &self,
        self_id: NodeIdentifier,
        data: &pb::OverlayData,
        level: ServiceLevel,
        class: MessageClass,
    ) -> Option<AcceptOutcome> {
        let lane = data.lane_id.and_then(|id| LaneId::try_from(id).ok())?;
        let src = NodeIdentifier::try_from(data.src).ok()?;
        let final_dst = NodeIdentifier::try_from(data.ordering_dst).ok()?;
        if final_dst != self_id {
            return None;
        }
        if !self
            .activate_remote_lane(src, data.origin_boot_epoch, self_id, lane)
            .await
        {
            return None;
        }
        let key = InboundKey {
            src,
            boot_epoch: data.origin_boot_epoch,
            dst: self_id,
            lane,
        };
        let delivery = OrderedDelivery::new(
            src,
            data.origin_boot_epoch,
            data.service_tag,
            level,
            class,
            data.payload.clone(),
        );
        let mut inbound = self.inbound.lock().await;
        let state = inbound.entry(key).or_default();

        if data.ordering_seq < state.next_seq {
            return Some(AcceptOutcome {
                ready: Vec::new(),
                ack_next_seq: state.next_seq,
                nack: None,
            });
        }

        if data.ordering_seq > state.next_seq {
            let gap = data.ordering_seq.saturating_sub(state.next_seq);
            if gap as usize > self.reorder_buffer_packets || self.reorder_buffer_packets == 0 {
                return Some(AcceptOutcome {
                    ready: Vec::new(),
                    ack_next_seq: state.next_seq,
                    nack: None,
                });
            }
            if state.buffered.len() < self.reorder_buffer_packets {
                state.buffered.entry(data.ordering_seq).or_insert(delivery);
            }
            return Some(AcceptOutcome {
                ready: Vec::new(),
                ack_next_seq: state.next_seq,
                nack: Some((state.next_seq, data.ordering_seq.saturating_sub(1))),
            });
        }

        let mut ready = vec![delivery];
        state.next_seq = state.next_seq.saturating_add(1);
        while let Some(delivery) = state.buffered.remove(&state.next_seq) {
            ready.push(delivery);
            state.next_seq = state.next_seq.saturating_add(1);
        }

        Some(AcceptOutcome {
            ready,
            ack_next_seq: state.next_seq,
            nack: None,
        })
    }

    pub(crate) async fn should_deliver_unordered(
        &self,
        origin: NodeIdentifier,
        boot_epoch: u64,
        message_id: u64,
        service_tag: u32,
    ) -> bool {
        if message_id == 0 {
            return true;
        }
        self.unordered_delivered_seen
            .lock()
            .await
            .insert(DeliveryKey {
                origin,
                boot_epoch,
                message_id,
                service_tag,
            })
    }

    pub(crate) async fn should_deliver_transit(
        &self,
        origin: NodeIdentifier,
        boot_epoch: u64,
        message_id: u64,
        service_tag: u32,
    ) -> bool {
        if message_id == 0 {
            return true;
        }
        self.ordered_transit_seen.lock().await.insert(DeliveryKey {
            origin,
            boot_epoch,
            message_id,
            service_tag,
        })
    }

    pub(crate) async fn filter_unforwarded_unordered(
        &self,
        origin: NodeIdentifier,
        boot_epoch: u64,
        message_id: u64,
        service_tag: u32,
        dsts: Vec<u32>,
    ) -> Vec<u32> {
        if message_id == 0 {
            return dsts;
        }

        let mut seen = self.unordered_forwarded_seen.lock().await;
        dsts.into_iter()
            .filter(|dst_wire| {
                let Ok(final_dst) = NodeIdentifier::try_from(*dst_wire) else {
                    return true;
                };
                seen.insert(UnorderedForwardKey {
                    origin,
                    boot_epoch,
                    message_id,
                    service_tag,
                    final_dst,
                })
            })
            .collect()
    }

    pub(crate) async fn reset_peer(&self, peer: NodeIdentifier) {
        self.outbound_next
            .lock()
            .await
            .retain(|key, _| key.dst != peer);
        self.pending.lock().await.retain(|key, _| key.dst != peer);
        self.inbound
            .lock()
            .await
            .retain(|key, _| key.src != peer && key.dst != peer);
        self.remote_lanes
            .lock()
            .await
            .retain(|key, _| key.src != peer && key.dst != peer);
        self.repair_cache.lock().await.retain_peer(peer);
    }
}

impl Default for OverlayOrdering {
    fn default() -> Self {
        Self::new(&OverlayConfig::new(Vec::new()))
    }
}

#[derive(Debug)]
pub(crate) struct AcceptOutcome {
    pub ready: Vec<OrderedDelivery>,
    pub ack_next_seq: u64,
    pub nack: Option<(u64, u64)>,
}

#[derive(Debug, Clone)]
pub(crate) struct OrderedDelivery {
    src: NodeIdentifier,
    origin_boot_epoch: u64,
    tag: u32,
    level: ServiceLevel,
    class: MessageClass,
    body: Bytes,
}

impl OrderedDelivery {
    pub(crate) fn new(
        src: NodeIdentifier,
        origin_boot_epoch: u64,
        tag: u32,
        level: ServiceLevel,
        class: MessageClass,
        body: Bytes,
    ) -> Self {
        Self {
            src,
            origin_boot_epoch,
            tag,
            level,
            class,
            body,
        }
    }

    pub(crate) fn src(&self) -> NodeIdentifier {
        self.src
    }

    pub(crate) fn origin_boot_epoch(&self) -> u64 {
        self.origin_boot_epoch
    }

    pub(crate) fn tag(&self) -> u32 {
        self.tag
    }

    pub(crate) fn level(&self) -> ServiceLevel {
        self.level
    }

    pub(crate) fn class(&self) -> MessageClass {
        self.class
    }

    pub(crate) fn body(&self) -> Bytes {
        self.body.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::num::{NonZeroU32, NonZeroUsize};

    use super::*;

    fn lane() -> LaneId {
        lane_with(7)
    }

    fn lane_with(id: u32) -> LaneId {
        LaneId::new(NonZeroU32::new(id).unwrap())
    }

    fn data_on_lane(seq: u64, body: &'static [u8], lane: LaneId) -> pb::OverlayData {
        pb::OverlayData {
            src: 2,
            dsts: vec![1],
            path_trace: vec![2],
            service_tag: 7,
            service_level: 0,
            message_class: 1,
            payload: Bytes::from_static(body),
            process_on_transit: false,
            route_metric: 2,
            ordered_delivery: true,
            ordering_seq: seq,
            ordering_dst: 1,
            lane_id: Some(lane.get()),
            origin_boot_epoch: 99,
            origin_message_id: seq + 10,
            allow_l1_compression: false,
            distribution_profile: None,
            distribution_tree_version: None,
            distribution_group: None,
            distribution_group_version: None,
            distribution_topology_epoch: None,
            distribution_deadline_unix_ms: None,
            distribution_repair: false,
            distribution_repair_target: None,
            distribution_deadline_issuer: None,
            distribution_deadline_unix_us: None,
            inline_attachments: Vec::new(),
        }
    }

    fn data(seq: u64, body: &'static [u8]) -> pb::OverlayData {
        data_on_lane(seq, body, lane())
    }

    fn reliable_low_latency_data(seq: u64, body: &'static [u8]) -> pb::OverlayData {
        let mut data = data(seq, body);
        data.service_level = 1;
        data
    }

    fn best_effort_data(seq: u64, body: &'static [u8]) -> pb::OverlayData {
        let mut data = data(seq, body);
        data.service_level = 2;
        data
    }

    #[test]
    fn ordered_defaults_are_sensible() {
        let cfg = OverlayConfig::new(Vec::new());

        assert_eq!(cfg.ordered_lane_cap().get(), 64);
        assert_eq!(cfg.ordered_repair_cache_packets(), 1024);
        assert_eq!(cfg.ordered_retry_max_age(), Duration::from_secs(30));
        assert_eq!(cfg.ordered_retry_max_attempts(), 16);
    }

    #[tokio::test]
    async fn buffers_until_missing_sequence_arrives_and_preserves_origin_boot_epoch() {
        let ordering = OverlayOrdering::default();

        let second = ordering
            .accept_inbound(
                1,
                &data(1, b"second"),
                ServiceLevel::Reliable,
                MessageClass::Regular,
            )
            .await
            .unwrap();
        assert!(second.ready.is_empty());
        assert_eq!(second.ack_next_seq, 0);
        assert_eq!(second.nack, Some((0, 0)));

        let first = ordering
            .accept_inbound(
                1,
                &data(0, b"first"),
                ServiceLevel::Reliable,
                MessageClass::Regular,
            )
            .await
            .unwrap();
        assert_eq!(first.ready.len(), 2);
        assert_eq!(&first.ready[0].body()[..], b"first");
        assert_eq!(&first.ready[1].body()[..], b"second");
        assert_eq!(first.ready[0].origin_boot_epoch(), 99);
        assert_eq!(first.ready[1].origin_boot_epoch(), 99);
        assert_eq!(first.ack_next_seq, 2);
    }

    #[tokio::test]
    async fn outbound_sequence_is_per_destination_lane() {
        let ordering = OverlayOrdering::default();

        assert_eq!(ordering.next_outbound_seq(2, lane()).await, 0);
        assert_eq!(ordering.next_outbound_seq(2, lane()).await, 1);
        assert_eq!(ordering.next_outbound_seq(3, lane()).await, 0);
    }

    #[tokio::test]
    #[should_panic(expected = "ordered overlay lane cap 1 exceeded")]
    async fn local_lane_cap_excess_panics() {
        let cfg =
            OverlayConfig::new(Vec::new()).with_ordered_lane_cap(NonZeroUsize::new(1).unwrap());
        let ordering = OverlayOrdering::new(&cfg);

        ordering.activate_local_lane(lane_with(1)).await;
        ordering.activate_local_lane(lane_with(2)).await;
    }

    #[tokio::test]
    async fn remote_lane_cap_excess_drops() {
        let cfg =
            OverlayConfig::new(Vec::new()).with_ordered_lane_cap(NonZeroUsize::new(1).unwrap());
        let ordering = OverlayOrdering::new(&cfg);

        let first = ordering
            .accept_inbound(
                1,
                &data_on_lane(0, b"first", lane_with(1)),
                ServiceLevel::Reliable,
                MessageClass::Regular,
            )
            .await;
        let second = ordering
            .accept_inbound(
                1,
                &data_on_lane(0, b"second", lane_with(2)),
                ServiceLevel::Reliable,
                MessageClass::Regular,
            )
            .await;

        assert!(first.is_some());
        assert!(second.is_none());
    }

    #[tokio::test]
    async fn pending_window_full_is_reported_per_destination_lane() {
        let cfg = OverlayConfig::new(Vec::new()).with_ordered_pending_window_packets(1);
        let ordering = OverlayOrdering::new(&cfg);

        ordering
            .store_pending(lane(), reliable_low_latency_data(0, b"pending"))
            .await;

        assert_eq!(
            ordering.can_store_pending(&[1], lane()).await,
            Err((1, lane()))
        );
        assert_eq!(ordering.can_store_pending(&[2], lane()).await, Ok(()));
    }

    #[tokio::test]
    async fn ordered_pending_retries_up_to_sixteen_attempt_cap_then_drops() {
        let cfg = OverlayConfig::new(Vec::new())
            .with_ordered_retry_initial(Duration::from_millis(1))
            .with_ordered_retry_max(Duration::from_millis(1))
            .with_ordered_retry_max_age(Duration::from_secs(30))
            .with_ordered_retry_max_attempts(16);
        let ordering = OverlayOrdering::new(&cfg);
        ordering
            .store_pending(lane(), best_effort_data(0, b"pending"))
            .await;

        let first_due = Instant::now() + Duration::from_millis(5);
        for attempt in 0..16 {
            assert_eq!(
                ordering
                    .due_retransmits(first_due + Duration::from_millis(attempt))
                    .await
                    .len(),
                1,
                "attempt {attempt} should retransmit"
            );
        }
        assert!(
            ordering
                .due_retransmits(first_due + Duration::from_millis(16))
                .await
                .is_empty()
        );
        assert!(ordering.pending_range(1, lane(), 0, 0).await.is_empty());
    }

    #[tokio::test]
    async fn ordered_pending_drops_when_retry_age_expires() {
        let cfg = OverlayConfig::new(Vec::new())
            .with_ordered_retry_initial(Duration::from_millis(1))
            .with_ordered_retry_max_age(Duration::from_millis(1))
            .with_ordered_retry_max_attempts(16);
        let ordering = OverlayOrdering::new(&cfg);
        ordering
            .store_pending(lane(), best_effort_data(0, b"pending"))
            .await;

        assert!(
            ordering
                .due_retransmits(Instant::now() + Duration::from_millis(5))
                .await
                .is_empty()
        );
        assert!(ordering.pending_range(1, lane(), 0, 0).await.is_empty());
    }

    #[tokio::test]
    async fn ack_removes_pending_before_retry_caps() {
        let cfg = OverlayConfig::new(Vec::new())
            .with_ordered_retry_max_age(Duration::from_millis(1))
            .with_ordered_retry_max_attempts(0);
        let ordering = OverlayOrdering::new(&cfg);
        ordering.store_pending(lane(), data(0, b"pending")).await;

        ordering.apply_ack(1, lane(), 1).await;

        assert!(
            ordering
                .due_retransmits(Instant::now() + Duration::from_secs(1))
                .await
                .is_empty()
        );
        assert!(ordering.pending_range(1, lane(), 0, 0).await.is_empty());
    }

    #[tokio::test]
    async fn reliable_levels_ignore_retry_caps_until_ack_or_epoch_reset() {
        let cfg = OverlayConfig::new(Vec::new())
            .with_ordered_retry_initial(Duration::from_millis(1))
            .with_ordered_retry_max(Duration::from_millis(1))
            .with_ordered_retry_max_age(Duration::from_millis(1))
            .with_ordered_retry_max_attempts(0);
        let ordering = OverlayOrdering::new(&cfg);
        ordering.store_pending(lane(), data(0, b"pending")).await;
        ordering
            .store_pending(lane_with(2), reliable_low_latency_data(0, b"pending"))
            .await;

        let retransmits = ordering
            .due_retransmits(Instant::now() + Duration::from_secs(1))
            .await;
        assert_eq!(retransmits.len(), 2);
        assert_eq!(ordering.pending_range(1, lane(), 0, 0).await.len(), 1);
        assert_eq!(ordering.pending_range(1, lane_with(2), 0, 0).await.len(), 1);

        // `reset_peer` is invoked only for MembershipEvent::Restarted, which
        // is the observed destination boot-epoch transition.
        ordering.reset_peer(1).await;
        assert!(ordering.pending_range(1, lane(), 0, 0).await.is_empty());
        assert!(
            ordering
                .pending_range(1, lane_with(2), 0, 0)
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn reset_peer_clears_pending_packets() {
        let ordering = OverlayOrdering::default();
        ordering.store_pending(lane(), data(0, b"pending")).await;

        ordering.reset_peer(1).await;

        assert!(ordering.pending_range(1, lane(), 0, 0).await.is_empty());
    }

    #[tokio::test]
    async fn oversized_sequence_gap_does_not_request_unbounded_repair() {
        let cfg = OverlayConfig::new(Vec::new()).with_ordered_reorder_buffer_packets(2);
        let ordering = OverlayOrdering::new(&cfg);

        let outcome = ordering
            .accept_inbound(
                1,
                &data(10, b"too-far-ahead"),
                ServiceLevel::Reliable,
                MessageClass::Regular,
            )
            .await
            .unwrap();

        assert!(outcome.ready.is_empty());
        assert_eq!(outcome.ack_next_seq, 0);
        assert_eq!(outcome.nack, None);
    }

    #[tokio::test]
    async fn lane_less_packets_do_not_enter_ordering_state() {
        let ordering = OverlayOrdering::default();
        let mut packet = data(0, b"unordered");
        packet.ordered_delivery = false;
        packet.lane_id = None;

        ordering.cache_ordered_packet(&packet).await;

        assert!(
            ordering
                .cached_range(2, 99, 1, lane(), 0, 0)
                .await
                .is_empty()
        );
        assert!(
            ordering
                .accept_inbound(1, &packet, ServiceLevel::Reliable, MessageClass::Regular,)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn repair_cache_can_be_disabled() {
        let cfg = OverlayConfig::new(Vec::new()).with_ordered_repair_cache_packets(0);
        let ordering = OverlayOrdering::new(&cfg);
        let packet = data(0, b"packet");
        ordering.cache_ordered_packet(&packet).await;

        assert!(
            ordering
                .cached_range(2, 99, 1, lane(), 0, 0)
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn repair_cache_evicts_oldest_packet() {
        let cfg = OverlayConfig::new(Vec::new()).with_ordered_repair_cache_packets(1);
        let ordering = OverlayOrdering::new(&cfg);

        ordering.cache_ordered_packet(&data(0, b"old")).await;
        ordering.cache_ordered_packet(&data(1, b"new")).await;

        assert!(
            ordering
                .cached_range(2, 99, 1, lane(), 0, 0)
                .await
                .is_empty()
        );
        let repaired = ordering.cached_range(2, 99, 1, lane(), 1, 1).await;
        assert_eq!(repaired.len(), 1);
        assert_eq!(&repaired[0].payload[..], b"new");
    }

    #[tokio::test]
    async fn transit_dedupe_tracks_ordered_origin_identity() {
        let ordering = OverlayOrdering::default();

        assert!(ordering.should_deliver_transit(2, 99, 10, 7).await);
        assert!(!ordering.should_deliver_transit(2, 99, 10, 7).await);
        assert!(ordering.should_deliver_transit(2, 99, 0, 7).await);
        assert!(ordering.should_deliver_transit(2, 99, 0, 7).await);
    }
}
