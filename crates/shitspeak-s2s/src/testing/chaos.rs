//! Per-node inbound chaos middleware for geo-distributed integration
//! tests.
//!
//! Sits between the L1 transport's `Inbound` channels and the overlay's
//! dispatcher. Lets a test selectively drop, delay, or rate-limit
//! inbound frames per (sender, type) pair without touching transport
//! code.
//!
//! Notes:
//!   * The two priority queues are filtered by **independent tasks** —
//!     the chaos layer must not introduce its own head-of-line blocking
//!     between high-priority and regular traffic. This mirrors the
//!     dispatcher's own two-task design.
//!   * Latency / jitter delays are applied by spawning a per-message
//!     "release task" so the filter loop never blocks. As a side effect,
//!     adding latency may reorder messages — tests that care about
//!     ordering should not enable it.
//!   * Bandwidth is a token bucket sized in **bytes per second** of the
//!     inbound payload. When the bucket is empty, the over-budget frame
//!     is dropped (the alternative — queueing — would distort timing
//!     more than tests typically want).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use prost::Message as _;
use tokio::sync::Notify;
use tracing::trace;

use crate::overlay::proto::{OverlayBody, decode_message};
use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::{
    AdaptiveInboundReceiver, AdaptiveQueueBudget, AdaptiveQueueSender, Inbound, InboundMessage,
    MessageClass,
};

const DISTRIBUTION_CONTROL_SERVICE_TAG: u32 = 250;

/// Variants of `OverlayMessage.body`. Used by per-type drop/filter rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    Hello,
    HelloAck,
    LsaFlood,
    LsdbSync,
    LsdbSyncResp,
    Data,
    DistributionInstall,
    DistributionAck,
    DistributionData,
    Control,
    StrictPropose,
    StrictAck,
    StrictCommit,
    StrictCatchup,
    /// Compatibility name retained for existing scenarios.
    StrictProposeAck,
}

impl MessageType {
    pub fn classify(payload: &[u8]) -> Option<Self> {
        let m = decode_message(payload).ok()?;
        Some(match m.body? {
            OverlayBody::Hello(_) => MessageType::Hello,
            OverlayBody::HelloAck(_) => MessageType::HelloAck,
            OverlayBody::LsaFlood(_) => MessageType::LsaFlood,
            OverlayBody::LsdbSync(_) => MessageType::LsdbSync,
            OverlayBody::LsdbSyncResp(_) => MessageType::LsdbSyncResp,
            OverlayBody::Control(_) => MessageType::Control,
            OverlayBody::Data(data) => {
                if data.service_tag == DISTRIBUTION_CONTROL_SERVICE_TAG {
                    let control = shitspeak_proto::s2s_overlay_proto::DistributionControl::decode(
                        data.payload.as_ref(),
                    )
                    .ok()?;
                    return match control.body? {
                        shitspeak_proto::s2s_overlay_proto::distribution_control::Body::Install(
                            _,
                        ) => Some(MessageType::DistributionInstall),
                        shitspeak_proto::s2s_overlay_proto::distribution_control::Body::Ack(_) => {
                            Some(MessageType::DistributionAck)
                        }
                        _ => Some(MessageType::Control),
                    };
                }
                if data.distribution_profile.is_some() {
                    return Some(MessageType::DistributionData);
                }
                if data.service_tag == crate::replications::proto::REPLICATION_SERVICE_TAG {
                    if let Ok(repl) = crate::replications::proto::decode(&data.payload) {
                        if let Some(crate::replications::proto::ReplBody::Strict(strict)) =
                            repl.body
                        {
                            return match strict.body? {
                                crate::replications::proto::StrictBody::Propose(_) => {
                                    Some(MessageType::StrictPropose)
                                }
                                crate::replications::proto::StrictBody::ProposeAck(_) => {
                                    Some(MessageType::StrictAck)
                                }
                                crate::replications::proto::StrictBody::Commit(_)
                                | crate::replications::proto::StrictBody::RecoveryCommit(_) => {
                                    Some(MessageType::StrictCommit)
                                }
                                crate::replications::proto::StrictBody::CatchupReq(_)
                                | crate::replications::proto::StrictBody::CatchupResp(_)
                                | crate::replications::proto::StrictBody::RecoveryReq(_)
                                | crate::replications::proto::StrictBody::RecoveryAck(_) => {
                                    Some(MessageType::StrictCatchup)
                                }
                                _ => Some(MessageType::Data),
                            };
                        }
                    }
                }
                MessageType::Data
            }
        })
    }
}

fn canonical_type(t: MessageType) -> MessageType {
    match t {
        MessageType::StrictProposeAck => MessageType::StrictAck,
        other => other,
    }
}

/// Exact deterministic-fault key. The sender is the physical previous hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FaultSelector {
    sender: NodeIdentifier,
    transport: shitspeak_s2s_transport::TransportKind,
    message_type: MessageType,
}

impl FaultSelector {
    pub fn new(
        sender: NodeIdentifier,
        transport: shitspeak_s2s_transport::TransportKind,
        message_type: MessageType,
    ) -> Self {
        Self {
            sender,
            transport,
            message_type: canonical_type(message_type),
        }
    }

    pub fn sender(self) -> NodeIdentifier {
        self.sender
    }

    pub fn transport(self) -> shitspeak_s2s_transport::TransportKind {
        self.transport
    }

    pub fn message_type(self) -> MessageType {
        self.message_type
    }
}

#[derive(Debug)]
struct ReleaseBarrier {
    open: AtomicBool,
    notify: Notify,
}

impl ReleaseBarrier {
    fn closed() -> Self {
        Self {
            open: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    async fn wait(&self) {
        while !self.open.load(Ordering::Acquire) {
            self.notify.notified().await;
        }
    }

    fn release(&self) {
        self.open.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct DeterministicRule {
    delay: Duration,
    jitter: Duration,
    reorder: Duration,
    burst_drop: u32,
    burst_deliver: u32,
    duplicate_every: u32,
    bandwidth_bytes_per_sec: Option<u64>,
}

#[derive(Debug)]
struct PlannedAction {
    delay: Duration,
    copies: usize,
    barrier: Option<Arc<ReleaseBarrier>>,
}

fn logical_sender(msg: &InboundMessage) -> NodeIdentifier {
    let Ok(decoded) = decode_message(msg.payload()) else {
        return msg.from();
    };
    match decoded.body {
        Some(OverlayBody::Data(data)) => {
            NodeIdentifier::try_from(data.src).unwrap_or_else(|_| msg.from())
        }
        _ => msg.from(),
    }
}

#[derive(Debug)]
struct TokenBucket {
    capacity_bytes: u64,
    refill_per_sec: u64,
    tokens: u64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(rate_per_sec: u64) -> Self {
        Self {
            capacity_bytes: rate_per_sec,
            refill_per_sec: rate_per_sec,
            tokens: rate_per_sec,
            last_refill: Instant::now(),
        }
    }

    fn try_consume(&mut self, bytes: u64) -> bool {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last_refill);
        let refill = (self.refill_per_sec as u128 * elapsed.as_micros() / 1_000_000) as u64;
        if refill > 0 {
            self.tokens = self.tokens.saturating_add(refill).min(self.capacity_bytes);
            self.last_refill = now;
        }
        if self.tokens >= bytes {
            self.tokens -= bytes;
            true
        } else {
            false
        }
    }
}

/// Mutable chaos rules for one node's inbound path.
#[derive(Default, Debug)]
struct ChaosState {
    seed: u64,
    sequence: u64,
    /// Source node ids whose messages are dropped on arrival.
    blocked: HashSet<NodeIdentifier>,
    /// Per-sender added latency.
    latency: HashMap<NodeIdentifier, Duration>,
    /// Drop the next N messages of the given type. Counter decrements on
    /// each drop; when it hits 0, normal delivery resumes.
    type_drops: HashMap<MessageType, u32>,
    /// Drop the next N messages of (sender, type). Combined rule.
    type_drops_per_sender: HashMap<(NodeIdentifier, MessageType), u32>,
    /// If set, every inbound message is delayed by U(0, max).
    jitter_max: Option<Duration>,
    /// Optional inbound bandwidth cap (bytes/sec). When the bucket is
    /// empty, frames are dropped.
    bandwidth: Option<TokenBucket>,
    transport_down: HashSet<shitspeak_s2s_transport::TransportKind>,
    rules: HashMap<FaultSelector, DeterministicRule>,
    rule_sequences: HashMap<FaultSelector, u64>,
    exact_drops: HashMap<FaultSelector, u32>,
    rule_bandwidth: HashMap<FaultSelector, TokenBucket>,
    barriers: HashMap<FaultSelector, Arc<ReleaseBarrier>>,
}

/// Public handle. Cloning is cheap; clones share the same chaos rules.
#[derive(Clone, Debug)]
pub struct LinkChaos {
    state: Arc<Mutex<ChaosState>>,
}

impl LinkChaos {
    pub fn new() -> Self {
        Self::with_seed(0)
    }

    pub fn with_seed(seed: u64) -> Self {
        let mut state = ChaosState::default();
        state.seed = seed;
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }

    pub fn set_seed(&self, seed: u64) {
        let mut state = self.state.lock();
        state.seed = seed;
        state.sequence = 0;
        state.rule_sequences.clear();
    }

    pub fn block(&self, sender: NodeIdentifier) {
        self.state.lock().blocked.insert(sender);
    }

    pub fn unblock(&self, sender: NodeIdentifier) {
        self.state.lock().blocked.remove(&sender);
    }

    pub fn block_many(&self, senders: impl IntoIterator<Item = NodeIdentifier>) {
        let mut g = self.state.lock();
        for s in senders {
            g.blocked.insert(s);
        }
    }

    pub fn add_latency(&self, sender: NodeIdentifier, dur: Duration) {
        self.state.lock().latency.insert(sender, dur);
    }

    pub fn clear_latency(&self, sender: NodeIdentifier) {
        self.state.lock().latency.remove(&sender);
    }

    /// Drop the next `count` inbound messages of the given type from any
    /// sender.
    pub fn drop_next_of_type(&self, t: MessageType, count: u32) {
        self.state
            .lock()
            .type_drops
            .insert(canonical_type(t), count);
    }

    /// Drop the next `count` inbound messages of the given type from the
    /// given sender. More specific than `drop_next_of_type`.
    pub fn drop_next_of_type_from(&self, sender: NodeIdentifier, t: MessageType, count: u32) {
        self.state
            .lock()
            .type_drops_per_sender
            .insert((sender, canonical_type(t)), count);
    }

    /// Remaining count for a transport-independent semantic drop rule.
    pub fn remaining_type_drops_from(&self, sender: NodeIdentifier, t: MessageType) -> u32 {
        self.state
            .lock()
            .type_drops_per_sender
            .get(&(sender, canonical_type(t)))
            .copied()
            .unwrap_or_default()
    }

    pub fn set_jitter(&self, max: Option<Duration>) {
        self.state.lock().jitter_max = max;
    }

    pub fn set_bandwidth(&self, bytes_per_sec: Option<u64>) {
        self.state.lock().bandwidth = bytes_per_sec.map(TokenBucket::new);
    }

    /// Enable or disable every inbound frame carried by a transport kind.
    pub fn set_transport_up(&self, transport: shitspeak_s2s_transport::TransportKind, up: bool) {
        let mut state = self.state.lock();
        if up {
            state.transport_down.remove(&transport);
        } else {
            state.transport_down.insert(transport);
        }
    }

    pub fn set_delay(&self, selector: FaultSelector, delay: Duration, jitter: Duration) {
        let mut state = self.state.lock();
        let rule = state.rules.entry(selector).or_default();
        rule.delay = delay;
        rule.jitter = jitter;
    }

    /// Drop `drop` consecutive matches, then deliver `deliver`, repeating.
    /// The seed chooses a stable phase independently for each selector.
    pub fn set_burst_loss(&self, selector: FaultSelector, drop: u32, deliver: u32) {
        let mut state = self.state.lock();
        let rule = state.rules.entry(selector).or_default();
        rule.burst_drop = drop;
        rule.burst_deliver = deliver;
    }

    /// Drop exactly the next `count` frames matching the full selector.
    pub fn drop_next(&self, selector: FaultSelector, count: u32) {
        self.state.lock().exact_drops.insert(selector, count);
    }

    pub fn remaining_drops(&self, selector: FaultSelector) -> u32 {
        self.state
            .lock()
            .exact_drops
            .get(&selector)
            .copied()
            .unwrap_or_default()
    }

    /// Add one duplicate to every Nth selected frame. Zero disables it.
    pub fn set_duplication(&self, selector: FaultSelector, every: u32) {
        self.state
            .lock()
            .rules
            .entry(selector)
            .or_default()
            .duplicate_every = every;
    }

    /// Add a seeded delay in `0..=max_delay`, allowing deterministic reorder.
    pub fn set_reorder(&self, selector: FaultSelector, max_delay: Duration) {
        self.state.lock().rules.entry(selector).or_default().reorder = max_delay;
    }

    pub fn set_bandwidth_for(&self, selector: FaultSelector, bytes_per_sec: Option<u64>) {
        let mut state = self.state.lock();
        state
            .rules
            .entry(selector)
            .or_default()
            .bandwidth_bytes_per_sec = bytes_per_sec;
        match bytes_per_sec {
            Some(rate) => {
                state
                    .rule_bandwidth
                    .insert(selector, TokenBucket::new(rate));
            }
            None => {
                state.rule_bandwidth.remove(&selector);
            }
        }
    }

    /// Hold future matching frames until [`release`](Self::release) is called.
    pub fn hold(&self, selector: FaultSelector) {
        self.state
            .lock()
            .barriers
            .entry(selector)
            .or_insert_with(|| Arc::new(ReleaseBarrier::closed()));
    }

    pub fn release(&self, selector: FaultSelector) {
        if let Some(barrier) = self.state.lock().barriers.remove(&selector) {
            barrier.release();
        }
    }

    pub fn clear_fault(&self, selector: FaultSelector) {
        let mut state = self.state.lock();
        state.rules.remove(&selector);
        state.rule_sequences.remove(&selector);
        state.exact_drops.remove(&selector);
        state.rule_bandwidth.remove(&selector);
        if let Some(barrier) = state.barriers.remove(&selector) {
            barrier.release();
        }
    }

    /// Decide what to do with `msg`. Returns the delay to apply before
    /// re-emitting it; `None` means drop. The chaos rules are mutated
    /// (e.g., type-drop counters decrement) as a side effect.
    fn decide(&self, msg: &InboundMessage) -> Option<PlannedAction> {
        let physical_from = msg.from();
        let logical_from = logical_sender(msg);
        let mut g = self.state.lock();
        if g.transport_down.contains(&msg.transport()) {
            return None;
        }
        let message_type = MessageType::classify(msg.payload()).map(canonical_type);
        let selector = message_type
            .map(|message_type| FaultSelector::new(physical_from, msg.transport(), message_type));
        let (mut delay, jitter_max) = {
            if g.blocked.contains(&physical_from) {
                return None;
            }
            if let Some(t) = message_type {
                if let Some(c) = g.type_drops.get_mut(&t) {
                    if *c > 0 {
                        *c -= 1;
                        trace!(?t, from = %logical_from, "chaos: dropped (type rule)");
                        return None;
                    }
                }
                if let Some(c) = g.type_drops_per_sender.get_mut(&(logical_from, t)) {
                    if *c > 0 {
                        *c -= 1;
                        trace!(?t, from = %logical_from, "chaos: dropped (per-sender type rule)");
                        return None;
                    }
                }
            }
            if let Some(bucket) = g.bandwidth.as_mut() {
                let bytes = msg.payload().len() as u64;
                if !bucket.try_consume(bytes) {
                    trace!(from = %physical_from, bytes, "chaos: dropped (bandwidth)");
                    return None;
                }
            }
            // Sample jitter_max before releasing the lock so we can apply it
            // outside without holding the chaos lock open longer than needed.
            (
                g.latency.get(&physical_from).copied().unwrap_or_default(),
                g.jitter_max,
            )
        };
        let global_seq = g.sequence;
        g.sequence = g.sequence.wrapping_add(1);
        if let Some(max) = jitter_max {
            let max_us = max.as_micros() as u64;
            if max_us > 0 {
                let extra_us = deterministic_value(g.seed, None, global_seq) % (max_us + 1);
                delay = delay.saturating_add(Duration::from_micros(extra_us));
            }
        }
        let mut copies = 1;
        let mut barrier = None;
        if let Some(selector) = selector {
            if let Some(remaining) = g.exact_drops.get_mut(&selector) {
                if *remaining > 0 {
                    *remaining -= 1;
                    return None;
                }
            }
            let seq = *g.rule_sequences.entry(selector).or_default();
            g.rule_sequences.insert(selector, seq.wrapping_add(1));
            let value = deterministic_value(g.seed, Some(selector), seq);
            if let Some(rule) = g.rules.get(&selector).copied() {
                let cycle = u64::from(rule.burst_drop) + u64::from(rule.burst_deliver);
                let phase = deterministic_value(g.seed, Some(selector), 0) % cycle.max(1);
                if cycle > 0 && (seq + phase) % cycle < u64::from(rule.burst_drop) {
                    return None;
                }
                delay = delay.saturating_add(rule.delay);
                delay = delay.saturating_add(seeded_duration(rule.jitter, value));
                delay = delay.saturating_add(seeded_duration(rule.reorder, value.rotate_left(17)));
                if rule.duplicate_every > 0
                    && (seq + value % u64::from(rule.duplicate_every))
                        % u64::from(rule.duplicate_every)
                        == 0
                {
                    copies = 2;
                }
                if rule.bandwidth_bytes_per_sec.is_some() {
                    let bytes = msg.payload().len() as u64;
                    if !g
                        .rule_bandwidth
                        .get_mut(&selector)
                        .is_some_and(|bucket| bucket.try_consume(bytes))
                    {
                        return None;
                    }
                }
            }
            barrier = g.barriers.get(&selector).cloned();
        }
        Some(PlannedAction {
            delay,
            copies,
            barrier,
        })
    }

    /// Wrap `real` so every inbound message passes through chaos rules
    /// before reaching the overlay's dispatcher. Two filter tasks are
    /// spawned (one per priority queue) to avoid head-of-line blocking
    /// between classes.
    pub fn install(&self, real: Inbound) -> Inbound {
        let budget = AdaptiveQueueBudget::new(3 * 1024 * 1024);
        let (control_tx, control_rx) = AdaptiveQueueSender::new(budget.split(1024 * 1024));
        let (high_tx, high_rx) = AdaptiveQueueSender::new(budget.split(1024 * 1024));
        let (reg_tx, reg_rx) = AdaptiveQueueSender::new(budget.split(1024 * 1024));
        let (real_control, real_high, real_reg) = real.into_parts();
        spawn_filter(
            self.clone(),
            real_control,
            control_tx,
            MessageClass::Control,
        );
        spawn_filter(self.clone(), real_high, high_tx, MessageClass::HighPriority);
        spawn_filter(self.clone(), real_reg, reg_tx, MessageClass::Regular);
        Inbound::new(control_rx, high_rx, reg_rx)
    }
}

impl Default for LinkChaos {
    fn default() -> Self {
        Self::new()
    }
}

fn deterministic_value(seed: u64, selector: Option<FaultSelector>, sequence: u64) -> u64 {
    let mut value = seed ^ sequence.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    if let Some(selector) = selector {
        value ^= u64::from(selector.sender());
        value ^= (selector.transport() as u64).rotate_left(21);
        value ^= (selector.message_type() as u64).rotate_left(42);
    }
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn seeded_duration(max: Duration, value: u64) -> Duration {
    let max_us = max.as_micros().min(u128::from(u64::MAX)) as u64;
    if max_us == 0 {
        Duration::ZERO
    } else if max_us == u64::MAX {
        Duration::from_micros(value)
    } else {
        Duration::from_micros(value % (max_us + 1))
    }
}

fn spawn_filter(
    chaos: LinkChaos,
    mut rx: AdaptiveInboundReceiver,
    tx: AdaptiveQueueSender<InboundMessage>,
    _class: MessageClass,
) {
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let Some(action) = chaos.decide(&msg) else {
                continue;
            };
            let tx2 = tx.clone();
            tokio::spawn(async move {
                if let Some(barrier) = action.barrier {
                    barrier.wait().await;
                }
                if !action.delay.is_zero() {
                    tokio::time::sleep(action.delay).await;
                }
                for _ in 0..action.copies {
                    if tx2.send(msg.clone()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use shitspeak_s2s_transport::TransportKind;

    #[test]
    fn selector_normalizes_legacy_strict_ack_name() {
        let old = FaultSelector::new(7, TransportKind::Tcp, MessageType::StrictProposeAck);
        let current = FaultSelector::new(7, TransportKind::Tcp, MessageType::StrictAck);
        assert_eq!(old, current);
    }

    #[test]
    fn deterministic_stream_is_repeatable_and_keyed() {
        let a = FaultSelector::new(7, TransportKind::Tcp, MessageType::Data);
        let b = FaultSelector::new(7, TransportKind::Udp, MessageType::Data);
        let first: Vec<_> = (0..8)
            .map(|seq| deterministic_value(42, Some(a), seq))
            .collect();
        let replay: Vec<_> = (0..8)
            .map(|seq| deterministic_value(42, Some(a), seq))
            .collect();
        assert_eq!(first, replay);
        assert_ne!(first[0], deterministic_value(42, Some(b), 0));
    }

    #[tokio::test]
    async fn release_barrier_remembers_early_release() {
        let barrier = Arc::new(ReleaseBarrier::closed());
        barrier.release();
        tokio::time::timeout(Duration::from_millis(10), barrier.wait())
            .await
            .expect("released barrier must not block");
    }
}
