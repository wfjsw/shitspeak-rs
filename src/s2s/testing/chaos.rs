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
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rand::RngExt;
use tokio::sync::mpsc;
use tracing::trace;

use crate::s2s::overlay::proto::{decode_message, node_from_wire, OverlayBody};
use crate::s2s::transport::{Inbound, InboundMessage, MessageClass};
use crate::types::NodeIdentifier;

/// Variants of `OverlayMessage.body`. Used by per-type drop/filter rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    Hello,
    HelloAck,
    LsaFlood,
    LsdbSync,
    LsdbSyncResp,
    Data,
    StrictProposeAck,
}

impl MessageType {
    fn classify(payload: &[u8]) -> Option<Self> {
        let m = decode_message(payload).ok()?;
        Some(match m.body? {
            OverlayBody::Hello(_) => MessageType::Hello,
            OverlayBody::HelloAck(_) => MessageType::HelloAck,
            OverlayBody::LsaFlood(_) => MessageType::LsaFlood,
            OverlayBody::LsdbSync(_) => MessageType::LsdbSync,
            OverlayBody::LsdbSyncResp(_) => MessageType::LsdbSyncResp,
            OverlayBody::Data(data) => {
                if data.service_tag == crate::s2s::replications::proto::REPLICATION_SERVICE_TAG {
                    if let Ok(repl) = crate::s2s::replications::proto::decode(&data.payload) {
                        if matches!(
                            repl.body,
                            Some(crate::s2s::replications::proto::ReplBody::Strict(
                                crate::s2s::replications::proto::StrictMessage {
                                    body: Some(
                                        crate::s2s::replications::proto::StrictBody::ProposeAck(_)
                                    ),
                                },
                            ))
                        ) {
                            return Some(MessageType::StrictProposeAck);
                        }
                    }
                }
                MessageType::Data
            }
        })
    }
}

fn logical_sender(msg: &InboundMessage) -> NodeIdentifier {
    let Ok(decoded) = decode_message(msg.payload()) else {
        return msg.from();
    };
    match decoded.body {
        Some(OverlayBody::Data(data)) => node_from_wire(data.src).unwrap_or_else(|| msg.from()),
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
}

/// Public handle. Cloning is cheap; clones share the same chaos rules.
#[derive(Clone)]
pub struct LinkChaos {
    state: Arc<Mutex<ChaosState>>,
}

impl LinkChaos {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ChaosState::default())),
        }
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
        self.state.lock().type_drops.insert(t, count);
    }

    /// Drop the next `count` inbound messages of the given type from the
    /// given sender. More specific than `drop_next_of_type`.
    pub fn drop_next_of_type_from(&self, sender: NodeIdentifier, t: MessageType, count: u32) {
        self.state
            .lock()
            .type_drops_per_sender
            .insert((sender, t), count);
    }

    pub fn set_jitter(&self, max: Option<Duration>) {
        self.state.lock().jitter_max = max;
    }

    pub fn set_bandwidth(&self, bytes_per_sec: Option<u64>) {
        self.state.lock().bandwidth = bytes_per_sec.map(TokenBucket::new);
    }

    /// Decide what to do with `msg`. Returns the delay to apply before
    /// re-emitting it; `None` means drop. The chaos rules are mutated
    /// (e.g., type-drop counters decrement) as a side effect.
    fn decide(&self, msg: &InboundMessage) -> Option<Duration> {
        let physical_from = msg.from();
        let logical_from = logical_sender(msg);
        let (mut delay, jitter_max) = {
            let mut g = self.state.lock();
            if g.blocked.contains(&physical_from) {
                return None;
            }
            if let Some(t) = MessageType::classify(msg.payload()) {
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
        if let Some(max) = jitter_max {
            let max_us = max.as_micros() as u64;
            if max_us > 0 {
                let extra_us = rand::rng().random_range(0..=max_us);
                delay = delay.saturating_add(Duration::from_micros(extra_us));
            }
            return Some(delay);
        }
        Some(delay)
    }

    /// Wrap `real` so every inbound message passes through chaos rules
    /// before reaching the overlay's dispatcher. Two filter tasks are
    /// spawned (one per priority queue) to avoid head-of-line blocking
    /// between classes.
    pub fn install(&self, real: Inbound) -> Inbound {
        let (high_tx, high_rx) = mpsc::channel(1024);
        let (reg_tx, reg_rx) = mpsc::channel(1024);
        let (real_high, real_reg) = real.into_parts();
        spawn_filter(self.clone(), real_high, high_tx, MessageClass::HighPriority);
        spawn_filter(self.clone(), real_reg, reg_tx, MessageClass::Regular);
        Inbound::new(high_rx, reg_rx)
    }
}

impl Default for LinkChaos {
    fn default() -> Self {
        Self::new()
    }
}

fn spawn_filter(
    chaos: LinkChaos,
    mut rx: mpsc::Receiver<InboundMessage>,
    tx: mpsc::Sender<InboundMessage>,
    _class: MessageClass,
) {
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let Some(delay) = chaos.decide(&msg) else {
                continue;
            };
            if delay.is_zero() {
                if tx.send(msg).await.is_err() {
                    return;
                }
            } else {
                let tx2 = tx.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = tx2.send(msg).await;
                });
            }
        }
    });
}
