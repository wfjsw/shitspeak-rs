//! Direct-neighbor table.
//!
//! Tracks every peer with a live L1 stream — these are the *direct
//! neighbors* whose edges feed into our locally-emitted LSA. State per
//! neighbor:
//!   * `boot_epoch` — last observed via Hello/HelloAck.
//!   * `miss_count` — consecutive missed Hellos; once it crosses
//!     `hello_dead_interval / hello_interval`, the link is declared down.
//!   * `is_up` — whether we currently include this neighbor in our LSA.
//!
//! The monitor exposes a `snapshot()` that returns one
//! `NeighborSnapshot` per `is_up` neighbor with its current cost
//! readings (RTT / jitter / throughput / transports). This snapshot is
//! what `lsdb::advert::build_local_lsa` reads to construct each LSA.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::{broadcast, Notify};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace};

use crate::s2s::transport::{ConnectionManager, TransportKind};
use crate::types::NodeIdentifier;

use super::super::config::OverlayConfig;
use super::super::membership::MembershipEvent;
use super::super::proto::transports_to_mask;

/// Snapshot suitable for embedding as a `LinkAdvert` in an outbound LSA.
#[derive(Clone, Debug)]
pub struct NeighborSnapshot {
    pub node_id: NodeIdentifier,
    pub rtt_us: u64,
    pub jitter_us: u64,
    pub throughput_bps: u64,
    pub transports_mask: u32,
}

#[derive(Debug)]
struct NeighborState {
    boot_epoch: u64,
    last_ack_at: Option<Instant>,
    miss_count: u32,
    is_up: bool,
    /// Pending pings by nonce -> when sent (for RTT calculation on ack).
    pending: HashMap<u64, Instant>,
}

impl NeighborState {
    fn new() -> Self {
        Self {
            boot_epoch: 0,
            last_ack_at: None,
            miss_count: 0,
            is_up: false,
            pending: HashMap::new(),
        }
    }
}

/// Direct-neighbor table.
pub struct NeighborMonitor {
    self_id: NodeIdentifier,
    transport: ConnectionManager,
    cfg: OverlayConfig,
    state: Mutex<HashMap<NodeIdentifier, NeighborState>>,
    /// Notified whenever a neighbor goes up/down or boot_epoch changes.
    /// Wakes the LSA emitter and the LSDB sync trigger.
    on_change: Arc<Notify>,
    /// To emit `Restarted` events directly on Hello-driven boot_epoch
    /// increase (faster than waiting for the LSA).
    membership_events: broadcast::Sender<MembershipEvent>,
    /// Notified after a "link up" so the runtime can schedule a full
    /// `LsdbSync` pull.
    on_link_up: Arc<Notify>,
}

impl NeighborMonitor {
    pub fn new(
        self_id: NodeIdentifier,
        transport: ConnectionManager,
        cfg: OverlayConfig,
        membership_events: broadcast::Sender<MembershipEvent>,
    ) -> Self {
        Self {
            self_id,
            transport,
            cfg,
            state: Mutex::new(HashMap::new()),
            on_change: Arc::new(Notify::new()),
            membership_events,
            on_link_up: Arc::new(Notify::new()),
        }
    }

    pub fn on_change(&self) -> Arc<Notify> {
        self.on_change.clone()
    }

    pub fn on_link_up(&self) -> Arc<Notify> {
        self.on_link_up.clone()
    }

    /// Build a snapshot of every currently-up neighbor with live cost
    /// metrics drawn from `metrics_snapshot()`.
    pub fn snapshot(&self) -> Vec<NeighborSnapshot> {
        let metrics = self.transport.metrics_snapshot();
        let g = self.state.lock();
        let mut out = Vec::with_capacity(g.len());
        for (nid, st) in g.iter() {
            if !st.is_up {
                continue;
            }
            let (rtt_us, jitter_us, throughput_bps, kinds) = match metrics.for_node(*nid) {
                Some(per_t) => {
                    let mut best_rtt: Option<f64> = None;
                    let mut best_jitter: Option<f64> = None;
                    let mut total_tput: f64 = 0.0;
                    let mut kinds: Vec<TransportKind> = Vec::new();
                    for (k, m) in per_t {
                        kinds.push(*k);
                        if m.rtt_us() > 0.0 {
                            best_rtt = Some(match best_rtt {
                                Some(prev) => prev.min(m.rtt_us()),
                                None => m.rtt_us(),
                            });
                            best_jitter = Some(match best_jitter {
                                Some(prev) => prev.min(m.jitter_us()),
                                None => m.jitter_us(),
                            });
                        }
                        total_tput += m.estimated_throughput_bps();
                    }
                    (
                        best_rtt.unwrap_or(0.0) as u64,
                        best_jitter.unwrap_or(0.0) as u64,
                        total_tput as u64,
                        kinds,
                    )
                }
                None => (0, 0, 0, Vec::new()),
            };
            let transports_mask = transports_to_mask(&kinds);
            out.push(NeighborSnapshot {
                node_id: *nid,
                rtt_us,
                jitter_us,
                throughput_bps,
                transports_mask,
            });
        }
        out.sort_by_key(|n| n.node_id);
        out
    }

    /// True if `node` is currently considered a direct neighbor.
    pub fn is_up(&self, node: NodeIdentifier) -> bool {
        self.state
            .lock()
            .get(&node)
            .map(|s| s.is_up)
            .unwrap_or(false)
    }

    /// Record an outbound Hello so we can match its ack later.
    pub fn record_outbound_ping(&self, dst: NodeIdentifier, nonce: u64) {
        let mut g = self.state.lock();
        let st = g.entry(dst).or_insert_with(NeighborState::new);
        st.pending.insert(nonce, Instant::now());
    }

    /// Caller: inbound dispatcher when a `Hello` arrives. Updates
    /// boot_epoch tracking and returns `Restarted` if this is a higher
    /// boot_epoch than we'd seen for `from`.
    pub fn record_hello(&self, from: NodeIdentifier, boot_epoch: u64) {
        let became_up = {
            let mut g = self.state.lock();
            let st = g.entry(from).or_insert_with(NeighborState::new);
            let was_up = st.is_up;
            let prev_be = st.boot_epoch;
            if boot_epoch > prev_be {
                st.boot_epoch = boot_epoch;
                // Only emit Restarted if we'd seen a *previous* epoch (>0).
                // First-ever boot_epoch is just initial state.
                if prev_be > 0 {
                    let _ = self
                        .membership_events
                        .send(MembershipEvent::Restarted(from));
                    debug!(peer=%from, new_epoch=boot_epoch, "neighbor restart detected via hello");
                }
            }
            st.last_ack_at = Some(Instant::now());
            st.miss_count = 0;
            st.is_up = true;
            !was_up
        };
        if became_up {
            debug!(peer=%from, "direct link up");
            self.on_change.notify_one();
            self.on_link_up.notify_one();
        }
    }

    /// Caller: inbound dispatcher when a `HelloAck` arrives. Records RTT
    /// (against the matched nonce), updates miss_count, and tracks
    /// boot_epoch.
    pub fn record_hello_ack(
        &self,
        from: NodeIdentifier,
        boot_epoch: u64,
        nonce: u64,
        ts_send_us: u64,
        peer_metrics_target: Option<TransportKind>,
    ) {
        let now = Instant::now();
        let (was_up, mut sent_at_instant) = {
            let mut g = self.state.lock();
            let st = g.entry(from).or_insert_with(NeighborState::new);
            let was_up = st.is_up;
            let prev_be = st.boot_epoch;
            if boot_epoch > prev_be {
                st.boot_epoch = boot_epoch;
                if prev_be > 0 {
                    let _ = self
                        .membership_events
                        .send(MembershipEvent::Restarted(from));
                }
            }
            st.last_ack_at = Some(now);
            st.miss_count = 0;
            st.is_up = true;
            // RTT calc — prefer the recorded ts_send (echoed) over our own
            // pending table since either is a valid round-trip measurement.
            let sent_at_instant: Option<Instant> = st.pending.remove(&nonce);
            // Cap pending table size — drop stale entries occasionally.
            if st.pending.len() > 32 {
                let cutoff = now - Duration::from_secs(60);
                st.pending.retain(|_, t| *t > cutoff);
            }
            (was_up, sent_at_instant)
        };
        let rtt = if let Some(t) = sent_at_instant.take() {
            now.saturating_duration_since(t)
        } else {
            // Reconstruct from echoed wall-clock if we lost track of the
            // pending entry. ts_send_us is microseconds-since-arbitrary;
            // we cannot reliably convert to a duration-since-now without
            // a shared epoch. Skip RTT in that case.
            return;
        };
        let kind = peer_metrics_target.unwrap_or(TransportKind::Tcp);
        if let Some(peer) = self.transport.inner.get_peer(from) {
            peer.metrics().record_rtt(kind, rtt);
        }
        let became_up = !was_up;
        if became_up {
            debug!(peer=%from, ?rtt, "direct link up");
            self.on_change.notify_one();
            self.on_link_up.notify_one();
        }
    }

    /// Sweep neighbors on a tick. For each peer with a live L1 stream:
    ///   * if `last_ack_at` older than `hello_dead_interval`, increment
    ///     `miss_count`. Once miss_count crosses the dead threshold, drop
    ///     the link from the LSA.
    /// For peers no longer in L1's live set, mark down.
    pub fn sweep_and_collect_targets(&self) -> Vec<(NodeIdentifier, Vec<TransportKind>)> {
        let live_peers = self.live_peers();
        let live_ids: HashSet<NodeIdentifier> = live_peers.iter().map(|(n, _)| *n).collect();
        let now = Instant::now();
        let dead = self.cfg.hello_dead_interval();
        let transitions = {
            let mut g = self.state.lock();
            let mut transitions = Vec::new();

            // Sweep existing entries.
            let mut to_remove: Vec<NodeIdentifier> = Vec::new();
            for (nid, st) in g.iter_mut() {
                if !live_ids.contains(nid) {
                    if st.is_up {
                        st.is_up = false;
                        transitions.push((*nid, false));
                    }
                    // L1 also dropped; eventually purge.
                    if st
                        .last_ack_at
                        .map_or(true, |t| now.duration_since(t) > dead * 4)
                    {
                        to_remove.push(*nid);
                    }
                    continue;
                }
                if let Some(last) = st.last_ack_at {
                    if now.duration_since(last) >= dead {
                        if st.is_up {
                            st.is_up = false;
                            transitions.push((*nid, false));
                        }
                    }
                }
            }
            for n in to_remove {
                g.remove(&n);
            }
            transitions
        };

        for (n, _) in &transitions {
            debug!(peer=%n, "direct link down (hello dead-interval)");
        }
        if !transitions.is_empty() {
            self.on_change.notify_one();
        }
        live_peers
    }

    /// Direct neighbor enumeration: every peer in the L1 manager with
    /// `has_any_live_stream`.
    fn live_peers(&self) -> Vec<(NodeIdentifier, Vec<TransportKind>)> {
        let mut out = Vec::new();
        for (nid, peer) in self.transport.inner.iter_peers() {
            if nid == self.self_id {
                continue;
            }
            if peer.has_any_live_stream() {
                out.push((nid, peer.live_kinds()));
            }
        }
        out
    }
}
