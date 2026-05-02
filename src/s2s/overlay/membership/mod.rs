//! Membership subsystem: SWIM-driven view of who is in the cluster.

pub mod gossip;
pub mod swim;
pub mod view;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tokio::sync::broadcast;
use tracing::{debug, info};

use crate::s2s::transport::PeerAddress;
use crate::types::NodeIdentifier;

use super::config::OverlayConfig;
pub use view::{MemberRecord, MemberStatus};

/// Caller-facing snapshot of one member's state. Cheap to clone.
#[derive(Clone, Debug)]
pub struct MemberSnapshot {
    node_id: NodeIdentifier,
    incarnation: u64,
    status: MemberStatus,
    addresses: Vec<PeerAddress>,
    last_state_change: Instant,
}

impl MemberSnapshot {
    pub fn node_id(&self) -> NodeIdentifier {
        self.node_id
    }

    pub fn incarnation(&self) -> u64 {
        self.incarnation
    }

    pub fn status(&self) -> MemberStatus {
        self.status
    }

    pub fn addresses(&self) -> &[PeerAddress] {
        &self.addresses
    }

    pub fn last_state_change(&self) -> Instant {
        self.last_state_change
    }
}

impl From<&MemberRecord> for MemberSnapshot {
    fn from(r: &MemberRecord) -> Self {
        Self {
            node_id: r.node_id(),
            incarnation: r.incarnation(),
            status: r.status(),
            addresses: r.addresses().to_vec(),
            last_state_change: r.last_state_change(),
        }
    }
}

/// Public event stream produced by the membership subsystem. Subscribers
/// each receive every event via `tokio::sync::broadcast`. Restarted is
/// emitted in Phase 3.
#[derive(Clone, Debug)]
pub enum MembershipEvent {
    Joined(NodeIdentifier),
    Left(NodeIdentifier),
    Failed(NodeIdentifier),
    Restarted(NodeIdentifier),
}

/// Local node's view of cluster membership. Internally a `RwLock<HashMap>`;
/// reads (snapshots, gossip selection) take a read lock, mutations (merge,
/// local transitions) take a write lock briefly.
pub struct MembershipTable {
    inner: RwLock<HashMap<NodeIdentifier, MemberRecord>>,
    events_tx: broadcast::Sender<MembershipEvent>,
    /// We never put ourselves in the table; everyone else does. But we
    /// remember our own id so we can no-op if our id ever appears in gossip.
    self_id: NodeIdentifier,
}

impl MembershipTable {
    pub fn new(self_id: NodeIdentifier, events_tx: broadcast::Sender<MembershipEvent>) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            events_tx,
            self_id,
        }
    }

    pub fn self_id(&self) -> NodeIdentifier {
        self.self_id
    }

    /// Snapshot every known member. Result is sorted by node id for stable test output.
    pub fn snapshot(&self) -> Vec<MemberSnapshot> {
        let g = self.inner.read();
        let mut out: Vec<_> = g.values().map(MemberSnapshot::from).collect();
        out.sort_by_key(|m| m.node_id());
        out
    }

    pub fn snapshot_one(&self, node: NodeIdentifier) -> Option<MemberSnapshot> {
        self.inner.read().get(&node).map(MemberSnapshot::from)
    }

    /// Insert (or upsert) a peer learned at startup from seeds or persisted
    /// state. Inserts as `Suspect` so the SWIM ticker probes it; we do not
    /// emit `Joined` until a real ack confirms the peer.
    pub fn install_seed(&self, node: NodeIdentifier, addresses: Vec<PeerAddress>) {
        if node == self.self_id {
            return;
        }
        let mut g = self.inner.write();
        g.entry(node)
            .and_modify(|r| {
                for a in &addresses {
                    r.add_address(*a);
                }
            })
            .or_insert_with(|| MemberRecord::new_seed(node, addresses));
    }

    /// Apply one inbound `GossipUpdate` (already converted to domain types).
    /// Returns the events that should be broadcast (zero or more).
    pub fn merge_update(
        &self,
        node: NodeIdentifier,
        incarnation: u64,
        claim: MemberStatus,
        addresses: &[PeerAddress],
    ) -> Vec<MembershipEvent> {
        if node == self.self_id {
            // We never store ourselves; refute logic happens elsewhere.
            return Vec::new();
        }
        let mut events = Vec::new();
        let mut g = self.inner.write();
        match g.get_mut(&node) {
            Some(r) => {
                let prev_status = r.status();
                let prev_incarnation = r.incarnation();
                if r.merge(incarnation, claim, addresses) {
                    let now_status = r.status();
                    let now_incarnation = r.incarnation();
                    drop(g);
                    events.extend(transition_events(
                        node,
                        prev_status,
                        now_status,
                        prev_incarnation,
                        now_incarnation,
                    ));
                }
            }
            None => {
                let mut r = MemberRecord::new_alive(node, incarnation, addresses.to_vec());
                r.set_status(claim);
                g.insert(node, r);
                drop(g);
                if claim == MemberStatus::Alive {
                    events.push(MembershipEvent::Joined(node));
                } else if claim == MemberStatus::Left {
                    events.push(MembershipEvent::Left(node));
                } else if claim == MemberStatus::Dead {
                    events.push(MembershipEvent::Failed(node));
                }
            }
        }
        events
    }

    /// Note that a SWIM ack arrived from `node`. If the peer was Suspect we
    /// move them back to Alive locally (no incarnation bump — the ack itself
    /// proves liveness). Returns events to broadcast.
    pub fn note_ack(&self, node: NodeIdentifier) -> Vec<MembershipEvent> {
        if node == self.self_id {
            return Vec::new();
        }
        let mut g = self.inner.write();
        let Some(r) = g.get_mut(&node) else {
            return Vec::new();
        };
        let prev = r.status();
        r.note_ack();
        let now = r.status();
        if prev != now && now == MemberStatus::Alive {
            // Peer recovered from Suspect; not really a "Joined" event,
            // upper layers can ignore. We don't emit anything here — only
            // first-time joins emit Joined.
            debug!(peer=%node, "swim ack moved peer back to Alive");
        }
        Vec::new()
    }

    /// Force a local transition (no incarnation bump). Used by the SWIM
    /// ticker on probe timeout (Alive→Suspect) and the reaper (Suspect→Dead).
    pub fn local_transition(
        &self,
        node: NodeIdentifier,
        new_status: MemberStatus,
    ) -> Vec<MembershipEvent> {
        if node == self.self_id {
            return Vec::new();
        }
        let mut g = self.inner.write();
        let Some(r) = g.get_mut(&node) else {
            return Vec::new();
        };
        let prev = r.status();
        if !r.local_transition(new_status) {
            return Vec::new();
        }
        let now = r.status();
        let inc = r.incarnation();
        drop(g);
        transition_events(node, prev, now, inc, inc)
    }

    /// Reap members that have been `Dead` longer than `dead_timeout`. Returns
    /// the list of reaped node ids so the caller can call `transport.forget_node`.
    pub fn reap_dead(&self, dead_timeout: Duration) -> Vec<NodeIdentifier> {
        let now = Instant::now();
        let mut g = self.inner.write();
        let mut reaped = Vec::new();
        g.retain(|node_id, r| {
            let should_reap = matches!(r.status(), MemberStatus::Dead | MemberStatus::Left)
                && now.duration_since(r.last_state_change()) >= dead_timeout;
            if should_reap {
                info!(peer=%node_id, status=?r.status(), "reaping member");
                reaped.push(*node_id);
                false
            } else {
                true
            }
        });
        reaped
    }

    /// Pick `n` `Alive` peers at random for indirect ping. Excludes `exclude`.
    pub fn pick_alive_random<R: rand::Rng>(
        &self,
        n: usize,
        exclude: NodeIdentifier,
        rng: &mut R,
    ) -> Vec<(NodeIdentifier, Vec<PeerAddress>)> {
        let g = self.inner.read();
        let mut alive: Vec<_> = g
            .values()
            .filter(|r| r.status() == MemberStatus::Alive && r.node_id() != exclude)
            .map(|r| (r.node_id(), r.addresses().to_vec()))
            .collect();
        // Fisher-Yates shuffle truncated at n.
        for i in 0..alive.len().min(n) {
            let j = rng.gen_range(i..alive.len());
            alive.swap(i, j);
        }
        alive.truncate(n);
        alive
    }

    /// Pick the next probe target via round-robin over a stable ordering of
    /// alive peers. The caller threads a `usize` cursor so successive calls
    /// across many ticks visit each peer.
    pub fn next_probe_target(&self, cursor: usize) -> Option<(NodeIdentifier, Vec<PeerAddress>)> {
        let g = self.inner.read();
        let mut alive: Vec<_> = g
            .values()
            .filter(|r| r.status().is_reachable())
            .map(|r| (r.node_id(), r.addresses().to_vec()))
            .collect();
        if alive.is_empty() {
            return None;
        }
        alive.sort_by_key(|(id, _)| *id);
        Some(alive[cursor % alive.len()].clone())
    }

    /// Gather up to `cap` of the most-recently-changed records as
    /// `GossipUpdate` payloads, for piggyback on SWIM ping/ack.
    pub fn recent_updates(&self, cap: usize) -> Vec<MemberRecord> {
        let g = self.inner.read();
        let mut all: Vec<_> = g.values().cloned().collect();
        all.sort_by_key(|r| std::cmp::Reverse(r.last_state_change()));
        all.truncate(cap);
        all
    }

    /// Send `events` over the broadcast channel. Errors (no subscribers)
    /// are silently ignored — the broadcast sender always succeeds when
    /// nobody is listening.
    pub fn publish(&self, events: Vec<MembershipEvent>) {
        for e in events {
            let _ = self.events_tx.send(e);
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<MembershipEvent> {
        self.events_tx.subscribe()
    }
}

/// Map a status transition to the public-event surface. Same incarnation,
/// status-only transitions emit `Failed` for Alive→Dead. Incarnation bumps
/// where the status drops (e.g., Dead → Alive at higher incarnation) emit
/// `Joined` since the peer must have rejoined.
fn transition_events(
    node: NodeIdentifier,
    prev_status: MemberStatus,
    now_status: MemberStatus,
    prev_inc: u64,
    now_inc: u64,
) -> Vec<MembershipEvent> {
    if prev_status == now_status && prev_inc == now_inc {
        return Vec::new();
    }
    match (prev_status, now_status) {
        (_, MemberStatus::Left) => vec![MembershipEvent::Left(node)],
        (_, MemberStatus::Dead) => vec![MembershipEvent::Failed(node)],
        (MemberStatus::Suspect, MemberStatus::Alive) | (MemberStatus::Dead, MemberStatus::Alive) => {
            vec![MembershipEvent::Joined(node)]
        }
        _ => Vec::new(),
    }
}

/// Construct an `Arc<MembershipTable>` together with its event broadcaster.
/// The capacity bounds how far behind a slow subscriber can fall before
/// missing events.
pub fn new_table(
    self_id: NodeIdentifier,
    event_capacity: usize,
) -> (Arc<MembershipTable>, broadcast::Sender<MembershipEvent>) {
    let (tx, _) = broadcast::channel(event_capacity);
    (Arc::new(MembershipTable::new(self_id, tx.clone())), tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn addr(port: u16) -> PeerAddress {
        PeerAddress::new(
            SocketAddr::from(([127, 0, 0, 1], port)),
            crate::s2s::transport::TransportKind::Tcp,
        )
    }

    #[test]
    fn joined_event_on_first_alive() {
        let (table, _tx) = new_table(1, 16);
        let events = table.merge_update(2, 100, MemberStatus::Alive, &[addr(2000)]);
        assert!(matches!(events.as_slice(), [MembershipEvent::Joined(2)]));
        assert!(table.snapshot_one(2).is_some());
    }

    #[test]
    fn failed_event_on_dead_transition() {
        let (table, _tx) = new_table(1, 16);
        table.merge_update(2, 100, MemberStatus::Alive, &[addr(2000)]);
        let events = table.local_transition(2, MemberStatus::Dead);
        assert!(matches!(events.as_slice(), [MembershipEvent::Failed(2)]));
    }

    #[test]
    fn left_event_dominates() {
        let (table, _tx) = new_table(1, 16);
        table.merge_update(2, 100, MemberStatus::Alive, &[addr(2000)]);
        let events = table.merge_update(2, 100, MemberStatus::Left, &[]);
        assert!(matches!(events.as_slice(), [MembershipEvent::Left(2)]));
    }

    #[test]
    fn reap_after_dead_timeout() {
        let (table, _tx) = new_table(1, 16);
        table.merge_update(2, 100, MemberStatus::Dead, &[addr(2000)]);
        // Force last_state_change far enough in the past.
        {
            let mut g = table.inner.write();
            let r = g.get_mut(&2).unwrap();
            r.set_last_state_change(Instant::now() - Duration::from_secs(60));
        }
        let reaped = table.reap_dead(Duration::from_secs(30));
        assert_eq!(reaped, vec![2u16]);
        assert!(table.snapshot_one(2).is_none());
    }

    #[test]
    fn self_id_is_skipped() {
        let (table, _tx) = new_table(7, 16);
        let events = table.merge_update(7, 100, MemberStatus::Dead, &[]);
        assert!(events.is_empty());
        assert!(table.snapshot_one(7).is_none());
    }
}
