//! Membership view derived from the LSDB.
//!
//! In Phase 2, the LSDB is the single source of truth for cluster
//! membership: an origin is `Alive` iff its non-tombstone LSA is
//! current; `Left` is announced via an explicit tombstone LSA; `Failed`
//! is emitted when a non-tombstone LSA ages out without a refresh.
//! `Restarted` fires whenever an origin's `boot_epoch` advances —
//! either via a Hello (immediate) or via an LSA admission (from the
//! diff watcher).
//!
//! The public types (`MemberSnapshot`, `MemberStatus`, `MembershipEvent`)
//! mirror Phase 1 in shape so callers compile unchanged.

pub mod view;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use shitspeak_s2s_transport::PeerAddress;
use shitspeak_core::NodeIdentifier;

use super::lsdb::{LinkStateDb, ReplicationServices};
pub use view::MemberStatus;

/// Caller-facing snapshot of one cluster member.
#[derive(Clone, Debug)]
pub struct MemberSnapshot {
    node_id: NodeIdentifier,
    status: MemberStatus,
    addresses: Vec<PeerAddress>,
    boot_epoch: u64,
    max_users: u64,
    replication_services: ReplicationServices,
}

impl MemberSnapshot {
    pub fn node_id(&self) -> NodeIdentifier {
        self.node_id
    }

    pub fn status(&self) -> MemberStatus {
        self.status
    }

    pub fn addresses(&self) -> &[PeerAddress] {
        &self.addresses
    }

    pub fn boot_epoch(&self) -> u64 {
        self.boot_epoch
    }

    pub fn max_users(&self) -> u64 {
        self.max_users
    }

    pub fn replication_services(&self) -> ReplicationServices {
        self.replication_services
    }

    /// Phase-1 compatibility: callers expect an "incarnation"; we map it
    /// to `boot_epoch` (which serves the same monotonic-restart role).
    pub fn incarnation(&self) -> u64 {
        self.boot_epoch
    }

    pub fn last_state_change(&self) -> Instant {
        Instant::now()
    }
}

/// Public event surface. `Restarted` is emitted whenever an origin's
/// `boot_epoch` advances — both Hello-driven and LSA-driven paths
/// contribute. The diff watcher is idempotent w.r.t. the last-emitted
/// boot_epoch, but Hello-driven emission is best-effort and may
/// duplicate.
#[derive(Clone, Debug)]
pub enum MembershipEvent {
    Joined(NodeIdentifier),
    Left(NodeIdentifier),
    Failed(NodeIdentifier),
    Restarted(NodeIdentifier),
}

/// Thin reader over the LSDB. The Phase-1 `merge_update`/`note_ack`/
/// `local_transition` API is gone — the LSDB owns admission. Public
/// surface is `snapshot()`, `snapshot_one()`, `subscribe()`,
/// `alive_members()`, `self_id()`.
pub struct MembershipTable {
    lsdb: Arc<LinkStateDb>,
    events_tx: broadcast::Sender<MembershipEvent>,
    self_id: NodeIdentifier,
    /// Snapshot of {origin -> boot_epoch} from the last diff pass, used
    /// to compute Joined/Left/Failed/Restarted transitions.
    last: RwLock<HashMap<NodeIdentifier, LastSeen>>,
}

#[derive(Clone, Copy, Debug)]
struct LastSeen {
    boot_epoch: u64,
    tombstone: bool,
}

impl MembershipTable {
    pub fn new(
        self_id: NodeIdentifier,
        lsdb: Arc<LinkStateDb>,
        events_tx: broadcast::Sender<MembershipEvent>,
    ) -> Self {
        Self {
            lsdb,
            events_tx,
            self_id,
            last: RwLock::new(HashMap::new()),
        }
    }

    pub fn self_id(&self) -> NodeIdentifier {
        self.self_id
    }

    /// Snapshot of every known cluster member. Sorted by node id.
    pub fn snapshot(&self) -> Vec<MemberSnapshot> {
        let lsas = self.lsdb.snapshot();
        let mut out: Vec<MemberSnapshot> = lsas
            .iter()
            .map(|e| MemberSnapshot {
                node_id: e.origin,
                status: if e.tombstone {
                    MemberStatus::Left
                } else {
                    MemberStatus::Alive
                },
                addresses: e.addresses.clone(),
                boot_epoch: e.boot_epoch,
                max_users: e.max_users,
                replication_services: e.replication_services,
            })
            .collect();
        out.sort_by_key(|m| m.node_id);
        out
    }

    pub fn snapshot_one(&self, node: NodeIdentifier) -> Option<MemberSnapshot> {
        self.lsdb.get(node).map(|e| MemberSnapshot {
            node_id: e.origin,
            status: if e.tombstone {
                MemberStatus::Left
            } else {
                MemberStatus::Alive
            },
            addresses: e.addresses.clone(),
            boot_epoch: e.boot_epoch,
            max_users: e.max_users,
            replication_services: e.replication_services,
        })
    }

    /// IDs of every origin with a current non-tombstone LSA.
    pub fn alive_members(&self) -> Vec<NodeIdentifier> {
        self.lsdb.active_origins()
    }

    /// IDs of active origins that advertise strict replication service.
    pub fn strict_replication_members(&self) -> Vec<NodeIdentifier> {
        self.lsdb.strict_replication_origins()
    }

    /// IDs of active origins that advertise content/blob replication service.
    pub fn content_replication_members(&self) -> Vec<NodeIdentifier> {
        self.lsdb.content_replication_origins()
    }

    /// IDs of active origins that advertise owner-scoped replication service.
    pub fn owner_replication_members(&self) -> Vec<NodeIdentifier> {
        self.lsdb.owner_replication_origins()
    }

    /// Sum max_users advertised by every current non-tombstone LSA.
    pub fn alive_max_users(&self) -> u64 {
        self.lsdb.alive_max_users()
    }

    /// Event broadcast subscriber. Each subscriber receives every event.
    pub fn subscribe(&self) -> broadcast::Receiver<MembershipEvent> {
        self.events_tx.subscribe()
    }

    /// Diff the current LSDB origin set against `last` and emit events
    /// for transitions. Called by the diff watcher task.
    pub fn diff_and_emit(&self, swept_failed: &HashSet<NodeIdentifier>) {
        let now: HashMap<NodeIdentifier, LastSeen> = self.lsdb.with_entries(|entries| {
            entries
                .values()
                .map(|e| {
                    (
                        e.origin,
                        LastSeen {
                            boot_epoch: e.boot_epoch,
                            tombstone: e.tombstone,
                        },
                    )
                })
                .collect()
        });
        let mut last = self.last.write();
        // Departed origins (not in `now`): if previously Alive AND
        // we know it failed (sweeper told us), emit Failed; otherwise
        // it's a tombstone aged-out (silent).
        for (nid, prev) in last.iter() {
            if !now.contains_key(nid) {
                if !prev.tombstone && swept_failed.contains(nid) {
                    let _ = self.events_tx.send(MembershipEvent::Failed(*nid));
                }
                // tombstone aged out: silent (Left already emitted).
            }
        }
        // New / changed origins.
        for (nid, cur) in &now {
            if *nid == self.self_id {
                continue;
            }
            match last.get(nid) {
                None => {
                    // First sight.
                    if cur.tombstone {
                        let _ = self.events_tx.send(MembershipEvent::Left(*nid));
                    } else {
                        let _ = self.events_tx.send(MembershipEvent::Joined(*nid));
                    }
                }
                Some(prev) => {
                    // Restart detection.
                    if cur.boot_epoch > prev.boot_epoch {
                        let _ = self.events_tx.send(MembershipEvent::Restarted(*nid));
                    }
                    // Alive -> Left transition.
                    if !prev.tombstone && cur.tombstone {
                        let _ = self.events_tx.send(MembershipEvent::Left(*nid));
                    }
                    // Left/Failed -> Alive (rejoin).
                    if prev.tombstone && !cur.tombstone {
                        let _ = self.events_tx.send(MembershipEvent::Joined(*nid));
                    }
                }
            }
        }
        *last = now;
    }
}

/// Construct an `Arc<MembershipTable>` together with its event broadcaster.
pub fn new_table(
    self_id: NodeIdentifier,
    lsdb: Arc<LinkStateDb>,
    event_capacity: usize,
) -> (Arc<MembershipTable>, broadcast::Sender<MembershipEvent>) {
    let (tx, _) = broadcast::channel(event_capacity);
    (
        Arc::new(MembershipTable::new(self_id, lsdb, tx.clone())),
        tx,
    )
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::overlay::lsdb::{LsaEntry, LsaFloor};

    fn entry(origin: NodeIdentifier, seq: u64, tombstone: bool, max_users: u64) -> LsaEntry {
        LsaEntry {
            origin,
            boot_epoch: 100,
            seq,
            ts_local_received: Instant::now(),
            tombstone,
            addresses: Vec::new(),
            links: Vec::new(),
            max_users,
            transit_disabled: false,
            replication_services: ReplicationServices::ALL,
        }
    }

    #[test]
    fn alive_max_users_sums_alive_members_only() {
        let floor = Arc::new(LsaFloor::new(0, None));
        let lsdb = Arc::new(LinkStateDb::new(floor));
        let (table, _) = new_table(1, lsdb.clone(), 8);

        lsdb.admit(entry(1, 1, false, 100));
        lsdb.admit(entry(2, 1, false, 200));
        lsdb.admit(entry(3, 1, true, 300));

        assert_eq!(table.alive_max_users(), 300);
        assert_eq!(table.snapshot_one(1).unwrap().max_users(), 100);
    }

    #[test]
    fn replication_members_filter_by_service_kind() {
        let floor = Arc::new(LsaFloor::new(0, None));
        let lsdb = Arc::new(LinkStateDb::new(floor));
        let (table, _) = new_table(1, lsdb.clone(), 8);

        let strict = entry(1, 1, false, 100);
        let mut content = entry(2, 1, false, 200);
        content.replication_services = ReplicationServices::new(false, true, false);
        let mut owner = entry(3, 1, false, 300);
        owner.replication_services = ReplicationServices::new(false, false, true);

        lsdb.admit(strict);
        lsdb.admit(content);
        lsdb.admit(owner);

        assert_eq!(table.strict_replication_members(), vec![1]);
        assert_eq!(table.content_replication_members(), vec![1, 2]);
        assert_eq!(table.owner_replication_members(), vec![1, 3]);
        assert!(
            table
                .snapshot_one(2)
                .unwrap()
                .replication_services()
                .content()
        );
    }
}

/// Background task: diff the LSDB on every change_signal + after sweep
/// passes; emit Joined/Left/Failed/Restarted events.
pub fn spawn_diff_watcher(
    table: Arc<MembershipTable>,
    lsdb: Arc<LinkStateDb>,
    cfg_lsa_max_age: std::time::Duration,
    cfg_tombstone_age: std::time::Duration,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        let mut sweep_tick = tokio::time::interval(std::time::Duration::from_secs(1));
        sweep_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        sweep_tick.tick().await; // discard the immediate first tick
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = lsdb.change_signal().notified() => {
                    table.diff_and_emit(&HashSet::new());
                }
                _ = sweep_tick.tick() => {
                    let (failed, _swept_tombstones) = lsdb.sweep(cfg_lsa_max_age, cfg_tombstone_age);
                    let failed_set: HashSet<NodeIdentifier> = failed.into_iter().collect();
                    table.diff_and_emit(&failed_set);
                }
            }
        }
    });
}
