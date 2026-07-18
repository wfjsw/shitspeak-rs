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

use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::PeerAddress;

use super::lsdb::{ApplicationServices, LinkStateDb, ReplicationServices};
pub use view::MemberStatus;

/// Immutable identity of one observed node incarnation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MemberIncarnation {
    node_id: NodeIdentifier,
    incarnation: u64,
}

impl MemberIncarnation {
    pub fn new(node_id: NodeIdentifier, incarnation: u64) -> Self {
        Self {
            node_id,
            incarnation,
        }
    }

    pub fn node_id(&self) -> NodeIdentifier {
        self.node_id
    }

    pub fn incarnation(&self) -> u64 {
        self.incarnation
    }
}

/// Caller-facing snapshot of one cluster member.
#[derive(Clone, Debug)]
pub struct MemberSnapshot {
    node_id: NodeIdentifier,
    status: MemberStatus,
    addresses: Vec<PeerAddress>,
    boot_epoch: u64,
    max_users: u64,
    transit_disabled: bool,
    replication_services: ReplicationServices,
    application_services: ApplicationServices,
    strict_replication_protocol_version: u32,
    strict_replication_transit_protocol_version: u32,
    upper_layer_capabilities: Option<Vec<u8>>,
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

    /// Whether this member asks peers not to use it as a transit router.
    pub fn transit_disabled(&self) -> bool {
        self.transit_disabled
    }

    /// Deprecated wire-compatibility service bits. Upper layers should use
    /// `upper_layer_capabilities`; these bits are consulted only when that
    /// authoritative field is absent.
    pub fn replication_services(&self) -> ReplicationServices {
        self.replication_services
    }

    pub fn application_services(&self) -> ApplicationServices {
        self.application_services.clone()
    }

    /// Deprecated rolling-upgrade participant version. Replication decodes
    /// the opaque capability envelope whenever it is present.
    pub fn strict_replication_protocol_version(&self) -> u32 {
        self.strict_replication_protocol_version
    }

    /// Deprecated rolling-upgrade transit marker. Overlay payload forwarding
    /// is opaque and current replication negotiation does not consume it.
    pub fn strict_replication_transit_protocol_version(&self) -> u32 {
        self.strict_replication_transit_protocol_version
    }

    /// Opaque upper-layer capabilities advertised by this member. Absence
    /// identifies a legacy LSA without the generic capability envelope.
    pub fn upper_layer_capabilities(&self) -> Option<&[u8]> {
        self.upper_layer_capabilities.as_deref()
    }

    /// Whether this alive member can relay the requested generic
    /// distribution-tree profile.
    pub fn supports_distribution_profile(
        &self,
        required_protocol_version: u32,
        profile_id: u32,
    ) -> bool {
        self.status.is_reachable()
            && self
                .application_services
                .distribution()
                .supports(required_protocol_version, profile_id)
    }

    /// Phase-1 compatibility: callers expect an "incarnation"; we map it
    /// to `boot_epoch` (which serves the same monotonic-restart role).
    pub fn incarnation(&self) -> u64 {
        self.boot_epoch
    }

    pub fn member_incarnation(&self) -> MemberIncarnation {
        MemberIncarnation::new(self.node_id, self.boot_epoch)
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
    Joined(MemberIncarnation),
    Left(MemberIncarnation),
    Failed(MemberIncarnation),
    Restarted(MemberIncarnation),
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
                transit_disabled: e.transit_disabled,
                replication_services: e.replication_services,
                application_services: e.application_services.clone(),
                strict_replication_protocol_version: e.strict_replication_protocol_version(),
                strict_replication_transit_protocol_version: e
                    .strict_replication_transit_protocol_version(),
                upper_layer_capabilities: e.upper_layer_capabilities().map(<[u8]>::to_vec),
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
            transit_disabled: e.transit_disabled,
            replication_services: e.replication_services,
            application_services: e.application_services.clone(),
            strict_replication_protocol_version: e.strict_replication_protocol_version(),
            strict_replication_transit_protocol_version: e
                .strict_replication_transit_protocol_version(),
            upper_layer_capabilities: e.upper_layer_capabilities().map(<[u8]>::to_vec),
        })
    }

    /// IDs of every origin with a current non-tombstone LSA.
    pub fn alive_members(&self) -> Vec<NodeIdentifier> {
        self.lsdb.active_origins()
    }

    /// IDs of active origins that advertise application voice service.
    pub fn voice_members(&self) -> Vec<NodeIdentifier> {
        self.lsdb.voice_origins()
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
                    let _ = self
                        .events_tx
                        .send(MembershipEvent::Failed(MemberIncarnation::new(
                            *nid,
                            prev.boot_epoch,
                        )));
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
                        let _ = self
                            .events_tx
                            .send(MembershipEvent::Left(MemberIncarnation::new(
                                *nid,
                                cur.boot_epoch,
                            )));
                    } else {
                        let _ =
                            self.events_tx
                                .send(MembershipEvent::Joined(MemberIncarnation::new(
                                    *nid,
                                    cur.boot_epoch,
                                )));
                    }
                }
                Some(prev) => {
                    // Restart detection.
                    if cur.boot_epoch > prev.boot_epoch {
                        let _ = self.events_tx.send(MembershipEvent::Restarted(
                            MemberIncarnation::new(*nid, cur.boot_epoch),
                        ));
                    }
                    // Alive -> Left transition.
                    if !prev.tombstone && cur.tombstone {
                        let _ = self
                            .events_tx
                            .send(MembershipEvent::Left(MemberIncarnation::new(
                                *nid,
                                cur.boot_epoch,
                            )));
                    }
                    // Left/Failed -> Alive (rejoin).
                    if prev.tombstone && !cur.tombstone {
                        let _ =
                            self.events_tx
                                .send(MembershipEvent::Joined(MemberIncarnation::new(
                                    *nid,
                                    cur.boot_epoch,
                                )));
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
            application_services: ApplicationServices::ALL,
            strict_replication_protocol_version: 0,
            strict_replication_transit_protocol_version: 0,
            upper_layer_capabilities: None,
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
    fn snapshot_preserves_upper_layer_capability_presence_and_bytes() {
        let floor = Arc::new(LsaFloor::new(0, None));
        let lsdb = Arc::new(LinkStateDb::new(floor));
        let (table, _) = new_table(1, lsdb.clone(), 8);

        let legacy = entry(1, 1, false, 100);
        let mut current = entry(2, 1, false, 100);
        current.upper_layer_capabilities = Some(vec![7, 8, 9]);
        lsdb.admit(legacy);
        lsdb.admit(current);

        assert_eq!(
            table.snapshot_one(1).unwrap().upper_layer_capabilities(),
            None
        );
        assert_eq!(
            table.snapshot_one(2).unwrap().upper_layer_capabilities(),
            Some(&[7, 8, 9][..])
        );
    }

    #[test]
    fn voice_members_filter_by_application_service() {
        let floor = Arc::new(LsaFloor::new(0, None));
        let lsdb = Arc::new(LinkStateDb::new(floor));
        let (table, _) = new_table(1, lsdb.clone(), 8);

        let voice = entry(1, 1, false, 100);
        let mut forwarder = entry(2, 1, false, 0);
        forwarder.application_services = ApplicationServices::NONE;

        lsdb.admit(voice);
        lsdb.admit(forwarder);

        assert_eq!(table.voice_members(), vec![1]);
        assert!(
            !table
                .snapshot_one(2)
                .unwrap()
                .application_services()
                .voice()
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
