//! Link-state database in-memory store + on-disk LSA floor.
//!
//! The LSDB is keyed by `origin: NodeIdentifier` and holds at most one
//! `LsaEntry` per origin. An incoming LSA is admitted iff its
//! `(boot_epoch, seq)` is strictly greater than the current `(boot_epoch,
//! seq)` for that origin in BOTH the LSDB and the on-disk floor.
//!
//! ## Floor (zombie defense)
//!
//! The floor is a single monotonic `(boot_epoch, seq)` per origin we have
//! ever seen. Every LSA admission advances it; persistence is debounced
//! via a [`Notify`]. The floor protects against the "stale LSA from a
//! partitioned peer revives a graceful-leaver" scenario AND the analogous
//! "we restart with empty LSDB and a stale LSA slips through" scenario.
//!
//! ## Lifecycle
//!
//! * Non-tombstone entries age out at `now - ts_local_received >=
//!   lsa_max_age` and emit `MembershipEvent::Failed(origin)`.
//! * Tombstone entries age out at `tombstone_in_memory_age` to free
//!   memory; the `Left` event was already emitted on first sight, so age-
//!   out is silent. The floor entry persists.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tracing::{debug, warn};

use crate::s2s::transport::PeerAddress;
use crate::types::NodeIdentifier;

use super::super::proto::{address_from_pb, address_to_pb};
use crate::s2s_overlay_proto as pb;

/// One LSA's domain-side representation.
#[derive(Clone, Debug)]
pub struct LsaEntry {
    pub origin: NodeIdentifier,
    pub boot_epoch: u64,
    pub seq: u64,
    pub ts_local_received: Instant,
    pub tombstone: bool,
    pub addresses: Vec<PeerAddress>,
    pub links: Vec<LinkAdvertised>,
    pub max_users: u64,
}

#[derive(Clone, Debug)]
pub struct LinkAdvertised {
    pub neighbor: NodeIdentifier,
    pub rtt_us: u64,
    pub jitter_us: u64,
    pub throughput_bps: u64,
    pub transports_mask: u32,
}

impl LsaEntry {
    /// Build from a wire LSA. Returns `None` if `origin` is not a valid
    /// `NodeIdentifier` (overflows u16).
    pub fn from_pb(pb: &pb::LinkStateAdvert) -> Option<Self> {
        use super::super::proto::node_from_wire;
        let origin = node_from_wire(pb.origin)?;
        let addresses = pb.addresses.iter().filter_map(address_from_pb).collect();
        let links = pb
            .links
            .iter()
            .filter_map(|l| {
                let neighbor = node_from_wire(l.neighbor)?;
                Some(LinkAdvertised {
                    neighbor,
                    rtt_us: l.rtt_us,
                    jitter_us: l.jitter_us,
                    throughput_bps: l.throughput_bps,
                    transports_mask: l.transports_mask,
                })
            })
            .collect();
        Some(LsaEntry {
            origin,
            boot_epoch: pb.boot_epoch,
            seq: pb.seq,
            ts_local_received: Instant::now(),
            tombstone: pb.tombstone,
            addresses,
            links,
            max_users: pb.max_users,
        })
    }

    pub fn to_pb(&self) -> pb::LinkStateAdvert {
        use super::super::proto::node_to_wire;
        pb::LinkStateAdvert {
            origin: node_to_wire(self.origin),
            boot_epoch: self.boot_epoch,
            seq: self.seq,
            ts_emit_us: 0,
            tombstone: self.tombstone,
            addresses: self.addresses.iter().map(address_to_pb).collect(),
            links: self
                .links
                .iter()
                .map(|l| pb::LinkAdvert {
                    neighbor: node_to_wire(l.neighbor),
                    rtt_us: l.rtt_us,
                    jitter_us: l.jitter_us,
                    throughput_bps: l.throughput_bps,
                    transports_mask: l.transports_mask,
                })
                .collect(),
            max_users: self.max_users,
        }
    }
}

/// Strictly-greater comparison on `(boot_epoch, seq)`.
#[inline]
pub fn is_strictly_newer(new_be: u64, new_seq: u64, cur_be: u64, cur_seq: u64) -> bool {
    new_be > cur_be || (new_be == cur_be && new_seq > cur_seq)
}

/// Outcome of an admission attempt. Used by the flood path to decide
/// whether to forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionResult {
    /// New origin or strictly newer (boot_epoch, seq); store updated.
    Accepted,
    /// Same/older `(boot_epoch, seq)` — already known.
    Stale,
    /// Same boot_epoch, same or older seq, BUT old entry was tombstone-
    /// gone-from-memory yet floor knew this seq. Caller drops silently.
    BelowFloor,
}

#[derive(Debug, Clone, Copy)]
pub struct OriginVersion {
    pub boot_epoch: u64,
    pub seq: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum DiffOutcome {
    /// Newer than what the requester says they have; send them ours.
    SendOurs,
    /// They have something newer or equal; skip.
    Skip,
}

/// On-disk floor entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct FloorEntryDisk {
    origin: u32,
    boot_epoch: u64,
    seq: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct FloorFileV1 {
    version: u32,
    floor: Vec<FloorEntryDisk>,
}

/// Monotonic per-origin floor: highest `(boot_epoch, seq)` we have ever
/// seen. Persisted to disk debounced.
pub struct LsaFloor {
    inner: RwLock<HashMap<NodeIdentifier, OriginVersion>>,
    persistence_dir: Option<PathBuf>,
    persist_signal: Notify,
}

impl LsaFloor {
    pub fn new(persistence_dir: Option<PathBuf>) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            persistence_dir,
            persist_signal: Notify::new(),
        }
    }

    /// Load from `lsa_floor.json` under `persistence_dir/overlay/`. Missing
    /// file is not an error.
    pub fn load(&self) {
        let Some(dir) = &self.persistence_dir else {
            return;
        };
        let path = floor_path(dir);
        match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<FloorFileV1>(&bytes) {
                Ok(v1) if v1.version == 1 => {
                    let mut g = self.inner.write();
                    for e in v1.floor {
                        if e.origin <= u16::MAX as u32 {
                            g.insert(
                                e.origin as NodeIdentifier,
                                OriginVersion {
                                    boot_epoch: e.boot_epoch,
                                    seq: e.seq,
                                },
                            );
                        }
                    }
                    debug!(?path, count = g.len(), "lsa floor loaded");
                }
                Ok(_) => warn!(?path, "lsa floor: unrecognized version, ignoring"),
                Err(e) => warn!(?path, error=%e, "lsa floor parse error; starting fresh"),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!(?path, error=%e, "lsa floor read error; starting fresh"),
        }
    }

    pub fn get(&self, origin: NodeIdentifier) -> Option<OriginVersion> {
        self.inner.read().get(&origin).copied()
    }

    /// Advance the floor for `origin` to `(boot_epoch, seq)` if strictly
    /// greater. Returns true if changed.
    pub fn advance(&self, origin: NodeIdentifier, boot_epoch: u64, seq: u64) -> bool {
        let mut g = self.inner.write();
        let entry = g.entry(origin).or_insert(OriginVersion {
            boot_epoch: 0,
            seq: 0,
        });
        if is_strictly_newer(boot_epoch, seq, entry.boot_epoch, entry.seq) {
            entry.boot_epoch = boot_epoch;
            entry.seq = seq;
            self.persist_signal.notify_one();
            true
        } else {
            false
        }
    }

    /// Snapshot every entry for the persister.
    fn snapshot(&self) -> Vec<FloorEntryDisk> {
        self.inner
            .read()
            .iter()
            .map(|(origin, v)| FloorEntryDisk {
                origin: *origin as u32,
                boot_epoch: v.boot_epoch,
                seq: v.seq,
            })
            .collect()
    }

    fn write_now(&self) {
        let Some(dir) = &self.persistence_dir else {
            return;
        };
        let path = floor_path(dir);
        let snapshot = self.snapshot();
        let body = FloorFileV1 {
            version: 1,
            floor: snapshot,
        };
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                warn!(?parent, error=%e, "lsa floor: cannot create dir");
                return;
            }
        }
        match serde_json::to_vec_pretty(&body) {
            Ok(bytes) => {
                let tmp = path.with_extension("json.tmp");
                if let Err(e) = std::fs::write(&tmp, &bytes) {
                    warn!(?tmp, error=%e, "lsa floor: write tmp failed");
                    return;
                }
                if let Err(e) = std::fs::rename(&tmp, &path) {
                    warn!(?path, error=%e, "lsa floor: rename failed");
                }
            }
            Err(e) => warn!(error=%e, "lsa floor: serialize failed"),
        }
    }

    /// Subscribe to "floor changed" notifications.
    pub fn signal(&self) -> &Notify {
        &self.persist_signal
    }
}

fn floor_path(dir: &Path) -> PathBuf {
    dir.join("overlay").join("lsa_floor.json")
}

/// In-memory link-state database. Owned by `OverlayInner`.
pub struct LinkStateDb {
    inner: RwLock<HashMap<NodeIdentifier, LsaEntry>>,
    floor: Arc<LsaFloor>,
    change_signal: Notify,
}

impl LinkStateDb {
    pub fn new(floor: Arc<LsaFloor>) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            floor,
            change_signal: Notify::new(),
        }
    }

    pub fn floor(&self) -> &Arc<LsaFloor> {
        &self.floor
    }

    /// Wakes routing recomputer + membership diff watcher.
    pub fn change_signal(&self) -> &Notify {
        &self.change_signal
    }

    /// Try to admit one incoming LSA. Order of checks:
    ///   1. If we have a current LSDB entry, accept iff strictly newer
    ///      than it; otherwise return `Stale`.
    ///   2. If we have no LSDB entry, fall back to the on-disk floor —
    ///      accept iff strictly newer than the floor; otherwise return
    ///      `BelowFloor` (zombie defense after age-out / our restart).
    ///   3. Admission advances the floor in place.
    pub fn admit(&self, lsa: LsaEntry) -> AdmissionResult {
        let origin = lsa.origin;
        {
            let mut g = self.inner.write();
            match g.get(&origin) {
                Some(prev) => {
                    if !is_strictly_newer(lsa.boot_epoch, lsa.seq, prev.boot_epoch, prev.seq) {
                        return AdmissionResult::Stale;
                    }
                }
                None => {
                    // No live entry — defer to the floor.
                    if let Some(fv) = self.floor.get(origin) {
                        if !is_strictly_newer(lsa.boot_epoch, lsa.seq, fv.boot_epoch, fv.seq) {
                            return AdmissionResult::BelowFloor;
                        }
                    }
                }
            }
            // Advance floor under the write lock so any subsequent admit
            // sees the updated value.
            self.floor.advance(origin, lsa.boot_epoch, lsa.seq);
            g.insert(origin, lsa);
        }
        self.change_signal.notify_waiters();
        AdmissionResult::Accepted
    }

    pub fn get(&self, origin: NodeIdentifier) -> Option<LsaEntry> {
        self.inner.read().get(&origin).cloned()
    }

    pub fn snapshot(&self) -> Vec<LsaEntry> {
        let mut out: Vec<LsaEntry> = self.inner.read().values().cloned().collect();
        out.sort_by_key(|e| e.origin);
        out
    }

    /// Compact `(origin, boot_epoch, seq)` digest.
    pub fn digest(&self) -> Vec<(NodeIdentifier, u64, u64)> {
        self.inner
            .read()
            .values()
            .map(|e| (e.origin, e.boot_epoch, e.seq))
            .collect()
    }

    /// Compute LSAs to send to a peer whose digest we just received.
    /// Returns LSAs strictly newer than what the peer has.
    pub fn diff_for(&self, peer_digest: &HashMap<NodeIdentifier, OriginVersion>) -> Vec<LsaEntry> {
        let g = self.inner.read();
        g.values()
            .filter(|e| match peer_digest.get(&e.origin) {
                Some(v) => is_strictly_newer(e.boot_epoch, e.seq, v.boot_epoch, v.seq),
                None => true,
            })
            .cloned()
            .collect()
    }

    /// Sweep entries for age-out. Returns (failed, tombstone_swept).
    /// `failed` = origins whose non-tombstone LSA timed out.
    /// `tombstone_swept` = origins whose tombstone aged out of memory.
    pub fn sweep(
        &self,
        lsa_max_age: Duration,
        tombstone_in_memory_age: Duration,
    ) -> (Vec<NodeIdentifier>, Vec<NodeIdentifier>) {
        let now = Instant::now();
        let mut failed = Vec::new();
        let mut tombstone_swept = Vec::new();
        {
            let mut g = self.inner.write();
            g.retain(|origin, e| {
                let age = now.saturating_duration_since(e.ts_local_received);
                if e.tombstone {
                    if age >= tombstone_in_memory_age {
                        tombstone_swept.push(*origin);
                        return false;
                    }
                } else if age >= lsa_max_age {
                    failed.push(*origin);
                    return false;
                }
                true
            });
        }
        if !failed.is_empty() || !tombstone_swept.is_empty() {
            self.change_signal.notify_waiters();
        }
        (failed, tombstone_swept)
    }

    /// Set of origins with an active (non-tombstone) LSA. Used for
    /// `alive_members()` and membership diffs.
    pub fn active_origins(&self) -> Vec<NodeIdentifier> {
        let mut out: Vec<_> = self
            .inner
            .read()
            .values()
            .filter(|e| !e.tombstone)
            .map(|e| e.origin)
            .collect();
        out.sort();
        out
    }
}

/// Background task: write the floor to disk once per `interval` whenever
/// changes have been signalled. Cancellable via `shutdown`.
pub fn spawn_floor_persister(
    floor: Arc<LsaFloor>,
    interval: Duration,
    shutdown: tokio_util::sync::CancellationToken,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    floor.write_now();
                    return;
                }
                _ = floor.signal().notified() => {}
            }
            tokio::select! {
                _ = shutdown.cancelled() => {
                    floor.write_now();
                    return;
                }
                _ = tokio::time::sleep(interval) => {}
            }
            floor.write_now();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(origin: NodeIdentifier, boot: u64, seq: u64, tombstone: bool) -> LsaEntry {
        LsaEntry {
            origin,
            boot_epoch: boot,
            seq,
            ts_local_received: Instant::now(),
            tombstone,
            addresses: vec![],
            links: vec![],
            max_users: 0,
        }
    }

    #[test]
    fn admit_first_lsa() {
        let floor = Arc::new(LsaFloor::new(None));
        let db = LinkStateDb::new(floor);
        assert_eq!(db.admit(entry(1, 100, 1, false)), AdmissionResult::Accepted);
        assert!(db.get(1).is_some());
    }

    #[test]
    fn lsa_roundtrips_max_users() {
        let mut lsa = entry(1, 100, 1, false);
        lsa.max_users = 250;
        let pb = lsa.to_pb();
        assert_eq!(pb.max_users, 250);
        assert_eq!(LsaEntry::from_pb(&pb).unwrap().max_users, 250);
    }

    #[test]
    fn link_state_db_sums_alive_max_users() {
        let floor = Arc::new(LsaFloor::new(None));
        let db = LinkStateDb::new(floor);
        let mut first = entry(1, 100, 1, false);
        first.max_users = 100;
        let mut second = entry(2, 100, 1, false);
        second.max_users = 200;
        let mut left = entry(3, 100, 1, true);
        left.max_users = 300;
        db.admit(first);
        db.admit(second);
        db.admit(left);
        let total: u64 = db
            .snapshot()
            .into_iter()
            .filter(|entry| !entry.tombstone)
            .map(|entry| entry.max_users)
            .sum();
        assert_eq!(total, 300);
    }

    #[test]
    fn reject_stale_seq() {
        let floor = Arc::new(LsaFloor::new(None));
        let db = LinkStateDb::new(floor);
        db.admit(entry(1, 100, 5, false));
        assert_eq!(db.admit(entry(1, 100, 3, false)), AdmissionResult::Stale);
    }

    #[test]
    fn higher_boot_epoch_supersedes() {
        let floor = Arc::new(LsaFloor::new(None));
        let db = LinkStateDb::new(floor);
        db.admit(entry(1, 100, 10, false));
        assert_eq!(db.admit(entry(1, 200, 0, false)), AdmissionResult::Accepted);
        let got = db.get(1).unwrap();
        assert_eq!(got.boot_epoch, 200);
        assert_eq!(got.seq, 0);
    }

    #[test]
    fn floor_blocks_zombie_after_age_out() {
        let floor = Arc::new(LsaFloor::new(None));
        // Floor has been advanced (e.g., by a tombstone admitted earlier).
        floor.advance(1, 100, 50);
        let db = LinkStateDb::new(floor);
        // LSDB is empty (entry aged out of memory).
        // Inject a stale LSA at same boot_epoch and lower seq.
        assert_eq!(
            db.admit(entry(1, 100, 49, false)),
            AdmissionResult::BelowFloor
        );
        assert!(db.get(1).is_none());
    }

    #[test]
    fn floor_admits_legitimate_restart() {
        let floor = Arc::new(LsaFloor::new(None));
        floor.advance(1, 100, 50);
        let db = LinkStateDb::new(floor);
        // Higher boot_epoch always wins.
        assert_eq!(db.admit(entry(1, 200, 0, false)), AdmissionResult::Accepted);
    }

    #[test]
    fn admit_advances_floor() {
        let floor = Arc::new(LsaFloor::new(None));
        let db = LinkStateDb::new(floor.clone());
        db.admit(entry(1, 100, 5, false));
        let v = floor.get(1).unwrap();
        assert_eq!(v.boot_epoch, 100);
        assert_eq!(v.seq, 5);
    }

    #[test]
    fn sweep_ages_out_non_tombstone() {
        let floor = Arc::new(LsaFloor::new(None));
        let db = LinkStateDb::new(floor);
        db.admit(entry(1, 100, 5, false));
        // Shift ts_local_received back.
        {
            let mut g = db.inner.write();
            let e = g.get_mut(&1).unwrap();
            e.ts_local_received = Instant::now() - Duration::from_secs(60);
        }
        let (failed, _) = db.sweep(Duration::from_secs(30), Duration::from_secs(120));
        assert_eq!(failed, vec![1u16]);
    }

    #[test]
    fn floor_disk_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let f1 = LsaFloor::new(Some(dir.path().to_path_buf()));
        f1.advance(7, 1234, 9);
        f1.advance(8, 5678, 1);
        f1.write_now();
        let f2 = LsaFloor::new(Some(dir.path().to_path_buf()));
        f2.load();
        assert_eq!(f2.get(7).unwrap().boot_epoch, 1234);
        assert_eq!(f2.get(7).unwrap().seq, 9);
        assert_eq!(f2.get(8).unwrap().boot_epoch, 5678);
    }
}
