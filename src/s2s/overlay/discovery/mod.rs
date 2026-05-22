//! Bootstrap and runtime peer-set persistence.
//!
//! At start, [`bootstrap`] primes the L1 transport's address book with
//! the merge of operator-supplied seeds and any persisted peer file.
//! In Phase 2 we no longer pre-install seeds into the membership table —
//! membership is derived from the LSDB, so a peer becomes "Alive" when
//! its LSA arrives, and that arrives once a direct L1 stream is up.
//!
//! The [`spawn_persister`] task debounces LSDB changes and writes the current
//! transport address book back to disk.

pub mod persistence;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::s2s::transport::{ConnectionManager, PeerAddressSnapshot};

use super::config::OverlayConfig;
use super::lsdb::{LinkStateDb, LsaEntry};

/// Run all start-time discovery work: load persisted peers (if any),
/// merge with config seeds, and prime the L1 transport's address book.
pub fn bootstrap(cfg: &OverlayConfig, transport: &ConnectionManager) {
    let mut seeded_from_disk = 0usize;
    if let Some(dir) = cfg.persistence_dir() {
        match persistence::load(dir) {
            Ok(persisted) => {
                seeded_from_disk = persisted.len();
                for peer in persisted {
                    for a in peer.addresses() {
                        let t = transport.clone();
                        let node = peer.node_id();
                        let addr = *a;
                        let last_seen = peer.last_seen().unwrap_or_else(SystemTime::now);
                        tokio::spawn(async move {
                            t.add_address_seen_at(node, addr, last_seen).await;
                        });
                    }
                }
            }
            Err(e) => {
                warn!(error=%e, "failed to load persisted overlay peers; continuing with config seeds only");
            }
        }
    }

    for seed in cfg.seed_peers() {
        for a in seed.addresses() {
            let t = transport.clone();
            let node = seed.node_id();
            let addr = *a;
            tokio::spawn(async move {
                t.add_address(node, addr).await;
            });
        }
    }
    tracing::info!(
        from_disk = seeded_from_disk,
        from_config = cfg.seed_peers().len(),
        "overlay bootstrap"
    );
}

/// Add addresses learned from an accepted non-tombstone LSA into the
/// transport address book. Seeing a fresh LSA also refreshes the peer's
/// last-seen time even if all addresses were already known.
pub fn learn_from_lsa(transport: &ConnectionManager, lsa: &LsaEntry) {
    if lsa.tombstone || lsa.addresses.is_empty() {
        return;
    }
    let seen_at = SystemTime::now();
    for addr in &lsa.addresses {
        let t = transport.clone();
        let addr = *addr;
        let node = lsa.origin;
        tokio::spawn(async move {
            t.add_address_seen_at(node, addr, seen_at).await;
        });
    }
}

/// Spawn the debounced persister. The persister writes the transport address
/// book to disk after accepted LSAs update the LSDB, and once more on
/// shutdown.
pub fn spawn_persister(
    persistence_dir: PathBuf,
    interval: Duration,
    transport: ConnectionManager,
    lsdb: Arc<LinkStateDb>,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    let _ = persist_now(&persistence_dir, &transport);
                    return;
                }
                _ = lsdb.change_signal().notified() => {}
            }
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = sleep(interval) => {}
            }
            if let Err(e) = persist_now(&persistence_dir, &transport) {
                warn!(error=%e, "overlay persistence write failed");
            }
        }
    });
}

fn persist_now(
    persistence_dir: &std::path::Path,
    transport: &ConnectionManager,
) -> Result<(), super::error::OverlayError> {
    let peers: Vec<_> = transport
        .peer_address_snapshot()
        .into_iter()
        .map(peer_record_from_snapshot)
        .collect();
    persistence::save(persistence_dir, &peers)
}

fn peer_record_from_snapshot(snapshot: PeerAddressSnapshot) -> persistence::PersistedPeerRecord {
    persistence::PersistedPeerRecord::new(
        snapshot.node_id(),
        snapshot.addresses().to_vec(),
        snapshot.last_seen(),
    )
}
