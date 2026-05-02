//! Bootstrap and runtime peer-set persistence.
//!
//! At start, [`bootstrap`] populates the local membership table with the
//! merge of operator-supplied seeds and any persisted peer file. The
//! [`spawn_persister`] task periodically (and at most once per
//! `peer_persistence_interval`) writes the current peer set back to disk.

pub mod persistence;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::s2s::transport::ConnectionManager;

use super::config::OverlayConfig;
use super::membership::MembershipTable;

/// Run all start-time discovery work: load persisted peers (if any),
/// merge with config seeds, install into membership table, and prime the
/// transport's address book.
pub fn bootstrap(
    cfg: &OverlayConfig,
    table: &MembershipTable,
    transport: &ConnectionManager,
) {
    let mut seeded_from_disk = 0usize;
    if let Some(dir) = cfg.persistence_dir() {
        match persistence::load(dir) {
            Ok(persisted) => {
                seeded_from_disk = persisted.len();
                for (node, addrs) in persisted {
                    table.install_seed(node, addrs.clone());
                    for a in addrs {
                        let t = transport.clone();
                        tokio::spawn(async move {
                            t.add_address(node, a).await;
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
        table.install_seed(seed.node_id(), seed.addresses().to_vec());
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

/// Spawn the debounced persister. Calls to [`PersistTrigger::ping`] schedule
/// a write that runs at most once per `peer_persistence_interval`.
pub fn spawn_persister(
    persistence_dir: PathBuf,
    interval: Duration,
    table: Arc<MembershipTable>,
    trigger: Arc<Notify>,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    let _ = persist_now(&persistence_dir, &table);
                    return;
                }
                _ = trigger.notified() => {}
            }
            // Debounce: wait `interval` before writing, but if more triggers
            // pile up during the wait, collapse them into one write.
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = sleep(interval) => {}
            }
            if let Err(e) = persist_now(&persistence_dir, &table) {
                warn!(error=%e, "overlay persistence write failed");
            }
        }
    });
}

fn persist_now(
    persistence_dir: &std::path::Path,
    table: &MembershipTable,
) -> Result<(), super::error::OverlayError> {
    let snapshot = table.snapshot();
    let peers: Vec<_> = snapshot
        .into_iter()
        .filter(|m| m.status().is_reachable())
        .map(|m| (m.node_id(), m.addresses().to_vec()))
        .collect();
    persistence::save(persistence_dir, &peers)
}

/// Notify handle that the membership table has changed and should be
/// rewritten to disk on the next debounce window.
pub type PersistTrigger = Arc<Notify>;
