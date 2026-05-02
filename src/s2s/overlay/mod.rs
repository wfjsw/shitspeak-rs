//! Layer-2 overlay network for S2S traffic.
//!
//! Sits on top of the L1 [`crate::s2s::transport::ConnectionManager`] and
//! provides cluster-level services to higher layers: discovery, SWIM
//! membership, and (in later phases) routing + multicast + in-order
//! streams.
//!
//! ## Phase status
//!
//! This is **Phase 1** of the overlay rebuild and ships:
//!   * Wire format and module skeleton.
//!   * SWIM membership with ping/ack/ping-req, suspicion timeout, refute,
//!     graceful leave on shutdown, and gossip piggyback.
//!   * Discovery from operator-supplied seeds and from a persisted
//!     `peers.json` next to the project's blob storage.
//!
//! Phase 2 will add unicast/multicast/broadcast routing and a link-state
//! protocol; Phase 3 will add source-seq + reorder buffer streams.

mod config;
mod discovery;
mod error;
mod inbound;
pub mod membership;
mod proto;
mod runtime;

#[cfg(test)]
mod integration_tests;

use std::sync::Arc;

use tokio::sync::broadcast;

use crate::s2s::transport::{ConnectionManager, Inbound};
use crate::types::NodeIdentifier;

pub use config::{OverlayConfig, SeedPeer};
pub use error::OverlayError;
pub use membership::{MemberSnapshot, MemberStatus, MembershipEvent};

/// Public handle for the overlay network. Cheap to clone — internally a
/// shared `Arc`.
#[derive(Clone)]
pub struct OverlayNetwork {
    inner: Arc<runtime::OverlayInner>,
}

impl OverlayNetwork {
    /// Bring up the overlay over an already-started transport. Spawns SWIM,
    /// gossip, persistence, and inbound dispatcher tasks; runs discovery
    /// bootstrap (seed addresses + persisted file) before returning.
    pub async fn start(
        transport: ConnectionManager,
        inbound: Inbound,
        cfg: OverlayConfig,
    ) -> Result<Self, OverlayError> {
        let inner = runtime::start_inner(transport, inbound, cfg).await?;
        Ok(Self { inner })
    }

    /// Local node id derived from the transport's TLS cert CN.
    pub fn local_node_id(&self) -> NodeIdentifier {
        self.inner.self_id
    }

    /// Snapshot of the current membership table, sorted by node id.
    pub fn members(&self) -> Vec<MemberSnapshot> {
        self.inner.table.snapshot()
    }

    /// Look up one peer.
    pub fn member(&self, node: NodeIdentifier) -> Option<MemberSnapshot> {
        self.inner.table.snapshot_one(node)
    }

    /// Subscribe to the membership-event stream. Each subscriber receives
    /// every event independently.
    pub fn subscribe_membership(&self) -> broadcast::Receiver<MembershipEvent> {
        self.inner.table.subscribe()
    }

    /// Announce graceful leave to all alive peers, then cancel internal
    /// tasks. Future operations on this handle are no-ops.
    pub async fn shutdown(&self) {
        self.inner.shutdown_graceful().await;
    }
}
