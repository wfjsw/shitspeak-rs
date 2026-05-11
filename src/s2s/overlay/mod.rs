//! Layer-2 overlay network for S2S traffic.
//!
//! Sits on top of the L1 [`crate::s2s::transport::ConnectionManager`]
//! and provides cluster-level services to higher layers: discovery,
//! LSDB-derived membership, multi-hop routing across three service
//! levels, and an `OverlayData` envelope for L3 services.
//!
//! ## Architecture (Phase 2)
//!
//! Direct neighbors are discovered via the `Hello/HelloAck` protocol
//! (see [`neighbor`]). Each node publishes a Link-State Advertisement
//! (LSA) on triggered + periodic events; LSAs flood to direct neighbors
//! and feed the local [`lsdb::LinkStateDb`]. The LSDB is the single
//! source of truth for both routing (per-service-level Dijkstra) and
//! membership (alive iff non-tombstone LSA is current).
//!
//! ## Public API
//!
//! The overlay's send path is exposed via [`OverlayNetwork::send_unicast`],
//! [`send_multicast`](OverlayNetwork::send_multicast), and
//! [`send_broadcast`](OverlayNetwork::send_broadcast). L3 services
//! register a [`messaging::ServiceInbound`] handler keyed by a
//! `service_tag` (replications uses `tag = 1`).

pub(crate) mod config;
mod discovery;
mod error;
mod inbound;
pub mod lsdb;
pub mod membership;
pub mod messaging;
pub mod neighbor;
pub(crate) mod proto;
pub mod routing;
mod runtime;

#[cfg(test)]
mod integration_tests;

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::broadcast;

use crate::s2s::transport::{ConnectionManager, Inbound, MessageClass, ServiceLevel};
use crate::types::NodeIdentifier;

pub use config::{OverlayConfig, OverlayTuning, SeedPeer, TransportMask};
pub use error::OverlayError;
pub use membership::{MemberSnapshot, MemberStatus, MembershipEvent};
pub use messaging::{OverlayInboundMessage, ServiceInbound};
pub use routing::RouteEntry;

/// Public handle for the overlay network. Cheap to clone — internally a
/// shared `Arc`.
#[derive(Clone)]
pub struct OverlayNetwork {
    inner: Arc<runtime::OverlayInner>,
}

impl OverlayNetwork {
    /// Bring up the overlay over an already-started transport. Spawns
    /// all long-running tasks (Hello protocol, LSA emitter, anti-entropy,
    /// routing recomputer, diff watcher, inbound dispatcher); runs
    /// discovery bootstrap (seed addresses + persisted file) before
    /// returning.
    pub async fn start(
        transport: ConnectionManager,
        inbound: Inbound,
        cfg: OverlayConfig,
    ) -> Result<Self, OverlayError> {
        Self::start_with_max_users(transport, inbound, cfg, Arc::new(AtomicU64::new(0))).await
    }

    /// Bring up the overlay with local server capacity advertised in this
    /// node's LSA.
    pub async fn start_with_max_users(
        transport: ConnectionManager,
        inbound: Inbound,
        cfg: OverlayConfig,
        max_users: Arc<AtomicU64>,
    ) -> Result<Self, OverlayError> {
        let inner = runtime::start_inner(transport, inbound, cfg, max_users).await?;
        Ok(Self { inner })
    }

    /// Local node id derived from the transport's TLS cert CN.
    pub fn local_node_id(&self) -> NodeIdentifier {
        self.inner.self_id
    }

    /// Local node's `boot_epoch` (microseconds since UNIX epoch, captured
    /// once at overlay start). Stable until the process restarts.
    pub fn local_boot_epoch(&self) -> u64 {
        self.inner.boot_epoch
    }

    /// Snapshot of every directed-edge RTT currently advertised in the
    /// LSDB. Zero values (uninitialized links) are filtered out.
    /// Tombstoned origins' edges are excluded so a recently-departed peer
    /// can't skew the distribution.
    ///
    /// Used by L3 (replications) to scale the strict-mode clock-tick
    /// cadence to the cluster's measured network latency.
    pub fn edge_rtt_snapshot(&self) -> Vec<std::time::Duration> {
        let mut out = Vec::new();
        for entry in self.inner.lsdb.snapshot() {
            if entry.tombstone {
                continue;
            }
            for link in entry.links {
                if link.rtt_us > 0 {
                    out.push(std::time::Duration::from_micros(link.rtt_us));
                }
            }
        }
        out
    }

    /// Snapshot of the current membership view, sorted by node id.
    pub fn members(&self) -> Vec<MemberSnapshot> {
        self.inner.table.snapshot()
    }

    /// Look up one peer.
    pub fn member(&self, node: NodeIdentifier) -> Option<MemberSnapshot> {
        self.inner.table.snapshot_one(node)
    }

    /// IDs of every origin with a current non-tombstone LSA.
    pub fn alive_members(&self) -> Vec<NodeIdentifier> {
        self.inner.table.alive_members()
    }

    /// Sum local max_users advertised by alive cluster members.
    pub fn alive_max_users(&self) -> u64 {
        self.inner.table.alive_max_users()
    }

    /// Publish a changed local max_users value in the next local LSA.
    pub fn update_local_max_users(&self, max_users: u64) {
        self.inner
            .emitter
            .max_users
            .store(max_users, std::sync::atomic::Ordering::Relaxed);
        self.inner.emitter.poke_force();
    }

    /// Subscribe to the membership-event stream. Each subscriber receives
    /// every event independently.
    pub fn subscribe_membership(&self) -> broadcast::Receiver<MembershipEvent> {
        self.inner.table.subscribe()
    }

    /// Register an L3 service handler for `tag`. The handler is invoked
    /// synchronously on the inbound dispatcher when an `OverlayData`
    /// frame with that tag arrives addressed to (or transiting through)
    /// this node and destined locally.
    pub fn register_service(&self, tag: u32, handler: Arc<dyn ServiceInbound>) {
        self.inner.services.register(tag, handler);
    }

    pub fn unregister_service(&self, tag: u32) {
        self.inner.services.unregister(tag);
    }

    /// Send to a single peer using per-service-level routing.
    pub async fn send_unicast(
        &self,
        dst: NodeIdentifier,
        tag: u32,
        level: ServiceLevel,
        class: MessageClass,
        body: Bytes,
    ) -> Result<(), OverlayError> {
        messaging::send_unicast(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            dst,
            tag,
            level,
            class,
            body,
        )
        .await
    }

    /// Send to a list of peers — fanned out per next-hop.
    pub async fn send_multicast(
        &self,
        dsts: &[NodeIdentifier],
        tag: u32,
        level: ServiceLevel,
        class: MessageClass,
        body: Bytes,
    ) -> Result<(), OverlayError> {
        messaging::send_multicast(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            dsts,
            tag,
            level,
            class,
            body,
        )
        .await
    }

    /// Send to every alive peer.
    pub async fn send_broadcast(
        &self,
        tag: u32,
        level: ServiceLevel,
        class: MessageClass,
        body: Bytes,
    ) -> Result<(), OverlayError> {
        let alive = self.alive_members();
        messaging::send_broadcast(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            &alive,
            tag,
            level,
            class,
            body,
        )
        .await
    }

    /// Look up the next-hop for `dst` at `level`. Returns `None` if no
    /// route is known.
    pub fn route_to(&self, dst: NodeIdentifier, level: ServiceLevel) -> Option<NodeIdentifier> {
        self.inner
            .routing
            .load()
            .lookup(dst, level)
            .map(|e| e.next_hop)
    }

    /// Announce graceful leave (tombstone LSA flood) to every direct
    /// neighbor, then cancel internal tasks.
    pub async fn shutdown(&self) {
        self.inner.shutdown_graceful().await;
    }
}
