//! Cluster builder — N transport+overlay nodes wired together with
//! optional [`LinkChaos`](super::chaos::LinkChaos) on each node's inbound
//! path.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::sync::{OwnedMutexGuard, mpsc};

use super::chaos::LinkChaos;
use crate::overlay::OverlayNetwork;
use crate::overlay::config::{OverlayConfig, SeedPeer};
use crate::overlay::messaging::{OverlayInboundMessage, ServiceInbound};
use shitspeak_s2s_transport::testing::{
    Pki, install_provider_once, loopback, mint_pki, pick_free_port, s2s_network_test_guard,
};
use shitspeak_s2s_transport::{
    AdaptiveInboundReceiver, ConnectionManager, PeerAddress, TransportConfig, TransportKind,
};

/// Build a `TransportConfig` for the test cluster: TCP-only, short
/// reconnect/backoff windows, no bandwidth probing.
pub fn transport_cfg(pki: &Pki, node_idx: usize, tcp: SocketAddr) -> TransportConfig {
    let (cert, key) = &pki.nodes[node_idx];
    TransportConfig::new(pki.ca_path.clone(), cert.clone(), key.clone())
        .with_tcp_listen(tcp)
        .with_reconnect_check_interval(Duration::from_millis(100))
        .with_backoff_initial(Duration::from_millis(50))
        .with_backoff_cap(Duration::from_millis(500))
        .with_ping_interval(Duration::from_secs(10))
        .with_bandwidth_probe_size(0)
}

/// Build an `OverlayConfig` tuned for fast test convergence.
pub fn overlay_cfg(seeds: Vec<SeedPeer>) -> OverlayConfig {
    OverlayConfig::new(seeds)
        .with_hello_interval(Duration::from_millis(200))
        .with_hello_dead_interval(Duration::from_millis(800))
        .with_lsa_refresh_interval(Duration::from_millis(500))
        .with_lsa_max_age(Duration::from_secs(5))
        .with_lsa_unchanged_refresh_interval(Duration::from_secs(1))
        .with_lsa_flood_pacing_interval(Duration::from_millis(25))
        .with_tombstone_in_memory_age(Duration::from_secs(10))
        .with_anti_entropy_interval(Duration::from_millis(500))
        .with_routing_recompute_debounce(Duration::from_millis(20))
        .with_peer_persistence_interval(Duration::from_secs(1))
}

/// One node in an integration-test cluster.
pub struct Node {
    pub id: u16,
    pub port: u16,
    pub transport: ConnectionManager,
    pub overlay: OverlayNetwork,
    pub chaos: LinkChaos,
}

impl Node {
    pub async fn shutdown(&self) {
        self.overlay.shutdown().await;
        self.transport.shutdown().await;
    }

    /// Cancel one live peer transport. The transport supervisor may reconnect
    /// it normally, which lets tests model a link flap without rebuilding the
    /// cluster.
    pub fn disconnect_transport(&self, peer: u16, kind: TransportKind) -> bool {
        self.transport.test_drop_transport_kind(peer, kind)
    }

    pub fn transport_is_up(&self, peer: u16, kind: TransportKind) -> bool {
        self.transport.has_live_transport_kind(peer, kind)
    }
}

/// Cluster: N nodes with PKI, ports, transports, and overlays. Each node
/// has its own [`LinkChaos`] installed on its inbound path so tests can
/// model partitions, latency, asymmetric reachability, etc.
pub struct Cluster {
    pub pki: Pki,
    pub nodes: Vec<Node>,
    _guard: OwnedMutexGuard<()>,
}

impl Cluster {
    /// Build a cluster of `node_ids.len()` nodes. `seeds_for(idx, ids,
    /// ports)` returns the list of peers to seed for node `idx`. The
    /// node's own port is not known until it's allocated, so seeds are
    /// built against the cluster's pre-allocated ports passed in.
    pub async fn build<F>(node_ids: &[u16], seeds_for: F) -> Self
    where
        F: Fn(usize, &[u16], &[u16]) -> Vec<SeedPeer>,
    {
        Self::build_with_cfg(node_ids, seeds_for, |_idx, base| base).await
    }

    /// Like [`build`](Self::build) but allows the caller to mutate the
    /// per-node `OverlayConfig` (e.g., to shorten anti-entropy interval
    /// for a specific scenario).
    pub async fn build_with_cfg<F, G>(node_ids: &[u16], seeds_for: F, cfg_for: G) -> Self
    where
        F: Fn(usize, &[u16], &[u16]) -> Vec<SeedPeer>,
        G: Fn(usize, OverlayConfig) -> OverlayConfig,
    {
        let guard = s2s_network_test_guard().await;

        install_provider_once();
        let pki = mint_pki(node_ids);

        let mut ports = Vec::with_capacity(node_ids.len());
        for _ in node_ids {
            ports.push(pick_free_port().await);
        }

        let mut transports = Vec::with_capacity(node_ids.len());
        for (idx, &id) in node_ids.iter().enumerate() {
            let port = ports[idx];
            let chaos = LinkChaos::new();
            let t_cfg = transport_cfg(&pki, idx, loopback(port));
            let (transport, raw_inbound) = ConnectionManager::start(t_cfg).await.unwrap();
            transports.push((idx, id, port, chaos, transport, raw_inbound));
        }

        let mut nodes = Vec::with_capacity(node_ids.len());
        for (idx, id, port, chaos, transport, raw_inbound) in transports {
            let seeds = seeds_for(idx, node_ids, &ports);
            let inbound = chaos.install(raw_inbound);
            let o_cfg = cfg_for(idx, overlay_cfg(seeds));
            let overlay = OverlayNetwork::start(transport.clone(), inbound, o_cfg)
                .await
                .unwrap();
            nodes.push(Node {
                id,
                port,
                transport,
                overlay,
                chaos,
            });
        }
        Self {
            pki,
            nodes,
            _guard: guard,
        }
    }

    pub fn node(&self, id: u16) -> &Node {
        self.nodes.iter().find(|n| n.id == id).expect("node id")
    }

    pub fn ids(&self) -> Vec<u16> {
        self.nodes.iter().map(|n| n.id).collect()
    }

    /// Convenience: build a peer-address record for node `id`.
    pub fn seed(&self, id: u16) -> SeedPeer {
        let n = self.node(id);
        SeedPeer::new(
            id,
            vec![PeerAddress::new(loopback(n.port), TransportKind::Tcp)],
        )
    }

    /// Symmetrically partition the cluster: every node in `left` blocks
    /// inbound from every node in `right`, and vice versa. Existing block
    /// rules are preserved.
    pub fn partition(&self, left: &[u16], right: &[u16]) {
        for &l in left {
            let n = self.node(l);
            for &r in right {
                n.chaos.block(r);
            }
        }
        for &r in right {
            let n = self.node(r);
            for &l in left {
                n.chaos.block(l);
            }
        }
    }

    /// Reverse of `partition`.
    pub fn heal_partition(&self, left: &[u16], right: &[u16]) {
        for &l in left {
            let n = self.node(l);
            for &r in right {
                n.chaos.unblock(r);
            }
        }
        for &r in right {
            let n = self.node(r);
            for &l in left {
                n.chaos.unblock(l);
            }
        }
    }

    pub async fn shutdown_all(&self) {
        for n in &self.nodes {
            n.shutdown().await;
        }
    }
}

/// Helper: shape the seeds into a full mesh (every node seeded with
/// every other).
pub fn full_mesh_seeds(self_idx: usize, ids: &[u16], ports: &[u16]) -> Vec<SeedPeer> {
    ids.iter()
        .zip(ports.iter())
        .enumerate()
        .filter(|(i, _)| *i != self_idx)
        .map(|(_, (&id, &port))| {
            SeedPeer::new(
                id,
                vec![PeerAddress::new(loopback(port), TransportKind::Tcp)],
            )
        })
        .collect()
}

/// Linear seeds: node `i` seeds node `i-1` and `i+1` (where present).
pub fn line_seeds(self_idx: usize, ids: &[u16], ports: &[u16]) -> Vec<SeedPeer> {
    let mut out = Vec::new();
    if self_idx > 0 {
        out.push(SeedPeer::new(
            ids[self_idx - 1],
            vec![PeerAddress::new(
                loopback(ports[self_idx - 1]),
                TransportKind::Tcp,
            )],
        ));
    }
    if self_idx + 1 < ids.len() {
        out.push(SeedPeer::new(
            ids[self_idx + 1],
            vec![PeerAddress::new(
                loopback(ports[self_idx + 1]),
                TransportKind::Tcp,
            )],
        ));
    }
    out
}

/// Test handler that pushes received messages onto an mpsc.
pub struct Capture(pub mpsc::Sender<OverlayInboundMessage>);
impl ServiceInbound for Capture {
    fn handle(&self, msg: OverlayInboundMessage) {
        let _ = self.0.try_send(msg);
    }
}

/// Re-export so callers can construct `InboundMessage`-aware closures.
pub type InboundMpsc = AdaptiveInboundReceiver;
