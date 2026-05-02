use std::path::PathBuf;
use std::time::Duration;

use crate::s2s::transport::PeerAddress;
use crate::types::NodeIdentifier;

/// Knobs for [`super::OverlayNetwork::start`].
#[derive(Debug, Clone)]
pub struct OverlayConfig {
    seed_peers: Vec<SeedPeer>,
    persistence_dir: Option<PathBuf>,
    swim_ping_interval: Duration,
    swim_indirect_ping_count: usize,
    swim_suspicion_timeout: Duration,
    swim_dead_timeout: Duration,
    gossip_piggyback_max: usize,
    peer_persistence_interval: Duration,
}

impl OverlayConfig {
    pub fn new(seed_peers: Vec<SeedPeer>) -> Self {
        Self {
            seed_peers,
            persistence_dir: None,
            swim_ping_interval: Duration::from_secs(1),
            swim_indirect_ping_count: 3,
            swim_suspicion_timeout: Duration::from_secs(5),
            swim_dead_timeout: Duration::from_secs(30),
            gossip_piggyback_max: 8,
            peer_persistence_interval: Duration::from_secs(30),
        }
    }

    // ── Getters ──

    pub fn seed_peers(&self) -> &[SeedPeer] {
        &self.seed_peers
    }

    pub fn persistence_dir(&self) -> Option<&PathBuf> {
        self.persistence_dir.as_ref()
    }

    pub fn swim_ping_interval(&self) -> Duration {
        self.swim_ping_interval
    }

    pub fn swim_indirect_ping_count(&self) -> usize {
        self.swim_indirect_ping_count
    }

    pub fn swim_suspicion_timeout(&self) -> Duration {
        self.swim_suspicion_timeout
    }

    pub fn swim_dead_timeout(&self) -> Duration {
        self.swim_dead_timeout
    }

    pub fn gossip_piggyback_max(&self) -> usize {
        self.gossip_piggyback_max
    }

    pub fn peer_persistence_interval(&self) -> Duration {
        self.peer_persistence_interval
    }

    // ── Builder setters ──

    pub fn with_persistence_dir(mut self, dir: PathBuf) -> Self {
        self.persistence_dir = Some(dir);
        self
    }

    pub fn with_swim_ping_interval(mut self, d: Duration) -> Self {
        self.swim_ping_interval = d;
        self
    }

    pub fn with_swim_indirect_ping_count(mut self, n: usize) -> Self {
        self.swim_indirect_ping_count = n;
        self
    }

    pub fn with_swim_suspicion_timeout(mut self, d: Duration) -> Self {
        self.swim_suspicion_timeout = d;
        self
    }

    pub fn with_swim_dead_timeout(mut self, d: Duration) -> Self {
        self.swim_dead_timeout = d;
        self
    }

    pub fn with_gossip_piggyback_max(mut self, n: usize) -> Self {
        self.gossip_piggyback_max = n;
        self
    }

    pub fn with_peer_persistence_interval(mut self, d: Duration) -> Self {
        self.peer_persistence_interval = d;
        self
    }
}

/// Bootstrap peer entry from operator config. The node id is required so the
/// local node can call `transport.add_address(id, addr)` directly without
/// waiting for a TLS handshake to disclose the peer's CN.
#[derive(Debug, Clone)]
pub struct SeedPeer {
    node_id: NodeIdentifier,
    addresses: Vec<PeerAddress>,
}

impl SeedPeer {
    pub fn new(node_id: NodeIdentifier, addresses: Vec<PeerAddress>) -> Self {
        Self { node_id, addresses }
    }

    pub fn node_id(&self) -> NodeIdentifier {
        self.node_id
    }

    pub fn addresses(&self) -> &[PeerAddress] {
        &self.addresses
    }
}
