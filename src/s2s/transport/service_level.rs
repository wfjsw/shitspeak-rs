use std::net::SocketAddr;

use crate::types::NodeIdentifier;

/// Reliability tier requested by the caller (or provided by a transport).
///
/// Numerically lower = stronger guarantees. KCP/QUIC are reliable *and*
/// low-latency, so `ReliableLowLatency` ranks above plain `Reliable` (TCP).
/// A transport whose level value is `<=` the requested level satisfies the
/// request, so `ReliableLowLatency` can serve a `Reliable` send (and either
/// can serve `BestEffort`) when nothing exact is up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum ServiceLevel {
    ReliableLowLatency = 0,
    Reliable = 1,
    BestEffort = 2,
}

impl ServiceLevel {
    /// True when a transport providing `self` can satisfy a `requested` level.
    #[inline]
    pub fn satisfies(self, requested: ServiceLevel) -> bool {
        (self as u8) <= (requested as u8)
    }
}

/// Route-selection metric used in addition to [`ServiceLevel`].
///
/// The default preserves the per-service cost formulas. Upper layers can
/// request a different metric when the payload has different quality needs,
/// for example conversational voice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum RoutingMetric {
    #[default]
    PerServiceCost,
    ConversationalQuality,
}

/// Wire transport flavor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TransportKind {
    Tcp,
    Kcp,
    Quic,
    Udp,
}

impl TransportKind {
    #[inline]
    pub fn service_level(self) -> ServiceLevel {
        match self {
            TransportKind::Tcp => ServiceLevel::Reliable,
            TransportKind::Kcp | TransportKind::Quic => ServiceLevel::ReliableLowLatency,
            TransportKind::Udp => ServiceLevel::BestEffort,
        }
    }

    /// True for transports that carry a TLS-authenticated bidirectional stream.
    #[inline]
    pub fn is_stream(self) -> bool {
        matches!(
            self,
            TransportKind::Tcp | TransportKind::Kcp | TransportKind::Quic
        )
    }

    /// True when this transport is acceptable for a send at `requested`.
    ///
    /// This mirrors overlay routing fallback: best-effort traffic may ride
    /// any live transport, reliable traffic never rides UDP, and
    /// reliable-low-latency traffic can fall back to TCP when needed.
    #[inline]
    pub fn is_acceptable_for(self, requested: ServiceLevel) -> bool {
        match requested {
            ServiceLevel::BestEffort => true,
            ServiceLevel::Reliable | ServiceLevel::ReliableLowLatency => {
                self.service_level() != ServiceLevel::BestEffort
            }
        }
    }
}

/// Receiver-side routing class. Picked by the sender; carried in the frame
/// header so the receiver can fan inbound traffic into one of two queues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageClass {
    HighPriority,
    Regular,
}

/// Application traffic shape used by active transport probes and topology
/// reporting. These are workload shapes, not new reliability tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ServiceShape {
    Voice,
    Control,
    Bulk,
}

impl ServiceShape {
    pub const ALL: [Self; 3] = [Self::Voice, Self::Control, Self::Bulk];

    pub fn name(self) -> &'static str {
        match self {
            Self::Voice => "voice",
            Self::Control => "control",
            Self::Bulk => "bulk",
        }
    }

    pub fn service_level(self) -> ServiceLevel {
        match self {
            Self::Voice => ServiceLevel::BestEffort,
            Self::Control => ServiceLevel::ReliableLowLatency,
            Self::Bulk => ServiceLevel::Reliable,
        }
    }

    pub fn message_class(self) -> MessageClass {
        match self {
            Self::Voice | Self::Control => MessageClass::HighPriority,
            Self::Bulk => MessageClass::Regular,
        }
    }

    pub fn probe_payload_bytes(self, bulk_payload_bytes: usize) -> usize {
        if bulk_payload_bytes == 0 {
            return 0;
        }
        match self {
            Self::Voice => 160.min(bulk_payload_bytes),
            Self::Control => 1024.min(bulk_payload_bytes),
            Self::Bulk => bulk_payload_bytes,
        }
    }
}

/// A peer address bound to a specific transport flavor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerAddress {
    addr: SocketAddr,
    transport: TransportKind,
}

impl PeerAddress {
    pub fn new(addr: SocketAddr, transport: TransportKind) -> Self {
        Self { addr, transport }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn transport(&self) -> TransportKind {
        self.transport
    }

    pub fn is_dialable(&self) -> bool {
        !self.addr.ip().is_unspecified()
    }
}

/// Lookup convenience: who is asking? Used by the supervisor when iterating
/// peers waiting on a reconnect attempt.
#[derive(Debug, Clone, Copy)]
pub struct PeerKey(NodeIdentifier);

impl PeerKey {
    pub fn new(node_id: NodeIdentifier) -> Self {
        Self(node_id)
    }

    pub fn node_id(&self) -> NodeIdentifier {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn satisfies_matrix() {
        use ServiceLevel::*;
        let levels = [Reliable, ReliableLowLatency, BestEffort];
        for &provider in &levels {
            for &requested in &levels {
                let expected = (provider as u8) <= (requested as u8);
                assert_eq!(provider.satisfies(requested), expected);
            }
        }
        // Spot check: ReliableLowLatency (KCP/QUIC) is strongest and can
        // serve any request; Reliable (TCP) can serve itself or weaker;
        // BestEffort can only serve BestEffort.
        assert!(ReliableLowLatency.satisfies(Reliable));
        assert!(ReliableLowLatency.satisfies(BestEffort));
        assert!(Reliable.satisfies(BestEffort));
        assert!(!Reliable.satisfies(ReliableLowLatency));
        assert!(!BestEffort.satisfies(Reliable));
        assert!(!BestEffort.satisfies(ReliableLowLatency));
    }

    #[test]
    fn transport_levels() {
        assert_eq!(TransportKind::Tcp.service_level(), ServiceLevel::Reliable);
        assert_eq!(
            TransportKind::Kcp.service_level(),
            ServiceLevel::ReliableLowLatency
        );
        assert_eq!(
            TransportKind::Quic.service_level(),
            ServiceLevel::ReliableLowLatency
        );
        assert_eq!(TransportKind::Udp.service_level(), ServiceLevel::BestEffort);
    }
}
