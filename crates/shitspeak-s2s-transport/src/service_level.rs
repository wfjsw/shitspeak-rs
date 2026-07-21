use std::net::SocketAddr;

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
    pub const ALL: [Self; 3] = [Self::Reliable, Self::ReliableLowLatency, Self::BestEffort];

    /// True when a transport providing `self` can satisfy a `requested` level.
    #[inline]
    pub fn satisfies(self, requested: ServiceLevel) -> bool {
        (self as u8) <= (requested as u8)
    }
}

/// Route-selection metric used in addition to [`ServiceLevel`].
///
/// Each default service-level policy has its own metric identity. Upper layers
/// can request a different metric when the payload has different quality needs,
/// for example conversational voice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum RoutingMetric {
    #[default]
    ReliableCost,
    ReliableLowLatencyCost,
    BestEffortCost,
    ConversationalQuality,
}

impl RoutingMetric {
    pub const ALL: [Self; 4] = [
        Self::ReliableCost,
        Self::ReliableLowLatencyCost,
        Self::BestEffortCost,
        Self::ConversationalQuality,
    ];

    pub fn default_for_level(level: ServiceLevel) -> Self {
        match level {
            ServiceLevel::Reliable => Self::ReliableCost,
            ServiceLevel::ReliableLowLatency => Self::ReliableLowLatencyCost,
            ServiceLevel::BestEffort => Self::BestEffortCost,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::ReliableCost => "reliable",
            Self::ReliableLowLatencyCost => "reliable_low_latency",
            Self::BestEffortCost => "best_effort",
            Self::ConversationalQuality => "conversational",
        }
    }
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

/// Logical delivery path selected within a physical transport.
///
/// QUIC DATAGRAM and QUIC streams intentionally remain distinct here even
/// though both use [`TransportKind::Quic`]. This gives routing and
/// observability the correct blocking/reliability semantics without inventing
/// a second QUIC endpoint or link metric identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DeliveryPath {
    UdpDatagram,
    QuicDatagram,
    TcpStream,
    KcpStream,
    QuicStream,
}

impl DeliveryPath {
    pub const ALL: [Self; 5] = [
        Self::UdpDatagram,
        Self::QuicDatagram,
        Self::TcpStream,
        Self::KcpStream,
        Self::QuicStream,
    ];

    pub fn stream(transport: TransportKind) -> Option<Self> {
        match transport {
            TransportKind::Tcp => Some(Self::TcpStream),
            TransportKind::Kcp => Some(Self::KcpStream),
            TransportKind::Quic => Some(Self::QuicStream),
            TransportKind::Udp => None,
        }
    }

    pub fn transport(self) -> TransportKind {
        match self {
            Self::UdpDatagram => TransportKind::Udp,
            Self::QuicDatagram | Self::QuicStream => TransportKind::Quic,
            Self::TcpStream => TransportKind::Tcp,
            Self::KcpStream => TransportKind::Kcp,
        }
    }

    pub fn is_datagram(self) -> bool {
        matches!(self, Self::UdpDatagram | Self::QuicDatagram)
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::UdpDatagram => "udp_datagram",
            Self::QuicDatagram => "quic_datagram",
            Self::TcpStream => "tcp_stream",
            Self::KcpStream => "kcp_stream",
            Self::QuicStream => "quic_stream",
        }
    }
}

/// Receiver-side routing class. Picked by the sender; carried in the frame
/// header so the receiver can fan inbound traffic into control, high-priority,
/// or regular queues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageClass {
    Control,
    HighPriority,
    Regular,
}

/// Application traffic shape used by topology reporting. These are workload
/// shapes, not new reliability tiers.
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

/// A configured seed address. Unlike [`PeerAddress`], this keeps hostname
/// seeds unresolved so DNS failures can use the normal seed retry path instead
/// of preventing startup.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SeedAddress {
    addr: String,
    transport: TransportKind,
}

impl SeedAddress {
    pub fn new(addr: impl Into<String>, transport: TransportKind) -> Self {
        Self {
            addr: addr.into(),
            transport,
        }
    }

    pub fn from_peer_address(addr: PeerAddress) -> Self {
        Self::new(addr.addr().to_string(), addr.transport())
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    pub fn transport(&self) -> TransportKind {
        self.transport
    }

    pub fn as_static_peer_address(&self) -> Option<PeerAddress> {
        self.addr
            .parse::<SocketAddr>()
            .ok()
            .map(|addr| PeerAddress::new(addr, self.transport))
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
