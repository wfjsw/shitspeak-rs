use serde::{Deserialize, Serialize};

use super::routing::RouteClass;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TransportKind {
    Quic,
    TlsTcp,
    Udp,
    Kcp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportCapabilities {
    pub supported: Vec<TransportKind>,
}

impl Default for TransportCapabilities {
    fn default() -> Self {
        Self {
            supported: vec![TransportKind::Quic, TransportKind::TlsTcp],
        }
    }
}

impl TransportCapabilities {
    pub fn supports(&self, transport: TransportKind) -> bool {
        self.supported.contains(&transport)
    }

    pub fn preferred_for(&self, class: RouteClass) -> Option<TransportKind> {
        let preference = match class {
            RouteClass::Reliable => [TransportKind::Quic, TransportKind::TlsTcp, TransportKind::Kcp, TransportKind::Udp],
            RouteClass::ReliableLowLatency => [TransportKind::Quic, TransportKind::Kcp, TransportKind::TlsTcp, TransportKind::Udp],
            RouteClass::BestEffort => [TransportKind::Udp, TransportKind::Quic, TransportKind::TlsTcp, TransportKind::Kcp],
        };

        preference.into_iter().find(|candidate| self.supports(*candidate))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_prefers_quic_for_reliable() {
        let caps = TransportCapabilities::default();
        assert_eq!(caps.preferred_for(RouteClass::Reliable), Some(TransportKind::Quic));
    }

    #[test]
    fn best_effort_prefers_udp_when_supported() {
        let caps = TransportCapabilities {
            supported: vec![TransportKind::TlsTcp, TransportKind::Udp],
        };
        assert_eq!(caps.preferred_for(RouteClass::BestEffort), Some(TransportKind::Udp));
    }
}
