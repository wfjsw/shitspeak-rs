use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex, RwLock};

use super::{ClusterEnvelope, RouteClass, TransportCapabilities, TransportKind};

#[derive(Debug, Clone)]
pub struct TransportRuntimePolicy {
    pub require_reliable_fallback: bool,
}

impl Default for TransportRuntimePolicy {
    fn default() -> Self {
        Self {
            require_reliable_fallback: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectedTransport {
    pub primary: TransportKind,
    pub fallback: Option<TransportKind>,
}

#[derive(Debug, Clone)]
pub struct InboundEnvelope {
    pub source: SocketAddr,
    pub frame_len: usize,
    pub envelope: ClusterEnvelope,
}

#[derive(Debug)]
pub struct OverlaySocketRuntime {
    local_node: u16,
    peers: Arc<RwLock<Vec<SocketAddr>>>,
    udp_socket: Option<Arc<UdpSocket>>,
    tcp_local_addr: Option<SocketAddr>,
    incoming_rx: Mutex<mpsc::UnboundedReceiver<InboundEnvelope>>,
}

impl OverlaySocketRuntime {
    pub async fn bind(
        local_node: u16,
        quic_listen: Option<&str>,
        tcp_listen: Option<&str>,
        bootstrap_nodes: &[String],
    ) -> Result<Self, String> {
        let mut peers = Vec::with_capacity(bootstrap_nodes.len());
        for peer in bootstrap_nodes {
            let addr: SocketAddr = peer
                .parse()
                .map_err(|e| format!("invalid bootstrap peer address {peer}: {e}"))?;
            peers.push(addr);
        }

        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();

        let udp_socket = if let Some(listen) = quic_listen {
            let socket = Arc::new(
                UdpSocket::bind(listen)
                    .await
                    .map_err(|e| format!("failed to bind overlay UDP socket on {listen}: {e}"))?,
            );
            spawn_udp_reader(Arc::clone(&socket), incoming_tx.clone());
            Some(socket)
        } else {
            None
        };

        let tcp_local_addr = if let Some(listen) = tcp_listen {
            let listener = Arc::new(
                TcpListener::bind(listen)
                    .await
                    .map_err(|e| format!("failed to bind overlay TCP listener on {listen}: {e}"))?,
            );
            let addr = listener.local_addr().ok();
            spawn_tcp_acceptor(listener, incoming_tx.clone());
            addr
        } else {
            None
        };

        Ok(Self {
            local_node,
            peers: Arc::new(RwLock::new(peers)),
            udp_socket,
            tcp_local_addr,
            incoming_rx: Mutex::new(incoming_rx),
        })
    }

    pub async fn register_peer_addr(&self, addr: SocketAddr) {
        let mut peers = self.peers.write().await;
        if !peers.contains(&addr) {
            peers.push(addr);
        }
    }

    pub async fn drain_incoming(&self, max_items: usize) -> Vec<InboundEnvelope> {
        let mut rx = self.incoming_rx.lock().await;
        let mut drained = Vec::new();
        for _ in 0..max_items {
            match rx.try_recv() {
                Ok(item) => drained.push(item),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            }
        }
        drained
    }

    pub async fn send_envelope(
        &self,
        envelope: &ClusterEnvelope,
        class: RouteClass,
        selected: Option<SelectedTransport>,
    ) -> Result<usize, String> {
        let mut envelope = envelope.clone();
        envelope.from = self.local_node;

        let frame = serde_json::to_vec(&envelope)
            .map_err(|e| format!("encode cluster envelope failed: {e}"))?;

        let peers = self.peers.read().await.clone();
        if peers.is_empty() {
            return Ok(0);
        }

        let transports = if let Some(pair) = selected {
            let mut ordered = vec![pair.primary];
            if let Some(fallback) = pair.fallback {
                ordered.push(fallback);
            }
            ordered
        } else {
            default_transports_for_class(class)
        };

        let mut sent = 0_usize;
        for peer in peers {
            let mut delivered = false;
            for transport in &transports {
                if self.send_with_transport(peer, &frame, *transport).await {
                    delivered = true;
                    break;
                }
            }
            if delivered {
                sent = sent.saturating_add(1);
            }
        }

        Ok(sent)
    }

    pub fn udp_local_addr(&self) -> Option<SocketAddr> {
        self.udp_socket.as_ref().and_then(|socket| socket.local_addr().ok())
    }

    pub fn tcp_local_addr(&self) -> Option<SocketAddr> {
        self.tcp_local_addr
    }

    /// Remove a known peer address. Returns `true` if the address was present.
    pub async fn remove_peer_addr(&self, addr: SocketAddr) -> bool {
        let mut peers = self.peers.write().await;
        let before = peers.len();
        peers.retain(|&a| a != addr);
        peers.len() < before
    }

    /// Return the current list of known peer addresses.
    pub async fn peer_addrs(&self) -> Vec<SocketAddr> {
        self.peers.read().await.clone()
    }

    /// Unicast an envelope to a single explicit address, trying transport kinds in preference order.
    pub async fn send_to(
        &self,
        addr: SocketAddr,
        envelope: &ClusterEnvelope,
        class: RouteClass,
        selected: Option<SelectedTransport>,
    ) -> Result<bool, String> {
        let mut envelope = envelope.clone();
        envelope.from = self.local_node;
        let frame = serde_json::to_vec(&envelope)
            .map_err(|e| format!("encode cluster envelope failed: {e}"))?;

        let transports = if let Some(pair) = selected {
            let mut ordered = vec![pair.primary];
            if let Some(fallback) = pair.fallback {
                ordered.push(fallback);
            }
            ordered
        } else {
            default_transports_for_class(class)
        };

        for transport in &transports {
            if self.send_with_transport(addr, &frame, *transport).await {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Wait asynchronously until the next inbound envelope arrives.
    /// Returns `None` when all listener tasks have stopped (runtime dropped).
    pub async fn recv_next(&self) -> Option<InboundEnvelope> {
        let mut rx = self.incoming_rx.lock().await;
        rx.recv().await
    }

    async fn send_with_transport(
        &self,
        peer: SocketAddr,
        frame: &[u8],
        transport: TransportKind,
    ) -> bool {
        match transport {
            TransportKind::Quic | TransportKind::Udp | TransportKind::Kcp => {
                if let Some(socket) = &self.udp_socket {
                    return socket.send_to(frame, peer).await.is_ok();
                }
                false
            }
            TransportKind::TlsTcp => send_tcp(peer, frame).await,
        }
    }
}

fn default_transports_for_class(class: RouteClass) -> Vec<TransportKind> {
    match class {
        RouteClass::Reliable => vec![TransportKind::TlsTcp, TransportKind::Quic, TransportKind::Udp],
        RouteClass::ReliableLowLatency => vec![TransportKind::Quic, TransportKind::TlsTcp, TransportKind::Udp],
        RouteClass::BestEffort => vec![TransportKind::Udp, TransportKind::Quic, TransportKind::TlsTcp],
    }
}

async fn send_tcp(peer: SocketAddr, frame: &[u8]) -> bool {
    let mut stream = match TcpStream::connect(peer).await {
        Ok(stream) => stream,
        Err(_) => return false,
    };
    stream.write_all(frame).await.is_ok() && stream.write_all(b"\n").await.is_ok()
}

fn spawn_udp_reader(socket: Arc<UdpSocket>, incoming_tx: mpsc::UnboundedSender<InboundEnvelope>) {
    tokio::spawn(async move {
        let mut buf = vec![0_u8; 64 * 1024];
        loop {
            let (len, source) = match socket.recv_from(&mut buf).await {
                Ok(result) => result,
                Err(err) => {
                    tracing::debug!(%err, "overlay UDP reader stopped");
                    break;
                }
            };

            let envelope = match serde_json::from_slice::<ClusterEnvelope>(&buf[..len]) {
                Ok(envelope) => envelope,
                Err(err) => {
                    tracing::trace!(%err, source = %source, "overlay UDP frame decode failed");
                    continue;
                }
            };

            if incoming_tx
                .send(InboundEnvelope {
                    source,
                    frame_len: len,
                    envelope,
                })
                .is_err()
            {
                break;
            }
        }
    });
}

fn spawn_tcp_acceptor(
    listener: Arc<TcpListener>,
    incoming_tx: mpsc::UnboundedSender<InboundEnvelope>,
) {
    tokio::spawn(async move {
        loop {
            let (stream, source) = match listener.accept().await {
                Ok(result) => result,
                Err(err) => {
                    tracing::debug!(%err, "overlay TCP acceptor stopped");
                    break;
                }
            };

            let tx = incoming_tx.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                loop {
                    line.clear();
                    let read = match reader.read_line(&mut line).await {
                        Ok(read) => read,
                        Err(err) => {
                            tracing::trace!(%err, source = %source, "overlay TCP read failed");
                            break;
                        }
                    };

                    if read == 0 {
                        break;
                    }

                    let payload = line.trim_end_matches(['\r', '\n']);
                    let envelope = match serde_json::from_str::<ClusterEnvelope>(payload) {
                        Ok(envelope) => envelope,
                        Err(err) => {
                            tracing::trace!(%err, source = %source, "overlay TCP frame decode failed");
                            continue;
                        }
                    };

                    if tx
                        .send(InboundEnvelope {
                            source,
                            frame_len: payload.len(),
                            envelope,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
    });
}

pub fn choose_transport_pair(
    capabilities: &TransportCapabilities,
    class: RouteClass,
    policy: &TransportRuntimePolicy,
) -> Option<SelectedTransport> {
    let primary = capabilities.preferred_for(class)?;

    let fallback = match primary {
        TransportKind::Quic if capabilities.supports(TransportKind::TlsTcp) => Some(TransportKind::TlsTcp),
        TransportKind::Udp if capabilities.supports(TransportKind::Quic) => Some(TransportKind::Quic),
        TransportKind::Udp if capabilities.supports(TransportKind::TlsTcp) => Some(TransportKind::TlsTcp),
        _ => None,
    };

    if policy.require_reliable_fallback && class != RouteClass::BestEffort {
        let reliable_ok = matches!(primary, TransportKind::Quic | TransportKind::TlsTcp)
            || matches!(fallback, Some(TransportKind::Quic | TransportKind::TlsTcp));
        if !reliable_ok {
            return None;
        }
    }

    Some(SelectedTransport { primary, fallback })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s2s::overlay_network::{ClusterMessage, MessageMode};
    use tokio::time::{sleep, Duration};

    #[test]
    fn selects_quic_with_tls_fallback() {
        let caps = TransportCapabilities {
            supported: vec![TransportKind::Quic, TransportKind::TlsTcp],
        };
        let selected = choose_transport_pair(&caps, RouteClass::Reliable, &TransportRuntimePolicy::default())
            .expect("pair should be selected");
        assert_eq!(selected.primary, TransportKind::Quic);
        assert_eq!(selected.fallback, Some(TransportKind::TlsTcp));
    }

    #[test]
    fn rejects_unreliable_only_for_reliable_class() {
        let caps = TransportCapabilities {
            supported: vec![TransportKind::Udp],
        };
        let result = choose_transport_pair(&caps, RouteClass::Reliable, &TransportRuntimePolicy::default());
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn udp_runtime_sends_and_receives_cluster_envelope() {
        let receiver = OverlaySocketRuntime::bind(2, Some("127.0.0.1:0"), None, &[])
            .await
            .expect("receiver runtime should bind");
        let receiver_addr = receiver
            .udp_local_addr()
            .expect("receiver should expose udp address");

        let sender = OverlaySocketRuntime::bind(
            1,
            Some("127.0.0.1:0"),
            None,
            &[receiver_addr.to_string()],
        )
        .await
        .expect("sender runtime should bind");

        let envelope = ClusterEnvelope {
            version: 1,
            feature_bitmap: 0,
            from: 1,
            seq: 9,
            mode: MessageMode::Broadcast,
            body: ClusterMessage::Heartbeat {
                boot_id: "boot-a".to_owned(),
                members_seen: 1,
            },
        };

        let sent = sender
            .send_envelope(
                &envelope,
                RouteClass::ReliableLowLatency,
                Some(SelectedTransport {
                    primary: TransportKind::Quic,
                    fallback: Some(TransportKind::Udp),
                }),
            )
            .await
            .expect("send should succeed");
        assert_eq!(sent, 1);

        let mut inbound = Vec::new();
        for _ in 0..20 {
            inbound = receiver.drain_incoming(8).await;
            if !inbound.is_empty() {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }

        assert_eq!(inbound.len(), 1);
        assert_eq!(inbound[0].envelope.from, 1);
        assert!(matches!(
            inbound[0].envelope.body,
            ClusterMessage::Heartbeat { .. }
        ));
    }
}
