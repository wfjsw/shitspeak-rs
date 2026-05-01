use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::RwLock;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::s2s::core::NodeId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum StreamClass {
    Reliable,
    BestEffort,
    LowLatencyDatagram,
}

#[derive(Debug, Clone)]
pub struct InboundFrame {
    pub source: SocketAddr,
    pub source_node: Option<NodeId>,
    pub class: StreamClass,
    pub payload: Bytes,
}

#[derive(Debug, Clone)]
pub struct OutboundFrame {
    pub class: StreamClass,
    pub payload: Bytes,
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("peer not registered: {0}")]
    UnknownPeer(NodeId),
    #[error("channel closed")]
    ChannelClosed,
    #[error("io error: {0}")]
    Io(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerTransportStats {
    pub enqueued_frames: u64,
    pub overflow_drops: u64,
    pub send_errors: u64,
    pub worker_stops: u64,
}

pub trait Transport: Send + Sync {
    fn try_send_frame(
        &self,
        next_hop: NodeId,
        class: StreamClass,
        payload: Bytes,
    ) -> Result<(), TransportError>;

    fn try_send_batch(
        &self,
        next_hop: NodeId,
        class: StreamClass,
        payloads: &[Bytes],
    ) -> Result<usize, TransportError>;

    fn bind_udp(&self, listen: &str) -> Result<SocketAddr, TransportError>;

    fn register_peer_addr(&self, node_id: NodeId, addr: SocketAddr) -> Result<(), TransportError>;
}

#[derive(Debug, Clone)]
pub struct NetworkRuntime {
    outbound_by_peer: Arc<RwLock<HashMap<NodeId, mpsc::Sender<OutboundFrame>>>>,
    peer_addrs: Arc<RwLock<HashMap<NodeId, SocketAddr>>>,
    udp_socket: Arc<RwLock<Option<Arc<UdpSocket>>>>,
    inbound_tx: mpsc::Sender<InboundFrame>,
    peer_stats: Arc<RwLock<HashMap<NodeId, PeerTransportStats>>>,
}

impl NetworkRuntime {
    pub fn new(inbound_capacity: usize) -> (Self, mpsc::Receiver<InboundFrame>) {
        let (inbound_tx, inbound_rx) = mpsc::channel(inbound_capacity.max(1));
        (
            Self {
                outbound_by_peer: Arc::new(RwLock::new(HashMap::new())),
                peer_addrs: Arc::new(RwLock::new(HashMap::new())),
                udp_socket: Arc::new(RwLock::new(None)),
                inbound_tx,
                peer_stats: Arc::new(RwLock::new(HashMap::new())),
            },
            inbound_rx,
        )
    }

    fn ensure_peer_stats(&self, peer: NodeId) {
        self.peer_stats.write().entry(peer).or_default();
    }

    fn bump_stats(&self, peer: NodeId, update: impl FnOnce(&mut PeerTransportStats)) {
        let mut stats = self.peer_stats.write();
        let entry = stats.entry(peer).or_default();
        update(entry);
    }

    pub fn peer_stats(&self, peer: NodeId) -> PeerTransportStats {
        self.peer_stats
            .read()
            .get(&peer)
            .cloned()
            .unwrap_or_default()
    }

    pub fn unregister_peer_sender(&self, peer: NodeId) {
        self.outbound_by_peer.write().remove(&peer);
    }

    pub async fn register_peer_sender(
        &self,
        peer: NodeId,
        sender: mpsc::Sender<OutboundFrame>,
    ) {
        self.ensure_peer_stats(peer);
        self.outbound_by_peer.write().insert(peer, sender);
    }

    pub async fn register_peer_queue(
        &self,
        peer: NodeId,
        capacity: usize,
    ) -> mpsc::Receiver<OutboundFrame> {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        self.register_peer_sender(peer, tx).await;
        rx
    }

    pub async fn register_peer_udp_worker(
        &self,
        peer: NodeId,
        capacity: usize,
    ) -> JoinHandle<()> {
        let mut rx = self.register_peer_queue(peer, capacity).await;
        let runtime = self.clone();
        tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                if runtime
                    .send_udp_async(peer, frame.class, frame.payload)
                    .await
                    .is_err()
                {
                    runtime.bump_stats(peer, |s| {
                        s.send_errors = s.send_errors.saturating_add(1);
                    });
                }
            }
            runtime.bump_stats(peer, |s| {
                s.worker_stops = s.worker_stops.saturating_add(1);
            });
        })
    }

    pub async fn push_inbound(&self, frame: InboundFrame) -> Result<(), TransportError> {
        self.inbound_tx
            .send(frame)
            .await
            .map_err(|_| TransportError::ChannelClosed)
    }

    pub fn set_peer_addr(&self, node_id: NodeId, addr: SocketAddr) {
        self.ensure_peer_stats(node_id);
        self.peer_addrs.write().insert(node_id, addr);
    }
}

impl Transport for NetworkRuntime {
    fn try_send_frame(
        &self,
        next_hop: NodeId,
        class: StreamClass,
        payload: Bytes,
    ) -> Result<(), TransportError> {
        let tx = {
            let outbound = self.outbound_by_peer.read();
            outbound.get(&next_hop).cloned()
        };

        let Some(tx) = tx else {
            return self.try_send_udp(next_hop, class, payload);
        };

        tx.try_send(OutboundFrame { class, payload })
            .map(|_| {
                self.bump_stats(next_hop, |s| {
                    s.enqueued_frames = s.enqueued_frames.saturating_add(1);
                });
            })
            .map_err(|_| {
                self.bump_stats(next_hop, |s| {
                    s.overflow_drops = s.overflow_drops.saturating_add(1);
                });
                TransportError::ChannelClosed
            })
    }

    fn try_send_batch(
        &self,
        next_hop: NodeId,
        class: StreamClass,
        payloads: &[Bytes],
    ) -> Result<usize, TransportError> {
        let tx = {
            let outbound = self.outbound_by_peer.read();
            outbound.get(&next_hop).cloned()
        };

        let Some(tx) = tx else {
            return self.try_send_udp_batch(next_hop, class, payloads);
        };

        let mut sent = 0_usize;
        for payload in payloads {
            tx.try_send(OutboundFrame {
                class,
                payload: payload.clone(),
            })
            .map_err(|_| {
                self.bump_stats(next_hop, |s| {
                    s.overflow_drops = s.overflow_drops.saturating_add(1);
                });
                TransportError::ChannelClosed
            })?;
            sent = sent.saturating_add(1);
        }

        self.bump_stats(next_hop, |s| {
            s.enqueued_frames = s.enqueued_frames.saturating_add(sent as u64);
        });

        Ok(sent)
    }

    fn bind_udp(&self, listen: &str) -> Result<SocketAddr, TransportError> {
        let std_socket = std::net::UdpSocket::bind(listen)
            .map_err(|e| TransportError::Io(format!("udp bind failed on {listen}: {e}")))?;
        std_socket
            .set_nonblocking(true)
            .map_err(|e| TransportError::Io(format!("udp nonblocking failed on {listen}: {e}")))?;
        let local_addr = std_socket
            .local_addr()
            .map_err(|e| TransportError::Io(format!("udp local_addr failed on {listen}: {e}")))?;
        let socket = Arc::new(
            UdpSocket::from_std(std_socket)
                .map_err(|e| TransportError::Io(format!("udp from_std failed on {listen}: {e}")))?,
        );

        {
            let mut guard = self.udp_socket.write();
            *guard = Some(Arc::clone(&socket));
        }

        let inbound_tx = self.inbound_tx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0_u8; 64 * 1024];
            loop {
                let (len, source) = match socket.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let payload = Bytes::copy_from_slice(&buf[..len]);
                if inbound_tx
                    .send(InboundFrame {
                        source,
                        source_node: None,
                        class: StreamClass::BestEffort,
                        payload,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        Ok(local_addr)
    }

    fn register_peer_addr(&self, node_id: NodeId, addr: SocketAddr) -> Result<(), TransportError> {
        self.set_peer_addr(node_id, addr);
        Ok(())
    }
}

impl NetworkRuntime {
    fn try_send_udp(&self, next_hop: NodeId, _class: StreamClass, payload: Bytes) -> Result<(), TransportError> {
        let Some(addr) = self.peer_addrs.read().get(&next_hop).copied() else {
            return Err(TransportError::UnknownPeer(next_hop));
        };
        let Some(socket) = self.udp_socket.read().as_ref().cloned() else {
            return Err(TransportError::UnknownPeer(next_hop));
        };
        socket
            .try_send_to(&payload, addr)
            .map(|_| ())
            .map_err(|e| TransportError::Io(format!("udp send_to failed: {e}")))
    }

    fn try_send_udp_batch(
        &self,
        next_hop: NodeId,
        class: StreamClass,
        payloads: &[Bytes],
    ) -> Result<usize, TransportError> {
        let mut sent = 0_usize;
        for payload in payloads {
            self.try_send_udp(next_hop, class, payload.clone())?;
            sent = sent.saturating_add(1);
        }
        Ok(sent)
    }

    async fn send_udp_async(
        &self,
        next_hop: NodeId,
        _class: StreamClass,
        payload: Bytes,
    ) -> Result<(), TransportError> {
        let Some(addr) = self.peer_addrs.read().get(&next_hop).copied() else {
            return Err(TransportError::UnknownPeer(next_hop));
        };
        let Some(socket) = self.udp_socket.read().as_ref().cloned() else {
            return Err(TransportError::UnknownPeer(next_hop));
        };
        socket
            .send_to(&payload, addr)
            .await
            .map(|_| ())
            .map_err(|e| TransportError::Io(format!("udp async send_to failed: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn send_batch_enqueues_in_fifo_order() {
        let (runtime, _inbound_rx) = NetworkRuntime::new(8);
        let mut peer_rx = runtime.register_peer_queue(42, 8).await;

        let payloads = vec![Bytes::from_static(b"a"), Bytes::from_static(b"b")];
        let count = runtime
            .try_send_batch(42, StreamClass::BestEffort, &payloads)
            .expect("batch send should succeed");

        assert_eq!(count, 2);

        let first = peer_rx.recv().await.expect("first frame expected");
        let second = peer_rx.recv().await.expect("second frame expected");

        assert_eq!(first.payload, Bytes::from_static(b"a"));
        assert_eq!(second.payload, Bytes::from_static(b"b"));
    }

    #[tokio::test]
    async fn send_to_unknown_peer_returns_error() {
        let (runtime, _inbound_rx) = NetworkRuntime::new(8);
        let err = runtime
            .try_send_frame(7, StreamClass::Reliable, Bytes::from_static(b"x"))
            .expect_err("unknown peer should fail");

        assert!(matches!(err, TransportError::UnknownPeer(7)));
    }

    #[tokio::test]
    async fn peer_udp_worker_sends_to_registered_peer_addr() {
        let (runtime, _inbound_rx) = NetworkRuntime::new(8);
        let _local = runtime.bind_udp("127.0.0.1:0").expect("udp bind should succeed");

        let receiver = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("receiver bind should succeed");
        let receiver_addr = receiver.local_addr().expect("receiver addr should exist");

        runtime.set_peer_addr(42, receiver_addr);
        let worker = runtime.register_peer_udp_worker(42, 8).await;

        runtime
            .try_send_frame(42, StreamClass::BestEffort, Bytes::from_static(b"hello"))
            .expect("queue send should succeed");

        let mut buf = [0_u8; 64];
        let (len, _from) = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            receiver.recv_from(&mut buf),
        )
        .await
        .expect("recv should complete")
        .expect("recv should succeed");

        assert_eq!(&buf[..len], b"hello");

        worker.abort();
    }

    #[tokio::test]
    async fn queue_overflow_increments_drop_stats() {
        let (runtime, _inbound_rx) = NetworkRuntime::new(8);
        let _peer_rx = runtime.register_peer_queue(42, 1).await;

        runtime
            .try_send_frame(42, StreamClass::BestEffort, Bytes::from_static(b"first"))
            .expect("first enqueue should succeed");

        let err = runtime
            .try_send_frame(42, StreamClass::BestEffort, Bytes::from_static(b"second"))
            .expect_err("second enqueue should overflow");
        assert!(matches!(err, TransportError::ChannelClosed));

        let stats = runtime.peer_stats(42);
        assert_eq!(stats.enqueued_frames, 1);
        assert_eq!(stats.overflow_drops, 1);
    }

    #[tokio::test]
    async fn unregister_peer_sender_stops_worker_and_updates_stats() {
        let (runtime, _inbound_rx) = NetworkRuntime::new(8);
        let worker = runtime.register_peer_udp_worker(42, 8).await;

        runtime.unregister_peer_sender(42);

        tokio::time::timeout(std::time::Duration::from_millis(200), worker)
            .await
            .expect("worker should stop")
            .expect("worker join should succeed");

        let stats = runtime.peer_stats(42);
        assert_eq!(stats.worker_stops, 1);
    }
}
