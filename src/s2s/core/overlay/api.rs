use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::task::JoinHandle;

use crate::s2s::core::transport::{InboundFrame, StreamClass, Transport, TransportError};
use crate::s2s::core::NodeId;

use super::quality::{FanoutPlanner, NextHopQuality};
use super::types::{
    ClusterEvent, ClusterView, DirectSendReceipt, EventReceiver, MulticastReceipt,
    OverlayFrame, SendReceipt, UnreliableSendReceipt,
};

const MAX_RELAY_HOPS: usize = 8;

#[derive(Debug, thiserror::Error)]
pub enum OverlayError {
    #[error("no route to node {0}")]
    NoRoute(NodeId),
    #[error("no direct route to node {0}")]
    NoDirectRoute(NodeId),
    #[error("transport error: {0}")]
    Transport(String),
}

impl From<TransportError> for OverlayError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value.to_string())
    }
}

#[derive(Clone)]
pub struct Overlay {
    transport: Arc<dyn Transport>,
    cluster_view: Arc<dyn ClusterView>,
    events_tx: broadcast::Sender<ClusterEvent>,
    inbound_tx: mpsc::Sender<OverlayFrame>,
    inbound_subscribers: Arc<Mutex<HashMap<StreamClass, Vec<mpsc::Sender<OverlayFrame>>>>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WireOverlayFrame {
    from: NodeId,
    recipients: Vec<NodeId>,
    class: StreamClass,
    payload: Vec<u8>,
    path_trace: Vec<NodeId>,
}

impl Overlay {
    pub fn new(
        transport: Arc<dyn Transport>,
        cluster_view: Arc<dyn ClusterView>,
    ) -> (Self, mpsc::Receiver<OverlayFrame>) {
        let (events_tx, _) = broadcast::channel(512);
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<OverlayFrame>(1024);
        let (raw_inbound_tx, raw_inbound_rx) = mpsc::channel::<OverlayFrame>(1024);
        let inbound_subscribers: Arc<Mutex<HashMap<StreamClass, Vec<mpsc::Sender<OverlayFrame>>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let local_node = cluster_view.local_node();
        let subscribers = Arc::clone(&inbound_subscribers);
        let transport_for_task = Arc::clone(&transport);
        let cluster_view_for_task = Arc::clone(&cluster_view);
        tokio::spawn(async move {
            while let Some(frame) = inbound_rx.recv().await {
                let _ = raw_inbound_tx.send(frame.clone()).await;

                if !Self::can_accept_frame(&frame, local_node) {
                    continue;
                }

                let mut remaining = Self::prune_recipients(&frame.recipients, local_node);
                remaining.sort_unstable();
                remaining.dedup();

                if !remaining.is_empty() {
                    let mut next = frame.path_trace.clone();
                    next.push(local_node);

                    let mut fanout: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
                    for recipient in remaining {
                        let Some(next_hop) = cluster_view_for_task.resolve_next_hop(recipient) else {
                            continue;
                        };
                        if !Self::should_forward_with_loop_guard(&next, local_node, next_hop) {
                            continue;
                        }
                        fanout.entry(next_hop).or_default().push(recipient);
                    }

                    for (next_hop, recipients) in fanout {
                        let forwarded = OverlayFrame {
                            from: frame.from,
                            recipients,
                            class: frame.class,
                            payload: frame.payload.clone(),
                            path_trace: next.clone(),
                        };

                        if let Ok(bytes) = Self::encode_wire_frame(&forwarded) {
                            let _ = transport_for_task.try_send_frame(next_hop, frame.class, Bytes::from(bytes));
                        }
                    }
                }

                if !frame.recipients.contains(&local_node) {
                    continue;
                }

                let senders = {
                    let subscribers_guard = subscribers.lock().await;
                    subscribers_guard
                        .get(&frame.class)
                        .cloned()
                        .unwrap_or_default()
                };

                for sender in senders {
                    let _ = sender.send(frame.clone()).await;
                }
            }
        });

        (
            Self {
                transport,
                cluster_view,
                events_tx,
                inbound_tx,
                inbound_subscribers,
            },
            raw_inbound_rx,
        )
    }

    pub fn attach_transport_inbound(
        &self,
        mut inbound_rx: mpsc::Receiver<InboundFrame>,
    ) -> JoinHandle<()> {
        let overlay = self.clone();
        tokio::spawn(async move {
            while let Some(frame) = inbound_rx.recv().await {
                let Ok(decoded) = Self::decode_wire_frame(&frame.payload) else {
                    continue;
                };
                let _ = overlay.inbound_tx.send(decoded).await;
            }
        })
    }

    pub async fn send(
        &self,
        dst: NodeId,
        class: StreamClass,
        payload: Bytes,
    ) -> Result<SendReceipt, OverlayError> {
        let next_hop = self
            .cluster_view
            .resolve_next_hop(dst)
            .ok_or(OverlayError::NoRoute(dst))?;
        let frame = OverlayFrame {
            from: self.cluster_view.local_node(),
            recipients: vec![dst],
            class,
            payload,
            path_trace: vec![self.cluster_view.local_node()],
        };
        self.send_encoded(next_hop, &frame)?;
        Ok(SendReceipt { delivered_to: 1 })
    }

    pub async fn send_direct(
        &self,
        dst: NodeId,
        class: StreamClass,
        payload: Bytes,
    ) -> Result<DirectSendReceipt, OverlayError> {
        let next_hop = self
            .cluster_view
            .resolve_direct_hop(dst)
            .ok_or(OverlayError::NoDirectRoute(dst))?;
        let frame = OverlayFrame {
            from: self.cluster_view.local_node(),
            recipients: vec![dst],
            class,
            payload,
            path_trace: vec![self.cluster_view.local_node()],
        };
        self.send_encoded(next_hop, &frame)?;
        Ok(DirectSendReceipt { attempted: true })
    }

    pub async fn send_unreliable(
        &self,
        dst: NodeId,
        class: StreamClass,
        payload: Bytes,
    ) -> Result<UnreliableSendReceipt, OverlayError> {
        let next_hop = self
            .cluster_view
            .resolve_next_hop(dst)
            .ok_or(OverlayError::NoRoute(dst))?;
        let frame = OverlayFrame {
            from: self.cluster_view.local_node(),
            recipients: vec![dst],
            class,
            payload,
            path_trace: vec![self.cluster_view.local_node()],
        };
        self.send_encoded(next_hop, &frame)?;
        Ok(UnreliableSendReceipt { attempted: true })
    }

    pub async fn send_multicast(
        &self,
        dsts: &[NodeId],
        class: StreamClass,
        payload: Bytes,
    ) -> Result<MulticastReceipt, OverlayError> {
        let mut fanout: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
        for dst in dsts {
            let Some(next_hop) = self.cluster_view.resolve_next_hop(*dst) else {
                continue;
            };
            fanout.entry(next_hop).or_default().push(*dst);
        }

        let quality = fanout
            .keys()
            .copied()
            .map(|hop| (hop, NextHopQuality::default()))
            .collect::<HashMap<_, _>>();
        let planner = FanoutPlanner::new(quality);

        let mut sent_buckets = 0_usize;
        for (next_hop, recipients) in planner.plan(fanout) {
            let frame = OverlayFrame {
                from: self.cluster_view.local_node(),
                recipients,
                class,
                payload: payload.clone(),
                path_trace: vec![self.cluster_view.local_node()],
            };
            self.send_encoded(next_hop, &frame)?;
            sent_buckets = sent_buckets.saturating_add(1);
        }

        let recipients = dsts.len();

        Ok(MulticastReceipt {
            fanout_buckets: sent_buckets,
            recipients,
        })
    }

    pub async fn send_broadcast(
        &self,
        class: StreamClass,
        payload: Bytes,
    ) -> Result<MulticastReceipt, OverlayError> {
        let recipients = self.cluster_view.alive_nodes_excluding_self();
        self.send_multicast(&recipients, class, payload).await
    }

    pub async fn subscribe_inbound(&self, class: StreamClass) -> mpsc::Receiver<OverlayFrame> {
        let (tx, rx) = mpsc::channel(1024);
        let mut subscribers = self.inbound_subscribers.lock().await;
        subscribers.entry(class).or_default().push(tx);
        rx
    }

    pub fn subscribe_events(&self) -> EventReceiver {
        self.events_tx.subscribe()
    }

    pub fn cluster_view(&self) -> Arc<dyn ClusterView> {
        Arc::clone(&self.cluster_view)
    }

    pub fn emit_event(&self, event: ClusterEvent) {
        let _ = self.events_tx.send(event);
    }

    pub fn bind_udp_transport(&self, listen: &str) -> Result<SocketAddr, OverlayError> {
        self.transport.bind_udp(listen).map_err(OverlayError::from)
    }

    pub fn register_peer_addr(&self, node: NodeId, addr: SocketAddr) -> Result<(), OverlayError> {
        self.transport
            .register_peer_addr(node, addr)
            .map_err(OverlayError::from)
    }

    pub async fn inject_inbound(&self, frame: OverlayFrame) {
        let _ = self.inbound_tx.send(frame).await;
    }

    fn send_encoded(&self, next_hop: NodeId, frame: &OverlayFrame) -> Result<(), OverlayError> {
        let payload = Self::encode_wire_frame(frame)?;
        self.transport
            .try_send_frame(next_hop, frame.class, Bytes::from(payload))?;
        Ok(())
    }

    fn can_accept_frame(frame: &OverlayFrame, local_node: NodeId) -> bool {
        if frame.path_trace.contains(&local_node) {
            return false;
        }
        frame.path_trace.len() <= MAX_RELAY_HOPS
    }

    fn prune_recipients(recipients: &[NodeId], local_node: NodeId) -> Vec<NodeId> {
        recipients
            .iter()
            .copied()
            .filter(|r| *r != local_node)
            .collect()
    }

    fn should_forward_with_loop_guard(path_trace: &[NodeId], local_node: NodeId, next_hop: NodeId) -> bool {
        if path_trace.len() >= MAX_RELAY_HOPS {
            return false;
        }
        if next_hop == local_node {
            return false;
        }
        !path_trace.contains(&next_hop)
    }

    fn encode_wire_frame(frame: &OverlayFrame) -> Result<Vec<u8>, OverlayError> {
        let wire = WireOverlayFrame {
            from: frame.from,
            recipients: frame.recipients.clone(),
            class: frame.class,
            payload: frame.payload.to_vec(),
            path_trace: frame.path_trace.clone(),
        };
        serde_json::to_vec(&wire).map_err(|e| OverlayError::Transport(format!("wire encode failed: {e}")))
    }

    fn decode_wire_frame(bytes: &[u8]) -> Result<OverlayFrame, OverlayError> {
        let decoded: WireOverlayFrame =
            serde_json::from_slice(bytes).map_err(|e| OverlayError::Transport(format!("wire decode failed: {e}")))?;
        Ok(OverlayFrame {
            from: decoded.from,
            recipients: decoded.recipients,
            class: decoded.class,
            payload: Bytes::from(decoded.payload),
            path_trace: decoded.path_trace,
        })
    }

}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use bytes::Bytes;

    use crate::s2s::core::transport::Transport;

    use super::*;

    #[derive(Default)]
    struct MockTransport {
        sends: Mutex<Vec<(NodeId, StreamClass, Vec<u8>)>>,
        batches: Mutex<Vec<(NodeId, StreamClass, usize)>>,
    }

    impl Transport for MockTransport {
        fn try_send_frame(
            &self,
            next_hop: NodeId,
            class: StreamClass,
            payload: Bytes,
        ) -> Result<(), TransportError> {
            self.sends
                .lock()
                .expect("lock")
                .push((next_hop, class, payload.to_vec()));
            Ok(())
        }

        fn try_send_batch(
            &self,
            next_hop: NodeId,
            class: StreamClass,
            payloads: &[Bytes],
        ) -> Result<usize, TransportError> {
            self.batches
                .lock()
                .expect("lock")
                .push((next_hop, class, payloads.len()));
            Ok(payloads.len())
        }

        fn bind_udp(&self, _listen: &str) -> Result<std::net::SocketAddr, TransportError> {
            "127.0.0.1:0"
                .parse()
                .map_err(|e| TransportError::Io(format!("mock parse failed: {e}")))
        }

        fn register_peer_addr(&self, _node_id: NodeId, _addr: std::net::SocketAddr) -> Result<(), TransportError> {
            Ok(())
        }
    }

    struct MockClusterView {
        local: NodeId,
        routed: HashMap<NodeId, NodeId>,
        direct: HashMap<NodeId, NodeId>,
        alive: Vec<NodeId>,
    }

    impl ClusterView for MockClusterView {
        fn local_node(&self) -> NodeId {
            self.local
        }

        fn alive_nodes_excluding_self(&self) -> Vec<NodeId> {
            self.alive.clone()
        }

        fn resolve_next_hop(&self, dst: NodeId) -> Option<NodeId> {
            self.routed.get(&dst).copied()
        }

        fn resolve_direct_hop(&self, dst: NodeId) -> Option<NodeId> {
            self.direct.get(&dst).copied()
        }
    }

    fn build_overlay() -> (Overlay, Arc<MockTransport>) {
        let transport = Arc::new(MockTransport::default());
        let cluster_view = Arc::new(MockClusterView {
            local: 1,
            routed: HashMap::from([(2, 12), (3, 12), (4, 14)]),
            direct: HashMap::from([(2, 2)]),
            alive: vec![2, 3, 4],
        });

        let (overlay, _raw_rx) = Overlay::new(transport.clone(), cluster_view);
        (overlay, transport)
    }

    #[tokio::test]
    async fn send_direct_requires_direct_route() {
        let (overlay, transport) = build_overlay();

        overlay
            .send_direct(2, StreamClass::BestEffort, Bytes::from_static(b"x"))
            .await
            .expect("direct send should succeed");

        let err = overlay
            .send_direct(3, StreamClass::BestEffort, Bytes::from_static(b"x"))
            .await
            .expect_err("missing direct route should fail");

        assert!(matches!(err, OverlayError::NoDirectRoute(3)));

        let sends = transport.sends.lock().expect("lock");
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].0, 2);

        let decoded = Overlay::decode_wire_frame(&sends[0].2).expect("decode should succeed");
        assert_eq!(decoded.recipients, vec![2]);
    }

    #[tokio::test]
    async fn send_unreliable_routes_by_node_id() {
        let (overlay, transport) = build_overlay();

        overlay
            .send_unreliable(4, StreamClass::LowLatencyDatagram, Bytes::from_static(b"u"))
            .await
            .expect("unreliable send should route");

        let sends = transport.sends.lock().expect("lock");
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].0, 14);

        let decoded = Overlay::decode_wire_frame(&sends[0].2).expect("decode should succeed");
        assert_eq!(decoded.recipients, vec![4]);
    }

    #[tokio::test]
    async fn multicast_fanout_deduplicates_by_next_hop() {
        let (overlay, transport) = build_overlay();

        let receipt = overlay
            .send_multicast(&[2, 3, 4], StreamClass::LowLatencyDatagram, Bytes::from_static(b"m"))
            .await
            .expect("multicast should succeed");

        assert_eq!(receipt.fanout_buckets, 2);
        assert_eq!(receipt.recipients, 3);

        let sends = transport.sends.lock().expect("lock");
        assert_eq!(sends.len(), 2);

        let mut recipient_sets = sends
            .iter()
            .map(|(_, _, bytes)| Overlay::decode_wire_frame(bytes).expect("decode should succeed").recipients)
            .collect::<Vec<_>>();
        recipient_sets.sort_by_key(|v| v[0]);
        assert_eq!(recipient_sets, vec![vec![2, 3], vec![4]]);
    }

    #[tokio::test]
    async fn subscribe_inbound_receives_frames_for_local_recipient() {
        let (overlay, transport) = build_overlay();
        let mut rx = overlay
            .subscribe_inbound(StreamClass::LowLatencyDatagram)
            .await;

        overlay
            .inject_inbound(OverlayFrame {
                from: 2,
                recipients: vec![1, 3],
                class: StreamClass::LowLatencyDatagram,
                payload: Bytes::from_static(b"voice"),
                path_trace: vec![2],
            })
            .await;

        let received = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
            .await
            .expect("receive should complete")
            .expect("frame should be present");

        assert_eq!(received.from, 2);
        assert_eq!(received.payload, Bytes::from_static(b"voice"));

        let sends = transport.sends.lock().expect("lock");
        assert!(!sends.is_empty(), "local-delivery frame should also relay to remaining recipients");
    }

    #[tokio::test]
    async fn inbound_nonlocal_frame_is_relayed() {
        let (overlay, transport) = build_overlay();

        overlay
            .inject_inbound(OverlayFrame {
                from: 2,
                recipients: vec![3, 4],
                class: StreamClass::LowLatencyDatagram,
                payload: Bytes::from_static(b"relay"),
                path_trace: vec![2],
            })
            .await;

        // Give the relay task a chance to process.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let sends = transport.sends.lock().expect("lock");
        assert_eq!(sends.len(), 2);

        let decoded = Overlay::decode_wire_frame(&sends[0].2).expect("decode should succeed");
        assert!(decoded.path_trace.contains(&1));
    }

    #[tokio::test]
    async fn looped_or_over_hop_frame_is_dropped() {
        let (overlay, transport) = build_overlay();

        // Local already exists in path trace => drop.
        overlay
            .inject_inbound(OverlayFrame {
                from: 2,
                recipients: vec![3, 4],
                class: StreamClass::LowLatencyDatagram,
                payload: Bytes::from_static(b"loop"),
                path_trace: vec![2, 1],
            })
            .await;

        // Exceeds relay hop budget => drop.
        overlay
            .inject_inbound(OverlayFrame {
                from: 2,
                recipients: vec![3],
                class: StreamClass::LowLatencyDatagram,
                payload: Bytes::from_static(b"hop"),
                path_trace: vec![2, 5, 6, 7, 8, 9, 10, 11, 12],
            })
            .await;

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let sends = transport.sends.lock().expect("lock");
        assert!(sends.is_empty(), "looped/over-budget frames must be dropped");
    }
}
