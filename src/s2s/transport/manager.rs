//! `ConnectionManager` — public face of the transport module.
//!
//! Holds the peer table, the inbound dispatch sinks, the shutdown signal, and
//! a registry of per-transport endpoints. Each endpoint owns its own state
//! (TLS configs, bound listener, `quinn::Endpoint`, etc.) so the manager
//! itself stays free of transport-specific fields.

use std::sync::Arc;

use bytes::Bytes;
use scc::HashMap as SccMap;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::types::NodeIdentifier;

use super::config::TransportConfig;
use super::connection::{OutboundFrame, PeerState};
use super::endpoint::{
    kcp::KcpEndpoint, quic::QuicEndpoint, tcp::TcpEndpoint, udp::UdpEndpoint, EndpointRegistry,
};
use super::error::{ConfigError, SendError, TransportError};
use super::identity::NodeIdentity;
use super::metrics::{assemble_snapshot, MetricsSnapshot};
use super::service_level::{MessageClass, PeerAddress, ServiceLevel, TransportKind};
use super::tls::build_tls_configs;

/// Inbound message handed to the caller via one of the two mpscs in
/// [`Inbound`]. The caller owns the receivers; the manager keeps the senders.
#[derive(Debug)]
pub struct InboundMessage {
    from: NodeIdentifier,
    level: ServiceLevel,
    transport: TransportKind,
    class: MessageClass,
    payload: Bytes,
}

impl InboundMessage {
    pub(crate) fn new(
        from: NodeIdentifier,
        level: ServiceLevel,
        transport: TransportKind,
        class: MessageClass,
        payload: Bytes,
    ) -> Self {
        Self { from, level, transport, class, payload }
    }

    pub fn from(&self) -> NodeIdentifier {
        self.from
    }

    pub fn level(&self) -> ServiceLevel {
        self.level
    }

    pub fn transport(&self) -> TransportKind {
        self.transport
    }

    pub fn class(&self) -> MessageClass {
        self.class
    }

    pub fn payload(&self) -> &Bytes {
        &self.payload
    }
}

/// Receiver halves returned once at `start`.
pub struct Inbound {
    high_priority: mpsc::Receiver<InboundMessage>,
    regular: mpsc::Receiver<InboundMessage>,
}

impl Inbound {
    pub(crate) fn new(
        high_priority: mpsc::Receiver<InboundMessage>,
        regular: mpsc::Receiver<InboundMessage>,
    ) -> Self {
        Self { high_priority, regular }
    }

    pub fn high_priority(&mut self) -> &mut mpsc::Receiver<InboundMessage> {
        &mut self.high_priority
    }

    pub fn regular(&mut self) -> &mut mpsc::Receiver<InboundMessage> {
        &mut self.regular
    }

    /// Consume the handle and return the two receivers (high-priority, regular).
    /// Used by callers (e.g. the overlay dispatcher) that want to take owned
    /// halves into separate tasks.
    pub fn into_parts(
        self,
    ) -> (
        mpsc::Receiver<InboundMessage>,
        mpsc::Receiver<InboundMessage>,
    ) {
        (self.high_priority, self.regular)
    }
}

/// Sender halves used by all stream/datagram pumps. Cheap to clone.
#[derive(Clone)]
pub(crate) struct InboundDispatch {
    high: mpsc::Sender<InboundMessage>,
    regular: mpsc::Sender<InboundMessage>,
}

impl InboundDispatch {
    pub fn new(
        high: mpsc::Sender<InboundMessage>,
        regular: mpsc::Sender<InboundMessage>,
    ) -> Self {
        Self { high, regular }
    }

    pub fn dispatch(&self, msg: InboundMessage) {
        match msg.class {
            MessageClass::HighPriority => {
                if let Err(e) = self.high.try_send(msg) {
                    warn!(error=%e, "high-priority inbound queue full; dropping frame");
                }
            }
            MessageClass::Regular => {
                if let Err(e) = self.regular.try_send(msg) {
                    warn!(error=%e, "regular inbound queue full; dropping frame");
                }
            }
        }
    }
}

/// Internal state shared across the manager handle, supervisor task, and all
/// endpoint accept/dial loops. Transport-specific state lives inside the
/// individual endpoints reachable through `endpoints`.
pub(crate) struct ManagerInner {
    self_id: NodeIdentifier,
    peers: Arc<SccMap<NodeIdentifier, Arc<PeerState>>>,
    inbound: InboundDispatch,
    shutdown: CancellationToken,
    cfg: TransportConfig,
    endpoints: EndpointRegistry,
}

impl ManagerInner {
    pub fn self_id(&self) -> NodeIdentifier {
        self.self_id
    }

    pub fn inbound(&self) -> &InboundDispatch {
        &self.inbound
    }

    pub fn shutdown(&self) -> &CancellationToken {
        &self.shutdown
    }

    pub fn cfg(&self) -> &TransportConfig {
        &self.cfg
    }

    pub fn endpoints(&self) -> &EndpointRegistry {
        &self.endpoints
    }

    pub fn get_or_create_peer(&self, id: NodeIdentifier) -> Arc<PeerState> {
        if let Some(existing) = self.peers.get(&id) {
            return existing.get().clone();
        }
        let new = PeerState::new(
            id,
            self.cfg.backoff_initial(),
            self.cfg.backoff_cap(),
            self.cfg.bandwidth_window(),
        );
        match self.peers.entry(id) {
            scc::hash_map::Entry::Occupied(e) => e.get().clone(),
            scc::hash_map::Entry::Vacant(e) => {
                e.insert_entry(new.clone());
                new
            }
        }
    }

    pub fn get_peer(&self, id: NodeIdentifier) -> Option<Arc<PeerState>> {
        self.peers.get(&id).map(|e| e.get().clone())
    }

    pub fn remove_peer(&self, id: NodeIdentifier) -> Option<Arc<PeerState>> {
        self.peers.remove(&id).map(|(_, v)| v)
    }

    pub fn iter_peers(&self) -> Vec<(NodeIdentifier, Arc<PeerState>)> {
        let mut out = Vec::new();
        let mut probe = self.peers.first_entry();
        while let Some(e) = probe {
            out.push((*e.key(), e.get().clone()));
            probe = e.next();
        }
        out
    }
}

/// Public handle.
#[derive(Clone)]
pub struct ConnectionManager {
    pub(crate) inner: Arc<ManagerInner>,
}

impl ConnectionManager {
    /// Bring up listeners, build TLS configs, install peer table, and return
    /// the handle along with the two inbound receivers.
    pub async fn start(cfg: TransportConfig) -> Result<(Self, Inbound), TransportError> {
        let identity = Arc::new(NodeIdentity::load(cfg.ca_path(), cfg.cert_path(), cfg.key_path())?);
        let (server_tls, client_tls) = build_tls_configs(&identity)?;

        let endpoints = build_endpoints(&cfg, identity.clone(), server_tls, client_tls)?;
        if !endpoints.any_configured() {
            return Err(ConfigError::NoListener.into());
        }

        let (high_tx, high_rx) = mpsc::channel(cfg.inbound_high_capacity());
        let (regular_tx, regular_rx) = mpsc::channel(cfg.inbound_regular_capacity());
        let inbound = InboundDispatch::new(high_tx, regular_tx);

        let inner = Arc::new(ManagerInner {
            self_id: identity.node_id(),
            peers: Arc::new(SccMap::new()),
            inbound,
            shutdown: CancellationToken::new(),
            endpoints,
            cfg,
        });

        super::endpoint::start_all(inner.clone()).await?;
        tokio::spawn(super::endpoint::run_supervisor(inner.clone()));

        Ok((ConnectionManager { inner }, Inbound::new(high_rx, regular_rx)))
    }

    pub fn local_node_id(&self) -> NodeIdentifier {
        self.inner.self_id
    }

    pub async fn add_address(&self, node: NodeIdentifier, addr: PeerAddress) {
        if node == self.inner.self_id {
            return;
        }
        let peer = self.inner.get_or_create_peer(node);
        let added = peer.add_address(addr);
        if added {
            debug!(peer=%node, ?addr, "address added");
        }
    }

    pub async fn remove_address(&self, node: NodeIdentifier, addr: PeerAddress) {
        if let Some(peer) = self.inner.get_peer(node) {
            peer.remove_address(addr);
        }
    }

    pub async fn forget_node(&self, node: NodeIdentifier) {
        if let Some(peer) = self.inner.remove_peer(node) {
            // Cancel any active streams.
            for kind in peer.live_kinds() {
                peer.drop_stream(kind);
            }
        }
    }

    /// Send a `Data` frame to `node` using the best transport satisfying
    /// `level`. Falls back to a stronger transport when the requested level's
    /// flavor isn't currently up; returns `NoSuitableTransport` if nothing
    /// qualifies.
    pub async fn send(
        &self,
        node: NodeIdentifier,
        level: ServiceLevel,
        class: MessageClass,
        payload: Bytes,
    ) -> Result<(), SendError> {
        let peer = self
            .inner
            .get_peer(node)
            .ok_or(SendError::UnknownNode { node })?;

        let chosen = pick_transport(&peer, level)
            .ok_or(SendError::NoSuitableTransport { node })?;

        self.send_stream(&peer, chosen, class, payload).await
    }

    /// Send via a specific transport, ignoring the fallback ordering. Useful
    /// for tests and for callers that already know which link they want.
    pub async fn send_via(
        &self,
        node: NodeIdentifier,
        transport: TransportKind,
        class: MessageClass,
        payload: Bytes,
    ) -> Result<(), SendError> {
        let peer = self
            .inner
            .get_peer(node)
            .ok_or(SendError::UnknownNode { node })?;
        self.send_stream(&peer, transport, class, payload).await
    }

    async fn send_stream(
        &self,
        peer: &Arc<PeerState>,
        kind: TransportKind,
        class: MessageClass,
        payload: Bytes,
    ) -> Result<(), SendError> {
        let sender = peer
            .try_get_stream(kind)
            .ok_or(SendError::StreamClosed { node: peer.node_id(), transport: kind })?;
        sender
            .try_send(OutboundFrame::new(class, payload))
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => SendError::Backpressure {
                    node: peer.node_id(),
                    transport: kind,
                },
                mpsc::error::TrySendError::Closed(_) => SendError::StreamClosed {
                    node: peer.node_id(),
                    transport: kind,
                },
            })?;
        Ok(())
    }

    pub fn metrics_snapshot(&self) -> MetricsSnapshot {
        let entries: Vec<_> = self
            .inner
            .iter_peers()
            .into_iter()
            .map(|(n, p)| (n, p.metrics().clone()))
            .collect();
        assemble_snapshot(entries)
    }

    pub async fn shutdown(&self) {
        self.inner.shutdown.cancel();
        // Drop streams.
        for (_, peer) in self.inner.iter_peers() {
            for k in peer.live_kinds() {
                peer.drop_stream(k);
            }
        }
    }
}

/// Pick a transport kind for `level`: prefer an exact-flavor match, then
/// fall back to a stronger kind. Only considers transports with a live
/// session (DTLS handshake completed for UDP, TLS for TCP/KCP, QUIC).
fn pick_transport(peer: &PeerState, level: ServiceLevel) -> Option<TransportKind> {
    let mut candidates: Vec<TransportKind> = peer
        .live_kinds()
        .into_iter()
        .filter(|k| k.service_level().satisfies(level))
        .collect();
    if candidates.is_empty() {
        return None;
    }

    // Prefer transports whose service-level == requested. Then sort by
    // service_level numeric (lower = stronger), then a stable kind order.
    candidates.sort_by_key(|k| {
        let provided = k.service_level();
        let exact_first = if provided == level { 0 } else { 1 };
        (exact_first, provided as u8, kind_order(*k))
    });
    candidates.first().copied()
}

fn kind_order(k: TransportKind) -> u8 {
    match k {
        TransportKind::Tcp => 3,
        TransportKind::Quic => 1,
        TransportKind::Kcp => 2,
        TransportKind::Udp => 0,
    }
}

/// Build every endpoint for which the corresponding `<kind>_listen` is set.
/// Each endpoint owns its own state; the `EndpointRegistry` returned is
/// stored inside `ManagerInner` for dial dispatch.
fn build_endpoints(
    cfg: &TransportConfig,
    identity: Arc<NodeIdentity>,
    server_tls: Arc<rustls::ServerConfig>,
    client_tls: Arc<rustls::ClientConfig>,
) -> Result<EndpointRegistry, TransportError> {
    let tcp = cfg.tcp_listen().map(|addr| {
        Arc::new(TcpEndpoint::new(server_tls.clone(), client_tls.clone(), Some(addr)))
    });
    let kcp = cfg.kcp_listen().map(|addr| {
        Arc::new(KcpEndpoint::new(server_tls.clone(), client_tls.clone(), Some(addr)))
    });
    let quic = match cfg.quic_listen() {
        Some(addr) => Some(Arc::new(
            QuicEndpoint::new(server_tls.clone(), client_tls.clone(), Some(addr))
                .map_err(|source| TransportError::Bind { addr, source })?,
        )),
        None => None,
    };
    let udp = cfg
        .udp_listen()
        .map(|addr| Arc::new(UdpEndpoint::new(identity, Some(addr))));

    Ok(EndpointRegistry::new(tcp, kcp, quic, udp))
}

