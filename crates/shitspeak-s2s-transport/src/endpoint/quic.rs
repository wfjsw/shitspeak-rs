//! QUIC endpoint. Reuses the same rustls server/client configs as the TLS
//! stream transports. The bound `quinn::Endpoint` is built once at endpoint
//! construction time and shared between accept and dial.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{
    ClientConfig as QuinnClientConfig, Endpoint as QuinnEndpoint, EndpointConfig,
    ServerConfig as QuinnServerConfig, TransportConfig as QuinnTransportConfig, default_runtime,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, warn};

use super::super::connection::PeerState;
use super::super::identity::parse_peer_cn;
use super::super::manager::ManagerInner;
use super::super::native_stats;
use super::super::service_level::TransportKind;
use super::{
    Endpoint, install_stream_session,
    mux::{DISCRIMINATOR_LEN, PrefixedUdpSocket, UdpMuxSet},
};

/// QUIC endpoint state. Owns the bound `quinn::Endpoint` and the QUIC
/// client config used for outbound connections.
pub(crate) struct QuicEndpoint {
    listen_addrs: Vec<SocketAddr>,
    server_cfg: QuinnServerConfig,
    accept_handles: parking_lot::Mutex<Vec<AcceptEndpoint>>,
    client_cfg: QuinnClientConfig,
    mux: UdpMuxSet,
}

struct AcceptEndpoint {
    handle: QuinnEndpoint,
}

pub(crate) struct QuicBindError {
    addr: SocketAddr,
    source: io::Error,
}

impl QuicBindError {
    pub(crate) fn into_parts(self) -> (SocketAddr, io::Error) {
        (self.addr, self.source)
    }
}

impl QuicEndpoint {
    /// Build a `QuicEndpoint`. If `listen_addrs` is non-empty, each address is
    /// bound in server mode. Empty listeners preserve dial-only operation.
    pub fn new(
        server_tls: Arc<rustls::ServerConfig>,
        client_tls: Arc<rustls::ClientConfig>,
        listen_addrs: impl IntoIterator<Item = SocketAddr>,
        mux: UdpMuxSet,
    ) -> Result<Self, QuicBindError> {
        let listen_addrs = listen_addrs.into_iter().collect::<Vec<_>>();
        let mut server_tls = (*server_tls).clone();
        server_tls.alpn_protocols = vec![b"s2s/1".to_vec()];

        let mut client_tls = (*client_tls).clone();
        client_tls.alpn_protocols = vec![b"s2s/1".to_vec()];
        let qcc: QuicClientConfig = client_tls
            .try_into()
            .map_err(|e| quic_config_error(SocketAddr::from(([0, 0, 0, 0], 0)), e))?;
        let mut client_cfg = QuinnClientConfig::new(Arc::new(qcc));
        client_cfg.transport_config(quic_transport_config());

        let qsc: QuicServerConfig = server_tls
            .try_into()
            .map_err(|e| quic_config_error(first_listen_addr(&listen_addrs), e))?;
        let server_cfg = QuinnServerConfig::with_crypto(Arc::new(qsc));
        Ok(Self {
            listen_addrs,
            server_cfg,
            accept_handles: parking_lot::Mutex::new(Vec::new()),
            client_cfg,
            mux,
        })
    }

    async fn client_handle(&self, addr: SocketAddr) -> io::Result<QuinnEndpoint> {
        bind_prefixed_client_endpoint(addr).await
    }

    fn client_config_for_path(&self) -> QuinnClientConfig {
        let mut cfg = self.client_cfg.clone();
        cfg.transport_config(quic_transport_config());
        cfg
    }
}

fn first_listen_addr(listen_addrs: &[SocketAddr]) -> SocketAddr {
    listen_addrs
        .first()
        .copied()
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)))
}

fn quic_config_error<E: std::fmt::Debug>(addr: SocketAddr, error: E) -> QuicBindError {
    QuicBindError {
        addr,
        source: io::Error::new(io::ErrorKind::InvalidInput, format!("{error:?}")),
    }
}

fn bind_mux_server_endpoint(
    server_cfg: QuinnServerConfig,
    handle: super::mux::UdpMuxHandle,
) -> io::Result<QuinnEndpoint> {
    let runtime = default_runtime().ok_or_else(|| io::Error::other("no async runtime found"))?;
    QuinnEndpoint::new_with_abstract_socket(
        endpoint_config()?,
        Some(server_cfg),
        Arc::new(handle),
        runtime,
    )
}

async fn bind_prefixed_client_endpoint(addr: SocketAddr) -> io::Result<QuinnEndpoint> {
    let socket = PrefixedUdpSocket::bind_ephemeral(addr, TransportKind::Quic).await?;
    let runtime = default_runtime().ok_or_else(|| io::Error::other("no async runtime found"))?;
    QuinnEndpoint::new_with_abstract_socket(endpoint_config()?, None, Arc::new(socket), runtime)
}

fn endpoint_config() -> io::Result<EndpointConfig> {
    let mut cfg = EndpointConfig::default();
    let max_payload = 1472usize.saturating_sub(DISCRIMINATOR_LEN);
    cfg.max_udp_payload_size(max_payload as u16)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e:?}")))?;
    Ok(cfg)
}

fn quic_transport_config() -> Arc<QuinnTransportConfig> {
    let mut transport = QuinnTransportConfig::default();
    let mtu = 1200u16.saturating_sub(DISCRIMINATOR_LEN as u16);
    transport.initial_mtu(mtu);
    transport.min_mtu(mtu);
    Arc::new(transport)
}

impl Endpoint for QuicEndpoint {
    async fn start(self: Arc<Self>, inner: Arc<ManagerInner>) -> io::Result<()> {
        let mut handles = Vec::with_capacity(self.listen_addrs.len());
        for addr in self.listen_addrs.iter().copied() {
            let mux_handle = self
                .mux
                .take_handle(addr, TransportKind::Quic, inner.shutdown().child_token())
                .await?;
            let mut server_cfg = self.server_cfg.clone();
            server_cfg.transport = quic_transport_config();
            let handle = bind_mux_server_endpoint(server_cfg, mux_handle)
                .map_err(|e| io::Error::new(e.kind(), format!("quic mux bind {addr}: {e}")))?;
            handles.push(AcceptEndpoint { handle });
        }
        *self.accept_handles.lock() = handles;
        for accept in self.accept_handles.lock().iter() {
            let handle = accept.handle.clone();
            debug!(addr=?handle.local_addr().ok(), "quic listener up");
            tokio::spawn(accept_loop(handle, inner.clone()));
        }
        Ok(())
    }

    async fn dial(
        self: Arc<Self>,
        inner: Arc<ManagerInner>,
        peer: Arc<PeerState>,
        addr: SocketAddr,
    ) -> io::Result<()> {
        let connecting = self
            .client_handle(addr)
            .await?
            .connect_with(
                self.client_config_for_path(),
                addr,
                &format!("node-{}", peer.node_id()),
            )
            .map_err(|e| io::Error::other(format!("quic connect_with: {e}")))?;
        let conn = connecting
            .await
            .map_err(|e| io::Error::other(format!("quic connecting: {e}")))?;
        let chain = conn
            .peer_identity()
            .and_then(|d| {
                d.downcast::<Vec<rustls_pki_types::CertificateDer<'static>>>()
                    .ok()
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no quic peer identity"))?;
        let peer_node = parse_peer_cn(&chain)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
        if peer_node != peer.node_id() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "peer certificate node id {peer_node} != expected {}",
                    peer.node_id()
                ),
            ));
        }
        let native_sampler = Some(native_stats::quic_sampler(conn.clone()));
        let (send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| io::Error::other(format!("quic open_bi: {e}")))?;
        install_stream_session(
            &inner,
            peer_node,
            TransportKind::Quic,
            Some(addr),
            true,
            BiStream { send, recv },
            native_sampler,
        );
        Ok(())
    }

    async fn dial_unidentified(
        self: Arc<Self>,
        inner: Arc<ManagerInner>,
        addr: SocketAddr,
    ) -> io::Result<crate::types::NodeIdentifier> {
        let connecting = self
            .client_handle(addr)
            .await?
            .connect_with(self.client_config_for_path(), addr, "s2s-seed.local")
            .map_err(|e| io::Error::other(format!("quic connect_with: {e}")))?;
        let conn = connecting
            .await
            .map_err(|e| io::Error::other(format!("quic connecting: {e}")))?;
        let chain = conn
            .peer_identity()
            .and_then(|d| {
                d.downcast::<Vec<rustls_pki_types::CertificateDer<'static>>>()
                    .ok()
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no quic peer identity"))?;
        let peer_node = parse_peer_cn(&chain)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
        if peer_node == inner.self_id() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "self-loop rejected",
            ));
        }
        let native_sampler = Some(native_stats::quic_sampler(conn.clone()));
        let (send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| io::Error::other(format!("quic open_bi: {e}")))?;
        install_stream_session(
            &inner,
            peer_node,
            TransportKind::Quic,
            Some(addr),
            true,
            BiStream { send, recv },
            native_sampler,
        );
        Ok(peer_node)
    }
}

async fn accept_loop(handle: QuinnEndpoint, inner: Arc<ManagerInner>) {
    loop {
        tokio::select! {
            _ = inner.shutdown().cancelled() => return,
            incoming = handle.accept() => {
                let Some(incoming) = incoming else { return };
                let inner_c = inner.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_incoming(inner_c, incoming).await {
                        if is_peer_closed_quic_inbound(&e) {
                            debug!(error=%e, "quic inbound closed by peer during setup");
                        } else {
                            warn!(error=%e, "quic inbound failed");
                        }
                    }
                });
            }
        }
    }
}

fn is_peer_closed_quic_inbound(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::UnexpectedEof
    ) || error.to_string().contains("closed by peer")
}

async fn handle_incoming(inner: Arc<ManagerInner>, incoming: quinn::Incoming) -> io::Result<()> {
    let conn = incoming
        .await
        .map_err(|e| io::Error::other(format!("quic connect: {e}")))?;
    let remote_addr = conn.remote_address();
    let chain = conn
        .peer_identity()
        .and_then(|d| {
            d.downcast::<Vec<rustls_pki_types::CertificateDer<'static>>>()
                .ok()
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no quic peer identity"))?;
    let peer_node = parse_peer_cn(&chain)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
    if peer_node == inner.self_id() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "self-loop rejected",
        ));
    }
    inner
        .get_or_create_peer(peer_node)
        .note_observed_remote_addr(TransportKind::Quic, remote_addr);
    let native_sampler = Some(native_stats::quic_sampler(conn.clone()));
    let (send, recv) = conn
        .accept_bi()
        .await
        .map_err(|e| io::Error::other(format!("quic accept_bi: {e}")))?;
    install_stream_session(
        &inner,
        peer_node,
        TransportKind::Quic,
        Some(remote_addr),
        false,
        BiStream { send, recv },
        native_sampler,
    );
    Ok(())
}

/// Joins a quinn `SendStream` + `RecvStream` into one `AsyncRead + AsyncWrite`.
struct BiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl AsyncRead for BiStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        <quinn::RecvStream as AsyncRead>::poll_read(std::pin::Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for BiStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        <quinn::SendStream as AsyncWrite>::poll_write(std::pin::Pin::new(&mut self.send), cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        <quinn::SendStream as AsyncWrite>::poll_flush(std::pin::Pin::new(&mut self.send), cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        <quinn::SendStream as AsyncWrite>::poll_shutdown(std::pin::Pin::new(&mut self.send), cx)
    }
}
