//! QUIC endpoint. Reuses the same rustls server/client configs as the TLS
//! stream transports. The bound `quinn::Endpoint` is built once at endpoint
//! construction time and shared between accept and dial.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{
    ClientConfig as QuinnClientConfig, Endpoint as QuinnEndpoint, ServerConfig as QuinnServerConfig,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, warn};

use super::super::connection::PeerState;
use super::super::identity::parse_peer_cn;
use super::super::manager::ManagerInner;
use super::super::native_stats;
use super::super::service_level::TransportKind;
use super::{Endpoint, install_stream_session};

/// QUIC endpoint state. Owns the bound `quinn::Endpoint` and the QUIC
/// client config used for outbound connections.
pub(crate) struct QuicEndpoint {
    accept_handle: Option<QuinnEndpoint>,
    client_v4: Option<QuinnEndpoint>,
    client_v6: Option<QuinnEndpoint>,
    client_cfg: QuinnClientConfig,
    listen_addr: Option<SocketAddr>,
}

impl QuicEndpoint {
    /// Build a `QuicEndpoint`. If `listen_addr` is `Some`, the endpoint is
    /// bound in server mode at that address (and can also be used to dial).
    /// If `None`, the endpoint binds an ephemeral client-only socket.
    pub fn new(
        server_tls: Arc<rustls::ServerConfig>,
        client_tls: Arc<rustls::ClientConfig>,
        listen_addr: Option<SocketAddr>,
    ) -> io::Result<Self> {
        let mut server_tls = (*server_tls).clone();
        server_tls.alpn_protocols = vec![b"s2s/1".to_vec()];

        let mut client_tls = (*client_tls).clone();
        client_tls.alpn_protocols = vec![b"s2s/1".to_vec()];
        let qcc: QuicClientConfig = client_tls
            .try_into()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e:?}")))?;
        let client_cfg = QuinnClientConfig::new(Arc::new(qcc));

        let accept_handle = match listen_addr {
            Some(addr) => {
                let qsc: QuicServerConfig = server_tls
                    .try_into()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e:?}")))?;
                let server_cfg = QuinnServerConfig::with_crypto(Arc::new(qsc));
                Some(QuinnEndpoint::server(server_cfg, addr)?)
            }
            None => None,
        };
        let (client_v4, client_v6) = build_client_endpoints()?;

        Ok(Self {
            accept_handle,
            client_v4,
            client_v6,
            client_cfg,
            listen_addr,
        })
    }

    fn client_handle(&self, addr: SocketAddr) -> io::Result<&QuinnEndpoint> {
        if addr.is_ipv4() {
            self.client_v4
                .as_ref()
                .or_else(|| self.accept_handle_for_family(addr))
                .ok_or_else(|| missing_client_socket(addr))
        } else {
            self.client_v6
                .as_ref()
                .or_else(|| self.accept_handle_for_family(addr))
                .ok_or_else(|| missing_client_socket(addr))
        }
    }

    fn accept_handle_for_family(&self, addr: SocketAddr) -> Option<&QuinnEndpoint> {
        let handle = self.accept_handle.as_ref()?;
        let local = handle.local_addr().ok()?;
        (local.is_ipv4() == addr.is_ipv4()).then_some(handle)
    }
}

fn build_client_endpoints() -> io::Result<(Option<QuinnEndpoint>, Option<QuinnEndpoint>)> {
    let client_v4 = bind_client_endpoint(SocketAddr::from(([0, 0, 0, 0], 0)));
    let client_v6 = bind_client_endpoint(SocketAddr::from(([0u16; 8], 0)));

    match (client_v4, client_v6) {
        (Ok(v4), Ok(v6)) => Ok((Some(v4), Some(v6))),
        (Ok(v4), Err(e)) => {
            debug!(error=%e, "quic IPv6 client socket unavailable");
            Ok((Some(v4), None))
        }
        (Err(e), Ok(v6)) => {
            debug!(error=%e, "quic IPv4 client socket unavailable");
            Ok((None, Some(v6)))
        }
        (Err(v4), Err(v6)) => Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("quic client socket bind failed for IPv4 ({v4}) and IPv6 ({v6})"),
        )),
    }
}

fn bind_client_endpoint(addr: SocketAddr) -> io::Result<QuinnEndpoint> {
    QuinnEndpoint::client(addr)
}

fn missing_client_socket(addr: SocketAddr) -> io::Error {
    io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        format!("no quic client socket is available for {addr}"),
    )
}

impl Endpoint for QuicEndpoint {
    const KIND: TransportKind = TransportKind::Quic;

    fn start(
        self: Arc<Self>,
        inner: Arc<ManagerInner>,
    ) -> impl Future<Output = io::Result<()>> + Send {
        async move {
            if self.listen_addr.is_none() {
                return Ok(());
            }
            let handle = self
                .accept_handle
                .clone()
                .ok_or_else(|| io::Error::other("quic listener missing accept endpoint"))?;
            debug!(addr=?handle.local_addr().ok(), "quic listener up");
            tokio::spawn(accept_loop(handle, inner));
            Ok(())
        }
    }

    fn dial(
        self: Arc<Self>,
        inner: Arc<ManagerInner>,
        peer: Arc<PeerState>,
        addr: SocketAddr,
    ) -> impl Future<Output = io::Result<()>> + Send {
        async move {
            let connecting = self
                .client_handle(addr)?
                .connect_with(
                    self.client_cfg.clone(),
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
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "no quic peer identity")
                })?;
            let peer_node = parse_peer_cn(&chain)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
            if peer_node != peer.node_id() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("peer cn {peer_node} != expected {}", peer.node_id()),
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
    }

    fn dial_unidentified(
        self: Arc<Self>,
        inner: Arc<ManagerInner>,
        addr: SocketAddr,
    ) -> impl Future<Output = io::Result<crate::types::NodeIdentifier>> + Send {
        async move {
            let connecting = self
                .client_handle(addr)?
                .connect_with(self.client_cfg.clone(), addr, "s2s-seed.local")
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
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "no quic peer identity")
                })?;
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
