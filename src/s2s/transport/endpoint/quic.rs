//! QUIC endpoint. Reuses the same rustls server/client configs as the TLS
//! stream transports. The bound `quinn::Endpoint` is built once at endpoint
//! construction time and shared between accept and dial.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{
    ClientConfig as QuinnClientConfig, Endpoint as QuinnEndpoint,
    ServerConfig as QuinnServerConfig,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, warn};

use super::super::connection::PeerState;
use super::super::identity::parse_peer_cn;
use super::super::manager::ManagerInner;
use super::super::service_level::TransportKind;
use super::{install_stream_session, Endpoint};

/// QUIC endpoint state. Owns the bound `quinn::Endpoint` and the QUIC
/// client config used for outbound connections.
pub(crate) struct QuicEndpoint {
    handle: QuinnEndpoint,
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

        let handle = match listen_addr {
            Some(addr) => {
                let qsc: QuicServerConfig = server_tls
                    .try_into()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e:?}")))?;
                let server_cfg = QuinnServerConfig::with_crypto(Arc::new(qsc));
                QuinnEndpoint::server(server_cfg, addr)?
            }
            None => QuinnEndpoint::client("[::]:0".parse().unwrap())?,
        };

        Ok(Self { handle, client_cfg, listen_addr })
    }
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
            debug!(addr=?self.handle.local_addr().ok(), "quic listener up");
            tokio::spawn(accept_loop(self.clone(), inner));
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
                .handle
                .connect_with(self.client_cfg.clone(), addr, &format!("node-{}", peer.node_id()))
                .map_err(|e| io::Error::other(format!("quic connect_with: {e}")))?;
            let conn = connecting
                .await
                .map_err(|e| io::Error::other(format!("quic connecting: {e}")))?;
            let chain = conn
                .peer_identity()
                .and_then(|d| d.downcast::<Vec<rustls_pki_types::CertificateDer<'static>>>().ok())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no quic peer identity"))?;
            let peer_node = parse_peer_cn(&chain)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
            if peer_node != peer.node_id() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("peer cn {peer_node} != expected {}", peer.node_id()),
                ));
            }
            let (send, recv) = conn
                .open_bi()
                .await
                .map_err(|e| io::Error::other(format!("quic open_bi: {e}")))?;
            install_stream_session(
                &inner,
                peer_node,
                TransportKind::Quic,
                true,
                BiStream { send, recv },
            );
            Ok(())
        }
    }
}

async fn accept_loop(ep: Arc<QuicEndpoint>, inner: Arc<ManagerInner>) {
    loop {
        tokio::select! {
            _ = inner.shutdown().cancelled() => return,
            incoming = ep.handle.accept() => {
                let Some(incoming) = incoming else { return };
                let inner_c = inner.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_incoming(inner_c, incoming).await {
                        warn!(error=%e, "quic inbound failed");
                    }
                });
            }
        }
    }
}

async fn handle_incoming(inner: Arc<ManagerInner>, incoming: quinn::Incoming) -> io::Result<()> {
    let conn = incoming
        .await
        .map_err(|e| io::Error::other(format!("quic connect: {e}")))?;
    let chain = conn
        .peer_identity()
        .and_then(|d| d.downcast::<Vec<rustls_pki_types::CertificateDer<'static>>>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no quic peer identity"))?;
    let peer_node = parse_peer_cn(&chain)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
    if peer_node == inner.self_id() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "self-loop rejected"));
    }
    let (send, recv) = conn
        .accept_bi()
        .await
        .map_err(|e| io::Error::other(format!("quic accept_bi: {e}")))?;
    install_stream_session(
        &inner,
        peer_node,
        TransportKind::Quic,
        false,
        BiStream { send, recv },
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
