//! KCP + mTLS endpoint. KCP gives reliability + low latency over UDP; we
//! layer rustls on top of `KcpStream` (which implements AsyncRead+AsyncWrite)
//! exactly like we do for TCP.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use rustls_pki_types::ServerName;
use tokio_kcp::{KcpConfig, KcpListener, KcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, warn};

use super::super::connection::PeerState;
use super::super::identity::parse_peer_cn;
use super::super::manager::ManagerInner;
use super::super::service_level::TransportKind;
use super::{
    bind_reusable_udp_socket, bind_transport_udp_socket, install_stream_session, Endpoint,
};

pub(crate) struct KcpEndpoint {
    server_tls: Arc<rustls::ServerConfig>,
    client_tls: Arc<rustls::ClientConfig>,
    listen_addr: Option<SocketAddr>,
}

impl KcpEndpoint {
    pub fn new(
        server_tls: Arc<rustls::ServerConfig>,
        client_tls: Arc<rustls::ClientConfig>,
        listen_addr: Option<SocketAddr>,
    ) -> Self {
        Self {
            server_tls,
            client_tls,
            listen_addr,
        }
    }
}

impl Endpoint for KcpEndpoint {
    const KIND: TransportKind = TransportKind::Kcp;

    fn start(
        self: Arc<Self>,
        inner: Arc<ManagerInner>,
    ) -> impl Future<Output = io::Result<()>> + Send {
        async move {
            let Some(addr) = self.listen_addr else {
                return Ok(());
            };
            let cfg = KcpConfig::default();
            let socket = bind_reusable_udp_socket(addr).await?;
            let listener = KcpListener::from_socket(cfg, socket)
                .await
                .map_err(|e| io::Error::other(format!("kcp bind: {e}")))?;
            let acceptor = TlsAcceptor::from(self.server_tls.clone());
            debug!(%addr, "kcp listener up");
            tokio::spawn(accept_loop(listener, acceptor, inner));
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
            let cfg = KcpConfig::default();
            let socket = bind_transport_udp_socket(self.listen_addr, addr).await?;
            let sock = KcpStream::connect_with_socket(&cfg, socket, addr)
                .await
                .map_err(|e| io::Error::other(format!("kcp connect: {e}")))?;
            let connector = TlsConnector::from(self.client_tls.clone());
            let server_name = ServerName::try_from(format!("node-{}", peer.node_id()))
                .expect("static name parses");
            let tls = connector.connect(server_name, sock).await?;
            let (_, client) = tls.get_ref();
            let chain = client
                .peer_certificates()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no peer cert chain"))?;
            let peer_node = parse_peer_cn(chain)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
            if peer_node != peer.node_id() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("peer cn {peer_node} != expected {}", peer.node_id()),
                ));
            }
            install_stream_session(&inner, peer_node, TransportKind::Kcp, Some(addr), true, tls);
            Ok(())
        }
    }

    fn dial_unidentified(
        self: Arc<Self>,
        inner: Arc<ManagerInner>,
        addr: SocketAddr,
    ) -> impl Future<Output = io::Result<crate::types::NodeIdentifier>> + Send {
        async move {
            let cfg = KcpConfig::default();
            let socket = bind_transport_udp_socket(self.listen_addr, addr).await?;
            let sock = KcpStream::connect_with_socket(&cfg, socket, addr)
                .await
                .map_err(|e| io::Error::other(format!("kcp connect: {e}")))?;
            let connector = TlsConnector::from(self.client_tls.clone());
            let server_name = ServerName::try_from("s2s-seed.local").expect("static name parses");
            let tls = connector.connect(server_name, sock).await?;
            let (_, client) = tls.get_ref();
            let chain = client
                .peer_certificates()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no peer cert chain"))?;
            let peer_node = parse_peer_cn(chain)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
            if peer_node == inner.self_id() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "self-loop rejected",
                ));
            }
            install_stream_session(&inner, peer_node, TransportKind::Kcp, Some(addr), true, tls);
            Ok(peer_node)
        }
    }
}

async fn accept_loop(mut listener: KcpListener, acceptor: TlsAcceptor, inner: Arc<ManagerInner>) {
    loop {
        tokio::select! {
            _ = inner.shutdown().cancelled() => return,
            accept = listener.accept() => {
                let (sock, peer_addr) = match accept {
                    Ok(v) => v,
                    Err(e) => { warn!(error=%e, "kcp accept failed"); continue; }
                };
                let inner_c = inner.clone();
                let acceptor_c = acceptor.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_inbound(inner_c, acceptor_c, sock, peer_addr).await {
                        warn!(error=%e, %peer_addr, "kcp inbound handshake failed");
                    }
                });
            }
        }
    }
}

async fn handle_inbound(
    inner: Arc<ManagerInner>,
    acceptor: TlsAcceptor,
    sock: KcpStream,
    peer_addr: SocketAddr,
) -> io::Result<()> {
    let tls = acceptor.accept(sock).await?;
    let (_, server) = tls.get_ref();
    let chain = server
        .peer_certificates()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no peer cert chain"))?;
    let peer_node = parse_peer_cn(chain)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
    if peer_node == inner.self_id() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "self-loop rejected",
        ));
    }
    inner
        .get_or_create_peer(peer_node)
        .note_observed_remote_addr(peer_addr);
    install_stream_session(
        &inner,
        peer_node,
        TransportKind::Kcp,
        Some(peer_addr),
        false,
        tls,
    );
    Ok(())
}
