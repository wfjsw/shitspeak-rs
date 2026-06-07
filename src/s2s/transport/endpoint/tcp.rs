//! TCP + mTLS endpoint.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use rustls_pki_types::ServerName;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, warn};

use super::super::connection::PeerState;
use super::super::identity::parse_peer_cn;
use super::super::manager::ManagerInner;
use super::super::native_stats;
use super::super::service_level::TransportKind;
use super::{Endpoint, bind_tcp_listener, install_stream_session, ipv6_only_for_address};

/// TCP endpoint state. Holds the rustls server/client configs and the
/// listen address. The TLS configs are shared (and built once) by the
/// manager at construction time.
pub(crate) struct TcpEndpoint {
    server_tls: Arc<rustls::ServerConfig>,
    client_tls: Arc<rustls::ClientConfig>,
    listen_addrs: Vec<SocketAddr>,
}

impl TcpEndpoint {
    pub fn new(
        server_tls: Arc<rustls::ServerConfig>,
        client_tls: Arc<rustls::ClientConfig>,
        listen_addrs: impl IntoIterator<Item = SocketAddr>,
    ) -> Self {
        Self {
            server_tls,
            client_tls,
            listen_addrs: listen_addrs.into_iter().collect(),
        }
    }
}

impl Endpoint for TcpEndpoint {
    const KIND: TransportKind = TransportKind::Tcp;

    fn start(
        self: Arc<Self>,
        inner: Arc<ManagerInner>,
    ) -> impl Future<Output = io::Result<()>> + Send {
        async move {
            let acceptor = TlsAcceptor::from(self.server_tls.clone());
            for addr in self.listen_addrs.iter().copied() {
                let ipv6_only = ipv6_only_for_address(addr, &self.listen_addrs);
                let listener = bind_tcp_listener(addr, ipv6_only).await?;
                debug!(%addr, %ipv6_only, "tcp listener up");
                tokio::spawn(accept_loop(listener, acceptor.clone(), inner.clone()));
            }
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
            let sock = TcpStream::connect(addr).await?;
            let _ = sock.set_nodelay(true);
            let native_sampler = native_stats::tcp_sampler(&sock);
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
                    format!(
                        "peer certificate node id {peer_node} != expected {}",
                        peer.node_id()
                    ),
                ));
            }
            install_stream_session(
                &inner,
                peer_node,
                TransportKind::Tcp,
                Some(addr),
                true,
                tls,
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
            let sock = TcpStream::connect(addr).await?;
            let _ = sock.set_nodelay(true);
            let native_sampler = native_stats::tcp_sampler(&sock);
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
            install_stream_session(
                &inner,
                peer_node,
                TransportKind::Tcp,
                Some(addr),
                true,
                tls,
                native_sampler,
            );
            Ok(peer_node)
        }
    }
}

async fn accept_loop(listener: TcpListener, acceptor: TlsAcceptor, inner: Arc<ManagerInner>) {
    loop {
        tokio::select! {
            _ = inner.shutdown().cancelled() => return,
            accept = listener.accept() => {
                let (sock, peer_addr) = match accept {
                    Ok(v) => v,
                    Err(e) => { warn!(error=%e, "tcp accept failed"); continue; }
                };
                let inner_c = inner.clone();
                let acceptor_c = acceptor.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_inbound(inner_c, acceptor_c, sock, peer_addr).await {
                        warn!(error=%e, %peer_addr, "tcp inbound handshake failed");
                    }
                });
            }
        }
    }
}

async fn handle_inbound(
    inner: Arc<ManagerInner>,
    acceptor: TlsAcceptor,
    sock: TcpStream,
    peer_addr: SocketAddr,
) -> io::Result<()> {
    let _ = sock.set_nodelay(true);
    let native_sampler = native_stats::tcp_sampler(&sock);
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
        .note_observed_remote_addr(TransportKind::Tcp, peer_addr);
    install_stream_session(
        &inner,
        peer_node,
        TransportKind::Tcp,
        Some(peer_addr),
        false,
        tls,
        native_sampler,
    );
    Ok(())
}
