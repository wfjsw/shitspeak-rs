//! KCP + mTLS endpoint. KCP gives reliability + low latency over UDP; we
//! layer rustls on top of `KcpStream` (which implements AsyncRead+AsyncWrite)
//! exactly like we do for TCP.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use rustls_pki_types::ServerName;
use tokio::sync::Semaphore;
use tokio_kcp::{KcpConfig, KcpListener, KcpNoDelayConfig, KcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, warn};

use super::super::config::KcpTuning;
use super::super::connection::PeerState;
use super::super::identity::parse_peer_cn;
use super::super::manager::ManagerInner;
use super::super::native_stats;
use super::super::service_level::TransportKind;
use super::{
    Endpoint, install_stream_session,
    mux::{DISCRIMINATOR_LEN, PrefixedUdpSocket, UdpMuxSet},
};

const KCP_MAX_LISTENER_SESSIONS: usize = 512;
const KCP_MAX_LISTENER_SESSIONS_PER_IP: usize = 32;
const KCP_MAX_INBOUND_HANDSHAKES: usize = 64;

pub(crate) struct KcpEndpoint {
    server_tls: Arc<rustls::ServerConfig>,
    client_tls: Arc<rustls::ClientConfig>,
    listen_addrs: Vec<SocketAddr>,
    mux: UdpMuxSet,
    kcp_tuning: KcpTuning,
}

impl KcpEndpoint {
    pub fn new(
        server_tls: Arc<rustls::ServerConfig>,
        client_tls: Arc<rustls::ClientConfig>,
        listen_addrs: impl IntoIterator<Item = SocketAddr>,
        mux: UdpMuxSet,
        kcp_tuning: KcpTuning,
    ) -> Self {
        Self {
            server_tls,
            client_tls,
            listen_addrs: listen_addrs.into_iter().collect(),
            mux,
            kcp_tuning,
        }
    }
}

impl Endpoint for KcpEndpoint {
    async fn start(self: Arc<Self>, inner: Arc<ManagerInner>) -> io::Result<()> {
        let acceptor = TlsAcceptor::from(self.server_tls.clone());
        for addr in self.listen_addrs.iter().copied() {
            let handle = self
                .mux
                .take_handle(addr, TransportKind::Kcp, inner.shutdown().child_token())
                .await?;
            let cfg = kcp_config(self.kcp_tuning);
            let listener = KcpListener::from_io(cfg, Arc::new(handle))
                .await
                .map_err(|e| io::Error::other(format!("kcp mux bind {addr}: {e}")))?;
            debug!(%addr, "kcp listener up");
            tokio::spawn(accept_loop(
                listener,
                acceptor.clone(),
                inner.clone(),
                Arc::new(Semaphore::new(KCP_MAX_INBOUND_HANDSHAKES)),
            ));
        }
        Ok(())
    }

    async fn dial(
        self: Arc<Self>,
        inner: Arc<ManagerInner>,
        peer: Arc<PeerState>,
        addr: SocketAddr,
    ) -> io::Result<()> {
        let cfg = kcp_config(self.kcp_tuning);
        let sock = connect_kcp_stream(&cfg, addr)
            .await
            .map_err(|e| io::Error::other(format!("kcp connect: {e}")))?;
        let native_sampler = native_stats::kcp_sampler(&sock);
        let connector = TlsConnector::from(self.client_tls.clone());
        let server_name =
            ServerName::try_from(format!("node-{}", peer.node_id())).expect("static name parses");
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
            TransportKind::Kcp,
            Some(addr),
            true,
            tls,
            native_sampler,
        );
        Ok(())
    }

    async fn dial_unidentified(
        self: Arc<Self>,
        inner: Arc<ManagerInner>,
        addr: SocketAddr,
    ) -> io::Result<crate::types::NodeIdentifier> {
        let cfg = kcp_config(self.kcp_tuning);
        let sock = connect_kcp_stream(&cfg, addr)
            .await
            .map_err(|e| io::Error::other(format!("kcp connect: {e}")))?;
        let native_sampler = native_stats::kcp_sampler(&sock);
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
            TransportKind::Kcp,
            Some(addr),
            true,
            tls,
            native_sampler,
        );
        Ok(peer_node)
    }
}

fn kcp_config(tuning: KcpTuning) -> KcpConfig {
    let mut cfg = KcpConfig::default();
    cfg.nodelay = KcpNoDelayConfig {
        nodelay: tuning.nodelay(),
        interval: tuning.interval_ms().min(i32::MAX as u32) as i32,
        resend: tuning.fast_resend().min(i32::MAX as u32) as i32,
        nc: tuning.no_congestion(),
    };
    cfg.flush_write = tuning.flush_write();
    cfg.flush_acks_input = tuning.flush_acks_input();
    cfg.no_progress_timeout = tuning.no_progress_close();
    cfg.mtu = cfg.mtu.saturating_sub(DISCRIMINATOR_LEN);
    cfg.with_max_sessions(KCP_MAX_LISTENER_SESSIONS)
        .with_max_sessions_per_ip(KCP_MAX_LISTENER_SESSIONS_PER_IP)
}

async fn connect_kcp_stream(
    cfg: &KcpConfig,
    addr: SocketAddr,
) -> Result<KcpStream, Box<dyn std::error::Error + Send + Sync>> {
    let socket = PrefixedUdpSocket::bind_ephemeral(addr, TransportKind::Kcp).await?;
    Ok(KcpStream::connect_with_io(cfg, Arc::new(socket), addr).await?)
}

async fn accept_loop(
    mut listener: KcpListener,
    acceptor: TlsAcceptor,
    inner: Arc<ManagerInner>,
    inbound_handshakes: Arc<Semaphore>,
) {
    loop {
        tokio::select! {
            _ = inner.shutdown().cancelled() => return,
            accept = listener.accept() => {
                let (sock, peer_addr) = match accept {
                    Ok(v) => v,
                    Err(e) => { warn!(error=%e, "kcp accept failed"); continue; }
                };
                let Ok(permit) = inbound_handshakes.clone().try_acquire_owned() else {
                    warn!(
                        %peer_addr,
                        max_inbound_handshakes = KCP_MAX_INBOUND_HANDSHAKES,
                        "dropping KCP inbound stream: handshake cap reached"
                    );
                    continue;
                };
                let inner_c = inner.clone();
                let acceptor_c = acceptor.clone();
                tokio::spawn(async move {
                    let _permit = permit;
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
    let native_sampler = native_stats::kcp_sampler(&sock);
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
        .note_observed_remote_addr(TransportKind::Kcp, peer_addr);
    install_stream_session(
        &inner,
        peer_node,
        TransportKind::Kcp,
        Some(peer_addr),
        false,
        tls,
        native_sampler,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kcp_config_applies_realtime_defaults() {
        let cfg = kcp_config(KcpTuning::default());

        assert!(cfg.nodelay.nodelay);
        assert_eq!(cfg.nodelay.interval, 10);
        assert_eq!(cfg.nodelay.resend, 2);
        assert!(!cfg.nodelay.nc);
        assert!(cfg.flush_write);
        assert!(cfg.flush_acks_input);
    }

    #[test]
    fn kcp_config_reserves_discriminator_mtu_budget() {
        let cfg = kcp_config(KcpTuning::default());
        assert_eq!(cfg.mtu, KcpConfig::default().mtu - DISCRIMINATOR_LEN);
    }
}
