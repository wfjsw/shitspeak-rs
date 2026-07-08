use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use byte_string::ByteStr;
use kcp::{Error as KcpError, KcpResult};
use log::{debug, error, trace};
use tokio::{
    net::{ToSocketAddrs, UdpSocket},
    sync::mpsc,
    task::JoinHandle,
    time,
};

use crate::{
    config::KcpConfig,
    session::{KcpSessionManager, SessionInputError},
    stream::KcpStream,
    udp_io::SharedUdpIo,
};

#[derive(Debug)]
pub struct KcpListener {
    udp: SharedUdpIo,
    accept_rx: mpsc::Receiver<(KcpStream, SocketAddr)>,
    task_watcher: JoinHandle<()>,
}

impl Drop for KcpListener {
    fn drop(&mut self) {
        self.task_watcher.abort();
    }
}

impl KcpListener {
    /// Create an `KcpListener` bound to `addr`
    pub async fn bind<A: ToSocketAddrs>(config: KcpConfig, addr: A) -> KcpResult<KcpListener> {
        let udp = UdpSocket::bind(addr).await?;
        KcpListener::from_socket(config, udp).await
    }

    /// Create a `KcpListener` from an existed `UdpSocket`
    pub async fn from_socket(config: KcpConfig, udp: UdpSocket) -> KcpResult<KcpListener> {
        let udp = Arc::new(udp);
        KcpListener::from_io(config, udp).await
    }

    /// Create a `KcpListener` from abstract UDP I/O.
    pub async fn from_io(config: KcpConfig, udp: SharedUdpIo) -> KcpResult<KcpListener> {
        let server_udp = udp.clone();

        let (accept_tx, accept_rx) = mpsc::channel(1024 /* backlogs */);
        let task_watcher = tokio::spawn(async move {
            let (close_tx, mut close_rx) = mpsc::channel(64);

            let mut sessions = KcpSessionManager::new();
            let mut packet_buffer = [0u8; 65536];
            loop {
                tokio::select! {
                    peer_addr = close_rx.recv() => {
                        let peer_addr = peer_addr.expect("close_tx closed unexpectedly");
                        sessions.close_peer(peer_addr);
                        trace!("session peer_addr: {} removed", peer_addr);
                    }

                    recv_res = udp.recv_from(&mut packet_buffer) => {
                        match recv_res {
                            Err(err)
                                if matches!(err.kind(), ErrorKind::ConnectionReset | ErrorKind::Interrupted) =>
                            {
                                trace!("udp.recv_from transient failure, error: {}", err);
                            }
                            Err(err) => {
                                error!("udp.recv_from failed, error: {}", err);
                                time::sleep(Duration::from_secs(1)).await;
                            }
                            Ok((n, peer_addr)) => {
                                let packet = &mut packet_buffer[..n];

                                trace!("received peer: {}, {:?}", peer_addr, ByteStr::new(packet));

                                if packet.len() < kcp::KCP_OVERHEAD {
                                    error!("packet too short, received {} bytes, but at least {} bytes",
                                           packet.len(),
                                           kcp::KCP_OVERHEAD);
                                    continue;
                                }

                                let mut conv = kcp::get_conv(packet);
                                if conv == 0 {
                                    // Allocate a conv for client.
                                    conv = sessions.alloc_conv();
                                    debug!("allocate {} conv for peer: {}", conv, peer_addr);

                                    kcp::set_conv(packet, conv);
                                }

                                let sn = kcp::get_sn(packet);

                                let is_new_peer = sessions.get_peer(peer_addr).is_none();
                                if is_new_peer && sessions.is_full(config.max_sessions()) {
                                    debug!(
                                        "dropping new KCP session from {}: listener session cap {} reached",
                                        peer_addr,
                                        config.max_sessions()
                                    );
                                    continue;
                                }
                                if is_new_peer
                                    && sessions.ip_is_full(peer_addr.ip(), config.max_sessions_per_ip())
                                {
                                    debug!(
                                        "dropping new KCP session from {}: per-IP session cap {} reached",
                                        peer_addr,
                                        config.max_sessions_per_ip()
                                    );
                                    continue;
                                }

                                let session = match sessions.get_or_create(&config, conv, sn, &udp, peer_addr, &close_tx).await {
                                    Ok((s, created)) => {
                                        if created {
                                            // Created a new session, constructed a new accepted client
                                            let stream = KcpStream::with_session(s.clone());
                                            if  accept_tx.try_send((stream, peer_addr)).is_err() {
                                                debug!("failed to create accepted stream due to channel failure");

                                                // remove it from session
                                                sessions.close_peer(peer_addr);
                                                continue;
                                            }
                                        } else {
                                            let session_conv = s.conv().await;
                                            if session_conv != conv {
                                                debug!("received peer: {} with conv: {} not match with session conv: {}",
                                                       peer_addr,
                                                       conv,
                                                       session_conv);
                                                continue;
                                            }
                                        }

                                        s
                                    },
                                    Err(err) => {
                                        error!("failed to create session, error: {}, peer: {}, conv: {}", err, peer_addr, conv);
                                        continue;
                                    }
                                };

                                // let mut kcp = session.kcp_socket().lock().await;
                                // if let Err(err) = kcp.input(packet) {
                                //     error!("kcp.input failed, peer: {}, conv: {}, error: {}, packet: {:?}", peer_addr, conv, err, ByteStr::new(packet));
                                // }
                                match session.try_input(packet) {
                                    Ok(()) => {}
                                    Err(SessionInputError::Closed) => {
                                        trace!("[SESSION] KCP session is closing while listener tries to input");
                                    }
                                    Err(SessionInputError::Full) => {
                                        trace!("[SESSION] KCP session input queue full; dropping datagram");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        Ok(KcpListener {
            udp: server_udp,
            accept_rx,
            task_watcher,
        })
    }

    /// Accept a new connected `KcpStream`
    pub async fn accept(&mut self) -> KcpResult<(KcpStream, SocketAddr)> {
        match self.accept_rx.recv().await {
            Some(s) => Ok(s),
            None => Err(KcpError::IoError(io::Error::new(
                ErrorKind::Other,
                "accept channel closed unexpectedly",
            ))),
        }
    }

    pub fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<KcpResult<(KcpStream, SocketAddr)>> {
        self.accept_rx.poll_recv(cx).map(|op_res| {
            op_res.ok_or_else(|| {
                KcpError::IoError(io::Error::new(ErrorKind::Other, "accept channel closed unexpectedly"))
            })
        })
    }

    /// Get the local address of the underlying socket
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.udp.local_addr()
    }
}

#[cfg(test)]
mod test {
    use futures_util::future;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UdpSocket;
    use tokio::time::{timeout, Duration};

    use super::KcpListener;
    use crate::{
        config::{KcpConfig, KcpNoDelayConfig},
        stream::KcpStream,
    };

    async fn send_open_packet(server_addr: std::net::SocketAddr, conv: u32) -> std::io::Result<()> {
        const KCP_CMD_PUSH: u8 = 81;

        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let mut packet = vec![0u8; kcp::KCP_OVERHEAD as usize];
        kcp::set_conv(&mut packet, conv);
        packet[4] = KCP_CMD_PUSH;
        socket.send_to(&packet, server_addr).await?;
        Ok(())
    }

    #[tokio::test]
    async fn multi_echo() {
        let _ = env_logger::try_init();

        let mut config = KcpConfig::default();
        config.nodelay = KcpNoDelayConfig::fastest();
        config.flush_write = true;
        config.flush_acks_input = true;

        let mut listener = KcpListener::bind(config, "127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();

                tokio::spawn(async move {
                    let mut buffer = [0u8; 8192];
                    while let Ok(n) = stream.read(&mut buffer).await {
                        if n == 0 {
                            break;
                        }

                        let data = &buffer[..n];
                        stream.write_all(data).await.unwrap();
                        stream.flush().await.unwrap();
                    }
                });
            }
        });

        let mut vfut = Vec::new();

        const CLIENTS: usize = 32;
        const ROUNDS: usize = 10;

        for _ in 0..CLIENTS {
            vfut.push(async move {
                timeout(Duration::from_secs(10), async move {
                    let mut stream = KcpStream::connect(&config, server_addr).await.unwrap();

                    for _ in 0..ROUNDS {
                        const SEND_BUFFER: &[u8] = b"HELLO WORLD";
                        stream.write_all(SEND_BUFFER).await.unwrap();
                        stream.flush().await.unwrap();

                        let mut buffer = [0u8; 1024];
                        let n = stream.recv(&mut buffer).await.unwrap();
                        assert_eq!(SEND_BUFFER, &buffer[..n]);
                    }
                })
                .await
                .expect("multi_echo client timed out");
            });
        }

        timeout(Duration::from_secs(20), future::join_all(vfut))
            .await
            .expect("multi_echo timed out");
    }

    #[tokio::test]
    async fn listener_caps_accepted_sessions() {
        let config = KcpConfig::default().with_max_sessions(1);
        let mut listener = KcpListener::bind(config, "127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        send_open_packet(server_addr, 1).await.unwrap();
        send_open_packet(server_addr, 2).await.unwrap();

        let (_stream, _peer) = timeout(Duration::from_secs(1), listener.accept())
            .await
            .expect("first session should be accepted")
            .expect("first accept should succeed");

        let second = timeout(Duration::from_millis(100), listener.accept()).await;
        assert!(second.is_err(), "second session must be dropped at the cap");
    }

    #[tokio::test]
    async fn listener_caps_accepted_sessions_per_ip() {
        let config = KcpConfig::default().with_max_sessions(8).with_max_sessions_per_ip(1);
        let mut listener = KcpListener::bind(config, "127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        send_open_packet(server_addr, 3).await.unwrap();
        send_open_packet(server_addr, 4).await.unwrap();

        let (_stream, _peer) = timeout(Duration::from_secs(1), listener.accept())
            .await
            .expect("first session should be accepted")
            .expect("first accept should succeed");

        let second = timeout(Duration::from_millis(100), listener.accept()).await;
        assert!(
            second.is_err(),
            "second same-IP session must be dropped at the per-IP cap"
        );
    }
}
