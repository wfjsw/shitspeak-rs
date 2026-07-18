use std::{
    fmt::{self, Debug},
    io::{self, ErrorKind},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::{future, ready};
use kcp::{Error as KcpError, KcpResult, KcpStats};
use log::trace;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::UdpSocket,
};

use crate::{
    config::KcpConfig,
    session::{KcpSession, KcpStatsHandle},
    skcp::{is_would_block, KcpSocket},
    udp_io::SharedUdpIo,
};

pub struct KcpStream {
    session: Arc<KcpSession>,
    recv_buffer: Vec<u8>,
    recv_buffer_pos: usize,
    recv_buffer_cap: usize,
}

impl Drop for KcpStream {
    fn drop(&mut self) {
        self.session.close();
    }
}

impl Debug for KcpStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KcpStream")
            .field("session", self.session.as_ref())
            .field("recv_buffer.len", &self.recv_buffer.len())
            .field("recv_buffer_pos", &self.recv_buffer_pos)
            .field("recv_buffer_cap", &self.recv_buffer_cap)
            .finish()
    }
}

impl KcpStream {
    /// Create a `KcpStream` connecting to `addr`
    ///
    /// NOTE: `conv` will be randomly generated
    pub async fn connect(config: &KcpConfig, addr: SocketAddr) -> KcpResult<KcpStream> {
        let udp = match addr.ip() {
            IpAddr::V4(..) => UdpSocket::bind("0.0.0.0:0").await?,
            IpAddr::V6(..) => UdpSocket::bind("[::]:0").await?,
        };

        KcpStream::connect_with_socket(config, udp, addr).await
    }

    /// Create a `KcpStream` connecting to `addr`
    ///
    /// `conv` is the conversation identifier, setting to `0` will let server to randomly generate one for you.
    pub async fn connect_with_conv(config: &KcpConfig, conv: u32, addr: SocketAddr) -> KcpResult<KcpStream> {
        let udp = match addr.ip() {
            IpAddr::V4(..) => UdpSocket::bind("0.0.0.0:0").await?,
            IpAddr::V6(..) => UdpSocket::bind("[::]:0").await?,
        };

        KcpStream::connect_with_socket_conv(config, conv, udp, addr).await
    }

    /// Create a `KcpStream` with an existed `UdpSocket` connecting to `addr`
    ///
    /// NOTE: `conv` will be randomly generated
    pub async fn connect_with_socket(config: &KcpConfig, udp: UdpSocket, addr: SocketAddr) -> KcpResult<KcpStream> {
        let mut conv = rand::random();
        while conv == 0 {
            conv = rand::random();
        }
        KcpStream::connect_with_socket_conv(config, conv, udp, addr).await
    }

    /// Create a `KcpStream` with an existed `UdpSocket` connecting to `addr`
    ///
    /// `conv` is the conversation identifier, setting to `0` will let server to randomly generate one for you.
    pub async fn connect_with_socket_conv(
        config: &KcpConfig,
        conv: u32,
        udp: UdpSocket,
        addr: SocketAddr,
    ) -> KcpResult<KcpStream> {
        let udp = Arc::new(udp);
        KcpStream::connect_with_io_conv(config, conv, udp, addr).await
    }

    /// Create a `KcpStream` with an abstract UDP I/O object connecting to `addr`.
    ///
    /// NOTE: `conv` will be randomly generated
    pub async fn connect_with_io(config: &KcpConfig, udp: SharedUdpIo, addr: SocketAddr) -> KcpResult<KcpStream> {
        let mut conv = rand::random();
        while conv == 0 {
            conv = rand::random();
        }
        KcpStream::connect_with_io_conv(config, conv, udp, addr).await
    }

    /// Create a `KcpStream` with an abstract UDP I/O object connecting to `addr`.
    ///
    /// `conv` is the conversation identifier, setting to `0` will let server to randomly generate one for you.
    pub async fn connect_with_io_conv(
        config: &KcpConfig,
        conv: u32,
        udp: SharedUdpIo,
        addr: SocketAddr,
    ) -> KcpResult<KcpStream> {
        let socket = KcpSocket::new(config, conv, udp, addr, config.stream)?;

        let session = KcpSession::new_shared(socket, config.session_expire, config.no_progress_timeout, None);

        Ok(KcpStream::with_session(session))
    }

    pub(crate) fn with_session(session: Arc<KcpSession>) -> KcpStream {
        KcpStream {
            session,
            recv_buffer: Vec::new(),
            recv_buffer_pos: 0,
            recv_buffer_cap: 0,
        }
    }

    /// `send` data in `buf`
    pub fn poll_send(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<KcpResult<usize>> {
        let mut kcp = match self.session.kcp_socket().try_lock() {
            Ok(kcp) => kcp,
            Err(_) => {
                self.session.register_socket_waker(cx.waker());
                return Poll::Pending;
            }
        };
        match kcp.poll_send(cx, buf) {
            Poll::Ready(result) => {
                self.session.update_stats(&kcp);
                self.session.refresh_runtime_state(&kcp);
                drop(kcp);
                self.session.wake_socket_waiters();
                self.session.notify();
                Poll::Ready(result)
            }
            Poll::Pending => {
                self.session.update_stats(&kcp);
                self.session.refresh_runtime_state(&kcp);
                drop(kcp);
                self.session.wake_socket_waiters();
                Poll::Pending
            }
        }
    }

    /// `send` data in `buf`
    pub async fn send(&mut self, buf: &[u8]) -> KcpResult<usize> {
        future::poll_fn(|cx| self.poll_send(cx, buf)).await
    }

    /// `recv` data into `buf`
    pub fn poll_recv(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<KcpResult<usize>> {
        loop {
            // Consumes all data in buffer
            if self.recv_buffer_pos < self.recv_buffer_cap {
                let remaining = self.recv_buffer_cap - self.recv_buffer_pos;
                let copy_length = remaining.min(buf.len());

                buf[..copy_length]
                    .copy_from_slice(&self.recv_buffer[self.recv_buffer_pos..self.recv_buffer_pos + copy_length]);
                self.recv_buffer_pos += copy_length;
                return Ok(copy_length).into();
            }

            let mut kcp = match self.session.kcp_socket().try_lock() {
                Ok(kcp) => kcp,
                Err(_) => {
                    self.session.register_socket_waker(cx.waker());
                    return Poll::Pending;
                }
            };

            // Try to read from KCP
            // 1. Read directly with user provided `buf`
            let peek_size = kcp.peek_size().unwrap_or(0);

            // 1.1. User's provided buffer is larger than available buffer's size
            if peek_size > 0 && peek_size <= buf.len() {
                match kcp.poll_recv(cx, buf) {
                    Poll::Ready(Ok(n)) => {
                        trace!("[CLIENT] recv directly {} bytes", n);
                        self.session.update_stats(&kcp);
                        drop(kcp);
                        self.session.wake_socket_waiters();
                        return Ok(n).into();
                    }
                    Poll::Ready(Err(KcpError::UserBufTooSmall)) => {}
                    Poll::Ready(Err(err)) => {
                        self.session.update_stats(&kcp);
                        drop(kcp);
                        self.session.wake_socket_waiters();
                        return Err(err).into();
                    }
                    Poll::Pending => {
                        self.session.update_stats(&kcp);
                        drop(kcp);
                        self.session.wake_socket_waiters();
                        return Poll::Pending;
                    }
                }
            }

            // 2. User `buf` too small, read to recv_buffer
            let required_size = peek_size;
            if self.recv_buffer.len() < required_size {
                self.recv_buffer.resize(required_size, 0);
            }

            match kcp.poll_recv(cx, &mut self.recv_buffer) {
                Poll::Ready(Ok(0)) => {
                    self.session.update_stats(&kcp);
                    drop(kcp);
                    self.session.wake_socket_waiters();
                    return Ok(0).into();
                }
                Poll::Ready(Ok(n)) => {
                    trace!("[CLIENT] recv buffered {} bytes", n);
                    self.recv_buffer_pos = 0;
                    self.recv_buffer_cap = n;
                    self.session.update_stats(&kcp);
                    drop(kcp);
                    self.session.wake_socket_waiters();
                }
                Poll::Ready(Err(err)) => {
                    self.session.update_stats(&kcp);
                    drop(kcp);
                    self.session.wake_socket_waiters();
                    return Err(err).into();
                }
                Poll::Pending => {
                    self.session.update_stats(&kcp);
                    drop(kcp);
                    self.session.wake_socket_waiters();
                    return Poll::Pending;
                }
            }
        }
    }

    /// `recv` data into `buf`
    pub async fn recv(&mut self, buf: &mut [u8]) -> KcpResult<usize> {
        future::poll_fn(|cx| self.poll_recv(cx, buf)).await
    }

    /// Get the `KcpSession` for this `KcpStream`
    pub fn session(&self) -> &KcpSession {
        &self.session
    }

    pub fn stats(&self) -> KcpStats {
        self.session.snapshot_stats()
    }

    pub fn stats_handle(&self) -> KcpStatsHandle {
        KcpStatsHandle::new(self.session.clone())
    }
}

impl AsyncRead for KcpStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match ready!(self.poll_recv(cx, buf.initialize_unfilled())) {
            Ok(n) => {
                buf.advance(n);
                Ok(()).into()
            }
            Err(KcpError::IoError(err)) => Err(err).into(),
            Err(err) => Err(io::Error::other(err)).into(),
        }
    }
}

impl AsyncWrite for KcpStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match ready!(self.poll_send(cx, buf)) {
            Ok(n) => Ok(n).into(),
            Err(KcpError::IoError(err)) => Err(err).into(),
            Err(err) => Err(io::Error::other(err)).into(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut kcp = match self.session.kcp_socket().try_lock() {
            Ok(kcp) => kcp,
            Err(_) => {
                self.session.register_socket_waker(cx.waker());
                return Poll::Pending;
            }
        };
        match kcp.flush() {
            Ok(..) => {
                self.session.update_stats(&kcp);
                self.session.refresh_runtime_state(&kcp);
                drop(kcp);
                self.session.wake_socket_waiters();
                self.session.notify();
                Ok(()).into()
            }
            Err(KcpError::IoError(err)) => {
                if err.kind() == ErrorKind::WouldBlock {
                    self.session.register_socket_waker(cx.waker());
                    self.session.update_stats(&kcp);
                    self.session.refresh_runtime_state(&kcp);
                    drop(kcp);
                    self.session.wake_socket_waiters();
                    self.session.notify();
                    return Poll::Pending;
                }
                self.session.update_stats(&kcp);
                self.session.refresh_runtime_state(&kcp);
                drop(kcp);
                self.session.wake_socket_waiters();
                Err(err).into()
            }
            Err(err) => {
                if is_would_block(&err) {
                    self.session.register_socket_waker(cx.waker());
                    self.session.update_stats(&kcp);
                    self.session.refresh_runtime_state(&kcp);
                    drop(kcp);
                    self.session.wake_socket_waiters();
                    self.session.notify();
                    return Poll::Pending;
                }
                self.session.update_stats(&kcp);
                self.session.refresh_runtime_state(&kcp);
                drop(kcp);
                self.session.wake_socket_waiters();
                Err(io::Error::other(err)).into()
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Ok(()).into()
    }
}

#[cfg(test)]
mod test {
    use crate::KcpListener;

    use super::*;

    #[tokio::test]
    async fn test_stream_echo() {
        let _ = env_logger::try_init();

        let config = KcpConfig::default();
        let server_addr = "127.0.0.1:5555".parse::<SocketAddr>().unwrap();

        let mut listener = KcpListener::bind(config, server_addr).await.unwrap();
        let listener_hdl = tokio::spawn(async move {
            loop {
                let (mut stream, peer_addr) = listener.accept().await.unwrap();
                println!("accepted {}", peer_addr);

                tokio::spawn(async move {
                    let mut buffer = [0u8; 8192];
                    loop {
                        match stream.recv(&mut buffer).await {
                            Ok(n) => {
                                println!("server recv: {:?}", &buffer[..n]);
                                let send_n = stream.send(&buffer[..n]).await.unwrap();
                                println!("server sent: {}", send_n);
                            }
                            Err(err) => {
                                println!("recv error: {}", err);
                                break;
                            }
                        }
                    }
                });
            }
        });

        let mut stream = KcpStream::connect(&config, server_addr).await.unwrap();

        let test_payload = b"HELLO WORLD";
        stream.send(test_payload).await.unwrap();
        println!("client sent: {:?}", test_payload);

        let mut recv_buffer = [0u8; 1024];
        let recv_n = stream.recv(&mut recv_buffer).await.unwrap();
        println!("client recv: {:?}", &recv_buffer[..recv_n]);
        assert_eq!(recv_n, test_payload.len());
        assert_eq!(&recv_buffer[..recv_n], test_payload);

        listener_hdl.abort();
    }
}
