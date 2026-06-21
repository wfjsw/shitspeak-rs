use std::{fmt::Debug, io, net::SocketAddr, sync::Arc};

use tokio::net::UdpSocket;

#[async_trait::async_trait]
pub trait KcpUdpIo: Debug + Send + Sync + 'static {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize>;

    fn try_send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize>;

    fn local_addr(&self) -> io::Result<SocketAddr>;
}

#[async_trait::async_trait]
impl KcpUdpIo for UdpSocket {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        UdpSocket::recv(self, buf).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        UdpSocket::recv_from(self, buf).await
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        UdpSocket::send_to(self, buf, target).await
    }

    fn try_send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        UdpSocket::try_send_to(self, buf, target)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        UdpSocket::local_addr(self)
    }
}

pub type SharedUdpIo = Arc<dyn KcpUdpIo>;
