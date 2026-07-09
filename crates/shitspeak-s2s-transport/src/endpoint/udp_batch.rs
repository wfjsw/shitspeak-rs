//! Small S2S-local UDP datagram batch helper.

use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;

#[derive(Clone, Copy)]
pub(crate) struct UdpBatchDatagram<'a> {
    payload: &'a [u8],
    target: SocketAddr,
}

impl<'a> UdpBatchDatagram<'a> {
    pub(crate) fn new(payload: &'a [u8], target: SocketAddr) -> Self {
        Self { payload, target }
    }

    fn payload(self) -> &'a [u8] {
        self.payload
    }

    fn target(self) -> SocketAddr {
        self.target
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UdpBatchStats {
    would_block: u64,
    partial: u64,
}

impl UdpBatchStats {
    pub(crate) fn would_block_count(self) -> u64 {
        self.would_block
    }

    pub(crate) fn partial_count(self) -> u64 {
        self.partial
    }

    #[cfg(target_os = "linux")]
    fn record_would_block(&mut self) {
        self.would_block += 1;
    }

    #[cfg(target_os = "linux")]
    fn record_partial(&mut self) {
        self.partial += 1;
    }
}

pub(crate) async fn send_udp_batch(
    socket: &UdpSocket,
    datagrams: &[UdpBatchDatagram<'_>],
) -> io::Result<UdpBatchStats> {
    if datagrams.is_empty() {
        return Ok(UdpBatchStats::default());
    }

    #[cfg(target_os = "linux")]
    {
        sendmmsg_linux(socket, datagrams).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        send_each(socket, datagrams).await
    }
}

#[cfg(not(target_os = "linux"))]
async fn send_each(
    socket: &UdpSocket,
    datagrams: &[UdpBatchDatagram<'_>],
) -> io::Result<UdpBatchStats> {
    for datagram in datagrams {
        socket
            .send_to(datagram.payload(), datagram.target())
            .await?;
    }
    Ok(UdpBatchStats::default())
}

#[cfg(target_os = "linux")]
async fn sendmmsg_linux(
    socket: &UdpSocket,
    datagrams: &[UdpBatchDatagram<'_>],
) -> io::Result<UdpBatchStats> {
    use std::os::fd::AsRawFd;

    const CHUNK_SIZE: usize = 64;

    let fd = socket.as_raw_fd();
    let mut stats = UdpBatchStats::default();
    let mut cursor = 0;

    while cursor < datagrams.len() {
        let chunk_end = (cursor + CHUNK_SIZE).min(datagrams.len());
        let mut chunk_cursor = cursor;

        while chunk_cursor < chunk_end {
            let chunk = &datagrams[chunk_cursor..chunk_end];
            match sendmmsg_chunk(fd, chunk) {
                Ok(0) => {
                    stats.record_would_block();
                    socket.writable().await?;
                }
                Ok(sent) => {
                    if sent < chunk.len() {
                        stats.record_partial();
                    }
                    chunk_cursor += sent;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    stats.record_would_block();
                    socket.writable().await?;
                }
                Err(err) => return Err(err),
            }
        }

        cursor = chunk_end;
    }

    Ok(stats)
}

#[cfg(target_os = "linux")]
fn sendmmsg_chunk(fd: std::os::fd::RawFd, chunk: &[UdpBatchDatagram<'_>]) -> io::Result<usize> {
    let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(chunk.len());
    let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(chunk.len());
    let mut sockaddrs: Vec<SocketAddrStorage> = Vec::with_capacity(chunk.len());

    for datagram in chunk {
        let payload = datagram.payload();
        iovecs.push(libc::iovec {
            iov_base: payload.as_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
        });
        sockaddrs.push(socket_addr_to_storage(&datagram.target()));
    }

    for index in 0..chunk.len() {
        let mut msg: libc::mmsghdr = unsafe { std::mem::zeroed() };
        msg.msg_hdr.msg_name = &sockaddrs[index].storage as *const _ as *mut libc::c_void;
        msg.msg_hdr.msg_namelen = sockaddrs[index].len;
        msg.msg_hdr.msg_iov = &iovecs[index] as *const _ as *mut libc::iovec;
        msg.msg_hdr.msg_iovlen = 1;
        msg.msg_hdr.msg_control = std::ptr::null_mut();
        msg.msg_hdr.msg_controllen = 0;
        msg.msg_hdr.msg_flags = 0;
        msgs.push(msg);
    }

    let ret = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), msgs.len() as u32, 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(ret as usize)
}

#[cfg(target_os = "linux")]
struct SocketAddrStorage {
    storage: libc::sockaddr_storage,
    len: libc::socklen_t,
}

#[cfg(target_os = "linux")]
fn socket_addr_to_storage(addr: &SocketAddr) -> SocketAddrStorage {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(v4) => {
            let sa = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_port = v4.port().to_be();
            sa.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(v4.ip().octets()),
            };
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(v6) => {
            let sa = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
            sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa.sin6_port = v6.port().to_be();
            sa.sin6_flowinfo = v6.flowinfo();
            sa.sin6_addr.s6_addr = v6.ip().octets();
            sa.sin6_scope_id = v6.scope_id();
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    };

    SocketAddrStorage { storage, len }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_batch_returns_zero_stats() {
        let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let stats = send_udp_batch(&socket, &[]).await.unwrap();

        assert_eq!(stats.would_block_count(), 0);
        assert_eq!(stats.partial_count(), 0);
    }

    #[tokio::test]
    async fn batch_sends_to_ipv4_destination() {
        let sender = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let receiver = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let target = receiver.local_addr().unwrap();
        let payloads = [b"first".as_slice(), b"second".as_slice()];
        let batch = payloads
            .iter()
            .map(|payload| UdpBatchDatagram::new(payload, target))
            .collect::<Vec<_>>();

        send_udp_batch(&sender, &batch).await.unwrap();

        let mut received = Vec::new();
        for _ in 0..payloads.len() {
            let mut buf = [0u8; 64];
            let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
            received.push(buf[..n].to_vec());
        }

        assert_eq!(received, vec![b"first".to_vec(), b"second".to_vec()]);
    }
}
