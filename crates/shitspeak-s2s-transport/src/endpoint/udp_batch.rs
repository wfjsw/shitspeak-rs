//! Small S2S-local UDP datagram batch helper.

use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;

pub(crate) const UDP_RECV_BATCH_MAX_DATAGRAMS: usize = 32;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReceivedDatagram<'a> {
    payload: &'a [u8],
    peer_addr: SocketAddr,
}

impl<'a> ReceivedDatagram<'a> {
    pub(crate) fn payload(self) -> &'a [u8] {
        self.payload
    }

    pub(crate) fn peer_addr(self) -> SocketAddr {
        self.peer_addr
    }
}

#[derive(Debug, Clone, Copy)]
struct ReceivedDatagramMeta {
    index: usize,
    len: usize,
    peer_addr: SocketAddr,
}

pub(crate) struct RecvDatagramBatch {
    buffers: Vec<Vec<u8>>,
    received: Vec<ReceivedDatagramMeta>,
}

impl RecvDatagramBatch {
    pub(crate) fn new(capacity: usize, buffer_size: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            buffers: (0..capacity).map(|_| vec![0u8; buffer_size]).collect(),
            received: Vec::with_capacity(capacity),
        }
    }

    pub(crate) fn clear(&mut self) {
        self.received.clear();
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = ReceivedDatagram<'_>> {
        self.received.iter().map(|meta| ReceivedDatagram {
            payload: &self.buffers[meta.index][..meta.len],
            peer_addr: meta.peer_addr,
        })
    }

    pub(crate) fn first_buffer_mut(&mut self) -> &mut [u8] {
        self.buffers[0].as_mut_slice()
    }

    pub(crate) fn push_received(&mut self, index: usize, len: usize, peer_addr: SocketAddr) {
        self.received.push(ReceivedDatagramMeta {
            index,
            len: len.min(self.buffers[index].len()),
            peer_addr,
        });
    }

    fn capacity(&self) -> usize {
        self.buffers.len()
    }
}

pub(crate) async fn recv_udp_batch(
    socket: &UdpSocket,
    batch: &mut RecvDatagramBatch,
) -> io::Result<usize> {
    #[cfg(target_os = "linux")]
    {
        recvmmsg_linux(socket, batch).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        recv_each_available(socket, batch).await
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
async fn recv_each_available(
    socket: &UdpSocket,
    batch: &mut RecvDatagramBatch,
) -> io::Result<usize> {
    batch.clear();
    let (len, peer_addr) = socket.recv_from(batch.first_buffer_mut()).await?;
    batch.push_received(0, len, peer_addr);

    for index in 1..batch.capacity() {
        match socket.try_recv_from(batch.buffers[index].as_mut_slice()) {
            Ok((len, peer_addr)) => batch.push_received(index, len, peer_addr),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(err) => return Err(err),
        }
    }

    Ok(batch.received.len())
}

#[cfg(target_os = "linux")]
async fn recvmmsg_linux(socket: &UdpSocket, batch: &mut RecvDatagramBatch) -> io::Result<usize> {
    use std::os::fd::AsRawFd;

    let fd = socket.as_raw_fd();
    loop {
        socket.readable().await?;
        match socket.try_io(tokio::io::Interest::READABLE, || recvmmsg_chunk(fd, batch)) {
            Ok(0) => continue,
            Ok(n) => return Ok(n),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
}

#[cfg(target_os = "linux")]
fn recvmmsg_chunk(fd: std::os::fd::RawFd, batch: &mut RecvDatagramBatch) -> io::Result<usize> {
    batch.clear();

    let cap = batch.capacity();
    let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(cap);
    let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(cap);
    let mut sockaddrs: Vec<SocketAddrStorage> = (0..cap)
        .map(|_| SocketAddrStorage {
            storage: unsafe { std::mem::zeroed() },
            len: std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
        })
        .collect();

    for buffer in &mut batch.buffers {
        iovecs.push(libc::iovec {
            iov_base: buffer.as_mut_ptr() as *mut libc::c_void,
            iov_len: buffer.len(),
        });
    }

    for index in 0..cap {
        let mut msg: libc::mmsghdr = unsafe { std::mem::zeroed() };
        msg.msg_hdr.msg_name = &mut sockaddrs[index].storage as *mut _ as *mut libc::c_void;
        msg.msg_hdr.msg_namelen = sockaddrs[index].len;
        msg.msg_hdr.msg_iov = &mut iovecs[index] as *mut libc::iovec;
        msg.msg_hdr.msg_iovlen = 1;
        msg.msg_hdr.msg_control = std::ptr::null_mut();
        msg.msg_hdr.msg_controllen = 0;
        msg.msg_hdr.msg_flags = 0;
        msgs.push(msg);
    }

    let ret = unsafe {
        libc::recvmmsg(
            fd,
            msgs.as_mut_ptr(),
            msgs.len() as u32,
            libc::MSG_DONTWAIT as _,
            std::ptr::null_mut(),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    let received = ret as usize;
    for index in 0..received {
        sockaddrs[index].len = msgs[index].msg_hdr.msg_namelen;
        let peer_addr = socket_addr_from_storage(&sockaddrs[index])?;
        batch.push_received(index, msgs[index].msg_len as usize, peer_addr);
    }

    Ok(received)
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
    use std::os::fd::AsFd;

    const CHUNK_SIZE: usize = 64;

    let fd = socket.as_fd();
    let mut stats = UdpBatchStats::default();
    let mut cursor = 0;

    while cursor < datagrams.len() {
        let chunk_end = (cursor + CHUNK_SIZE).min(datagrams.len());
        let mut chunk_cursor = cursor;

        while chunk_cursor < chunk_end {
            let chunk = &datagrams[chunk_cursor..chunk_end];
            let result = socket.try_io(tokio::io::Interest::WRITABLE, || {
                match sendmmsg_chunk(fd, chunk)? {
                    0 => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                    sent => Ok(sent),
                }
            });
            match result {
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
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            }
        }

        cursor = chunk_end;
    }

    Ok(stats)
}

#[cfg(target_os = "linux")]
fn sendmmsg_chunk(
    fd: std::os::fd::BorrowedFd<'_>,
    chunk: &[UdpBatchDatagram<'_>],
) -> io::Result<usize> {
    shitspeak_core::linux_net::sendmmsg_to(
        fd,
        chunk
            .iter()
            .map(|datagram| (datagram.target(), datagram.payload())),
    )
}

#[cfg(target_os = "linux")]
struct SocketAddrStorage {
    storage: libc::sockaddr_storage,
    len: libc::socklen_t,
}

#[cfg(target_os = "linux")]
fn socket_addr_from_storage(addr: &SocketAddrStorage) -> io::Result<SocketAddr> {
    match addr.storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let sa = unsafe { &*(&addr.storage as *const _ as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(sa.sin_addr.s_addr.to_ne_bytes());
            Ok(SocketAddr::from((ip, u16::from_be(sa.sin_port))))
        }
        libc::AF_INET6 => {
            let sa = unsafe { &*(&addr.storage as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr);
            Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
                ip,
                u16::from_be(sa.sin6_port),
                sa.sin6_flowinfo,
                sa.sin6_scope_id,
            )))
        }
        family => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported UDP peer address family {family}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

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

    #[tokio::test]
    async fn recv_empty_socket_waits_without_spinning() {
        let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let mut batch = RecvDatagramBatch::new(UDP_RECV_BATCH_MAX_DATAGRAMS, 64);

        assert!(
            timeout(
                Duration::from_millis(25),
                recv_udp_batch(&socket, &mut batch)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn recv_batch_preserves_ordered_payloads_and_source_address() {
        let sender = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let receiver = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let target = receiver.local_addr().unwrap();
        sender.send_to(b"first", target).await.unwrap();
        sender.send_to(b"second", target).await.unwrap();

        let mut batch = RecvDatagramBatch::new(UDP_RECV_BATCH_MAX_DATAGRAMS, 64);
        let n = recv_udp_batch(&receiver, &mut batch).await.unwrap();
        let received = batch
            .iter()
            .map(|datagram| (datagram.payload().to_vec(), datagram.peer_addr()))
            .collect::<Vec<_>>();

        assert_eq!(n, 2);
        assert_eq!(
            received[0],
            (b"first".to_vec(), sender.local_addr().unwrap())
        );
        assert_eq!(
            received[1],
            (b"second".to_vec(), sender.local_addr().unwrap())
        );
    }
}
