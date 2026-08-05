use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;

pub(super) const VOICE_UDP_RECV_BATCH_MAX_DATAGRAMS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct VoiceUdpDatagram<'a> {
    payload: &'a [u8],
    src_addr: SocketAddr,
}

impl<'a> VoiceUdpDatagram<'a> {
    pub(super) fn payload(self) -> &'a [u8] {
        self.payload
    }

    pub(super) fn src_addr(self) -> SocketAddr {
        self.src_addr
    }
}

#[derive(Debug, Clone, Copy)]
struct VoiceUdpDatagramMeta {
    index: usize,
    len: usize,
    src_addr: SocketAddr,
}

pub(super) struct VoiceUdpRecvBatch {
    buffers: Vec<Vec<u8>>,
    received: Vec<VoiceUdpDatagramMeta>,
}

impl VoiceUdpRecvBatch {
    pub(super) fn new(capacity: usize, buffer_size: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            buffers: (0..capacity).map(|_| vec![0u8; buffer_size]).collect(),
            received: Vec::with_capacity(capacity),
        }
    }

    fn clear(&mut self) {
        self.received.clear();
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = VoiceUdpDatagram<'_>> {
        self.received.iter().map(|meta| VoiceUdpDatagram {
            payload: &self.buffers[meta.index][..meta.len],
            src_addr: meta.src_addr,
        })
    }

    #[allow(dead_code)]
    fn first_buffer_mut(&mut self) -> &mut [u8] {
        self.buffers[0].as_mut_slice()
    }

    fn push_received(&mut self, index: usize, len: usize, src_addr: SocketAddr) {
        self.received.push(VoiceUdpDatagramMeta {
            index,
            len: len.min(self.buffers[index].len()),
            src_addr,
        });
    }

    fn capacity(&self) -> usize {
        self.buffers.len()
    }
}

pub(super) async fn recv_voice_udp_batch(
    socket: &UdpSocket,
    batch: &mut VoiceUdpRecvBatch,
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

#[cfg(not(target_os = "linux"))]
async fn recv_each_available(
    socket: &UdpSocket,
    batch: &mut VoiceUdpRecvBatch,
) -> io::Result<usize> {
    batch.clear();
    let (len, src_addr) = socket.recv_from(batch.first_buffer_mut()).await?;
    batch.push_received(0, len, src_addr);

    for index in 1..batch.capacity() {
        match socket.try_recv_from(batch.buffers[index].as_mut_slice()) {
            Ok((len, src_addr)) => batch.push_received(index, len, src_addr),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(err) => return Err(err),
        }
    }

    Ok(batch.received.len())
}

#[cfg(target_os = "linux")]
async fn recvmmsg_linux(socket: &UdpSocket, batch: &mut VoiceUdpRecvBatch) -> io::Result<usize> {
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
fn recvmmsg_chunk(fd: std::os::fd::RawFd, batch: &mut VoiceUdpRecvBatch) -> io::Result<usize> {
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
        let src_addr = socket_addr_from_storage(&sockaddrs[index])?;
        batch.push_received(index, msgs[index].msg_len as usize, src_addr);
    }

    Ok(received)
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
    async fn empty_socket_waits_without_spinning() {
        let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let mut batch = VoiceUdpRecvBatch::new(VOICE_UDP_RECV_BATCH_MAX_DATAGRAMS, 64);

        assert!(
            timeout(
                Duration::from_millis(25),
                recv_voice_udp_batch(&socket, &mut batch)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn batch_receives_ordered_payloads_and_source_address() {
        let sender = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let receiver = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let target = receiver.local_addr().unwrap();
        sender.send_to(b"first", target).await.unwrap();
        sender.send_to(b"second", target).await.unwrap();

        let mut batch = VoiceUdpRecvBatch::new(VOICE_UDP_RECV_BATCH_MAX_DATAGRAMS, 64);
        let n = recv_voice_udp_batch(&receiver, &mut batch).await.unwrap();
        let received = batch
            .iter()
            .map(|datagram| (datagram.payload().to_vec(), datagram.src_addr()))
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
