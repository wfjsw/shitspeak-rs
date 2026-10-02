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
            src_addr: shitspeak_auth::canonical_socket_addr(src_addr),
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
    let (len, src_addr) =
        recv_from_skipping_transient_errors(socket, batch.first_buffer_mut()).await?;
    batch.push_received(0, len, src_addr);

    for index in 1..batch.capacity() {
        match socket.try_recv_from(batch.buffers[index].as_mut_slice()) {
            Ok((len, src_addr)) => batch.push_received(index, len, src_addr),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
            // Keep what this batch already holds; the next call reads on.
            Err(err) if is_transient_udp_recv_error(&err) => break,
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
            Err(err) if is_transient_udp_recv_error(&err) => continue,
            Err(err) => return Err(err),
        }
    }
}

#[cfg(target_os = "linux")]
fn recvmmsg_chunk(fd: std::os::fd::RawFd, batch: &mut VoiceUdpRecvBatch) -> io::Result<usize> {
    RECV_MMSG_BUFFERS.with(|scratch| match scratch.try_borrow_mut() {
        Ok(mut scratch) => recvmmsg_with_scratch(fd, batch, &mut scratch),
        Err(_) => recvmmsg_with_scratch(fd, batch, &mut RecvMmsgBuffers::new()),
    })
}

#[cfg(target_os = "linux")]
fn recvmmsg_with_scratch(
    fd: std::os::fd::RawFd,
    batch: &mut VoiceUdpRecvBatch,
    scratch: &mut RecvMmsgBuffers,
) -> io::Result<usize> {
    batch.clear();

    let cap = batch.capacity();
    scratch.msgs.clear();
    scratch.iovecs.clear();
    scratch.sockaddrs.clear();
    scratch.sockaddrs.resize_with(cap, || SocketAddrStorage {
        storage: unsafe { std::mem::zeroed() },
        len: std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
    });

    // Refresh all pointers after resizing, even when a different batch uses this worker.
    for buffer in &mut batch.buffers {
        scratch.iovecs.push(libc::iovec {
            iov_base: buffer.as_mut_ptr() as *mut libc::c_void,
            iov_len: buffer.len(),
        });
    }

    for index in 0..cap {
        let mut msg: libc::mmsghdr = unsafe { std::mem::zeroed() };
        msg.msg_hdr.msg_name = &mut scratch.sockaddrs[index].storage as *mut _ as *mut libc::c_void;
        msg.msg_hdr.msg_namelen = scratch.sockaddrs[index].len;
        msg.msg_hdr.msg_iov = &mut scratch.iovecs[index] as *mut libc::iovec;
        msg.msg_hdr.msg_iovlen = 1;
        msg.msg_hdr.msg_control = std::ptr::null_mut();
        msg.msg_hdr.msg_controllen = 0;
        msg.msg_hdr.msg_flags = 0;
        scratch.msgs.push(msg);
    }

    let ret = unsafe {
        libc::recvmmsg(
            fd,
            scratch.msgs.as_mut_ptr(),
            scratch.msgs.len() as u32,
            libc::MSG_DONTWAIT as _,
            std::ptr::null_mut(),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    let received = ret as usize;
    for index in 0..received {
        scratch.sockaddrs[index].len = scratch.msgs[index].msg_hdr.msg_namelen;
        let src_addr = socket_addr_from_storage(&scratch.sockaddrs[index])?;
        batch.push_received(index, scratch.msgs[index].msg_len as usize, src_addr);
    }

    Ok(received)
}

#[cfg(target_os = "linux")]
struct RecvMmsgBuffers {
    msgs: Vec<libc::mmsghdr>,
    iovecs: Vec<libc::iovec>,
    sockaddrs: Vec<SocketAddrStorage>,
}

#[cfg(target_os = "linux")]
impl RecvMmsgBuffers {
    const fn new() -> Self {
        Self {
            msgs: Vec::new(),
            iovecs: Vec::new(),
            sockaddrs: Vec::new(),
        }
    }
}

#[cfg(target_os = "linux")]
thread_local! {
    static RECV_MMSG_BUFFERS: std::cell::RefCell<RecvMmsgBuffers> =
        const { std::cell::RefCell::new(RecvMmsgBuffers::new()) };
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

/// Whether a UDP receive error reports one earlier datagram rather than the
/// socket. An ICMP unreachable for voice we sent to a client that went away
/// surfaces on the shared socket's next receive (WSAECONNRESET /
/// WSAENETRESET on Windows); the next datagram is still deliverable.
pub(super) fn is_transient_udp_recv_error(error: &io::Error) -> bool {
    /// WSAENETRESET: the TTL-expired counterpart of WSAECONNRESET.
    #[cfg(windows)]
    const NETWORK_RESET: i32 = 10052;
    #[cfg(windows)]
    if error.raw_os_error() == Some(NETWORK_RESET) {
        return true;
    }
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::Interrupted
    )
}

/// `socket.recv_from`, retried past per-datagram errors.
async fn recv_from_skipping_transient_errors(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr)> {
    loop {
        match socket.recv_from(buf).await {
            Err(error) if is_transient_udp_recv_error(&error) => {
                tracing::trace!(%error, "skipped a per-datagram UDP receive error");
            }
            result => return result,
        }
    }
}

/// Stop Windows from reporting ICMP port/network unreachable for datagrams
/// the voice socket sent as WSAECONNRESET / WSAENETRESET on its next
/// receive (`SIO_UDP_CONNRESET`, `SIO_UDP_NETRESET`): one departed client
/// must not register as an error on the socket every client shares.
#[cfg(windows)]
pub(super) fn disable_udp_connection_reset_reports(
    socket: &impl std::os::windows::io::AsRawSocket,
) {
    use windows_sys::Win32::Networking::WinSock::{
        SIO_UDP_CONNRESET, SIO_UDP_NETRESET, SOCKET, WSAIoctl,
    };
    for (name, code) in [
        ("SIO_UDP_CONNRESET", SIO_UDP_CONNRESET),
        ("SIO_UDP_NETRESET", SIO_UDP_NETRESET),
    ] {
        let enabled: i32 = 0;
        let mut returned: u32 = 0;
        // SAFETY: the socket handle is live for the borrow; the input
        // buffer is a valid BOOL and no output, overlapped I/O or
        // completion routine is used.
        let rc = unsafe {
            WSAIoctl(
                socket.as_raw_socket() as SOCKET,
                code,
                (&enabled as *const i32).cast(),
                std::mem::size_of::<i32>() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
                None,
            )
        };
        if rc != 0 {
            tracing::debug!(
                ioctl = name,
                error = %io::Error::last_os_error(),
                "unable to disable UDP reset reports"
            );
        }
    }
}

/// Only Windows reports a peer's ICMP unreachable on an unconnected socket.
#[cfg(not(windows))]
pub(super) fn disable_udp_connection_reset_reports<S: ?Sized>(_socket: &S) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddrV6};
    use std::time::Duration;
    use tokio::time::timeout;

    /// Send from `socket` to a port nobody listens on and wait for the ICMP
    /// port unreachable. On Windows this queues a WSAECONNRESET for the
    /// socket's next receive — a client that went away must not stop the
    /// voice drain for every other client.
    #[cfg(windows)]
    async fn provoke_port_unreachable(socket: &UdpSocket) {
        let closed = {
            let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap()
        };
        socket.send_to(b"nobody", closed).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[cfg(windows)]
    async fn assert_next_batch_delivers(receiver: &UdpSocket) {
        let sender = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        sender
            .send_to(b"after", receiver.local_addr().unwrap())
            .await
            .unwrap();
        let mut batch = VoiceUdpRecvBatch::new(VOICE_UDP_RECV_BATCH_MAX_DATAGRAMS, 64);
        let n = timeout(
            Duration::from_secs(1),
            recv_voice_udp_batch(receiver, &mut batch),
        )
        .await
        .expect("receive completes")
        .expect("the reset report does not fail the batch");
        assert!(n >= 1);
        assert_eq!(
            batch
                .iter()
                .next()
                .map(|datagram| datagram.payload().to_vec()),
            Some(b"after".to_vec())
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn voice_batch_survives_a_port_unreachable_report() {
        let receiver = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        provoke_port_unreachable(&receiver).await;
        assert_next_batch_delivers(&receiver).await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn disabled_reset_reports_never_reach_a_plain_receive() {
        let receiver = {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            disable_udp_connection_reset_reports(&socket);
            socket.set_nonblocking(true).unwrap();
            UdpSocket::from_std(socket).unwrap()
        };
        provoke_port_unreachable(&receiver).await;
        let sender = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        sender
            .send_to(b"after", receiver.local_addr().unwrap())
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        let (n, _) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
            .await
            .expect("receive completes")
            .expect("no reset report is queued");
        assert_eq!(&buf[..n], b"after");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn allocation_churn_receive_metadata_is_reused() {
        use std::os::fd::AsRawFd;
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let mut batch = VoiceUdpRecvBatch::new(32, 64);
        assert_eq!(
            recvmmsg_chunk(socket.as_raw_fd(), &mut batch)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        let allocations = shitspeak_test_support::count_allocations(|| {
            for _ in 0..10 {
                assert_eq!(
                    recvmmsg_chunk(socket.as_raw_fd(), &mut batch)
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::WouldBlock
                );
            }
        });
        assert_eq!(allocations, 0);
    }

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

    #[tokio::test]
    async fn batch_canonicalizes_ipv4_peers_on_dual_stack_socket() {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();
        socket.set_only_v6(false).unwrap();
        socket.set_nonblocking(true).unwrap();
        socket
            .bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0).into())
            .unwrap();
        let receiver = UdpSocket::from_std(socket.into()).unwrap();
        let sender = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();

        sender
            .send_to(
                b"ping",
                (
                    std::net::Ipv4Addr::LOCALHOST,
                    receiver.local_addr().unwrap().port(),
                ),
            )
            .await
            .unwrap();

        let mut batch = VoiceUdpRecvBatch::new(VOICE_UDP_RECV_BATCH_MAX_DATAGRAMS, 64);
        timeout(
            Duration::from_secs(1),
            recv_voice_udp_batch(&receiver, &mut batch),
        )
        .await
        .unwrap()
        .unwrap();

        let received = batch.iter().next().unwrap();
        assert_eq!(received.payload(), b"ping");
        assert_eq!(received.src_addr(), sender.local_addr().unwrap());
    }
}
