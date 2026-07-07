//! Batched UDP send using `sendmmsg` on Linux, falling back to per-packet
//! `send_to` on other platforms.
//!
//! On Linux, `libc::sendmmsg` sends multiple datagrams in a single syscall,
//! significantly reducing overhead for voice packets (which are small and
//! frequent).  On non-Linux platforms we fall back to a simple loop of
//! `send_to` calls.

use std::net::SocketAddr;
use std::time::Duration;

#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::time::Instant;

use crate::constants::MTU;

const DATAGRAMS_PER_CHUNK: usize = 64;
const CHUNK_BYTES: usize = MTU * DATAGRAMS_PER_CHUNK;

struct QueuedDatagram {
    addr: SocketAddr,
    chunk: usize,
    offset: usize,
    len: usize,
}

pub struct DatagramBatch {
    chunks: Vec<Vec<u8>>,
    datagrams: Vec<QueuedDatagram>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FlushStats {
    would_block: u64,
    partial: u64,
}

impl FlushStats {
    pub fn would_block_count(self) -> u64 {
        self.would_block
    }

    pub fn partial_count(self) -> u64 {
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

impl DatagramBatch {
    pub fn new() -> Self {
        Self {
            chunks: Vec::new(),
            datagrams: Vec::new(),
        }
    }

    pub fn with_capacity(datagram_capacity: usize) -> Self {
        let mut chunks = Vec::new();
        if datagram_capacity > 0 {
            let first_chunk_bytes = CHUNK_BYTES
                .min(datagram_capacity.saturating_mul(MTU))
                .max(MTU);
            chunks.push(Vec::with_capacity(first_chunk_bytes));
        }

        Self {
            chunks,
            datagrams: Vec::with_capacity(datagram_capacity),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.datagrams.is_empty()
    }

    pub fn len(&self) -> usize {
        self.datagrams.len()
    }

    pub fn bytes_len(&self) -> usize {
        self.datagrams.iter().map(|datagram| datagram.len).sum()
    }

    pub fn try_push_zeroed<E>(
        &mut self,
        addr: SocketAddr,
        len: usize,
        write: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        let created_chunk = self.ensure_chunk(len);
        let chunk = self.chunks.len() - 1;
        let offset = self.chunks[chunk].len();
        self.chunks[chunk].resize(offset + len, 0);

        match write(&mut self.chunks[chunk][offset..offset + len]) {
            Ok(()) => {
                self.datagrams.push(QueuedDatagram {
                    addr,
                    chunk,
                    offset,
                    len,
                });
                Ok(())
            }
            Err(e) => {
                if created_chunk {
                    self.chunks.pop();
                } else {
                    self.chunks[chunk].truncate(offset);
                }
                Err(e)
            }
        }
    }

    pub fn append(&mut self, mut other: Self) {
        if other.datagrams.is_empty() {
            return;
        }

        let chunk_base = self.chunks.len();
        self.datagrams.reserve(other.datagrams.len());
        for datagram in &mut other.datagrams {
            datagram.chunk += chunk_base;
        }
        self.datagrams.append(&mut other.datagrams);
        self.chunks.append(&mut other.chunks);
    }

    fn ensure_chunk(&mut self, len: usize) -> bool {
        let need_new_chunk = match self.chunks.last() {
            Some(chunk) => chunk.capacity().saturating_sub(chunk.len()) < len,
            None => true,
        };

        if need_new_chunk {
            self.chunks.push(Vec::with_capacity(CHUNK_BYTES.max(len)));
        }

        need_new_chunk
    }

    fn data(&self, datagram: &QueuedDatagram) -> &[u8] {
        let chunk = &self.chunks[datagram.chunk];
        &chunk[datagram.offset..datagram.offset + datagram.len]
    }
}

/// Send all queued datagrams through `socket`.
///
/// On Linux this uses `sendmmsg` for a single syscall.  On other platforms
/// it loops over `send_to`.
pub async fn flush_batch(
    socket: &tokio::net::UdpSocket,
    batch: &DatagramBatch,
) -> std::io::Result<()> {
    flush_batch_with_retry_budget(socket, batch, Duration::ZERO)
        .await
        .map(|_| ())
}

pub async fn flush_batch_with_retry_budget(
    socket: &tokio::net::UdpSocket,
    batch: &DatagramBatch,
    retry_budget: Duration,
) -> std::io::Result<FlushStats> {
    if batch.is_empty() {
        return Ok(FlushStats::default());
    }

    #[cfg(not(target_os = "linux"))]
    let _ = retry_budget;

    #[cfg(target_os = "linux")]
    {
        sendmmsg_linux(socket, batch, retry_budget).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        send_each(socket, batch).await
    }
}

/// Fallback: one `send_to` per datagram.
async fn send_each(
    socket: &tokio::net::UdpSocket,
    batch: &DatagramBatch,
) -> std::io::Result<FlushStats> {
    for d in &batch.datagrams {
        socket.send_to(batch.data(d), d.addr).await?;
    }
    Ok(FlushStats::default())
}

/// Linux `sendmmsg` path.
///
/// We use `libc::sendmmsg` directly through a raw file descriptor.  Tokio's
/// `UdpSocket` exposes `as_raw_fd()` on Unix, which we can use for the
/// batched send.  Since `sendmmsg` is non-blocking for UDP (datagram sockets
/// don't block on send), this is safe to call from an async context without
/// blocking the reactor.
#[cfg(target_os = "linux")]
async fn sendmmsg_linux(
    socket: &tokio::net::UdpSocket,
    batch: &DatagramBatch,
) -> std::io::Result<FlushStats> {
    use std::os::fd::AsRawFd;

    // Maximum number of messages per sendmmsg call (kernel limit is typically
    // 1024, but we cap lower to keep stack usage reasonable).
    const CHUNK_SIZE: usize = 64;

    let fd = socket.as_raw_fd();
    let started_at = Instant::now();
    let mut stats = FlushStats::default();
    let mut cursor = 0;

    while cursor < batch.datagrams.len() {
        let chunk_end = (cursor + CHUNK_SIZE).min(batch.datagrams.len());
        let mut chunk_cursor = cursor;

        while chunk_cursor < chunk_end {
            socket.writable().await?;
            let chunk = &batch.datagrams[chunk_cursor..chunk_end];
            match sendmmsg_chunk(fd, batch, chunk) {
                Ok(0) => {
                    stats.record_would_block();
                    wait_for_retry_readiness(socket, started_at, retry_budget).await?;
                }
                Ok(sent) => {
                    if sent < chunk.len() {
                        stats.record_partial();
                    }
                    chunk_cursor += sent;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    stats.record_would_block();
                    wait_for_retry_readiness(socket, started_at, retry_budget).await?;
                }
                Err(err) => return Err(err),
            }
        }

        cursor = chunk_end;
    }

    Ok(stats)
}

#[cfg(target_os = "linux")]
async fn wait_for_retry_readiness(
    socket: &tokio::net::UdpSocket,
    started_at: Instant,
    retry_budget: Duration,
) -> io::Result<()> {
    let elapsed = started_at.elapsed();
    if retry_budget.is_zero() || elapsed >= retry_budget {
        return Err(io::Error::from(io::ErrorKind::WouldBlock));
    }

    let remaining = retry_budget.saturating_sub(elapsed);
    match tokio::time::timeout(remaining, socket.writable()).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::from(io::ErrorKind::WouldBlock)),
    }
}

#[cfg(target_os = "linux")]
fn sendmmsg_chunk(
    fd: std::os::fd::RawFd,
    batch: &DatagramBatch,
    chunk: &[QueuedDatagram],
) -> io::Result<usize> {
    let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(chunk.len());
    let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(chunk.len());
    let mut sockaddrs: Vec<SocketAddrStorage> = Vec::with_capacity(chunk.len());

    for d in chunk {
        let addr = socket_addr_to_storage(&d.addr);
        let data = batch.data(d);

        iovecs.push(libc::iovec {
            iov_base: data.as_ptr() as *mut libc::c_void,
            iov_len: data.len(),
        });

        sockaddrs.push(addr);
    }

    for i in 0..chunk.len() {
        let mut msg: libc::mmsghdr = unsafe { std::mem::zeroed() };
        msg.msg_hdr.msg_name = &sockaddrs[i].storage as *const _ as *mut libc::c_void;
        msg.msg_hdr.msg_namelen = sockaddrs[i].len;
        msg.msg_hdr.msg_iov = &iovecs[i] as *const _ as *mut libc::iovec;
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
fn socket_addr_to_storage(addr: &std::net::SocketAddr) -> SocketAddrStorage {
    use std::net::SocketAddr;

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
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn flush_empty_batch_returns_zero_stats() {
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind sender");
        let batch = DatagramBatch::new();

        let stats = flush_batch_with_retry_budget(&sender, &batch, Duration::from_millis(2))
            .await
            .expect("flush empty batch");

        assert_eq!(stats.would_block_count(), 0);
        assert_eq!(stats.partial_count(), 0);
    }

    #[tokio::test]
    async fn flush_batch_sends_to_ipv4_destination() {
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind sender");
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind receiver");
        let receiver_addr = receiver.local_addr().expect("receiver local addr");
        let sender_addr = sender.local_addr().expect("sender local addr");
        let payload = b"voice";

        let mut batch = DatagramBatch::new();
        batch
            .try_push_zeroed(receiver_addr, payload.len(), |buf| {
                buf.copy_from_slice(payload);
                Ok::<(), std::convert::Infallible>(())
            })
            .expect("queue datagram");

        flush_batch(&sender, &batch).await.expect("flush batch");

        let mut buf = [0; 16];
        let (len, from_addr) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
            .await
            .expect("receive timeout")
            .expect("receive datagram");

        assert_eq!(&buf[..len], payload);
        assert_eq!(from_addr, sender_addr);
    }
}
