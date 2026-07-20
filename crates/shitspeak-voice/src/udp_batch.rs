//! Batched UDP send using `sendmmsg` on Linux, falling back to per-packet
//! `send_to` on other platforms.
//!
//! On Linux, `sendmmsg` sends multiple datagrams in a single syscall,
//! significantly reducing overhead for voice packets (which are small and
//! frequent). On 64-bit musl we use a kernel-layout header and invoke the
//! syscall directly because musl's wrapper loops over `sendmsg`. On non-Linux
//! platforms we fall back to a simple loop of `send_to` calls.

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
#[cfg(not(target_os = "linux"))]
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
/// We use the native Linux operation through a borrowed file descriptor.
/// Since `sendmmsg` is non-blocking for UDP (datagram sockets
/// don't block on send), this is safe to call from an async context without
/// blocking the reactor.
#[cfg(target_os = "linux")]
async fn sendmmsg_linux(
    socket: &tokio::net::UdpSocket,
    batch: &DatagramBatch,
    retry_budget: Duration,
) -> std::io::Result<FlushStats> {
    use std::os::fd::AsFd;

    // Maximum number of messages per sendmmsg call (kernel limit is typically
    // 1024, but we cap lower to bound retained per-worker scratch memory).
    const CHUNK_SIZE: usize = 512;

    let fd = socket.as_fd();
    let started_at = Instant::now();
    let mut stats = FlushStats::default();
    let mut cursor = 0;

    while cursor < batch.datagrams.len() {
        let chunk_end = (cursor + CHUNK_SIZE).min(batch.datagrams.len());
        let mut chunk_cursor = cursor;

        while chunk_cursor < chunk_end {
            let chunk = &batch.datagrams[chunk_cursor..chunk_end];
            let result = socket.try_io(tokio::io::Interest::WRITABLE, || {
                match sendmmsg_chunk(fd, batch, chunk)? {
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
                    wait_for_retry_readiness(socket, started_at, retry_budget).await?;
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
    fd: std::os::fd::BorrowedFd<'_>,
    batch: &DatagramBatch,
    chunk: &[QueuedDatagram],
) -> io::Result<usize> {
    shitspeak_core::linux_net::sendmmsg_to(
        fd,
        chunk
            .iter()
            .map(|datagram| (datagram.addr, batch.data(datagram))),
    )
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
