//! Batched UDP send using `sendmmsg` on Linux, falling back to per-packet
//! `send_to` on other platforms.
//!
//! On Linux, `libc::sendmmsg` sends multiple datagrams in a single syscall,
//! significantly reducing overhead for voice packets (which are small and
//! frequent).  On non-Linux platforms we fall back to a simple loop of
//! `send_to` calls.

use bytes::Bytes;

/// A single datagram queued for batched transmission.
pub struct QueuedDatagram {
    /// Destination socket address.
    pub addr: std::net::SocketAddr,
    /// Encrypted payload.
    pub data: Bytes,
}

/// Send all queued datagrams through `socket`.
///
/// On Linux this uses `sendmmsg` for a single syscall.  On other platforms
/// it loops over `send_to`.
pub async fn flush_batch(
    socket: &tokio::net::UdpSocket,
    batch: &[QueuedDatagram],
) -> std::io::Result<()> {
    if batch.is_empty() {
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        sendmmsg_linux(socket, batch).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        send_each(socket, batch).await
    }
}

/// Fallback: one `send_to` per datagram.
async fn send_each(
    socket: &tokio::net::UdpSocket,
    batch: &[QueuedDatagram],
) -> std::io::Result<()> {
    for d in batch {
        socket.send_to(&d.data, d.addr).await?;
    }
    Ok(())
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
    batch: &[QueuedDatagram],
) -> std::io::Result<()> {
    use std::io;
    use std::os::fd::AsRawFd;

    // Maximum number of messages per sendmmsg call (kernel limit is typically
    // 1024, but we cap lower to keep stack usage reasonable).
    const CHUNK_SIZE: usize = 64;

    let fd = socket.as_raw_fd();

    // Convert our batch into libc::mmsghdr structures.
    // We process in chunks to avoid huge stack allocations.
    for chunk in batch.chunks(CHUNK_SIZE) {
        let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(chunk.len());
        let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(chunk.len());
        let mut sockaddrs: Vec<libc::sockaddr_in6> = Vec::with_capacity(chunk.len());

        for d in chunk {
            let addr = socket_addr_to_sockaddr_in6(&d.addr);

            iovecs.push(libc::iovec {
                iov_base: d.data.as_ptr() as *mut libc::c_void,
                iov_len: d.data.len(),
            });

            sockaddrs.push(addr);
        }

        for i in 0..chunk.len() {
            msgs.push(libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: &sockaddrs[i] as *const _ as *mut libc::c_void,
                    msg_namelen: std::mem::size_of::<libc::sockaddr_in6>() as u32,
                    msg_iov: &iovecs[i] as *const _ as *mut libc::iovec,
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            });
        }

        // Safety: sendmmsg operates on UDP datagram sockets and is non-blocking.
        // The buffers (iovecs, sockaddrs, msgs) are stack-pinned for this call.
        let ret = unsafe {
            libc::sendmmsg(
                fd,
                msgs.as_mut_ptr(),
                msgs.len() as u32,
                0, // flags
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // Check for partial failures
        let sent = ret as usize;
        if sent < chunk.len() {
            // Some messages weren't sent — log but don't fail the whole batch
            tracing::warn!(
                "sendmmsg sent {}/{} datagrams",
                sent,
                chunk.len()
            );
        }
    }

    Ok(())
}

/// Convert a `SocketAddr` to a `libc::sockaddr_in6` (supports both IPv4-mapped
/// IPv6 and native IPv6).
#[cfg(target_os = "linux")]
fn socket_addr_to_sockaddr_in6(addr: &std::net::SocketAddr) -> libc::sockaddr_in6 {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    sa.sin6_family = libc::AF_INET6 as u16;

    match addr.ip() {
        IpAddr::V4(v4) => {
            // IPv4-mapped IPv6: ::ffff:a.b.c.d
            let octets = v4.octets();
            sa.sin6_addr.s6_addr[10] = 0xff;
            sa.sin6_addr.s6_addr[11] = 0xff;
            sa.sin6_addr.s6_addr[12] = octets[0];
            sa.sin6_addr.s6_addr[13] = octets[1];
            sa.sin6_addr.s6_addr[14] = octets[2];
            sa.sin6_addr.s6_addr[15] = octets[3];
        }
        IpAddr::V6(v6) => {
            sa.sin6_addr.s6_addr = v6.octets();
        }
    }

    sa.sin6_port = addr.port().to_be();
    sa
}
