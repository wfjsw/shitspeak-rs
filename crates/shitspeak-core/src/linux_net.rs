//! Linux-specific networking primitives shared by the UDP transports.

use std::cell::RefCell;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};

#[cfg(all(target_env = "musl", target_pointer_width = "64"))]
use std::sync::atomic::{AtomicBool, Ordering};

// Linux caps one sendmmsg call at UIO_MAXIOV. Keeping the same bound also
// prevents an invalid ExactSizeIterator implementation from pinning an
// unbounded allocation in thread-local storage.
const MAX_SENDMMSG_DATAGRAMS: usize = 1024;

thread_local! {
    /// Per-worker scratch avoids synchronization and allocations after the
    /// largest batch seen by that worker has established the vector capacity.
    static SENDMMSG_BUFFERS: RefCell<SendMmsgBuffers> =
        const { RefCell::new(SendMmsgBuffers::new()) };
}

/// Sends UDP datagrams with one native Linux `sendmmsg` operation.
///
/// The payloads are referenced directly; only socket addresses and syscall
/// metadata are written into reusable thread-local scratch storage. On 64-bit
/// musl this invokes the raw syscall because musl's wrapper loops over
/// `sendmsg`. Other Linux environments keep using their libc wrapper.
///
/// A reentrant call on the same thread uses temporary local scratch rather
/// than panicking or waiting for the outer call's thread-local buffer.
pub fn sendmmsg_to<'a, I>(fd: BorrowedFd<'_>, datagrams: I) -> io::Result<usize>
where
    I: ExactSizeIterator<Item = (SocketAddr, &'a [u8])>,
{
    sendmmsg_to_from(
        fd,
        datagrams.map(|(target, payload)| (target, None, payload)),
    )
}

/// [`sendmmsg_to`] with an optional source address per datagram.
///
/// A socket bound to a wildcard address sends from whichever local address
/// the kernel selects for the route to the peer. On a host with several
/// addresses that is not necessarily the address the peer dialled (the kernel
/// never selects a deprecated address), and a peer whose UDP socket is
/// connected to the address it dialled drops datagrams from any other. A
/// `Some(source)` pins the datagram's source address through an
/// `IP_PKTINFO` / `IPV6_PKTINFO` control message; `None`, or a source whose
/// family differs from the target's, leaves the choice to the kernel.
///
/// A source the kernel rejects (an address that has since been removed) must
/// not cost the whole batch: when the call fails with `EINVAL`,
/// `EADDRNOTAVAIL` or `ENETUNREACH` it is retried once without any source, so
/// those datagrams go out from the kernel's choice instead.
pub fn sendmmsg_to_from<'a, I>(fd: BorrowedFd<'_>, datagrams: I) -> io::Result<usize>
where
    I: ExactSizeIterator<Item = (SocketAddr, Option<IpAddr>, &'a [u8])>,
{
    let fd = fd.as_raw_fd();
    let mut datagrams = Some(datagrams);
    match SENDMMSG_BUFFERS.try_with(|shared| {
        let datagrams = datagrams
            .take()
            .expect("sendmmsg iterator must only be consumed once");
        match shared.try_borrow_mut() {
            Ok(mut buffers) => buffers.send_to(fd, datagrams),
            Err(_) => SendMmsgBuffers::new().send_to(fd, datagrams),
        }
    }) {
        Ok(result) => result,
        Err(_) => SendMmsgBuffers::new().send_to(
            fd,
            datagrams
                .take()
                .expect("TLS failure must leave the sendmmsg iterator available"),
        ),
    }
}

/// Sends one datagram, optionally from a chosen source address; see
/// [`sendmmsg_to_from`]. A socket that cannot take the datagram right now
/// yields [`io::ErrorKind::WouldBlock`].
pub fn send_to_from(
    fd: BorrowedFd<'_>,
    target: SocketAddr,
    source: Option<IpAddr>,
    payload: &[u8],
) -> io::Result<usize> {
    match sendmmsg_to_from(fd, std::iter::once((target, source, payload)))? {
        0 => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        _ => Ok(payload.len()),
    }
}

struct SendMmsgBuffers {
    prepared: Vec<PreparedDatagram>,
    messages: Vec<SendMmsgHdr>,
    #[cfg(all(target_env = "musl", target_pointer_width = "64"))]
    libc_messages: Vec<libc::mmsghdr>,
}

impl SendMmsgBuffers {
    const fn new() -> Self {
        Self {
            prepared: Vec::new(),
            messages: Vec::new(),
            #[cfg(all(target_env = "musl", target_pointer_width = "64"))]
            libc_messages: Vec::new(),
        }
    }

    fn send_to<'a, I>(&mut self, fd: RawFd, datagrams: I) -> io::Result<usize>
    where
        I: ExactSizeIterator<Item = (SocketAddr, Option<IpAddr>, &'a [u8])>,
    {
        let expected = datagrams.len();
        if expected > MAX_SENDMMSG_DATAGRAMS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sendmmsg vector is too large",
            ));
        }

        self.prepared.clear();
        self.messages.clear();
        #[cfg(all(target_env = "musl", target_pointer_width = "64"))]
        self.libc_messages.clear();

        self.prepared.reserve(expected);
        let mut any_source = false;
        for (target, source, payload) in datagrams {
            if self.prepared.len() == MAX_SENDMMSG_DATAGRAMS {
                self.prepared.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "sendmmsg vector is too large",
                ));
            }
            let mut control = SourceControl::EMPTY;
            if let Some(source) = source {
                any_source |= control.set_source(target, source);
            }
            self.prepared.push(PreparedDatagram {
                addr: SocketAddrBuffer::new(target),
                iovec: libc::iovec {
                    // Linux does not mutate an iovec used by sendmmsg.
                    iov_base: payload.as_ptr().cast_mut().cast(),
                    iov_len: payload.len(),
                },
                control,
            });
        }

        self.messages.reserve(self.prepared.len());
        for prepared in &mut self.prepared {
            self.messages.push(SendMmsgHdr::new(
                prepared.addr.as_mut_ptr(),
                prepared.addr.len(),
                &mut prepared.iovec,
                prepared.control.as_mut_ptr(),
                prepared.control.len(),
            ));
        }

        // SAFETY: every nested pointer targets `prepared` or a payload yielded
        // above. Neither is changed until the synchronous syscall returns.
        let mut result = unsafe {
            sendmmsg(
                fd,
                &mut self.messages,
                #[cfg(all(target_env = "musl", target_pointer_width = "64"))]
                &mut self.libc_messages,
            )
        };

        // `sendmmsg` fails as a whole only when its first datagram fails, so
        // nothing was sent yet and the batch can be retried as it stands. A
        // source the host no longer has fails the route lookup for IPv4
        // (`ENETUNREACH`) and the address check for IPv6 (`EINVAL` /
        // `EADDRNOTAVAIL`). A peer that is genuinely unreachable fails the
        // retry the same way and that error is what the caller sees.
        if any_source
            && matches!(
                &result,
                Err(error) if matches!(
                    error.raw_os_error(),
                    Some(libc::EINVAL | libc::EADDRNOTAVAIL | libc::ENETUNREACH)
                )
            )
        {
            for message in &mut self.messages {
                message.clear_control();
            }
            // SAFETY: as above; only the control pointers were reset.
            result = unsafe {
                sendmmsg(
                    fd,
                    &mut self.messages,
                    #[cfg(all(target_env = "musl", target_pointer_width = "64"))]
                    &mut self.libc_messages,
                )
            };
        }

        // Retain capacity, but do not retain stale pointers to caller-owned
        // payloads after the synchronous operation has completed.
        self.messages.clear();
        self.prepared.clear();
        #[cfg(all(target_env = "musl", target_pointer_width = "64"))]
        self.libc_messages.clear();
        result
    }
}

struct PreparedDatagram {
    addr: SocketAddrBuffer,
    iovec: libc::iovec,
    control: SourceControl,
}

/// Room for one `IP_PKTINFO` (`CMSG_SPACE` 32) or `IPV6_PKTINFO` (40)
/// control message on a 64-bit target.
const SOURCE_CONTROL_BYTES: usize = 40;

const _: () = {
    // SAFETY: `CMSG_SPACE` is alignment arithmetic on its argument.
    unsafe {
        assert!(
            libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as libc::c_uint) as usize
                <= SOURCE_CONTROL_BYTES
        );
        assert!(
            libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as libc::c_uint) as usize
                <= SOURCE_CONTROL_BYTES
        );
    }
};

/// The control message that selects one datagram's source address. Empty
/// (`len() == 0`) leaves the source to the kernel.
#[repr(C, align(8))]
struct SourceControl {
    bytes: [u8; SOURCE_CONTROL_BYTES],
    len: usize,
}

impl SourceControl {
    const EMPTY: Self = Self {
        bytes: [0; SOURCE_CONTROL_BYTES],
        len: 0,
    };

    /// Select `source` for a datagram to `target`. Only a source of the
    /// target's address family can apply; returns whether one was written.
    fn set_source(&mut self, target: SocketAddr, source: IpAddr) -> bool {
        match (source, target) {
            (IpAddr::V4(source), SocketAddr::V4(_)) => {
                let info = libc::in_pktinfo {
                    ipi_ifindex: 0,
                    ipi_spec_dst: libc::in_addr {
                        s_addr: u32::from_ne_bytes(source.octets()),
                    },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                };
                self.write(libc::IPPROTO_IP, libc::IP_PKTINFO, &info);
                true
            }
            (IpAddr::V6(source), SocketAddr::V6(target)) => {
                let info = libc::in6_pktinfo {
                    ipi6_addr: libc::in6_addr {
                        s6_addr: source.octets(),
                    },
                    // A link-local source is only meaningful with its interface.
                    ipi6_ifindex: target.scope_id(),
                };
                self.write(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, &info);
                true
            }
            _ => false,
        }
    }

    fn write<T>(&mut self, level: libc::c_int, kind: libc::c_int, payload: &T) {
        let data_len = std::mem::size_of::<T>() as libc::c_uint;
        // SAFETY: `CMSG_SPACE` is alignment arithmetic on its argument.
        let space = unsafe { libc::CMSG_SPACE(data_len) } as usize;
        assert!(space <= SOURCE_CONTROL_BYTES);
        let header = self.bytes.as_mut_ptr().cast::<libc::cmsghdr>();
        // SAFETY: `bytes` is 8-byte aligned (`repr(align(8))`) and holds at
        // least `CMSG_SPACE(data_len)` bytes, so the header and its data fit.
        unsafe {
            (*header).cmsg_level = level;
            (*header).cmsg_type = kind;
            (*header).cmsg_len = libc::CMSG_LEN(data_len) as _;
            std::ptr::copy_nonoverlapping(
                (payload as *const T).cast::<u8>(),
                libc::CMSG_DATA(header),
                data_len as usize,
            );
        }
        self.len = space;
    }

    fn as_mut_ptr(&mut self) -> *mut libc::c_void {
        if self.len == 0 {
            std::ptr::null_mut()
        } else {
            self.bytes.as_mut_ptr().cast()
        }
    }

    fn len(&self) -> usize {
        self.len
    }
}

#[repr(C)]
union SocketAddrUnion {
    v4: libc::sockaddr_in,
    v6: libc::sockaddr_in6,
}

struct SocketAddrBuffer {
    addr: SocketAddrUnion,
    len: libc::socklen_t,
}

impl SocketAddrBuffer {
    fn new(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(addr) => Self {
                addr: SocketAddrUnion {
                    v4: libc::sockaddr_in {
                        sin_family: libc::AF_INET as libc::sa_family_t,
                        sin_port: addr.port().to_be(),
                        sin_addr: libc::in_addr {
                            s_addr: u32::from_ne_bytes(addr.ip().octets()),
                        },
                        sin_zero: [0; 8],
                    },
                },
                len: std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            },
            SocketAddr::V6(addr) => Self {
                addr: SocketAddrUnion {
                    v6: libc::sockaddr_in6 {
                        sin6_family: libc::AF_INET6 as libc::sa_family_t,
                        sin6_port: addr.port().to_be(),
                        sin6_flowinfo: addr.flowinfo(),
                        sin6_addr: libc::in6_addr {
                            s6_addr: addr.ip().octets(),
                        },
                        sin6_scope_id: addr.scope_id(),
                    },
                },
                len: std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            },
        }
    }

    fn as_mut_ptr(&mut self) -> *mut libc::c_void {
        (&mut self.addr as *mut SocketAddrUnion).cast()
    }

    fn len(&self) -> libc::socklen_t {
        self.len
    }
}

/// A message with the layout expected by the selected path. The control
/// pointer is null and its length zero unless a source address is selected.
#[cfg(all(target_env = "musl", target_pointer_width = "64"))]
#[repr(C)]
struct SendMmsgHdr {
    msg_name: *mut libc::c_void,
    msg_namelen: libc::c_int,
    msg_namelen_pad: libc::c_uint,
    msg_iov: *mut libc::iovec,
    msg_iovlen: libc::c_ulong,
    msg_control: *mut libc::c_void,
    msg_controllen: libc::c_ulong,
    msg_flags: libc::c_uint,
    msg_flags_pad: libc::c_uint,
    msg_len: libc::c_uint,
    msg_len_pad: libc::c_uint,
}

#[cfg(not(all(target_env = "musl", target_pointer_width = "64")))]
#[repr(transparent)]
struct SendMmsgHdr {
    inner: libc::mmsghdr,
}

impl SendMmsgHdr {
    fn new(
        msg_name: *mut libc::c_void,
        msg_namelen: libc::socklen_t,
        msg_iov: *mut libc::iovec,
        msg_control: *mut libc::c_void,
        msg_controllen: usize,
    ) -> Self {
        #[cfg(all(target_env = "musl", target_pointer_width = "64"))]
        {
            Self {
                msg_name,
                msg_namelen: msg_namelen as libc::c_int,
                msg_namelen_pad: 0,
                msg_iov,
                msg_iovlen: 1,
                msg_control,
                msg_controllen: msg_controllen as libc::c_ulong,
                msg_flags: 0,
                msg_flags_pad: 0,
                msg_len: 0,
                msg_len_pad: 0,
            }
        }

        #[cfg(not(all(target_env = "musl", target_pointer_width = "64")))]
        {
            let mut inner: libc::mmsghdr = unsafe { std::mem::zeroed() };
            inner.msg_hdr.msg_name = msg_name;
            inner.msg_hdr.msg_namelen = msg_namelen;
            inner.msg_hdr.msg_iov = msg_iov;
            inner.msg_hdr.msg_iovlen = 1;
            inner.msg_hdr.msg_control = msg_control;
            inner.msg_hdr.msg_controllen = msg_controllen as _;
            Self { inner }
        }
    }

    /// Drop the control message, leaving the source to the kernel.
    fn clear_control(&mut self) {
        #[cfg(all(target_env = "musl", target_pointer_width = "64"))]
        {
            self.msg_control = std::ptr::null_mut();
            self.msg_controllen = 0;
        }

        #[cfg(not(all(target_env = "musl", target_pointer_width = "64")))]
        {
            self.inner.msg_hdr.msg_control = std::ptr::null_mut();
            self.inner.msg_hdr.msg_controllen = 0;
        }
    }
}

/// # Safety
///
/// Every nested pointer in `messages` must remain valid for this synchronous
/// call, and the descriptor must remain open.
unsafe fn sendmmsg(
    fd: RawFd,
    messages: &mut [SendMmsgHdr],
    #[cfg(all(target_env = "musl", target_pointer_width = "64"))] libc_messages: &mut Vec<
        libc::mmsghdr,
    >,
) -> io::Result<usize> {
    if messages.is_empty() {
        return Ok(0);
    }

    let message_count = messages.len() as libc::c_uint;

    #[cfg(all(target_env = "musl", target_pointer_width = "64"))]
    {
        static RAW_SENDMMSG_UNAVAILABLE: AtomicBool = AtomicBool::new(false);

        if !RAW_SENDMMSG_UNAVAILABLE.load(Ordering::Relaxed) {
            let result = unsafe {
                libc::syscall(
                    libc::SYS_sendmmsg,
                    libc::c_long::from(fd),
                    messages.as_mut_ptr(),
                    libc::c_long::from(message_count),
                    0 as libc::c_long,
                )
            };
            if result >= 0 {
                return Ok(result as usize);
            }

            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ENOSYS) {
                return Err(error);
            }
            RAW_SENDMMSG_UNAVAILABLE.store(true, Ordering::Relaxed);
        }

        return unsafe { sendmmsg_via_libc(fd, messages, message_count, libc_messages) };
    }

    #[cfg(not(all(target_env = "musl", target_pointer_width = "64")))]
    {
        let result = unsafe {
            libc::sendmmsg(
                fd,
                messages.as_mut_ptr().cast::<libc::mmsghdr>(),
                message_count,
                0,
            )
        };
        sendmmsg_result(result)
    }
}

#[cfg(all(target_env = "musl", target_pointer_width = "64"))]
unsafe fn sendmmsg_via_libc(
    fd: RawFd,
    messages: &[SendMmsgHdr],
    message_count: libc::c_uint,
    libc_messages: &mut Vec<libc::mmsghdr>,
) -> io::Result<usize> {
    libc_messages.clear();
    libc_messages.reserve(messages.len());
    for message in messages {
        let mut libc_message: libc::mmsghdr = unsafe { std::mem::zeroed() };
        libc_message.msg_hdr.msg_name = message.msg_name;
        libc_message.msg_hdr.msg_namelen = message.msg_namelen as libc::socklen_t;
        libc_message.msg_hdr.msg_iov = message.msg_iov;
        libc_message.msg_hdr.msg_iovlen = message.msg_iovlen as libc::c_int;
        libc_message.msg_hdr.msg_control = message.msg_control;
        libc_message.msg_hdr.msg_controllen = message.msg_controllen as _;
        libc_messages.push(libc_message);
    }

    let result = unsafe { libc::sendmmsg(fd, libc_messages.as_mut_ptr(), message_count, 0) };
    sendmmsg_result(result)
}

fn sendmmsg_result(result: libc::c_int) -> io::Result<usize> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    struct ReentrantDatagram<'a> {
        fd: BorrowedFd<'a>,
        target: SocketAddr,
        payload: Option<&'a [u8]>,
    }

    impl<'a> Iterator for ReentrantDatagram<'a> {
        type Item = (SocketAddr, &'a [u8]);

        fn next(&mut self) -> Option<Self::Item> {
            let payload = self.payload.take()?;
            let nested = std::iter::empty::<(SocketAddr, &[u8])>();
            assert_eq!(sendmmsg_to(self.fd, nested).expect("nested send"), 0);
            Some((self.target, payload))
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let remaining = usize::from(self.payload.is_some());
            (remaining, Some(remaining))
        }
    }

    impl ExactSizeIterator for ReentrantDatagram<'_> {}

    #[test]
    fn sends_multiple_ipv4_datagrams() {
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .expect("set timeout");
        let target = receiver.local_addr().expect("receiver address");
        let payloads = [b"first".as_slice(), b"second".as_slice()];

        let sent = sendmmsg_to(
            sender.as_fd(),
            payloads.iter().copied().map(|payload| (target, payload)),
        )
        .expect("send datagrams");
        assert_eq!(sent, payloads.len());

        let mut buffer = [0_u8; 16];
        for expected in payloads {
            let received = receiver.recv(&mut buffer).expect("receive datagram");
            assert_eq!(&buffer[..received], expected);
        }
    }

    /// A wildcard-bound sender and a loopback receiver. All of 127.0.0.0/8 is
    /// local, so 127.0.0.2 stands in for a second address of the host; with no
    /// source selected the kernel answers a 127.0.0.1 peer from 127.0.0.1.
    fn wildcard_sender_and_receiver() -> (std::net::UdpSocket, std::net::UdpSocket, SocketAddr) {
        let sender = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind sender");
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .expect("set timeout");
        let target = receiver.local_addr().expect("receiver address");
        (sender, receiver, target)
    }

    fn source_of_next(receiver: &std::net::UdpSocket, expected_payload: &[u8]) -> IpAddr {
        let mut buffer = [0_u8; 16];
        let (received, from) = receiver.recv_from(&mut buffer).expect("receive datagram");
        assert_eq!(&buffer[..received], expected_payload);
        from.ip()
    }

    #[test]
    fn selected_source_address_is_used_per_datagram() {
        let (sender, receiver, target) = wildcard_sender_and_receiver();
        let second: IpAddr = [127, 0, 0, 2].into();

        let sent = sendmmsg_to_from(
            sender.as_fd(),
            [
                (target, Some(second), b"pinned".as_slice()),
                (target, None, b"unpinned".as_slice()),
                (target, Some(second), b"pinned again".as_slice()),
            ]
            .into_iter(),
        )
        .expect("send datagrams");
        assert_eq!(sent, 3);

        assert_eq!(source_of_next(&receiver, b"pinned"), second);
        assert_eq!(
            source_of_next(&receiver, b"unpinned"),
            IpAddr::from([127, 0, 0, 1]),
            "a datagram without a source keeps the kernel's choice"
        );
        assert_eq!(source_of_next(&receiver, b"pinned again"), second);
    }

    #[test]
    fn source_of_another_family_is_ignored() {
        let (sender, receiver, target) = wildcard_sender_and_receiver();

        let sent = sendmmsg_to_from(
            sender.as_fd(),
            std::iter::once((
                target,
                Some(IpAddr::from(std::net::Ipv6Addr::LOCALHOST)),
                b"mixed".as_slice(),
            )),
        )
        .expect("send datagram");
        assert_eq!(sent, 1);
        assert_eq!(
            source_of_next(&receiver, b"mixed"),
            IpAddr::from([127, 0, 0, 1])
        );
    }

    /// An address the host no longer has must not cost the batch: the kernel
    /// rejects the source with `EINVAL`, and the datagrams go out without it.
    #[test]
    fn rejected_source_address_does_not_drop_the_batch() {
        let (sender, receiver, target) = wildcard_sender_and_receiver();
        let not_local: IpAddr = [203, 0, 113, 9].into();
        let second: IpAddr = [127, 0, 0, 2].into();

        let sent = sendmmsg_to_from(
            sender.as_fd(),
            [
                (target, Some(not_local), b"stale".as_slice()),
                (target, Some(second), b"valid".as_slice()),
            ]
            .into_iter(),
        )
        .expect("batch with a stale source still sends");
        assert_eq!(sent, 2);

        assert_eq!(
            source_of_next(&receiver, b"stale"),
            IpAddr::from([127, 0, 0, 1])
        );
        assert_eq!(
            source_of_next(&receiver, b"valid"),
            IpAddr::from([127, 0, 0, 1])
        );
    }

    #[test]
    fn send_to_from_pins_a_single_datagram() {
        let (sender, receiver, target) = wildcard_sender_and_receiver();
        let second: IpAddr = [127, 0, 0, 2].into();

        assert_eq!(
            send_to_from(sender.as_fd(), target, Some(second), b"one").expect("send"),
            3
        );
        assert_eq!(source_of_next(&receiver, b"one"), second);
    }

    #[test]
    fn reentrant_iterator_uses_local_scratch() {
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .expect("set timeout");
        let fd = sender.as_fd();
        let datagrams = ReentrantDatagram {
            fd,
            target: receiver.local_addr().expect("receiver address"),
            payload: Some(b"outer"),
        };

        assert_eq!(sendmmsg_to(fd, datagrams).expect("outer send"), 1);
        let mut buffer = [0_u8; 16];
        let received = receiver.recv(&mut buffer).expect("receive datagram");
        assert_eq!(&buffer[..received], b"outer");
    }

    #[test]
    fn warm_thread_local_scratch_retains_allocations() {
        std::thread::spawn(|| {
            let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind sender");
            let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
            let target = receiver.local_addr().expect("receiver address");
            let fd = sender.as_fd();
            let payloads = [b"one".as_slice(), b"two".as_slice()];

            assert_eq!(
                sendmmsg_to(
                    fd,
                    payloads.iter().copied().map(|payload| (target, payload)),
                )
                .expect("warm send"),
                2
            );
            let before = SENDMMSG_BUFFERS.with(|buffers| {
                let buffers = buffers.borrow();
                (
                    buffers.prepared.as_ptr(),
                    buffers.prepared.capacity(),
                    buffers.messages.as_ptr(),
                    buffers.messages.capacity(),
                )
            });

            assert_eq!(
                sendmmsg_to(fd, std::iter::once((target, b"three".as_slice())))
                    .expect("reuse send"),
                1
            );
            let after = SENDMMSG_BUFFERS.with(|buffers| {
                let buffers = buffers.borrow();
                (
                    buffers.prepared.as_ptr(),
                    buffers.prepared.capacity(),
                    buffers.messages.as_ptr(),
                    buffers.messages.capacity(),
                )
            });

            assert_eq!(after, before);
        })
        .join()
        .expect("scratch test thread");
    }

    #[test]
    fn compact_socket_address_storage_avoids_sockaddr_storage_overhead() {
        assert_eq!(
            std::mem::size_of::<SocketAddrUnion>(),
            std::mem::size_of::<libc::sockaddr_in6>()
        );
        assert!(
            std::mem::size_of::<SocketAddrUnion>() < std::mem::size_of::<libc::sockaddr_storage>()
        );
    }

    #[cfg(all(target_env = "musl", target_pointer_width = "64"))]
    #[test]
    fn sendmmsg_header_matches_linux_64_bit_uapi_layout() {
        use std::mem::{align_of, offset_of, size_of};

        assert_eq!(align_of::<SendMmsgHdr>(), 8);
        assert_eq!(size_of::<SendMmsgHdr>(), 64);
        assert_eq!(offset_of!(SendMmsgHdr, msg_name), 0);
        assert_eq!(offset_of!(SendMmsgHdr, msg_namelen), 8);
        assert_eq!(offset_of!(SendMmsgHdr, msg_iov), 16);
        assert_eq!(offset_of!(SendMmsgHdr, msg_iovlen), 24);
        assert_eq!(offset_of!(SendMmsgHdr, msg_control), 32);
        assert_eq!(offset_of!(SendMmsgHdr, msg_controllen), 40);
        assert_eq!(offset_of!(SendMmsgHdr, msg_flags), 48);
        assert_eq!(offset_of!(SendMmsgHdr, msg_len), 56);
    }
}
