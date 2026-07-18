//! UDP shared-port mux for S2S UDP-family transports.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, ready};

use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::sync::{
    Mutex,
    mpsc::{self, error::TrySendError},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use super::{
    bind_ephemeral_udp_dial_socket, bind_udp_socket_with_ipv6_only,
    udp_batch::{
        RecvDatagramBatch, UDP_RECV_BATCH_MAX_DATAGRAMS, UdpBatchDatagram, recv_udp_batch,
        send_udp_batch,
    },
};
use crate::service_level::TransportKind;

pub(crate) const DISCRIMINATOR_LEN: usize = 1;

const MARKER_MASK: u8 = 0b1100_0000;
const MARKER_BITS: u8 = 0b1000_0000;
const ID_MASK: u8 = 0b0011_1111;
const MIN_BASELINE_QUEUE_CAPACITY: usize = 1024;
const DATAGRAMS_PER_USER_BASELINE: usize = 16;
const BURST_MULTIPLIER: usize = 5;
const MIN_HARD_QUEUE_CAPACITY: usize = MIN_BASELINE_QUEUE_CAPACITY * BURST_MULTIPLIER;
const DATAGRAMS_PER_USER_HARD_CAP: usize = 128;
const MAX_DATAGRAM: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UdpMuxQueueTuning {
    baseline_capacity: usize,
    burst_capacity: usize,
    hard_capacity: usize,
}

impl UdpMuxQueueTuning {
    pub(crate) fn for_max_users(max_users: usize) -> Self {
        let users = max_users.max(1);
        let baseline_capacity = users
            .saturating_mul(DATAGRAMS_PER_USER_BASELINE)
            .max(MIN_BASELINE_QUEUE_CAPACITY);
        let burst_capacity = baseline_capacity.saturating_mul(BURST_MULTIPLIER);
        let hard_capacity = users
            .saturating_mul(DATAGRAMS_PER_USER_HARD_CAP)
            .max(MIN_HARD_QUEUE_CAPACITY)
            .max(burst_capacity);
        Self {
            baseline_capacity,
            burst_capacity,
            hard_capacity,
        }
    }

    pub(crate) fn baseline_capacity(&self) -> usize {
        self.baseline_capacity
    }

    pub(crate) fn burst_capacity(&self) -> usize {
        self.burst_capacity
    }

    pub(crate) fn hard_capacity(&self) -> usize {
        self.hard_capacity
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MuxProtocol {
    Udp,
    Kcp,
    Quic,
}

impl MuxProtocol {
    fn from_transport(kind: TransportKind) -> Option<Self> {
        match kind {
            TransportKind::Udp => Some(Self::Udp),
            TransportKind::Kcp => Some(Self::Kcp),
            TransportKind::Quic => Some(Self::Quic),
            TransportKind::Tcp => None,
        }
    }

    fn to_transport(self) -> TransportKind {
        match self {
            Self::Udp => TransportKind::Udp,
            Self::Kcp => TransportKind::Kcp,
            Self::Quic => TransportKind::Quic,
        }
    }

    fn discriminator(self) -> u8 {
        MARKER_BITS
            | match self {
                Self::Udp => 0,
                Self::Kcp => 1,
                Self::Quic => 2,
            }
    }

    fn decode(value: u8) -> io::Result<Self> {
        if value & MARKER_MASK != MARKER_BITS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing S2S UDP mux discriminator marker",
            ));
        }
        match value & ID_MASK {
            0 => Ok(Self::Udp),
            1 => Ok(Self::Kcp),
            2 => Ok(Self::Quic),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown S2S UDP mux protocol id",
            )),
        }
    }
}

#[derive(Debug)]
struct MuxDatagram {
    payload: Vec<u8>,
    peer_addr: SocketAddr,
}

#[derive(Debug)]
struct ProtocolSlot {
    tx: mpsc::Sender<MuxDatagram>,
    rx: parking_lot::Mutex<Option<mpsc::Receiver<MuxDatagram>>>,
    adaptive_capacity: AtomicUsize,
    tuning: UdpMuxQueueTuning,
}

impl ProtocolSlot {
    fn new(tuning: UdpMuxQueueTuning) -> Self {
        let (tx, rx) = mpsc::channel(tuning.hard_capacity());
        Self {
            tx,
            rx: parking_lot::Mutex::new(Some(rx)),
            adaptive_capacity: AtomicUsize::new(tuning.baseline_capacity()),
            tuning,
        }
    }

    fn take_rx(&self) -> io::Result<mpsc::Receiver<MuxDatagram>> {
        self.rx.lock().take().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "S2S UDP mux protocol receiver was already taken",
            )
        })
    }

    fn try_send(
        &self,
        datagram: MuxDatagram,
    ) -> Result<Option<(usize, usize)>, TrySendError<MuxDatagram>> {
        let queued_len = self.queued_len();
        let growth = self.grow_for_queued_len(queued_len);
        self.tx.try_send(datagram)?;
        Ok(growth)
    }

    fn queued_len(&self) -> usize {
        self.tx.max_capacity().saturating_sub(self.tx.capacity())
    }

    fn capacity(&self) -> usize {
        self.adaptive_capacity.load(Ordering::Relaxed)
    }

    fn grow_for_queued_len(&self, queued_len: usize) -> Option<(usize, usize)> {
        loop {
            let current = self.adaptive_capacity.load(Ordering::Acquire);
            if queued_len < current || current >= self.tuning.hard_capacity() {
                return None;
            }
            let next = current
                .saturating_mul(BURST_MULTIPLIER)
                .min(self.tuning.hard_capacity())
                .max(current.saturating_add(1));
            match self.adaptive_capacity.compare_exchange(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some((current, next)),
                Err(_) => continue,
            }
        }
    }
}

#[derive(Debug)]
struct UdpMuxSocket {
    addr: SocketAddr,
    ipv6_only: bool,
    slots: HashMap<TransportKind, ProtocolSlot>,
    socket: Mutex<Option<Arc<UdpSocket>>>,
}

impl UdpMuxSocket {
    fn new(
        addr: SocketAddr,
        ipv6_only: bool,
        protocols: Vec<TransportKind>,
        queue_tuning: UdpMuxQueueTuning,
    ) -> Self {
        let mut slots = HashMap::new();
        for kind in protocols {
            slots.insert(kind, ProtocolSlot::new(queue_tuning));
        }
        Self {
            addr,
            ipv6_only,
            slots,
            socket: Mutex::new(None),
        }
    }

    fn has_protocol(&self, kind: TransportKind) -> bool {
        self.slots.contains_key(&kind)
    }

    async fn take_handle(
        self: &Arc<Self>,
        kind: TransportKind,
        shutdown: CancellationToken,
    ) -> io::Result<UdpMuxHandle> {
        let protocol = MuxProtocol::from_transport(kind).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "transport is not UDP-family")
        })?;
        if !self.slots.contains_key(&kind) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{kind:?} is not registered on UDP mux {}", self.addr),
            ));
        }
        let socket = self.ensure_socket(shutdown).await?;
        let slot = self.slots.get(&kind).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{kind:?} is not registered on UDP mux {}", self.addr),
            )
        })?;
        let rx = slot.take_rx()?;
        Ok(UdpMuxHandle::new(socket, protocol, rx))
    }

    async fn ensure_socket(
        self: &Arc<Self>,
        shutdown: CancellationToken,
    ) -> io::Result<Arc<UdpSocket>> {
        let mut guard = self.socket.lock().await;
        if let Some(socket) = guard.as_ref() {
            return Ok(socket.clone());
        }

        let socket = Arc::new(bind_udp_socket_with_ipv6_only(self.addr, self.ipv6_only).await?);
        tokio::spawn(run_mux_read_loop(self.clone(), socket.clone(), shutdown));
        *guard = Some(socket.clone());
        Ok(socket)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct UdpMuxSet {
    sockets: Arc<Vec<Arc<UdpMuxSocket>>>,
    aliases: Arc<HashMap<SocketAddr, SocketAddr>>,
}

impl UdpMuxSet {
    pub(crate) fn new(
        listen_addrs: &[(TransportKind, SocketAddr)],
        queue_tuning: UdpMuxQueueTuning,
    ) -> io::Result<Self> {
        let mut by_addr: HashMap<SocketAddr, Vec<TransportKind>> = HashMap::new();
        for (kind, addr) in listen_addrs.iter().copied() {
            if MuxProtocol::from_transport(kind).is_some() {
                let kinds = by_addr.entry(addr).or_default();
                if !kinds.contains(&kind) {
                    kinds.push(kind);
                }
            }
        }

        let aliases = canonical_udp_bind_aliases(by_addr.keys().copied())?;
        let mut canonical_protocols: HashMap<SocketAddr, Vec<TransportKind>> = HashMap::new();
        for (addr, protocols) in by_addr {
            let canonical = aliases.get(&addr).copied().unwrap_or(addr);
            let target = canonical_protocols.entry(canonical).or_default();
            for protocol in protocols {
                if !target.contains(&protocol) {
                    target.push(protocol);
                }
            }
        }

        let mut sockets = Vec::new();
        for (addr, protocols) in canonical_protocols {
            let ipv6_only = addr.is_ipv6() && !addr.ip().is_unspecified();
            sockets.push(Arc::new(UdpMuxSocket::new(
                addr,
                ipv6_only,
                protocols,
                queue_tuning,
            )));
        }

        Ok(Self {
            sockets: Arc::new(sockets),
            aliases: Arc::new(aliases),
        })
    }

    pub(crate) async fn take_handle(
        &self,
        addr: SocketAddr,
        kind: TransportKind,
        shutdown: CancellationToken,
    ) -> io::Result<UdpMuxHandle> {
        let canonical = self.aliases.get(&addr).copied().unwrap_or(addr);
        let Some(socket) = self
            .sockets
            .iter()
            .find(|socket| socket.addr == canonical && socket.has_protocol(kind))
            .cloned()
        else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{kind:?} is not configured on UDP mux {addr}"),
            ));
        };
        socket.take_handle(kind, shutdown).await
    }

    pub(crate) fn binding_for(&self, addr: SocketAddr) -> io::Result<(SocketAddr, bool)> {
        let canonical = self.aliases.get(&addr).copied().unwrap_or(addr);
        let socket = self
            .sockets
            .iter()
            .find(|socket| socket.addr == canonical)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("UDP-family listener {addr} is not configured"),
                )
            })?;
        Ok((canonical, socket.ipv6_only))
    }

    pub(crate) fn supports_remote(&self, addr: SocketAddr, remote: SocketAddr) -> bool {
        self.binding_for(addr)
            .map(|(local, ipv6_only)| super::socket_addr_supports_remote(local, ipv6_only, remote))
            .unwrap_or(false)
    }

    #[cfg(test)]
    fn socket_count(&self) -> usize {
        self.sockets.len()
    }
}

fn canonical_udp_bind_aliases(
    addrs: impl IntoIterator<Item = SocketAddr>,
) -> io::Result<HashMap<SocketAddr, SocketAddr>> {
    let mut by_port: HashMap<u16, Vec<SocketAddr>> = HashMap::new();
    for addr in addrs {
        let entries = by_port.entry(addr.port()).or_default();
        if !entries.contains(&addr) {
            entries.push(addr);
        }
    }

    let mut aliases = HashMap::new();
    for (port, addrs) in by_port {
        let canonical = if addrs.len() == 1 {
            addrs[0]
        } else if addrs.iter().all(|addr| {
            addr.is_ipv4() && addr.ip().is_unspecified()
                || (addr.is_ipv6() && addr.ip().is_unspecified())
        }) && addrs
            .iter()
            .any(|addr| addr.is_ipv6() && addr.ip().is_unspecified())
        {
            SocketAddr::from(([0u16; 8], port))
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("UDP-family listeners on port {port} cannot share one socket: {addrs:?}"),
            ));
        };
        for addr in addrs {
            aliases.insert(addr, canonical);
        }
    }
    Ok(aliases)
}

async fn run_mux_read_loop(
    mux: Arc<UdpMuxSocket>,
    socket: Arc<UdpSocket>,
    shutdown: CancellationToken,
) {
    let mut batch = RecvDatagramBatch::new(UDP_RECV_BATCH_MAX_DATAGRAMS, MAX_DATAGRAM);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            result = recv_udp_batch(&socket, &mut batch) => {
                match result {
                    Ok(_) => {}
                    Err(e) => {
                        warn!(addr=%mux.addr, error=%e, "S2S UDP mux socket read failed");
                        return;
                    }
                };
                for datagram in batch.iter() {
                    if shutdown.is_cancelled() {
                        return;
                    }
                    handle_mux_datagram(&mux, datagram.payload(), datagram.peer_addr());
                }
            }
        }
    }
}

fn handle_mux_datagram(mux: &UdpMuxSocket, packet: &[u8], peer_addr: SocketAddr) {
    let Some((&discriminator, payload)) = packet.split_first() else {
        debug!(addr=%mux.addr, %peer_addr, "dropped empty S2S UDP mux datagram");
        return;
    };
    let protocol = match MuxProtocol::decode(discriminator) {
        Ok(protocol) => protocol,
        Err(e) => {
            debug!(addr=%mux.addr, %peer_addr, error=%e, "dropped invalid S2S UDP mux datagram");
            return;
        }
    };
    let Some(slot) = mux.slots.get(&protocol.to_transport()) else {
        debug!(addr=%mux.addr, %peer_addr, protocol=?protocol, "dropped S2S UDP mux datagram for unconfigured protocol");
        return;
    };
    let datagram = MuxDatagram {
        payload: payload.to_vec(),
        peer_addr,
    };
    match slot.try_send(datagram) {
        Ok(Some((old_capacity, new_capacity))) => {
            debug!(
                addr=%mux.addr,
                %peer_addr,
                protocol=?protocol,
                old_capacity,
                new_capacity,
                burst_capacity=slot.tuning.burst_capacity(),
                hard_capacity=slot.tuning.hard_capacity(),
                queued_len=slot.queued_len(),
                "grew S2S UDP mux protocol queue capacity"
            );
        }
        Ok(None) => {}
        Err(e) => {
            debug!(
                addr=%mux.addr,
                %peer_addr,
                protocol=?protocol,
                queue_capacity=slot.capacity(),
                baseline_capacity=slot.tuning.baseline_capacity(),
                burst_capacity=slot.tuning.burst_capacity(),
                hard_capacity=slot.tuning.hard_capacity(),
                queued_len=slot.queued_len(),
                error=%e,
                "dropped S2S UDP mux datagram because protocol queue is full"
            );
        }
    }
}

#[derive(Clone)]
pub(crate) struct UdpMuxHandle {
    socket: Arc<UdpSocket>,
    protocol: MuxProtocol,
    rx: Arc<parking_lot::Mutex<mpsc::Receiver<MuxDatagram>>>,
}

impl UdpMuxHandle {
    fn new(socket: Arc<UdpSocket>, protocol: MuxProtocol, rx: mpsc::Receiver<MuxDatagram>) -> Self {
        Self {
            socket,
            protocol,
            rx: Arc::new(parking_lot::Mutex::new(rx)),
        }
    }

    pub(crate) async fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        send_prefixed(&self.socket, self.protocol, payload, target).await
    }

    pub(crate) async fn send_batch_to(
        &self,
        payloads: &[&[u8]],
        target: SocketAddr,
    ) -> io::Result<usize> {
        send_prefixed_batch(&self.socket, self.protocol, payloads, target).await
    }

    pub(crate) fn try_send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        try_send_prefixed(&self.socket, self.protocol, payload, target)
    }

    pub(crate) async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        std::future::poll_fn(|cx| self.poll_recv_from(cx, buf)).await
    }

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut rx = self.rx.lock();
        match Pin::new(&mut *rx).poll_recv(cx) {
            Poll::Ready(Some(datagram)) => {
                if datagram.payload.len() > buf.len() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "S2S UDP mux datagram exceeds receive buffer",
                    )));
                }
                buf[..datagram.payload.len()].copy_from_slice(&datagram.payload);
                Poll::Ready(Ok((datagram.payload.len(), datagram.peer_addr)))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "S2S UDP mux protocol receiver closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

impl fmt::Debug for UdpMuxHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpMuxHandle")
            .field("local_addr", &self.socket.local_addr().ok())
            .field("protocol", &self.protocol)
            .finish_non_exhaustive()
    }
}

impl quinn::AsyncUdpSocket for UdpMuxHandle {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(SocketWritablePoller::new(self.socket.clone()))
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        self.try_send_to(transmit.contents, transmit.destination)?;
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        poll_quic_recv_from(cx, bufs, meta, |cx, buf| self.poll_recv_from(cx, buf))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.local_addr()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PrefixedUdpSocket {
    socket: Arc<UdpSocket>,
    protocol: MuxProtocol,
}

impl PrefixedUdpSocket {
    pub(crate) async fn bind_ephemeral(
        remote_addr: SocketAddr,
        kind: TransportKind,
    ) -> io::Result<Self> {
        let protocol = MuxProtocol::from_transport(kind).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "transport is not UDP-family")
        })?;
        Ok(Self {
            socket: Arc::new(bind_ephemeral_udp_dial_socket(remote_addr).await?),
            protocol,
        })
    }

    pub(crate) async fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        send_prefixed(&self.socket, self.protocol, payload, target).await
    }

    pub(crate) async fn send_batch_to(
        &self,
        payloads: &[&[u8]],
        target: SocketAddr,
    ) -> io::Result<usize> {
        send_prefixed_batch(&self.socket, self.protocol, payloads, target).await
    }

    pub(crate) fn try_send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        try_send_prefixed(&self.socket, self.protocol, payload, target)
    }

    pub(crate) async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut recv = vec![0u8; buf.len().saturating_add(DISCRIMINATOR_LEN)];
        loop {
            let (n, peer_addr) = self.socket.recv_from(&mut recv).await?;
            let Some(payload) = decode_prefixed(self.protocol, &recv[..n])? else {
                continue;
            };
            if payload.len() > buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "S2S UDP mux datagram exceeds receive buffer",
                ));
            }
            buf[..payload.len()].copy_from_slice(payload);
            return Ok((payload.len(), peer_addr));
        }
    }

    pub(crate) async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_from(buf).await.map(|(n, _)| n)
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

impl quinn::AsyncUdpSocket for PrefixedUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(SocketWritablePoller::new(self.socket.clone()))
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        self.try_send_to(transmit.contents, transmit.destination)?;
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut recv = vec![0u8; bufs.first().map_or(0, |buf| buf.len() + DISCRIMINATOR_LEN)];
        loop {
            ready!(self.socket.poll_recv_ready(cx))?;
            match self
                .socket
                .try_io(Interest::READABLE, || self.socket.try_recv_from(&mut recv))
            {
                Ok((n, peer_addr)) => {
                    let Some(payload) = decode_prefixed(self.protocol, &recv[..n])? else {
                        continue;
                    };
                    return fill_quic_recv(bufs, meta, payload, peer_addr);
                }
                Err(_) => continue,
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.local_addr()
    }
}

struct SocketWritablePoller {
    socket: Arc<UdpSocket>,
}

impl SocketWritablePoller {
    fn new(socket: Arc<UdpSocket>) -> Self {
        Self { socket }
    }
}

impl quinn::UdpPoller for SocketWritablePoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.poll_send_ready(cx)
    }
}

impl fmt::Debug for SocketWritablePoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocketWritablePoller")
            .field("local_addr", &self.socket.local_addr().ok())
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl tokio_kcp::KcpUdpIo for UdpMuxHandle {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_from(buf).await.map(|(n, _)| n)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from(buf).await
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.send_to(buf, target).await
    }

    fn try_send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.try_send_to(buf, target)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.local_addr()
    }
}

#[async_trait::async_trait]
impl tokio_kcp::KcpUdpIo for PrefixedUdpSocket {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv(buf).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from(buf).await
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.send_to(buf, target).await
    }

    fn try_send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.try_send_to(buf, target)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.local_addr()
    }
}

async fn send_prefixed(
    socket: &UdpSocket,
    protocol: MuxProtocol,
    payload: &[u8],
    target: SocketAddr,
) -> io::Result<usize> {
    let datagram = prefixed_datagram(protocol, payload);
    socket.send_to(&datagram, target).await?;
    Ok(payload.len())
}

async fn send_prefixed_batch(
    socket: &UdpSocket,
    protocol: MuxProtocol,
    payloads: &[&[u8]],
    target: SocketAddr,
) -> io::Result<usize> {
    if payloads.is_empty() {
        return Ok(0);
    }

    let datagrams = payloads
        .iter()
        .map(|payload| prefixed_datagram(protocol, payload))
        .collect::<Vec<_>>();
    let batch = datagrams
        .iter()
        .map(|datagram| UdpBatchDatagram::new(datagram.as_slice(), target))
        .collect::<Vec<_>>();
    let stats = send_udp_batch(socket, &batch).await?;
    if stats.would_block_count() > 0 || stats.partial_count() > 0 {
        debug!(
            protocol=?protocol,
            would_block=stats.would_block_count(),
            partial=stats.partial_count(),
            "S2S UDP mux batch send observed socket backpressure"
        );
    }

    Ok(payloads.iter().map(|payload| payload.len()).sum())
}

fn try_send_prefixed(
    socket: &UdpSocket,
    protocol: MuxProtocol,
    payload: &[u8],
    target: SocketAddr,
) -> io::Result<usize> {
    let datagram = prefixed_datagram(protocol, payload);
    socket.try_send_to(&datagram, target)?;
    Ok(payload.len())
}

fn prefixed_datagram(protocol: MuxProtocol, payload: &[u8]) -> Vec<u8> {
    let mut datagram = Vec::with_capacity(payload.len() + DISCRIMINATOR_LEN);
    datagram.push(protocol.discriminator());
    datagram.extend_from_slice(payload);
    datagram
}

fn decode_prefixed(expected: MuxProtocol, datagram: &[u8]) -> io::Result<Option<&[u8]>> {
    let Some((&discriminator, payload)) = datagram.split_first() else {
        return Ok(None);
    };
    let protocol = match MuxProtocol::decode(discriminator) {
        Ok(protocol) => protocol,
        Err(_) => return Ok(None),
    };
    Ok((protocol == expected).then_some(payload))
}

fn poll_quic_recv_from<F>(
    cx: &mut Context<'_>,
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [quinn::udp::RecvMeta],
    mut recv: F,
) -> Poll<io::Result<usize>>
where
    F: FnMut(&mut Context<'_>, &mut [u8]) -> Poll<io::Result<(usize, SocketAddr)>>,
{
    let Some(first) = bufs.first_mut() else {
        return Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "QUIC receive requires a buffer",
        )));
    };
    let Some(first_meta) = meta.first_mut() else {
        return Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "QUIC receive requires metadata storage",
        )));
    };

    let mut scratch = vec![0u8; first.len()];
    let (n, peer_addr) = ready!(recv(cx, &mut scratch))?;
    first[..n].copy_from_slice(&scratch[..n]);
    *first_meta = quinn::udp::RecvMeta {
        addr: peer_addr,
        len: n,
        stride: n,
        ecn: None,
        dst_ip: None,
    };
    Poll::Ready(Ok(1))
}

fn fill_quic_recv(
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [quinn::udp::RecvMeta],
    payload: &[u8],
    peer_addr: SocketAddr,
) -> Poll<io::Result<usize>> {
    let Some(first) = bufs.first_mut() else {
        return Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "QUIC receive requires a buffer",
        )));
    };
    let Some(first_meta) = meta.first_mut() else {
        return Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "QUIC receive requires metadata storage",
        )));
    };
    if payload.len() > first.len() {
        return Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "S2S UDP mux datagram exceeds QUIC receive buffer",
        )));
    }
    first[..payload.len()].copy_from_slice(payload);
    *first_meta = quinn::udp::RecvMeta {
        addr: peer_addr,
        len: payload.len(),
        stride: payload.len(),
        ecn: None,
        dst_ip: None,
    };
    Poll::Ready(Ok(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminator_roundtrips() {
        assert_eq!(MuxProtocol::decode(0x80).unwrap(), MuxProtocol::Udp);
        assert_eq!(MuxProtocol::decode(0x81).unwrap(), MuxProtocol::Kcp);
        assert_eq!(MuxProtocol::decode(0x82).unwrap(), MuxProtocol::Quic);
    }

    #[test]
    fn discriminator_rejects_missing_marker_and_unknown_id() {
        assert!(MuxProtocol::decode(0x00).is_err());
        assert!(MuxProtocol::decode(0x83).is_err());
        assert!(MuxProtocol::decode(0xc0).is_err());
    }

    #[test]
    fn mux_set_creates_one_socket_for_a_single_protocol() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 64738));
        let mux = UdpMuxSet::new(
            &[(TransportKind::Udp, addr)],
            UdpMuxQueueTuning::for_max_users(1),
        )
        .unwrap();

        assert_eq!(mux.socket_count(), 1);
    }

    #[test]
    fn mux_set_canonicalizes_dual_stack_wildcards() {
        let v4 = SocketAddr::from(([0, 0, 0, 0], 64738));
        let v6 = SocketAddr::from(([0u16; 8], 64738));
        let mux = UdpMuxSet::new(
            &[
                (TransportKind::Kcp, v4),
                (TransportKind::Quic, v6),
                (TransportKind::Udp, v4),
            ],
            UdpMuxQueueTuning::for_max_users(1),
        )
        .unwrap();

        assert_eq!(mux.socket_count(), 1);
        assert_eq!(mux.binding_for(v4).unwrap().0, v6);
        assert_eq!(mux.binding_for(v6).unwrap().0, v6);
        assert!(!mux.binding_for(v6).unwrap().1);
    }

    #[test]
    fn mux_set_rejects_conflicting_same_port_bindings() {
        let v4 = SocketAddr::from(([127, 0, 0, 1], 64738));
        let v6 = SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 64738));
        let error = UdpMuxSet::new(
            &[(TransportKind::Udp, v4), (TransportKind::Kcp, v6)],
            UdpMuxQueueTuning::for_max_users(1),
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn protocol_handles_share_one_underlying_socket() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let mux = UdpMuxSet::new(
            &[
                (TransportKind::Udp, addr),
                (TransportKind::Kcp, addr),
                (TransportKind::Quic, addr),
            ],
            UdpMuxQueueTuning::for_max_users(1),
        )
        .unwrap();
        let shutdown = CancellationToken::new();
        let udp = mux
            .take_handle(addr, TransportKind::Udp, shutdown.child_token())
            .await
            .unwrap();
        let kcp = mux
            .take_handle(addr, TransportKind::Kcp, shutdown.child_token())
            .await
            .unwrap();
        let quic = mux
            .take_handle(addr, TransportKind::Quic, shutdown.child_token())
            .await
            .unwrap();

        assert!(Arc::ptr_eq(&udp.socket, &kcp.socket));
        assert!(Arc::ptr_eq(&kcp.socket, &quic.socket));
        shutdown.cancel();
    }

    #[tokio::test]
    async fn single_protocol_handle_receives_prefixed_datagrams() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let mux = UdpMuxSet::new(
            &[(TransportKind::Udp, addr)],
            UdpMuxQueueTuning::for_max_users(1),
        )
        .unwrap();
        let shutdown = CancellationToken::new();
        let handle = mux
            .take_handle(addr, TransportKind::Udp, shutdown.child_token())
            .await
            .unwrap();
        let sender = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let target = handle.local_addr().unwrap();
        sender
            .send_to(&prefixed_datagram(MuxProtocol::Udp, b"single"), target)
            .await
            .unwrap();

        let mut buf = [0u8; 32];
        let (len, peer_addr) = handle.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"single");
        assert_eq!(peer_addr, sender.local_addr().unwrap());
        shutdown.cancel();
    }

    #[tokio::test]
    async fn configured_udp_bind_is_exclusive() {
        let first = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let error = bind_udp_socket_with_ipv6_only(first.local_addr().unwrap(), false)
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    }

    #[test]
    fn prefixed_empty_payload_decodes() {
        let datagram = prefixed_datagram(MuxProtocol::Udp, &[]);
        assert_eq!(
            decode_prefixed(MuxProtocol::Udp, &datagram).unwrap(),
            Some(&[][..])
        );
    }

    #[tokio::test]
    async fn prefixed_batch_sends_ordered_payloads() {
        let sender = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let receiver = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let target = receiver.local_addr().unwrap();
        let payloads = [b"first".as_slice(), b"second".as_slice()];

        let sent = send_prefixed_batch(&sender, MuxProtocol::Udp, &payloads, target)
            .await
            .unwrap();

        assert_eq!(
            sent,
            payloads.iter().map(|payload| payload.len()).sum::<usize>()
        );
        let mut received = Vec::new();
        for _ in 0..payloads.len() {
            let mut buf = [0u8; 64];
            let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
            received.push(
                decode_prefixed(MuxProtocol::Udp, &buf[..n])
                    .unwrap()
                    .unwrap()
                    .to_vec(),
            );
        }
        assert_eq!(received, vec![b"first".to_vec(), b"second".to_vec()]);
    }

    #[tokio::test]
    async fn mux_datagram_handler_delivers_ordered_payloads_to_protocol_slot() {
        let tuning = UdpMuxQueueTuning::for_max_users(1);
        let mux = UdpMuxSocket::new(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            false,
            vec![TransportKind::Udp],
            tuning,
        );
        let slot = mux.slots.get(&TransportKind::Udp).unwrap();
        let mut rx = slot.take_rx().unwrap();
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 64738));

        handle_mux_datagram(
            &mux,
            &prefixed_datagram(MuxProtocol::Udp, b"first"),
            peer_addr,
        );
        handle_mux_datagram(
            &mux,
            &prefixed_datagram(MuxProtocol::Udp, b"second"),
            peer_addr,
        );

        let first = rx.recv().await.unwrap();
        let second = rx.recv().await.unwrap();
        assert_eq!(first.payload, b"first");
        assert_eq!(first.peer_addr, peer_addr);
        assert_eq!(second.payload, b"second");
        assert_eq!(second.peer_addr, peer_addr);
    }

    #[tokio::test]
    async fn mux_datagram_handler_demultiplexes_all_protocols() {
        let tuning = UdpMuxQueueTuning::for_max_users(1);
        let mux = UdpMuxSocket::new(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            false,
            vec![TransportKind::Udp, TransportKind::Kcp, TransportKind::Quic],
            tuning,
        );
        let mut udp = mux
            .slots
            .get(&TransportKind::Udp)
            .unwrap()
            .take_rx()
            .unwrap();
        let mut kcp = mux
            .slots
            .get(&TransportKind::Kcp)
            .unwrap()
            .take_rx()
            .unwrap();
        let mut quic = mux
            .slots
            .get(&TransportKind::Quic)
            .unwrap()
            .take_rx()
            .unwrap();
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 64738));

        handle_mux_datagram(
            &mux,
            &prefixed_datagram(MuxProtocol::Udp, b"udp"),
            peer_addr,
        );
        handle_mux_datagram(
            &mux,
            &prefixed_datagram(MuxProtocol::Kcp, b"kcp"),
            peer_addr,
        );
        handle_mux_datagram(
            &mux,
            &prefixed_datagram(MuxProtocol::Quic, b"quic"),
            peer_addr,
        );

        assert_eq!(udp.recv().await.unwrap().payload, b"udp");
        assert_eq!(kcp.recv().await.unwrap().payload, b"kcp");
        assert_eq!(quic.recv().await.unwrap().payload, b"quic");
    }

    #[test]
    fn mux_datagram_handler_drops_invalid_and_unconfigured_protocols() {
        let tuning = UdpMuxQueueTuning::for_max_users(1);
        let mux = UdpMuxSocket::new(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            false,
            vec![TransportKind::Udp],
            tuning,
        );
        let mut udp = mux
            .slots
            .get(&TransportKind::Udp)
            .unwrap()
            .take_rx()
            .unwrap();
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 64738));

        handle_mux_datagram(&mux, &[], peer_addr);
        handle_mux_datagram(&mux, &[0x00, b'x'], peer_addr);
        handle_mux_datagram(
            &mux,
            &prefixed_datagram(MuxProtocol::Kcp, b"unconfigured"),
            peer_addr,
        );

        assert!(udp.try_recv().is_err());
    }

    #[test]
    fn protocol_slot_grows_when_initial_capacity_is_exhausted() {
        let tuning = UdpMuxQueueTuning::for_max_users(16);
        let slot = ProtocolSlot::new(tuning);
        for _ in 0..tuning.baseline_capacity() {
            assert_eq!(
                slot.try_send(MuxDatagram {
                    payload: Vec::new(),
                    peer_addr: "127.0.0.1:1".parse().unwrap(),
                })
                .unwrap(),
                None
            );
        }

        assert_eq!(slot.capacity(), tuning.baseline_capacity());
        assert_eq!(
            slot.try_send(MuxDatagram {
                payload: Vec::new(),
                peer_addr: "127.0.0.1:1".parse().unwrap(),
            })
            .unwrap(),
            Some((tuning.baseline_capacity(), tuning.burst_capacity()))
        );
        assert_eq!(slot.capacity(), tuning.burst_capacity());
    }

    #[test]
    fn udp_mux_queue_tuning_uses_five_x_burst_and_server_size_cap() {
        let tuning = UdpMuxQueueTuning::for_max_users(400);

        assert_eq!(tuning.baseline_capacity(), 6_400);
        assert_eq!(tuning.burst_capacity(), 32_000);
        assert_eq!(tuning.hard_capacity(), 51_200);
    }
}
