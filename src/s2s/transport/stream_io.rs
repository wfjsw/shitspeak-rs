//! Generic framed read/write pump shared by every stream transport.
//!
//! A "stream" here is anything that satisfies `AsyncRead + AsyncWrite + Send +
//! Unpin` — TCP+TLS, KCP+TLS, or a QUIC bidirectional stream. The pump:
//!
//!   * frames every outbound `Bytes` payload as a `pb::Frame` with the
//!     local `NodeIdentifier` as `src_node`, then encodes with prost +
//!     length-prefix via `LengthDelimitedCodec`;
//!   * decodes incoming length-prefixed frames, dispatches `Data` to the
//!     appropriate inbound mpsc, generates `Pong` for `Ping` (echoing the
//!     ping's payload back so bandwidth probes round-trip enough bytes),
//!     and updates RTT + jitter + probe-goodput metrics for `Pong`;
//!   * periodically issues two kinds of self-driven Pings:
//!       - a small Ping every `ping_interval` for latency / jitter;
//!       - service-shaped probe Pings derived from `bandwidth_probe_size` every
//!         `bandwidth_probe_interval` for throughput estimation;
//!   * exits on EOF, write error, or `closed` cancellation.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use prost::Message as _;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::time::{Instant as TokioInstant, Interval, interval_at};
use tokio_util::codec::Framed;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use crate::s2s_transport_proto as pb;
use crate::types::NodeIdentifier;

use super::compression::{
    CompressionConfig, maybe_compress_frame_payload, validate_and_decode_payload,
};
use super::connection::{ActiveStream, OutboundFrame, PeerState};
use super::frame::{FrameType, build_frame, stream_codec};
use super::manager::InboundDispatch;
use super::native_stats::BoxedNativeLossSampler;
use super::probe_schedule::{
    StartupBandwidthProbe, bandwidth_probe_startup_jitter, stabilized_ping_interval,
};
use super::service_level::{MessageClass, ServiceLevel, ServiceShape, TransportKind};

/// Tunables for a single stream pump. Cloned per stream.
#[derive(Clone)]
pub(crate) struct StreamPumpConfig {
    local_node: NodeIdentifier,
    peer_node: NodeIdentifier,
    transport: TransportKind,
    max_frame_bytes: usize,
    outbound_capacity: usize,
    ping_interval: Duration,
    idle_ping_interval: Duration,
    bandwidth_probe_interval: Duration,
    bandwidth_probe_size: usize,
    native_stats_interval: Duration,
    compression: CompressionConfig,
    /// Cap on how many in-flight pings we remember. Older entries are
    /// dropped when the buffer fills, preventing unbounded memory if pongs
    /// are lost.
    max_pending_pings: usize,
}

impl StreamPumpConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        local_node: NodeIdentifier,
        peer_node: NodeIdentifier,
        transport: TransportKind,
        max_frame_bytes: usize,
        outbound_capacity: usize,
        ping_interval: Duration,
        idle_ping_interval: Duration,
        bandwidth_probe_interval: Duration,
        bandwidth_probe_size: usize,
        native_stats_interval: Duration,
        compression: CompressionConfig,
        max_pending_pings: usize,
    ) -> Self {
        Self {
            local_node,
            peer_node,
            transport,
            max_frame_bytes,
            outbound_capacity,
            ping_interval,
            idle_ping_interval,
            bandwidth_probe_interval,
            bandwidth_probe_size,
            native_stats_interval,
            compression,
            max_pending_pings,
        }
    }
}

/// Spawn a framed read/write pump over `stream`. Returns the `ActiveStream`
/// handle (with its outbound mpsc and `closed` token) used by `PeerState`.
pub(crate) fn spawn_stream_pump<S>(
    stream: S,
    cfg: StreamPumpConfig,
    peer: Arc<PeerState>,
    inbound: InboundDispatch,
    remote_addr: Option<SocketAddr>,
    is_dialer: bool,
    closed: CancellationToken,
    native_sampler: Option<BoxedNativeLossSampler>,
) -> ActiveStream
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (tx, rx) = mpsc::channel::<OutboundFrame>(cfg.outbound_capacity);

    let active = ActiveStream::new(cfg.transport, remote_addr, tx, closed.clone(), is_dialer);

    tokio::spawn(run_pump(
        stream,
        cfg,
        peer,
        inbound,
        rx,
        closed,
        native_sampler,
    ));

    active
}

/// In-flight ping bookkeeping.
struct PendingPings {
    inner: VecDeque<(u64, PendingPing)>,
    cap: usize,
}

#[derive(Debug, Clone, Copy)]
struct PendingPing {
    sent_at: Instant,
    shape: Option<ServiceShape>,
    payload_bytes: usize,
}

impl PendingPings {
    fn new(cap: usize) -> Self {
        Self {
            inner: VecDeque::with_capacity(cap),
            cap,
        }
    }
    fn insert(
        &mut self,
        ts_us: u64,
        shape: Option<ServiceShape>,
        payload_bytes: usize,
    ) -> Option<PendingPing> {
        if self.cap == 0 {
            return None;
        }
        let evicted = if self.inner.len() >= self.cap {
            self.inner.pop_front().map(|(_, pending)| pending)
        } else {
            None
        };
        self.inner.push_back((
            ts_us,
            PendingPing {
                sent_at: Instant::now(),
                shape,
                payload_bytes,
            },
        ));
        evicted
    }
    fn take(&mut self, ts_us: u64) -> Option<PendingPing> {
        let pos = self.inner.iter().position(|(t, _)| *t == ts_us)?;
        self.inner.remove(pos).map(|(_, pending)| pending)
    }

    fn expire_older_than(&mut self, timeout: Duration) -> usize {
        let now = Instant::now();
        let mut expired_liveness = 0;
        while self
            .inner
            .front()
            .is_some_and(|(_, pending)| now.saturating_duration_since(pending.sent_at) >= timeout)
        {
            if self
                .inner
                .pop_front()
                .is_some_and(|(_, pending)| pending.shape.is_none())
            {
                expired_liveness += 1;
            }
        }
        expired_liveness
    }
}

/// Either a real `tokio::time::Interval` or a no-op for disabled features.
enum MaybeInterval {
    Active(Interval),
    Disabled,
}

impl MaybeInterval {
    fn maybe(period: Duration) -> Self {
        if period.is_zero() {
            Self::Disabled
        } else {
            Self::Active(interval_at(TokioInstant::now() + period, period))
        }
    }

    fn maybe_with_initial_delay(period: Duration, initial_delay: Duration) -> Self {
        if period.is_zero() {
            Self::Disabled
        } else {
            Self::Active(interval_at(
                TokioInstant::now() + period.saturating_add(initial_delay),
                period,
            ))
        }
    }

    /// Future-like helper. Returns ready when the timer ticks, or never if
    /// disabled.
    async fn tick(&mut self) {
        match self {
            Self::Active(iv) => {
                iv.tick().await;
            }
            Self::Disabled => std::future::pending::<()>().await,
        }
    }
}

fn is_tls_close_notify_eof(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::UnexpectedEof
        && error
            .to_string()
            .contains("without sending TLS close_notify")
}

fn is_peer_closed_initial_write(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::UnexpectedEof
    )
}

async fn run_pump<S>(
    stream: S,
    cfg: StreamPumpConfig,
    peer: Arc<PeerState>,
    inbound: InboundDispatch,
    mut rx: mpsc::Receiver<OutboundFrame>,
    closed: CancellationToken,
    mut native_sampler: Option<BoxedNativeLossSampler>,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let codec = stream_codec(cfg.max_frame_bytes);
    let mut framed = Framed::new(stream, codec);
    let mut ping_tick = MaybeInterval::maybe(cfg.ping_interval);
    let stable_ping_interval = stabilized_ping_interval(cfg.ping_interval, cfg.idle_ping_interval);
    let mut stable_ping_interval_armed = false;
    let probe_enabled = cfg.bandwidth_probe_size > 0;
    let startup_probe_delay = bandwidth_probe_startup_jitter(
        cfg.local_node,
        cfg.peer_node,
        cfg.transport,
        cfg.ping_interval,
    );
    let mut startup_probe = StartupBandwidthProbe::new(
        probe_enabled && !cfg.bandwidth_probe_interval.is_zero(),
        startup_probe_delay,
    );
    let periodic_probe_delay = startup_probe_delay.min(cfg.bandwidth_probe_interval);
    let mut probe_tick = if probe_enabled {
        MaybeInterval::maybe_with_initial_delay(cfg.bandwidth_probe_interval, periodic_probe_delay)
    } else {
        MaybeInterval::Disabled
    };
    let mut native_tick = if native_sampler.is_some() {
        MaybeInterval::maybe(cfg.native_stats_interval)
    } else {
        MaybeInterval::Disabled
    };
    let mut pending = PendingPings::new(cfg.max_pending_pings);
    let pending_timeout = cfg
        .ping_interval
        .max(stable_ping_interval)
        .saturating_mul(2)
        .max(Duration::from_secs(1));
    let level_for_metrics = cfg.transport.service_level();

    let hello = build_frame(
        cfg.local_node,
        cfg.peer_node,
        level_for_metrics,
        FrameType::Hello,
        MessageClass::Regular,
        now_us(),
        Bytes::new(),
    );
    let hello_result = tokio::select! {
        biased;

        _ = closed.cancelled() => return,
        result = encode_and_send(&mut framed, &hello, cfg.transport, &peer) => result,
    };
    if let Err(e) = hello_result {
        if is_peer_closed_initial_write(&e) {
            debug!(peer=%peer.node_id(), transport=?cfg.transport, error=%e, "hello write closed by peer");
        } else {
            warn!(peer=%peer.node_id(), transport=?cfg.transport, error=%e, "hello write failed");
        }
        closed.cancel();
        return;
    }

    loop {
        tokio::select! {
            biased;

            _ = closed.cancelled() => {
                debug!(peer=%peer.node_id(), transport=?cfg.transport, "stream closed by supervisor");
                break;
            }

            maybe_in = framed.next() => {
                let buf = match maybe_in {
                    Some(Ok(b)) => b,
                    Some(Err(e)) => {
                        peer.metrics().record_data_health_failure(cfg.transport);
                        if is_tls_close_notify_eof(&e) {
                            debug!(peer=%peer.node_id(), transport=?cfg.transport, error=%e, "stream closed without TLS close_notify");
                        } else {
                            warn!(peer=%peer.node_id(), transport=?cfg.transport, error=%e, "stream read error");
                        }
                        break;
                    }
                    None => { debug!(peer=%peer.node_id(), transport=?cfg.transport, "stream EOF"); break; }
                };
                peer.metrics().record_data_health_success(cfg.transport);
                let recv_size = buf.len();
                peer.metrics().record_recv(cfg.transport, recv_size);
                match pb::Frame::decode(buf.as_ref()) {
                    Ok(frame) => {
                        #[cfg(debug_assertions)]
                        crate::s2s::debug_io::record_named_received(
                            stream_frame_kind_name(cfg.transport, frame.frame_type),
                            recv_size,
                        );
                        match handle_inbound(
                            frame,
                            recv_size,
                            &cfg,
                            &peer,
                            &inbound,
                            &mut framed,
                            &mut pending,
                            level_for_metrics,
                        ).await {
                            Ok(transport_link_stable) => {
                                if transport_link_stable {
                                    startup_probe.arm();
                                    if !stable_ping_interval_armed
                                        && stable_ping_interval != cfg.ping_interval
                                    {
                                        ping_tick = MaybeInterval::maybe(stable_ping_interval);
                                        stable_ping_interval_armed = true;
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(peer=%peer.node_id(), transport=?cfg.transport, error=%e, "inbound handling failed");
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        peer.metrics().record_data_health_failure(cfg.transport);
                        warn!(peer=%peer.node_id(), transport=?cfg.transport, error=%e, "frame decode error; dropping connection");
                        break;
                    }
                }
            }

            maybe_out = rx.recv() => {
                let Some(out) = maybe_out else { break };
                let original_payload_len = out.payload().len();
                let mut frame = build_frame(
                    cfg.local_node,
                    cfg.peer_node,
                    level_for_metrics,
                    FrameType::Data,
                    out.class(),
                    now_us(),
                    out.payload().clone(),
                );
                if let Err(e) = maybe_compress_frame_payload(
                    &mut frame,
                    out.options(),
                    cfg.compression,
                    cfg.max_frame_bytes,
                ) {
                    warn!(peer=%peer.node_id(), transport=?cfg.transport, error=%e, "stream payload compression failed");
                    break;
                }
                match encode_and_send(&mut framed, &frame, cfg.transport, &peer).await {
                    Ok(()) => peer
                        .metrics()
                        .record_payload_sent(cfg.transport, original_payload_len),
                    Err(e) => {
                        warn!(peer=%peer.node_id(), transport=?cfg.transport, error=%e, "stream write failed");
                        break;
                    }
                }
            }

            _ = ping_tick.tick() => {
                record_expired_pending(&mut pending, pending_timeout, cfg.transport, &peer);
                let ts = now_us();
                let frame = build_frame(
                    cfg.local_node,
                    cfg.peer_node,
                    level_for_metrics,
                    FrameType::KeepAlive,
                    MessageClass::Regular,
                    ts,
                    Bytes::new(),
                );
                match encode_and_send_returning_size(&mut framed, &frame, cfg.transport, &peer).await {
                    Ok(_) => {
                        record_evicted_pending(
                            pending.insert(ts, None, 0),
                            cfg.transport,
                            &peer,
                        );
                    }
                    Err(e) => {
                        warn!(peer=%peer.node_id(), transport=?cfg.transport, error=%e, "keepalive write failed");
                        break;
                    }
                }
            }

            _ = startup_probe.tick() => {
                startup_probe.complete();
                if send_bandwidth_probes(
                    &mut framed,
                    &cfg,
                    &peer,
                    &mut pending,
                    pending_timeout,
                ).await.is_err() {
                    break;
                }
            }

            _ = probe_tick.tick() => {
                if send_bandwidth_probes(
                    &mut framed,
                    &cfg,
                    &peer,
                    &mut pending,
                    pending_timeout,
                ).await.is_err() {
                    break;
                }
            }

            _ = native_tick.tick() => {
                if let Some(sampler) = native_sampler.as_mut() {
                    if let Some(sample) = sampler.sample() {
                        peer.metrics().record_native_loss_sample(
                            cfg.transport,
                            sample.sent_units(),
                            sample.lost_units(),
                        );
                    }
                }
            }
        }
    }

    closed.cancel();
    trace!(peer=%peer.node_id(), transport=?cfg.transport, "stream pump exiting");
}

async fn send_bandwidth_probes<S>(
    framed: &mut Framed<S, tokio_util::codec::LengthDelimitedCodec>,
    cfg: &StreamPumpConfig,
    peer: &PeerState,
    pending: &mut PendingPings,
    pending_timeout: Duration,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    record_expired_pending(pending, pending_timeout, cfg.transport, peer);
    let mut ts = now_us();
    for shape in ServiceShape::ALL {
        let payload_bytes = shape.probe_payload_bytes(cfg.bandwidth_probe_size);
        if payload_bytes == 0 {
            continue;
        }
        let payload = BytesMut::zeroed(payload_bytes).freeze();
        let frame = build_frame(
            cfg.local_node,
            cfg.peer_node,
            shape.service_level(),
            FrameType::Ping,
            shape.message_class(),
            ts,
            payload,
        );
        if frame.encoded_len() > cfg.max_frame_bytes {
            continue;
        }
        match encode_and_send_returning_size(framed, &frame, cfg.transport, peer).await {
            Ok(_) => {
                record_evicted_pending(
                    pending.insert(ts, Some(shape), payload_bytes),
                    cfg.transport,
                    peer,
                );
            }
            Err(e) => {
                warn!(peer=%peer.node_id(), transport=?cfg.transport, service=%shape.name(), error=%e, "probe write failed");
                return Err(e);
            }
        }
        ts = ts.saturating_add(1);
    }
    Ok(())
}

fn record_expired_pending(
    pending: &mut PendingPings,
    timeout: Duration,
    transport: TransportKind,
    peer: &PeerState,
) {
    for _ in 0..pending.expire_older_than(timeout) {
        peer.metrics().record_probe_lost(transport);
    }
}

fn record_evicted_pending(
    evicted: Option<PendingPing>,
    transport: TransportKind,
    peer: &PeerState,
) {
    if evicted.is_some_and(|pending| pending.shape.is_none()) {
        peer.metrics().record_probe_lost(transport);
    }
}

async fn encode_and_send<S>(
    framed: &mut Framed<S, tokio_util::codec::LengthDelimitedCodec>,
    frame: &pb::Frame,
    transport: TransportKind,
    peer: &PeerState,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    let _ = encode_and_send_returning_size(framed, frame, transport, peer).await?;
    Ok(())
}

async fn encode_and_send_returning_size<S>(
    framed: &mut Framed<S, tokio_util::codec::LengthDelimitedCodec>,
    frame: &pb::Frame,
    transport: TransportKind,
    peer: &PeerState,
) -> std::io::Result<usize>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    let mut buf = BytesMut::with_capacity(frame.encoded_len());
    frame
        .encode(&mut buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let len = buf.len();
    if let Err(error) = framed.send(buf.freeze()).await {
        peer.metrics().record_data_health_failure(transport);
        return Err(error);
    }
    peer.metrics().record_sent(transport, len);
    #[cfg(debug_assertions)]
    crate::s2s::debug_io::record_named_sent(
        stream_frame_kind_name(transport, frame.frame_type),
        len,
    );
    peer.metrics().record_data_health_success(transport);
    Ok(len)
}

#[cfg(debug_assertions)]
fn stream_frame_kind_name(transport: TransportKind, frame_type: i32) -> &'static str {
    match transport {
        TransportKind::Tcp => match pb::FrameType::try_from(frame_type) {
            Ok(pb::FrameType::FrameData) => "transport.tcp.frame.data",
            Ok(pb::FrameType::FramePing) => "transport.tcp.frame.ping",
            Ok(pb::FrameType::FramePong) => "transport.tcp.frame.pong",
            Ok(pb::FrameType::FrameKeepalive) => "transport.tcp.frame.keepalive",
            Ok(pb::FrameType::FrameHello) => "transport.tcp.frame.hello",
            Ok(pb::FrameType::FrameBye) => "transport.tcp.frame.bye",
            Err(_) => "transport.tcp.frame.unknown",
        },
        TransportKind::Kcp => match pb::FrameType::try_from(frame_type) {
            Ok(pb::FrameType::FrameData) => "transport.kcp.frame.data",
            Ok(pb::FrameType::FramePing) => "transport.kcp.frame.ping",
            Ok(pb::FrameType::FramePong) => "transport.kcp.frame.pong",
            Ok(pb::FrameType::FrameKeepalive) => "transport.kcp.frame.keepalive",
            Ok(pb::FrameType::FrameHello) => "transport.kcp.frame.hello",
            Ok(pb::FrameType::FrameBye) => "transport.kcp.frame.bye",
            Err(_) => "transport.kcp.frame.unknown",
        },
        TransportKind::Quic => match pb::FrameType::try_from(frame_type) {
            Ok(pb::FrameType::FrameData) => "transport.quic.frame.data",
            Ok(pb::FrameType::FramePing) => "transport.quic.frame.ping",
            Ok(pb::FrameType::FramePong) => "transport.quic.frame.pong",
            Ok(pb::FrameType::FrameKeepalive) => "transport.quic.frame.keepalive",
            Ok(pb::FrameType::FrameHello) => "transport.quic.frame.hello",
            Ok(pb::FrameType::FrameBye) => "transport.quic.frame.bye",
            Err(_) => "transport.quic.frame.unknown",
        },
        TransportKind::Udp => match pb::FrameType::try_from(frame_type) {
            Ok(pb::FrameType::FrameData) => "transport.udp.stream_frame.data",
            Ok(pb::FrameType::FramePing) => "transport.udp.stream_frame.ping",
            Ok(pb::FrameType::FramePong) => "transport.udp.stream_frame.pong",
            Ok(pb::FrameType::FrameKeepalive) => "transport.udp.stream_frame.keepalive",
            Ok(pb::FrameType::FrameHello) => "transport.udp.stream_frame.hello",
            Ok(pb::FrameType::FrameBye) => "transport.udp.stream_frame.bye",
            Err(_) => "transport.udp.stream_frame.unknown",
        },
    }
}

async fn handle_inbound<S>(
    mut frame: pb::Frame,
    _incoming_wire_size: usize,
    cfg: &StreamPumpConfig,
    peer: &PeerState,
    inbound: &InboundDispatch,
    framed: &mut Framed<S, tokio_util::codec::LengthDelimitedCodec>,
    pending: &mut PendingPings,
    level: ServiceLevel,
) -> std::io::Result<bool>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    validate_and_decode_payload(&mut frame, cfg.max_frame_bytes)?;
    let mut transport_link_stable = false;
    let ty = match pb::FrameType::try_from(frame.frame_type) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    match ty {
        pb::FrameType::FrameData => {
            let class = pb::MessageClass::try_from(frame.message_class)
                .map(MessageClass::from)
                .unwrap_or(MessageClass::Regular);
            peer.metrics()
                .record_payload_recv(cfg.transport, frame.payload.len());
            inbound.dispatch(super::manager::InboundMessage::new(
                cfg.peer_node,
                level,
                cfg.transport,
                class,
                frame.payload,
            ));
        }
        pb::FrameType::FramePing | pb::FrameType::FrameKeepalive => {
            // Echo the payload back so the round trip carries enough bytes
            // for the sender to estimate throughput. Empty pings (latency
            // probes) round-trip a tiny pong; large probes round-trip a
            // payload-sized pong.
            let echo_payload = frame.payload.clone();
            let pong = build_frame(
                cfg.local_node,
                cfg.peer_node,
                level,
                FrameType::Pong,
                MessageClass::Regular,
                frame.ts_us,
                echo_payload,
            );
            encode_and_send(framed, &pong, cfg.transport, peer).await?;
        }
        pb::FrameType::FramePong => {
            let now = now_us();
            if now > frame.ts_us {
                let rtt = Duration::from_micros(now - frame.ts_us);
                peer.metrics().record_rtt(cfg.transport, rtt);
                if let Some(pending) = pending.take(frame.ts_us) {
                    if pending.shape.is_none() {
                        peer.metrics().record_probe_delivered(cfg.transport);
                        transport_link_stable = true;
                    }
                    if let Some(shape) = pending.shape {
                        peer.metrics().record_probe(
                            cfg.transport,
                            shape,
                            pending.payload_bytes,
                            rtt,
                        );
                    }
                }
            }
        }
        pb::FrameType::FrameHello => {
            trace!(peer=%cfg.peer_node, transport=?cfg.transport, "received transport hello");
        }
        pb::FrameType::FrameBye => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "peer sent BYE",
            ));
        }
    }
    Ok(transport_link_stable)
}

#[inline]
fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_close_notify_eof_is_not_a_read_warning() {
        let error = io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "peer closed connection without sending TLS close_notify: https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof",
        );

        assert!(is_tls_close_notify_eof(&error));
    }

    #[test]
    fn unrelated_unexpected_eof_still_warns() {
        let error = io::Error::new(io::ErrorKind::UnexpectedEof, "short frame");

        assert!(!is_tls_close_notify_eof(&error));
    }

    #[test]
    fn stream_frame_kind_names_include_transport_and_type() {
        assert_eq!(
            stream_frame_kind_name(TransportKind::Tcp, pb::FrameType::FrameData as i32),
            "transport.tcp.frame.data"
        );
        assert_eq!(
            stream_frame_kind_name(TransportKind::Quic, pb::FrameType::FrameKeepalive as i32),
            "transport.quic.frame.keepalive"
        );
    }

    #[test]
    fn expiring_service_probe_does_not_count_as_liveness_loss() {
        let mut pending = PendingPings::new(4);
        assert!(pending.insert(1, None, 0).is_none());
        assert!(
            pending
                .insert(2, Some(ServiceShape::Bulk), 64 * 1024)
                .is_none()
        );

        assert_eq!(pending.expire_older_than(Duration::ZERO), 1);
    }

    #[test]
    fn evicted_pending_probe_preserves_shape_for_loss_accounting() {
        let mut pending = PendingPings::new(1);
        assert!(
            pending
                .insert(1, Some(ServiceShape::Control), 1024)
                .is_none()
        );

        let evicted = pending.insert(2, None, 0).expect("old probe evicted");
        assert_eq!(evicted.shape, Some(ServiceShape::Control));
    }
}
