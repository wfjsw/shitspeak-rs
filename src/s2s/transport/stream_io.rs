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
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use prost::Message as _;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::time::{interval, Interval};
use tokio_util::codec::Framed;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use crate::s2s_transport_proto as pb;
use crate::types::NodeIdentifier;

use super::connection::{ActiveStream, OutboundFrame, PeerState};
use super::frame::{build_frame, stream_codec, FrameType};
use super::manager::InboundDispatch;
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
    bandwidth_probe_interval: Duration,
    bandwidth_probe_size: usize,
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
        bandwidth_probe_interval: Duration,
        bandwidth_probe_size: usize,
        max_pending_pings: usize,
    ) -> Self {
        Self {
            local_node,
            peer_node,
            transport,
            max_frame_bytes,
            outbound_capacity,
            ping_interval,
            bandwidth_probe_interval,
            bandwidth_probe_size,
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
) -> ActiveStream
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (tx, rx) = mpsc::channel::<OutboundFrame>(cfg.outbound_capacity);
    let closed = CancellationToken::new();

    let active = ActiveStream::new(cfg.transport, remote_addr, tx, closed.clone(), is_dialer);

    tokio::spawn(run_pump(stream, cfg, peer, inbound, rx, closed));

    active
}

/// In-flight ping bookkeeping.
struct PendingPings {
    inner: VecDeque<(u64, PendingPing)>,
    cap: usize,
}

#[derive(Debug, Clone, Copy)]
struct PendingPing {
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
    fn insert(&mut self, ts_us: u64, shape: Option<ServiceShape>, payload_bytes: usize) {
        if self.inner.len() >= self.cap {
            self.inner.pop_front();
        }
        self.inner.push_back((
            ts_us,
            PendingPing {
                shape,
                payload_bytes,
            },
        ));
    }
    fn take(&mut self, ts_us: u64) -> Option<PendingPing> {
        let pos = self.inner.iter().position(|(t, _)| *t == ts_us)?;
        self.inner.remove(pos).map(|(_, pending)| pending)
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
            let mut iv = interval(period);
            // burn the immediate first tick
            iv.reset();
            Self::Active(iv)
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
) where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let codec = stream_codec(cfg.max_frame_bytes);
    let mut framed = Framed::new(stream, codec);
    let mut ping_tick = MaybeInterval::maybe(cfg.ping_interval);
    let probe_enabled = cfg.bandwidth_probe_size > 0;
    let mut probe_tick = if probe_enabled {
        MaybeInterval::maybe(cfg.bandwidth_probe_interval)
    } else {
        MaybeInterval::Disabled
    };
    let mut pending = PendingPings::new(cfg.max_pending_pings);
    let level_for_metrics = cfg.transport.service_level();

    let hello = build_frame(
        cfg.local_node,
        cfg.peer_node,
        level_for_metrics,
        FrameType::Hello,
        MessageClass::Regular,
        peer.next_seq(),
        now_us(),
        Bytes::new(),
    );
    if let Err(e) = encode_and_send(&mut framed, &hello, cfg.transport, &peer).await {
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
                        if is_tls_close_notify_eof(&e) {
                            debug!(peer=%peer.node_id(), transport=?cfg.transport, error=%e, "stream closed without TLS close_notify");
                        } else {
                            warn!(peer=%peer.node_id(), transport=?cfg.transport, error=%e, "stream read error");
                        }
                        break;
                    }
                    None => { debug!(peer=%peer.node_id(), transport=?cfg.transport, "stream EOF"); break; }
                };
                let recv_size = buf.len();
                peer.metrics().record_recv(cfg.transport, recv_size);
                match pb::Frame::decode(buf.as_ref()) {
                    Ok(frame) => {
                        if let Err(e) = handle_inbound(
                            frame,
                            recv_size,
                            &cfg,
                            &peer,
                            &inbound,
                            &mut framed,
                            &mut pending,
                            level_for_metrics,
                        ).await {
                            warn!(peer=%peer.node_id(), transport=?cfg.transport, error=%e, "inbound handling failed");
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(peer=%peer.node_id(), transport=?cfg.transport, error=%e, "frame decode error; dropping connection");
                        break;
                    }
                }
            }

            maybe_out = rx.recv() => {
                let Some(out) = maybe_out else { break };
                let frame = build_frame(
                    cfg.local_node,
                    cfg.peer_node,
                    level_for_metrics,
                    FrameType::Data,
                    out.class(),
                    peer.next_seq(),
                    now_us(),
                    out.payload().clone(),
                );
                match encode_and_send(&mut framed, &frame, cfg.transport, &peer).await {
                    Ok(()) => peer
                        .metrics()
                        .record_payload_sent(cfg.transport, out.payload().len()),
                    Err(e) => {
                        warn!(peer=%peer.node_id(), transport=?cfg.transport, error=%e, "stream write failed");
                        break;
                    }
                }
            }

            _ = ping_tick.tick() => {
                let ts = now_us();
                let frame = build_frame(
                    cfg.local_node,
                    cfg.peer_node,
                    level_for_metrics,
                    FrameType::KeepAlive,
                    MessageClass::Regular,
                    peer.next_seq(),
                    ts,
                    Bytes::new(),
                );
                match encode_and_send_returning_size(&mut framed, &frame, cfg.transport, &peer).await {
                    Ok(_) => pending.insert(ts, None, 0),
                    Err(e) => {
                        warn!(peer=%peer.node_id(), transport=?cfg.transport, error=%e, "keepalive write failed");
                        break;
                    }
                }
            }

            _ = probe_tick.tick() => {
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
                        peer.next_seq(),
                        ts,
                        payload,
                    );
                    if frame.encoded_len() > cfg.max_frame_bytes {
                        continue;
                    }
                    match encode_and_send_returning_size(&mut framed, &frame, cfg.transport, &peer).await {
                        Ok(_) => pending.insert(ts, Some(shape), payload_bytes),
                        Err(e) => {
                            warn!(peer=%peer.node_id(), transport=?cfg.transport, service=%shape.name(), error=%e, "probe write failed");
                            break;
                        }
                    }
                    ts = ts.saturating_add(1);
                }
            }
        }
    }

    closed.cancel();
    trace!(peer=%peer.node_id(), transport=?cfg.transport, "stream pump exiting");
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
    framed.send(buf.freeze()).await?;
    peer.metrics().record_sent(transport, len);
    Ok(len)
}

async fn handle_inbound<S>(
    frame: pb::Frame,
    _incoming_wire_size: usize,
    cfg: &StreamPumpConfig,
    peer: &PeerState,
    inbound: &InboundDispatch,
    framed: &mut Framed<S, tokio_util::codec::LengthDelimitedCodec>,
    pending: &mut PendingPings,
    level: ServiceLevel,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    let ty = match pb::FrameType::try_from(frame.frame_type) {
        Ok(v) => v,
        Err(_) => return Ok(()),
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
                peer.next_seq(),
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
            trace!(peer=%cfg.peer_node, transport=?cfg.transport, seq=frame.seq, "received transport hello");
        }
        pb::FrameType::FrameBye => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "peer sent BYE",
            ));
        }
    }
    Ok(())
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
}
