//! Generic framed read/write pump shared by every stream transport.
//!
//! A "stream" here is anything that satisfies `AsyncRead + AsyncWrite + Send +
//! Unpin` — TCP+TLS, KCP+TLS, or a QUIC bidirectional stream. The pump:
//!
//!   * frames every outbound `Bytes` payload as a `pb::Frame` with the
//!     local `NodeIdentifier` as `src_node`, then encodes with prost +
//!     length-prefix via `LengthDelimitedCodec`;
//!   * decodes incoming length-prefixed frames, dispatches `Data` to the
//!     appropriate inbound mpsc, generates `Pong` for `Ping`, and updates
//!     stream RTT + jitter metrics for `Pong` when no native RTT is preferred;
//!   * periodically issues a small keepalive Ping every `ping_interval` for
//!     latency / jitter and liveness;
//!   * exits on EOF, write error, or `closed` cancellation.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use prost::Message as _;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::time::{Instant as TokioInstant, Interval, interval_at, timeout};
use tokio_util::codec::Framed;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use crate::types::NodeIdentifier;
use shitspeak_proto::s2s_transport_proto as pb;

use super::adaptive_queue::{AdaptiveQueueBudget, AdaptiveQueueReceiver, AdaptiveQueueSender};
use super::compression::{
    AdaptiveCompressionState, CompressionConfig, CompressionDictionary, CompressionDictionaryKind,
    DICTIONARY_FINGERPRINT_BYTES, maybe_compress_frame_payload_with_dictionary,
    train_adaptive_dictionary, validate_and_decode_payload_with_dictionary,
};
use super::connection::{ActiveStream, OutboundFrame, PeerState};
use super::frame::{FrameType, build_frame, stream_codec};
use super::manager::InboundDispatch;
use super::metrics::{
    ExpiredOutboundDropStage, QuicDeliveryLane, QuicProtocolErrorReason, TransportIoDirection,
    TransportIoPressureResult, TransportPipelineStage, record_quic_lane_delivery,
    record_quic_protocol_error, record_transport_io_batch, record_transport_io_frames,
    record_transport_io_pressure, record_transport_pipeline_stage,
};
use super::native_stats::BoxedNativeLossSampler;
use super::service_level::{MessageClass, ServiceLevel, TransportKind};

const DICTIONARY_COMPRESSION_HELLO_CAPABILITY: &[u8] = b"shitspeak-s2s-l1-zstd-dict-v1";
#[cfg(test)]
const DICTIONARY_COMPRESSION_LEGACY_ADAPTIVE_FLAG: u8 = 0x01;
const DICTIONARY_COMPRESSION_CONFIGURED_FLAG: u8 = 0x02;
const DICTIONARY_COMPRESSION_ADAPTIVE_ADVERTISEMENT_FLAG: u8 = 0x04;
const MAX_ADAPTIVE_DICTIONARIES_PER_STREAM: usize = 4;
const STREAM_HANDOFF_FRAMES: usize = 2;
const STREAM_WRITE_BATCH_MAX_FRAMES: usize = 32;
const STREAM_WRITE_BATCH_MAX_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PeerDictionaryCompressionSupport {
    adaptive_advertisement: bool,
    configured_fingerprint: Option<[u8; DICTIONARY_FINGERPRINT_BYTES]>,
}

impl PeerDictionaryCompressionSupport {
    fn supports_configured_dictionary(
        self,
        fingerprint: [u8; DICTIONARY_FINGERPRINT_BYTES],
    ) -> bool {
        self.configured_fingerprint == Some(fingerprint)
    }
}

struct AdaptiveDictionaryStore {
    by_id: HashMap<u64, Arc<CompressionDictionary>>,
    order: VecDeque<u64>,
    cap: usize,
}

impl AdaptiveDictionaryStore {
    fn new(cap: usize) -> Self {
        Self {
            by_id: HashMap::with_capacity(cap),
            order: VecDeque::with_capacity(cap),
            cap,
        }
    }

    fn insert(&mut self, dictionary: Arc<CompressionDictionary>) {
        let id = dictionary.wire_id();
        if !self.by_id.contains_key(&id) {
            self.order.push_back(id);
        }
        self.by_id.insert(id, dictionary);
        while self.order.len() > self.cap {
            if let Some(oldest) = self.order.pop_front() {
                self.by_id.remove(&oldest);
            }
        }
    }

    fn get(&self, id: u64) -> Option<&CompressionDictionary> {
        self.by_id.get(&id).map(Arc::as_ref)
    }

    fn latest(&self) -> Option<&CompressionDictionary> {
        self.order.back().and_then(|id| self.get(*id))
    }

    fn contains(&self, id: u64) -> bool {
        self.by_id.contains_key(&id)
    }
}

type AdaptiveTrainingResult = io::Result<Arc<CompressionDictionary>>;

/// Tunables for a single stream pump. Cloned per stream.
#[derive(Clone)]
pub(crate) struct StreamPumpConfig {
    local_node: NodeIdentifier,
    peer_node: NodeIdentifier,
    transport: TransportKind,
    max_frame_bytes: usize,
    ping_interval: Duration,
    idle_ping_interval: Duration,
    native_stats_interval: Duration,
    stream_write_timeout: Duration,
    compression: CompressionConfig,
    /// Cap on how many in-flight pings we remember. Older entries are
    /// dropped when the buffer fills, preventing unbounded memory if pongs
    /// are lost.
    max_pending_pings: usize,
    quic_v2_lane: Option<MessageClass>,
    quic_v2_close_code: Option<Arc<AtomicU32>>,
}

impl StreamPumpConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        local_node: NodeIdentifier,
        peer_node: NodeIdentifier,
        transport: TransportKind,
        max_frame_bytes: usize,
        _outbound_capacity: usize,
        ping_interval: Duration,
        idle_ping_interval: Duration,
        native_stats_interval: Duration,
        stream_write_timeout: Duration,
        compression: CompressionConfig,
        max_pending_pings: usize,
    ) -> Self {
        Self {
            local_node,
            peer_node,
            transport,
            max_frame_bytes,
            ping_interval,
            idle_ping_interval,
            native_stats_interval,
            stream_write_timeout,
            compression,
            max_pending_pings,
            quic_v2_lane: None,
            quic_v2_close_code: None,
        }
    }

    pub(crate) fn with_quic_v2_close_code(mut self, close_code: Arc<AtomicU32>) -> Self {
        self.quic_v2_close_code = Some(close_code);
        self
    }

    fn mark_protocol_violation(&self) {
        if let Some(close_code) = &self.quic_v2_close_code {
            close_code.store(
                super::endpoint::quic::QUIC_CLOSE_SETUP_PROTOCOL,
                Ordering::Release,
            );
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct StreamLanePolicy {
    data_class: Option<MessageClass>,
    owns_session_control: bool,
}

impl StreamLanePolicy {
    pub(crate) const fn legacy() -> Self {
        Self {
            data_class: None,
            owns_session_control: true,
        }
    }

    pub(crate) const fn quic_v2(data_class: MessageClass) -> Self {
        Self {
            data_class: Some(data_class),
            owns_session_control: matches!(data_class, MessageClass::Control),
        }
    }

    fn hello_class(self) -> MessageClass {
        self.data_class.unwrap_or(MessageClass::Regular)
    }

    fn validates_data_lane(self) -> bool {
        self.data_class.is_some()
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
    let budget = AdaptiveQueueBudget::auto();
    let lane_bytes = stream_handoff_lane_bytes(budget.max_bytes(), cfg.max_frame_bytes);
    let (tx, rx) = AdaptiveQueueSender::new(budget.split(lane_bytes));

    let active = ActiveStream::new(cfg.transport, remote_addr, tx, closed.clone(), is_dialer);

    spawn_stream_lane_pump(
        stream,
        cfg,
        peer,
        inbound,
        rx,
        closed,
        native_sampler,
        StreamLanePolicy::legacy(),
    );

    active
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_stream_lane_pump<S>(
    stream: S,
    mut cfg: StreamPumpConfig,
    peer: Arc<PeerState>,
    inbound: InboundDispatch,
    rx: AdaptiveQueueReceiver<OutboundFrame>,
    closed: CancellationToken,
    native_sampler: Option<BoxedNativeLossSampler>,
    policy: StreamLanePolicy,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    cfg.quic_v2_lane = policy.data_class;
    tokio::spawn(run_pump(
        stream,
        cfg,
        peer,
        inbound,
        rx,
        closed,
        native_sampler,
        policy,
    ));
}

pub(crate) fn stream_handoff_lane_bytes(global_bytes: usize, max_frame_bytes: usize) -> usize {
    max_frame_bytes
        .saturating_add(super::adaptive_queue::QUEUE_ITEM_OVERHEAD_BYTES)
        .saturating_mul(STREAM_HANDOFF_FRAMES)
        .max(1)
        .min(global_bytes)
}

#[derive(Clone)]
struct PreparedStreamWrite {
    encoded: Bytes,
    #[cfg(debug_assertions)]
    frame_type: i32,
    class: MessageClass,
    expires_at: Option<Instant>,
}

struct PreparedStreamData {
    write: PreparedStreamWrite,
    class: MessageClass,
    original_payload: Bytes,
    original_payload_len: usize,
    encoded_payload_len: usize,
}

/// In-flight ping bookkeeping.
struct PendingPings {
    inner: VecDeque<(u64, PendingPing)>,
    cap: usize,
}

#[derive(Debug, Clone, Copy)]
struct PendingPing {
    sent_at: Instant,
}

impl PendingPings {
    fn new(cap: usize) -> Self {
        Self {
            inner: VecDeque::with_capacity(cap),
            cap,
        }
    }
    fn insert(&mut self, ts_us: u64) -> Option<PendingPing> {
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
            if self.inner.pop_front().is_some() {
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

fn stabilized_ping_interval(active: Duration, idle: Duration) -> Duration {
    if idle.is_zero() { active } else { idle }
}

fn sample_native_transport_metrics(
    sampler: &mut BoxedNativeLossSampler,
    transport: TransportKind,
    peer: &PeerState,
) -> bool {
    let mut kcp_no_progress_close = false;
    if let Some(rtt) = sampler.sample_rtt() {
        peer.record_native_transport_rtt(transport, rtt);
    }
    if let Some(sample) = sampler.sample() {
        peer.metrics().record_native_loss_sample(
            transport,
            sample.sent_units(),
            sample.lost_units(),
        );
    }
    if let Some(runtime) = sampler.kcp_runtime_sample() {
        peer.metrics().record_kcp_runtime_sample(
            transport,
            runtime.closed(),
            runtime.pending_sender(),
            runtime.waiting_conv(),
            runtime.wait_snd(),
            runtime.snd_wnd(),
            runtime.rmt_wnd(),
            runtime.input_queue_drops(),
            runtime.no_progress_closes(),
            runtime.last_input_age_ms(),
            runtime.outstanding_no_progress_age_ms(),
        );
        kcp_no_progress_close = transport == TransportKind::Kcp && runtime.no_progress_closes() > 0;
    }
    kcp_no_progress_close
}

fn sample_final_native_transport_metrics(
    sampler: &mut BoxedNativeLossSampler,
    transport: TransportKind,
    peer: &PeerState,
) {
    if sample_native_transport_metrics(sampler, transport, peer) {
        peer.require_kcp_best_effort_recovery();
    }
}

async fn run_pump<S>(
    stream: S,
    cfg: StreamPumpConfig,
    peer: Arc<PeerState>,
    inbound: InboundDispatch,
    mut rx: AdaptiveQueueReceiver<OutboundFrame>,
    closed: CancellationToken,
    mut native_sampler: Option<BoxedNativeLossSampler>,
    policy: StreamLanePolicy,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let codec = stream_codec(cfg.max_frame_bytes);
    let mut framed = Framed::new(stream, codec);
    let mut ping_tick = if policy.owns_session_control {
        MaybeInterval::maybe(cfg.ping_interval)
    } else {
        MaybeInterval::Disabled
    };
    let stable_ping_interval = stabilized_ping_interval(cfg.ping_interval, cfg.idle_ping_interval);
    let mut stable_ping_interval_armed = false;
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
    let mut outbound_compression = AdaptiveCompressionState::new(cfg.compression.clone());
    let mut inbound_compression = AdaptiveCompressionState::new(cfg.compression.clone());
    let mut peer_dictionary_support = PeerDictionaryCompressionSupport::default();
    let mut local_adaptive_dictionaries = local_adaptive_dictionary_store(&cfg.compression);
    let mut peer_adaptive_dictionaries =
        AdaptiveDictionaryStore::new(MAX_ADAPTIVE_DICTIONARIES_PER_STREAM);
    let mut active_adaptive_dictionary_id = None;
    let mut pending_adaptive_dictionary_id = None;
    let mut training_in_flight = false;
    let (training_tx, mut training_rx) = mpsc::channel::<AdaptiveTrainingResult>(1);
    let mut pending_stream_data = None;

    let hello = build_frame(
        cfg.local_node,
        cfg.peer_node,
        level_for_metrics,
        FrameType::Hello,
        policy.hello_class(),
        now_us(),
        dictionary_compression_hello_payload(&cfg.compression),
    );
    let hello_result = tokio::select! {
        biased;

        _ = closed.cancelled() => return,
        result = encode_and_send(&mut framed, &hello, &cfg, &peer, None) => result,
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
        maybe_start_adaptive_training(
            &mut outbound_compression,
            peer_dictionary_support,
            active_adaptive_dictionary_id,
            pending_adaptive_dictionary_id,
            &mut training_in_flight,
            &training_tx,
        );

        if let Some(first) = pending_stream_data.take() {
            let Some(first) = drop_expired_prepared_stream_data(first, &cfg, &peer) else {
                continue;
            };
            if let Err(e) = send_stream_data_batch(
                &mut framed,
                &cfg,
                &peer,
                &mut rx,
                &mut pending_stream_data,
                first,
                &mut outbound_compression,
                &local_adaptive_dictionaries,
                active_adaptive_dictionary_id,
                peer_dictionary_support,
            )
            .await
            {
                warn!(peer=%peer.node_id(), transport=?cfg.transport, error=%e, "stream write failed");
                break;
            }
            continue;
        }

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
                        if e.kind() == io::ErrorKind::InvalidData {
                            cfg.mark_protocol_violation();
                        }
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
                let decode_started_at = Instant::now();
                let decoded_frame = pb::Frame::decode(buf.as_ref());
                record_transport_pipeline_stage(
                    cfg.transport,
                    TransportPipelineStage::FrameDecode,
                    decode_started_at.elapsed(),
                );
                match decoded_frame {
                    Ok(frame) => {
                        let class = match pb::MessageClass::try_from(frame.message_class) {
                            Ok(class) => MessageClass::from(class),
                            Err(_) if policy.validates_data_lane() => {
                                cfg.mark_protocol_violation();
                                peer.metrics().record_data_health_failure(cfg.transport);
                                record_quic_protocol_error(QuicProtocolErrorReason::ClassMismatch);
                                warn!(peer=%peer.node_id(), transport=?cfg.transport, message_class=frame.message_class, "invalid message class on strict stream lane");
                                break;
                            }
                            Err(_) => MessageClass::Regular,
                        };
                        record_transport_io_batch(
                            peer.node_id(),
                            cfg.transport,
                            TransportIoDirection::Ingress,
                            1,
                            recv_size,
                        );
                        record_transport_io_frames(
                            peer.node_id(),
                            cfg.transport,
                            TransportIoDirection::Ingress,
                            class,
                            1,
                        );
                        if let Some(lane) = cfg.quic_v2_lane {
                            record_quic_lane_delivery(
                                peer.node_id(),
                                TransportIoDirection::Ingress,
                                quic_delivery_lane(lane),
                                1,
                                recv_size,
                            );
                        }
                        #[cfg(debug_assertions)]
                        crate::debug_io::record_named_received(
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
                            &mut inbound_compression,
                            &mut peer_adaptive_dictionaries,
                            &local_adaptive_dictionaries,
                            &mut active_adaptive_dictionary_id,
                            &mut pending_adaptive_dictionary_id,
                            &mut peer_dictionary_support,
                            level_for_metrics,
                            policy,
                        ).await {
                            Ok(transport_link_stable) => {
                                if let Err(e) = maybe_advertise_local_adaptive_dictionary(
                                    &cfg,
                                    &peer,
                                    &mut framed,
                                    &local_adaptive_dictionaries,
                                    peer_dictionary_support,
                                    active_adaptive_dictionary_id,
                                    &mut pending_adaptive_dictionary_id,
                                ).await {
                                    warn!(peer=%peer.node_id(), transport=?cfg.transport, error=%e, "adaptive dictionary advertisement failed");
                                    break;
                                }
                                if transport_link_stable {
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
                        cfg.mark_protocol_violation();
                        peer.metrics().record_data_health_failure(cfg.transport);
                        warn!(peer=%peer.node_id(), transport=?cfg.transport, error=%e, "frame decode error; dropping connection");
                        break;
                    }
                }
            }

            maybe_dictionary = training_rx.recv() => {
                training_in_flight = false;
                let Some(result) = maybe_dictionary else { break };
                match result {
                    Ok(dictionary) => {
                        let dictionary_id = dictionary.wire_id();
                        local_adaptive_dictionaries.insert(dictionary.clone());
                        if let Err(e) = outbound_compression
                            .config()
                            .cache_adaptive_dictionary(dictionary)
                            .await
                        {
                            warn!(peer=%peer.node_id(), transport=?cfg.transport, dictionary_id, error=%e, "adaptive dictionary cache write failed");
                        }
                        if let Err(e) = maybe_advertise_local_adaptive_dictionary(
                            &cfg,
                            &peer,
                            &mut framed,
                            &local_adaptive_dictionaries,
                            peer_dictionary_support,
                            active_adaptive_dictionary_id,
                            &mut pending_adaptive_dictionary_id,
                        ).await {
                            warn!(peer=%peer.node_id(), transport=?cfg.transport, dictionary_id, error=%e, "adaptive dictionary advertisement failed");
                            break;
                        }
                    }
                    Err(e) => {
                        debug!(peer=%peer.node_id(), transport=?cfg.transport, error=%e, "adaptive dictionary training failed");
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
                match encode_and_send_returning_size(&mut framed, &frame, &cfg, &peer, None).await {
                    Ok(_) => {
                        record_evicted_pending(
                            pending.insert(ts),
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

            _ = native_tick.tick() => {
                if let Some(sampler) = native_sampler.as_mut() {
                    let _ = sample_native_transport_metrics(sampler, cfg.transport, &peer);
                }
            }

            maybe_out = rx.recv() => {
                let Some(out) = maybe_out else { break };
                let first = match prepare_stream_data_frame(
                    out,
                    &cfg,
                    &peer,
                    &mut outbound_compression,
                    &local_adaptive_dictionaries,
                    active_adaptive_dictionary_id,
                    peer_dictionary_support,
                ) {
                    Ok(Some(first)) => first,
                    Ok(None) => continue,
                    Err(e) => {
                        warn!(peer=%peer.node_id(), transport=?cfg.transport, error=%e, "stream outbound frame preparation failed");
                        break;
                    }
                };
                match send_stream_data_batch(
                    &mut framed,
                    &cfg,
                    &peer,
                    &mut rx,
                    &mut pending_stream_data,
                    first,
                    &mut outbound_compression,
                    &local_adaptive_dictionaries,
                    active_adaptive_dictionary_id,
                    peer_dictionary_support,
                ).await {
                    Ok(()) => {}
                    Err(e) => {
                        warn!(peer=%peer.node_id(), transport=?cfg.transport, error=%e, "stream write failed");
                        break;
                    }
                }
            }
        }
    }

    // A no-progress KCP close can happen between periodic native-stat ticks.
    // Take one final handle snapshot before dropping the sampler so BestEffort
    // does not immediately reselect the replacement session on stale metrics.
    if let Some(sampler) = native_sampler.as_mut() {
        sample_final_native_transport_metrics(sampler, cfg.transport, &peer);
    }
    closed.cancel();
    peer.notify_outbound_dispatch();
    trace!(peer=%peer.node_id(), transport=?cfg.transport, "stream pump exiting");
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
    if evicted.is_some() {
        peer.metrics().record_probe_lost(transport);
    }
}

fn local_adaptive_dictionary_store(cfg: &CompressionConfig) -> AdaptiveDictionaryStore {
    let mut store = AdaptiveDictionaryStore::new(MAX_ADAPTIVE_DICTIONARIES_PER_STREAM);
    if let Some(dictionary) = cfg.cached_adaptive_dictionary() {
        store.insert(dictionary);
    }
    store
}

fn maybe_start_adaptive_training(
    state: &mut AdaptiveCompressionState,
    peer_support: PeerDictionaryCompressionSupport,
    active_adaptive_dictionary_id: Option<u64>,
    pending_adaptive_dictionary_id: Option<u64>,
    training_in_flight: &mut bool,
    training_tx: &mpsc::Sender<AdaptiveTrainingResult>,
) {
    if *training_in_flight
        || active_adaptive_dictionary_id.is_some()
        || pending_adaptive_dictionary_id.is_some()
        || !peer_support.adaptive_advertisement
    {
        return;
    }

    let Some(snapshot) = state.training_snapshot_if_ready() else {
        return;
    };

    *training_in_flight = true;
    let training_tx = training_tx.clone();
    tokio::spawn(async move {
        let result = tokio::task::spawn_blocking(move || train_adaptive_dictionary(snapshot))
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
            .and_then(|result| result);
        let _ = training_tx.send(result).await;
    });
}

async fn maybe_advertise_local_adaptive_dictionary<S>(
    cfg: &StreamPumpConfig,
    peer: &PeerState,
    framed: &mut Framed<S, tokio_util::codec::LengthDelimitedCodec>,
    local_adaptive_dictionaries: &AdaptiveDictionaryStore,
    peer_support: PeerDictionaryCompressionSupport,
    active_adaptive_dictionary_id: Option<u64>,
    pending_adaptive_dictionary_id: &mut Option<u64>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    let Some(dictionary) = next_adaptive_dictionary_to_advertise(
        local_adaptive_dictionaries,
        peer_support,
        active_adaptive_dictionary_id,
        *pending_adaptive_dictionary_id,
    ) else {
        return Ok(());
    };

    let dictionary_id = dictionary.wire_id();
    let frame = dictionary_advertisement_frame(cfg, dictionary);
    encode_and_send(framed, &frame, cfg, peer, None).await?;
    *pending_adaptive_dictionary_id = Some(dictionary_id);
    trace!(peer=%cfg.peer_node, transport=?cfg.transport, dictionary_id, "advertised adaptive dictionary");
    Ok(())
}

fn next_adaptive_dictionary_to_advertise(
    local_adaptive_dictionaries: &AdaptiveDictionaryStore,
    peer_support: PeerDictionaryCompressionSupport,
    active_adaptive_dictionary_id: Option<u64>,
    pending_adaptive_dictionary_id: Option<u64>,
) -> Option<&CompressionDictionary> {
    if !peer_support.adaptive_advertisement
        || active_adaptive_dictionary_id.is_some()
        || pending_adaptive_dictionary_id.is_some()
    {
        return None;
    }

    local_adaptive_dictionaries.latest()
}

fn outbound_compression_dictionary<'a>(
    cfg: &'a CompressionConfig,
    local_adaptive_dictionaries: &'a AdaptiveDictionaryStore,
    active_adaptive_dictionary_id: Option<u64>,
    peer_support: PeerDictionaryCompressionSupport,
) -> Option<&'a CompressionDictionary> {
    if let Some(fingerprint) = cfg.configured_dictionary_fingerprint() {
        if peer_support.supports_configured_dictionary(fingerprint) {
            return cfg.dictionary();
        }
    }

    if !peer_support.adaptive_advertisement {
        return None;
    }

    active_adaptive_dictionary_id.and_then(|id| local_adaptive_dictionaries.get(id))
}

fn inbound_compression_dictionary<'a>(
    frame: &pb::Frame,
    cfg: &'a CompressionConfig,
    peer_adaptive_dictionaries: &'a AdaptiveDictionaryStore,
) -> Option<&'a CompressionDictionary> {
    if pb::PayloadEncoding::try_from(frame.payload_encoding) != Ok(pb::PayloadEncoding::ZstdDict) {
        return None;
    }

    if frame.payload_dictionary_id == 0 {
        return cfg.dictionary();
    }

    if cfg.dictionary_wire_id() == Some(frame.payload_dictionary_id) {
        return cfg.dictionary();
    }

    peer_adaptive_dictionaries.get(frame.payload_dictionary_id)
}

fn dictionary_advertisement_frame(
    cfg: &StreamPumpConfig,
    dictionary: &CompressionDictionary,
) -> pb::Frame {
    let mut frame = build_frame(
        cfg.local_node,
        cfg.peer_node,
        cfg.transport.service_level(),
        FrameType::Dictionary,
        MessageClass::Control,
        now_us(),
        dictionary.bytes(),
    );
    frame.payload_dictionary_id = dictionary.wire_id();
    frame
}

fn dictionary_ack_frame(cfg: &StreamPumpConfig, dictionary_id: u64) -> pb::Frame {
    let mut frame = build_frame(
        cfg.local_node,
        cfg.peer_node,
        cfg.transport.service_level(),
        FrameType::DictionaryAck,
        MessageClass::Control,
        now_us(),
        Bytes::new(),
    );
    frame.payload_dictionary_id = dictionary_id;
    frame
}

async fn handle_dictionary_advertisement<S>(
    frame: pb::Frame,
    cfg: &StreamPumpConfig,
    peer: &PeerState,
    framed: &mut Framed<S, tokio_util::codec::LengthDelimitedCodec>,
    peer_adaptive_dictionaries: &mut AdaptiveDictionaryStore,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    if !cfg.compression.enabled() || !cfg.compression.adaptive_dictionary_enabled() {
        return Ok(());
    }

    let dictionary_id = frame.payload_dictionary_id;
    if dictionary_id == 0 || frame.payload.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "adaptive dictionary advertisement missing dictionary id or bytes",
        ));
    }

    let dictionary = Arc::new(CompressionDictionary::new(
        frame.payload.to_vec(),
        cfg.compression.level(),
        CompressionDictionaryKind::Adaptive,
    )?);
    if dictionary.wire_id() != dictionary_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "adaptive dictionary advertisement id does not match bytes",
        ));
    }

    peer_adaptive_dictionaries.insert(dictionary);
    let ack = dictionary_ack_frame(cfg, dictionary_id);
    encode_and_send(framed, &ack, cfg, peer, None).await?;
    trace!(peer=%cfg.peer_node, transport=?cfg.transport, dictionary_id, "accepted adaptive dictionary");
    Ok(())
}

fn prepare_stream_data_frame(
    out: OutboundFrame,
    cfg: &StreamPumpConfig,
    peer: &PeerState,
    outbound_compression: &mut AdaptiveCompressionState,
    local_adaptive_dictionaries: &AdaptiveDictionaryStore,
    active_adaptive_dictionary_id: Option<u64>,
    peer_dictionary_support: PeerDictionaryCompressionSupport,
) -> io::Result<Option<PreparedStreamData>> {
    let options = out.options();
    if options.is_expired() {
        peer.record_expired_outbound_drop(
            ExpiredOutboundDropStage::TransportWrite,
            Some(cfg.transport),
            out.class(),
        );
        trace!(peer=%peer.node_id(), transport=?cfg.transport, "dropping expired outbound stream frame");
        return Ok(None);
    }

    let original_payload = out.payload().clone();
    let original_payload_len = original_payload.len();
    let class = out.class();
    // Legacy transports retain their historical inferred service level.
    // QUIC v2 carries the caller's requested reliable level on the selected
    // class lane so the receiver can preserve that logical contract.
    let wire_level = if cfg.quic_v2_lane.is_some() {
        out.level()
    } else {
        cfg.transport.service_level()
    };
    let mut frame = build_frame(
        cfg.local_node,
        cfg.peer_node,
        wire_level,
        FrameType::Data,
        class,
        now_us(),
        original_payload.clone(),
    );
    let dictionary = outbound_compression_dictionary(
        outbound_compression.config(),
        local_adaptive_dictionaries,
        active_adaptive_dictionary_id,
        peer_dictionary_support,
    );
    let compress_started_at = Instant::now();
    let compress_result = maybe_compress_frame_payload_with_dictionary(
        &mut frame,
        options,
        outbound_compression.config(),
        dictionary,
        cfg.max_frame_bytes,
    );
    record_transport_pipeline_stage(
        cfg.transport,
        TransportPipelineStage::L1Compress,
        compress_started_at.elapsed(),
    );
    compress_result?;

    let encoded_payload_len = frame.payload.len();
    let encoded = encode_stream_frame(&frame, cfg)?;
    Ok(Some(PreparedStreamData {
        write: PreparedStreamWrite {
            encoded,
            #[cfg(debug_assertions)]
            frame_type: frame.frame_type,
            class,
            expires_at: options.expires_at(),
        },
        class,
        original_payload,
        original_payload_len,
        encoded_payload_len,
    }))
}

fn drop_expired_prepared_stream_data(
    prepared: PreparedStreamData,
    cfg: &StreamPumpConfig,
    peer: &PeerState,
) -> Option<PreparedStreamData> {
    if prepared
        .write
        .expires_at
        .is_some_and(|expires_at| Instant::now() >= expires_at)
    {
        peer.record_expired_outbound_drop(
            ExpiredOutboundDropStage::TransportWrite,
            Some(cfg.transport),
            prepared.class,
        );
        trace!(peer=%peer.node_id(), transport=?cfg.transport, "dropping expired pending outbound stream frame");
        return None;
    }
    Some(prepared)
}

async fn send_stream_data_batch<S>(
    framed: &mut Framed<S, tokio_util::codec::LengthDelimitedCodec>,
    cfg: &StreamPumpConfig,
    peer: &PeerState,
    rx: &mut AdaptiveQueueReceiver<OutboundFrame>,
    pending_stream_data: &mut Option<PreparedStreamData>,
    first: PreparedStreamData,
    outbound_compression: &mut AdaptiveCompressionState,
    local_adaptive_dictionaries: &AdaptiveDictionaryStore,
    active_adaptive_dictionary_id: Option<u64>,
    peer_dictionary_support: PeerDictionaryCompressionSupport,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    let mut batch = Vec::with_capacity(STREAM_WRITE_BATCH_MAX_FRAMES);
    let mut batch_bytes = first.write.encoded.len();
    batch.push(first);

    while batch.len() < STREAM_WRITE_BATCH_MAX_FRAMES && batch_bytes < STREAM_WRITE_BATCH_MAX_BYTES
    {
        let out = match rx.try_recv() {
            Ok(out) => out,
            Err(mpsc::error::TryRecvError::Empty) => break,
            Err(mpsc::error::TryRecvError::Disconnected) => break,
        };
        let Some(prepared) = prepare_stream_data_frame(
            out,
            cfg,
            peer,
            outbound_compression,
            local_adaptive_dictionaries,
            active_adaptive_dictionary_id,
            peer_dictionary_support,
        )?
        else {
            continue;
        };
        if let Err(prepared) = push_prepared_stream_data(&mut batch, &mut batch_bytes, prepared) {
            *pending_stream_data = Some(prepared);
            break;
        }
    }

    let writes = batch
        .iter()
        .map(|entry| entry.write.clone())
        .collect::<Vec<_>>();
    send_encoded_stream_writes(framed, cfg, peer, &writes).await?;
    for entry in batch {
        peer.metrics()
            .record_payload_sent(cfg.transport, entry.original_payload_len);
        peer.metrics().record_l1_compression_sent(
            cfg.transport,
            entry.original_payload_len,
            entry.encoded_payload_len,
        );
        outbound_compression.record_sample(&entry.original_payload);
    }
    Ok(())
}

fn push_prepared_stream_data(
    batch: &mut Vec<PreparedStreamData>,
    batch_bytes: &mut usize,
    prepared: PreparedStreamData,
) -> Result<(), PreparedStreamData> {
    let encoded_len = prepared.write.encoded.len();
    if !batch.is_empty()
        && (batch.len() >= STREAM_WRITE_BATCH_MAX_FRAMES
            || batch_bytes.saturating_add(encoded_len) > STREAM_WRITE_BATCH_MAX_BYTES)
    {
        return Err(prepared);
    }
    *batch_bytes = batch_bytes.saturating_add(encoded_len);
    batch.push(prepared);
    Ok(())
}

async fn encode_and_send<S>(
    framed: &mut Framed<S, tokio_util::codec::LengthDelimitedCodec>,
    frame: &pb::Frame,
    cfg: &StreamPumpConfig,
    peer: &PeerState,
    expires_at: Option<Instant>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    let _ = encode_and_send_returning_size(framed, frame, cfg, peer, expires_at).await?;
    Ok(())
}

async fn encode_and_send_returning_size<S>(
    framed: &mut Framed<S, tokio_util::codec::LengthDelimitedCodec>,
    frame: &pb::Frame,
    cfg: &StreamPumpConfig,
    peer: &PeerState,
    expires_at: Option<Instant>,
) -> std::io::Result<usize>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    let encoded = encode_stream_frame(frame, cfg)?;
    let len = encoded.len();
    let write = PreparedStreamWrite {
        encoded,
        #[cfg(debug_assertions)]
        frame_type: frame.frame_type,
        class: pb::MessageClass::try_from(frame.message_class)
            .map(MessageClass::from)
            .unwrap_or(MessageClass::Regular),
        expires_at,
    };
    let _ = send_encoded_stream_writes(framed, cfg, peer, std::slice::from_ref(&write)).await?;
    Ok(len)
}

fn encode_stream_frame(frame: &pb::Frame, cfg: &StreamPumpConfig) -> io::Result<Bytes> {
    let mut buf = BytesMut::with_capacity(frame.encoded_len());
    let encode_started_at = Instant::now();
    frame
        .encode(&mut buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    record_transport_pipeline_stage(
        cfg.transport,
        TransportPipelineStage::FrameEncode,
        encode_started_at.elapsed(),
    );
    Ok(buf.freeze())
}

async fn send_encoded_stream_writes<S>(
    framed: &mut Framed<S, tokio_util::codec::LengthDelimitedCodec>,
    cfg: &StreamPumpConfig,
    peer: &PeerState,
    writes: &[PreparedStreamWrite],
) -> io::Result<usize>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    if writes.is_empty() {
        return Ok(0);
    }

    let total_len = writes
        .iter()
        .fold(0usize, |acc, write| acc.saturating_add(write.encoded.len()));
    let expires_at = writes.iter().filter_map(|write| write.expires_at).min();
    let send = async {
        for write in writes {
            framed.feed(write.encoded.clone()).await?;
        }
        framed.flush().await
    };
    let write_started_at = Instant::now();
    let send_result = match stream_write_deadline(&cfg, expires_at) {
        Some(deadline) => match timeout(deadline, send).await {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "stream write timed out",
            )),
        },
        None => send.await,
    };
    record_transport_pipeline_stage(
        cfg.transport,
        TransportPipelineStage::StreamWrite,
        write_started_at.elapsed(),
    );
    if let Err(error) = send_result {
        record_transport_io_batch(
            peer.node_id(),
            cfg.transport,
            TransportIoDirection::Egress,
            writes.len(),
            total_len,
        );
        record_transport_io_pressure(
            peer.node_id(),
            cfg.transport,
            TransportIoDirection::Egress,
            if error.kind() == io::ErrorKind::TimedOut {
                TransportIoPressureResult::Timeout
            } else {
                TransportIoPressureResult::Error
            },
            1,
        );
        peer.metrics().record_data_health_failure(cfg.transport);
        return Err(error);
    }

    for write in writes {
        let len = write.encoded.len();
        peer.metrics().record_sent(cfg.transport, len);
        record_transport_io_frames(
            peer.node_id(),
            cfg.transport,
            TransportIoDirection::Egress,
            write.class,
            1,
        );
        if let Some(lane) = cfg.quic_v2_lane {
            record_quic_lane_delivery(
                peer.node_id(),
                TransportIoDirection::Egress,
                quic_delivery_lane(lane),
                1,
                len,
            );
        }
        #[cfg(debug_assertions)]
        crate::debug_io::record_named_sent(
            stream_frame_kind_name(cfg.transport, write.frame_type),
            len,
        );
        peer.metrics().record_data_health_success(cfg.transport);
    }
    record_transport_io_batch(
        peer.node_id(),
        cfg.transport,
        TransportIoDirection::Egress,
        writes.len(),
        total_len,
    );
    Ok(total_len)
}

fn quic_delivery_lane(class: MessageClass) -> QuicDeliveryLane {
    match class {
        MessageClass::Control => QuicDeliveryLane::Control,
        MessageClass::HighPriority => QuicDeliveryLane::HighPriority,
        MessageClass::Regular => QuicDeliveryLane::Regular,
    }
}

fn stream_write_deadline(cfg: &StreamPumpConfig, expires_at: Option<Instant>) -> Option<Duration> {
    let mut deadline = (!cfg.stream_write_timeout.is_zero()).then_some(cfg.stream_write_timeout);
    if let Some(expires_at) = expires_at {
        let remaining = expires_at.saturating_duration_since(Instant::now());
        deadline = Some(deadline.map_or(remaining, |deadline| deadline.min(remaining)));
    }
    deadline
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
            Ok(pb::FrameType::FrameDictionary) => "transport.tcp.frame.dictionary",
            Ok(pb::FrameType::FrameDictionaryAck) => "transport.tcp.frame.dictionary_ack",
            Err(_) => "transport.tcp.frame.unknown",
        },
        TransportKind::Kcp => match pb::FrameType::try_from(frame_type) {
            Ok(pb::FrameType::FrameData) => "transport.kcp.frame.data",
            Ok(pb::FrameType::FramePing) => "transport.kcp.frame.ping",
            Ok(pb::FrameType::FramePong) => "transport.kcp.frame.pong",
            Ok(pb::FrameType::FrameKeepalive) => "transport.kcp.frame.keepalive",
            Ok(pb::FrameType::FrameHello) => "transport.kcp.frame.hello",
            Ok(pb::FrameType::FrameBye) => "transport.kcp.frame.bye",
            Ok(pb::FrameType::FrameDictionary) => "transport.kcp.frame.dictionary",
            Ok(pb::FrameType::FrameDictionaryAck) => "transport.kcp.frame.dictionary_ack",
            Err(_) => "transport.kcp.frame.unknown",
        },
        TransportKind::Quic => match pb::FrameType::try_from(frame_type) {
            Ok(pb::FrameType::FrameData) => "transport.quic.frame.data",
            Ok(pb::FrameType::FramePing) => "transport.quic.frame.ping",
            Ok(pb::FrameType::FramePong) => "transport.quic.frame.pong",
            Ok(pb::FrameType::FrameKeepalive) => "transport.quic.frame.keepalive",
            Ok(pb::FrameType::FrameHello) => "transport.quic.frame.hello",
            Ok(pb::FrameType::FrameBye) => "transport.quic.frame.bye",
            Ok(pb::FrameType::FrameDictionary) => "transport.quic.frame.dictionary",
            Ok(pb::FrameType::FrameDictionaryAck) => "transport.quic.frame.dictionary_ack",
            Err(_) => "transport.quic.frame.unknown",
        },
        TransportKind::Udp => match pb::FrameType::try_from(frame_type) {
            Ok(pb::FrameType::FrameData) => "transport.udp.stream_frame.data",
            Ok(pb::FrameType::FramePing) => "transport.udp.stream_frame.ping",
            Ok(pb::FrameType::FramePong) => "transport.udp.stream_frame.pong",
            Ok(pb::FrameType::FrameKeepalive) => "transport.udp.stream_frame.keepalive",
            Ok(pb::FrameType::FrameHello) => "transport.udp.stream_frame.hello",
            Ok(pb::FrameType::FrameBye) => "transport.udp.stream_frame.bye",
            Ok(pb::FrameType::FrameDictionary) => "transport.udp.stream_frame.dictionary",
            Ok(pb::FrameType::FrameDictionaryAck) => "transport.udp.stream_frame.dictionary_ack",
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
    inbound_compression: &mut AdaptiveCompressionState,
    peer_adaptive_dictionaries: &mut AdaptiveDictionaryStore,
    local_adaptive_dictionaries: &AdaptiveDictionaryStore,
    active_adaptive_dictionary_id: &mut Option<u64>,
    pending_adaptive_dictionary_id: &mut Option<u64>,
    peer_dictionary_support: &mut PeerDictionaryCompressionSupport,
    legacy_level: ServiceLevel,
    policy: StreamLanePolicy,
) -> std::io::Result<bool>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    let encoded_payload_len = frame.payload.len();
    {
        let dictionary = inbound_compression_dictionary(
            &frame,
            inbound_compression.config(),
            peer_adaptive_dictionaries,
        );
        let decompress_started_at = Instant::now();
        let decompress_result = validate_and_decode_payload_with_dictionary(
            &mut frame,
            cfg.max_frame_bytes,
            inbound_compression.config(),
            dictionary,
        );
        record_transport_pipeline_stage(
            cfg.transport,
            TransportPipelineStage::L1Decompress,
            decompress_started_at.elapsed(),
        );
        if let Err(error) = decompress_result {
            if policy.validates_data_lane() {
                cfg.mark_protocol_violation();
            }
            return Err(error);
        }
    }
    let mut transport_link_stable = false;
    let ty = match pb::FrameType::try_from(frame.frame_type) {
        Ok(v) => v,
        Err(_) if policy.validates_data_lane() => {
            cfg.mark_protocol_violation();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown frame type on QUIC v2 lane",
            ));
        }
        Err(_) => return Ok(false),
    };
    match ty {
        pb::FrameType::FrameData => {
            let class = match pb::MessageClass::try_from(frame.message_class) {
                Ok(class) => MessageClass::from(class),
                Err(_) if policy.validates_data_lane() => {
                    cfg.mark_protocol_violation();
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unknown message class",
                    ));
                }
                Err(_) => MessageClass::Regular,
            };
            // Validate frame identity on every lane (QUIC v2 and legacy
            // TCP/KCP/QUIC-v1). Without this, an authenticated but
            // malicious/misconfigured peer could inject Data frames claiming
            // any src_node/dst_node, defeating per-node provenance before
            // overlay routing.
            if frame.src_node != u32::from(cfg.peer_node) {
                cfg.mark_protocol_violation();
                record_quic_protocol_error(QuicProtocolErrorReason::SourceMismatch);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stream frame source identity mismatch",
                ));
            }
            if frame.dst_node != u32::from(cfg.local_node) {
                cfg.mark_protocol_violation();
                record_quic_protocol_error(QuicProtocolErrorReason::DestinationMismatch);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stream frame destination identity mismatch",
                ));
            }
            let wire_level = if let Some(expected) = policy.data_class {
                let wire_level = ServiceLevel::try_from(frame.service_level).map_err(|_| {
                    cfg.mark_protocol_violation();
                    record_quic_protocol_error(QuicProtocolErrorReason::ServiceMismatch);
                    io::Error::new(io::ErrorKind::InvalidData, "unknown service level")
                })?;
                if class != expected {
                    cfg.mark_protocol_violation();
                    record_quic_protocol_error(QuicProtocolErrorReason::ClassMismatch);
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("message class {class:?} does not match {expected:?} QUIC lane"),
                    ));
                }
                if wire_level == ServiceLevel::BestEffort {
                    cfg.mark_protocol_violation();
                    record_quic_protocol_error(QuicProtocolErrorReason::ServiceMismatch);
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "best-effort data is not allowed on a QUIC v2 stream",
                    ));
                }
                wire_level
            } else {
                legacy_level
            };
            let original_payload_len = frame.payload.len();
            peer.metrics()
                .record_payload_recv(cfg.transport, original_payload_len);
            peer.metrics().record_l1_compression_recv(
                cfg.transport,
                original_payload_len,
                encoded_payload_len,
            );
            inbound_compression.record_sample(&frame.payload);
            inbound.dispatch(super::manager::InboundMessage::new(
                cfg.peer_node,
                wire_level,
                cfg.transport,
                class,
                frame.payload,
            ));
        }
        pb::FrameType::FramePing | pb::FrameType::FrameKeepalive => {
            if !policy.owns_session_control {
                cfg.mark_protocol_violation();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "session-control frame received outside the Control lane",
                ));
            }
            // Echo the payload back so the round trip carries enough bytes
            // for the sender to estimate throughput. Empty pings (latency
            // probes) round-trip a tiny pong; large probes round-trip a
            // payload-sized pong.
            let echo_payload = frame.payload.clone();
            let pong = build_frame(
                cfg.local_node,
                cfg.peer_node,
                legacy_level,
                FrameType::Pong,
                MessageClass::Regular,
                frame.ts_us,
                echo_payload,
            );
            encode_and_send(framed, &pong, cfg, peer, None).await?;
        }
        pb::FrameType::FramePong => {
            if !policy.owns_session_control {
                cfg.mark_protocol_violation();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "session-control frame received outside the Control lane",
                ));
            }
            if let Some(ping) = pending.take(frame.ts_us) {
                let rtt = ping.sent_at.elapsed();
                if cfg.transport != TransportKind::Kcp {
                    peer.metrics().record_rtt(cfg.transport, rtt);
                } else {
                    trace!(
                        peer=%cfg.peer_node,
                        rtt_us = rtt.as_micros() as u64,
                        "kcp stream pong observed; native kcp ack rtt drives latency metric"
                    );
                }
                peer.metrics().record_probe_delivered(cfg.transport);
                transport_link_stable = true;
            } else {
                peer.metrics().record_unmatched_probe_pong(cfg.transport);
            }
        }
        pb::FrameType::FrameHello => {
            *peer_dictionary_support =
                parse_dictionary_compression_hello_payload(frame.payload.as_ref());
            trace!(peer=%cfg.peer_node, transport=?cfg.transport, "received transport hello");
        }
        pb::FrameType::FrameDictionary => {
            if let Err(error) = handle_dictionary_advertisement(
                frame,
                cfg,
                peer,
                framed,
                peer_adaptive_dictionaries,
            )
            .await
            {
                if error.kind() == io::ErrorKind::InvalidData {
                    cfg.mark_protocol_violation();
                }
                return Err(error);
            }
        }
        pb::FrameType::FrameDictionaryAck => {
            let dictionary_id = frame.payload_dictionary_id;
            if acknowledge_adaptive_dictionary(
                dictionary_id,
                local_adaptive_dictionaries,
                active_adaptive_dictionary_id,
                pending_adaptive_dictionary_id,
            ) {
                trace!(peer=%cfg.peer_node, transport=?cfg.transport, dictionary_id, "adaptive dictionary acknowledged");
            }
        }
        pb::FrameType::FrameBye => {
            if !policy.owns_session_control {
                cfg.mark_protocol_violation();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "session-control frame received outside the Control lane",
                ));
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "peer sent BYE",
            ));
        }
    }
    Ok(transport_link_stable)
}

fn acknowledge_adaptive_dictionary(
    dictionary_id: u64,
    local_adaptive_dictionaries: &AdaptiveDictionaryStore,
    active_adaptive_dictionary_id: &mut Option<u64>,
    pending_adaptive_dictionary_id: &mut Option<u64>,
) -> bool {
    if dictionary_id == 0 || *pending_adaptive_dictionary_id != Some(dictionary_id) {
        return false;
    }

    if !local_adaptive_dictionaries.contains(dictionary_id) {
        return false;
    }

    *active_adaptive_dictionary_id = Some(dictionary_id);
    *pending_adaptive_dictionary_id = None;
    true
}

fn dictionary_compression_supported(cfg: &CompressionConfig) -> bool {
    cfg.enabled() && (cfg.dictionary_len().is_some() || cfg.adaptive_dictionary_enabled())
}

fn dictionary_compression_hello_payload(cfg: &CompressionConfig) -> Bytes {
    if !dictionary_compression_supported(cfg) {
        return Bytes::new();
    }

    let configured_fingerprint = cfg.configured_dictionary_fingerprint();
    let mut flags = 0;
    if cfg.adaptive_dictionary_enabled() {
        flags |= DICTIONARY_COMPRESSION_ADAPTIVE_ADVERTISEMENT_FLAG;
    }
    if configured_fingerprint.is_some() {
        flags |= DICTIONARY_COMPRESSION_CONFIGURED_FLAG;
    }

    let mut payload = Vec::with_capacity(
        DICTIONARY_COMPRESSION_HELLO_CAPABILITY.len()
            + 1
            + configured_fingerprint
                .map(|_| DICTIONARY_FINGERPRINT_BYTES)
                .unwrap_or_default(),
    );
    payload.extend_from_slice(DICTIONARY_COMPRESSION_HELLO_CAPABILITY);
    payload.push(flags);
    if let Some(fingerprint) = configured_fingerprint {
        payload.extend_from_slice(&fingerprint);
    }
    Bytes::from(payload)
}

fn parse_dictionary_compression_hello_payload(payload: &[u8]) -> PeerDictionaryCompressionSupport {
    if !payload.starts_with(DICTIONARY_COMPRESSION_HELLO_CAPABILITY)
        || payload.len() <= DICTIONARY_COMPRESSION_HELLO_CAPABILITY.len()
    {
        return PeerDictionaryCompressionSupport::default();
    }

    let flags = payload[DICTIONARY_COMPRESSION_HELLO_CAPABILITY.len()];
    let mut offset = DICTIONARY_COMPRESSION_HELLO_CAPABILITY.len() + 1;
    let configured_fingerprint = if flags & DICTIONARY_COMPRESSION_CONFIGURED_FLAG != 0 {
        if payload.len() < offset + DICTIONARY_FINGERPRINT_BYTES {
            return PeerDictionaryCompressionSupport::default();
        }
        let mut fingerprint = [0; DICTIONARY_FINGERPRINT_BYTES];
        fingerprint.copy_from_slice(&payload[offset..offset + DICTIONARY_FINGERPRINT_BYTES]);
        offset += DICTIONARY_FINGERPRINT_BYTES;
        Some(fingerprint)
    } else {
        None
    };

    if offset != payload.len() {
        return PeerDictionaryCompressionSupport::default();
    }

    PeerDictionaryCompressionSupport {
        adaptive_advertisement: flags & DICTIONARY_COMPRESSION_ADAPTIVE_ADVERTISEMENT_FLAG != 0,
        configured_fingerprint,
    }
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
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, duplex};

    use super::super::metrics::MetricsTuning;
    use super::super::native_stats::{KcpRuntimeSample, NativeLossSample, NativeLossSampler};

    struct KcpRuntimeTestSampler {
        no_progress_closes: u64,
        rtt: Option<Duration>,
    }

    impl NativeLossSampler for KcpRuntimeTestSampler {
        fn sample(&mut self) -> Option<NativeLossSample> {
            None
        }

        fn sample_rtt(&mut self) -> Option<Duration> {
            self.rtt.take()
        }

        fn kcp_runtime_sample(&mut self) -> Option<KcpRuntimeSample> {
            Some(KcpRuntimeSample::with_no_progress_closes(
                self.no_progress_closes,
            ))
        }
    }

    struct FlushCountingDuplex {
        inner: DuplexStream,
        flushes: Arc<AtomicUsize>,
    }

    impl FlushCountingDuplex {
        fn new(inner: DuplexStream, flushes: Arc<AtomicUsize>) -> Self {
            Self { inner, flushes }
        }
    }

    impl AsyncRead for FlushCountingDuplex {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for FlushCountingDuplex {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flushes.fetch_add(1, Ordering::Relaxed);
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    fn test_peer() -> Arc<PeerState> {
        PeerState::new(
            2,
            Duration::from_millis(250),
            Duration::from_secs(5),
            MetricsTuning::default(),
            1024 * 1024,
        )
    }

    fn test_stream_cfg() -> StreamPumpConfig {
        StreamPumpConfig::new(
            1,
            2,
            TransportKind::Tcp,
            4096,
            0,
            Duration::from_secs(30),
            Duration::from_secs(30),
            Duration::from_secs(30),
            Duration::from_secs(1),
            CompressionConfig::default(),
            4,
        )
    }

    #[tokio::test]
    async fn encoded_stream_writes_feed_in_order_with_one_flush() {
        let (client, server) = duplex(4096);
        let flushes = Arc::new(AtomicUsize::new(0));
        let counting_client = FlushCountingDuplex::new(client, flushes.clone());
        let cfg = test_stream_cfg();
        let peer = test_peer();
        let mut writer = Framed::new(counting_client, stream_codec(cfg.max_frame_bytes));
        let mut reader = Framed::new(server, stream_codec(cfg.max_frame_bytes));
        let writes = [
            PreparedStreamWrite {
                encoded: Bytes::from_static(b"first"),
                #[cfg(debug_assertions)]
                frame_type: pb::FrameType::FrameData as i32,
                class: MessageClass::HighPriority,
                expires_at: None,
            },
            PreparedStreamWrite {
                encoded: Bytes::from_static(b"second"),
                #[cfg(debug_assertions)]
                frame_type: pb::FrameType::FrameData as i32,
                class: MessageClass::HighPriority,
                expires_at: None,
            },
        ];

        send_encoded_stream_writes(&mut writer, &cfg, &peer, &writes)
            .await
            .unwrap();

        let first = timeout(Duration::from_secs(1), reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let second = timeout(Duration::from_secs(1), reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(first.freeze(), Bytes::from_static(b"first"));
        assert_eq!(second.freeze(), Bytes::from_static(b"second"));
        assert_eq!(flushes.load(Ordering::Relaxed), 1);
    }

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

    #[cfg(debug_assertions)]
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
    fn dictionary_capability_requires_compression_enabled() {
        let adaptive = CompressionConfig::default().with_adaptive_dictionary_enabled(true);
        assert!(dictionary_compression_supported(&adaptive));

        let disabled = adaptive.with_enabled(false);
        assert!(!dictionary_compression_supported(&disabled));
        assert!(dictionary_compression_hello_payload(&disabled).is_empty());
    }

    #[test]
    fn dictionary_hello_advertises_adaptive_and_configured_support_separately() {
        let cfg = CompressionConfig::default()
            .with_adaptive_dictionary_enabled(true)
            .with_dictionary_bytes(
                b"configured s2s transport zstd dictionary bytes for tests".to_vec(),
            )
            .unwrap();

        let support = parse_dictionary_compression_hello_payload(
            dictionary_compression_hello_payload(&cfg).as_ref(),
        );

        assert!(support.adaptive_advertisement);
        assert_eq!(
            support.configured_fingerprint,
            cfg.configured_dictionary_fingerprint()
        );
    }

    #[test]
    fn legacy_dictionary_hello_marker_is_ignored_as_ambiguous() {
        let support =
            parse_dictionary_compression_hello_payload(DICTIONARY_COMPRESSION_HELLO_CAPABILITY);

        assert!(!support.adaptive_advertisement);
        assert!(support.configured_fingerprint.is_none());
    }

    #[test]
    fn legacy_adaptive_hello_flag_is_not_treated_as_advertisement_support() {
        let mut payload = DICTIONARY_COMPRESSION_HELLO_CAPABILITY.to_vec();
        payload.push(DICTIONARY_COMPRESSION_LEGACY_ADAPTIVE_FLAG);

        let support = parse_dictionary_compression_hello_payload(&payload);

        assert!(!support.adaptive_advertisement);
        assert!(support.configured_fingerprint.is_none());
    }

    #[test]
    fn configured_dictionary_requires_peer_fingerprint_match() {
        let cfg = CompressionConfig::default()
            .with_dictionary_bytes(
                b"configured s2s transport zstd dictionary bytes for tests".to_vec(),
            )
            .unwrap();
        let local_adaptive_dictionaries =
            AdaptiveDictionaryStore::new(MAX_ADAPTIVE_DICTIONARIES_PER_STREAM);
        let adaptive_only_peer = PeerDictionaryCompressionSupport {
            adaptive_advertisement: true,
            configured_fingerprint: None,
        };

        assert!(
            outbound_compression_dictionary(
                &cfg,
                &local_adaptive_dictionaries,
                None,
                adaptive_only_peer
            )
            .is_none()
        );

        let matching_peer = PeerDictionaryCompressionSupport {
            adaptive_advertisement: true,
            configured_fingerprint: cfg.configured_dictionary_fingerprint(),
        };
        assert_eq!(
            outbound_compression_dictionary(
                &cfg,
                &local_adaptive_dictionaries,
                None,
                matching_peer
            )
            .map(CompressionDictionary::wire_id),
            cfg.dictionary_wire_id()
        );
    }

    #[test]
    fn cached_adaptive_dictionary_is_ready_for_startup_advertisement() {
        let dictionary = Arc::new(
            CompressionDictionary::new(
                b"cached adaptive s2s transport zstd dictionary bytes for startup".to_vec(),
                CompressionConfig::default().level(),
                CompressionDictionaryKind::Adaptive,
            )
            .unwrap(),
        );
        let dictionary_id = dictionary.wire_id();
        let mut local_adaptive_dictionaries =
            AdaptiveDictionaryStore::new(MAX_ADAPTIVE_DICTIONARIES_PER_STREAM);
        local_adaptive_dictionaries.insert(dictionary);
        let peer_support = PeerDictionaryCompressionSupport {
            adaptive_advertisement: true,
            configured_fingerprint: None,
        };

        assert_eq!(
            next_adaptive_dictionary_to_advertise(
                &local_adaptive_dictionaries,
                peer_support,
                None,
                None
            )
            .map(CompressionDictionary::wire_id),
            Some(dictionary_id)
        );
        assert!(
            next_adaptive_dictionary_to_advertise(
                &local_adaptive_dictionaries,
                PeerDictionaryCompressionSupport::default(),
                None,
                None
            )
            .is_none()
        );
        assert!(
            next_adaptive_dictionary_to_advertise(
                &local_adaptive_dictionaries,
                peer_support,
                Some(dictionary_id),
                None
            )
            .is_none()
        );
        assert!(
            next_adaptive_dictionary_to_advertise(
                &local_adaptive_dictionaries,
                peer_support,
                None,
                Some(dictionary_id)
            )
            .is_none()
        );
    }

    #[test]
    fn adaptive_dictionary_ack_must_match_pending_local_dictionary() {
        let dictionary = Arc::new(
            CompressionDictionary::new(
                b"adaptive s2s transport zstd dictionary bytes for ack tests".to_vec(),
                CompressionConfig::default().level(),
                CompressionDictionaryKind::Adaptive,
            )
            .unwrap(),
        );
        let dictionary_id = dictionary.wire_id();
        let unrelated_id = if dictionary_id == u64::MAX {
            1
        } else {
            dictionary_id + 1
        };
        let mut local_adaptive_dictionaries =
            AdaptiveDictionaryStore::new(MAX_ADAPTIVE_DICTIONARIES_PER_STREAM);
        local_adaptive_dictionaries.insert(dictionary);
        let mut active_adaptive_dictionary_id = None;
        let mut pending_adaptive_dictionary_id = None;

        assert!(!acknowledge_adaptive_dictionary(
            dictionary_id,
            &local_adaptive_dictionaries,
            &mut active_adaptive_dictionary_id,
            &mut pending_adaptive_dictionary_id,
        ));
        assert_eq!(active_adaptive_dictionary_id, None);

        pending_adaptive_dictionary_id = Some(unrelated_id);
        assert!(!acknowledge_adaptive_dictionary(
            dictionary_id,
            &local_adaptive_dictionaries,
            &mut active_adaptive_dictionary_id,
            &mut pending_adaptive_dictionary_id,
        ));
        assert_eq!(active_adaptive_dictionary_id, None);
        assert_eq!(pending_adaptive_dictionary_id, Some(unrelated_id));

        pending_adaptive_dictionary_id = Some(dictionary_id);
        assert!(acknowledge_adaptive_dictionary(
            dictionary_id,
            &local_adaptive_dictionaries,
            &mut active_adaptive_dictionary_id,
            &mut pending_adaptive_dictionary_id,
        ));
        assert_eq!(active_adaptive_dictionary_id, Some(dictionary_id));
        assert_eq!(pending_adaptive_dictionary_id, None);

        assert!(!acknowledge_adaptive_dictionary(
            dictionary_id,
            &local_adaptive_dictionaries,
            &mut active_adaptive_dictionary_id,
            &mut pending_adaptive_dictionary_id,
        ));
    }

    #[test]
    fn expiring_keepalive_counts_as_liveness_loss() {
        let mut pending = PendingPings::new(4);
        assert!(pending.insert(1).is_none());
        assert!(pending.insert(2).is_none());

        assert_eq!(pending.expire_older_than(Duration::ZERO), 2);
    }

    #[test]
    fn evicted_pending_keepalive_is_returned_for_loss_accounting() {
        let mut pending = PendingPings::new(1);
        assert!(pending.insert(1).is_none());

        assert!(pending.insert(2).is_some());
    }

    #[test]
    fn matched_pong_rtt_uses_monotonic_pending_instant() {
        let mut pending = PendingPings::new(4);
        pending.insert(u64::MAX);
        std::thread::sleep(Duration::from_millis(1));

        let pong = pending.take(u64::MAX).expect("pending ping");
        let rtt = pong.sent_at.elapsed();

        assert!(rtt >= Duration::from_millis(1));
    }

    #[test]
    fn unmatched_pong_does_not_consume_pending_ping() {
        let mut pending = PendingPings::new(4);
        pending.insert(1);

        assert!(pending.take(2).is_none());
        assert!(pending.take(1).is_some());
    }

    #[test]
    fn native_no_progress_close_requires_fresh_kcp_ack_progress() {
        let peer = test_peer();
        let mut sampler: BoxedNativeLossSampler = Box::new(KcpRuntimeTestSampler {
            no_progress_closes: 1,
            rtt: None,
        });

        assert!(sample_native_transport_metrics(
            &mut sampler,
            TransportKind::Kcp,
            &peer
        ));
        assert!(
            !peer.kcp_best_effort_recovery_pending(),
            "a cumulative runtime counter must not re-arm recovery every periodic tick"
        );

        sample_final_native_transport_metrics(&mut sampler, TransportKind::Kcp, &peer);
        assert!(peer.kcp_best_effort_recovery_pending());

        let mut replacement_close: BoxedNativeLossSampler = Box::new(KcpRuntimeTestSampler {
            no_progress_closes: 1,
            rtt: Some(Duration::from_millis(20)),
        });
        sample_final_native_transport_metrics(&mut replacement_close, TransportKind::Kcp, &peer);
        assert!(
            peer.kcp_best_effort_recovery_pending(),
            "final ACK progress must clear the old gate before the close installs a new baseline"
        );

        peer.record_native_transport_rtt(TransportKind::Kcp, Duration::from_millis(20));
        assert!(!peer.kcp_best_effort_recovery_pending());

        let mut ordinary_close: BoxedNativeLossSampler = Box::new(KcpRuntimeTestSampler {
            no_progress_closes: 0,
            rtt: None,
        });
        sample_final_native_transport_metrics(&mut ordinary_close, TransportKind::Kcp, &peer);
        assert!(!peer.kcp_best_effort_recovery_pending());
    }
}
