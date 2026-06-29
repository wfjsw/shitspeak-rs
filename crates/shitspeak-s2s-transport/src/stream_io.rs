//! Generic framed read/write pump shared by every stream transport.
//!
//! A "stream" here is anything that satisfies `AsyncRead + AsyncWrite + Send +
//! Unpin` — TCP+TLS, KCP+TLS, or a QUIC bidirectional stream. The pump:
//!
//!   * frames every outbound `Bytes` payload as a `pb::Frame` with the
//!     local `NodeIdentifier` as `src_node`, then encodes with prost +
//!     length-prefix via `LengthDelimitedCodec`;
//!   * decodes incoming length-prefixed frames, dispatches `Data` to the
//!     appropriate inbound mpsc, generates `Pong` for `Ping`, and updates RTT
//!     + jitter metrics for `Pong`;
//!   * periodically issues a small keepalive Ping every `ping_interval` for
//!     latency / jitter and liveness;
//!   * exits on EOF, write error, or `closed` cancellation.

use std::collections::{HashMap, VecDeque};
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
    AdaptiveCompressionState, CompressionConfig, CompressionDictionary, CompressionDictionaryKind,
    DICTIONARY_FINGERPRINT_BYTES, maybe_compress_frame_payload_with_dictionary,
    train_adaptive_dictionary, validate_and_decode_payload_with_dictionary,
};
use super::connection::{ActiveStream, OutboundFrame, PeerState};
use super::frame::{FrameType, build_frame, stream_codec};
use super::manager::InboundDispatch;
use super::native_stats::BoxedNativeLossSampler;
use super::service_level::{MessageClass, ServiceLevel, TransportKind};

const DICTIONARY_COMPRESSION_HELLO_CAPABILITY: &[u8] = b"shitspeak-s2s-l1-zstd-dict-v1";
#[cfg(test)]
const DICTIONARY_COMPRESSION_LEGACY_ADAPTIVE_FLAG: u8 = 0x01;
const DICTIONARY_COMPRESSION_CONFIGURED_FLAG: u8 = 0x02;
const DICTIONARY_COMPRESSION_ADAPTIVE_ADVERTISEMENT_FLAG: u8 = 0x04;
const MAX_ADAPTIVE_DICTIONARIES_PER_STREAM: usize = 4;

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
    outbound_capacity: usize,
    ping_interval: Duration,
    idle_ping_interval: Duration,
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

    let hello = build_frame(
        cfg.local_node,
        cfg.peer_node,
        level_for_metrics,
        FrameType::Hello,
        MessageClass::Regular,
        now_us(),
        dictionary_compression_hello_payload(&cfg.compression),
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
        maybe_start_adaptive_training(
            &mut outbound_compression,
            peer_dictionary_support,
            active_adaptive_dictionary_id,
            pending_adaptive_dictionary_id,
            &mut training_in_flight,
            &training_tx,
        );

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
                let dictionary = outbound_compression_dictionary(
                    outbound_compression.config(),
                    &local_adaptive_dictionaries,
                    active_adaptive_dictionary_id,
                    peer_dictionary_support,
                );
                if let Err(e) = maybe_compress_frame_payload_with_dictionary(
                    &mut frame,
                    out.options(),
                    outbound_compression.config(),
                    dictionary,
                    cfg.max_frame_bytes,
                ) {
                    warn!(peer=%peer.node_id(), transport=?cfg.transport, error=%e, "stream payload compression failed");
                    break;
                }
                let encoded_payload_len = frame.payload.len();
                match encode_and_send(&mut framed, &frame, cfg.transport, &peer).await {
                    Ok(()) => {
                        peer
                            .metrics()
                            .record_payload_sent(cfg.transport, original_payload_len);
                        peer.metrics().record_l1_compression_sent(
                            cfg.transport,
                            original_payload_len,
                            encoded_payload_len,
                        );
                        outbound_compression.record_sample(out.payload());
                    }
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
    encode_and_send(framed, &frame, cfg.transport, peer).await?;
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
    encode_and_send(framed, &ack, cfg.transport, peer).await?;
    trace!(peer=%cfg.peer_node, transport=?cfg.transport, dictionary_id, "accepted adaptive dictionary");
    Ok(())
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
    crate::debug_io::record_named_sent(stream_frame_kind_name(transport, frame.frame_type), len);
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
    level: ServiceLevel,
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
        validate_and_decode_payload_with_dictionary(
            &mut frame,
            cfg.max_frame_bytes,
            inbound_compression.config(),
            dictionary,
        )?;
    }
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
                if pending.take(frame.ts_us).is_some() {
                    peer.metrics().record_probe_delivered(cfg.transport);
                    transport_link_stable = true;
                }
            }
        }
        pb::FrameType::FrameHello => {
            *peer_dictionary_support =
                parse_dictionary_compression_hello_payload(frame.payload.as_ref());
            trace!(peer=%cfg.peer_node, transport=?cfg.transport, "received transport hello");
        }
        pb::FrameType::FrameDictionary => {
            handle_dictionary_advertisement(frame, cfg, peer, framed, peer_adaptive_dictionaries)
                .await?;
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
    fn dictionary_capability_requires_compression_enabled() {
        assert!(dictionary_compression_supported(
            &CompressionConfig::default()
        ));

        let disabled = CompressionConfig::default().with_enabled(false);
        assert!(!dictionary_compression_supported(&disabled));
        assert!(dictionary_compression_hello_payload(&disabled).is_empty());
    }

    #[test]
    fn dictionary_hello_advertises_adaptive_and_configured_support_separately() {
        let cfg = CompressionConfig::default()
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
}
