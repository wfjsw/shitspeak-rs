use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use aws_lc_rs::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
use bytes::Bytes;
use parking_lot::RwLock;
use tokio::io::AsyncWriteExt;
use zstd::dict::{DecoderDictionary, EncoderDictionary};

use crate::s2s_transport_proto as pb;

const DEFAULT_COMPRESSION_MIN_BYTES: usize = 1024;
const DEFAULT_COMPRESSION_MIN_SAVINGS_PERCENT: u8 = 10;
const DEFAULT_COMPRESSION_LEVEL: i32 = 1;
const DEFAULT_COMPRESSION_ADAPTIVE_DICTIONARY_ENABLED: bool = true;
const MIN_ZSTD_DICTIONARY_BYTES: usize = 8;
const ADAPTIVE_MIN_SAMPLES: usize = 16;
const ADAPTIVE_RETRAIN_SAMPLES: usize = 16;
const ADAPTIVE_MIN_BYTES: usize = 32 * 1024;
const ADAPTIVE_MAX_SAMPLES: usize = 128;
const ADAPTIVE_MAX_BYTES: usize = 256 * 1024;
const ADAPTIVE_MAX_DICTIONARY_BYTES: usize = 16 * 1024;
const ADAPTIVE_MIN_SAMPLE_BYTES: usize = 64;
const ADAPTIVE_MAX_SAMPLE_BYTES: usize = 64 * 1024;
const ADAPTIVE_DICTIONARY_CACHE_SUBDIR: &str = "transport";
const ADAPTIVE_DICTIONARY_CACHE_FILE: &str = "adaptive-compression.zdict";
pub(crate) const DICTIONARY_FINGERPRINT_BYTES: usize = 20;
const DICTIONARY_WIRE_ID_BYTES: usize = 8;
static ADAPTIVE_DICTIONARY_CACHE_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Per-send transport options. Defaults are intentionally raw so only
/// non-latency-sensitive callers opt in to L1 compression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendOptions {
    allow_l1_compression: bool,
}

impl SendOptions {
    pub fn allow_l1_compression(mut self) -> Self {
        self.allow_l1_compression = true;
        self
    }

    pub fn l1_compression_allowed(&self) -> bool {
        self.allow_l1_compression
    }
}

impl Default for SendOptions {
    fn default() -> Self {
        Self {
            allow_l1_compression: false,
        }
    }
}

#[derive(Clone)]
pub(crate) struct CompressionConfig {
    enabled: bool,
    min_bytes: usize,
    min_savings_percent: u8,
    level: i32,
    adaptive_dictionary_enabled: bool,
    dictionary: Option<Arc<CompressionDictionary>>,
    adaptive_dictionary_cache: Option<Arc<AdaptiveDictionaryCache>>,
}

impl fmt::Debug for CompressionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompressionConfig")
            .field("enabled", &self.enabled)
            .field("min_bytes", &self.min_bytes)
            .field("min_savings_percent", &self.min_savings_percent)
            .field("level", &self.level)
            .field(
                "adaptive_dictionary_enabled",
                &self.adaptive_dictionary_enabled,
            )
            .field("dictionary", &self.dictionary)
            .field(
                "adaptive_dictionary_cache_path",
                &self.adaptive_dictionary_cache_path(),
            )
            .field(
                "cached_adaptive_dictionary",
                &self.cached_adaptive_dictionary(),
            )
            .finish()
    }
}

impl PartialEq for CompressionConfig {
    fn eq(&self, other: &Self) -> bool {
        self.enabled == other.enabled
            && self.min_bytes == other.min_bytes
            && self.min_savings_percent == other.min_savings_percent
            && self.level == other.level
            && self.adaptive_dictionary_enabled == other.adaptive_dictionary_enabled
            && self.dictionary.as_deref() == other.dictionary.as_deref()
            && self.adaptive_dictionary_cache_path() == other.adaptive_dictionary_cache_path()
            && self.cached_adaptive_dictionary_wire_id()
                == other.cached_adaptive_dictionary_wire_id()
    }
}

impl Eq for CompressionConfig {}

pub(crate) struct CompressionDictionary {
    bytes: Bytes,
    encoder: EncoderDictionary<'static>,
    decoder: DecoderDictionary<'static>,
    id: Option<u32>,
    wire_id: u64,
    fingerprint: [u8; DICTIONARY_FINGERPRINT_BYTES],
    kind: CompressionDictionaryKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompressionDictionaryKind {
    Configured,
    Adaptive,
}

impl CompressionDictionary {
    pub(crate) fn new(
        bytes: Vec<u8>,
        level: i32,
        kind: CompressionDictionaryKind,
    ) -> io::Result<Self> {
        if bytes.len() < MIN_ZSTD_DICTIONARY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("zstd dictionary must be at least {MIN_ZSTD_DICTIONARY_BYTES} bytes"),
            ));
        }

        let bytes = Bytes::from(bytes);
        let mut fingerprint = [0; DICTIONARY_FINGERPRINT_BYTES];
        fingerprint.copy_from_slice(digest(&SHA1_FOR_LEGACY_USE_ONLY, bytes.as_ref()).as_ref());
        let wire_id = dictionary_wire_id(&fingerprint);
        let encoder = EncoderDictionary::copy(bytes.as_ref(), level);
        let decoder = DecoderDictionary::copy(bytes.as_ref());
        let id = encoder.as_cdict().get_dict_id().map(|id| id.get());
        Ok(Self {
            bytes,
            encoder,
            decoder,
            id,
            wire_id,
            fingerprint,
            kind,
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.bytes.len()
    }

    fn id(&self) -> Option<u32> {
        self.id
    }

    pub(crate) fn wire_id(&self) -> u64 {
        self.wire_id
    }

    pub(crate) fn bytes(&self) -> Bytes {
        self.bytes.clone()
    }

    pub(crate) fn fingerprint(&self) -> [u8; DICTIONARY_FINGERPRINT_BYTES] {
        self.fingerprint
    }

    pub(crate) fn kind(&self) -> CompressionDictionaryKind {
        self.kind
    }

    fn encoder(&self) -> &EncoderDictionary<'static> {
        &self.encoder
    }

    fn decoder(&self) -> &DecoderDictionary<'static> {
        &self.decoder
    }
}

impl fmt::Debug for CompressionDictionary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompressionDictionary")
            .field("len", &self.len())
            .field("id", &self.id())
            .field("wire_id", &self.wire_id())
            .field("kind", &self.kind())
            .finish()
    }
}

impl PartialEq for CompressionDictionary {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes && self.id == other.id && self.kind == other.kind
    }
}

impl Eq for CompressionDictionary {}

fn dictionary_wire_id(fingerprint: &[u8; DICTIONARY_FINGERPRINT_BYTES]) -> u64 {
    let mut bytes = [0; DICTIONARY_WIRE_ID_BYTES];
    bytes.copy_from_slice(&fingerprint[..DICTIONARY_WIRE_ID_BYTES]);
    let id = u64::from_be_bytes(bytes);
    if id == 0 { 1 } else { id }
}

pub(crate) fn adaptive_dictionary_cache_file(persistence_dir: &Path) -> PathBuf {
    persistence_dir
        .join(ADAPTIVE_DICTIONARY_CACHE_SUBDIR)
        .join(ADAPTIVE_DICTIONARY_CACHE_FILE)
}

pub(crate) struct AdaptiveDictionaryCache {
    path: PathBuf,
    latest: RwLock<Option<Arc<CompressionDictionary>>>,
}

impl AdaptiveDictionaryCache {
    fn open(path: PathBuf, level: i32) -> Arc<Self> {
        let latest = load_cached_adaptive_dictionary(&path, level);
        Arc::new(Self {
            path,
            latest: RwLock::new(latest),
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn latest(&self) -> Option<Arc<CompressionDictionary>> {
        self.latest.read().clone()
    }

    fn rebuild_for_level(&self, level: i32) {
        let Some(dictionary) = self.latest() else {
            return;
        };

        match CompressionDictionary::new(
            dictionary.bytes.to_vec(),
            level,
            CompressionDictionaryKind::Adaptive,
        ) {
            Ok(rebuilt) => {
                *self.latest.write() = Some(Arc::new(rebuilt));
            }
            Err(error) => {
                tracing::warn!(
                    path = %self.path.display(),
                    error = %error,
                    "ignoring cached adaptive compression dictionary after level change"
                );
                *self.latest.write() = None;
            }
        }
    }

    async fn store(&self, dictionary: Arc<CompressionDictionary>) -> io::Result<()> {
        if dictionary.kind() != CompressionDictionaryKind::Adaptive {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "only adaptive compression dictionaries can be cached",
            ));
        }

        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let tmp_path = self.tmp_path();
        let result = async {
            {
                let mut file = tokio::fs::OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(&tmp_path)
                    .await?;
                file.write_all(dictionary.bytes.as_ref()).await?;
                file.sync_data().await?;
            }
            tokio::fs::rename(&tmp_path, &self.path).await
        }
        .await;

        if let Err(error) = result {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(error);
        }

        *self.latest.write() = Some(dictionary);
        Ok(())
    }

    fn tmp_path(&self) -> PathBuf {
        let seq = ADAPTIVE_DICTIONARY_CACHE_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let file_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(ADAPTIVE_DICTIONARY_CACHE_FILE);
        self.path
            .with_file_name(format!("{file_name}.{}.{}.tmp", std::process::id(), seq))
    }
}

impl fmt::Debug for AdaptiveDictionaryCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdaptiveDictionaryCache")
            .field("path", &self.path)
            .field("latest", &self.latest())
            .finish()
    }
}

fn load_cached_adaptive_dictionary(path: &Path, level: i32) -> Option<Arc<CompressionDictionary>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return None,
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                error = %error,
                "ignoring unreadable adaptive compression dictionary cache"
            );
            return None;
        }
    };

    match CompressionDictionary::new(bytes, level, CompressionDictionaryKind::Adaptive) {
        Ok(dictionary) => Some(Arc::new(dictionary)),
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                error = %error,
                "ignoring invalid adaptive compression dictionary cache"
            );
            None
        }
    }
}

impl CompressionConfig {
    pub(crate) fn new(
        enabled: bool,
        min_bytes: usize,
        min_savings_percent: u8,
        level: i32,
    ) -> Self {
        Self {
            enabled,
            min_bytes,
            min_savings_percent: min_savings_percent.min(100),
            level,
            adaptive_dictionary_enabled: DEFAULT_COMPRESSION_ADAPTIVE_DICTIONARY_ENABLED,
            dictionary: None,
            adaptive_dictionary_cache: None,
        }
    }

    pub(crate) fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub(crate) fn with_min_bytes(mut self, min_bytes: usize) -> Self {
        self.min_bytes = min_bytes;
        self
    }

    pub(crate) fn with_min_savings_percent(mut self, min_savings_percent: u8) -> Self {
        self.min_savings_percent = min_savings_percent.min(100);
        self
    }

    pub(crate) fn with_level(mut self, level: i32) -> Self {
        if self.level != level {
            self.dictionary = self
                .dictionary
                .as_ref()
                .map(|dict| {
                    CompressionDictionary::new(dict.bytes.to_vec(), level, dict.kind())
                        .expect("existing compression dictionary remains valid")
                })
                .map(Arc::new);
            if let Some(cache) = &self.adaptive_dictionary_cache {
                cache.rebuild_for_level(level);
            }
            self.level = level;
        }
        self
    }

    pub(crate) fn with_adaptive_dictionary_enabled(mut self, enabled: bool) -> Self {
        self.adaptive_dictionary_enabled = enabled;
        self
    }

    pub(crate) fn with_dictionary_bytes(mut self, dictionary: Vec<u8>) -> io::Result<Self> {
        self.dictionary = Some(Arc::new(CompressionDictionary::new(
            dictionary,
            self.level,
            CompressionDictionaryKind::Configured,
        )?));
        Ok(self)
    }

    pub(crate) fn without_dictionary(mut self) -> Self {
        self.dictionary = None;
        self
    }

    pub(crate) fn with_adaptive_dictionary_cache_file(mut self, path: PathBuf) -> Self {
        self.adaptive_dictionary_cache = Some(AdaptiveDictionaryCache::open(path, self.level));
        self
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn min_bytes(&self) -> usize {
        self.min_bytes
    }

    pub(crate) fn min_savings_percent(&self) -> u8 {
        self.min_savings_percent
    }

    pub(crate) fn level(&self) -> i32 {
        self.level
    }

    pub(crate) fn adaptive_dictionary_enabled(&self) -> bool {
        self.adaptive_dictionary_enabled
    }

    pub(crate) fn dictionary_len(&self) -> Option<usize> {
        self.dictionary.as_ref().map(|dict| dict.len())
    }

    pub(crate) fn dictionary_id(&self) -> Option<u32> {
        self.dictionary.as_ref().and_then(|dict| dict.id())
    }

    pub(crate) fn dictionary_wire_id(&self) -> Option<u64> {
        self.dictionary.as_ref().map(|dict| dict.wire_id())
    }

    pub(crate) fn configured_dictionary_fingerprint(
        &self,
    ) -> Option<[u8; DICTIONARY_FINGERPRINT_BYTES]> {
        self.dictionary.as_ref().and_then(|dict| {
            (dict.kind() == CompressionDictionaryKind::Configured).then(|| dict.fingerprint())
        })
    }

    pub(crate) fn dictionary(&self) -> Option<&CompressionDictionary> {
        self.dictionary.as_deref()
    }

    pub(crate) fn cached_adaptive_dictionary(&self) -> Option<Arc<CompressionDictionary>> {
        if !self.enabled || !self.adaptive_dictionary_enabled {
            return None;
        }
        self.adaptive_dictionary_cache
            .as_ref()
            .and_then(|cache| cache.latest())
    }

    pub(crate) async fn cache_adaptive_dictionary(
        &self,
        dictionary: Arc<CompressionDictionary>,
    ) -> io::Result<()> {
        if !self.enabled || !self.adaptive_dictionary_enabled {
            return Ok(());
        }
        let Some(cache) = &self.adaptive_dictionary_cache else {
            return Ok(());
        };
        cache.store(dictionary).await
    }

    fn adaptive_dictionary_cache_path(&self) -> Option<&Path> {
        self.adaptive_dictionary_cache
            .as_ref()
            .map(|cache| cache.path())
    }

    fn cached_adaptive_dictionary_wire_id(&self) -> Option<u64> {
        self.cached_adaptive_dictionary()
            .as_ref()
            .map(|dict| dict.wire_id())
    }
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self::new(
            true,
            DEFAULT_COMPRESSION_MIN_BYTES,
            DEFAULT_COMPRESSION_MIN_SAVINGS_PERCENT,
            DEFAULT_COMPRESSION_LEVEL,
        )
    }
}

pub(crate) struct AdaptiveCompressionState {
    config: CompressionConfig,
    samples: VecDeque<Bytes>,
    sample_bytes: usize,
    samples_since_train: usize,
}

pub(crate) struct AdaptiveTrainingSnapshot {
    samples: Vec<Bytes>,
    level: i32,
}

impl AdaptiveCompressionState {
    pub(crate) fn new(config: CompressionConfig) -> Self {
        Self {
            config,
            samples: VecDeque::new(),
            sample_bytes: 0,
            samples_since_train: 0,
        }
    }

    pub(crate) fn config(&self) -> &CompressionConfig {
        &self.config
    }

    pub(crate) fn record_sample(&mut self, payload: &Bytes) {
        if !self.config.enabled()
            || !self.config.adaptive_dictionary_enabled()
            || payload.len() < ADAPTIVE_MIN_SAMPLE_BYTES
        {
            return;
        }

        let sample_len = payload.len().min(ADAPTIVE_MAX_SAMPLE_BYTES);
        let sample = Bytes::copy_from_slice(&payload[..sample_len]);
        self.sample_bytes = self.sample_bytes.saturating_add(sample.len());
        self.samples_since_train = self.samples_since_train.saturating_add(1);
        self.samples.push_back(sample);
        self.trim_samples();
    }

    pub(crate) fn training_snapshot_if_ready(&mut self) -> Option<AdaptiveTrainingSnapshot> {
        if self.samples.len() < ADAPTIVE_MIN_SAMPLES
            || self.sample_bytes < ADAPTIVE_MIN_BYTES
            || self.samples_since_train < ADAPTIVE_RETRAIN_SAMPLES
        {
            return None;
        }

        self.samples_since_train = 0;
        Some(AdaptiveTrainingSnapshot {
            samples: self.samples.iter().cloned().collect(),
            level: self.config.level(),
        })
    }

    fn trim_samples(&mut self) {
        while self.samples.len() > ADAPTIVE_MAX_SAMPLES || self.sample_bytes > ADAPTIVE_MAX_BYTES {
            if let Some(sample) = self.samples.pop_front() {
                self.sample_bytes = self.sample_bytes.saturating_sub(sample.len());
            } else {
                break;
            }
        }
    }
}

pub(crate) fn train_adaptive_dictionary(
    snapshot: AdaptiveTrainingSnapshot,
) -> io::Result<Arc<CompressionDictionary>> {
    let samples: Vec<&Bytes> = snapshot.samples.iter().collect();
    let dictionary = zstd::dict::from_samples(&samples, ADAPTIVE_MAX_DICTIONARY_BYTES)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    CompressionDictionary::new(
        dictionary,
        snapshot.level,
        CompressionDictionaryKind::Adaptive,
    )
    .map(Arc::new)
}

pub(crate) fn default_compression_enabled() -> bool {
    CompressionConfig::default().enabled()
}

pub(crate) fn default_compression_min_bytes() -> usize {
    CompressionConfig::default().min_bytes()
}

pub(crate) fn default_compression_min_savings_percent() -> u8 {
    CompressionConfig::default().min_savings_percent()
}

pub(crate) fn default_compression_level() -> i32 {
    CompressionConfig::default().level()
}

pub(crate) fn default_compression_adaptive_dictionary_enabled() -> bool {
    CompressionConfig::default().adaptive_dictionary_enabled()
}

pub(crate) fn maybe_compress_frame_payload(
    frame: &mut pb::Frame,
    options: SendOptions,
    cfg: &CompressionConfig,
    max_frame_bytes: usize,
) -> io::Result<()> {
    maybe_compress_frame_payload_with_dictionary(
        frame,
        options,
        cfg,
        cfg.dictionary(),
        max_frame_bytes,
    )
}

pub(crate) fn maybe_compress_frame_payload_with_dictionary(
    frame: &mut pb::Frame,
    options: SendOptions,
    cfg: &CompressionConfig,
    dictionary: Option<&CompressionDictionary>,
    max_frame_bytes: usize,
) -> io::Result<()> {
    frame.payload_encoding = pb::PayloadEncoding::Identity as i32;
    frame.uncompressed_payload_len = 0;
    frame.payload_dictionary_id = 0;

    if !cfg.enabled() || !options.l1_compression_allowed() {
        return Ok(());
    }
    if pb::FrameType::try_from(frame.frame_type) != Ok(pb::FrameType::FrameData) {
        return Ok(());
    }

    let original_len = frame.payload.len();
    if original_len == 0 || original_len < cfg.min_bytes() {
        return Ok(());
    }
    if original_len > max_frame_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "payload exceeds frame cap before compression",
        ));
    }

    let compressed = encode_zstd(frame.payload.as_ref(), cfg, dictionary)?;
    if !meets_savings_threshold(original_len, compressed.len(), cfg.min_savings_percent()) {
        return Ok(());
    }

    frame.payload = Bytes::from(compressed);
    frame.payload_encoding = if let Some(dictionary) = dictionary {
        frame.payload_dictionary_id = dictionary.wire_id();
        pb::PayloadEncoding::ZstdDict as i32
    } else {
        pb::PayloadEncoding::Zstd as i32
    };
    frame.uncompressed_payload_len = original_len as u64;
    Ok(())
}

pub(crate) fn validate_and_decode_payload(
    frame: &mut pb::Frame,
    max_frame_bytes: usize,
    cfg: &CompressionConfig,
) -> io::Result<()> {
    validate_and_decode_payload_with_dictionary(frame, max_frame_bytes, cfg, cfg.dictionary())
}

pub(crate) fn validate_and_decode_payload_with_dictionary(
    frame: &mut pb::Frame,
    max_frame_bytes: usize,
    _cfg: &CompressionConfig,
    dictionary: Option<&CompressionDictionary>,
) -> io::Result<()> {
    let encoding = pb::PayloadEncoding::try_from(frame.payload_encoding).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown payload encoding {}", frame.payload_encoding),
        )
    })?;
    let is_data = pb::FrameType::try_from(frame.frame_type) == Ok(pb::FrameType::FrameData);

    match encoding {
        pb::PayloadEncoding::Identity => {
            if frame.uncompressed_payload_len != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "identity payload carried uncompressed length",
                ));
            }
            Ok(())
        }
        pb::PayloadEncoding::Zstd | pb::PayloadEncoding::ZstdDict => {
            if !is_data {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "compressed payload on non-data frame",
                ));
            }
            let declared_len = usize::try_from(frame.uncompressed_payload_len).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "compressed payload length too large for platform",
                )
            })?;
            if declared_len == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "compressed payload missing uncompressed length",
                ));
            }
            if declared_len > max_frame_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "compressed payload exceeds frame cap",
                ));
            }

            let dictionary = match encoding {
                pb::PayloadEncoding::Zstd => None,
                pb::PayloadEncoding::ZstdDict => {
                    let dictionary = dictionary.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "dictionary-compressed payload received without compression dictionary",
                        )
                    })?;
                    if frame.payload_dictionary_id != 0
                        && frame.payload_dictionary_id != dictionary.wire_id()
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "dictionary-compressed payload dictionary id mismatch",
                        ));
                    }
                    Some(dictionary)
                }
                pb::PayloadEncoding::Identity => unreachable!(),
            };
            let decoded = decode_zstd_bounded(
                frame.payload.as_ref(),
                declared_len,
                max_frame_bytes,
                dictionary,
            )?;
            frame.payload = Bytes::from(decoded);
            frame.payload_encoding = pb::PayloadEncoding::Identity as i32;
            frame.uncompressed_payload_len = 0;
            frame.payload_dictionary_id = 0;
            Ok(())
        }
    }
}

fn encode_zstd(
    payload: &[u8],
    cfg: &CompressionConfig,
    dictionary: Option<&CompressionDictionary>,
) -> io::Result<Vec<u8>> {
    let mut compressor = if let Some(dictionary) = dictionary {
        zstd::bulk::Compressor::with_prepared_dictionary(dictionary.encoder())
    } else {
        zstd::bulk::Compressor::new(cfg.level())
    }
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    compressor
        .compress(payload)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn meets_savings_threshold(
    original_len: usize,
    compressed_len: usize,
    min_savings_percent: u8,
) -> bool {
    if compressed_len >= original_len {
        return false;
    }
    let required_percent = 100u128.saturating_sub(min_savings_percent.min(100) as u128);
    (compressed_len as u128) * 100 <= (original_len as u128) * required_percent
}

fn decode_zstd_bounded(
    payload: &[u8],
    declared_len: usize,
    max_frame_bytes: usize,
    dictionary: Option<&CompressionDictionary>,
) -> io::Result<Vec<u8>> {
    let capacity = max_frame_bytes.saturating_add(1);
    let mut decompressor = if let Some(dictionary) = dictionary {
        zstd::bulk::Decompressor::with_prepared_dictionary(dictionary.decoder())
    } else {
        zstd::bulk::Decompressor::new()
    }
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let out = decompressor
        .decompress(payload, capacity)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if out.len() > max_frame_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "decompressed payload exceeds frame cap",
        ));
    }
    if out.len() != declared_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "decompressed payload length mismatch",
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{FrameType, build_frame};
    use crate::{MessageClass, ServiceLevel};
    use crate::s2s_overlay_proto as overlay_pb;
    use prost::Message as _;

    fn data_frame(payload: Bytes) -> pb::Frame {
        build_frame(
            1,
            2,
            ServiceLevel::Reliable,
            FrameType::Data,
            MessageClass::Regular,
            7,
            payload,
        )
    }

    fn compression_cfg() -> CompressionConfig {
        CompressionConfig::new(true, 1, 10, 1)
    }

    fn dictionary_cfg() -> CompressionConfig {
        CompressionConfig::new(true, 1, 0, 1)
            .with_dictionary_bytes(
                b"OverlayData ReplicationMessage StrictCatchupResp OwnerCatchupResp LsaFlood \
                  LinkStateAdvert PluginDataEnvelope channel clients blobs session user state"
                    .to_vec(),
            )
            .unwrap()
    }

    fn adaptive_cfg() -> CompressionConfig {
        CompressionConfig::new(true, 1, 0, 1).with_adaptive_dictionary_enabled(true)
    }

    fn adaptive_sample(i: usize) -> Bytes {
        Bytes::from(
            format!(
                "OverlayData ReplicationMessage StrictCatchupResp channel clients session user \
                 state version={i:04} "
            )
            .repeat(24),
        )
    }

    #[tokio::test]
    async fn adaptive_dictionary_cache_persists_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = adaptive_dictionary_cache_file(dir.path());
        let dictionary = Arc::new(
            CompressionDictionary::new(
                b"adaptive s2s transport zstd dictionary cache bytes for restart".to_vec(),
                1,
                CompressionDictionaryKind::Adaptive,
            )
            .unwrap(),
        );
        let dictionary_id = dictionary.wire_id();

        let cache = AdaptiveDictionaryCache::open(path.clone(), 1);
        assert!(cache.latest().is_none());
        cache.store(dictionary.clone()).await.unwrap();

        let reloaded = AdaptiveDictionaryCache::open(path, 3);
        let cached = reloaded.latest().expect("cached adaptive dictionary");
        assert_eq!(cached.bytes(), dictionary.bytes());
        assert_eq!(cached.wire_id(), dictionary_id);
        assert_eq!(cached.kind(), CompressionDictionaryKind::Adaptive);
    }

    #[test]
    fn l1_compression_round_trips() {
        let original = Bytes::from(vec![0x42; 4096]);
        let mut frame = data_frame(original.clone());
        let cfg = compression_cfg();

        maybe_compress_frame_payload(
            &mut frame,
            SendOptions::default().allow_l1_compression(),
            &cfg,
            8192,
        )
        .unwrap();

        assert_eq!(
            pb::PayloadEncoding::try_from(frame.payload_encoding).unwrap(),
            pb::PayloadEncoding::Zstd
        );
        assert!(frame.payload.len() < original.len());
        assert_eq!(frame.uncompressed_payload_len, original.len() as u64);

        validate_and_decode_payload(&mut frame, 8192, &cfg).unwrap();
        assert_eq!(frame.payload, original);
        assert_eq!(
            pb::PayloadEncoding::try_from(frame.payload_encoding).unwrap(),
            pb::PayloadEncoding::Identity
        );
        assert_eq!(frame.uncompressed_payload_len, 0);
    }

    #[test]
    fn l1_dictionary_compression_round_trips() {
        let original = Bytes::from(
            b"OverlayData ReplicationMessage StrictCatchupResp channel clients session user state "
                .repeat(64),
        );
        let mut frame = data_frame(original.clone());
        let cfg = dictionary_cfg();

        maybe_compress_frame_payload(
            &mut frame,
            SendOptions::default().allow_l1_compression(),
            &cfg,
            8192,
        )
        .unwrap();

        assert_eq!(
            pb::PayloadEncoding::try_from(frame.payload_encoding).unwrap(),
            pb::PayloadEncoding::ZstdDict
        );
        assert!(frame.payload.len() < original.len());
        assert_eq!(frame.uncompressed_payload_len, original.len() as u64);

        validate_and_decode_payload(&mut frame, 8192, &cfg).unwrap();
        assert_eq!(frame.payload, original);
        assert_eq!(
            pb::PayloadEncoding::try_from(frame.payload_encoding).unwrap(),
            pb::PayloadEncoding::Identity
        );
    }

    #[test]
    fn dictionary_payload_requires_dictionary_config() {
        let original = Bytes::from(
            b"OverlayData ReplicationMessage StrictCatchupResp channel clients session user state "
                .repeat(64),
        );
        let cfg = dictionary_cfg();
        let mut frame = data_frame(original);

        maybe_compress_frame_payload(
            &mut frame,
            SendOptions::default().allow_l1_compression(),
            &cfg,
            8192,
        )
        .unwrap();

        assert_eq!(
            pb::PayloadEncoding::try_from(frame.payload_encoding).unwrap(),
            pb::PayloadEncoding::ZstdDict
        );
        assert!(validate_and_decode_payload(&mut frame, 8192, &compression_cfg()).is_err());
    }

    #[test]
    fn adaptive_dictionary_trains_from_snapshot_and_round_trips_by_id() {
        let mut sender = AdaptiveCompressionState::new(adaptive_cfg());
        for i in 0..ADAPTIVE_MIN_SAMPLES {
            let sample = adaptive_sample(i);
            sender.record_sample(&sample);
        }

        let dictionary = train_adaptive_dictionary(
            sender
                .training_snapshot_if_ready()
                .expect("adaptive training snapshot is ready"),
        )
        .expect("adaptive dictionary trains");

        let original = adaptive_sample(ADAPTIVE_MIN_SAMPLES + 1);
        let mut frame = data_frame(original.clone());
        maybe_compress_frame_payload_with_dictionary(
            &mut frame,
            SendOptions::default().allow_l1_compression(),
            sender.config(),
            Some(dictionary.as_ref()),
            8192,
        )
        .unwrap();

        assert_eq!(
            pb::PayloadEncoding::try_from(frame.payload_encoding).unwrap(),
            pb::PayloadEncoding::ZstdDict
        );
        assert_eq!(frame.payload_dictionary_id, dictionary.wire_id());

        validate_and_decode_payload_with_dictionary(
            &mut frame,
            8192,
            sender.config(),
            Some(dictionary.as_ref()),
        )
        .unwrap();
        assert_eq!(frame.payload, original);
        assert_eq!(frame.payload_dictionary_id, 0);
    }

    #[test]
    fn adaptive_dictionary_does_not_train_when_compression_disabled() {
        let cfg = adaptive_cfg().with_enabled(false);
        let mut state = AdaptiveCompressionState::new(cfg);
        for i in 0..ADAPTIVE_MIN_SAMPLES * 2 {
            state.record_sample(&adaptive_sample(i));
        }

        assert!(state.training_snapshot_if_ready().is_none());
    }

    #[test]
    fn below_size_threshold_stays_identity() {
        let mut frame = data_frame(Bytes::from_static(b"small"));
        maybe_compress_frame_payload(
            &mut frame,
            SendOptions::default().allow_l1_compression(),
            &CompressionConfig::new(true, 1024, 10, 1),
            1024,
        )
        .unwrap();

        assert_eq!(
            pb::PayloadEncoding::try_from(frame.payload_encoding).unwrap(),
            pb::PayloadEncoding::Identity
        );
        assert_eq!(frame.payload, Bytes::from_static(b"small"));
    }

    #[test]
    fn low_savings_stays_identity() {
        let mut frame = data_frame(Bytes::from(vec![0x42; 4096]));
        maybe_compress_frame_payload(
            &mut frame,
            SendOptions::default().allow_l1_compression(),
            &CompressionConfig::new(true, 1, 100, 1),
            8192,
        )
        .unwrap();

        assert_eq!(
            pb::PayloadEncoding::try_from(frame.payload_encoding).unwrap(),
            pb::PayloadEncoding::Identity
        );
    }

    #[test]
    fn malformed_zstd_is_rejected() {
        let mut frame = data_frame(Bytes::from_static(b"not a zstd stream"));
        frame.payload_encoding = pb::PayloadEncoding::Zstd as i32;
        frame.uncompressed_payload_len = 16;

        assert!(validate_and_decode_payload(&mut frame, 1024, &compression_cfg()).is_err());
    }

    #[test]
    fn unknown_encoding_is_rejected() {
        let mut frame = data_frame(Bytes::from_static(b"hello"));
        frame.payload_encoding = 99;

        assert!(validate_and_decode_payload(&mut frame, 1024, &compression_cfg()).is_err());
    }

    #[test]
    fn decompressed_size_cap_is_enforced_before_decode() {
        let mut frame = data_frame(Bytes::from_static(b"ignored"));
        frame.payload_encoding = pb::PayloadEncoding::Zstd as i32;
        frame.uncompressed_payload_len = 2048;

        assert!(validate_and_decode_payload(&mut frame, 1024, &compression_cfg()).is_err());
    }

    #[test]
    fn compressed_non_data_frame_is_rejected() {
        let mut frame = build_frame(
            1,
            2,
            ServiceLevel::Reliable,
            FrameType::Ping,
            MessageClass::Regular,
            7,
            Bytes::from_static(b"ping"),
        );
        frame.payload_encoding = pb::PayloadEncoding::Zstd as i32;
        frame.uncompressed_payload_len = 4;

        assert!(validate_and_decode_payload(&mut frame, 1024, &compression_cfg()).is_err());
    }

    #[test]
    fn lsa_flood_payload_compresses() {
        let flood = overlay_pb::LsaFlood {
            advertisements: (0..64)
                .map(|i| overlay_pb::LinkStateAdvert {
                    origin: i,
                    boot_epoch: 1,
                    seq: i as u64,
                    ts_emit_us: 2,
                    tombstone: false,
                    addresses: vec![overlay_pb::AddressEntry {
                        addr: "10.0.0.1:64739".to_string(),
                        transport: 0,
                    }],
                    links: (0..8)
                        .map(|neighbor| overlay_pb::LinkAdvert {
                            neighbor,
                            rtt_us: 10_000,
                            jitter_us: 100,
                            throughput_bps: 1_000_000,
                            observed_recv_bps: 1_000_000,
                            observed_sent_bps: 1_000_000,
                            throughput_confidence_ppm: 1_000_000,
                            transports_mask: 0b1111,
                            loss_ppm: 10,
                            probe_loss_ppm: 10,
                            native_loss_ppm: 10,
                            data_health_ppm: 10,
                            loss_sample_count: 100,
                        })
                        .collect(),
                    max_users: 100,
                    transit_disabled: false,
                    strict_replication_disabled: false,
                    content_replication_disabled: false,
                    owner_replication_disabled: false,
                })
                .collect(),
        };
        let msg = overlay_pb::OverlayMessage {
            body: Some(overlay_pb::overlay_message::Body::LsaFlood(flood)),
        };
        let mut encoded = Vec::with_capacity(msg.encoded_len());
        msg.encode(&mut encoded).unwrap();
        assert!(encoded.len() > 1024);

        let mut frame = data_frame(Bytes::from(encoded.clone()));
        let cfg = CompressionConfig::default();
        maybe_compress_frame_payload(
            &mut frame,
            SendOptions::default().allow_l1_compression(),
            &cfg,
            encoded.len() + 512,
        )
        .unwrap();

        assert_eq!(
            pb::PayloadEncoding::try_from(frame.payload_encoding).unwrap(),
            pb::PayloadEncoding::Zstd
        );
        validate_and_decode_payload(&mut frame, encoded.len() + 512, &cfg).unwrap();
        assert_eq!(frame.payload, Bytes::from(encoded));
    }
}
