use std::io::{self, Cursor, Read};

use bytes::Bytes;

use crate::s2s_transport_proto as pb;

const DEFAULT_COMPRESSION_MIN_BYTES: usize = 1024;
const DEFAULT_COMPRESSION_MIN_SAVINGS_PERCENT: u8 = 10;
const DEFAULT_COMPRESSION_LEVEL: i32 = 1;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CompressionConfig {
    enabled: bool,
    min_bytes: usize,
    min_savings_percent: u8,
    level: i32,
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
        }
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

pub(crate) fn maybe_compress_frame_payload(
    frame: &mut pb::Frame,
    options: SendOptions,
    cfg: CompressionConfig,
    max_frame_bytes: usize,
) -> io::Result<()> {
    frame.payload_encoding = pb::PayloadEncoding::Identity as i32;
    frame.uncompressed_payload_len = 0;

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

    let compressed = zstd::stream::encode_all(Cursor::new(frame.payload.as_ref()), cfg.level())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if !meets_savings_threshold(original_len, compressed.len(), cfg.min_savings_percent()) {
        return Ok(());
    }

    frame.payload = Bytes::from(compressed);
    frame.payload_encoding = pb::PayloadEncoding::Zstd as i32;
    frame.uncompressed_payload_len = original_len as u64;
    Ok(())
}

pub(crate) fn validate_and_decode_payload(
    frame: &mut pb::Frame,
    max_frame_bytes: usize,
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
        pb::PayloadEncoding::Zstd => {
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

            let decoded =
                decode_zstd_bounded(frame.payload.as_ref(), declared_len, max_frame_bytes)?;
            frame.payload = Bytes::from(decoded);
            frame.payload_encoding = pb::PayloadEncoding::Identity as i32;
            frame.uncompressed_payload_len = 0;
            Ok(())
        }
    }
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
) -> io::Result<Vec<u8>> {
    let decoder = zstd::stream::read::Decoder::new(Cursor::new(payload))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let limit = max_frame_bytes.saturating_add(1) as u64;
    let mut limited = decoder.take(limit);
    let mut out = Vec::with_capacity(declared_len);
    limited
        .read_to_end(&mut out)
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
    use crate::s2s::transport::frame::{FrameType, build_frame};
    use crate::s2s::transport::{MessageClass, ServiceLevel};
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

    #[test]
    fn l1_compression_round_trips() {
        let original = Bytes::from(vec![0x42; 4096]);
        let mut frame = data_frame(original.clone());

        maybe_compress_frame_payload(
            &mut frame,
            SendOptions::default().allow_l1_compression(),
            compression_cfg(),
            8192,
        )
        .unwrap();

        assert_eq!(
            pb::PayloadEncoding::try_from(frame.payload_encoding).unwrap(),
            pb::PayloadEncoding::Zstd
        );
        assert!(frame.payload.len() < original.len());
        assert_eq!(frame.uncompressed_payload_len, original.len() as u64);

        validate_and_decode_payload(&mut frame, 8192).unwrap();
        assert_eq!(frame.payload, original);
        assert_eq!(
            pb::PayloadEncoding::try_from(frame.payload_encoding).unwrap(),
            pb::PayloadEncoding::Identity
        );
        assert_eq!(frame.uncompressed_payload_len, 0);
    }

    #[test]
    fn below_size_threshold_stays_identity() {
        let mut frame = data_frame(Bytes::from_static(b"small"));
        maybe_compress_frame_payload(
            &mut frame,
            SendOptions::default().allow_l1_compression(),
            CompressionConfig::new(true, 1024, 10, 1),
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
            CompressionConfig::new(true, 1, 100, 1),
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

        assert!(validate_and_decode_payload(&mut frame, 1024).is_err());
    }

    #[test]
    fn unknown_encoding_is_rejected() {
        let mut frame = data_frame(Bytes::from_static(b"hello"));
        frame.payload_encoding = 99;

        assert!(validate_and_decode_payload(&mut frame, 1024).is_err());
    }

    #[test]
    fn decompressed_size_cap_is_enforced_before_decode() {
        let mut frame = data_frame(Bytes::from_static(b"ignored"));
        frame.payload_encoding = pb::PayloadEncoding::Zstd as i32;
        frame.uncompressed_payload_len = 2048;

        assert!(validate_and_decode_payload(&mut frame, 1024).is_err());
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

        assert!(validate_and_decode_payload(&mut frame, 1024).is_err());
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
        maybe_compress_frame_payload(
            &mut frame,
            SendOptions::default().allow_l1_compression(),
            CompressionConfig::default(),
            encoded.len() + 512,
        )
        .unwrap();

        assert_eq!(
            pb::PayloadEncoding::try_from(frame.payload_encoding).unwrap(),
            pb::PayloadEncoding::Zstd
        );
        validate_and_decode_payload(&mut frame, encoded.len() + 512).unwrap();
        assert_eq!(frame.payload, Bytes::from(encoded));
    }
}
