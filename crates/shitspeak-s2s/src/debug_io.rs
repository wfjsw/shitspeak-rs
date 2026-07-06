//! High-level S2S packet IO counters.
//!
//! These counters intentionally live above L1 transport framing. They count the
//! encoded `OverlayMessage` bytes handed to transport send/receive paths so the
//! status page can attribute traffic to overlay, replication, and application
//! packet kinds. Nested payload classification only peeks protobuf envelope
//! field keys so release builds avoid extra full-message decodes on the hot
//! path.

use std::collections::BTreeMap;
use std::sync::LazyLock;
use std::time::Instant;

use bytes::{Buf, Bytes};
use parking_lot::Mutex;
use serde::Serialize;

use shitspeak_core::NodeIdentifier;

use crate::application::proto as app_proto;
use crate::overlay::proto::{OverlayBody, OverlayControlBody, OverlayData};
use crate::replications::proto as repl_proto;

static COUNTERS: LazyLock<Mutex<PacketCounters>> =
    LazyLock::new(|| Mutex::new(PacketCounters::new()));

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketKind {
    name: String,
}

impl PacketKind {
    fn from_static(name: &'static str) -> Self {
        Self {
            name: name.to_owned(),
        }
    }

    fn from_string(name: String) -> Self {
        Self { name }
    }

    fn into_name(self) -> String {
        self.name
    }
}

#[derive(Default)]
struct DirectionCounters {
    bytes: u64,
    count: u64,
}

impl DirectionCounters {
    fn record(&mut self, bytes: usize) {
        // Prometheus counters can handle wraps as resets; saturating here would
        // pin a maxed counter forever.
        self.bytes = self.bytes.wrapping_add(bytes as u64);
        self.count = self.count.wrapping_add(1);
    }
}

#[derive(Default)]
struct PacketCounter {
    sent: DirectionCounters,
    recv: DirectionCounters,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PacketKey {
    source: NodeIdentifier,
    destination: NodeIdentifier,
    kind: String,
}

impl PacketKey {
    fn new(source: NodeIdentifier, destination: NodeIdentifier, kind: PacketKind) -> Self {
        Self {
            source,
            destination,
            kind: kind.into_name(),
        }
    }
}

struct PacketCounters {
    started_at: Instant,
    by_packet: BTreeMap<PacketKey, PacketCounter>,
}

impl PacketCounters {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            by_packet: BTreeMap::new(),
        }
    }

    fn record_sent(
        &mut self,
        source: NodeIdentifier,
        destination: NodeIdentifier,
        kind: PacketKind,
        bytes: usize,
    ) {
        self.by_packet
            .entry(PacketKey::new(source, destination, kind))
            .or_default()
            .sent
            .record(bytes);
    }

    fn record_received(
        &mut self,
        source: NodeIdentifier,
        destination: NodeIdentifier,
        kind: PacketKind,
        bytes: usize,
    ) {
        self.by_packet
            .entry(PacketKey::new(source, destination, kind))
            .or_default()
            .recv
            .record(bytes);
    }

    fn snapshot(&self) -> Vec<PacketIoSnapshot> {
        let elapsed_secs = self.started_at.elapsed().as_secs_f64().max(0.001);
        let mut out = self
            .by_packet
            .iter()
            .map(|(key, counter)| PacketIoSnapshot::new(key, counter, elapsed_secs))
            .collect::<Vec<_>>();
        out.sort_by(|a, b| {
            b.total_bytes
                .cmp(&a.total_bytes)
                .then_with(|| a.source.cmp(&b.source))
                .then_with(|| a.destination.cmp(&b.destination))
                .then_with(|| a.kind.cmp(&b.kind))
        });
        out
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PacketIoSnapshot {
    source: NodeIdentifier,
    destination: NodeIdentifier,
    kind: String,
    sent_bytes: u64,
    recv_bytes: u64,
    total_bytes: u64,
    sent_count: u64,
    recv_count: u64,
    total_count: u64,
    avg_sent_bps: f64,
    avg_recv_bps: f64,
    avg_total_bps: f64,
}

impl PacketIoSnapshot {
    fn new(key: &PacketKey, counter: &PacketCounter, elapsed_secs: f64) -> Self {
        let sent_bytes = counter.sent.bytes;
        let recv_bytes = counter.recv.bytes;
        let total_bytes = sent_bytes.saturating_add(recv_bytes);
        let sent_count = counter.sent.count;
        let recv_count = counter.recv.count;
        let total_count = sent_count.saturating_add(recv_count);
        Self {
            source: key.source,
            destination: key.destination,
            kind: key.kind.clone(),
            sent_bytes,
            recv_bytes,
            total_bytes,
            sent_count,
            recv_count,
            total_count,
            avg_sent_bps: sent_bytes as f64 / elapsed_secs,
            avg_recv_bps: recv_bytes as f64 / elapsed_secs,
            avg_total_bps: total_bytes as f64 / elapsed_secs,
        }
    }

    #[cfg(test)]
    fn kind(&self) -> &str {
        &self.kind
    }

    #[cfg(test)]
    fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

pub fn classify_overlay_body(body: &OverlayBody) -> PacketKind {
    match body {
        OverlayBody::Hello(_) => PacketKind::from_static("overlay.hello"),
        OverlayBody::HelloAck(_) => PacketKind::from_static("overlay.hello_ack"),
        OverlayBody::LsaFlood(_) => PacketKind::from_static("overlay.lsa_flood"),
        OverlayBody::LsdbSync(_) => PacketKind::from_static("overlay.lsdb_sync_req"),
        OverlayBody::LsdbSyncResp(_) => PacketKind::from_static("overlay.lsdb_sync_resp"),
        OverlayBody::Control(control) => match &control.body {
            Some(OverlayControlBody::Ack(_)) => PacketKind::from_static("overlay.control.ack"),
            Some(OverlayControlBody::RepairRequest(_)) => {
                PacketKind::from_static("overlay.control.repair_request")
            }
            Some(OverlayControlBody::RepairResponse(_)) => {
                PacketKind::from_static("overlay.control.repair_response")
            }
            None => PacketKind::from_static("overlay.control.empty"),
        },
        OverlayBody::Data(data) => classify_overlay_data(data),
    }
}

pub fn record_sent(
    source: NodeIdentifier,
    destination: NodeIdentifier,
    kind: PacketKind,
    bytes: usize,
) {
    COUNTERS
        .lock()
        .record_sent(source, destination, kind, bytes);
}

pub fn record_received(
    source: NodeIdentifier,
    destination: NodeIdentifier,
    kind: PacketKind,
    bytes: usize,
) {
    COUNTERS
        .lock()
        .record_received(source, destination, kind, bytes);
}

pub fn record_named_sent(
    source: NodeIdentifier,
    destination: NodeIdentifier,
    kind: &'static str,
    bytes: usize,
) {
    record_sent(source, destination, PacketKind::from_static(kind), bytes);
}

pub fn record_named_received(
    source: NodeIdentifier,
    destination: NodeIdentifier,
    kind: &'static str,
    bytes: usize,
) {
    record_received(source, destination, PacketKind::from_static(kind), bytes);
}

pub fn snapshot() -> Vec<PacketIoSnapshot> {
    COUNTERS.lock().snapshot()
}

fn classify_overlay_data(data: &OverlayData) -> PacketKind {
    match data.service_tag {
        repl_proto::REPLICATION_SERVICE_TAG => classify_replication_payload(&data.payload),
        app_proto::MODERATION_SERVICE_TAG => classify_moderation_payload(&data.payload),
        app_proto::VOICE_SERVICE_TAG => classify_voice_payload(&data.payload),
        app_proto::USER_STATS_SERVICE_TAG => classify_user_stats_payload(&data.payload),
        app_proto::PLUGIN_DATA_SERVICE_TAG => classify_plugin_data_payload(&data.payload),
        app_proto::TEXT_MESSAGE_SERVICE_TAG => classify_text_message_payload(&data.payload),
        tag => PacketKind::from_string(format!("overlay.data.tag.{tag}")),
    }
}

fn classify_replication_payload(payload: &Bytes) -> PacketKind {
    match first_length_delimited_field(payload, &[2, 3, 4]) {
        Ok(Some((2, nested))) => classify_nested_oneof(
            nested,
            &[
                (1, "replication.strict.propose"),
                (2, "replication.strict.propose_ack"),
                (3, "replication.strict.commit"),
                (4, "replication.strict.clock_tick"),
                (5, "replication.strict.catchup_req"),
                (6, "replication.strict.catchup_resp"),
                (7, "replication.strict.recovery_req"),
                (8, "replication.strict.recovery_ack"),
                (9, "replication.strict.recovery_commit"),
            ],
            "replication.strict.empty",
            "replication.strict.unknown",
            "replication.decode_error",
        ),
        Ok(Some((3, nested))) => classify_nested_oneof(
            nested,
            &[
                (1, "replication.owner.op"),
                (2, "replication.owner.catchup_req"),
                (3, "replication.owner.catchup_resp"),
            ],
            "replication.owner.empty",
            "replication.owner.unknown",
            "replication.decode_error",
        ),
        Ok(Some((4, nested))) => classify_nested_oneof(
            nested,
            &[
                (1, "replication.blob.find"),
                (2, "replication.blob.offer"),
                (3, "replication.blob.chunk_req"),
                (4, "replication.blob.chunk"),
            ],
            "replication.blob.empty",
            "replication.blob.unknown",
            "replication.decode_error",
        ),
        Ok(Some((_, _))) => PacketKind::from_static("replication.unknown"),
        Ok(None) => PacketKind::from_static("replication.empty"),
        Err(()) => PacketKind::from_static("replication.decode_error"),
    }
}

fn classify_moderation_payload(payload: &Bytes) -> PacketKind {
    classify_oneof(
        payload,
        &[
            (4, "application.moderation.user_state"),
            (5, "application.moderation.user_remove"),
        ],
        "application.moderation.empty",
        "application.moderation.unknown",
        "application.moderation.decode_error",
    )
}

fn classify_voice_payload(_payload: &Bytes) -> PacketKind {
    PacketKind::from_static("application.voice.frame")
}

fn classify_user_stats_payload(payload: &Bytes) -> PacketKind {
    classify_oneof(
        payload,
        &[
            (1, "application.user_stats.request"),
            (2, "application.user_stats.reply"),
        ],
        "application.user_stats.empty",
        "application.user_stats.unknown",
        "application.user_stats.decode_error",
    )
}

fn classify_plugin_data_payload(_payload: &Bytes) -> PacketKind {
    PacketKind::from_static("application.plugin_data.envelope")
}

fn classify_text_message_payload(_payload: &Bytes) -> PacketKind {
    PacketKind::from_static("application.text_message.envelope")
}

fn classify_oneof(
    payload: &[u8],
    tags: &[(u32, &'static str)],
    empty: &'static str,
    unknown: &'static str,
    decode_error: &'static str,
) -> PacketKind {
    match first_matching_field(payload, tags) {
        Ok(Some(tag)) => tags
            .iter()
            .find_map(|(candidate, name)| (*candidate == tag).then_some(*name))
            .map(PacketKind::from_static)
            .unwrap_or_else(|| PacketKind::from_static(unknown)),
        Ok(None) => PacketKind::from_static(empty),
        Err(()) => PacketKind::from_static(decode_error),
    }
}

fn classify_nested_oneof(
    payload: &[u8],
    tags: &[(u32, &'static str)],
    empty: &'static str,
    unknown: &'static str,
    decode_error: &'static str,
) -> PacketKind {
    classify_oneof(payload, tags, empty, unknown, decode_error)
}

fn first_matching_field(
    mut payload: &[u8],
    wanted: &[(u32, &'static str)],
) -> Result<Option<u32>, ()> {
    while payload.has_remaining() {
        let key = read_varint(&mut payload)?;
        let field = (key >> 3) as u32;
        let wire_type = (key & 0x07) as u8;
        if wanted
            .iter()
            .any(|(wanted_field, _)| *wanted_field == field)
        {
            return Ok(Some(field));
        }
        skip_field(&mut payload, wire_type)?;
    }
    Ok(None)
}

fn first_length_delimited_field<'a>(
    mut payload: &'a [u8],
    wanted: &[u32],
) -> Result<Option<(u32, &'a [u8])>, ()> {
    while payload.has_remaining() {
        let key = read_varint(&mut payload)?;
        let field = (key >> 3) as u32;
        let wire_type = (key & 0x07) as u8;
        if wire_type == 2 {
            let len = read_varint(&mut payload)? as usize;
            if payload.remaining() < len {
                return Err(());
            }
            let (nested, rest) = payload.split_at(len);
            if wanted.contains(&field) {
                return Ok(Some((field, nested)));
            }
            payload = rest;
        } else {
            if wanted.contains(&field) {
                return Err(());
            }
            skip_field(&mut payload, wire_type)?;
        }
    }
    Ok(None)
}

fn read_varint(payload: &mut &[u8]) -> Result<u64, ()> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        if !payload.has_remaining() {
            return Err(());
        }
        let byte = payload.get_u8();
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(())
}

fn skip_field(payload: &mut &[u8], wire_type: u8) -> Result<(), ()> {
    match wire_type {
        0 => {
            read_varint(payload)?;
            Ok(())
        }
        1 => skip_bytes(payload, 8),
        2 => {
            let len = read_varint(payload)? as usize;
            skip_bytes(payload, len)
        }
        5 => skip_bytes(payload, 4),
        _ => Err(()),
    }
}

fn skip_bytes(payload: &mut &[u8], len: usize) -> Result<(), ()> {
    if payload.remaining() < len {
        return Err(());
    }
    payload.advance(len);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::overlay::proto::{OverlayData, level_to_wire, node_to_wire};
    use crate::replications::proto::{StrictBody, StrictClockTick, wrap_strict};
    use shitspeak_s2s_transport::{MessageClass, ServiceLevel};

    fn overlay_data(tag: u32, payload: Bytes) -> OverlayData {
        OverlayData {
            src: node_to_wire(1),
            dsts: vec![node_to_wire(2)],
            path_trace: vec![node_to_wire(1)],
            service_tag: tag,
            service_level: level_to_wire(ServiceLevel::Reliable),
            message_class: crate::overlay::proto::class_to_wire(MessageClass::Regular),
            payload,
            process_on_transit: false,
            route_metric: 0,
            ordered_delivery: false,
            ordering_seq: 0,
            ordering_dst: 0,
            lane_id: None,
            origin_boot_epoch: 0,
            origin_message_id: 0,
            allow_l1_compression: false,
        }
    }

    #[test]
    fn classifies_nested_replication_packets() {
        let repl = wrap_strict(
            "channels",
            StrictBody::ClockTick(StrictClockTick {
                src_node: 1,
                src_clock: 9,
            }),
        );
        let payload = repl_proto::encode(&repl).unwrap();
        let body = OverlayBody::Data(overlay_data(repl_proto::REPLICATION_SERVICE_TAG, payload));

        let kind = classify_overlay_body(&body);

        assert_eq!(kind.into_name(), "replication.strict.clock_tick");
    }

    #[test]
    fn snapshots_sort_by_total_bytes() {
        let mut counters = PacketCounters::new();
        counters.record_sent(1, 2, PacketKind::from_static("small"), 10);
        counters.record_received(3, 1, PacketKind::from_static("large"), 20);
        counters.record_received(3, 1, PacketKind::from_static("large"), 30);

        let snapshot = counters.snapshot();

        assert_eq!(snapshot[0].kind(), "large");
        assert_eq!(snapshot[0].total_bytes(), 50);
        assert_eq!(snapshot[1].kind(), "small");
        assert_eq!(snapshot[1].total_bytes(), 10);
    }
}
