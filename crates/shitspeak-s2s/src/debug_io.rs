//! Debug-only high-level S2S packet IO counters.
//!
//! These counters intentionally live above L1 transport framing. They count the
//! encoded `OverlayMessage` bytes handed to transport send/receive paths so the
//! debug page can attribute traffic to overlay, replication, and application
//! packet kinds.

use std::collections::BTreeMap;
use std::sync::LazyLock;
use std::time::Instant;

use bytes::Bytes;
use parking_lot::Mutex;
use serde::Serialize;

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
        self.bytes = self.bytes.saturating_add(bytes as u64);
        self.count = self.count.saturating_add(1);
    }
}

#[derive(Default)]
struct PacketCounter {
    sent: DirectionCounters,
    recv: DirectionCounters,
}

struct PacketCounters {
    started_at: Instant,
    by_kind: BTreeMap<String, PacketCounter>,
}

impl PacketCounters {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            by_kind: BTreeMap::new(),
        }
    }

    fn record_sent(&mut self, kind: PacketKind, bytes: usize) {
        self.by_kind
            .entry(kind.into_name())
            .or_default()
            .sent
            .record(bytes);
    }

    fn record_received(&mut self, kind: PacketKind, bytes: usize) {
        self.by_kind
            .entry(kind.into_name())
            .or_default()
            .recv
            .record(bytes);
    }

    fn snapshot(&self) -> Vec<PacketIoSnapshot> {
        let elapsed_secs = self.started_at.elapsed().as_secs_f64().max(0.001);
        let mut out = self
            .by_kind
            .iter()
            .map(|(kind, counter)| PacketIoSnapshot::new(kind.clone(), counter, elapsed_secs))
            .collect::<Vec<_>>();
        out.sort_by(|a, b| {
            b.total_bytes
                .cmp(&a.total_bytes)
                .then_with(|| a.kind.cmp(&b.kind))
        });
        out
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PacketIoSnapshot {
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
    fn new(kind: String, counter: &PacketCounter, elapsed_secs: f64) -> Self {
        let sent_bytes = counter.sent.bytes;
        let recv_bytes = counter.recv.bytes;
        let total_bytes = sent_bytes.saturating_add(recv_bytes);
        let sent_count = counter.sent.count;
        let recv_count = counter.recv.count;
        let total_count = sent_count.saturating_add(recv_count);
        Self {
            kind,
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

pub fn record_sent(kind: PacketKind, bytes: usize) {
    COUNTERS.lock().record_sent(kind, bytes);
}

pub fn record_received(kind: PacketKind, bytes: usize) {
    COUNTERS.lock().record_received(kind, bytes);
}

pub fn record_named_sent(kind: &'static str, bytes: usize) {
    record_sent(PacketKind::from_static(kind), bytes);
}

pub fn record_named_received(kind: &'static str, bytes: usize) {
    record_received(PacketKind::from_static(kind), bytes);
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
        tag => PacketKind::from_string(format!("overlay.data.tag.{tag}")),
    }
}

fn classify_replication_payload(payload: &Bytes) -> PacketKind {
    let Ok(msg) = repl_proto::decode(payload) else {
        return PacketKind::from_static("replication.decode_error");
    };
    match msg.body {
        Some(repl_proto::ReplBody::Strict(strict)) => match strict.body {
            Some(repl_proto::StrictBody::Propose(_)) => {
                PacketKind::from_static("replication.strict.propose")
            }
            Some(repl_proto::StrictBody::ProposeAck(_)) => {
                PacketKind::from_static("replication.strict.propose_ack")
            }
            Some(repl_proto::StrictBody::Commit(_)) => {
                PacketKind::from_static("replication.strict.commit")
            }
            Some(repl_proto::StrictBody::ClockTick(_)) => {
                PacketKind::from_static("replication.strict.clock_tick")
            }
            Some(repl_proto::StrictBody::CatchupReq(_)) => {
                PacketKind::from_static("replication.strict.catchup_req")
            }
            Some(repl_proto::StrictBody::CatchupResp(_)) => {
                PacketKind::from_static("replication.strict.catchup_resp")
            }
            Some(repl_proto::StrictBody::RecoveryReq(_)) => {
                PacketKind::from_static("replication.strict.recovery_req")
            }
            Some(repl_proto::StrictBody::RecoveryAck(_)) => {
                PacketKind::from_static("replication.strict.recovery_ack")
            }
            Some(repl_proto::StrictBody::RecoveryCommit(_)) => {
                PacketKind::from_static("replication.strict.recovery_commit")
            }
            None => PacketKind::from_static("replication.strict.empty"),
        },
        Some(repl_proto::ReplBody::Owner(owner)) => match owner.body {
            Some(repl_proto::OwnerBody::Op(_)) => PacketKind::from_static("replication.owner.op"),
            Some(repl_proto::OwnerBody::CatchupReq(_)) => {
                PacketKind::from_static("replication.owner.catchup_req")
            }
            Some(repl_proto::OwnerBody::CatchupResp(_)) => {
                PacketKind::from_static("replication.owner.catchup_resp")
            }
            None => PacketKind::from_static("replication.owner.empty"),
        },
        Some(repl_proto::ReplBody::Blob(blob)) => match blob.body {
            Some(repl_proto::BlobBody::Find(_)) => PacketKind::from_static("replication.blob.find"),
            Some(repl_proto::BlobBody::Offer(_)) => {
                PacketKind::from_static("replication.blob.offer")
            }
            Some(repl_proto::BlobBody::ChunkReq(_)) => {
                PacketKind::from_static("replication.blob.chunk_req")
            }
            Some(repl_proto::BlobBody::Chunk(_)) => {
                PacketKind::from_static("replication.blob.chunk")
            }
            None => PacketKind::from_static("replication.blob.empty"),
        },
        None => PacketKind::from_static("replication.empty"),
    }
}

fn classify_moderation_payload(payload: &Bytes) -> PacketKind {
    let Ok(env) = app_proto::decode_moderation(payload) else {
        return PacketKind::from_static("application.moderation.decode_error");
    };
    match env.command {
        Some(app_proto::ModerationCommand::UserState(_)) => {
            PacketKind::from_static("application.moderation.user_state")
        }
        Some(app_proto::ModerationCommand::UserRemove(_)) => {
            PacketKind::from_static("application.moderation.user_remove")
        }
        None => PacketKind::from_static("application.moderation.empty"),
    }
}

fn classify_voice_payload(payload: &Bytes) -> PacketKind {
    match app_proto::decode_voice(payload) {
        Ok(_) => PacketKind::from_static("application.voice.frame"),
        Err(_) => PacketKind::from_static("application.voice.decode_error"),
    }
}

fn classify_user_stats_payload(payload: &Bytes) -> PacketKind {
    let Ok(env) = app_proto::decode_user_stats(payload) else {
        return PacketKind::from_static("application.user_stats.decode_error");
    };
    match env.kind {
        Some(app_proto::UserStatsKind::Request(_)) => {
            PacketKind::from_static("application.user_stats.request")
        }
        Some(app_proto::UserStatsKind::Reply(_)) => {
            PacketKind::from_static("application.user_stats.reply")
        }
        None => PacketKind::from_static("application.user_stats.empty"),
    }
}

fn classify_plugin_data_payload(payload: &Bytes) -> PacketKind {
    match app_proto::decode_plugin_data(payload) {
        Ok(_) => PacketKind::from_static("application.plugin_data.envelope"),
        Err(_) => PacketKind::from_static("application.plugin_data.decode_error"),
    }
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
        counters.record_sent(PacketKind::from_static("small"), 10);
        counters.record_received(PacketKind::from_static("large"), 20);
        counters.record_received(PacketKind::from_static("large"), 30);

        let snapshot = counters.snapshot();

        assert_eq!(snapshot[0].kind(), "large");
        assert_eq!(snapshot[0].total_bytes(), 50);
        assert_eq!(snapshot[1].kind(), "small");
        assert_eq!(snapshot[1].total_bytes(), 10);
    }
}
