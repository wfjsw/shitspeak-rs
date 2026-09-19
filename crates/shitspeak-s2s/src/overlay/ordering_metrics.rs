//! Ordered-lane and forwarding observability for the overlay.
//!
//! Covers the previously invisible failure paths of the ordered overlay:
//! end-to-end no-route drops (data and control), Reliable originate
//! physical-send failures (swallowed by the retain-until-ownership
//! contract), per-destination window-full rejections, NACK emission, and
//! silent inbound ordered drops (remote lane cap, gap beyond the reorder
//! buffer). Per-(dst, lane) pending-window gauges expose the
//! retain-until-ACK state that backs the end-to-end delivery contract.
//!
//! Destination and lane label values stay bounded: destinations by the
//! mesh's node count, lanes by the fixed protocol lanes
//! (owner/strict/bulk) plus test lanes.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

use shitspeak_core::NodeIdentifier;

use crate::overlay::OverlayError;
use crate::status::PrometheusSample;

/// Bounded kinds of end-to-end no-route drops. Both were previously
/// debug-log-only (power-of-two sampled) and never exported.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum NoRouteKind {
    Control,
    Data,
}

impl NoRouteKind {
    fn label(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Data => "data",
        }
    }
}

/// Bounded reasons an ordered overlay packet failed its first physical
/// forward at the originator. For Reliable sends these errors are
/// deliberately swallowed — the packet is already retained in
/// `ordering.pending` and will be retransmitted — so without this counter
/// a permanently unrouted destination is invisible at the sender.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReliableOriginateFailure {
    NoRoute,
    NoSuitableTransport,
    UnknownNode,
    Backpressure,
    Send,
}

impl ReliableOriginateFailure {
    const ALL: [Self; 5] = [
        Self::NoRoute,
        Self::NoSuitableTransport,
        Self::UnknownNode,
        Self::Backpressure,
        Self::Send,
    ];

    fn index(self) -> usize {
        match self {
            Self::NoRoute => 0,
            Self::NoSuitableTransport => 1,
            Self::UnknownNode => 2,
            Self::Backpressure => 3,
            Self::Send => 4,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::NoRoute => "no_route",
            Self::NoSuitableTransport => "no_suitable_transport",
            Self::UnknownNode => "unknown_node",
            Self::Backpressure => "backpressure",
            Self::Send => "send_error",
        }
    }

    pub(crate) fn from_error(error: &OverlayError) -> Self {
        match error {
            OverlayError::NoRoute { .. } => Self::NoRoute,
            OverlayError::Send(send) => match send {
                shitspeak_s2s_transport::SendError::Backpressure { .. } => Self::Backpressure,
                shitspeak_s2s_transport::SendError::NoSuitableTransport { .. } => {
                    Self::NoSuitableTransport
                }
                shitspeak_s2s_transport::SendError::UnknownNode { .. } => Self::UnknownNode,
                _ => Self::Send,
            },
            _ => Self::Send,
        }
    }
}

const RELIABLE_ORIGINATE_FAILURE_COUNT: usize = 5;

/// Bounded reasons an inbound ordered packet was dropped before entering
/// the reorder state. All were previously silent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum InboundDropReason {
    /// The frame's `ordering_dst` is not this node (accept guard).
    DstMismatch,
    /// The (src, boot_epoch, dst) remote-lane cap was exhausted.
    RemoteLaneCap,
    /// An established lane received a sequence further ahead than the
    /// reorder buffer; the frame is dropped without a NACK.
    GapBeyondReorder,
}

impl InboundDropReason {
    fn label(self) -> &'static str {
        match self {
            Self::DstMismatch => "dst_mismatch",
            Self::RemoteLaneCap => "remote_lane_cap",
            Self::GapBeyondReorder => "gap_beyond_reorder",
        }
    }
}

#[derive(Default)]
struct PendingGauges {
    packets: u64,
    oldest_age_ms: u64,
}

static NO_ROUTE_DROPS: LazyLock<Mutex<BTreeMap<(NoRouteKind, NodeIdentifier), u64>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
static RELIABLE_ORIGINATE_FAILURES: [AtomicU64; RELIABLE_ORIGINATE_FAILURE_COUNT] =
    [const { AtomicU64::new(0) }; RELIABLE_ORIGINATE_FAILURE_COUNT];
static ORDERED_WINDOW_FULL: LazyLock<Mutex<BTreeMap<u32, u64>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
static ORDERED_NACKS: LazyLock<Mutex<BTreeMap<u32, u64>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
static ORDERED_INBOUND_DROPS: LazyLock<Mutex<BTreeMap<(InboundDropReason, u32), u64>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
static ORDERED_PENDING: LazyLock<Mutex<BTreeMap<(NodeIdentifier, u32), PendingGauges>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
static ORDERED_PENDING_STARVE_EVENTS: LazyLock<Mutex<BTreeMap<u32, u64>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
static ORDERED_PENDING_STARVE_PURGED: LazyLock<Mutex<BTreeMap<u32, u64>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
static ORDERED_INBOUND_GAP_STUCK: LazyLock<Mutex<BTreeMap<u32, u64>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
static ORDERED_INBOUND_GAP_HEALED: LazyLock<Mutex<BTreeMap<u32, u64>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
static CONTROL_ROUTE_FALLBACKS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn record_no_route_drop(kind: NoRouteKind, dst: NodeIdentifier) {
    *NO_ROUTE_DROPS
        .lock()
        .unwrap()
        .entry((kind, dst))
        .or_insert(0) += 1;
}

pub(crate) fn record_reliable_originate_failure(reason: ReliableOriginateFailure) {
    RELIABLE_ORIGINATE_FAILURES[reason.index()].fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_window_full(lane: u32) {
    *ORDERED_WINDOW_FULL.lock().unwrap().entry(lane).or_insert(0) += 1;
}

pub(crate) fn record_nack(lane: u32) {
    *ORDERED_NACKS.lock().unwrap().entry(lane).or_insert(0) += 1;
}

pub(crate) fn record_inbound_drop(reason: InboundDropReason, lane: u32) {
    *ORDERED_INBOUND_DROPS
        .lock()
        .unwrap()
        .entry((reason, lane))
        .or_insert(0) += 1;
}

/// Snapshot of one (dst, lane) pending window as observed by a retransmit
/// pass. Called while the pending map is already locked; takes only the
/// metrics lock.
pub(crate) fn record_ordered_pending(dst: NodeIdentifier, lane: u32, packets: u64, oldest_age_ms: u64) {
    ORDERED_PENDING
        .lock()
        .unwrap()
        .insert((dst, lane), PendingGauges {
            packets,
            oldest_age_ms,
        });
}

/// Remove the (dst, lane) pending gauge once the window is fully released
/// (ACK, purge, or peer reset), so the exported gauge cannot go stale at a
/// last non-zero value.
pub(crate) fn remove_ordered_pending(dst: NodeIdentifier, lane: u32) {
    ORDERED_PENDING.lock().unwrap().remove(&(dst, lane));
}

/// Remove every pending gauge for `dst` (peer reset: all its lanes were
/// purged at once).
pub(crate) fn remove_ordered_pending_dst(dst: NodeIdentifier) {
    ORDERED_PENDING
        .lock()
        .unwrap()
        .retain(|(pending_dst, _), _| *pending_dst != dst);
}

/// A Reliable pending window entered starvation: the oldest retained
/// packet is older than `ordered_pending_starve_after` while the
/// retain-until-ACK contract still holds it.
pub(crate) fn record_pending_starve(lane: u32) {
    *ORDERED_PENDING_STARVE_EVENTS
        .lock()
        .unwrap()
        .entry(lane)
        .or_insert(0) += 1;
}

/// A starved Reliable pending window was purged past the give-up
/// threshold. Sequence continuity is kept; the destination recovers the
/// skipped range through the replication layer's gap detection.
pub(crate) fn record_pending_starve_purged(lane: u32) {
    *ORDERED_PENDING_STARVE_PURGED
        .lock()
        .unwrap()
        .entry(lane)
        .or_insert(0) += 1;
}

/// An inbound lane entered a stuck reorder gap (recorded when the gap is
/// first observed).
pub(crate) fn record_inbound_gap_stuck(lane: u32) {
    *ORDERED_INBOUND_GAP_STUCK
        .lock()
        .unwrap()
        .entry(lane)
        .or_insert(0) += 1;
}

/// A stuck inbound lane was healed by rebasing onto the current
/// sequence.
pub(crate) fn record_inbound_gap_healed(lane: u32) {
    *ORDERED_INBOUND_GAP_HEALED
        .lock()
        .unwrap()
        .entry(lane)
        .or_insert(0) += 1;
}

/// An end-to-end control frame found no admitted edge in the
/// low-latency metric's tables and was routed through a reliable-metric
/// fallback instead of being dropped.
pub(crate) fn record_control_route_fallback() {
    CONTROL_ROUTE_FALLBACKS.fetch_add(1, Ordering::Relaxed);
}

/// Bounded lifecycle events of the next-hop failure backoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NextHopBackoffEvent {
    /// Consecutive send failures to an admitted first hop crossed the
    /// threshold: the hop is skipped in favor of alternates until the
    /// backoff expires.
    Activated,
    /// The backoff expired; the direct hop is retried.
    Expired,
}

impl NextHopBackoffEvent {
    const ALL: [Self; 2] = [Self::Activated, Self::Expired];

    fn index(self) -> usize {
        match self {
            Self::Activated => 0,
            Self::Expired => 1,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Activated => "activated",
            Self::Expired => "expired",
        }
    }
}

const NEXT_HOP_BACKOFF_EVENT_COUNT: usize = 2;
static NEXT_HOP_BACKOFF_EVENTS: [AtomicU64; NEXT_HOP_BACKOFF_EVENT_COUNT] =
    [const { AtomicU64::new(0) }; NEXT_HOP_BACKOFF_EVENT_COUNT];

pub(crate) fn record_next_hop_backoff(event: NextHopBackoffEvent) {
    NEXT_HOP_BACKOFF_EVENTS[event.index()].fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn prometheus_samples() -> Vec<PrometheusSample> {
    let mut samples = Vec::new();
    for ((kind, dst), drops) in NO_ROUTE_DROPS.lock().unwrap().iter() {
        if *drops > 0 {
            samples.push(PrometheusSample::new(
                "shitspeak_s2s_overlay_no_route_drops_total",
                vec![
                    ("kind".to_owned(), kind.label().to_owned()),
                    ("dst".to_owned(), dst.to_string()),
                ],
                *drops as f64,
            ));
        }
    }
    for reason in ReliableOriginateFailure::ALL {
        let failures = RELIABLE_ORIGINATE_FAILURES[reason.index()].load(Ordering::Relaxed);
        if failures > 0 {
            samples.push(PrometheusSample::new(
                "shitspeak_s2s_overlay_reliable_originate_failures_total",
                vec![("reason".to_owned(), reason.label().to_owned())],
                failures as f64,
            ));
        }
    }
    for (lane, full) in ORDERED_WINDOW_FULL.lock().unwrap().iter() {
        if *full > 0 {
            samples.push(PrometheusSample::new(
                "shitspeak_s2s_overlay_ordered_window_full_total",
                vec![("lane".to_owned(), lane.to_string())],
                *full as f64,
            ));
        }
    }
    for (lane, nacks) in ORDERED_NACKS.lock().unwrap().iter() {
        if *nacks > 0 {
            samples.push(PrometheusSample::new(
                "shitspeak_s2s_overlay_ordered_nacks_total",
                vec![("lane".to_owned(), lane.to_string())],
                *nacks as f64,
            ));
        }
    }
    for ((reason, lane), drops) in ORDERED_INBOUND_DROPS.lock().unwrap().iter() {
        if *drops > 0 {
            samples.push(PrometheusSample::new(
                "shitspeak_s2s_overlay_ordered_inbound_drops_total",
                vec![
                    ("reason".to_owned(), reason.label().to_owned()),
                    ("lane".to_owned(), lane.to_string()),
                ],
                *drops as f64,
            ));
        }
    }
    for ((dst, lane), gauges) in ORDERED_PENDING.lock().unwrap().iter() {
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_overlay_ordered_pending_packets",
            vec![
                ("dst".to_owned(), dst.to_string()),
                ("lane".to_owned(), lane.to_string()),
            ],
            gauges.packets as f64,
        ));
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_overlay_ordered_pending_oldest_age_ms",
            vec![
                ("dst".to_owned(), dst.to_string()),
                ("lane".to_owned(), lane.to_string()),
            ],
            gauges.oldest_age_ms as f64,
        ));
    }
    for (lane, starved) in ORDERED_PENDING_STARVE_EVENTS.lock().unwrap().iter() {
        if *starved > 0 {
            samples.push(PrometheusSample::new(
                "shitspeak_s2s_overlay_ordered_pending_starve_events_total",
                vec![("lane".to_owned(), lane.to_string())],
                *starved as f64,
            ));
        }
    }
    for (lane, purged) in ORDERED_PENDING_STARVE_PURGED.lock().unwrap().iter() {
        if *purged > 0 {
            samples.push(PrometheusSample::new(
                "shitspeak_s2s_overlay_ordered_pending_starve_purged_total",
                vec![("lane".to_owned(), lane.to_string())],
                *purged as f64,
            ));
        }
    }
    for (lane, stuck) in ORDERED_INBOUND_GAP_STUCK.lock().unwrap().iter() {
        if *stuck > 0 {
            samples.push(PrometheusSample::new(
                "shitspeak_s2s_overlay_ordered_inbound_gap_stuck_total",
                vec![("lane".to_owned(), lane.to_string())],
                *stuck as f64,
            ));
        }
    }
    for (lane, healed) in ORDERED_INBOUND_GAP_HEALED.lock().unwrap().iter() {
        if *healed > 0 {
            samples.push(PrometheusSample::new(
                "shitspeak_s2s_overlay_ordered_inbound_gap_healed_total",
                vec![("lane".to_owned(), lane.to_string())],
                *healed as f64,
            ));
        }
    }
    let control_fallbacks = CONTROL_ROUTE_FALLBACKS.load(Ordering::Relaxed);
    if control_fallbacks > 0 {
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_overlay_control_route_fallback_total",
            Vec::new(),
            control_fallbacks as f64,
        ));
    }
    for event in NextHopBackoffEvent::ALL {
        let events = NEXT_HOP_BACKOFF_EVENTS[event.index()].load(Ordering::Relaxed);
        if events > 0 {
            samples.push(PrometheusSample::new(
                "shitspeak_s2s_overlay_next_hop_backoff_events_total",
                vec![("reason".to_owned(), event.label().to_owned())],
                events as f64,
            ));
        }
    }
    samples
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordered_and_forwarding_metrics_use_bounded_labels() {
        let before_nack = ORDERED_NACKS
            .lock()
            .unwrap()
            .get(&7)
            .copied()
            .unwrap_or(0);
        record_no_route_drop(NoRouteKind::Control, 9);
        record_reliable_originate_failure(ReliableOriginateFailure::NoRoute);
        record_window_full(0x4f57_4e52);
        record_nack(7);
        record_inbound_drop(InboundDropReason::GapBeyondReorder, 8);
        record_ordered_pending(9, 8, 4, 250);
        record_pending_starve(11);
        record_pending_starve_purged(12);
        record_inbound_gap_stuck(13);
        record_inbound_gap_healed(14);
        record_next_hop_backoff(NextHopBackoffEvent::Activated);

        let samples = prometheus_samples();
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_overlay_no_route_drops_total"
                && sample.labels()
                    == [
                        ("kind".to_owned(), "control".to_owned()),
                        ("dst".to_owned(), "9".to_owned()),
                    ]
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_overlay_reliable_originate_failures_total"
                && sample.labels() == [("reason".to_owned(), "no_route".to_owned())]
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_overlay_ordered_window_full_total"
                && sample.labels() == [("lane".to_owned(), "1331121746".to_owned())]
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_overlay_ordered_nacks_total"
                && sample.labels() == [("lane".to_owned(), "7".to_owned())]
                && sample.value() >= before_nack as f64 + 1.0
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_overlay_ordered_inbound_drops_total"
                && sample.labels()
                    == [
                        ("reason".to_owned(), "gap_beyond_reorder".to_owned()),
                        ("lane".to_owned(), "8".to_owned()),
                    ]
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_overlay_ordered_pending_packets"
                && sample.labels()
                    == [
                        ("dst".to_owned(), "9".to_owned()),
                        ("lane".to_owned(), "8".to_owned()),
                    ]
                && sample.value() == 4.0
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_overlay_ordered_pending_starve_events_total"
                && sample.labels() == [("lane".to_owned(), "11".to_owned())]
                && sample.value() >= 1.0
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_overlay_ordered_pending_starve_purged_total"
                && sample.labels() == [("lane".to_owned(), "12".to_owned())]
                && sample.value() >= 1.0
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_overlay_ordered_inbound_gap_stuck_total"
                && sample.labels() == [("lane".to_owned(), "13".to_owned())]
                && sample.value() >= 1.0
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_overlay_ordered_inbound_gap_healed_total"
                && sample.labels() == [("lane".to_owned(), "14".to_owned())]
                && sample.value() >= 1.0
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_overlay_next_hop_backoff_events_total"
                && sample.labels() == [("reason".to_owned(), "activated".to_owned())]
                && sample.value() >= 1.0
        }));

        // Bounded labels only.
        for sample in samples.iter().filter(|sample| {
            sample.name().contains("overlay_no_route")
                || sample.name().contains("overlay_reliable_originate")
                || sample.name().contains("overlay_ordered_")
                || sample.name().contains("overlay_next_hop_backoff")
        }) {
            assert!(
                sample.labels().iter().all(|(label, _)| {
                    ["kind", "dst", "reason", "lane"].contains(&label.as_str())
                }),
                "unexpected label on {}",
                sample.name()
            );
        }

        remove_ordered_pending(9, 8);
        let samples = prometheus_samples();
        assert!(
            !samples.iter().any(|sample| sample
                .name()
                == "shitspeak_s2s_overlay_ordered_pending_packets"
                && sample.labels().contains(&("dst".to_owned(), "9".to_owned()))),
            "released pending window must not keep a stale gauge"
        );
    }

    #[test]
    fn reliable_originate_failure_reasons_map_from_overlay_errors() {
        assert!(matches!(
            ReliableOriginateFailure::from_error(&OverlayError::NoRoute {
                dst: 1,
                level: shitspeak_s2s_transport::ServiceLevel::Reliable,
            }),
            ReliableOriginateFailure::NoRoute
        ));
        assert!(matches!(
            ReliableOriginateFailure::from_error(&OverlayError::Send(
                shitspeak_s2s_transport::SendError::Backpressure {
                    transport: shitspeak_s2s_transport::TransportKind::Tcp,
                    node: 1,
                }
            )),
            ReliableOriginateFailure::Backpressure
        ));
    }
}
