//! Bounded Prometheus metrics for the generic distribution-tree plane.
//!
//! Tree/group/version identifiers are intentionally excluded from labels:
//! multicast group membership and tree churn can otherwise create unbounded
//! time series. Detailed identifiers remain available in structured logs.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use shitspeak_core::NodeIdentifier;

use crate::application::proto::VOICE_SERVICE_TAG;
use crate::overlay::neighbor::monitor::PeerClockOffset;
use crate::status::PrometheusSample;

static METRICS: LazyLock<Mutex<DistributionMetrics>> =
    LazyLock::new(|| Mutex::new(DistributionMetrics::default()));

#[allow(dead_code)] // Forwarding/reparent hooks are wired by their owning paths.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum DistributionEvent {
    ControlPublish,
    ControlAck,
    Activation,
    CandidateBuild,
    CandidateTrigger,
    EdgeForward,
    CompatibilityFallback,
    StateRequest,
    OriginalForward,
    AlternateForward,
    Reparent,
    HysteresisHold,
    DeadlineTranslation,
    DeadlineExpiry,
    ClockOffsetFallback,
}

impl DistributionEvent {
    fn label(self) -> &'static str {
        match self {
            Self::ControlPublish => "control_publish",
            Self::ControlAck => "control_ack",
            Self::Activation => "activation",
            Self::CandidateBuild => "candidate_build",
            Self::CandidateTrigger => "candidate_trigger",
            Self::EdgeForward => "edge_forward",
            Self::CompatibilityFallback => "compatibility_fallback",
            Self::StateRequest => "state_request",
            Self::OriginalForward => "original_forward",
            Self::AlternateForward => "alternate_forward",
            Self::Reparent => "reparent",
            Self::HysteresisHold => "hysteresis_hold",
            Self::DeadlineTranslation => "deadline_translation",
            Self::DeadlineExpiry => "deadline_expiry",
            Self::ClockOffsetFallback => "clock_offset_fallback",
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct EventKey {
    profile: ProfileBucket,
    event: DistributionEvent,
    result: Option<&'static str>,
    dimensions: EventDimensions,
}

/// Stable dimensions for a distribution outcome. Group and tree identifiers
/// deliberately never enter Prometheus labels; only the bounded group kind is
/// retained.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct DistributionMetricContext {
    profile: u32,
    service_tag: u32,
    source: NodeIdentifier,
    group_kind: GroupKind,
    edge_direction: EdgeDirection,
}

impl DistributionMetricContext {
    pub(crate) fn new(
        profile: u32,
        service_tag: u32,
        source: NodeIdentifier,
        group: Option<u64>,
        edge_direction: EdgeDirection,
    ) -> Self {
        Self {
            profile,
            service_tag,
            source,
            group_kind: GroupKind::from_group(group),
            edge_direction,
        }
    }
}

/// Direction relative to the local node emitting the metric.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum EdgeDirection {
    Inbound,
    Outbound,
    Local,
}

impl EdgeDirection {
    fn label(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
            Self::Local => "local",
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum GroupKind {
    Broadcast,
    Explicit,
    Unknown,
}

impl GroupKind {
    fn from_group(group: Option<u64>) -> Self {
        match group {
            Some(0) => Self::Broadcast,
            Some(_) => Self::Explicit,
            None => Self::Unknown,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Broadcast => "broadcast",
            Self::Explicit => "explicit",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct EventDimensions {
    service_tag: u32,
    source: Option<NodeIdentifier>,
    group_kind: GroupKind,
    edge_direction: EdgeDirection,
}

impl EventDimensions {
    fn legacy(profile: u32) -> Self {
        Self {
            service_tag: service_tag_for_profile(profile),
            source: None,
            group_kind: GroupKind::Unknown,
            edge_direction: EdgeDirection::Local,
        }
    }
}

impl From<DistributionMetricContext> for EventDimensions {
    fn from(context: DistributionMetricContext) -> Self {
        Self {
            service_tag: context.service_tag,
            source: Some(context.source),
            group_kind: context.group_kind,
            edge_direction: context.edge_direction,
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum ProfileBucket {
    VoiceRealtime,
    Other,
}

impl ProfileBucket {
    fn from_id(profile: u32) -> Self {
        if profile == crate::overlay::distribution::VOICE_REALTIME_PROFILE_ID {
            Self::VoiceRealtime
        } else {
            Self::Other
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::VoiceRealtime => "voice_realtime",
            Self::Other => "other",
        }
    }
}

fn service_tag_for_profile(profile: u32) -> u32 {
    (profile == crate::overlay::distribution::VOICE_REALTIME_PROFILE_ID)
        .then_some(VOICE_SERVICE_TAG)
        .unwrap_or_default()
}

#[derive(Clone, Copy, Debug, Default)]
struct ProfileGauge {
    pending_acks: u64,
    tree_edges: u64,
}

#[derive(Clone, Copy, Debug)]
struct PeerClockGauge {
    offset_us: i64,
    uncertainty_us: u64,
    estimate_age_seconds: f64,
}

#[derive(Default)]
struct DistributionMetrics {
    events: HashMap<EventKey, u64>,
    gauges: HashMap<ProfileBucket, ProfileGauge>,
    peer_clocks: HashMap<NodeIdentifier, PeerClockGauge>,
}

#[cfg(feature = "pre-release-workload")]
pub(crate) fn pre_release_counters() -> (u64, u64, u64, u64) {
    let metrics = METRICS.lock().unwrap();
    let profile = ProfileBucket::Other;
    let sum = |event, result: Option<&'static str>| {
        metrics
            .events
            .iter()
            .filter(|(key, _)| {
                key.profile == profile
                    && key.event == event
                    && result.is_none_or(|r| key.result == Some(r))
            })
            .map(|(_, count)| *count)
            .sum()
    };
    (
        sum(DistributionEvent::Activation, None),
        sum(DistributionEvent::CompatibilityFallback, None),
        sum(DistributionEvent::CandidateBuild, Some("attempt")),
        sum(DistributionEvent::CandidateTrigger, None),
    )
}

fn record(profile: u32, event: DistributionEvent) {
    record_with_result(profile, event, None, EventDimensions::legacy(profile));
}

fn record_with_result(
    profile: u32,
    event: DistributionEvent,
    result: Option<&'static str>,
    dimensions: EventDimensions,
) {
    let mut metrics = METRICS.lock().unwrap();
    *metrics
        .events
        .entry(EventKey {
            profile: ProfileBucket::from_id(profile),
            event,
            result,
            dimensions,
        })
        .or_default() += 1;
}

pub(crate) fn record_control_publish(profile: u32) {
    record(profile, DistributionEvent::ControlPublish);
}

pub(crate) fn record_control_ack(profile: u32) {
    record(profile, DistributionEvent::ControlAck);
}

pub(crate) fn record_activation(profile: u32) {
    record(profile, DistributionEvent::Activation);
}

pub(crate) fn record_candidate_build(profile: u32, result: &'static str) {
    record_with_result(
        profile,
        DistributionEvent::CandidateBuild,
        Some(result),
        EventDimensions::legacy(profile),
    );
}

pub(crate) fn record_candidate_trigger(profile: u32, result: &'static str) {
    record_with_result(
        profile,
        DistributionEvent::CandidateTrigger,
        Some(result),
        EventDimensions::legacy(profile),
    );
}

pub(crate) fn record_edge_forward(profile: u32, result: &'static str) {
    record_with_result(
        profile,
        DistributionEvent::EdgeForward,
        Some(result),
        EventDimensions::legacy(profile),
    );
}

#[allow(dead_code)] // Retained for unit coverage of legacy metric dimensions.
pub(crate) fn record_compatibility_fallback(profile: u32) {
    record_with_result(
        profile,
        DistributionEvent::CompatibilityFallback,
        Some("unspecified"),
        EventDimensions::legacy(profile),
    );
}

/// Record a capability, readiness, or inactive-tree fallback without exposing
/// a recipient group or tree version.
pub(crate) fn record_compatibility_fallback_with_context(
    context: DistributionMetricContext,
    reason: &'static str,
) {
    record_with_result(
        context.profile,
        DistributionEvent::CompatibilityFallback,
        Some(reason),
        context.into(),
    );
}

pub(crate) fn record_state_request(profile: u32) {
    record(profile, DistributionEvent::StateRequest);
}

/// Record one original frame forwarded across one tree edge.
#[allow(dead_code)] // The forwarding module owns this call site.
pub(crate) fn record_original_forward(profile: u32) {
    record(profile, DistributionEvent::OriginalForward);
}

/// Record one deadline-eligible alternate tree-edge attempt.
#[allow(dead_code)] // The repair path owns this call site.
pub(crate) fn record_alternate_forward(profile: u32) {
    record(profile, DistributionEvent::AlternateForward);
}

#[allow(dead_code)] // The reparenting controller owns this call site.
pub(crate) fn record_reparent(profile: u32) {
    record(profile, DistributionEvent::Reparent);
}

#[allow(dead_code)] // The tree-selection controller owns this call site.
pub(crate) fn record_hysteresis_hold(profile: u32) {
    record(profile, DistributionEvent::HysteresisHold);
}

/// Record the bounded result of translating a tree-frame deadline from its
/// immediate peer's clock into the local clock.
#[allow(dead_code)] // Retained for unit coverage of legacy metric dimensions.
pub(crate) fn record_deadline_translation(profile: u32, result: &'static str) {
    record_with_result(
        profile,
        DistributionEvent::DeadlineTranslation,
        Some(result),
        EventDimensions::legacy(profile),
    );
}

pub(crate) fn record_deadline_translation_with_context(
    context: DistributionMetricContext,
    result: &'static str,
) {
    record_with_result(
        context.profile,
        DistributionEvent::DeadlineTranslation,
        Some(result),
        context.into(),
    );
}

/// Record a tree frame that expired before it could be processed locally.
#[allow(dead_code)] // Retained for unit coverage of legacy metric dimensions.
pub(crate) fn record_deadline_expiry(profile: u32) {
    record_with_result(
        profile,
        DistributionEvent::DeadlineExpiry,
        Some("expired"),
        EventDimensions::legacy(profile),
    );
}

pub(crate) fn record_deadline_expiry_with_context(
    context: DistributionMetricContext,
    reason: &'static str,
) {
    record_with_result(
        context.profile,
        DistributionEvent::DeadlineExpiry,
        Some(reason),
        context.into(),
    );
}

/// Record a source-side fallback because the next peer has no usable clock
/// offset estimate for the v2 distribution protocol.
#[allow(dead_code)] // Retained for unit coverage of legacy metric dimensions.
pub(crate) fn record_clock_offset_fallback(profile: u32) {
    record_with_result(
        profile,
        DistributionEvent::ClockOffsetFallback,
        Some("unspecified"),
        EventDimensions::legacy(profile),
    );
}

pub(crate) fn record_clock_offset_fallback_with_context(
    context: DistributionMetricContext,
    reason: &'static str,
) {
    record_with_result(
        context.profile,
        DistributionEvent::ClockOffsetFallback,
        Some(reason),
        context.into(),
    );
}

pub(crate) fn set_pending_acks(profile: u32, pending_acks: usize) {
    METRICS
        .lock()
        .unwrap()
        .gauges
        .entry(ProfileBucket::from_id(profile))
        .or_default()
        .pending_acks = pending_acks as u64;
}

pub(crate) fn set_tree_edges(profile: u32, tree_edges: usize) {
    METRICS
        .lock()
        .unwrap()
        .gauges
        .entry(ProfileBucket::from_id(profile))
        .or_default()
        .tree_edges = tree_edges as u64;
}

/// Replace the local direct-peer clock gauges with the current fresh
/// estimates. No historical peer state is exported after an estimate expires.
pub(crate) fn set_peer_clock_offsets(offsets: &[(NodeIdentifier, PeerClockOffset)]) {
    let gauges = offsets
        .iter()
        .map(|(peer, offset)| {
            (
                *peer,
                PeerClockGauge {
                    offset_us: offset.peer_ahead_us(),
                    uncertainty_us: offset.uncertainty().as_micros().min(u128::from(u64::MAX))
                        as u64,
                    estimate_age_seconds: offset.age().as_secs_f64(),
                },
            )
        })
        .collect::<Vec<_>>();
    set_peer_clock_gauges(gauges);
}

fn set_peer_clock_gauges(gauges: Vec<(NodeIdentifier, PeerClockGauge)>) {
    let mut metrics = METRICS.lock().unwrap();
    metrics.peer_clocks.clear();
    metrics.peer_clocks.extend(gauges);
}

pub(crate) fn prometheus_samples(local_node: NodeIdentifier) -> Vec<PrometheusSample> {
    let metrics = METRICS.lock().unwrap();
    let mut out = Vec::new();
    let local_node = local_node.to_string();

    for (key, count) in &metrics.events {
        let mut labels = vec![
            ("local_node".to_owned(), local_node.clone()),
            (
                "source".to_owned(),
                key.dimensions
                    .source
                    .map(|source| source.to_string())
                    .unwrap_or_else(|| local_node.clone()),
            ),
            ("profile".to_owned(), key.profile.label().to_owned()),
            (
                "service_tag".to_owned(),
                key.dimensions.service_tag.to_string(),
            ),
            (
                "group_kind".to_owned(),
                key.dimensions.group_kind.label().to_owned(),
            ),
            (
                "edge_direction".to_owned(),
                key.dimensions.edge_direction.label().to_owned(),
            ),
            ("event".to_owned(), key.event.label().to_owned()),
        ];
        if let Some(result) = key.result {
            labels.push(("result".to_owned(), result.to_owned()));
        }
        out.push(PrometheusSample::new(
            "shitspeak_s2s_distribution_events_total",
            labels,
            *count as f64,
        ));
    }
    for (profile, gauge) in &metrics.gauges {
        let profile = profile.label().to_owned();
        out.push(PrometheusSample::new(
            "shitspeak_s2s_distribution_pending_acks",
            vec![
                ("source".to_owned(), local_node.clone()),
                ("profile".to_owned(), profile.clone()),
            ],
            gauge.pending_acks as f64,
        ));
        out.push(PrometheusSample::new(
            "shitspeak_s2s_distribution_tree_edges",
            vec![
                ("source".to_owned(), local_node.clone()),
                ("profile".to_owned(), profile),
            ],
            gauge.tree_edges as f64,
        ));
    }
    for (peer, gauge) in &metrics.peer_clocks {
        let base = vec![
            ("source".to_owned(), local_node.clone()),
            ("peer".to_owned(), peer.to_string()),
        ];
        out.push(PrometheusSample::new(
            "shitspeak_s2s_distribution_peer_clock_offset_us",
            base.clone(),
            gauge.offset_us as f64,
        ));
        out.push(PrometheusSample::new(
            "shitspeak_s2s_distribution_peer_clock_uncertainty_us",
            base.clone(),
            gauge.uncertainty_us as f64,
        ));
        out.push(PrometheusSample::new(
            "shitspeak_s2s_distribution_peer_clock_estimate_age_seconds",
            base,
            gauge.estimate_age_seconds,
        ));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(name: &str, labels: &[(&str, &str)]) -> Option<PrometheusSample> {
        prometheus_samples(1).into_iter().find(|sample| {
            sample.name() == name
                && labels.iter().all(|(key, value)| {
                    sample.labels().iter().any(|(sample_key, sample_value)| {
                        sample_key == key && sample_value == value
                    })
                })
        })
    }

    #[test]
    fn records_all_distribution_event_classes_with_bounded_labels() {
        let profile = 91;
        record_control_publish(profile);
        record_control_ack(profile);
        record_activation(profile);
        record_compatibility_fallback(profile);
        record_state_request(profile);
        record_original_forward(profile);
        record_alternate_forward(profile);
        record_reparent(profile);
        record_hysteresis_hold(profile);
        record_deadline_translation(profile, "translated");
        record_deadline_expiry(profile);
        record_clock_offset_fallback(profile);
        set_pending_acks(profile, 2);
        set_tree_edges(profile, 15);

        for event in [
            "control_publish",
            "control_ack",
            "activation",
            "compatibility_fallback",
            "state_request",
            "original_forward",
            "alternate_forward",
            "reparent",
            "hysteresis_hold",
            "deadline_expiry",
            "clock_offset_fallback",
        ] {
            let metric = sample(
                "shitspeak_s2s_distribution_events_total",
                &[("profile", "other"), ("event", event)],
            )
            .expect("event metric");
            assert!(metric.value() >= 1.0);
            assert!(metric.labels().iter().all(|(label, _)| {
                !matches!(
                    label.as_str(),
                    "group" | "tree_version" | "topology_epoch" | "member"
                )
            }));
        }

        let translation = sample(
            "shitspeak_s2s_distribution_events_total",
            &[
                ("profile", "other"),
                ("event", "deadline_translation"),
                ("result", "translated"),
            ],
        )
        .expect("deadline translation metric");
        assert!(translation.value() >= 1.0);

        assert_eq!(
            sample(
                "shitspeak_s2s_distribution_pending_acks",
                &[("profile", "other")],
            )
            .expect("pending ack gauge")
            .value(),
            2.0
        );
        assert_eq!(
            sample(
                "shitspeak_s2s_distribution_tree_edges",
                &[("profile", "other")],
            )
            .expect("tree edge gauge")
            .value(),
            15.0
        );
    }

    #[test]
    fn exports_fresh_peer_clock_gauges_with_bounded_peer_labels() {
        set_peer_clock_gauges(vec![(
            2,
            PeerClockGauge {
                offset_us: -4_000,
                uncertainty_us: 12_000,
                estimate_age_seconds: 1.5,
            },
        )]);

        assert_eq!(
            sample(
                "shitspeak_s2s_distribution_peer_clock_offset_us",
                &[("source", "1"), ("peer", "2")],
            )
            .expect("offset gauge")
            .value(),
            -4_000.0
        );
        assert_eq!(
            sample(
                "shitspeak_s2s_distribution_peer_clock_uncertainty_us",
                &[("source", "1"), ("peer", "2")],
            )
            .expect("uncertainty gauge")
            .value(),
            12_000.0
        );
        assert_eq!(
            sample(
                "shitspeak_s2s_distribution_peer_clock_estimate_age_seconds",
                &[("source", "1"), ("peer", "2")],
            )
            .expect("age gauge")
            .value(),
            1.5
        );
    }

    #[test]
    fn contextual_outcomes_export_bounded_source_service_and_group_labels() {
        let profile = crate::overlay::distribution::VOICE_REALTIME_PROFILE_ID;
        let context = DistributionMetricContext::new(
            profile,
            VOICE_SERVICE_TAG,
            7,
            Some(42),
            EdgeDirection::Inbound,
        );
        record_deadline_translation_with_context(context, "missing_offset");
        record_deadline_expiry_with_context(context, "expired");
        record_clock_offset_fallback_with_context(context, "child_clock_unready");
        record_compatibility_fallback_with_context(context, "child_clock_unready");

        let service_tag = VOICE_SERVICE_TAG.to_string();
        let labels = [
            ("local_node", "1"),
            ("source", "7"),
            ("profile", "voice_realtime"),
            ("service_tag", service_tag.as_str()),
            ("group_kind", "explicit"),
            ("edge_direction", "inbound"),
        ];
        for (event, result) in [
            ("deadline_translation", "missing_offset"),
            ("deadline_expiry", "expired"),
            ("clock_offset_fallback", "child_clock_unready"),
            ("compatibility_fallback", "child_clock_unready"),
        ] {
            let mut expected = labels.to_vec();
            expected.extend([("event", event), ("result", result)]);
            let metric = sample("shitspeak_s2s_distribution_events_total", &expected)
                .expect("contextual outcome metric");
            assert!(metric.labels().iter().all(|(label, _)| {
                !matches!(
                    label.as_str(),
                    "group" | "group_version" | "tree_version" | "topology_epoch" | "member"
                )
            }));
        }
    }
}
