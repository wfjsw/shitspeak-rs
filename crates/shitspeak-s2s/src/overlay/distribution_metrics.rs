//! Bounded Prometheus metrics for the generic distribution-tree plane.
//!
//! Tree/group/version identifiers are intentionally excluded from labels:
//! multicast group membership and tree churn can otherwise create unbounded
//! time series. Detailed identifiers remain available in structured logs.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use crate::status::PrometheusSample;

static METRICS: LazyLock<Mutex<DistributionMetrics>> =
    LazyLock::new(|| Mutex::new(DistributionMetrics::default()));

#[allow(dead_code)] // Forwarding/reparent hooks are wired by their owning paths.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum DistributionEvent {
    ControlPublish,
    ControlAck,
    Activation,
    CompatibilityFallback,
    StateRequest,
    OriginalForward,
    AlternateForward,
    Reparent,
    HysteresisHold,
}

impl DistributionEvent {
    fn label(self) -> &'static str {
        match self {
            Self::ControlPublish => "control_publish",
            Self::ControlAck => "control_ack",
            Self::Activation => "activation",
            Self::CompatibilityFallback => "compatibility_fallback",
            Self::StateRequest => "state_request",
            Self::OriginalForward => "original_forward",
            Self::AlternateForward => "alternate_forward",
            Self::Reparent => "reparent",
            Self::HysteresisHold => "hysteresis_hold",
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct EventKey {
    profile: ProfileBucket,
    event: DistributionEvent,
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

#[derive(Clone, Copy, Debug, Default)]
struct ProfileGauge {
    pending_acks: u64,
    tree_edges: u64,
}

#[derive(Default)]
struct DistributionMetrics {
    events: HashMap<EventKey, u64>,
    gauges: HashMap<ProfileBucket, ProfileGauge>,
}

fn record(profile: u32, event: DistributionEvent) {
    let mut metrics = METRICS.lock().unwrap();
    *metrics
        .events
        .entry(EventKey {
            profile: ProfileBucket::from_id(profile),
            event,
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

pub(crate) fn record_compatibility_fallback(profile: u32) {
    record(profile, DistributionEvent::CompatibilityFallback);
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

pub(crate) fn prometheus_samples() -> Vec<PrometheusSample> {
    let metrics = METRICS.lock().unwrap();
    let mut out = Vec::new();

    for (key, count) in &metrics.events {
        out.push(PrometheusSample::new(
            "shitspeak_s2s_distribution_events_total",
            vec![
                ("profile".to_owned(), key.profile.label().to_owned()),
                ("event".to_owned(), key.event.label().to_owned()),
            ],
            *count as f64,
        ));
    }
    for (profile, gauge) in &metrics.gauges {
        let profile = profile.label().to_owned();
        out.push(PrometheusSample::new(
            "shitspeak_s2s_distribution_pending_acks",
            vec![("profile".to_owned(), profile.clone())],
            gauge.pending_acks as f64,
        ));
        out.push(PrometheusSample::new(
            "shitspeak_s2s_distribution_tree_edges",
            vec![("profile".to_owned(), profile)],
            gauge.tree_edges as f64,
        ));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(name: &str, labels: &[(&str, &str)]) -> Option<PrometheusSample> {
        prometheus_samples().into_iter().find(|sample| {
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
}
