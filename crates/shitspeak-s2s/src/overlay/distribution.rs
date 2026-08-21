//! Versioned control-plane state for source-rooted multicast trees.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Weak};
use std::time::Duration;
use std::time::Instant;

use parking_lot::Mutex;
use prost::Message as _;
use tracing::debug;

use bytes::{Bytes, BytesMut};
use shitspeak_core::NodeIdentifier;
use shitspeak_proto::s2s_overlay_proto as pb;
use shitspeak_s2s_transport::{ConnectionManager, MessageClass, ServiceLevel};

use super::messaging::ordering::OverlayOrdering;
use super::routing::RoutingHandle;
use super::{
    OverlayInboundMessage, OverlayNetwork, OverlaySendOptions, RoutingMetric, ServiceInbound,
    distribution_metrics,
};

const RETAINED_VERSIONS: usize = 3;
const UNKNOWN_TREE_FRAMES_PER_KEY: usize = 8;
const UNKNOWN_TREE_FRAMES_TOTAL: usize = 256;
const UNKNOWN_TREE_RECOVERY_RETRY: Duration = Duration::from_millis(10);
const EDGE_FAILURE_REPORT_DEDUP: Duration = Duration::from_secs(1);
const FAILED_EDGE_EXCLUSION: Duration = Duration::from_secs(10);
const METRIC_RESHAPE_HOLD: Duration = Duration::from_secs(5);
const METRIC_RESHAPE_IMPROVEMENT_PERCENT: u64 = 10;
const VOICE_OVERLAP_RATE_WINDOW: Duration = Duration::from_secs(1);
const VOICE_OVERLAP_MIN_CAPACITY_BYTES: usize = 1024 * 1024;
const VOICE_OVERLAP_MAX_CAPACITY_BYTES: usize = 8 * 1024 * 1024;
/// Control cadence for the voice-split state machine. The split weight is
/// advanced at most once per interval, driven from `choose_tree_edge` (which
/// already runs once per forwarded frame per edge).
const TRANSITION_CONTROL_INTERVAL: Duration = Duration::from_millis(50);
/// A challenger that reads at least this hard-failure pressure for this many
/// consecutive frames *under load* aborts the transition and rolls back to the
/// warm old route. Queue pressure reacts immediately; loss/playout catch up
/// within a fraction of a second of real load.
const TRANSITION_ABORT_PRESSURE: u8 = 3;
const TRANSITION_ABORT_OBSERVATIONS: u32 = 2;
/// A challenger at or above this marginal pressure pauses the ramp until the
/// measurement catches up (it is loaded now, not idle).
const TRANSITION_MARGINAL_PRESSURE: u8 = 2;
/// How long the new route must hold full load at the end of a fade before the
/// transition commits and the old route is dropped entirely.
const TRANSITION_CONFIRM: Duration = Duration::from_millis(150);
pub(crate) const DISTRIBUTION_CONTROL_SERVICE_TAG: u32 = 250;
pub(crate) const VOICE_REALTIME_PROFILE_ID: u32 = 1;
#[cfg(feature = "pre-release-workload")]
pub(crate) const PRE_RELEASE_RELIABLE_PROFILE_ID: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum TreeEdgePath {
    DirectChild,
    LegacyVia(NodeIdentifier),
}

impl TreeEdgePath {
    pub(crate) fn mode_label(self) -> &'static str {
        match self {
            Self::DirectChild => "direct",
            Self::LegacyVia(_) => "legacy",
        }
    }

    pub(crate) fn first_hop(self, child: NodeIdentifier) -> NodeIdentifier {
        match self {
            Self::DirectChild => child,
            Self::LegacyVia(first_hop) => first_hop,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TreeEdgeCandidate {
    path: TreeEdgePath,
    pressure: u8,
    route_cost: u64,
    /// Whether `pressure` is a live transport measurement. The escape path seeds
    /// a routing-table alternate whose lane has no live transport today
    /// (`verified = false`); it is a last-resort escape target so a failed
    /// primary becomes a best-effort try rather than a guaranteed drop.
    verified: bool,
}

impl TreeEdgeCandidate {
    #[cfg(test)]
    pub(crate) fn direct(pressure: u8) -> Self {
        Self::direct_with_cost(pressure, 0)
    }

    pub(crate) fn direct_with_cost(pressure: u8, route_cost: u64) -> Self {
        Self {
            path: TreeEdgePath::DirectChild,
            pressure,
            route_cost,
            verified: true,
        }
    }

    pub(crate) fn legacy(first_hop: NodeIdentifier, pressure: u8, route_cost: u64) -> Self {
        Self {
            path: TreeEdgePath::LegacyVia(first_hop),
            pressure,
            route_cost,
            verified: true,
        }
    }

    /// The always-ready alternate: the cheapest whole-path route to every
    /// recipient whose first hop avoids the incumbent, seeded by the escape
    /// path (`tree_edge_candidates` with `force_alternates`) even when its lane
    /// has no live transport measurement. Its pressure is unknown, so it only
    /// qualifies as a last-resort escape target.
    pub(crate) fn alternate(first_hop: NodeIdentifier, route_cost: u64) -> Self {
        Self {
            path: TreeEdgePath::LegacyVia(first_hop),
            pressure: 0,
            route_cost,
            verified: false,
        }
    }

    pub(crate) fn path(self) -> TreeEdgePath {
        self.path
    }

    pub(crate) fn pressure(self) -> u8 {
        self.pressure
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TreeEdgeStickinessPolicy {
    min_hold: Duration,
    challenger_confirm: Duration,
    idle_reset: Duration,
    /// How long a confirmed switch first duplicates voice onto both routes
    /// (the load-probe window). Long enough for the new route to accumulate
    /// enough real traffic for its loaded loss/playout metrics to be truthful.
    transition_fanout: Duration,
    /// How long the old route's copy takes to fade to zero once the probe
    /// window ends and the split weight starts ramping.
    transition_fade: Duration,
    /// Interior split mode: once the controller settles at an interior weight
    /// (`HoldsInterior`), each frame rides exactly one path by weight instead of
    /// a redundant copy. OFF by default — the redundant fade is the staged first
    /// cut; enable once repair coverage is confirmed in Grafana.
    split_mode: bool,
    /// Softmax temperature over each leg's loaded cost. Larger = more decisive
    /// toward the cheaper route.
    split_target_beta: f64,
    /// Exponential smoothing on the split target per control interval; damps
    /// feedback flips so the split converges instead of whipping between paths.
    split_target_learning_rate: f64,
}

impl TreeEdgeStickinessPolicy {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        min_hold: Duration,
        challenger_confirm: Duration,
        idle_reset: Duration,
        transition_fanout: Duration,
        transition_fade: Duration,
        split_mode: bool,
        split_target_beta: f64,
        split_target_learning_rate: f64,
    ) -> Self {
        Self {
            min_hold,
            challenger_confirm,
            idle_reset,
            transition_fanout,
            transition_fade,
            split_mode,
            split_target_beta,
            split_target_learning_rate,
        }
    }

    pub(crate) fn split_mode(&self) -> bool {
        self.split_mode
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct TreeEdgeBindingKey {
    source: NodeIdentifier,
    profile: u32,
    group: u64,
    group_version: u64,
    parent: NodeIdentifier,
    child: NodeIdentifier,
}

impl TreeEdgeBindingKey {
    fn new(key: TreeKey, parent: NodeIdentifier, child: NodeIdentifier) -> Self {
        Self {
            source: key.source,
            profile: key.profile,
            group: key.group,
            group_version: key.group_version,
            parent,
            child,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct TreeEdgeBinding {
    path: TreeEdgePath,
    entered_at: Instant,
    last_used_at: Instant,
    challenger: Option<TreeEdgePath>,
    challenger_since: Option<Instant>,
    challenger_observations: u32,
    pending: Option<(TreeEdgePath, &'static str)>,
    pending_held: Duration,
    pending_confirmation: Duration,
    generation: u64,
    bound: bool,
    no_alternate_reported: bool,
    /// Active weighted-split transition, if any. While present the controller
    /// owns the edge: `path` is the challenger being adopted and the split
    /// fades `from` (the old route) out under the challenger's *loaded*
    /// quality, aborting back to `from` if it degrades.
    transition: Option<TreeEdgeSplitState>,
}

/// Snapshot of an in-flight voice split, handed to the sender each frame so it
/// can choose where the frame (or its redundant copy) rides.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TreeEdgeSplit {
    from: TreeEdgePath,
    to: TreeEdgePath,
    share: f64,
    /// True when the controller has converged on an interior split and is
    /// holding it as the steady state. The sender may then switch from
    /// redundant-copy to one-path-per-frame by weight (split mode).
    interior_hold: bool,
}

impl TreeEdgeSplit {
    pub(crate) fn from(self) -> TreeEdgePath {
        self.from
    }

    pub(crate) fn to(self) -> TreeEdgePath {
        self.to
    }

    /// Weight of the adopted path (`binding.path`); the old route receives a
    /// redundant copy with probability `1 - share`.
    pub(crate) fn share(self) -> f64 {
        self.share
    }

    /// Whether the controller is holding an interior split (a portion to each
    /// path) rather than still moving toward a corner.
    pub(crate) fn interior_hold(self) -> bool {
        self.interior_hold
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SplitPhase {
    /// Both routes carry voice at full rate (duplication). This is the
    /// load-probe window: it gives the challenger real traffic so its
    /// loaded loss/playout metrics become truthful before any commitment.
    Fanout,
    /// The split weight ramps toward its target; the old route mirror-fades.
    Adjusting,
    /// The controller has converged on an interior split (target < 1.0) and is
    /// holding it as the steady state, re-evaluating on a slow cadence.
    HoldsInterior,
}

impl SplitPhase {
    /// Stable Prometheus label for the phase. `&'static` so the metric's label
    /// set is bounded across restarts.
    pub(crate) fn label(self) -> &'static str {
        match self {
            SplitPhase::Fanout => "fanout",
            SplitPhase::Adjusting => "adjusting",
            SplitPhase::HoldsInterior => "holds_interior",
        }
    }
}

/// Weighted-split state machine for a tree-edge voice transition.
#[derive(Clone, Copy, Debug)]
pub(crate) enum TreeEdgeSplitState {
    Splitting {
        from: TreeEdgePath,
        to: TreeEdgePath,
        /// Weight on `to` in `[0, 1]`; the old route mirrors at `1 - share`.
        share: f64,
        /// The controller heading: the split weight ramps toward this.
        target: f64,
        phase: SplitPhase,
        phase_started_at: Instant,
        /// When the weight last ramped (or the ramp phase began), so the fade
        /// advances on wall time regardless of the per-edge frame rate.
        last_ramp_at: Instant,
        degraded_observations: u32,
    },
}

/// Effect of advancing the split controller one control interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TreeEdgeTransitionStep {
    Active,
    Complete,
    /// The split rolled back to the old route. `reason` is one of the
    /// `&'static` strings surfaced in `shitspeak_s2s_voice_split_abort_total`
    /// (`challenger_degraded` or `rollback`).
    Abort { reason: &'static str },
}

/// Loaded quality of one split leg: the coarse pressure the abort/confirm
/// logic keys on, plus a fine-grained loaded cost for the softmax target.
#[derive(Clone, Copy, Debug)]
struct LoadedRouteQuality {
    pressure: u8,
    loaded_cost: f64,
}

/// E-model route cost stressed by the loaded pressure signal (queue, loss,
/// playout, held-delay feedback). A pressure-3 route costs 4x its idle cost, so
/// an idle-looking challenger's low cost is discounted the moment load arrives
/// on it. A route with no candidate (missing from `candidates`) is treated as
/// broken: `u64::MAX` cost.
fn loaded_route_cost(route_cost: Option<u64>, pressure: u8) -> f64 {
    route_cost.unwrap_or(u64::MAX) as f64 * (1.0 + f64::from(pressure))
}

fn loaded_quality_for(candidate: Option<TreeEdgeCandidate>) -> LoadedRouteQuality {
    candidate.map_or(
        LoadedRouteQuality {
            pressure: TRANSITION_ABORT_PRESSURE,
            loaded_cost: loaded_route_cost(None, TRANSITION_ABORT_PRESSURE),
        },
        |candidate| LoadedRouteQuality {
            pressure: candidate.pressure,
            loaded_cost: loaded_route_cost(Some(candidate.route_cost), candidate.pressure),
        },
    )
}

fn logistic(x: f64) -> f64 {
    1.0 / (1.0 + (-x).exp())
}

/// Softmax equilibrium target for the `to` leg. Corner snaps make a decisively
/// cheaper route converge to a clean 100/0 (or 0/100) so the existing
/// Complete/Abort conditions fire rather than stalling at 0.9999.
fn softmax_share(beta: f64, to_loaded_cost: f64, from_loaded_cost: f64) -> f64 {
    let p = logistic(beta * (from_loaded_cost - to_loaded_cost));
    if p >= 0.999 {
        1.0
    } else if p <= 0.001 {
        0.0
    } else {
        p
    }
}

/// Move `share` toward `target` on wall time, one fade-fraction per control
/// interval. Bidirectional so a target rollback ramps back down to the old
/// route at the same speed the fade advanced.
fn ramp_split_share(
    share: &mut f64,
    target: f64,
    last_ramp_at: &mut Instant,
    now: Instant,
    fade: Duration,
) {
    let delta = target - *share;
    if delta.abs() <= f64::EPSILON {
        return;
    }
    let elapsed = now.saturating_duration_since(*last_ramp_at);
    let intervals = elapsed.as_secs_f64() / TRANSITION_CONTROL_INTERVAL.as_secs_f64();
    let step = TRANSITION_CONTROL_INTERVAL.as_secs_f64() / fade.as_secs_f64();
    let next = *share + intervals * step * delta.signum();
    *share = next.clamp(target.min(*share), target.max(*share));
    *last_ramp_at = now;
}

impl TreeEdgeSplitState {
    /// Advance the split one control interval under both legs' *loaded*
    /// quality. Returns the effect for `choose_tree_edge` to apply.
    fn reduce(
        &mut self,
        now: Instant,
        to_quality: LoadedRouteQuality,
        from_quality: LoadedRouteQuality,
        policy: TreeEdgeStickinessPolicy,
    ) -> TreeEdgeTransitionStep {
        let Self::Splitting {
            share,
            target,
            phase,
            phase_started_at,
            last_ramp_at,
            degraded_observations,
            ..
        } = self;

        let to_pressure = to_quality.pressure;
        let from_pressure = from_quality.pressure;

        // Abort fast path: the challenger degraded hard under load for enough
        // consecutive frames. Roll back to the warm old route.
        if to_pressure >= TRANSITION_ABORT_PRESSURE {
            *degraded_observations = degraded_observations.saturating_add(1);
            if *degraded_observations >= TRANSITION_ABORT_OBSERVATIONS {
                return TreeEdgeTransitionStep::Abort {
                    reason: "challenger_degraded",
                };
            }
        } else {
            *degraded_observations = 0;
        }

        // A failing old route must not stall the switch: escape it rather than
        // keep fading into a route that is broken. (The sender's copy gate
        // already sheds copies to any route reading pressure >= 2.)
        let old_route_broken = from_pressure >= TRANSITION_ABORT_PRESSURE;

        // Recompute the load-aware equilibrium target once the probe window has
        // passed: the softmax over each leg's *loaded* cost. This is what lets
        // the split settle at an interior weight (a portion to each) instead of
        // always racing to 100/0, and what lets it roll back when the challenger
        // is only cheap because it was idle. The learning rate damps feedback
        // flips so the split converges instead of whipping between paths.
        if *phase != SplitPhase::Fanout
            || now.saturating_duration_since(*phase_started_at) >= policy.transition_fanout
        {
            let desired = softmax_share(
                policy.split_target_beta,
                to_quality.loaded_cost,
                from_quality.loaded_cost,
            );
            *target += policy.split_target_learning_rate * (desired - *target);
            // Snap the *smoothed* target, not the raw desired, so a small
            // quality wiggle cannot drag a near-corner target back off 1.0 and
            // stall an almost-finished switch in an interior hold. A 99%+
            // preference IS a decisive corner.
            if *target >= 0.99 {
                *target = 1.0;
            } else if *target <= 0.01 {
                *target = 0.0;
            }
        }

        match phase {
            SplitPhase::Fanout => {
                if old_route_broken
                    || now.saturating_duration_since(*phase_started_at) >= policy.transition_fanout
                {
                    *phase = SplitPhase::Adjusting;
                    *phase_started_at = now;
                    *last_ramp_at = now;
                }
            }
            SplitPhase::Adjusting => {
                // Load-aware hold: pause an upward ramp while the challenger is
                // marginal (`>= 2`) so its loaded metrics catch up — unless the
                // old route itself is failing, in which case escaping wins. A
                // downward ramp (rolling back to the old route) is never paused:
                // a marginal challenger is exactly why we would roll back.
                let ramping_toward_challenger = *target > *share;
                let paused = ramping_toward_challenger
                    && to_pressure >= TRANSITION_MARGINAL_PRESSURE
                    && !old_route_broken;
                let was_at_target = (*share - *target).abs() <= f64::EPSILON;
                if !paused {
                    ramp_split_share(share, *target, last_ramp_at, now, policy.transition_fade);
                }
                if !was_at_target && (*share - *target).abs() <= f64::EPSILON {
                    // Start the confirm/hold window at the moment the share arrives.
                    *phase_started_at = now;
                }
                if *share <= *target && *target <= 0.0 {
                    // The controller converged fully back to the old route.
                    return TreeEdgeTransitionStep::Abort {
                        reason: "rollback",
                    };
                }
                if *share >= *target && *target < 1.0 {
                    // Interior steady state reached; hold and keep re-evaluating.
                    *phase = SplitPhase::HoldsInterior;
                    *phase_started_at = now;
                }
            }
            SplitPhase::HoldsInterior => {
                // Steady interior split: keep ramping toward the (re-evaluated)
                // equilibrium so quality drift is re-approached slowly instead of
                // held rigidly.
                let was_at_target = (*share - *target).abs() <= f64::EPSILON;
                ramp_split_share(share, *target, last_ramp_at, now, policy.transition_fade);
                if !was_at_target && (*share - *target).abs() <= f64::EPSILON {
                    *phase_started_at = now;
                }
                if *share <= *target && *target <= 0.0 {
                    // Loaded quality flipped decisively: return to the old route.
                    return TreeEdgeTransitionStep::Abort {
                        reason: "rollback",
                    };
                }
            }
        }

        if *share >= *target
            && *target >= 1.0
            && (old_route_broken
                || (to_pressure < TRANSITION_MARGINAL_PRESSURE
                    && now.saturating_duration_since(*phase_started_at) >= TRANSITION_CONFIRM))
        {
            return TreeEdgeTransitionStep::Complete;
        }
        TreeEdgeTransitionStep::Active
    }
}

#[derive(Default)]
struct VoiceOverlapLink {
    accepted_originals: VecDeque<(Instant, usize)>,
    accepted_bytes: usize,
    reserved_bytes: usize,
    copies_sent: u64,
    copies_shed: u64,
    primary_fallback_sends: u64,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct VoiceOverlapLinkSnapshot {
    pub(crate) reserved_bytes: usize,
    pub(crate) capacity_bytes: usize,
    pub(crate) copies_sent: u64,
    pub(crate) copies_shed: u64,
    pub(crate) primary_fallback_sends: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TreeEdgeAttempt {
    key: TreeEdgeBindingKey,
    path: TreeEdgePath,
    generation: u64,
    reason: &'static str,
    incumbent_pressure: Option<u8>,
    chosen_pressure: Option<u8>,
}

impl TreeEdgeAttempt {
    pub(crate) fn path(self) -> TreeEdgePath {
        self.path
    }

    pub(crate) fn incumbent_pressure(self) -> Option<u8> {
        self.incumbent_pressure
    }

    pub(crate) fn chosen_pressure(self) -> Option<u8> {
        self.chosen_pressure
    }

    pub(crate) fn for_split_copy(path: TreeEdgePath) -> Self {
        Self {
            key: TreeEdgeBindingKey {
                source: 0,
                profile: 0,
                group: 0,
                group_version: 0,
                parent: 0,
                child: 0,
            },
            path,
            generation: 0,
            reason: "split_copy",
            incumbent_pressure: None,
            chosen_pressure: None,
        }
    }
}

fn candidate_for(
    candidates: &[TreeEdgeCandidate],
    path: TreeEdgePath,
) -> Option<TreeEdgeCandidate> {
    candidates
        .iter()
        .copied()
        .find(|candidate| candidate.path == path)
}

fn observe_tree_edge_challenger(
    binding: &mut TreeEdgeBinding,
    challenger: TreeEdgePath,
    now: Instant,
) {
    if binding.challenger == Some(challenger) {
        binding.challenger_observations = binding.challenger_observations.saturating_add(1);
    } else {
        binding.challenger = Some(challenger);
        binding.challenger_since = Some(now);
        binding.challenger_observations = 1;
    }
}

fn clear_tree_edge_challenger(binding: &mut TreeEdgeBinding) {
    binding.challenger = None;
    binding.challenger_since = None;
    binding.challenger_observations = 0;
}

fn begin_tree_edge_transition(
    binding: &mut TreeEdgeBinding,
    path: TreeEdgePath,
    reason: &'static str,
    now: Instant,
) {
    binding.pending_held = now.saturating_duration_since(binding.entered_at);
    binding.pending_confirmation = binding
        .challenger_since
        .map(|since| now.saturating_duration_since(since))
        .unwrap_or_default();
    binding.generation = binding.generation.wrapping_add(1).max(1);
    binding.pending = Some((path, reason));
    binding.no_alternate_reported = false;
    // A pending decision replaces any in-flight split (e.g. a hard escape from
    // a transition that lost both routes).
    binding.transition = None;
    clear_tree_edge_challenger(binding);
}

/// Whether the challenger is genuinely a better route than the incumbent.
///
/// The decision is driven by the continuous whole-path conversational cost
/// (`route_cost`, an E-model impairment score), not the saturated bang-bang
/// pressure: once a voice lane crosses the low suspect threshold its pressure
/// saturates and can no longer discriminate between two degrading paths, so
/// cost is the primary axis and min_hold/challenger_confirm remain the only
/// time hysteresis.
///
/// `challenger_is_idle` applies the idle-credibility discount: a challenger
/// whose first hop has carried no recent voice traffic reports clean metrics
/// precisely because it is unloaded — those are stale bets the moment it takes
/// load. Against a *healthy* incumbent (pressure < 2) an idle challenger must
/// be ≥20% cheaper before we start loading it; non-idle challengers only clear
/// the normal ≥10% margin. A challenger whose first hop is live-degraded
/// relative to the incumbent cannot win on advertised cost alone — its cost
/// has not yet caught up with the live signal. Hard-failure replacement
/// (pressure >= 3) never reaches this gate; it is handled earlier so escaping
/// a failing route is never blocked.
fn candidate_is_better(
    challenger: TreeEdgeCandidate,
    incumbent: TreeEdgeCandidate,
    challenger_is_idle: bool,
) -> bool {
    if challenger.pressure > incumbent.pressure.saturating_add(1) {
        return false;
    }
    if challenger_is_idle && incumbent.pressure < 2 {
        return challenger
            .route_cost
            .saturating_mul(100)
            <= incumbent.route_cost.saturating_mul(80);
    }
    challenger.route_cost.saturating_mul(100) <= incumbent.route_cost.saturating_mul(90)
}

fn prune_voice_overlap_samples(link: &mut VoiceOverlapLink, now: Instant) {
    while link
        .accepted_originals
        .front()
        .is_some_and(|(at, _)| now.saturating_duration_since(*at) >= VOICE_OVERLAP_RATE_WINDOW)
    {
        let (_, bytes) = link.accepted_originals.pop_front().expect("checked front");
        link.accepted_bytes = link.accepted_bytes.saturating_sub(bytes);
    }
}

fn voice_overlap_capacity(link: &VoiceOverlapLink) -> usize {
    link.accepted_bytes.saturating_mul(2).clamp(
        VOICE_OVERLAP_MIN_CAPACITY_BYTES,
        VOICE_OVERLAP_MAX_CAPACITY_BYTES,
    )
}

fn publish_voice_overlap_link(first_hop: NodeIdentifier, link: &VoiceOverlapLink) {
    distribution_metrics::update_voice_overlap_link(
        first_hop,
        link.reserved_bytes,
        voice_overlap_capacity(link),
        link.copies_sent,
        link.copies_shed,
        link.primary_fallback_sends,
    );
}

fn record_no_tree_edge_alternate(key: TreeEdgeBindingKey, binding: &mut TreeEdgeBinding) {
    if binding.no_alternate_reported {
        return;
    }
    binding.no_alternate_reported = true;
    distribution_metrics::record_tree_edge_binding_event(
        key.parent,
        key.child,
        binding.path.mode_label(),
        binding.path.mode_label(),
        "no_alternate",
    );
}

fn prune_tree_edge_bindings(
    bindings: &mut HashMap<TreeEdgeBindingKey, TreeEdgeBinding>,
    current: TreeEdgeBindingKey,
    idle_reset: Duration,
    now: Instant,
) {
    let mut removed = Vec::new();
    bindings.retain(|key, binding| {
        let superseded_group = key.source == current.source
            && key.profile == current.profile
            && key.group == current.group
            && key.group_version != current.group_version;
        let idle = now.saturating_duration_since(binding.last_used_at) >= idle_reset;
        let keep = !superseded_group && !idle;
        if !keep && binding.bound {
            removed.push((*key, binding.path, idle));
        }
        keep
    });
    for (key, path, idle) in removed {
        distribution_metrics::update_tree_edge_binding(
            key.parent,
            key.child,
            Some(path.mode_label()),
            None,
        );
        if idle {
            distribution_metrics::record_tree_edge_binding_event(
                key.parent,
                key.child,
                path.mode_label(),
                "none",
                "idle_reset",
            );
            debug!(
                source = %key.parent,
                peer = %key.child,
                from_mode = path.mode_label(),
                reason = "idle_reset",
                "voice tree edge binding reset after idle"
            );
        }
    }
}

/// A stable, service-filtered distribution policy. Profiles deliberately own
/// transport semantics; callers supply only the recipient group.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DistributionProfile {
    id: u32,
    service_tag: u32,
    level: ServiceLevel,
    metric: RoutingMetric,
}

impl DistributionProfile {
    pub(crate) fn id(self) -> u32 {
        self.id
    }

    pub(crate) fn level(self) -> ServiceLevel {
        self.level
    }

    pub(crate) fn metric(self) -> RoutingMetric {
        self.metric
    }

    pub(crate) fn accepts(self, tag: u32) -> bool {
        self.service_tag == tag
    }
}

pub(crate) fn profile_for_service(tag: u32) -> Option<DistributionProfile> {
    let voice = DistributionProfile {
        id: VOICE_REALTIME_PROFILE_ID,
        service_tag: crate::application::proto::VOICE_SERVICE_TAG,
        level: ServiceLevel::BestEffort,
        metric: RoutingMetric::ConversationalQuality,
    };
    if voice.accepts(tag) {
        return Some(voice);
    }
    #[cfg(feature = "pre-release-workload")]
    {
        let pre_release = DistributionProfile {
            id: PRE_RELEASE_RELIABLE_PROFILE_ID,
            service_tag: super::PRE_RELEASE_DISTRIBUTION_SERVICE_TAG,
            level: ServiceLevel::ReliableLowLatency,
            metric: RoutingMetric::ReliableLowLatencyCost,
        };
        if pre_release.accepts(tag) {
            return Some(pre_release);
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct TreeKey {
    pub(crate) source: NodeIdentifier,
    pub(crate) profile: u32,
    pub(crate) group: u64,
    pub(crate) group_version: u64,
    pub(crate) topology_epoch: u64,
    pub(crate) version: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TreeScope {
    source: NodeIdentifier,
    profile: u32,
    group: u64,
    group_version: u64,
    topology_epoch: u64,
}

impl From<TreeKey> for TreeScope {
    fn from(key: TreeKey) -> Self {
        Self {
            source: key.source,
            profile: key.profile,
            group: key.group,
            group_version: key.group_version,
            topology_epoch: key.topology_epoch,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TreeState {
    members: HashSet<NodeIdentifier>,
    children: HashMap<NodeIdentifier, Vec<NodeIdentifier>>,
    nodes: HashSet<NodeIdentifier>,
    hop_ttl: Option<Duration>,
}

impl TreeState {
    pub(crate) fn new(
        source: NodeIdentifier,
        members: impl IntoIterator<Item = NodeIdentifier>,
        edges: impl IntoIterator<Item = (NodeIdentifier, NodeIdentifier)>,
    ) -> Self {
        let members: HashSet<_> = members.into_iter().collect();
        let mut children: HashMap<NodeIdentifier, Vec<NodeIdentifier>> = HashMap::new();
        let mut nodes = HashSet::from([source]);
        for (parent, child) in edges {
            if parent == child {
                continue;
            }
            children.entry(parent).or_default().push(child);
            nodes.insert(parent);
            nodes.insert(child);
        }
        for child_nodes in children.values_mut() {
            child_nodes.sort_unstable();
            child_nodes.dedup();
        }
        nodes.extend(members.iter().copied());
        Self {
            members,
            children,
            nodes,
            hop_ttl: None,
        }
    }

    /// Retained while mixed-version callers still supply the retired metadata.
    /// The values are deliberately ignored: tree state owns topology only.
    #[cfg(test)]
    pub(crate) fn new_with_playout(
        source: NodeIdentifier,
        members: impl IntoIterator<Item = NodeIdentifier>,
        edges: impl IntoIterator<Item = (NodeIdentifier, NodeIdentifier)>,
        _playout_delays_ms: impl IntoIterator<Item = (NodeIdentifier, u64)>,
    ) -> Self {
        Self::new(source, members, edges)
    }

    pub(crate) fn is_member(&self, node: NodeIdentifier) -> bool {
        self.members.contains(&node)
    }

    pub(crate) fn children(&self, node: NodeIdentifier) -> &[NodeIdentifier] {
        self.children.get(&node).map(Vec::as_slice).unwrap_or(&[])
    }

    pub(crate) fn nodes(&self) -> impl Iterator<Item = NodeIdentifier> + '_ {
        self.nodes.iter().copied()
    }

    pub(crate) fn members(&self) -> impl Iterator<Item = NodeIdentifier> + '_ {
        self.members.iter().copied()
    }

    pub(crate) fn edges(&self) -> impl Iterator<Item = (NodeIdentifier, NodeIdentifier)> + '_ {
        self.children
            .iter()
            .flat_map(|(parent, children)| children.iter().map(move |child| (*parent, *child)))
    }

    pub(crate) fn with_hop_ttl(mut self, hop_ttl: Duration) -> Self {
        self.hop_ttl = (!hop_ttl.is_zero()).then_some(hop_ttl);
        self
    }

    pub(crate) fn hop_ttl(&self) -> Option<Duration> {
        self.hop_ttl
    }

    pub(crate) fn is_valid_for_source(&self, source: NodeIdentifier) -> bool {
        self.is_valid(source)
    }

    /// Return the portion of this tree needed by the relay below `child`.
    /// The path from the original source to the child is retained so the
    /// existing whole-tree validation rules remain applicable to the hint.
    pub(crate) fn branch_for_child(
        &self,
        source: NodeIdentifier,
        child: NodeIdentifier,
    ) -> Option<Self> {
        if !self.is_reachable_from(source, child) {
            return None;
        }

        let all_edges: Vec<_> = self.edges().collect();
        let mut path_edges = Vec::new();
        let mut current = child;
        while current != source {
            let parent = all_edges
                .iter()
                .find_map(|(parent, edge_child)| (*edge_child == current).then_some(*parent))?;
            path_edges.push((parent, current));
            current = parent;
        }
        path_edges.reverse();

        let mut branch_nodes = HashSet::from([child]);
        let mut pending = vec![child];
        while let Some(node) = pending.pop() {
            for descendant in self.children(node) {
                if branch_nodes.insert(*descendant) {
                    pending.push(*descendant);
                }
            }
        }
        let mut edges = path_edges;
        edges.extend(all_edges.iter().copied().filter(|(parent, edge_child)| {
            branch_nodes.contains(parent) && branch_nodes.contains(edge_child)
        }));
        let members = self
            .members
            .iter()
            .copied()
            .filter(|member| branch_nodes.contains(member));
        let branch = Self::new(source, members, edges).with_hop_ttl_opt(self.hop_ttl);
        branch.is_valid(source).then_some(branch)
    }

    fn with_hop_ttl_opt(mut self, hop_ttl: Option<Duration>) -> Self {
        self.hop_ttl = hop_ttl;
        self
    }

    fn is_valid(&self, source: NodeIdentifier) -> bool {
        if !self.nodes.contains(&source) || self.members.contains(&source) {
            return false;
        }
        let mut parent_count = HashMap::<NodeIdentifier, usize>::new();
        for (parent, child) in self.edges() {
            if parent == child || child == source {
                return false;
            }
            *parent_count.entry(child).or_default() += 1;
        }
        if parent_count.values().any(|count| *count != 1) {
            return false;
        }
        let mut reached = HashSet::from([source]);
        let mut pending = vec![source];
        while let Some(parent) = pending.pop() {
            for child in self.children(parent) {
                if !reached.insert(*child) {
                    return false;
                }
                pending.push(*child);
            }
        }
        reached == self.nodes && self.members.iter().all(|member| reached.contains(member))
    }

    /// Exact recipient members reachable through one direct child branch.
    /// The source tree should be acyclic, but the visited set also bounds this
    /// traversal when inspecting malformed remotely installed control state.
    pub(crate) fn descendant_members(&self, child: NodeIdentifier) -> Vec<NodeIdentifier> {
        let mut pending = vec![child];
        let mut visited = HashSet::new();
        let mut members = Vec::new();
        while let Some(node) = pending.pop() {
            if !visited.insert(node) {
                continue;
            }
            if self.members.contains(&node) {
                members.push(node);
            }
            pending.extend(self.children(node).iter().copied());
        }
        members.sort_unstable();
        members.dedup();
        members
    }

    pub(crate) fn is_reachable_from(
        &self,
        source: NodeIdentifier,
        destination: NodeIdentifier,
    ) -> bool {
        let mut pending = vec![source];
        let mut visited = HashSet::new();
        while let Some(node) = pending.pop() {
            if !visited.insert(node) {
                continue;
            }
            if node == destination {
                return true;
            }
            pending.extend(self.children(node).iter().copied());
        }
        false
    }
}

#[derive(Default)]
struct PendingAcks {
    remaining: HashSet<NodeIdentifier>,
}

#[derive(Clone)]
struct ActiveTree {
    key: TreeKey,
    state: TreeState,
    path_cost: u64,
    /// Failure edges already incorporated into the active replacement.
    applied_failures: HashSet<(NodeIdentifier, NodeIdentifier)>,
    legacy_members: HashSet<NodeIdentifier>,
}

#[derive(Clone)]
struct CandidateTree {
    key: TreeKey,
    state: TreeState,
    path_cost: u64,
    routing_generation: u64,
    recheck_at: Option<Instant>,
    legacy_members: HashSet<NodeIdentifier>,
}

#[derive(Clone)]
struct MetricProposal {
    state: TreeState,
    path_cost: u64,
    first_seen: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct StableTreeScope {
    source: NodeIdentifier,
    profile: u32,
    group: u64,
    group_version: u64,
}

impl From<TreeKey> for StableTreeScope {
    fn from(key: TreeKey) -> Self {
        Self {
            source: key.source,
            profile: key.profile,
            group: key.group,
            group_version: key.group_version,
        }
    }
}

#[derive(Clone)]
pub(crate) struct SelectedTree {
    key: TreeKey,
    state: Arc<TreeState>,
    legacy_members: Arc<HashSet<NodeIdentifier>>,
}

impl SelectedTree {
    pub(crate) fn key(&self) -> TreeKey {
        self.key
    }

    pub(crate) fn state(&self) -> &Arc<TreeState> {
        &self.state
    }

    pub(crate) fn legacy_members(&self) -> &HashSet<NodeIdentifier> {
        &self.legacy_members
    }
}

#[derive(Default)]
struct VersionHistory {
    installed: Vec<u64>,
    activated: Vec<u64>,
}

impl VersionHistory {
    fn record_install(&mut self, version: u64) {
        self.installed.retain(|installed| *installed != version);
        self.installed.push(version);
    }

    fn record_activation(&mut self, version: u64) {
        self.activated.retain(|active| *active != version);
        self.activated.push(version);
        if self.activated.len() > RETAINED_VERSIONS {
            let excess = self.activated.len() - RETAINED_VERSIONS;
            self.activated.drain(..excess);
        }
    }

    fn evicted_versions(&mut self) -> Vec<u64> {
        // An installed replacement must survive until its ACK-gated
        // activation. Keep the latest installation window for receivers that
        // do not observe source activation, plus the source's active snapshot
        // and its two exact predecessors.
        let mut retained: HashSet<u64> = self
            .installed
            .iter()
            .rev()
            .take(RETAINED_VERSIONS)
            .copied()
            .collect();
        retained.extend(self.activated.iter().copied());
        let evicted: Vec<_> = self
            .installed
            .iter()
            .copied()
            .filter(|version| !retained.contains(version))
            .collect();
        self.installed.retain(|version| retained.contains(version));
        evicted
    }
}

/// A frame held only until the exact referenced tree state arrives. It is
/// deliberately opaque to the control plane: replay still goes through the
/// normal data-plane validation path.
#[derive(Debug)]
pub(crate) struct PendingDistributionFrame {
    pub(crate) from: NodeIdentifier,
    pub(crate) data: pb::OverlayData,
    pub(crate) route_transit_messages: bool,
}

impl PendingDistributionFrame {
    pub(crate) fn new(
        from: NodeIdentifier,
        data: pb::OverlayData,
        route_transit_messages: bool,
    ) -> Self {
        Self {
            from,
            data,
            route_transit_messages,
        }
    }
}

#[derive(Debug)]
struct PendingUnknownFrame {
    id: u64,
    frame: PendingDistributionFrame,
}

#[derive(Default)]
struct UnknownTreeFrames {
    by_key: HashMap<TreeKey, Vec<PendingUnknownFrame>>,
    in_flight_requests: HashSet<TreeKey>,
    total: usize,
    next_id: u64,
}

#[derive(Debug)]
pub(crate) enum UnknownTreeEnqueue {
    Queued,
    AlreadyInstalled(PendingDistributionFrame),
    Full,
}

#[derive(Clone)]
pub(crate) struct RecoverySender {
    transport: ConnectionManager,
    routing: RoutingHandle,
    ordering: Arc<OverlayOrdering>,
    self_id: NodeIdentifier,
    boot_epoch: u64,
}

impl RecoverySender {
    async fn request(&self, key: TreeKey) {
        self.send_control(key.source, encode_request(key, self.self_id))
            .await;
    }

    async fn send_failure(&self, key: TreeKey, parent: NodeIdentifier, child: NodeIdentifier) {
        self.send_control(key.source, encode_failure(key, parent, child))
            .await;
    }

    async fn send_control(&self, dst: NodeIdentifier, body: Bytes) {
        let _ = super::messaging::send_unicast_with_routing_metric_unordered_and_options(
            &self.transport,
            &self.routing,
            self.self_id,
            self.boot_epoch,
            &self.ordering,
            dst,
            DISTRIBUTION_CONTROL_SERVICE_TAG,
            ServiceLevel::ReliableLowLatency,
            RoutingMetric::ReliableLowLatencyCost,
            MessageClass::Control,
            body,
            false,
            OverlaySendOptions::default(),
        )
        .await;
    }
}

fn same_tree_structure(left: &TreeState, right: &TreeState) -> bool {
    let mut left_edges: Vec<_> = left.edges().collect();
    left_edges.sort_unstable();
    let mut right_edges: Vec<_> = right.edges().collect();
    right_edges.sort_unstable();
    let mut left_members: Vec<_> = left.members().collect();
    left_members.sort_unstable();
    let mut right_members: Vec<_> = right.members().collect();
    right_members.sort_unstable();
    left_edges == right_edges && left_members == right_members
}

#[derive(Default)]
pub(crate) struct DistributionPlane {
    trees: Mutex<HashMap<TreeKey, Arc<TreeState>>>,
    versions: Mutex<HashMap<TreeScope, VersionHistory>>,
    pending: Mutex<HashMap<TreeKey, PendingAcks>>,
    unknown: Mutex<UnknownTreeFrames>,
    recovery_sender: Mutex<Option<RecoverySender>>,
    self_ref: Mutex<Weak<DistributionPlane>>,
    failed_edges:
        Mutex<HashMap<StableTreeScope, HashMap<(NodeIdentifier, NodeIdentifier), Instant>>>,
    /// Reports are deduplicated by source-owned directed edge, rather than by
    /// exact tree version. A replacement can have a different version while
    /// referring to the same physical child edge.
    failure_reported_at: Mutex<HashMap<(NodeIdentifier, NodeIdentifier, NodeIdentifier), Instant>>,
    active_trees: Mutex<HashMap<StableTreeScope, ActiveTree>>,
    candidates: Mutex<HashMap<TreeScope, CandidateTree>>,
    metric_proposals: Mutex<HashMap<StableTreeScope, MetricProposal>>,
    routing_generations: Mutex<HashMap<StableTreeScope, u64>>,
    scope_activity: Mutex<HashMap<TreeScope, Instant>>,
    tree_edge_bindings: Mutex<HashMap<TreeEdgeBindingKey, TreeEdgeBinding>>,
    voice_overlap_links: Mutex<HashMap<NodeIdentifier, VoiceOverlapLink>>,
    /// First hops recently rolled back by a split abort, keyed per tree edge
    /// `(parent, child, first_hop)`. A route that looked good while idle but
    /// degraded under load must not be re-tried (and re-aborted) for
    /// [`FAILED_EDGE_EXCLUSION`]: its metrics are idle-credit until it has had
    /// a chance to prove otherwise.
    voice_route_cooldowns:
        Mutex<HashMap<(NodeIdentifier, NodeIdentifier, NodeIdentifier), Instant>>,
    #[cfg(test)]
    control_publishes: Mutex<u64>,
}

impl DistributionPlane {
    pub(crate) fn record_voice_original_bytes(
        &self,
        first_hop: NodeIdentifier,
        bytes: usize,
        now: Instant,
    ) {
        let mut links = self.voice_overlap_links.lock();
        let link = links.entry(first_hop).or_default();
        prune_voice_overlap_samples(link, now);
        let bytes = bytes.max(1);
        link.accepted_originals.push_back((now, bytes));
        link.accepted_bytes = link.accepted_bytes.saturating_add(bytes);
        publish_voice_overlap_link(first_hop, link);
    }

    /// Whether a candidate first hop has carried no recent voice traffic
    /// through this plane. A first hop with no record at all is idle too: it
    /// has never been loaded, so its clean metrics are idle-credit, not proof.
    fn voice_route_first_hop_idle(&self, first_hop: NodeIdentifier, now: Instant) -> bool {
        let mut links = self.voice_overlap_links.lock();
        let Some(link) = links.get_mut(&first_hop) else {
            return true;
        };
        prune_voice_overlap_samples(link, now);
        link.accepted_originals.is_empty()
    }

    /// Whether a first hop is cooling down after a split abort on this tree
    /// edge, and must be kept out of contention. Expiry is checked here so the
    /// map only ever holds live entries after a lookup.
    fn voice_route_first_hop_cooling_down(
        &self,
        parent: NodeIdentifier,
        child: NodeIdentifier,
        first_hop: NodeIdentifier,
        now: Instant,
    ) -> bool {
        let mut cooldowns = self.voice_route_cooldowns.lock();
        cooldowns.retain(|_, at| now.saturating_duration_since(*at) < FAILED_EDGE_EXCLUSION);
        cooldowns
            .get(&(parent, child, first_hop))
            .is_some_and(|at| now.saturating_duration_since(*at) < FAILED_EDGE_EXCLUSION)
    }

    /// Mark a split-abort's failed first hop so it stays out of contention for
    /// [`FAILED_EDGE_EXCLUSION`]. Called from both abort paths (the controller's
    /// rollback and the sender's fallback abort).
    fn record_tree_edge_split_abort(
        &self,
        parent: NodeIdentifier,
        child: NodeIdentifier,
        failed_first_hop: NodeIdentifier,
        now: Instant,
    ) {
        let mut cooldowns = self.voice_route_cooldowns.lock();
        cooldowns.retain(|_, at| now.saturating_duration_since(*at) < FAILED_EDGE_EXCLUSION);
        cooldowns.insert((parent, child, failed_first_hop), now);
    }

    pub(crate) fn try_reserve_voice_overlap(
        &self,
        first_hop: NodeIdentifier,
        bytes: usize,
        now: Instant,
    ) -> bool {
        let mut links = self.voice_overlap_links.lock();
        let link = links.entry(first_hop).or_default();
        prune_voice_overlap_samples(link, now);
        let bytes = bytes.max(1);
        if link.reserved_bytes.saturating_add(bytes) > voice_overlap_capacity(link) {
            link.copies_shed = link.copies_shed.saturating_add(1);
            publish_voice_overlap_link(first_hop, link);
            return false;
        }
        link.reserved_bytes = link.reserved_bytes.saturating_add(bytes);
        publish_voice_overlap_link(first_hop, link);
        true
    }

    pub(crate) fn release_voice_overlap(
        &self,
        first_hop: NodeIdentifier,
        bytes: usize,
        sent: bool,
        primary_fallback: bool,
        now: Instant,
    ) {
        let mut links = self.voice_overlap_links.lock();
        let link = links.entry(first_hop).or_default();
        prune_voice_overlap_samples(link, now);
        link.reserved_bytes = link.reserved_bytes.saturating_sub(bytes.max(1));
        if sent {
            link.copies_sent = link.copies_sent.saturating_add(1);
        } else {
            link.copies_shed = link.copies_shed.saturating_add(1);
        }
        if primary_fallback && sent {
            link.primary_fallback_sends = link.primary_fallback_sends.saturating_add(1);
        }
        publish_voice_overlap_link(first_hop, link);
    }

    #[cfg(test)]
    fn voice_overlap_link_snapshot(
        &self,
        first_hop: NodeIdentifier,
        now: Instant,
    ) -> VoiceOverlapLinkSnapshot {
        let mut links = self.voice_overlap_links.lock();
        let link = links.entry(first_hop).or_default();
        prune_voice_overlap_samples(link, now);
        VoiceOverlapLinkSnapshot {
            reserved_bytes: link.reserved_bytes,
            capacity_bytes: voice_overlap_capacity(link),
            copies_sent: link.copies_sent,
            copies_shed: link.copies_shed,
            primary_fallback_sends: link.primary_fallback_sends,
        }
    }

    pub(crate) fn active_tree_edge_split(
        &self,
        tree_key: TreeKey,
        parent: NodeIdentifier,
        child: NodeIdentifier,
    ) -> Option<TreeEdgeSplit> {
        self.tree_edge_bindings
            .lock()
            .get(&TreeEdgeBindingKey::new(tree_key, parent, child))
            .and_then(|binding| match binding.transition {
                Some(TreeEdgeSplitState::Splitting {
                    from,
                    to,
                    share,
                    phase,
                    ..
                }) => Some(TreeEdgeSplit {
                    from,
                    to,
                    share,
                    interior_hold: matches!(phase, SplitPhase::HoldsInterior),
                }),
                None => None,
            })
    }

    /// Roll an in-flight split back to the old route. Called by the sender when
    /// the primary (adopted) path failed to send and the old route successfully
    /// carried the frame as a fallback: the failed new path must not be treated
    /// as committed.
    pub(crate) fn abort_tree_edge_split(
        &self,
        tree_key: TreeKey,
        parent: NodeIdentifier,
        child: NodeIdentifier,
        now: Instant,
    ) -> bool {
        let mut bindings = self.tree_edge_bindings.lock();
        let Some(binding) = bindings.get_mut(&TreeEdgeBindingKey::new(tree_key, parent, child))
        else {
            return false;
        };
        let Some(TreeEdgeSplitState::Splitting { from, to, .. }) = binding.transition else {
            return false;
        };
        binding.transition = None;
        binding.path = from;
        binding.entered_at = now;
        // The adopted first hop failed to send; the sender fell back to the old
        // route. Keep the failed first hop out of contention while it cools.
        self.record_tree_edge_split_abort(parent, child, to.first_hop(child), now);
        distribution_metrics::record_split_abort(parent, child, "primary_failed");
        distribution_metrics::record_tree_edge_binding_event(
            parent,
            child,
            to.mode_label(),
            from.mode_label(),
            "transition_abort",
        );
        distribution_metrics::update_tree_edge_binding(
            parent,
            child,
            Some(to.mode_label()),
            Some(from.mode_label()),
        );
        distribution_metrics::update_tree_edge_transition(parent, child, false);
        distribution_metrics::update_tree_edge_split_share(parent, child, None);
        true
    }
    #[cfg(test)]
    pub(crate) fn current_tree_edge_path(
        &self,
        tree_key: TreeKey,
        parent: NodeIdentifier,
        child: NodeIdentifier,
    ) -> Option<TreeEdgePath> {
        self.tree_edge_bindings
            .lock()
            .get(&TreeEdgeBindingKey::new(tree_key, parent, child))
            .filter(|binding| binding.bound)
            .map(|binding| binding.path)
    }

    pub(crate) fn choose_tree_edge(
        &self,
        tree_key: TreeKey,
        parent: NodeIdentifier,
        child: NodeIdentifier,
        mut candidates: Vec<TreeEdgeCandidate>,
        policy: TreeEdgeStickinessPolicy,
        now: Instant,
    ) -> TreeEdgeAttempt {
        let key = TreeEdgeBindingKey::new(tree_key, parent, child);
        // Cost-primary so the cheapest whole-path route wins the initial pick
        // and the deterministic ordering mirrors the cost-primary decision in
        // `candidate_is_better`.
        candidates.sort_by_key(|candidate| {
            (
                candidate.route_cost,
                candidate.pressure,
                candidate.path.first_hop(child),
            )
        });

        let mut bindings = self.tree_edge_bindings.lock();
        prune_tree_edge_bindings(&mut bindings, key, policy.idle_reset, now);
        let binding = bindings.entry(key).or_insert(TreeEdgeBinding {
            path: TreeEdgePath::DirectChild,
            entered_at: now,
            last_used_at: now,
            challenger: None,
            challenger_since: None,
            challenger_observations: 0,
            pending: Some((TreeEdgePath::DirectChild, "initial")),
            pending_held: Duration::ZERO,
            pending_confirmation: Duration::ZERO,
            generation: 1,
            bound: false,
            no_alternate_reported: false,
            transition: None,
        });

        let incumbent = candidate_for(&candidates, binding.path);

        if !binding.bound && binding.pending == Some((TreeEdgePath::DirectChild, "initial")) {
            if let Some(replacement) = candidates
                .iter()
                .copied()
                .find(|candidate| candidate.pressure < 3)
            {
                binding.pending = Some((replacement.path, "initial"));
            }
        }
        if let Some((path, reason)) = binding.pending {
            return TreeEdgeAttempt {
                key,
                path,
                generation: binding.generation,
                reason,
                incumbent_pressure: incumbent.map(|candidate| candidate.pressure),
                chosen_pressure: candidate_for(&candidates, path)
                    .map(|candidate| candidate.pressure),
            };
        }

        // Drive an in-flight weighted split. The controller owns the edge until
        // it commits or aborts: no new challenger may interrupt the fade.
        if let Some(mut transition) = binding.transition {
            // An active transition is the edge in use (the controller owns the
            // edge every frame), so it must not be pruned as idle mid-fade or
            // mid-hold — an interior hold is a long-lived steady state, not a
            // brief switch, and would be torn down by idle pruning otherwise.
            binding.last_used_at = now;
            let TreeEdgeSplitState::Splitting { from, to, share, phase, .. } = transition;
            let phase_before = phase;
            let to_quality = loaded_quality_for(candidate_for(&candidates, binding.path));
            let from_quality = loaded_quality_for(candidate_for(&candidates, from));
            match transition.reduce(now, to_quality, from_quality, policy) {
                TreeEdgeTransitionStep::Complete => {
                    binding.transition = None;
                    distribution_metrics::update_tree_edge_split_share(parent, child, None);
                    distribution_metrics::record_tree_edge_binding_event(
                        parent,
                        child,
                        from.mode_label(),
                        binding.path.mode_label(),
                        "transition_complete",
                    );
                    distribution_metrics::update_tree_edge_transition(parent, child, false);
                }
                TreeEdgeTransitionStep::Abort { reason } => {
                    let rollback = from;
                    binding.transition = None;
                    binding.path = rollback;
                    binding.entered_at = now;
                    // The challenger's first hop looked good while idle but
                    // degraded under load: keep it out of contention until its
                    // loaded metrics could be re-established.
                    self.record_tree_edge_split_abort(
                        parent,
                        child,
                        to.first_hop(child),
                        now,
                    );
                    distribution_metrics::record_split_abort(parent, child, reason);
                    distribution_metrics::update_tree_edge_split_share(parent, child, None);
                    distribution_metrics::record_tree_edge_binding_event(
                        parent,
                        child,
                        to.mode_label(),
                        rollback.mode_label(),
                        "transition_abort",
                    );
                    distribution_metrics::update_tree_edge_binding(
                        parent,
                        child,
                        Some(to.mode_label()),
                        Some(rollback.mode_label()),
                    );
                    distribution_metrics::update_tree_edge_transition(parent, child, false);
                }
                TreeEdgeTransitionStep::Active => {
                    // Persist the advanced weight for the sender this frame.
                    // Record an entry into the phase the controller advanced to,
                    // so the fanout→adjusting→holds_interior progression (and a
                    // premature abort) is visible per edge in the dashboards.
                    let TreeEdgeSplitState::Splitting {
                        phase: phase_after, ..
                    } = transition;
                    if phase_after != phase_before {
                        distribution_metrics::record_split_phase(
                            parent,
                            child,
                            phase_after.label(),
                        );
                    }
                    binding.transition = Some(transition);
                    distribution_metrics::update_tree_edge_split_share(parent, child, Some(share));
                }
            }
            return TreeEdgeAttempt {
                key,
                path: binding.path,
                generation: binding.generation,
                reason: "transition",
                incumbent_pressure: candidate_for(&candidates, to)
                    .map(|candidate| candidate.pressure),
                chosen_pressure: candidate_for(&candidates, binding.path)
                    .map(|candidate| candidate.pressure),
            };
        }

        // A missing, closed, or fully pressured incumbent is a hard failure.
        if incumbent.is_none_or(|candidate| candidate.pressure >= 3) {
            let replacement = candidates
                .iter()
                .copied()
                .find(|candidate| candidate.path != binding.path && candidate.pressure < 3);
            if let Some(replacement) = replacement.filter(|candidate| candidate.pressure < 3) {
                begin_tree_edge_transition(binding, replacement.path, "transport_unavailable", now);
            } else {
                clear_tree_edge_challenger(binding);
                record_no_tree_edge_alternate(key, binding);
            }
            let (path, reason) = binding.pending.unwrap_or((binding.path, "no_alternate"));
            return TreeEdgeAttempt {
                key,
                path,
                generation: binding.generation,
                reason,
                incumbent_pressure: incumbent.map(|candidate| candidate.pressure),
                chosen_pressure: candidate_for(&candidates, path)
                    .map(|candidate| candidate.pressure),
            };
        }

        let challenger = candidates
            .iter()
            .copied()
            .filter(|candidate| {
                candidate.path != binding.path
                    && candidate.pressure < 3
                    && !self.voice_route_first_hop_cooling_down(
                        parent,
                        child,
                        candidate.path.first_hop(child),
                        now,
                    )
            })
            .find(|candidate| {
                incumbent.is_some_and(|current| {
                    candidate_is_better(
                        *candidate,
                        current,
                        self.voice_route_first_hop_idle(candidate.path.first_hop(child), now),
                    )
                })
            });

        if let Some(challenger) = challenger {
            observe_tree_edge_challenger(binding, challenger.path, now);
            if now.saturating_duration_since(binding.entered_at) >= policy.min_hold
                && binding.challenger_observations >= 2
                && binding.challenger_since.is_some_and(|since| {
                    now.saturating_duration_since(since) >= policy.challenger_confirm
                })
            {
                begin_tree_edge_transition(binding, challenger.path, "confirmed_challenger", now);
            }
        } else {
            clear_tree_edge_challenger(binding);
        }

        let (path, reason) = binding.pending.unwrap_or((binding.path, "incumbent"));
        TreeEdgeAttempt {
            key,
            path,
            generation: binding.generation,
            reason,
            incumbent_pressure: incumbent.map(|candidate| candidate.pressure),
            chosen_pressure: candidate_for(&candidates, path).map(|candidate| candidate.pressure),
        }
    }

    pub(crate) fn hard_escape_tree_edge(
        &self,
        attempt: TreeEdgeAttempt,
        mut candidates: Vec<TreeEdgeCandidate>,
        reason: &'static str,
        now: Instant,
    ) -> Option<TreeEdgeAttempt> {
        // Cost-primary, mirroring the soft path (`choose_tree_edge`): among
        // live alternates the cheapest whole-path route wins, not the first
        // sub-3-pressure relay. Unverified (seeded) alternates sort last so the
        // verified pick is always preferred when one exists.
        candidates.sort_by_key(|candidate| {
            (
                candidate.route_cost,
                candidate.pressure,
                !candidate.verified,
                candidate.path.first_hop(attempt.key.child),
            )
        });
        let mut bindings = self.tree_edge_bindings.lock();
        let binding = bindings.get_mut(&attempt.key)?;
        if binding.generation != attempt.generation {
            if binding.path != attempt.path
                && let Some(current) = candidate_for(&candidates, binding.path)
                    .filter(|candidate| candidate.pressure < 3)
            {
                return Some(TreeEdgeAttempt {
                    key: attempt.key,
                    path: current.path,
                    generation: binding.generation,
                    reason,
                    incumbent_pressure: candidate_for(&candidates, attempt.path)
                        .map(|candidate| candidate.pressure),
                    chosen_pressure: Some(current.pressure),
                });
            }
            // A sibling completion may have committed the same pending path.
            // Its rejection still needs one escape retry, but it must create a
            // fresh generation rather than completing the stale decision.
        }
        binding.pending = None;
        // Warm-gate preference: a verified alternate whose first hop has
        // actually carried voice traffic through this plane is the reliable
        // escape target. Escaping onto an idle lane is what re-arms the
        // "looked good while idle, degraded under load" abort loop, so a warm
        // alternate beats a cheaper cold one. Fall back to the cheapest verified
        // alternate, then to the seeded (unverified) routing-table alternate as
        // a last resort — trying it beats dropping the frame outright.
        let verified = || {
            candidates.iter().copied().filter(|candidate| {
                candidate.path != attempt.path && candidate.verified && candidate.pressure < 3
            })
        };
        let replacement = verified()
            .find(|candidate| {
                !self.voice_route_first_hop_idle(candidate.path.first_hop(attempt.key.child), now)
            })
            .or_else(|| verified().next())
            .or_else(|| {
                candidates.iter().copied().find(|candidate| {
                    candidate.path != attempt.path && !candidate.verified
                })
            });
        let Some(replacement) = replacement else {
            record_no_tree_edge_alternate(attempt.key, binding);
            return None;
        };
        begin_tree_edge_transition(binding, replacement.path, reason, now);
        Some(TreeEdgeAttempt {
            key: attempt.key,
            path: replacement.path,
            generation: binding.generation,
            reason,
            incumbent_pressure: candidate_for(&candidates, attempt.path)
                .map(|candidate| candidate.pressure),
            chosen_pressure: Some(replacement.pressure),
        })
    }

    pub(crate) fn complete_tree_edge_attempt(
        &self,
        attempt: TreeEdgeAttempt,
        success: bool,
        now: Instant,
    ) -> Option<TreeEdgeSplit> {
        let mut bindings = self.tree_edge_bindings.lock();
        let Some(binding) = bindings.get_mut(&attempt.key) else {
            return None;
        };
        if binding.generation != attempt.generation {
            return None;
        }
        if !success {
            if binding
                .pending
                .is_some_and(|(path, _)| path == attempt.path)
            {
                binding.pending = None;
                binding.generation = binding.generation.wrapping_add(1).max(1);
            }
            return None;
        }

        let previous = binding.bound.then_some(binding.path);
        let changed = previous != Some(attempt.path);
        if !changed {
            binding.last_used_at = now;
            binding.no_alternate_reported = false;
            return None;
        }
        let held_for = binding.pending_held;
        let confirmation_for = binding.pending_confirmation;
        binding.path = attempt.path;
        binding.entered_at = changed.then_some(now).unwrap_or(binding.entered_at);
        binding.last_used_at = now;
        binding.bound = true;
        binding.no_alternate_reported = false;
        binding.pending = None;
        clear_tree_edge_challenger(binding);
        binding.generation = binding.generation.wrapping_add(1).max(1);
        // A confirmed challenger starts a weighted split instead of a flat
        // overlap: the old route keeps its full load through the probe window
        // (`share = 0.0`), then the sender fades it out under the challenger's
        // loaded quality (see `TreeEdgeSplitState::reduce`).
        let split = if previous.is_some() && attempt.reason == "confirmed_challenger" {
            let previous = previous.expect("checked previous");
            binding.transition = Some(TreeEdgeSplitState::Splitting {
                from: previous,
                to: attempt.path,
                share: 0.0,
                target: 1.0,
                phase: SplitPhase::Fanout,
                phase_started_at: now,
                last_ramp_at: now,
                degraded_observations: 0,
            });
            distribution_metrics::record_tree_edge_binding_event(
                attempt.key.parent,
                attempt.key.child,
                previous.mode_label(),
                attempt.path.mode_label(),
                "transition_begin",
            );
            distribution_metrics::update_tree_edge_transition(
                attempt.key.parent,
                attempt.key.child,
                true,
            );
            distribution_metrics::record_split_phase(
                attempt.key.parent,
                attempt.key.child,
                SplitPhase::Fanout.label(),
            );
            distribution_metrics::update_tree_edge_split_share(
                attempt.key.parent,
                attempt.key.child,
                Some(0.0),
            );
            Some(TreeEdgeSplit {
                from: previous,
                to: attempt.path,
                share: 0.0,
                interior_hold: false,
            })
        } else {
            None
        };
        if changed {
            distribution_metrics::update_tree_edge_binding(
                attempt.key.parent,
                attempt.key.child,
                previous.map(TreeEdgePath::mode_label),
                Some(attempt.path.mode_label()),
            );
            distribution_metrics::record_tree_edge_binding_event(
                attempt.key.parent,
                attempt.key.child,
                previous.map(TreeEdgePath::mode_label).unwrap_or("none"),
                attempt.path.mode_label(),
                attempt.reason,
            );
            debug!(
                source = %attempt.key.parent,
                peer = %attempt.key.child,
                from_mode = previous.map(TreeEdgePath::mode_label).unwrap_or("none"),
                to_mode = attempt.path.mode_label(),
                reason = attempt.reason,
                held_ms = held_for.as_millis(),
                confirmation_ms = confirmation_for.as_millis(),
                incumbent_pressure = ?attempt.incumbent_pressure,
                chosen_pressure = ?attempt.chosen_pressure,
                chosen_peer = %match attempt.path {
                    TreeEdgePath::DirectChild => attempt.key.child,
                    TreeEdgePath::LegacyVia(first_hop) => first_hop,
                },
                "voice tree edge binding changed"
            );
        }
        split
    }

    pub(crate) fn configure_recovery(self: &Arc<Self>, sender: RecoverySender) {
        *self.recovery_sender.lock() = Some(sender);
        *self.self_ref.lock() = Arc::downgrade(self);
    }

    pub(crate) fn cached_candidate(
        &self,
        key: TreeKey,
        routing_generation: u64,
    ) -> Option<SelectedTree> {
        self.candidates
            .lock()
            .get(&TreeScope::from(key))
            .filter(|candidate| candidate.routing_generation == routing_generation)
            .filter(|candidate| candidate.recheck_at.is_none_or(|at| Instant::now() < at))
            .map(|candidate| SelectedTree {
                key: candidate.key,
                state: Arc::new(candidate.state.clone()),
                legacy_members: Arc::new(candidate.legacy_members.clone()),
            })
    }

    pub(crate) fn prepare_routing_generation(&self, key: TreeKey, routing_generation: u64) {
        let scope = StableTreeScope::from(key);
        self.prune_scope_state(scope);
        let previous_generation = self
            .routing_generations
            .lock()
            .insert(scope, routing_generation);
        let generation_changed = previous_generation != Some(routing_generation);
        let structural_change = self
            .active_trees
            .lock()
            .get(&scope)
            .is_some_and(|active| active.key.topology_epoch != key.topology_epoch);
        if generation_changed || structural_change {
            distribution_metrics::record_candidate_trigger(
                key.profile,
                if previous_generation.is_none() {
                    "group"
                } else if structural_change {
                    "topology"
                } else {
                    "routing"
                },
            );
        }
        if structural_change {
            // A topology epoch proves that service-eligible adjacency changed.
            // Metric-only recomputes are not evidence that a failed edge healed;
            // those exclusions clear only after a successful direct send or TTL.
            self.failed_edges.lock().remove(&scope);
        }
    }

    #[cfg(test)]
    pub(crate) fn stage_candidate(
        &self,
        key: TreeKey,
        candidate: TreeState,
        path_cost: u64,
        routing_generation: u64,
    ) -> Option<SelectedTree> {
        self.stage_candidate_with_legacy(
            key,
            candidate,
            path_cost,
            routing_generation,
            HashSet::new(),
        )
    }

    pub(crate) fn stage_candidate_with_legacy(
        &self,
        key: TreeKey,
        candidate: TreeState,
        path_cost: u64,
        routing_generation: u64,
        legacy_members: HashSet<NodeIdentifier>,
    ) -> Option<SelectedTree> {
        distribution_metrics::record_candidate_build(key.profile, "attempt");
        if !candidate.is_valid(key.source) {
            distribution_metrics::record_candidate_build(key.profile, "invalid");
            return None;
        }
        let stable_scope = StableTreeScope::from(key);
        self.prepare_routing_generation(key, routing_generation);
        let stale_keys = {
            let current_scope = TreeScope::from(key);
            let mut candidates = self.candidates.lock();
            let stale: Vec<_> = candidates
                .iter()
                .filter_map(|(scope, candidate)| {
                    (scope != &current_scope
                        && scope.source == stable_scope.source
                        && scope.profile == stable_scope.profile
                        && scope.group == stable_scope.group
                        && scope.group_version == stable_scope.group_version)
                        .then_some(candidate.key)
                })
                .collect();
            candidates.retain(|scope, _| {
                scope == &current_scope
                    || scope.source != stable_scope.source
                    || scope.profile != stable_scope.profile
                    || scope.group != stable_scope.group
                    || scope.group_version != stable_scope.group_version
            });
            stale
        };
        if !stale_keys.is_empty() {
            let mut pending = self.pending.lock();
            for stale_key in stale_keys {
                pending.remove(&stale_key);
            }
        }
        let currently_failed = self.failed_edges(key);
        if let Some(active) = self.active_trees.lock().get(&stable_scope).cloned() {
            let topology_changed = active.key.topology_epoch != key.topology_epoch;
            let capability_changed = active.legacy_members != legacy_members;
            if !topology_changed
                && same_tree_structure(&active.state, &candidate)
                && active.legacy_members == legacy_members
            {
                self.candidates.lock().insert(
                    TreeScope::from(key),
                    CandidateTree {
                        key: active.key,
                        state: active.state.clone(),
                        path_cost: active.path_cost,
                        routing_generation,
                        recheck_at: None,
                        legacy_members: active.legacy_members.clone(),
                    },
                );
                self.metric_proposals.lock().remove(&stable_scope);
                return Some(SelectedTree {
                    key: active.key,
                    state: Arc::new(active.state.clone()),
                    legacy_members: Arc::new(active.legacy_members.clone()),
                });
            }
            let failed_replacement = active.state.edges().any(|edge| {
                currently_failed.contains(&edge)
                    && active.applied_failures.contains(&edge)
                    && !candidate
                        .edges()
                        .any(|candidate_edge| candidate_edge == edge)
            });
            let improved = path_cost.saturating_mul(100)
                <= active
                    .path_cost
                    .saturating_mul(100 - METRIC_RESHAPE_IMPROVEMENT_PERCENT);
            let metric_ready = if improved {
                let mut proposals = self.metric_proposals.lock();
                let proposal = proposals
                    .entry(stable_scope)
                    .or_insert_with(|| MetricProposal {
                        state: candidate.clone(),
                        path_cost,
                        first_seen: Instant::now(),
                    });
                if !same_tree_structure(&proposal.state, &candidate) {
                    *proposal = MetricProposal {
                        state: candidate.clone(),
                        path_cost,
                        first_seen: Instant::now(),
                    };
                } else {
                    proposal.path_cost = path_cost;
                }
                proposal.first_seen.elapsed() >= METRIC_RESHAPE_HOLD
            } else {
                self.metric_proposals.lock().remove(&stable_scope);
                false
            };
            if !topology_changed && !capability_changed && !failed_replacement && !metric_ready {
                distribution_metrics::record_hysteresis_hold(key.profile);
                self.candidates.lock().insert(
                    TreeScope::from(key),
                    CandidateTree {
                        key: active.key,
                        state: active.state.clone(),
                        path_cost: active.path_cost,
                        routing_generation,
                        recheck_at: improved.then(|| {
                            self.metric_proposals
                                .lock()
                                .get(&stable_scope)
                                .expect("improved metric proposal installed")
                                .first_seen
                                + METRIC_RESHAPE_HOLD
                        }),
                        legacy_members: active.legacy_members.clone(),
                    },
                );
                return Some(SelectedTree {
                    key: active.key,
                    state: Arc::new(active.state.clone()),
                    legacy_members: Arc::new(active.legacy_members.clone()),
                });
            }
        }
        self.metric_proposals.lock().remove(&stable_scope);
        let selected = SelectedTree {
            key,
            state: Arc::new(candidate.clone()),
            legacy_members: Arc::new(legacy_members.clone()),
        };
        self.candidates.lock().insert(
            TreeScope::from(key),
            CandidateTree {
                key,
                state: candidate,
                path_cost,
                routing_generation,
                recheck_at: None,
                legacy_members,
            },
        );
        distribution_metrics::record_candidate_build(key.profile, "staged");
        Some(selected)
    }

    fn prune_scope_state(&self, current: StableTreeScope) {
        let stale = |scope: &StableTreeScope| {
            scope.source == current.source
                && scope.profile == current.profile
                && scope.group == current.group
                && scope.group_version != current.group_version
        };
        self.active_trees.lock().retain(|scope, _| !stale(scope));
        self.failed_edges.lock().retain(|scope, _| !stale(scope));
        self.metric_proposals
            .lock()
            .retain(|scope, _| !stale(scope));
        self.routing_generations
            .lock()
            .retain(|scope, _| !stale(scope));
        self.scope_activity.lock().retain(|scope, _| {
            scope.source != current.source
                || scope.profile != current.profile
                || scope.group != current.group
                || scope.group_version == current.group_version
        });
        self.candidates.lock().retain(|scope, _| {
            !(scope.source == current.source
                && scope.profile == current.profile
                && scope.group == current.group
                && scope.group_version != current.group_version)
        });
        self.pending.lock().retain(|key, _| {
            key.source != current.source
                || key.profile != current.profile
                || key.group != current.group
                || key.group_version == current.group_version
        });
        self.versions.lock().retain(|scope, _| {
            scope.source != current.source
                || scope.profile != current.profile
                || scope.group != current.group
                || scope.group_version == current.group_version
        });
        self.trees.lock().retain(|key, _| {
            key.source != current.source
                || key.profile != current.profile
                || key.group != current.group
                || key.group_version == current.group_version
        });
        let mut removed_bindings = Vec::new();
        self.tree_edge_bindings.lock().retain(|key, binding| {
            let stale = key.source == current.source
                && key.profile == current.profile
                && key.group == current.group
                && key.group_version != current.group_version;
            if stale && binding.bound {
                removed_bindings.push((*key, binding.path));
            }
            !stale
        });
        for (key, path) in removed_bindings {
            distribution_metrics::update_tree_edge_binding(
                key.parent,
                key.child,
                Some(path.mode_label()),
                None,
            );
        }
        let now = Instant::now();
        self.failure_reported_at.lock().retain(|_, reported_at| {
            now.saturating_duration_since(*reported_at) < EDGE_FAILURE_REPORT_DEDUP
        });
    }

    fn prune_tree_edge_bindings_for_tree(&self, key: TreeKey, state: &TreeState) {
        let edges: HashSet<_> = state.edges().collect();
        let mut removed = Vec::new();
        self.tree_edge_bindings
            .lock()
            .retain(|binding_key, binding| {
                let in_scope = binding_key.source == key.source
                    && binding_key.profile == key.profile
                    && binding_key.group == key.group
                    && binding_key.group_version == key.group_version;
                let keep = !in_scope || edges.contains(&(binding_key.parent, binding_key.child));
                if !keep && binding.bound {
                    removed.push((*binding_key, binding.path));
                }
                keep
            });
        for (binding_key, path) in removed {
            distribution_metrics::update_tree_edge_binding(
                binding_key.parent,
                binding_key.child,
                Some(path.mode_label()),
                None,
            );
        }
    }

    pub(crate) fn active_tree(&self, key: TreeKey) -> Option<SelectedTree> {
        self.active_trees
            .lock()
            .get(&StableTreeScope::from(key))
            .map(|active| SelectedTree {
                key: active.key,
                state: Arc::new(active.state.clone()),
                legacy_members: Arc::new(active.legacy_members.clone()),
            })
    }

    pub(crate) fn failed_edges(&self, key: TreeKey) -> HashSet<(NodeIdentifier, NodeIdentifier)> {
        let now = Instant::now();
        let mut failures = self.failed_edges.lock();
        let Some(edges) = failures.get_mut(&StableTreeScope::from(key)) else {
            return HashSet::new();
        };
        edges.retain(|_, failed_at| {
            now.saturating_duration_since(*failed_at) < FAILED_EDGE_EXCLUSION
        });
        edges.keys().copied().collect()
    }

    pub(crate) fn report_edge_failure(
        &self,
        key: TreeKey,
        parent: NodeIdentifier,
        child: NodeIdentifier,
    ) {
        if !self
            .get(key)
            .is_some_and(|tree| tree.edges().any(|edge| edge == (parent, child)))
        {
            return;
        }
        let now = Instant::now();
        {
            let mut reported = self.failure_reported_at.lock();
            reported.retain(|_, reported_at| {
                now.saturating_duration_since(*reported_at) < EDGE_FAILURE_REPORT_DEDUP
            });
            let report_key = (key.source, parent, child);
            if reported.get(&report_key).is_some_and(|reported_at| {
                now.saturating_duration_since(*reported_at) < EDGE_FAILURE_REPORT_DEDUP
            }) {
                return;
            }
            reported.insert(report_key, now);
        }
        let scope = StableTreeScope::from(key);
        let previous = self
            .failed_edges
            .lock()
            .entry(scope)
            .or_default()
            .insert((parent, child), now);
        if previous.is_some_and(|failed_at| {
            now.saturating_duration_since(failed_at) < FAILED_EDGE_EXCLUSION
        }) {
            return;
        }
        distribution_metrics::record_candidate_trigger(key.profile, "failed_edge");
        let invalidated: Vec<_> = self
            .candidates
            .lock()
            .iter()
            .filter_map(|(candidate_scope, candidate)| {
                (candidate_scope.source == scope.source
                    && candidate_scope.profile == scope.profile
                    && candidate_scope.group == scope.group
                    && candidate_scope.group_version == scope.group_version
                    && candidate.state.edges().any(|edge| edge == (parent, child)))
                .then_some(candidate.key)
            })
            .collect();
        self.candidates.lock().retain(|candidate_scope, _| {
            candidate_scope.source != scope.source
                || candidate_scope.profile != scope.profile
                || candidate_scope.group != scope.group
                || candidate_scope.group_version != scope.group_version
        });
        let mut pending = self.pending.lock();
        for invalidated_key in invalidated {
            pending.remove(&invalidated_key);
        }
        drop(pending);
        if let Some(active) = self
            .active_trees
            .lock()
            .get_mut(&StableTreeScope::from(key))
        {
            active.applied_failures.insert((parent, child));
        }
        distribution_metrics::record_reparent(key.profile);
        let (Some(plane), Some(sender)) = (
            self.self_ref.lock().upgrade(),
            self.recovery_sender.lock().clone(),
        ) else {
            return;
        };
        if sender.self_id == key.source {
            return;
        }
        tokio::spawn(async move {
            sender.send_failure(key, parent, child).await;
            drop(plane);
        });
    }

    pub(crate) fn record_edge_success(
        &self,
        key: TreeKey,
        parent: NodeIdentifier,
        child: NodeIdentifier,
    ) {
        let scope = StableTreeScope::from(key);
        let mut failures = self.failed_edges.lock();
        if let Some(edges) = failures.get_mut(&scope) {
            edges.remove(&(parent, child));
            if edges.is_empty() {
                failures.remove(&scope);
            }
        }
        drop(failures);
        if let Some(active) = self.active_trees.lock().get_mut(&scope) {
            active.applied_failures.remove(&(parent, child));
        }
    }

    pub(crate) fn install(&self, key: TreeKey, state: TreeState) -> Vec<PendingDistributionFrame> {
        self.try_install(key, state).unwrap_or_default()
    }

    fn try_install(&self, key: TreeKey, state: TreeState) -> Option<Vec<PendingDistributionFrame>> {
        if !state.is_valid(key.source) {
            distribution_metrics::record_candidate_build(key.profile, "invalid_install");
            return None;
        }
        self.prune_scope_state(StableTreeScope::from(key));
        self.prune_install_scopes(key);
        self.prune_tree_edge_bindings_for_tree(key, &state);
        let tree_edges = state.edges().count();
        let recovered = {
            // Queueing takes these locks in the same order so an install can
            // neither miss a newly queued frame nor replay it under another key.
            let mut trees = self.trees.lock();
            trees.insert(key, Arc::new(state));
            let mut unknown = self.unknown.lock();
            let frames = unknown
                .by_key
                .remove(&key)
                .unwrap_or_default()
                .into_iter()
                .map(|pending| pending.frame)
                .collect();
            unknown.total = unknown.by_key.values().map(Vec::len).sum();
            unknown.in_flight_requests.remove(&key);
            frames
        };
        self.record_installed_version(key);
        distribution_metrics::set_tree_edges(key.profile, tree_edges);
        Some(recovered)
    }

    fn prune_install_scopes(&self, key: TreeKey) {
        let current = TreeScope::from(key);
        let stable = StableTreeScope::from(key);
        let active_scope = self
            .active_trees
            .lock()
            .get(&stable)
            .map(|active| TreeScope::from(active.key));
        let stale = {
            let mut activity = self.scope_activity.lock();
            activity.insert(current, Instant::now());
            let mut matching: Vec<_> = activity
                .iter()
                .filter(|(scope, _)| {
                    scope.source == stable.source
                        && scope.profile == stable.profile
                        && scope.group == stable.group
                        && scope.group_version == stable.group_version
                })
                .map(|(scope, at)| (*scope, *at))
                .collect();
            matching.sort_unstable_by_key(|(_, at)| std::cmp::Reverse(*at));
            let mut retained: HashSet<_> = matching
                .iter()
                .take(RETAINED_VERSIONS)
                .map(|(scope, _)| *scope)
                .collect();
            retained.insert(current);
            retained.extend(active_scope);
            let stale: HashSet<_> = matching
                .into_iter()
                .map(|(scope, _)| scope)
                .filter(|scope| !retained.contains(scope))
                .collect();
            activity.retain(|scope, _| !stale.contains(scope));
            stale
        };
        if stale.is_empty() {
            return;
        }
        self.versions
            .lock()
            .retain(|scope, _| !stale.contains(scope));
        self.trees
            .lock()
            .retain(|tree_key, _| !stale.contains(&TreeScope::from(*tree_key)));
    }

    fn record_installed_version(&self, key: TreeKey) {
        let evicted = {
            let mut versions = self.versions.lock();
            let history = versions.entry(TreeScope::from(key)).or_default();
            history.record_install(key.version);
            history.evicted_versions()
        };
        if !evicted.is_empty() {
            let mut trees = self.trees.lock();
            for version in evicted {
                trees.remove(&TreeKey { version, ..key });
            }
        }
    }

    fn record_activated_version(&self, key: TreeKey) {
        let evicted = {
            let mut versions = self.versions.lock();
            let history = versions.entry(TreeScope::from(key)).or_default();
            history.record_install(key.version);
            history.record_activation(key.version);
            history.evicted_versions()
        };
        if !evicted.is_empty() {
            let mut trees = self.trees.lock();
            for version in evicted {
                trees.remove(&TreeKey { version, ..key });
            }
        }
    }

    pub(crate) fn get(&self, key: TreeKey) -> Option<Arc<TreeState>> {
        self.trees.lock().get(&key).cloned()
    }

    pub(crate) fn begin_publish(
        &self,
        key: TreeKey,
        peers: impl IntoIterator<Item = NodeIdentifier>,
    ) -> bool {
        let remaining: HashSet<NodeIdentifier> = peers.into_iter().collect();
        let remaining_count = remaining.len();
        let mut pending = self.pending.lock();
        if pending.contains_key(&key) {
            return false;
        }
        pending.insert(key, PendingAcks { remaining });
        drop(pending);
        #[cfg(test)]
        {
            *self.control_publishes.lock() += 1;
        }
        distribution_metrics::record_control_publish(key.profile);
        distribution_metrics::set_pending_acks(key.profile, remaining_count);
        if remaining_count == 0 {
            self.activate_candidate(key);
        }
        true
    }

    #[cfg(test)]
    pub(crate) fn control_publish_count_for_test(&self) -> u64 {
        *self.control_publishes.lock()
    }

    /// Forget a failed publish so the next source frame can retry the exact
    /// tree install while continuing to use the compatibility data path.
    pub(crate) fn abort_publish(&self, key: TreeKey) {
        let removed = {
            let mut pending = self.pending.lock();
            if pending
                .get(&key)
                .is_some_and(|pending| !pending.remaining.is_empty())
            {
                pending.remove(&key);
                true
            } else {
                false
            }
        };
        if removed {
            distribution_metrics::set_pending_acks(key.profile, 0);
        }
    }

    pub(crate) fn expire_candidate(&self, key: TreeKey) {
        self.abort_publish(key);
        let scope = TreeScope::from(key);
        self.candidates
            .lock()
            .retain(|candidate_scope, candidate| candidate_scope != &scope || candidate.key != key);
    }

    pub(crate) fn pending_peers(&self, key: TreeKey) -> Vec<NodeIdentifier> {
        self.pending
            .lock()
            .get(&key)
            .map(|pending| pending.remaining.iter().copied().collect())
            .unwrap_or_default()
    }

    pub(crate) fn acknowledge(&self, key: TreeKey, node: NodeIdentifier) {
        let (remaining, activated) = {
            let mut pending = self.pending.lock();
            let Some(entry) = pending.get_mut(&key) else {
                return;
            };
            let was_pending = !entry.remaining.is_empty();
            entry.remaining.remove(&node);
            (
                entry.remaining.len(),
                was_pending && entry.remaining.is_empty(),
            )
        };
        distribution_metrics::record_control_ack(key.profile);
        distribution_metrics::set_pending_acks(key.profile, remaining);
        if activated {
            self.activate_candidate(key);
        }
    }

    fn activate_candidate(&self, key: TreeKey) {
        let scope = TreeScope::from(key);
        let candidate = self.candidates.lock().get(&scope).cloned();
        let Some(candidate) = candidate else { return };
        if candidate.key != key {
            return;
        }
        let failed_edges = self.failed_edges(key);
        if candidate
            .state
            .edges()
            .any(|edge| failed_edges.contains(&edge))
        {
            self.pending.lock().remove(&key);
            return;
        }
        let applied_failures = failed_edges
            .into_iter()
            .filter(|failed| !candidate.state.edges().any(|edge| edge == *failed))
            .collect();
        self.prune_tree_edge_bindings_for_tree(key, &candidate.state);
        self.active_trees.lock().insert(
            StableTreeScope::from(key),
            ActiveTree {
                key,
                state: candidate.state,
                path_cost: candidate.path_cost,
                applied_failures,
                legacy_members: candidate.legacy_members,
            },
        );
        self.pending.lock().remove(&key);
        distribution_metrics::set_pending_acks(key.profile, 0);
        distribution_metrics::record_activation(key.profile);
        self.record_activated_version(key);
    }

    #[cfg(test)]
    pub(crate) fn is_ready(&self, key: TreeKey) -> bool {
        self.active_tree(key)
            .is_some_and(|active| active.key() == key)
            || self
                .pending
                .lock()
                .get(&key)
                .is_some_and(|pending| pending.remaining.is_empty())
    }

    /// Queue a frame for bounded exact-state recovery. The first frame for a
    /// key starts one request task; later frames coalesce onto that task.
    pub(crate) fn queue_unknown(
        &self,
        key: TreeKey,
        frame: PendingDistributionFrame,
        recovery_window: Duration,
    ) -> UnknownTreeEnqueue {
        let start_request = {
            // Keep the tree lock while enqueueing so `install` either drains
            // this frame or reports the exact state already present.
            let trees = self.trees.lock();
            if trees.contains_key(&key) {
                return UnknownTreeEnqueue::AlreadyInstalled(frame);
            }
            let mut unknown = self.unknown.lock();
            if unknown.total >= UNKNOWN_TREE_FRAMES_TOTAL
                || unknown
                    .by_key
                    .get(&key)
                    .is_some_and(|frames| frames.len() >= UNKNOWN_TREE_FRAMES_PER_KEY)
            {
                return UnknownTreeEnqueue::Full;
            }
            unknown.next_id = unknown.next_id.wrapping_add(1).max(1);
            let id = unknown.next_id;
            unknown
                .by_key
                .entry(key)
                .or_default()
                .push(PendingUnknownFrame { id, frame });
            unknown.total += 1;
            let start_request = unknown.in_flight_requests.insert(key);
            drop(unknown);
            drop(trees);
            self.schedule_unknown_expiry(key, id, recovery_window);
            start_request
        };

        if start_request {
            self.start_unknown_recovery(key);
        }
        UnknownTreeEnqueue::Queued
    }

    fn schedule_unknown_expiry(&self, key: TreeKey, id: u64, recovery_window: Duration) {
        let Some(plane) = self.self_ref.lock().upgrade() else {
            return;
        };
        tokio::spawn(async move {
            tokio::time::sleep(recovery_window).await;
            plane.expire_unknown(key, id);
        });
    }

    fn start_unknown_recovery(&self, key: TreeKey) {
        let (Some(plane), Some(sender)) = (
            self.self_ref.lock().upgrade(),
            self.recovery_sender.lock().clone(),
        ) else {
            return;
        };
        tokio::spawn(async move {
            sender.request(key).await;
            tokio::time::sleep(UNKNOWN_TREE_RECOVERY_RETRY).await;
            if plane.has_unknown(key) && plane.get(key).is_none() {
                sender.request(key).await;
            }
        });
    }

    fn has_unknown(&self, key: TreeKey) -> bool {
        self.unknown
            .lock()
            .by_key
            .get(&key)
            .is_some_and(|frames| !frames.is_empty())
    }

    fn expire_unknown(&self, key: TreeKey, id: u64) {
        let mut unknown = self.unknown.lock();
        let Some((removed, empty)) = unknown.by_key.get_mut(&key).map(|frames| {
            let before = frames.len();
            frames.retain(|pending| pending.id != id);
            (before.saturating_sub(frames.len()), frames.is_empty())
        }) else {
            return;
        };
        unknown.total = unknown.total.saturating_sub(removed);
        if empty {
            unknown.by_key.remove(&key);
            unknown.in_flight_requests.remove(&key);
        }
    }

    #[cfg(test)]
    fn unknown_frame_count(&self) -> usize {
        self.unknown.lock().total
    }
}

pub(crate) fn tree_version(
    source: NodeIdentifier,
    profile: u32,
    group: u64,
    group_version: u64,
    topology_epoch: u64,
    state: &TreeState,
) -> u64 {
    // Stable FNV-1a avoids process-random hashing and makes independent
    // publishers produce the same version for the same topology snapshot.
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut members: Vec<_> = state.members().collect();
    members.sort_unstable();
    let mut edges: Vec<_> = state.edges().collect();
    edges.sort_unstable();
    for value in std::iter::once(u64::from(source))
        .chain([
            u64::from(profile),
            group,
            group_version,
            topology_epoch,
            state
                .hop_ttl()
                .map(|ttl| ttl.as_millis().min(u128::from(u64::MAX)) as u64)
                .unwrap_or_default(),
        ])
        .chain(members.into_iter().map(u64::from))
        .chain(
            edges
                .into_iter()
                .flat_map(|(parent, child)| [u64::from(parent), u64::from(child)]),
        )
    {
        hash ^= value;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash.max(1)
}

pub(crate) fn register_control_handler(overlay: &OverlayNetwork) {
    overlay
        .inner
        .distribution
        .configure_recovery(RecoverySender {
            transport: overlay.inner.transport.clone(),
            routing: overlay.inner.routing.clone(),
            ordering: overlay.inner.ordering().clone(),
            self_id: overlay.inner.self_id,
            boot_epoch: overlay.inner.boot_epoch,
        });
    overlay.register_service(
        DISTRIBUTION_CONTROL_SERVICE_TAG,
        Arc::new(DistributionControlHandler {
            overlay: overlay.clone(),
            plane: overlay.inner.distribution.clone(),
        }),
    );
}

pub(crate) fn encode_install(key: TreeKey, state: &TreeState) -> Bytes {
    encode_control(pb::DistributionControl {
        body: Some(pb::distribution_control::Body::Install(
            pb::DistributionTreeInstall {
                source: key.source.into(),
                profile: key.profile,
                version: key.version,
                group: key.group,
                group_version: key.group_version,
                topology_epoch: key.topology_epoch,
                members: state.members().map(u32::from).collect(),
                // Reserved wire field for mixed-version compatibility. New
                // senders intentionally do not publish playout policy.
                playout_delays: Vec::new(),
                edges: state
                    .edges()
                    .map(|(parent, child)| pb::OverlayTreeEdge {
                        parent: parent.into(),
                        child: child.into(),
                    })
                    .collect(),
                hop_ttl_ms: state
                    .hop_ttl()
                    .map(|ttl| ttl.as_millis().min(u128::from(u32::MAX)) as u32)
                    .unwrap_or_default(),
            },
        )),
    })
}

pub(crate) fn encode_request(key: TreeKey, requester: NodeIdentifier) -> Bytes {
    encode_control(pb::DistributionControl {
        body: Some(pb::distribution_control::Body::Request(
            pb::DistributionTreeRequest {
                source: key.source.into(),
                profile: key.profile,
                version: key.version,
                requester: requester.into(),
                group: key.group,
                group_version: key.group_version,
                topology_epoch: key.topology_epoch,
            },
        )),
    })
}

pub(crate) fn encode_failure(key: TreeKey, parent: NodeIdentifier, child: NodeIdentifier) -> Bytes {
    encode_control(pb::DistributionControl {
        body: Some(pb::distribution_control::Body::Failure(
            pb::DistributionTreeFailure {
                source: key.source.into(),
                profile: key.profile,
                version: key.version,
                group: key.group,
                group_version: key.group_version,
                topology_epoch: key.topology_epoch,
                parent: parent.into(),
                child: child.into(),
            },
        )),
    })
}

fn encode_control(control: pb::DistributionControl) -> Bytes {
    let mut buf = BytesMut::with_capacity(control.encoded_len());
    control
        .encode(&mut buf)
        .expect("distribution control encode");
    buf.freeze()
}

fn installed_tree_state(
    source: NodeIdentifier,
    install: &pb::DistributionTreeInstall,
) -> TreeState {
    let members = install
        .members
        .iter()
        .filter_map(|node| NodeIdentifier::try_from(*node).ok());
    let edges = install.edges.iter().filter_map(|edge| {
        Some((
            NodeIdentifier::try_from(edge.parent).ok()?,
            NodeIdentifier::try_from(edge.child).ok()?,
        ))
    });
    // `playout_delays` remains decodable on the wire for mixed deployments,
    // but remote playout is no longer a distribution-tree concern.
    let state = TreeState::new(source, members, edges);
    if install.hop_ttl_ms == 0 {
        state
    } else {
        state.with_hop_ttl(Duration::from_millis(u64::from(install.hop_ttl_ms)))
    }
}

struct DistributionControlHandler {
    overlay: OverlayNetwork,
    plane: Arc<DistributionPlane>,
}

impl ServiceInbound for DistributionControlHandler {
    fn handle(&self, msg: OverlayInboundMessage) {
        let reporter = msg.from;
        let Ok(control) = pb::DistributionControl::decode(msg.body) else {
            return;
        };
        let overlay = self.overlay.clone();
        let plane = self.plane.clone();
        tokio::spawn(async move {
            let Some(body) = control.body else {
                return;
            };
            match body {
                pb::distribution_control::Body::Install(install) => {
                    let Ok(source) = NodeIdentifier::try_from(install.source) else {
                        return;
                    };
                    let key = TreeKey {
                        source,
                        profile: install.profile,
                        group: install.group,
                        group_version: install.group_version,
                        topology_epoch: install.topology_epoch,
                        version: install.version,
                    };
                    let Some(recovered) =
                        plane.try_install(key, installed_tree_state(source, &install))
                    else {
                        return;
                    };
                    let ack = encode_control(pb::DistributionControl {
                        body: Some(pb::distribution_control::Body::Ack(
                            pb::DistributionTreeAck {
                                source: source.into(),
                                profile: key.profile,
                                version: key.version,
                                node: overlay.local_node_id().into(),
                                group: key.group,
                                group_version: key.group_version,
                                topology_epoch: key.topology_epoch,
                            },
                        )),
                    });
                    let _ = overlay
                        .send_unicast_unordered_with_routing_metric(
                            source,
                            DISTRIBUTION_CONTROL_SERVICE_TAG,
                            ServiceLevel::ReliableLowLatency,
                            RoutingMetric::ReliableLowLatencyCost,
                            MessageClass::Control,
                            ack,
                        )
                        .await;
                    for frame in recovered {
                        let overlay = overlay.clone();
                        tokio::spawn(async move {
                            super::messaging::forward::replay_distribution_frame(overlay, frame)
                                .await;
                        });
                    }
                }
                pb::distribution_control::Body::Ack(ack) => {
                    let (Ok(source), Ok(node)) = (
                        NodeIdentifier::try_from(ack.source),
                        NodeIdentifier::try_from(ack.node),
                    ) else {
                        return;
                    };
                    if reporter != node {
                        return;
                    }
                    if source == overlay.local_node_id() {
                        plane.acknowledge(
                            TreeKey {
                                source,
                                profile: ack.profile,
                                group: ack.group,
                                group_version: ack.group_version,
                                topology_epoch: ack.topology_epoch,
                                version: ack.version,
                            },
                            node,
                        );
                    }
                }
                pb::distribution_control::Body::Request(request) => {
                    let (Ok(source), Ok(requester)) = (
                        NodeIdentifier::try_from(request.source),
                        NodeIdentifier::try_from(request.requester),
                    ) else {
                        return;
                    };
                    if source != overlay.local_node_id() {
                        return;
                    }
                    distribution_metrics::record_state_request(request.profile);
                    let key = TreeKey {
                        source,
                        profile: request.profile,
                        group: request.group,
                        group_version: request.group_version,
                        topology_epoch: request.topology_epoch,
                        version: request.version,
                    };
                    let Some(tree) = plane.get(key) else {
                        return;
                    };
                    let _ = overlay
                        .send_unicast_unordered_with_routing_metric(
                            requester,
                            DISTRIBUTION_CONTROL_SERVICE_TAG,
                            ServiceLevel::ReliableLowLatency,
                            RoutingMetric::ReliableLowLatencyCost,
                            MessageClass::Control,
                            encode_install(key, &tree),
                        )
                        .await;
                }
                pb::distribution_control::Body::Failure(failure) => {
                    let (Ok(source), Ok(parent), Ok(child)) = (
                        NodeIdentifier::try_from(failure.source),
                        NodeIdentifier::try_from(failure.parent),
                        NodeIdentifier::try_from(failure.child),
                    ) else {
                        return;
                    };
                    // A relay reports its own failed send, while a receiver
                    // can report expiry of its parent edge. Do not let an
                    // unrelated control sender poison a source tree.
                    if reporter != parent && reporter != child {
                        return;
                    }
                    if source == overlay.local_node_id() {
                        plane.report_edge_failure(
                            TreeKey {
                                source,
                                profile: failure.profile,
                                group: failure.group,
                                group_version: failure.group_version,
                                topology_epoch: failure.topology_epoch,
                                version: failure.version,
                            },
                            parent,
                            child,
                        );
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "pre-release-workload")]
    #[test]
    fn pre_release_service_selects_reliable_generic_profile() {
        let profile = profile_for_service(super::super::PRE_RELEASE_DISTRIBUTION_SERVICE_TAG)
            .expect("pre-release distribution profile");
        assert_eq!(profile.id(), PRE_RELEASE_RELIABLE_PROFILE_ID);
        assert_eq!(profile.level(), ServiceLevel::ReliableLowLatency);
        assert_eq!(profile.metric(), RoutingMetric::ReliableLowLatencyCost);
        assert!(profile_for_service(crate::application::proto::VOICE_SERVICE_TAG).is_some());
    }

    #[cfg(feature = "pre-release-workload")]
    #[test]
    fn candidate_trigger_counts_distinct_routing_generations() {
        let plane = DistributionPlane::default();
        let mut candidate = key(77, 1);
        candidate.profile = PRE_RELEASE_RELIABLE_PROFILE_ID;
        let before = distribution_metrics::pre_release_counters().3;

        plane.prepare_routing_generation(candidate, 10);
        plane.prepare_routing_generation(candidate, 10);
        plane.prepare_routing_generation(candidate, 11);

        assert_eq!(distribution_metrics::pre_release_counters().3 - before, 2);
    }

    fn key(group: u64, version: u64) -> TreeKey {
        TreeKey {
            source: 1,
            profile: VOICE_REALTIME_PROFILE_ID,
            group,
            group_version: 1,
            topology_epoch: 1,
            version,
        }
    }

    fn sticky_policy() -> TreeEdgeStickinessPolicy {
        TreeEdgeStickinessPolicy::new(
            Duration::from_millis(750),
            Duration::from_millis(500),
            Duration::from_secs(2),
            Duration::from_millis(700),
            Duration::from_millis(400),
            false,
            0.1,
            0.3,
        )
    }

    fn fast_sticky_policy() -> TreeEdgeStickinessPolicy {
        TreeEdgeStickinessPolicy::new(
            Duration::from_millis(250),
            Duration::from_millis(500),
            Duration::from_secs(2),
            Duration::from_millis(700),
            Duration::from_millis(400),
            false,
            0.1,
            0.3,
        )
    }

    #[test]
    fn confirmed_switch_starts_split_and_completes_after_fade() {
        let plane = DistributionPlane::default();
        let tree_key = key(94, 1);
        let start = Instant::now();
        let at = |ms: u64| start + Duration::from_millis(ms);
        let initial = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![TreeEdgeCandidate::direct_with_cost(1, 40)],
            fast_sticky_policy(),
            start,
        );
        let _ = plane.complete_tree_edge_attempt(initial, true, start);

        let candidates = || {
            vec![
                TreeEdgeCandidate::direct_with_cost(1, 40),
                TreeEdgeCandidate::legacy(4097, 1, 3),
            ]
        };
        let first = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            candidates(),
            fast_sticky_policy(),
            at(250),
        );
        assert_eq!(first.path(), TreeEdgePath::DirectChild);
        let confirmed = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            candidates(),
            fast_sticky_policy(),
            at(750),
        );
        assert_eq!(confirmed.path(), TreeEdgePath::LegacyVia(4097));
        let split = plane
            .complete_tree_edge_attempt(confirmed, true, at(750))
            .expect("confirmed switch starts a split");
        assert_eq!(split.from(), TreeEdgePath::DirectChild);
        assert_eq!(split.share(), 0.0, "probe window duplicates voice onto both routes");

        // Through the fanout window the split stays active and the old route
        // keeps its full load (share stays at the probe value).
        for ms in (760..=1400).step_by(50) {
            let attempt =
                plane.choose_tree_edge(tree_key, 1, 2, candidates(), fast_sticky_policy(), at(ms));
            assert_eq!(attempt.path(), TreeEdgePath::LegacyVia(4097));
            let split = plane
                .active_tree_edge_split(tree_key, 1, 2)
                .expect("split stays active through fanout");
            assert_eq!(split.from(), TreeEdgePath::DirectChild);
            assert_eq!(split.share(), 0.0);
        }

        // After fanout + fade + confirm the transition commits on a healthy
        // challenger, dropping the old route entirely.
        let completion = (0..100u64).find_map(|i| {
            let ms = 1450 + i * 50;
            let attempt =
                plane.choose_tree_edge(tree_key, 1, 2, candidates(), fast_sticky_policy(), at(ms));
            plane
                .active_tree_edge_split(tree_key, 1, 2)
                .is_none()
                .then_some((ms, attempt.path()))
        });
        let (done_at, path) = completion.expect("transition completes on a healthy challenger");
        assert_eq!(path, TreeEdgePath::LegacyVia(4097));
        assert_eq!(
            plane.current_tree_edge_path(tree_key, 1, 2),
            Some(TreeEdgePath::LegacyVia(4097))
        );
        assert!(
            done_at >= 750 + 700 + 400 + 150,
            "completes only after fanout+fade+confirm (was {done_at})"
        );
    }

    #[test]
    fn challenger_degradation_under_load_aborts_and_rolls_back() {
        let plane = DistributionPlane::default();
        let tree_key = key(97, 1);
        let start = Instant::now();
        let at = |ms: u64| start + Duration::from_millis(ms);
        let initial = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![TreeEdgeCandidate::direct_with_cost(1, 40)],
            fast_sticky_policy(),
            start,
        );
        let _ = plane.complete_tree_edge_attempt(initial, true, start);

        let healthy = || {
            vec![
                TreeEdgeCandidate::direct_with_cost(1, 40),
                TreeEdgeCandidate::legacy(4097, 1, 3),
            ]
        };
        let _ = plane.choose_tree_edge(tree_key, 1, 2, healthy(), fast_sticky_policy(), at(250));
        let confirmed =
            plane.choose_tree_edge(tree_key, 1, 2, healthy(), fast_sticky_policy(), at(750));
        let _ = plane.complete_tree_edge_attempt(confirmed, true, at(750));
        assert!(plane.active_tree_edge_split(tree_key, 1, 2).is_some());

        // The challenger degrades to hard failure under load.
        let degraded = || {
            vec![
                TreeEdgeCandidate::direct_with_cost(1, 40),
                TreeEdgeCandidate::legacy(4097, 3, 3),
            ]
        };
        let first = plane.choose_tree_edge(tree_key, 1, 2, degraded(), fast_sticky_policy(), at(800));
        assert_eq!(
            first.path(),
            TreeEdgePath::LegacyVia(4097),
            "one bad loaded read is not yet an abort"
        );
        assert!(plane.active_tree_edge_split(tree_key, 1, 2).is_some());

        let second = plane.choose_tree_edge(tree_key, 1, 2, degraded(), fast_sticky_policy(), at(850));
        assert_eq!(
            second.path(),
            TreeEdgePath::DirectChild,
            "consecutive hard-failure aborts and rolls back to the old route"
        );
        assert!(plane.active_tree_edge_split(tree_key, 1, 2).is_none());
        assert_eq!(
            plane.current_tree_edge_path(tree_key, 1, 2),
            Some(TreeEdgePath::DirectChild)
        );
    }

    /// Like `fast_sticky_policy` but with a decisive softmax temperature (β=1.0)
    /// so a modest loaded-cost gap snaps the controller to a clean corner.
    fn decisive_sticky_policy() -> TreeEdgeStickinessPolicy {
        TreeEdgeStickinessPolicy::new(
            Duration::from_millis(250),
            Duration::from_millis(500),
            Duration::from_secs(2),
            Duration::from_millis(700),
            Duration::from_millis(400),
            false,
            1.0,
            0.3,
        )
    }

    #[test]
    fn loaded_quality_can_hold_interior_split() {
        // The challenger beats the incumbent on idle cost (30 < 40, ≥25% cheaper)
        // and wins the switch. Under load the two routes are close — loaded
        // costs 60 vs 80 — so the softmax target settles inside (0, 1) and the
        // split holds a portion on each path instead of committing to a corner.
        let plane = DistributionPlane::default();
        let tree_key = key(95, 1);
        let start = Instant::now();
        let at = |ms: u64| start + Duration::from_millis(ms);
        let initial = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![TreeEdgeCandidate::direct_with_cost(1, 40)],
            fast_sticky_policy(),
            start,
        );
        let _ = plane.complete_tree_edge_attempt(initial, true, start);

        let candidates = || {
            vec![
                TreeEdgeCandidate::direct_with_cost(1, 40),
                TreeEdgeCandidate::legacy(4097, 1, 30),
            ]
        };
        let _ = plane.choose_tree_edge(tree_key, 1, 2, candidates(), fast_sticky_policy(), at(250));
        let confirmed =
            plane.choose_tree_edge(tree_key, 1, 2, candidates(), fast_sticky_policy(), at(750));
        assert_eq!(confirmed.path(), TreeEdgePath::LegacyVia(4097));
        let _ = plane.complete_tree_edge_attempt(confirmed, true, at(750));

        // Drive through fanout + fade. The controller converges to an interior
        // weight (~σ(0.1×20) ≈ 0.88) and holds it: never Complete (target < 1.0)
        // and never Abort.
        for ms in (1450..=4000u64).step_by(50) {
            let _ =
                plane.choose_tree_edge(tree_key, 1, 2, candidates(), fast_sticky_policy(), at(ms));
        }
        let split = plane
            .active_tree_edge_split(tree_key, 1, 2)
            .expect("interior split is the steady state");
        assert!(
            split.interior_hold(),
            "controller holds an interior split when loaded quality favors it"
        );
        assert!(
            (0.5..0.99).contains(&split.share()),
            "share settled around the softmax equilibrium (was {})",
            split.share()
        );
        assert_eq!(
            plane.current_tree_edge_path(tree_key, 1, 2),
            Some(TreeEdgePath::LegacyVia(4097)),
            "the adopted challenger stays the primary path during the interior hold"
        );
    }

    #[test]
    fn loaded_cost_flip_rolls_back_target_before_hard_failure() {
        // The challenger wins on idle cost (90 < 120, ≥25% cheaper), but once it
        // carries load its loaded cost (270) is decisively worse than the old
        // route's (240). With a decisive β the softmax target collapses to 0 and
        // the controller rolls back — without ever reading pressure 3, so this
        // is the target-driven rollback, not the abort fast path.
        let plane = DistributionPlane::default();
        let tree_key = key(96, 1);
        let start = Instant::now();
        let at = |ms: u64| start + Duration::from_millis(ms);
        let initial = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![TreeEdgeCandidate::direct_with_cost(1, 120)],
            decisive_sticky_policy(),
            start,
        );
        let _ = plane.complete_tree_edge_attempt(initial, true, start);

        let idle = || {
            vec![
                TreeEdgeCandidate::direct_with_cost(1, 120),
                TreeEdgeCandidate::legacy(4097, 1, 90),
            ]
        };
        let _ = plane.choose_tree_edge(tree_key, 1, 2, idle(), decisive_sticky_policy(), at(250));
        let confirmed =
            plane.choose_tree_edge(tree_key, 1, 2, idle(), decisive_sticky_policy(), at(750));
        assert_eq!(confirmed.path(), TreeEdgePath::LegacyVia(4097));
        let _ = plane.complete_tree_edge_attempt(confirmed, true, at(750));
        assert!(plane.active_tree_edge_split(tree_key, 1, 2).is_some());

        // Under load the challenger is marginal (pressure 2) but not a hard
        // failure; its loaded cost is what drives the rollback.
        let loaded = || {
            vec![
                TreeEdgeCandidate::direct_with_cost(1, 120),
                TreeEdgeCandidate::legacy(4097, 2, 90),
            ]
        };
        let completion = (0..200u64).find_map(|i| {
            let ms = 1450 + i * 50;
            let _ = plane.choose_tree_edge(tree_key, 1, 2, loaded(), decisive_sticky_policy(), at(ms));
            plane
                .active_tree_edge_split(tree_key, 1, 2)
                .is_none()
                .then_some(ms)
        });
        let done_at = completion.expect("target collapse rolls the split back");
        assert!(
            done_at >= 750 + 700,
            "rollback happens only after the probe window (was {done_at})"
        );
        assert!(
            plane.active_tree_edge_split(tree_key, 1, 2).is_none(),
            "no split remains after the rollback"
        );
        assert_eq!(
            plane.current_tree_edge_path(tree_key, 1, 2),
            Some(TreeEdgePath::DirectChild),
            "rolls back to the old route, not the marginal challenger"
        );
    }

    #[test]
    fn equal_pressure_lower_id_path_does_not_bypass_cost_switch_threshold() {
        let plane = DistributionPlane::default();
        let tree_key = key(96, 1);
        let start = Instant::now();
        let initial = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![TreeEdgeCandidate::legacy(4097, 0, 40)],
            fast_sticky_policy(),
            start,
        );
        let _ = plane.complete_tree_edge_attempt(initial, true, start);
        assert_eq!(
            plane.current_tree_edge_path(tree_key, 1, 2),
            Some(TreeEdgePath::LegacyVia(4097))
        );

        let candidates = || {
            vec![
                TreeEdgeCandidate::direct_with_cost(0, 39),
                TreeEdgeCandidate::legacy(4097, 0, 40),
            ]
        };
        let first = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            candidates(),
            fast_sticky_policy(),
            start + Duration::from_millis(250),
        );
        assert_eq!(first.path(), TreeEdgePath::LegacyVia(4097));
        let _ = plane.complete_tree_edge_attempt(first, true, start + Duration::from_millis(250));

        let later = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            candidates(),
            fast_sticky_policy(),
            start + Duration::from_millis(750),
        );
        assert_eq!(later.path(), TreeEdgePath::LegacyVia(4097));
    }

    #[test]
    fn idle_challenger_must_beat_healthy_incumbent_decisively() {
        let plane = DistributionPlane::default();
        let tree_key = key(98, 1);
        let start = Instant::now();
        let at = |ms: u64| start + Duration::from_millis(ms);
        let initial = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![TreeEdgeCandidate::direct_with_cost(1, 40)],
            fast_sticky_policy(),
            start,
        );
        let _ = plane.complete_tree_edge_attempt(initial, true, start);

        // The relay has never carried voice through this plane (idle-credit)
        // and reports clean metrics: pressure 0 vs the healthy incumbent's 1
        // (only a 1-point edge) and cost 38 vs 40 (~5% cheaper). Neither clears
        // the idle-credibility discount (≥2 pressure points or ≥20% cheaper),
        // so the switch must not happen even past the confirmation window.
        let idle_challenger = || {
            vec![
                TreeEdgeCandidate::direct_with_cost(1, 40),
                TreeEdgeCandidate::legacy(4097, 0, 38),
            ]
        };
        let _ = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            idle_challenger(),
            fast_sticky_policy(),
            at(250),
        );
        let later = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            idle_challenger(),
            fast_sticky_policy(),
            at(750),
        );
        assert_eq!(
            later.path(),
            TreeEdgePath::DirectChild,
            "an idle challenger's clean pressure is a stale bet once loaded"
        );
    }

    #[test]
    fn idle_challenger_wins_on_decisive_cost_improvement() {
        let plane = DistributionPlane::default();
        let tree_key = key(99, 1);
        let start = Instant::now();
        let at = |ms: u64| start + Duration::from_millis(ms);
        let initial = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![TreeEdgeCandidate::direct_with_cost(1, 40)],
            fast_sticky_policy(),
            start,
        );
        let _ = plane.complete_tree_edge_attempt(initial, true, start);

        // Same idle challenger, but 30 vs 40 is ≥20% cheaper — decisive enough
        // to justify loading an untested route.
        let idle_challenger = || {
            vec![
                TreeEdgeCandidate::direct_with_cost(1, 40),
                TreeEdgeCandidate::legacy(4097, 0, 30),
            ]
        };
        let _ = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            idle_challenger(),
            fast_sticky_policy(),
            at(250),
        );
        let confirmed = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            idle_challenger(),
            fast_sticky_policy(),
            at(750),
        );
        assert_eq!(confirmed.path(), TreeEdgePath::LegacyVia(4097));
    }

    #[test]
    fn loaded_challenger_keeps_normal_margin() {
        let plane = DistributionPlane::default();
        let tree_key = key(100, 1);
        let start = Instant::now();
        let at = |ms: u64| start + Duration::from_millis(ms);
        let initial = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![TreeEdgeCandidate::direct_with_cost(1, 40)],
            fast_sticky_policy(),
            start,
        );
        let _ = plane.complete_tree_edge_attempt(initial, true, start);

        // The relay has been carrying real voice through this plane: it is not
        // idle, so it only clears the normal ≥10% cost margin (35 vs 40 is
        // 12.5% cheaper), not the stricter ≥20% idle bar.
        plane.record_voice_original_bytes(4097, 1024, start);
        let loaded_challenger = || {
            vec![
                TreeEdgeCandidate::direct_with_cost(1, 40),
                TreeEdgeCandidate::legacy(4097, 0, 35),
            ]
        };
        let _ = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            loaded_challenger(),
            fast_sticky_policy(),
            at(250),
        );
        let confirmed = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            loaded_challenger(),
            fast_sticky_policy(),
            at(750),
        );
        assert_eq!(confirmed.path(), TreeEdgePath::LegacyVia(4097));
    }

    #[test]
    fn aborted_split_keeps_failed_first_hop_out_of_contention_for_exclusion_window() {
        let plane = DistributionPlane::default();
        let tree_key = key(101, 1);
        let start = Instant::now();
        let at = |ms: u64| start + Duration::from_millis(ms);
        let initial = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![TreeEdgeCandidate::direct_with_cost(1, 40)],
            fast_sticky_policy(),
            start,
        );
        let _ = plane.complete_tree_edge_attempt(initial, true, start);

        let healthy = || {
            vec![
                TreeEdgeCandidate::direct_with_cost(1, 40),
                TreeEdgeCandidate::legacy(4097, 1, 3),
            ]
        };
        let _ = plane.choose_tree_edge(tree_key, 1, 2, healthy(), fast_sticky_policy(), at(250));
        let confirmed =
            plane.choose_tree_edge(tree_key, 1, 2, healthy(), fast_sticky_policy(), at(750));
        let _ = plane.complete_tree_edge_attempt(confirmed, true, at(750));
        assert!(plane.active_tree_edge_split(tree_key, 1, 2).is_some());

        // The challenger degrades to hard failure under load → abort, rollback.
        let degraded = || {
            vec![
                TreeEdgeCandidate::direct_with_cost(1, 40),
                TreeEdgeCandidate::legacy(4097, 3, 3),
            ]
        };
        let _ = plane.choose_tree_edge(tree_key, 1, 2, degraded(), fast_sticky_policy(), at(800));
        let second = plane.choose_tree_edge(tree_key, 1, 2, degraded(), fast_sticky_policy(), at(850));
        assert_eq!(second.path(), TreeEdgePath::DirectChild);
        assert!(plane.active_tree_edge_split(tree_key, 1, 2).is_none());

        // Now the failed relay reports clean metrics again (idle-look) and the
        // 20%-cheaper cost qualifies normally — but it stays out of contention
        // for the whole exclusion window rather than being re-tried/re-aborted.
        let _ = plane.choose_tree_edge(tree_key, 1, 2, healthy(), fast_sticky_policy(), at(1_100));
        let later = plane.choose_tree_edge(tree_key, 1, 2, healthy(), fast_sticky_policy(), at(1_600));
        assert_eq!(
            later.path(),
            TreeEdgePath::DirectChild,
            "recently aborted first hop stays out of contention for the exclusion window"
        );
        assert!(plane.active_tree_edge_split(tree_key, 1, 2).is_none());

        // After the exclusion window, the first hop is eligible again.
        let _ = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            healthy(),
            fast_sticky_policy(),
            at(11_150),
        );
        let reeligible =
            plane.choose_tree_edge(tree_key, 1, 2, healthy(), fast_sticky_policy(), at(11_650));
        assert_eq!(reeligible.path(), TreeEdgePath::LegacyVia(4097));
    }

    #[test]
    fn challenger_deferred_until_inflight_transition_completes() {
        let plane = DistributionPlane::default();
        let tree_key = key(95, 1);
        let start = Instant::now();
        let at = |ms: u64| start + Duration::from_millis(ms);
        let initial = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![TreeEdgeCandidate::direct_with_cost(1, 40)],
            fast_sticky_policy(),
            start,
        );
        let _ = plane.complete_tree_edge_attempt(initial, true, start);
        let to_first_relay = || {
            vec![
                TreeEdgeCandidate::direct_with_cost(1, 40),
                TreeEdgeCandidate::legacy(3, 1, 3),
            ]
        };
        let _ = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            to_first_relay(),
            fast_sticky_policy(),
            at(250),
        );
        let first_relay = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            to_first_relay(),
            fast_sticky_policy(),
            at(750),
        );
        let _ = plane.complete_tree_edge_attempt(first_relay, true, at(750));
        assert!(plane.active_tree_edge_split(tree_key, 1, 2).is_some());

        // A second, better challenger arrives while the first split is in
        // flight; it is deferred — the controller owns the edge until it
        // commits or aborts, so no second fade can replace the first.
        let to_second_relay = || {
            vec![
                TreeEdgeCandidate::direct_with_cost(1, 40),
                TreeEdgeCandidate::legacy(3, 1, 3),
                TreeEdgeCandidate::legacy(4, 1, 1),
            ]
        };
        for ms in (1001..=1450).step_by(50) {
            let attempt = plane.choose_tree_edge(
                tree_key,
                1,
                2,
                to_second_relay(),
                fast_sticky_policy(),
                at(ms),
            );
            assert_eq!(attempt.path(), TreeEdgePath::LegacyVia(3), "deferred at {ms}");
        }
        assert_eq!(
            plane.current_tree_edge_path(tree_key, 1, 2),
            Some(TreeEdgePath::LegacyVia(3))
        );

        // Drive the first transition to completion (fanout + fade + confirm),
        // then the deferred challenger wins via normal sticky selection.
        for ms in (1500..=6000).step_by(50) {
            let _ = plane.choose_tree_edge(
                tree_key,
                1,
                2,
                to_second_relay(),
                fast_sticky_policy(),
                at(ms),
            );
            if plane.active_tree_edge_split(tree_key, 1, 2).is_none() {
                break;
            }
        }
        assert!(plane.active_tree_edge_split(tree_key, 1, 2).is_none());
        assert_eq!(
            plane.current_tree_edge_path(tree_key, 1, 2),
            Some(TreeEdgePath::LegacyVia(3))
        );

        let _ = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            to_second_relay(),
            fast_sticky_policy(),
            at(2_050),
        );
        let _ = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            to_second_relay(),
            fast_sticky_policy(),
            at(2_100),
        );
        let second_relay = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            to_second_relay(),
            fast_sticky_policy(),
            at(2_550),
        );
        assert_eq!(second_relay.path(), TreeEdgePath::LegacyVia(4));
    }

    #[test]
    fn overlap_capacity_scales_with_original_rate_without_repair_credit() {
        let plane = DistributionPlane::default();
        let now = Instant::now();
        let floor = plane.voice_overlap_link_snapshot(3, now);
        assert_eq!(floor.capacity_bytes, VOICE_OVERLAP_MIN_CAPACITY_BYTES);
        plane.record_voice_original_bytes(3, 6 * 1024 * 1024, now);
        let capped = plane.voice_overlap_link_snapshot(3, now);
        assert_eq!(capped.capacity_bytes, VOICE_OVERLAP_MAX_CAPACITY_BYTES);
        assert!(plane.try_reserve_voice_overlap(3, 1024, now));
        plane.release_voice_overlap(3, 1024, true, false, now);
        plane.release_voice_overlap(3, 1, true, true, now);
        let snapshot = plane.voice_overlap_link_snapshot(3, now);
        assert_eq!(snapshot.reserved_bytes, 0);
        assert_eq!(snapshot.copies_sent, 2);
        assert_eq!(snapshot.copies_shed, 0);
        assert_eq!(snapshot.primary_fallback_sends, 1);
        assert_eq!(
            plane
                .voice_overlap_link_snapshot(3, now + Duration::from_secs(1))
                .capacity_bytes,
            VOICE_OVERLAP_MIN_CAPACITY_BYTES
        );
    }

    #[test]
    fn tree_edge_soft_switch_requires_hold_and_stable_challenger() {
        let plane = DistributionPlane::default();
        let tree_key = key(90, 1);
        let start = Instant::now();
        let initial = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![TreeEdgeCandidate::direct_with_cost(1, 100)],
            sticky_policy(),
            start,
        );
        assert_eq!(initial.path(), TreeEdgePath::DirectChild);
        let _ = plane.complete_tree_edge_attempt(initial, true, start);

        let candidates = || {
            vec![
                TreeEdgeCandidate::direct_with_cost(2, 100),
                TreeEdgeCandidate::legacy(3, 1, 10),
            ]
        };
        let first = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            candidates(),
            sticky_policy(),
            start + Duration::from_millis(249),
        );
        assert_eq!(first.path(), TreeEdgePath::DirectChild);
        let before = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            candidates(),
            sticky_policy(),
            start + Duration::from_millis(749),
        );
        assert_eq!(before.path(), TreeEdgePath::DirectChild);
        let confirmed = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            candidates(),
            sticky_policy(),
            start + Duration::from_millis(750),
        );
        assert_eq!(confirmed.path(), TreeEdgePath::LegacyVia(3));
        assert_eq!(confirmed.reason, "confirmed_challenger");
    }

    #[test]
    fn tree_edge_challenger_change_resets_confirmation() {
        let plane = DistributionPlane::default();
        let tree_key = key(91, 1);
        let start = Instant::now();
        let initial = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![TreeEdgeCandidate::direct_with_cost(1, 100)],
            sticky_policy(),
            start,
        );
        let _ = plane.complete_tree_edge_attempt(initial, true, start);
        let at = |ms| start + Duration::from_millis(ms);
        let _ = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![
                TreeEdgeCandidate::direct_with_cost(2, 100),
                TreeEdgeCandidate::legacy(3, 1, 1),
            ],
            sticky_policy(),
            at(750),
        );
        let changed = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![
                TreeEdgeCandidate::direct_with_cost(2, 100),
                TreeEdgeCandidate::legacy(4, 1, 1),
            ],
            sticky_policy(),
            at(1_250),
        );
        assert_eq!(changed.path(), TreeEdgePath::DirectChild);
        let not_yet = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![
                TreeEdgeCandidate::direct_with_cost(2, 100),
                TreeEdgeCandidate::legacy(4, 1, 1),
            ],
            sticky_policy(),
            at(1_749),
        );
        assert_eq!(not_yet.path(), TreeEdgePath::DirectChild);
        let confirmed = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![
                TreeEdgeCandidate::direct_with_cost(2, 100),
                TreeEdgeCandidate::legacy(4, 1, 1),
            ],
            sticky_policy(),
            at(1_750),
        );
        assert_eq!(confirmed.path(), TreeEdgePath::LegacyVia(4));
    }

    #[test]
    fn tree_edge_idle_reset_and_stale_completion_are_deterministic() {
        let plane = DistributionPlane::default();
        let tree_key = key(92, 1);
        let start = Instant::now();
        let stale = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![TreeEdgeCandidate::direct(1)],
            sticky_policy(),
            start,
        );
        let _ = plane.complete_tree_edge_attempt(stale, true, start);
        let _ = plane.complete_tree_edge_attempt(stale, true, start + Duration::from_millis(10));
        assert_eq!(
            plane.current_tree_edge_path(tree_key, 1, 2),
            Some(TreeEdgePath::DirectChild)
        );

        let reset = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![TreeEdgeCandidate::direct(1)],
            sticky_policy(),
            start + Duration::from_secs(2),
        );
        assert_eq!(reset.path(), TreeEdgePath::DirectChild);
        assert_eq!(reset.reason, "initial");
    }

    #[test]
    fn hard_escape_prefers_direct_then_deterministic_fallback() {
        let plane = DistributionPlane::default();
        let tree_key = key(93, 1);
        let start = Instant::now();
        let direct = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![
                TreeEdgeCandidate::direct(3),
                TreeEdgeCandidate::legacy(4, 1, 20),
                TreeEdgeCandidate::legacy(3, 1, 10),
            ],
            sticky_policy(),
            start,
        );
        assert_eq!(direct.path(), TreeEdgePath::LegacyVia(3));
        let _ = plane.complete_tree_edge_attempt(direct, true, start);

        let failed_fallback = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![
                TreeEdgeCandidate::direct(1),
                TreeEdgeCandidate::legacy(3, 3, 10),
            ],
            sticky_policy(),
            start + Duration::from_millis(1),
        );
        assert_eq!(failed_fallback.path(), TreeEdgePath::DirectChild);
    }

    /// Commit a direct-child binding and return a fresh attempt at the current
    /// generation, so `hard_escape_tree_edge` sees `binding.generation ==
    /// attempt.generation` and takes the escape path.
    fn committed_direct_binding(
        plane: &DistributionPlane,
        tree_key: TreeKey,
        now: Instant,
    ) -> TreeEdgeAttempt {
        let initial = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![TreeEdgeCandidate::direct_with_cost(1, 40)],
            fast_sticky_policy(),
            now,
        );
        let _ = plane.complete_tree_edge_attempt(initial, true, now);
        plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![TreeEdgeCandidate::direct_with_cost(1, 40)],
            fast_sticky_policy(),
            now,
        )
    }

    #[test]
    fn hard_escape_is_cost_primary_among_warm_alternates() {
        let plane = DistributionPlane::default();
        let tree_key = key(101, 1);
        let start = Instant::now();
        let incumbent = committed_direct_binding(&plane, tree_key, start);
        assert_eq!(incumbent.path(), TreeEdgePath::DirectChild);
        // Both relays have carried voice; the escape must take the cheaper one.
        plane.record_voice_original_bytes(4097, 128, start);
        plane.record_voice_original_bytes(5, 128, start);
        let escape = plane
            .hard_escape_tree_edge(
                incumbent,
                vec![
                    TreeEdgeCandidate::direct(3),
                    TreeEdgeCandidate::legacy(4097, 1, 20),
                    TreeEdgeCandidate::legacy(5, 1, 10),
                ],
                "test",
                start,
            )
            .expect("escape target");
        assert_eq!(escape.path(), TreeEdgePath::LegacyVia(5));
    }

    #[test]
    fn hard_escape_prefers_warm_alternate_over_cheaper_idle_one() {
        let plane = DistributionPlane::default();
        let tree_key = key(102, 1);
        let start = Instant::now();
        let incumbent = committed_direct_binding(&plane, tree_key, start);
        // Only 4097 has carried voice; 5 is cheaper but idle (the lane that
        // never carried traffic — the exact cause of the abort churn).
        plane.record_voice_original_bytes(4097, 128, start);
        let escape = plane
            .hard_escape_tree_edge(
                incumbent,
                vec![
                    TreeEdgeCandidate::direct(3),
                    TreeEdgeCandidate::legacy(4097, 1, 20),
                    TreeEdgeCandidate::legacy(5, 1, 10),
                ],
                "test",
                start,
            )
            .expect("escape target");
        assert_eq!(escape.path(), TreeEdgePath::LegacyVia(4097));
    }

    #[test]
    fn hard_escape_falls_back_to_seeded_alternate_when_no_verified_relay() {
        let plane = DistributionPlane::default();
        let tree_key = key(103, 1);
        let start = Instant::now();
        let incumbent = committed_direct_binding(&plane, tree_key, start);
        // No live relay: the direct path failed and only the seeded
        // routing-table alternate (no live transport) is available. The escape
        // must try it rather than drop the frame.
        let escape = plane
            .hard_escape_tree_edge(
                incumbent,
                vec![
                    TreeEdgeCandidate::direct(3),
                    TreeEdgeCandidate::alternate(5, 10),
                ],
                "test",
                start,
            )
            .expect("seeded alternate escape target");
        assert_eq!(escape.path(), TreeEdgePath::LegacyVia(5));
    }

    #[test]
    fn hard_escape_returns_none_without_any_alternate() {
        let plane = DistributionPlane::default();
        let tree_key = key(104, 1);
        let start = Instant::now();
        let incumbent = committed_direct_binding(&plane, tree_key, start);
        assert!(
            plane
                .hard_escape_tree_edge(
                    incumbent,
                    vec![TreeEdgeCandidate::direct(3)],
                    "test",
                    start,
                )
                .is_none(),
            "no alternate leaves the escape to fail like today"
        );
    }

    fn frame(message_id: u64) -> PendingDistributionFrame {
        PendingDistributionFrame::new(
            2,
            pb::OverlayData {
                origin_message_id: message_id,
                ..Default::default()
            },
            true,
        )
    }

    fn state() -> TreeState {
        TreeState::new(1, [2], [(1, 2)])
    }

    fn state_with_ignored_playout(delay_ms: u64) -> TreeState {
        TreeState::new_with_playout(1, [2], [(1, 2)], [(2, delay_ms)])
    }

    #[test]
    fn ignored_playout_metadata_does_not_change_exact_tree_version() {
        let plain = state();
        let with_legacy_metadata = state_with_ignored_playout(120);
        assert_eq!(
            tree_version(1, VOICE_REALTIME_PROFILE_ID, 1, 1, 1, &plain),
            tree_version(1, VOICE_REALTIME_PROFILE_ID, 1, 1, 1, &with_legacy_metadata)
        );
    }

    #[test]
    fn install_ignores_legacy_playout_metadata() {
        let install = pb::DistributionTreeInstall {
            source: 1,
            members: vec![2],
            edges: vec![pb::OverlayTreeEdge {
                parent: 1,
                child: 2,
            }],
            playout_delays: vec![pb::DistributionTreePlayoutDelay {
                node: 2,
                delay_ms: 750,
            }],
            ..Default::default()
        };
        let installed = installed_tree_state(1, &install);

        assert_eq!(installed.children(1), &[2]);
        assert!(installed.is_member(2));
        assert_eq!(
            tree_version(1, VOICE_REALTIME_PROFILE_ID, 1, 1, 1, &installed),
            tree_version(1, VOICE_REALTIME_PROFILE_ID, 1, 1, 1, &state())
        );
    }

    #[test]
    fn install_encoding_leaves_legacy_playout_metadata_empty() {
        let control = pb::DistributionControl::decode(encode_install(key(1, 1), &state())).unwrap();
        let Some(pb::distribution_control::Body::Install(install)) = control.body else {
            panic!("expected tree install");
        };

        assert!(install.playout_delays.is_empty());
    }

    #[test]
    fn descendant_members_are_exact_to_the_child_branch() {
        let tree = TreeState::new(1, [2, 4, 5], [(1, 2), (1, 3), (3, 4), (3, 5)]);
        assert_eq!(tree.descendant_members(2), vec![2]);
        assert_eq!(tree.descendant_members(3), vec![4, 5]);
        assert!(tree.descendant_members(99).is_empty());
    }

    #[test]
    fn child_edge_failure_reports_are_deduplicated_by_source_directed_edge() {
        let plane = DistributionPlane::default();
        let first = key(1, 1);
        let replacement = key(1, 2);
        plane.install(first, state());
        plane.install(replacement, state());
        plane.report_edge_failure(first, 1, 2);
        plane.report_edge_failure(replacement, 1, 2);
        assert_eq!(plane.failure_reported_at.lock().len(), 1);
        assert!(plane.failed_edges(first).contains(&(1, 2)));

        plane.report_edge_failure(first, 1, 3);
        assert!(plane.failed_edges(first).contains(&(1, 2)));
        assert!(!plane.failed_edges(first).contains(&(1, 3)));
    }

    #[test]
    fn structural_replacement_keeps_active_until_candidate_acknowledged() {
        let plane = DistributionPlane::default();
        let initial_key = key(1, 1);
        let initial = state_with_ignored_playout(100);
        plane
            .stage_candidate(initial_key, initial.clone(), 100, 1)
            .unwrap();
        plane.install(initial_key, initial);
        assert!(plane.begin_publish(initial_key, [2]));
        plane.acknowledge(initial_key, 2);
        plane.report_edge_failure(initial_key, 1, 2);

        let replacement = TreeState::new_with_playout(1, [2], [(1, 3), (3, 2)], [(2, 120)]);
        let replacement_key = key(1, 2);
        let selected = plane
            .stage_candidate(replacement_key, replacement.clone(), 120, 1)
            .unwrap();
        assert_eq!(selected.state().children(1), &[3]);
        assert_eq!(
            plane.active_tree(replacement_key).unwrap().key(),
            initial_key
        );
        plane.install(replacement_key, replacement);
        assert!(plane.begin_publish(replacement_key, [2, 3]));
        plane.acknowledge(replacement_key, 2);
        assert_eq!(
            plane.active_tree(replacement_key).unwrap().key(),
            initial_key
        );
        plane.acknowledge(replacement_key, 3);
        assert_eq!(
            plane.active_tree(replacement_key).unwrap().key(),
            replacement_key
        );

        let unchanged_topology = TreeState::new_with_playout(1, [2], [(1, 3), (3, 2)], [(2, 140)]);
        assert_eq!(
            plane
                .stage_candidate(key(1, 3), unchanged_topology, 140, 3)
                .unwrap()
                .state()
                .children(1),
            &[3],
            "ignored playout metadata does not republish an unchanged tree"
        );
    }

    #[test]
    fn topology_epoch_change_bypasses_metric_reshape_hysteresis() {
        let plane = DistributionPlane::default();
        let initial_key = key(1, 1);
        let initial = state();
        plane
            .stage_candidate(initial_key, initial.clone(), 100, 1)
            .unwrap();
        plane.install(initial_key, initial);
        assert!(plane.begin_publish(initial_key, [2]));
        plane.acknowledge(initial_key, 2);

        let replacement_key = TreeKey {
            topology_epoch: 2,
            version: 2,
            ..initial_key
        };
        let replacement = TreeState::new(1, [2], [(1, 3), (3, 2)]);
        let selected = plane
            .stage_candidate(replacement_key, replacement, 200, 2)
            .expect("structural replacement");

        assert_eq!(selected.key(), replacement_key);
        assert_eq!(
            plane.active_tree(replacement_key).unwrap().key(),
            initial_key
        );
    }

    #[test]
    fn routing_generation_invalidates_cached_candidate() {
        let plane = DistributionPlane::default();
        let current = key(1, 1);
        plane
            .stage_candidate(current, state(), 100, 41)
            .expect("initial candidate");
        assert!(plane.cached_candidate(current, 41).is_some());
        assert!(plane.cached_candidate(current, 42).is_none());
    }

    #[test]
    fn cached_candidate_preserves_legacy_branch_recipients() {
        let plane = DistributionPlane::default();
        let current = key(1, 1);
        plane
            .stage_candidate_with_legacy(current, state(), 100, 41, HashSet::from([7, 8]))
            .expect("initial candidate");

        let cached = plane.cached_candidate(current, 41).unwrap();
        assert_eq!(cached.legacy_members(), &HashSet::from([7, 8]));
    }

    #[test]
    fn metric_reshape_must_remain_improved_for_five_seconds() {
        let plane = DistributionPlane::default();
        let initial_key = key(1, 1);
        let initial = state();
        plane
            .stage_candidate(initial_key, initial.clone(), 100, 1)
            .unwrap();
        plane.install(initial_key, initial);
        assert!(plane.begin_publish(initial_key, [2]));
        plane.acknowledge(initial_key, 2);

        let replacement_key = key(1, 2);
        let replacement = TreeState::new(1, [2], [(1, 3), (3, 2)]);
        let held = plane
            .stage_candidate(replacement_key, replacement.clone(), 80, 2)
            .unwrap();
        assert_eq!(held.key(), initial_key);
        let scope = StableTreeScope::from(replacement_key);
        plane
            .metric_proposals
            .lock()
            .get_mut(&scope)
            .unwrap()
            .first_seen -= METRIC_RESHAPE_HOLD;
        plane
            .candidates
            .lock()
            .get_mut(&TreeScope::from(replacement_key))
            .unwrap()
            .recheck_at = Some(Instant::now() - Duration::from_millis(1));
        assert!(plane.cached_candidate(replacement_key, 2).is_none());
        let selected = plane
            .stage_candidate(replacement_key, replacement, 79, 2)
            .unwrap();
        assert_eq!(selected.key(), replacement_key);
    }

    #[test]
    fn successful_direct_edge_clears_failure_exclusion() {
        let plane = DistributionPlane::default();
        let current = key(1, 1);
        plane.install(current, state());
        plane.report_edge_failure(current, 1, 2);
        assert!(plane.failed_edges(current).contains(&(1, 2)));

        plane.record_edge_success(current, 1, 2);
        assert!(!plane.failed_edges(current).contains(&(1, 2)));
    }

    #[test]
    fn metric_routing_generation_preserves_failure_exclusion_hold() {
        let plane = DistributionPlane::default();
        let current = key(1, 1);
        plane.prepare_routing_generation(current, 10);
        plane.install(current, state());
        plane.report_edge_failure(current, 1, 2);
        assert!(plane.failed_edges(current).contains(&(1, 2)));

        plane.prepare_routing_generation(current, 11);
        assert!(plane.failed_edges(current).contains(&(1, 2)));
    }

    #[test]
    fn receiver_install_state_is_bounded_across_topology_epochs() {
        let plane = DistributionPlane::default();
        let base = key(1, 1);
        for topology_epoch in 1..=6 {
            let current = TreeKey {
                topology_epoch,
                version: topology_epoch,
                ..base
            };
            plane.install(current, state());
        }
        let matching_scopes = plane
            .scope_activity
            .lock()
            .keys()
            .filter(|scope| {
                scope.source == base.source
                    && scope.profile == base.profile
                    && scope.group == base.group
                    && scope.group_version == base.group_version
            })
            .count();
        assert!(matching_scopes <= RETAINED_VERSIONS);
        assert!(plane.get(base).is_none());
    }

    #[test]
    fn receiver_install_prunes_obsolete_group_version() {
        let plane = DistributionPlane::default();
        let old = key(1, 1);
        plane.install(old, state());
        let new = TreeKey {
            group_version: 2,
            version: 2,
            ..old
        };
        plane.install(new, state());
        assert!(plane.get(old).is_none());
        assert!(plane.get(new).is_some());
    }

    #[test]
    fn edge_failure_cancels_candidate_and_late_ack_cannot_activate_it() {
        let plane = DistributionPlane::default();
        let initial_key = key(1, 1);
        let initial = state();
        plane
            .stage_candidate(initial_key, initial.clone(), 100, 1)
            .unwrap();
        plane.install(initial_key, initial);
        assert!(plane.begin_publish(initial_key, [2]));
        plane.acknowledge(initial_key, 2);

        let replacement_key = TreeKey {
            topology_epoch: 2,
            version: 2,
            ..initial_key
        };
        let replacement = TreeState::new(1, [2], [(1, 3), (3, 2)]);
        plane
            .stage_candidate(replacement_key, replacement.clone(), 90, 2)
            .unwrap();
        plane.install(replacement_key, replacement);
        assert!(plane.begin_publish(replacement_key, [2, 3]));
        plane.report_edge_failure(replacement_key, 1, 3);
        plane.acknowledge(replacement_key, 2);
        plane.acknowledge(replacement_key, 3);
        assert_eq!(
            plane.active_tree(replacement_key).unwrap().key(),
            initial_key
        );
        assert!(plane.pending_peers(replacement_key).is_empty());
    }

    #[test]
    fn active_tree_and_two_predecessors_survive_until_replacement_activates() {
        let plane = DistributionPlane::default();
        let first = key(1, 1);
        let second = key(1, 2);
        let third = key(1, 3);
        let replacement = key(1, 4);
        for (generation, current) in [first, second, third].into_iter().enumerate() {
            let tree = state();
            plane.candidates.lock().insert(
                TreeScope::from(current),
                CandidateTree {
                    key: current,
                    state: tree.clone(),
                    path_cost: 100,
                    routing_generation: generation as u64 + 1,
                    recheck_at: None,
                    legacy_members: HashSet::new(),
                },
            );
            plane.install(current, tree);
            assert!(plane.begin_publish(current, [2]));
            plane.acknowledge(current, 2);
        }

        let replacement_state = state();
        plane.candidates.lock().insert(
            TreeScope::from(replacement),
            CandidateTree {
                key: replacement,
                state: replacement_state.clone(),
                path_cost: 100,
                routing_generation: 4,
                recheck_at: None,
                legacy_members: HashSet::new(),
            },
        );
        plane.install(replacement, replacement_state);
        for retained in [first, second, third, replacement] {
            assert!(plane.get(retained).is_some());
        }

        assert!(plane.begin_publish(replacement, [2]));
        plane.acknowledge(replacement, 2);
        assert!(plane.get(first).is_none());
        for retained in [second, third, replacement] {
            assert!(plane.get(retained).is_some());
        }
    }

    #[test]
    fn unknown_tree_recovery_coalesces_and_replays_only_the_exact_key() {
        let plane = DistributionPlane::default();
        let missing = key(11, 1);
        let other = key(12, 1);

        assert!(matches!(
            plane.queue_unknown(missing, frame(10), Duration::from_secs(1)),
            UnknownTreeEnqueue::Queued
        ));
        assert!(matches!(
            plane.queue_unknown(missing, frame(11), Duration::from_secs(1)),
            UnknownTreeEnqueue::Queued
        ));
        assert_eq!(plane.unknown.lock().in_flight_requests.len(), 1);
        assert_eq!(plane.unknown_frame_count(), 2);

        assert!(plane.install(other, state()).is_empty());
        assert_eq!(plane.unknown_frame_count(), 2);

        let recovered = plane.install(missing, state());
        assert_eq!(
            recovered
                .iter()
                .map(|frame| frame.data.origin_message_id)
                .collect::<Vec<_>>(),
            vec![10, 11]
        );
        assert_eq!(plane.unknown_frame_count(), 0);
    }

    #[test]
    fn publication_coalesces_until_every_required_ack_activates() {
        let plane = DistributionPlane::default();
        let key = key(11, 1);

        assert!(plane.begin_publish(key, [2, 3]));
        assert!(
            !plane.begin_publish(key, [2, 3]),
            "a second voice frame must not restart the ACK window"
        );
        plane.acknowledge(key, 2);
        assert!(!plane.is_ready(key));
        plane.acknowledge(key, 3);
        assert!(plane.is_ready(key));
        assert!(
            !plane.begin_publish(key, [2, 3]),
            "an active exact tree must remain active for subsequent frames"
        );
    }

    #[test]
    fn control_publish_test_counter_is_plane_local() {
        let first = DistributionPlane::default();
        let second = DistributionPlane::default();

        assert!(first.begin_publish(key(12, 1), [2]));
        assert_eq!(first.control_publish_count_for_test(), 1);
        assert_eq!(second.control_publish_count_for_test(), 0);

        assert!(second.begin_publish(key(13, 1), [2]));
        assert_eq!(first.control_publish_count_for_test(), 1);
        assert_eq!(second.control_publish_count_for_test(), 1);
    }

    #[test]
    fn unknown_tree_recovery_enforces_per_key_and_global_limits() {
        let plane = DistributionPlane::default();
        let first = key(1, 1);
        for message_id in 0..UNKNOWN_TREE_FRAMES_PER_KEY as u64 {
            assert!(matches!(
                plane.queue_unknown(first, frame(message_id), Duration::from_secs(1)),
                UnknownTreeEnqueue::Queued
            ));
        }
        assert!(matches!(
            plane.queue_unknown(first, frame(99), Duration::from_secs(1)),
            UnknownTreeEnqueue::Full
        ));

        for group in 2..=(UNKNOWN_TREE_FRAMES_TOTAL - UNKNOWN_TREE_FRAMES_PER_KEY + 1) as u64 {
            assert!(matches!(
                plane.queue_unknown(key(group, 1), frame(group), Duration::from_secs(1)),
                UnknownTreeEnqueue::Queued
            ));
        }
        assert_eq!(plane.unknown_frame_count(), UNKNOWN_TREE_FRAMES_TOTAL);
        assert!(matches!(
            plane.queue_unknown(key(999, 1), frame(999), Duration::from_secs(1)),
            UnknownTreeEnqueue::Full
        ));
    }
}
