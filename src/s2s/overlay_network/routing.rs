use serde::{Deserialize, Serialize};

use super::NodeId;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RouteClass {
    Reliable,
    ReliableLowLatency,
    BestEffort,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RoutePath {
    Direct { target: NodeId },
    RelayChain { hops: Vec<NodeId> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkQualitySample {
    pub latency_ms: f64,
    pub jitter_ms: f64,
    pub loss_ratio: f64,
    pub bandwidth_kbps: f64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteCandidate {
    pub path: RoutePath,
    pub sample: LinkQualitySample,
}

#[derive(Debug, Clone, Copy)]
pub struct RouteSelectionPolicy {
    pub switch_margin: f64,
    pub min_switch_interval_ms: u64,
    pub dead_loss_ratio: f64,
    pub congested_loss_ratio: f64,
    pub congested_latency_ms: f64,
    pub emergency_score_drop: f64,
}

impl Default for RouteSelectionPolicy {
    fn default() -> Self {
        Self {
            // Require meaningful improvement before switching.
            switch_margin: 3.0,
            // Hold a chosen route briefly to absorb transient jitter.
            min_switch_interval_ms: 1_000,
            // Treat near-total loss as dead and fail over immediately.
            dead_loss_ratio: 0.98,
            // Consider severe loss/latency as congestion and fail over quickly.
            congested_loss_ratio: 0.35,
            congested_latency_ms: 350.0,
            // Trigger emergency switch when quality drops sharply.
            emergency_score_drop: 15.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StableRouteState {
    pub selected: RouteCandidate,
    pub selected_score: f64,
    pub last_switch_ms: u64,
}

impl RouteCandidate {
    pub fn score(&self) -> f64 {
        let delay_penalty = self.sample.latency_ms * 0.15;
        let jitter_penalty = self.sample.jitter_ms * 0.2;
        let loss_penalty = self.sample.loss_ratio.clamp(0.0, 1.0) * 100.0;
        100.0 - delay_penalty - jitter_penalty - loss_penalty
    }

    pub fn hop_count(&self) -> usize {
        match &self.path {
            RoutePath::RelayChain { hops } => hops.len(),
            _ => 1,
        }
    }
}

pub fn select_best_path(
    candidates: &[RouteCandidate],
    now_ms: u64,
    stale_after_ms: u64,
) -> Option<RouteCandidate> {
    let mut filtered = candidates
        .iter()
        .filter(|candidate| now_ms.saturating_sub(candidate.sample.updated_at_ms) <= stale_after_ms)
        .cloned()
        .collect::<Vec<_>>();

    filtered.sort_by(|a, b| {
        b.score()
            .partial_cmp(&a.score())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(
                a.sample
                    .latency_ms
                    .partial_cmp(&b.sample.latency_ms)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
            .then(a.hop_count().cmp(&b.hop_count()))
    });

    filtered.into_iter().next()
}

pub fn select_stable_path(
    current: Option<&StableRouteState>,
    best: Option<RouteCandidate>,
    now_ms: u64,
    policy: RouteSelectionPolicy,
) -> Option<StableRouteState> {
    let candidate = best?;
    let candidate_score = candidate.score();

    let Some(current) = current else {
        return Some(StableRouteState {
            selected: candidate,
            selected_score: candidate_score,
            last_switch_ms: now_ms,
        });
    };

    if candidate.path == current.selected.path {
        return Some(StableRouteState {
            selected: candidate,
            selected_score: candidate_score,
            last_switch_ms: current.last_switch_ms,
        });
    }

    let current_score_now = current.selected.score();
    let current_dead = current.selected.sample.loss_ratio >= policy.dead_loss_ratio;
    let current_congested = current.selected.sample.loss_ratio >= policy.congested_loss_ratio
        || current.selected.sample.latency_ms >= policy.congested_latency_ms;
    let severe_score_drop = current_score_now + policy.emergency_score_drop <= current.selected_score;

    if current_dead || current_congested || severe_score_drop {
        // Emergency failover path: bypass cooldown and hysteresis if the alternate route
        // is at least as good as the currently degraded one.
        if current_dead || candidate_score >= current_score_now {
            return Some(StableRouteState {
                selected: candidate,
                selected_score: candidate_score,
                last_switch_ms: now_ms,
            });
        }
    }

    let cooldown_active = now_ms.saturating_sub(current.last_switch_ms) < policy.min_switch_interval_ms;
    let improved_enough = candidate_score >= current.selected_score + policy.switch_margin;

    if cooldown_active || !improved_enough {
        return Some(current.clone());
    }

    Some(StableRouteState {
        selected: candidate,
        selected_score: candidate_score,
        last_switch_ms: now_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(target: NodeId, latency: f64, loss: f64, updated_at: u64) -> RouteCandidate {
        RouteCandidate {
            path: RoutePath::Direct { target },
            sample: LinkQualitySample {
                latency_ms: latency,
                jitter_ms: 5.0,
                loss_ratio: loss,
                bandwidth_kbps: 1000.0,
                updated_at_ms: updated_at,
            },
        }
    }

    #[test]
    fn select_best_path_filters_stale_candidates() {
        let fresh = candidate(1, 30.0, 0.01, 100);
        let stale = candidate(2, 10.0, 0.0, 10);
        let selected = select_best_path(&[fresh.clone(), stale], 100, 20)
            .expect("a fresh path should be selected");
        assert_eq!(selected.path, fresh.path);
    }

    #[test]
    fn select_stable_path_honors_cooldown() {
        let policy = RouteSelectionPolicy { min_switch_interval_ms: 1000, ..RouteSelectionPolicy::default() };
        let current_selected = candidate(1, 40.0, 0.01, 100);
        let current = StableRouteState {
            selected_score: current_selected.score(),
            selected: current_selected,
            last_switch_ms: 100,
        };
        let better = candidate(2, 5.0, 0.0, 110);

        let next = select_stable_path(Some(&current), Some(better), 500, policy)
            .expect("state should remain available");
        assert_eq!(next.selected.path, current.selected.path);
    }

    #[test]
    fn emergency_failover_switches_degraded_route() {
        let policy = RouteSelectionPolicy::default();
        let degraded = candidate(1, 500.0, 0.99, 100);
        let current = StableRouteState {
            selected_score: 90.0,
            selected: degraded,
            last_switch_ms: 100,
        };
        let alternate = candidate(2, 60.0, 0.05, 101);
        let next = select_stable_path(Some(&current), Some(alternate.clone()), 120, policy)
            .expect("state should switch");
        assert_eq!(next.selected.path, alternate.path);
    }
}
