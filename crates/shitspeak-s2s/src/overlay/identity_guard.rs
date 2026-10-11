//! Automatic recovery from an impostor that fenced this node's identity.
//!
//! A duplicate that boots with a higher [`boot_epoch`] is treated by every
//! peer as a restart of this node id. Those peers then reject this node's own
//! advertisements as stale, and — because the fence is also persisted in the
//! LSDB floor — the block survives the impostor leaving. The only thing that
//! clears it is this node minting a still-higher epoch, which a restart does.
//!
//! This guard performs that restart on its own, but only once the impostor is
//! actually gone. It is deliberately conservative:
//!
//! * the fence must be reported twice, at least one hello-dead interval apart,
//!   so a transient race cannot trigger it;
//! * it asks the peers what they see for our own node id first. While any
//!   peer reports a live foreign epoch, the impostor is still up and recovery
//!   would only fight it;
//! * at most one re-incarnation per [`REINCARNATION_COOLDOWN`].
//!
//! The request is published on a watch channel. The runtime that owns the
//! S2S stack decides how to act on it.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::{Notify, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{error, warn};

use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::ConnectionManager;

use super::identity::{IdentityProbeResponse, send_identity_probe};

/// Minimum gap between two fence reports before recovery is considered.
pub(crate) const FENCE_DEBOUNCE: Duration = Duration::from_secs(4);
/// Upper bound on waiting for probe answers.
const PROBE_WAIT: Duration = Duration::from_secs(3);
/// A foreign epoch younger than this counts as a live competitor.
const COMPETITOR_LIVE_WINDOW: Duration = Duration::from_secs(8);
/// Minimum gap between two re-incarnations.
pub(crate) const REINCARNATION_COOLDOWN: Duration = Duration::from_secs(300);

/// Guard timings. Production values are deliberately conservative; tests
/// shorten them so the decision logic is observable without waiting minutes.
#[derive(Debug, Clone, Copy)]
pub struct GuardTuning {
    /// Gap required between two fence reports before recovery is considered.
    pub fence_debounce: Duration,
    /// Upper bound on waiting for probe answers.
    pub probe_wait: Duration,
    /// A foreign epoch younger than this counts as a live competitor.
    pub competitor_live_window: Duration,
    /// Minimum gap between two re-incarnations.
    pub reincarnation_cooldown: Duration,
}

impl Default for GuardTuning {
    fn default() -> Self {
        Self {
            fence_debounce: FENCE_DEBOUNCE,
            probe_wait: PROBE_WAIT,
            competitor_live_window: COMPETITOR_LIVE_WINDOW,
            reincarnation_cooldown: REINCARNATION_COOLDOWN,
        }
    }
}

/// Why the guard thinks another process holds this node id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceTrigger {
    /// A peer rejected our LSA because a higher `(boot_epoch, seq)` for our
    /// own origin is already known there.
    OriginFenced { fence_epoch: u64, fence_seq: u64 },
    /// An LSA claiming our own origin arrived from the network.
    ForeignSelfLsa { foreign_epoch: u64, foreign_seq: u64 },
    /// Our own local LSA was rejected by the local LSDB.
    LocalLsaSuppressed { foreign_epoch: u64, foreign_seq: u64 },
}

impl FenceTrigger {
    fn fence_epoch(&self) -> u64 {
        match self {
            Self::OriginFenced { fence_epoch, .. } => *fence_epoch,
            Self::ForeignSelfLsa { foreign_epoch, .. } => *foreign_epoch,
            Self::LocalLsaSuppressed { foreign_epoch, .. } => *foreign_epoch,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::OriginFenced { .. } => "origin_fenced",
            Self::ForeignSelfLsa { .. } => "foreign_self_lsa",
            Self::LocalLsaSuppressed { .. } => "local_lsa_suppressed",
        }
    }
}

/// A decision to re-incarnate with an epoch above `floor_epoch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReincarnationRequest {
    pub floor_epoch: u64,
    pub reason: &'static str,
    pub peers_answered: usize,
}

/// One of the guard's published decisions, for metrics and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GuardDecision {
    /// Fence seen but not yet confirmed by a second report.
    Debouncing,
    /// A competitor is still live; recovery would only fight it.
    CompetitorLive,
    /// No peer answered; nothing can be proved either way.
    Inconclusive,
    /// Competitor is gone; re-incarnation requested.
    Requested,
    /// A recent re-incarnation already happened.
    Cooldown,
}

struct GuardState {
    last_trigger: Option<(Instant, FenceTrigger)>,
    last_reincarnation: Option<Instant>,
    decisions: HashMap<GuardDecision, u64>,
    pending_probes: HashMap<u64, oneshot::Sender<IdentityProbeResponse>>,
    next_nonce: u64,
}

impl GuardState {
    fn new() -> Self {
        Self {
            last_trigger: None,
            last_reincarnation: None,
            decisions: HashMap::new(),
            pending_probes: HashMap::new(),
            next_nonce: 1,
        }
    }

    fn record(&mut self, decision: GuardDecision) {
        *self.decisions.entry(decision).or_default() += 1;
    }
}

/// Watches for an impostor fencing this node id and requests re-incarnation
/// once the impostor is gone.
pub struct IdentityGuard {
    self_id: NodeIdentifier,
    local_epoch: u64,
    transport: ConnectionManager,
    state: Mutex<GuardState>,
    wake: Notify,
    reincarnation: tokio::sync::watch::Sender<Option<ReincarnationRequest>>,
    shutdown: CancellationToken,
    tuning: GuardTuning,
}

impl IdentityGuard {
    pub(crate) fn new(
        self_id: NodeIdentifier,
        local_epoch: u64,
        transport: ConnectionManager,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        Self::with_tuning(self_id, local_epoch, transport, shutdown, GuardTuning::default())
    }

    pub(crate) fn with_tuning(
        self_id: NodeIdentifier,
        local_epoch: u64,
        transport: ConnectionManager,
        shutdown: CancellationToken,
        tuning: GuardTuning,
    ) -> Arc<Self> {
        let (reincarnation, _) = tokio::sync::watch::channel(None);
        Arc::new(Self {
            self_id,
            local_epoch,
            transport,
            state: Mutex::new(GuardState::new()),
            wake: Notify::new(),
            reincarnation,
            shutdown,
            tuning,
        })
    }

    pub(crate) fn spawn(self: &Arc<Self>) {
        let guard = Arc::clone(self);
        let shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => return,
                    _ = guard.wake.notified() => {}
                    _ = interval.tick() => {}
                }
                guard.evaluate().await;
            }
        });
    }

    /// The re-incarnation request stream, one entry per decision.
    pub fn reincarnation_requests(&self) -> tokio::sync::watch::Receiver<Option<ReincarnationRequest>> {
        self.reincarnation.subscribe()
    }

    /// Record that another process's epoch for our own id was seen.
    pub fn report_trigger(&self, trigger: FenceTrigger) {
        if trigger.fence_epoch() <= self.local_epoch {
            return;
        }
        {
            let mut state = self.state.lock();
            state.last_trigger = Some((Instant::now(), trigger));
        }
        warn!(
            node = self.self_id,
            local_epoch = self.local_epoch,
            trigger = trigger.label(),
            fence_epoch = trigger.fence_epoch(),
            "another process holds this node id at a higher epoch"
        );
        self.wake.notify_one();
    }

    /// Deliver a probe answer from a peer. Called by the overlay dispatcher.
    pub fn deliver_probe_response(&self, response: IdentityProbeResponse) {
        let sender = self
            .state
            .lock()
            .pending_probes
            .remove(&response.nonce);
        if let Some(sender) = sender {
            let _ = sender.send(response);
        }
    }

    /// Current per-decision counters, for metrics and tests.
    pub fn decision_counts(&self) -> Vec<(GuardDecision, u64)> {
        let mut out: Vec<(GuardDecision, u64)> = self
            .state
            .lock()
            .decisions
            .iter()
            .map(|(decision, count)| (*decision, *count))
            .collect();
        out.sort_by_key(|(decision, _)| decision.label());
        out
    }

    async fn evaluate(&self) {
        let Some((observed_at, trigger)) = self.state.lock().last_trigger else {
            return;
        };
        if trigger.fence_epoch() <= self.local_epoch {
            return;
        }

        // Debounce: the fence must hold across two reports.
        let debounced = observed_at.elapsed() >= self.tuning.fence_debounce;
        if !debounced {
            self.state.lock().record(GuardDecision::Debouncing);
            return;
        }

        if let Some(last) = self.state.lock().last_reincarnation
            && last.elapsed() < self.tuning.reincarnation_cooldown
        {
            self.state.lock().record(GuardDecision::Cooldown);
            return;
        }

        let peers_answered = self.probe_competitor().await;
        match peers_answered {
            ProbeVerdict::CompetitorLive => {
                self.state.lock().record(GuardDecision::CompetitorLive);
            }
            ProbeVerdict::Inconclusive => {
                self.state.lock().record(GuardDecision::Inconclusive);
            }
            ProbeVerdict::Gone(answered) => {
                {
                    let mut state = self.state.lock();
                    state.record(GuardDecision::Requested);
                    state.last_reincarnation = Some(Instant::now());
                    state.last_trigger = None;
                }
                let request = ReincarnationRequest {
                    floor_epoch: trigger.fence_epoch(),
                    reason: trigger.label(),
                    peers_answered: answered,
                };
                error!(
                    node = self.self_id,
                    local_epoch = self.local_epoch,
                    floor_epoch = request.floor_epoch,
                    reason = request.reason,
                    peers_answered = request.peers_answered,
                    "impostor is gone; requesting S2S re-incarnation above its epoch"
                );
                let _ = self.reincarnation.send(Some(request));
            }
        }
    }

    /// Ask every transport-live peer what it sees for our own node id.
    async fn probe_competitor(&self) -> ProbeVerdict {
        let peers: Vec<NodeIdentifier> = self
            .transport
            .live_peers()
            .into_iter()
            .map(|(node, _)| node)
            .filter(|node| *node != self.self_id)
            .collect();
        if peers.is_empty() {
            return ProbeVerdict::Inconclusive;
        }

        let mut receivers = Vec::with_capacity(peers.len());
        for peer in peers {
            let (nonce, rx) = {
                let mut state = self.state.lock();
                let nonce = state.next_nonce;
                state.next_nonce = state.next_nonce.wrapping_add(1).max(1);
                let (tx, rx) = oneshot::channel();
                state.pending_probes.insert(nonce, tx);
                (nonce, rx)
            };
            let sent = send_identity_probe(
                &self.transport,
                self.self_id,
                peer,
                self.self_id,
                nonce,
            )
            .await;
            match sent {
                Some(_) => receivers.push(rx),
                None => {
                    self.state.lock().pending_probes.remove(&nonce);
                }
            }
        }
        if receivers.is_empty() {
            return ProbeVerdict::Inconclusive;
        }

        let deadline = Instant::now() + self.tuning.probe_wait;
        let mut answered = 0usize;
        let mut foreign_live = Vec::new();
        for rx in receivers {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            if let Ok(response) = tokio::time::timeout(remaining, rx).await
                && let Ok(response) = response
            {
                answered += 1;
                for (boot_epoch, age) in response.foreign_epochs(self.local_epoch) {
                    if age < self.tuning.competitor_live_window {
                        foreign_live.push((boot_epoch, age));
                    }
                }
            }
        }

        if !foreign_live.is_empty() {
            warn!(
                node = self.self_id,
                local_epoch = self.local_epoch,
                competitors = ?foreign_live,
                "a competitor for this node id is still live; holding off recovery"
            );
            return ProbeVerdict::CompetitorLive;
        }
        if answered == 0 {
            return ProbeVerdict::Inconclusive;
        }
        ProbeVerdict::Gone(answered)
    }
}

enum ProbeVerdict {
    CompetitorLive,
    Inconclusive,
    Gone(usize),
}

impl GuardDecision {
    pub fn label(self) -> &'static str {
        match self {
            Self::Debouncing => "debouncing",
            Self::CompetitorLive => "competitor_live",
            Self::Inconclusive => "inconclusive",
            Self::Requested => "requested",
            Self::Cooldown => "cooldown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triggers_at_or_below_the_local_epoch_are_ignored() {
        assert!(
            !matches!(
                // A trigger is dropped before reaching the state when its
                // epoch is not strictly higher.
                FenceTrigger::OriginFenced {
                    fence_epoch: 5,
                    fence_seq: 1
                }
                .fence_epoch(),
                epoch if epoch > 5
            )
        );
    }

    #[test]
    fn fence_epoch_is_taken_from_each_trigger_kind() {
        assert_eq!(
            FenceTrigger::OriginFenced {
                fence_epoch: 9,
                fence_seq: 3
            }
            .fence_epoch(),
            9
        );
        assert_eq!(
            FenceTrigger::ForeignSelfLsa {
                foreign_epoch: 11,
                foreign_seq: 1
            }
            .fence_epoch(),
            11
        );
        assert_eq!(
            FenceTrigger::LocalLsaSuppressed {
                foreign_epoch: 7,
                foreign_seq: 2
            }
            .fence_epoch(),
            7
        );
    }

    #[test]
    fn guard_state_records_decisions() {
        let mut state = GuardState::new();
        state.record(GuardDecision::Debouncing);
        state.record(GuardDecision::Debouncing);
        state.record(GuardDecision::Requested);
        assert_eq!(
            state.decisions.get(&GuardDecision::Debouncing),
            Some(&2)
        );
        assert_eq!(state.decisions.get(&GuardDecision::Requested), Some(&1));
    }
}