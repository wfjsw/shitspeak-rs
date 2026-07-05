use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::Serialize;

use shitspeak_core::NodeIdentifier;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum DuplicateEvidenceKind {
    Hello,
    HelloAck,
    Lsa,
}

impl DuplicateEvidenceKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Hello => "hello",
            Self::HelloAck => "hello_ack",
            Self::Lsa => "lsa",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DuplicateNodeSnapshot {
    node_id: NodeIdentifier,
    observed_epochs: usize,
    quarantined: bool,
    reason: &'static str,
    age_ms: u128,
    remaining_ms: u128,
    conflicts_total: u64,
    dropped_messages_total: Vec<DuplicateDropSnapshot>,
}

impl DuplicateNodeSnapshot {
    pub fn node_id(&self) -> NodeIdentifier {
        self.node_id
    }

    pub fn observed_epochs(&self) -> usize {
        self.observed_epochs
    }

    pub fn quarantined(&self) -> bool {
        self.quarantined
    }

    pub fn reason(&self) -> &'static str {
        self.reason
    }

    pub fn age_ms(&self) -> u128 {
        self.age_ms
    }

    pub fn remaining_ms(&self) -> u128 {
        self.remaining_ms
    }

    pub fn conflicts_total(&self) -> u64 {
        self.conflicts_total
    }

    pub fn dropped_messages_total(&self) -> &[DuplicateDropSnapshot] {
        &self.dropped_messages_total
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DuplicateDropSnapshot {
    kind: &'static str,
    count: u64,
}

impl DuplicateDropSnapshot {
    pub fn kind(&self) -> &'static str {
        self.kind
    }

    pub fn count(&self) -> u64 {
        self.count
    }
}

#[derive(Debug)]
struct EpochObservation {
    last_seen: Instant,
    tombstone: bool,
}

#[derive(Debug)]
struct NodeState {
    epochs: HashMap<u64, EpochObservation>,
    quarantined_since: Option<Instant>,
    conflicts_total: u64,
    dropped_by_kind: HashMap<&'static str, u64>,
}

impl NodeState {
    fn new() -> Self {
        Self {
            epochs: HashMap::new(),
            quarantined_since: None,
            conflicts_total: 0,
            dropped_by_kind: HashMap::new(),
        }
    }
}

#[derive(Debug)]
pub struct DuplicateDetector {
    self_id: NodeIdentifier,
    window: Duration,
    states: Mutex<HashMap<NodeIdentifier, NodeState>>,
    startup_failures: AtomicU64,
}

impl DuplicateDetector {
    pub fn new(self_id: NodeIdentifier, window: Duration) -> Self {
        Self {
            self_id,
            window: window.max(Duration::from_millis(1)),
            states: Mutex::new(HashMap::new()),
            startup_failures: AtomicU64::new(0),
        }
    }

    pub fn observe_epoch(
        &self,
        node: NodeIdentifier,
        boot_epoch: u64,
        tombstone: bool,
        _kind: DuplicateEvidenceKind,
    ) {
        if node == 0 || boot_epoch == 0 {
            return;
        }
        let now = Instant::now();
        let mut states = self.states.lock();
        let state = states.entry(node).or_insert_with(NodeState::new);
        prune_node_state(state, now, self.window);
        if !state.epochs.contains_key(&boot_epoch)
            && state
                .epochs
                .keys()
                .copied()
                .max()
                .is_some_and(|max_epoch| boot_epoch > max_epoch)
        {
            state.epochs.clear();
            state.quarantined_since = None;
        }
        state.epochs.insert(
            boot_epoch,
            EpochObservation {
                last_seen: now,
                tombstone,
            },
        );
        let live_epochs = live_epoch_count(state, now, self.window);
        if live_epochs > 1 && state.quarantined_since.is_none() {
            state.quarantined_since = Some(now);
            state.conflicts_total = state.conflicts_total.saturating_add(1);
        }
    }

    pub fn is_quarantined(&self, node: NodeIdentifier) -> bool {
        self.snapshot_one(node)
            .is_some_and(|snapshot| snapshot.quarantined)
    }

    pub fn record_drop(&self, node: NodeIdentifier, kind: &'static str) {
        let mut states = self.states.lock();
        let state = states.entry(node).or_insert_with(NodeState::new);
        let counter = state.dropped_by_kind.entry(kind).or_default();
        *counter = counter.saturating_add(1);
    }

    pub fn record_startup_failure(&self) {
        self.startup_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn startup_failures(&self) -> u64 {
        self.startup_failures.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> Vec<DuplicateNodeSnapshot> {
        let now = Instant::now();
        let mut states = self.states.lock();
        let mut out = Vec::new();
        states.retain(|node, state| {
            prune_node_state(state, now, self.window);
            if state.quarantined_since.is_some()
                || !state.epochs.is_empty()
                || state.conflicts_total > 0
                || !state.dropped_by_kind.is_empty()
                || (*node == self.self_id && self.startup_failures() > 0)
            {
                out.push(snapshot_for_node(*node, state, now, self.window));
                true
            } else {
                false
            }
        });
        if self.startup_failures() > 0 && !out.iter().any(|entry| entry.node_id == self.self_id) {
            out.push(DuplicateNodeSnapshot {
                node_id: self.self_id,
                observed_epochs: 0,
                quarantined: false,
                reason: "startup_duplicate",
                age_ms: 0,
                remaining_ms: 0,
                conflicts_total: 0,
                dropped_messages_total: Vec::new(),
            });
        }
        out.sort_by_key(|entry| entry.node_id);
        out
    }

    fn snapshot_one(&self, node: NodeIdentifier) -> Option<DuplicateNodeSnapshot> {
        let now = Instant::now();
        let mut states = self.states.lock();
        let state = states.get_mut(&node)?;
        prune_node_state(state, now, self.window);
        Some(snapshot_for_node(node, state, now, self.window))
    }
}

fn prune_node_state(state: &mut NodeState, now: Instant, window: Duration) {
    state.epochs.retain(|_, observation| {
        !observation.tombstone && now.duration_since(observation.last_seen) <= window
    });
    if let Some(since) = state.quarantined_since {
        if now.duration_since(since) > window && live_epoch_count(state, now, window) <= 1 {
            state.quarantined_since = None;
        }
    }
}

fn live_epoch_count(state: &NodeState, now: Instant, window: Duration) -> usize {
    state
        .epochs
        .values()
        .filter(|observation| {
            !observation.tombstone && now.duration_since(observation.last_seen) <= window
        })
        .count()
}

fn snapshot_for_node(
    node_id: NodeIdentifier,
    state: &NodeState,
    now: Instant,
    window: Duration,
) -> DuplicateNodeSnapshot {
    let age = state
        .quarantined_since
        .map(|since| now.duration_since(since))
        .unwrap_or(Duration::ZERO);
    let remaining = state
        .quarantined_since
        .map(|_| window.saturating_sub(age))
        .unwrap_or(Duration::ZERO);
    let mut dropped_messages_total = state
        .dropped_by_kind
        .iter()
        .map(|(kind, count)| DuplicateDropSnapshot {
            kind,
            count: *count,
        })
        .collect::<Vec<_>>();
    dropped_messages_total.sort_by_key(|entry| entry.kind);
    DuplicateNodeSnapshot {
        node_id,
        observed_epochs: live_epoch_count(state, now, window),
        quarantined: state.quarantined_since.is_some(),
        reason: if state.quarantined_since.is_some() {
            "duplicate_boot_epoch"
        } else {
            "observed"
        },
        age_ms: age.as_millis(),
        remaining_ms: remaining.as_millis(),
        conflicts_total: state.conflicts_total,
        dropped_messages_total,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_epochs_quarantine_and_expire() {
        let detector = DuplicateDetector::new(1, Duration::from_millis(20));
        detector.observe_epoch(2, 10, false, DuplicateEvidenceKind::Hello);
        assert!(!detector.is_quarantined(2));

        detector.observe_epoch(2, 11, false, DuplicateEvidenceKind::Lsa);
        assert!(!detector.is_quarantined(2));

        detector.observe_epoch(2, 10, false, DuplicateEvidenceKind::Hello);
        assert!(detector.is_quarantined(2));
        let snapshot = detector.snapshot();
        let node = snapshot.iter().find(|node| node.node_id() == 2).unwrap();
        assert_eq!(node.observed_epochs(), 2);
        assert_eq!(node.conflicts_total(), 1);

        std::thread::sleep(Duration::from_millis(30));
        assert!(!detector.is_quarantined(2));
    }

    #[test]
    fn tombstoned_restart_epoch_does_not_quarantine() {
        let detector = DuplicateDetector::new(1, Duration::from_secs(1));
        detector.observe_epoch(2, 10, false, DuplicateEvidenceKind::Hello);
        detector.observe_epoch(2, 10, true, DuplicateEvidenceKind::Lsa);
        detector.observe_epoch(2, 11, false, DuplicateEvidenceKind::HelloAck);

        assert!(!detector.is_quarantined(2));
        let snapshot = detector.snapshot();
        let node = snapshot.iter().find(|node| node.node_id() == 2).unwrap();
        assert_eq!(node.observed_epochs(), 1);
        assert_eq!(node.conflicts_total(), 0);
    }
}
