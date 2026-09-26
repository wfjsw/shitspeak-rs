//! Adaptive, byte-based admission limits for voice work.
//!
//! Capacity is sampled when work is reserved. Lowering `max_users` therefore
//! constrains later admission without evicting work which is already queued.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use shitspeak_core::NodeIdentifier;

use super::metrics::{self, RepairClassStage, RepairCreditStage, RepairDestinationStage};

const MIN_ADMISSION_BYTES: usize = 128;
const PRIMARY_MIN_BYTES: usize = 256 * 1024;
const PRIMARY_MAX_BYTES: usize = 4 * 1024 * 1024;
const PROACTIVE_MIN_BYTES: usize = 256 * 1024;
const PROACTIVE_MAX_BYTES: usize = 4 * 1024 * 1024;
const PROACTIVE_BURST_MIN_BYTES: usize = 16 * 1024;
const PROACTIVE_BURST_MAX_BYTES: usize = 128 * 1024;
const CREDIT_QUARTERS_PER_BYTE: usize = 4;
const LINK_REFILL_QUARTERS_PER_ACCEPTED_BYTE: usize = 2;
const LINK_CREDIT_MIN_BYTES: usize = 512 * 1024;
const LINK_CREDIT_MAX_BASE_BYTES: usize = 8 * 1024 * 1024;
const LINK_SPEAKER_HEADROOM_BYTES: usize = 128 * 1024;
const LINK_SPEAKER_HEADROOM_MAX_BYTES: usize = 8 * 1024 * 1024;
const LINK_SPEAKER_IDLE: Duration = Duration::from_secs(2);
const LINK_SPEAKER_SAMPLE: Duration = Duration::from_secs(1);
const LINK_SPEAKER_EMA_ALPHA: f64 = 0.2;
const DESTINATION_PRIVATE_POOL_PCT: u8 = 25;
/// Live voice capacity accounting derived from the runtime user limit.
///
/// This type is intentionally crate-private. Its permits are held by the
/// ingress and proactive-worker queue entries until the associated work has
/// been drained or dropped.
#[derive(Clone)]
pub(crate) struct AdaptiveVoiceBudget {
    max_users: Arc<AtomicU64>,
    primary: Arc<ByteBudget>,
    proactive: Arc<ByteBudget>,
    repair_credit: Arc<RepairCreditBucket>,
    link_credits: Arc<Mutex<HashMap<NodeIdentifier, Arc<RepairCreditBucket>>>>,
}

impl AdaptiveVoiceBudget {
    pub(crate) fn new(max_users: Arc<AtomicU64>) -> Self {
        Self {
            primary: Arc::new(ByteBudget::default()),
            proactive: Arc::new(ByteBudget::default()),
            repair_credit: Arc::new(RepairCreditBucket::legacy(max_users.clone())),
            link_credits: Arc::new(Mutex::new(HashMap::new())),
            max_users,
        }
    }

    /// Reserve primary ingress capacity for an original or a repair copy.
    ///
    /// Every item costs at least [`MIN_ADMISSION_BYTES`], which also bounds
    /// the item count when callers use unbounded channels.
    pub(crate) fn try_reserve_primary(&self, bytes: usize) -> Option<VoiceBytePermit> {
        self.primary
            .try_reserve(admission_cost(bytes), self.primary_capacity_bytes())
    }

    /// Reserve lower-priority ingress capacity for a proactive copy.
    pub(crate) fn try_reserve_proactive(&self, bytes: usize) -> Option<VoiceBytePermit> {
        self.proactive
            .try_reserve(admission_cost(bytes), self.proactive_capacity_bytes())
    }

    /// Mint one quarter of a proactive byte credit for every accepted primary
    /// byte. Call this only after an original frame has entered the primary
    /// ingress lane successfully.
    #[allow(dead_code)]
    pub(crate) fn mint_proactive_credit(&self, accepted_primary_bytes: usize) -> usize {
        self.repair_credit.mint(accepted_primary_bytes)
    }

    /// Mint repair credit only on the outgoing first hop that accepted the
    /// original. Link buckets deliberately do not share credit.
    pub(crate) fn mint_link_credit(
        &self,
        first_hop: NodeIdentifier,
        sender_session: u32,
        sender_epoch: u64,
        accepted_primary_bytes: usize,
    ) -> usize {
        let bucket = self.link_bucket(first_hop);
        bucket.observe_speaker(sender_session, sender_epoch, Instant::now());
        bucket.mint(accepted_primary_bytes.saturating_mul(LINK_REFILL_QUARTERS_PER_ACCEPTED_BYTE))
    }

    pub(crate) fn reserve_link_proactive_credit_batch(
        &self,
        first_hop: NodeIdentifier,
        frame_sequence: u64,
        requests: &[ProactiveCreditRequest],
    ) -> Vec<Option<ProactiveCreditPermit>> {
        self.link_bucket(first_hop)
            .reserve_proactive_batch(frame_sequence, requests)
    }

    /// Reserve proactive-byte credit before queueing alternate repair work.
    /// Dropping the returned permit refunds it; call `commit` only after the
    /// transport accepts the actual send attempt.
    #[cfg(test)]
    pub(crate) fn try_reserve_proactive_credit(
        &self,
        proactive_bytes: usize,
    ) -> Option<ProactiveCreditPermit> {
        self.repair_credit
            .try_reserve(proactive_bytes, RepairCreditSource::Shared)
    }

    /// Reserve a batch of ordinary proactive repair opportunities in a
    /// permutation-independent order. One first copy per destination forms
    /// the private/fair-share phase; remaining copies compete in the shared
    /// overflow phase by marginal utility per encoded byte.
    pub(crate) fn reserve_proactive_credit_batch(
        &self,
        frame_sequence: u64,
        requests: &[ProactiveCreditRequest],
    ) -> Vec<Option<ProactiveCreditPermit>> {
        self.repair_credit
            .reserve_proactive_batch(frame_sequence, requests)
    }

    /// Current primary ingress ceiling in bytes.
    pub(crate) fn primary_capacity_bytes(&self) -> usize {
        primary_capacity(self.current_users())
    }

    /// Current proactive ingress/worker ceiling in bytes.
    pub(crate) fn proactive_capacity_bytes(&self) -> usize {
        proactive_capacity(self.current_users())
    }

    /// Current maximum accumulated proactive credit, in bytes.
    pub(crate) fn proactive_credit_burst_bytes(&self) -> usize {
        link_credit_base_capacity(self.current_users())
    }

    /// Byte charge currently held by primary queue entries.
    pub(crate) fn primary_reserved_bytes(&self) -> usize {
        self.primary.reserved_bytes()
    }

    /// Byte charge currently held by proactive queue entries.
    pub(crate) fn proactive_reserved_bytes(&self) -> usize {
        self.proactive.reserved_bytes()
    }

    /// Available proactive credit, rounded down to whole bytes.
    pub(crate) fn proactive_credit_balance_bytes(&self) -> usize {
        let links = self.link_credits.lock();
        let link_balance = links
            .values()
            .map(|bucket| bucket.balance_bytes())
            .sum::<usize>();
        if link_balance == 0 {
            self.repair_credit.balance_bytes()
        } else {
            link_balance
        }
    }

    /// Available proactive credit in quarter-byte units. This is mainly for
    /// aggregate telemetry and tests; admission itself uses exact units.
    #[cfg(test)]
    pub(crate) fn proactive_credit_balance_quarters(&self) -> usize {
        self.repair_credit.balance_quarters()
    }

    /// Available proactive credit and the destinations competing for it.
    pub(crate) fn repair_allocator_state_bytes(&self) -> (usize, usize) {
        let links = self.link_credits.lock();
        if links.is_empty() {
            return self.repair_credit.state_bytes();
        }
        links.values().fold((0, 0), |total, bucket| {
            let state = bucket.state_bytes();
            (total.0 + state.0, total.1 + state.1)
        })
    }

    #[cfg(test)]
    fn repair_credit_snapshot(&self) -> RepairCreditAccountingSnapshot {
        self.repair_credit.accounting_snapshot()
    }

    fn current_users(&self) -> u64 {
        self.max_users.load(Ordering::Relaxed)
    }

    fn link_bucket(&self, first_hop: NodeIdentifier) -> Arc<RepairCreditBucket> {
        let mut buckets = self.link_credits.lock();
        buckets
            .entry(first_hop)
            .or_insert_with(|| Arc::new(RepairCreditBucket::link(self.max_users.clone())))
            .clone()
    }
}

/// A byte reservation retained by a queued voice item.
///
/// It is intentionally not cloneable: duplicate queue entries must acquire
/// their own reservation. Releasing the item releases the reservation.
#[derive(Debug)]
pub(crate) struct VoiceBytePermit {
    budget: Arc<ByteBudget>,
    charged_bytes: usize,
}

impl VoiceBytePermit {
    /// The byte charge held by this reservation, including the per-item floor.
    #[cfg(test)]
    pub(crate) fn charged_bytes(&self) -> usize {
        self.charged_bytes
    }
}

impl Drop for VoiceBytePermit {
    fn drop(&mut self) {
        self.budget
            .reserved_bytes
            .fetch_sub(self.charged_bytes, Ordering::Release);
    }
}

/// A tentative reservation from the proactive token bucket.
///
/// A permit refunds itself by default, including on queue admission, expiry,
/// pressure shedding, and transport rejection. The worker calls
/// [`Self::commit`] only when a transport queue accepts the send.
#[derive(Debug)]
pub(crate) struct ProactiveCreditPermit {
    bucket: Arc<RepairCreditBucket>,
    reserved_quarters: usize,
    source: RepairCreditSource,
    destination: Option<u32>,
    private_round: u64,
    committed: bool,
}

impl ProactiveCreditPermit {
    /// Consume this credit after a transport accepts the repair payload.
    pub(crate) fn commit(mut self) {
        self.bucket.commit(&self);
        self.committed = true;
    }

    pub(crate) fn record_attempt(&self) {
        metrics::record_repair_class_bytes(
            RepairClassStage::Attempted,
            self.reserved_quarters / CREDIT_QUARTERS_PER_BYTE,
        );
        if let Some(destination) = self.destination.and_then(node_identifier) {
            metrics::record_repair_destination_bytes(
                destination,
                RepairDestinationStage::Attempted,
                self.reserved_quarters / CREDIT_QUARTERS_PER_BYTE,
            );
        }
    }

    /// Number of quarter-byte credits held by this permit.
    #[cfg(test)]
    pub(crate) fn reserved_quarters(&self) -> usize {
        self.reserved_quarters
    }

    fn refund_inner(&mut self) {
        if self.committed {
            return;
        }
        self.committed = true;
        self.bucket.refund(self);
    }
}

impl Drop for ProactiveCreditPermit {
    fn drop(&mut self) {
        self.refund_inner();
    }
}

#[derive(Debug, Default)]
struct ByteBudget {
    reserved_bytes: AtomicUsize,
}

impl ByteBudget {
    fn try_reserve(
        self: &Arc<Self>,
        charged_bytes: usize,
        capacity: usize,
    ) -> Option<VoiceBytePermit> {
        let mut reserved = self.reserved_bytes.load(Ordering::Acquire);
        loop {
            let next = reserved.checked_add(charged_bytes)?;
            if next > capacity {
                return None;
            }
            match self.reserved_bytes.compare_exchange_weak(
                reserved,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(VoiceBytePermit {
                        budget: self.clone(),
                        charged_bytes,
                    });
                }
                Err(actual) => reserved = actual,
            }
        }
    }

    fn reserved_bytes(&self) -> usize {
        self.reserved_bytes.load(Ordering::Acquire)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RepairCreditSource {
    DestinationPrivate,
    Shared,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ProactiveCreditRequest {
    destination: u32,
    bytes: usize,
    marginal_utility_micros: u64,
    copy_index: usize,
}

impl ProactiveCreditRequest {
    pub(crate) fn new(
        destination: u32,
        bytes: usize,
        marginal_utility_micros: u64,
        copy_index: usize,
    ) -> Self {
        Self {
            destination,
            bytes,
            marginal_utility_micros,
            copy_index,
        }
    }
}

#[derive(Debug, Default)]
struct RepairCreditState {
    available_quarters: usize,
    gross_minted_quarters: usize,
    tentative_quarters: usize,
    committed_quarters: usize,
    cap_discarded_quarters: usize,
    private_round: u64,
    last_private_grant: HashMap<u32, u64>,
    overflow_fairness: HashMap<u32, OverflowFairness>,
    active_destinations: usize,
}

#[derive(Debug, Clone, Copy)]
struct OverflowFairness {
    last_active_round: u64,
    last_committed_service_round: u64,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RepairCreditAccountingSnapshot {
    gross_minted_quarters: usize,
    available_quarters: usize,
    tentative_quarters: usize,
    committed_quarters: usize,
    cap_discarded_quarters: usize,
}

#[cfg(test)]
impl RepairCreditAccountingSnapshot {
    fn assert_conserved(self) {
        assert_eq!(
            self.gross_minted_quarters,
            self.available_quarters
                .saturating_add(self.tentative_quarters)
                .saturating_add(self.committed_quarters)
                .saturating_add(self.cap_discarded_quarters)
        );
    }
}

#[derive(Debug)]
struct RepairCreditBucket {
    max_users: Arc<AtomicU64>,
    speakers: Option<Mutex<LinkSpeakerState>>,
    state: Mutex<RepairCreditState>,
}

#[derive(Debug, Default)]
struct LinkSpeakerState {
    speakers: HashMap<(u32, u64), Instant>,
    ema: f64,
    last_sample: Option<Instant>,
}

impl RepairCreditBucket {
    fn legacy(max_users: Arc<AtomicU64>) -> Self {
        Self {
            max_users,
            speakers: None,
            state: Mutex::new(RepairCreditState::default()),
        }
    }

    fn link(max_users: Arc<AtomicU64>) -> Self {
        Self {
            max_users,
            speakers: Some(Mutex::new(LinkSpeakerState::default())),
            state: Mutex::new(RepairCreditState::default()),
        }
    }

    fn observe_speaker(&self, sender_session: u32, sender_epoch: u64, now: Instant) {
        let Some(speakers) = &self.speakers else {
            return;
        };
        let mut speakers = speakers.lock();
        speakers
            .speakers
            .insert((sender_session, sender_epoch), now);
        sample_link_speakers(&mut speakers, now);
    }

    fn link_speaker_headroom_bytes(&self) -> usize {
        let Some(speakers) = &self.speakers else {
            return 0;
        };
        let mut speakers = speakers.lock();
        sample_link_speakers(&mut speakers, Instant::now());
        link_speaker_headroom(speakers.ema)
    }
    /// `accepted_primary_bytes` is itself measured in quarter credits: one
    /// accepted byte produces one quarter of a proactive byte credit.
    fn mint(&self, accepted_primary_bytes: usize) -> usize {
        let cap = self.capacity_quarters();
        let mut state = self.state.lock();
        self.trim_to_capacity(&mut state, cap);
        state.gross_minted_quarters = state
            .gross_minted_quarters
            .saturating_add(accepted_primary_bytes);
        let occupied = state
            .available_quarters
            .saturating_add(state.tentative_quarters);
        let admitted = accepted_primary_bytes.min(cap.saturating_sub(occupied));
        state.cap_discarded_quarters = state
            .cap_discarded_quarters
            .saturating_add(accepted_primary_bytes - admitted);
        metrics::record_repair_credit_quarters(RepairCreditStage::Minted, accepted_primary_bytes);
        metrics::record_repair_credit_quarters(
            RepairCreditStage::CapDiscarded,
            accepted_primary_bytes - admitted,
        );
        state.available_quarters = state.available_quarters.saturating_add(admitted);
        assert_credit_conserved(&state);
        admitted
    }

    #[cfg(test)]
    fn try_reserve(
        self: &Arc<Self>,
        bytes: usize,
        source: RepairCreditSource,
    ) -> Option<ProactiveCreditPermit> {
        let reserved_quarters = bytes.checked_mul(CREDIT_QUARTERS_PER_BYTE)?;
        let cap = self.capacity_quarters();
        let mut state = self.state.lock();
        self.trim_to_capacity(&mut state, cap);
        let permit = self.reserve_locked(&mut state, reserved_quarters, source);
        if permit.is_none() {
            metrics::record_repair_class_bytes(RepairClassStage::Shed, bytes);
        }
        permit
    }

    fn reserve_proactive_batch(
        self: &Arc<Self>,
        frame_sequence: u64,
        requests: &[ProactiveCreditRequest],
    ) -> Vec<Option<ProactiveCreditPermit>> {
        let cap = self.capacity_quarters();
        let mut state = self.state.lock();
        self.trim_to_capacity(&mut state, cap);
        state.private_round = state.private_round.wrapping_add(1);
        let round = state.private_round;
        let active = requests
            .iter()
            .map(|request| request.destination)
            .collect::<HashSet<_>>();
        state.active_destinations = active.len();
        state
            .last_private_grant
            .retain(|destination, _| active.contains(destination));
        let mut grants = (0..requests.len()).map(|_| None).collect::<Vec<_>>();
        for request in requests {
            if let Some(destination) = node_identifier(request.destination) {
                metrics::record_repair_destination_bytes(
                    destination,
                    RepairDestinationStage::Requested,
                    request.bytes,
                );
            }
        }
        let mut private = requests
            .iter()
            .enumerate()
            .filter_map(|(index, request)| (request.copy_index == 0).then_some(index))
            .collect::<Vec<_>>();
        private.sort_unstable_by_key(|&index| {
            let request = requests[index];
            let last = state
                .last_private_grant
                .get(&request.destination)
                .copied()
                .unwrap_or(0);
            (
                last,
                fairness_hash(frame_sequence, request.destination),
                request.destination,
            )
        });
        let initially_available = self.proactive_available_locked(&state);
        let smallest_private = private
            .iter()
            .filter_map(|&index| requests[index].bytes.checked_mul(CREDIT_QUARTERS_PER_BYTE))
            .min()
            .unwrap_or(0);
        let private_limit = if private.len() <= 1 {
            initially_available
        } else {
            percentage(initially_available, DESTINATION_PRIVATE_POOL_PCT).max(smallest_private)
        };
        let mut private_spent = 0usize;
        for index in private {
            let request = requests[index];
            let Some(units) = request.bytes.checked_mul(CREDIT_QUARTERS_PER_BYTE) else {
                continue;
            };
            if private_spent.saturating_add(units) > private_limit {
                continue;
            }
            if let Some(mut permit) =
                self.reserve_locked(&mut state, units, RepairCreditSource::DestinationPrivate)
            {
                permit.destination = Some(request.destination);
                permit.private_round = round;
                private_spent = private_spent.saturating_add(units);
                grants[index] = Some(permit);
            }
        }

        let mut overflow = requests
            .iter()
            .enumerate()
            .filter_map(|(index, _)| grants[index].is_none().then_some(index))
            .collect::<Vec<_>>();
        let overflow_destinations = overflow
            .iter()
            .map(|&index| requests[index].destination)
            .collect::<HashSet<_>>();
        state.overflow_fairness.retain(|destination, fairness| {
            overflow_destinations.contains(destination)
                && fairness.last_active_round.wrapping_add(1) == round
        });
        for &destination in &overflow_destinations {
            state
                .overflow_fairness
                .entry(destination)
                .and_modify(|fairness| fairness.last_active_round = round)
                .or_insert(OverflowFairness {
                    last_active_round: round,
                    last_committed_service_round: round,
                });
        }
        overflow.sort_unstable_by(|&left, &right| {
            let left = requests[left];
            let right = requests[right];
            let left_age = overflow_waiting_rounds(&state, left.destination, round);
            let right_age = overflow_waiting_rounds(&state, right.destination, round);
            compare_overflow_requests(left, right, left_age, right_age, frame_sequence)
        });
        for index in overflow {
            let request = requests[index];
            let Some(units) = request.bytes.checked_mul(CREDIT_QUARTERS_PER_BYTE) else {
                continue;
            };
            grants[index] = self.reserve_locked(&mut state, units, RepairCreditSource::Shared);
            if let Some(permit) = grants[index].as_mut() {
                permit.destination = Some(request.destination);
                permit.private_round = round;
            }
        }
        for (request, grant) in requests.iter().zip(&grants) {
            let Some(destination) = node_identifier(request.destination) else {
                continue;
            };
            let stage = match grant.as_ref().map(|permit| permit.source) {
                Some(RepairCreditSource::DestinationPrivate) => {
                    RepairDestinationStage::PrivateGrant
                }
                Some(RepairCreditSource::Shared) => RepairDestinationStage::OverflowGrant,
                None => RepairDestinationStage::Shed,
            };
            metrics::record_repair_destination_bytes(destination, stage, request.bytes);
            if grant.is_none() {
                metrics::record_repair_class_bytes(RepairClassStage::Shed, request.bytes);
            }
        }
        grants
    }

    fn reserve_locked(
        self: &Arc<Self>,
        state: &mut RepairCreditState,
        reserved_quarters: usize,
        source: RepairCreditSource,
    ) -> Option<ProactiveCreditPermit> {
        if reserved_quarters > state.available_quarters {
            return None;
        }
        state.available_quarters -= reserved_quarters;
        state.tentative_quarters = state.tentative_quarters.saturating_add(reserved_quarters);
        metrics::record_repair_credit_quarters(RepairCreditStage::Reserved, reserved_quarters);
        metrics::record_repair_class_bytes(
            RepairClassStage::Granted,
            reserved_quarters / CREDIT_QUARTERS_PER_BYTE,
        );
        assert_credit_conserved(state);
        Some(ProactiveCreditPermit {
            bucket: self.clone(),
            reserved_quarters,
            source,
            destination: None,
            private_round: 0,
            committed: false,
        })
    }

    fn proactive_available_locked(&self, state: &RepairCreditState) -> usize {
        state.available_quarters
    }

    fn commit(&self, permit: &ProactiveCreditPermit) {
        let mut state = self.state.lock();
        let service_round = state.private_round;
        state.tentative_quarters = state
            .tentative_quarters
            .saturating_sub(permit.reserved_quarters);
        state.committed_quarters = state
            .committed_quarters
            .saturating_add(permit.reserved_quarters);
        metrics::record_repair_credit_quarters(
            RepairCreditStage::Committed,
            permit.reserved_quarters,
        );
        metrics::record_repair_class_bytes(
            RepairClassStage::Sent,
            permit.reserved_quarters / CREDIT_QUARTERS_PER_BYTE,
        );
        if permit.source == RepairCreditSource::DestinationPrivate
            && let Some(destination) = permit.destination
        {
            state.last_private_grant.insert(destination, service_round);
        }
        if let Some(destination) = permit.destination
            && let Some(fairness) = state.overflow_fairness.get_mut(&destination)
        {
            fairness.last_committed_service_round =
                fairness.last_committed_service_round.max(service_round);
        }
        if let Some(destination) = permit.destination {
            if let Some(destination) = node_identifier(destination) {
                metrics::record_repair_destination_bytes(
                    destination,
                    RepairDestinationStage::Sent,
                    permit.reserved_quarters / CREDIT_QUARTERS_PER_BYTE,
                );
            }
        }
        assert_credit_conserved(&state);
    }

    fn refund(&self, permit: &ProactiveCreditPermit) {
        let cap = self.capacity_quarters();
        let mut state = self.state.lock();
        self.trim_to_capacity(&mut state, cap);
        state.tentative_quarters = state
            .tentative_quarters
            .saturating_sub(permit.reserved_quarters);
        metrics::record_repair_credit_quarters(
            RepairCreditStage::Refunded,
            permit.reserved_quarters,
        );
        let occupied = state
            .available_quarters
            .saturating_add(state.tentative_quarters);
        let refunded = permit.reserved_quarters.min(cap.saturating_sub(occupied));
        state.available_quarters = state.available_quarters.saturating_add(refunded);
        state.cap_discarded_quarters = state
            .cap_discarded_quarters
            .saturating_add(permit.reserved_quarters.saturating_sub(refunded));
        metrics::record_repair_credit_quarters(
            RepairCreditStage::CapDiscarded,
            permit.reserved_quarters.saturating_sub(refunded),
        );
        assert_credit_conserved(&state);
    }

    fn balance_bytes(&self) -> usize {
        self.balance_quarters() / CREDIT_QUARTERS_PER_BYTE
    }

    fn balance_quarters(&self) -> usize {
        let mut state = self.state.lock();
        self.trim_to_capacity(&mut state, self.capacity_quarters());
        state.available_quarters
    }

    fn state_bytes(&self) -> (usize, usize) {
        let mut state = self.state.lock();
        let cap = self.capacity_quarters();
        self.trim_to_capacity(&mut state, cap);
        (
            state.available_quarters / CREDIT_QUARTERS_PER_BYTE,
            state.active_destinations,
        )
    }

    #[cfg(test)]
    fn accounting_snapshot(&self) -> RepairCreditAccountingSnapshot {
        let mut state = self.state.lock();
        self.trim_to_capacity(&mut state, self.capacity_quarters());
        RepairCreditAccountingSnapshot {
            gross_minted_quarters: state.gross_minted_quarters,
            available_quarters: state.available_quarters,
            tentative_quarters: state.tentative_quarters,
            committed_quarters: state.committed_quarters,
            cap_discarded_quarters: state.cap_discarded_quarters,
        }
    }

    fn capacity_quarters(&self) -> usize {
        let base = if self.speakers.is_some() {
            link_credit_base_capacity(self.max_users.load(Ordering::Relaxed))
                .saturating_add(self.link_speaker_headroom_bytes())
        } else {
            proactive_credit_burst(self.max_users.load(Ordering::Relaxed))
        };
        base.saturating_mul(CREDIT_QUARTERS_PER_BYTE)
    }

    fn trim_to_capacity(&self, state: &mut RepairCreditState, cap: usize) {
        let available = state.available_quarters;
        // Tentative permits are already promised to queued work and cannot be
        // evicted when the live burst cap shrinks. They still occupy capacity,
        // so trim all available credit before allowing mint above that cap.
        let allowed_available = cap.saturating_sub(state.tentative_quarters);
        let excess = available.saturating_sub(allowed_available);
        state.cap_discarded_quarters = state.cap_discarded_quarters.saturating_add(excess);
        metrics::record_repair_credit_quarters(RepairCreditStage::CapDiscarded, excess);
        state.available_quarters -= excess;
        assert_credit_conserved(state);
    }
}

fn assert_credit_conserved(state: &RepairCreditState) {
    debug_assert_eq!(
        state.gross_minted_quarters,
        state
            .available_quarters
            .saturating_add(state.tentative_quarters)
            .saturating_add(state.committed_quarters)
            .saturating_add(state.cap_discarded_quarters)
    );
}

fn percentage(value: usize, pct: u8) -> usize {
    value.saturating_mul(pct as usize) / 100
}

fn fairness_hash(sequence: u64, destination: u32) -> u64 {
    let mut value = sequence ^ u64::from(destination).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    value ^= value >> 30;
    value = value.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value ^= value >> 27;
    value.wrapping_mul(0x94D0_49BB_1331_11EB) ^ (value >> 31)
}

fn overflow_waiting_rounds(state: &RepairCreditState, destination: u32, round: u64) -> u64 {
    state
        .overflow_fairness
        .get(&destination)
        .map(|fairness| {
            round
                .saturating_sub(fairness.last_committed_service_round)
                .min(16)
        })
        .unwrap_or(0)
}

fn compare_overflow_requests(
    left: ProactiveCreditRequest,
    right: ProactiveCreditRequest,
    left_age: u64,
    right_age: u64,
    frame_sequence: u64,
) -> std::cmp::Ordering {
    u128::from(right.marginal_utility_micros)
        .saturating_mul(u128::from(32 + right_age.min(16)))
        .saturating_mul(left.bytes as u128)
        .cmp(
            &u128::from(left.marginal_utility_micros)
                .saturating_mul(u128::from(32 + left_age.min(16)))
                .saturating_mul(right.bytes as u128),
        )
        .then_with(|| {
            fairness_hash(frame_sequence, left.destination)
                .cmp(&fairness_hash(frame_sequence, right.destination))
        })
        .then_with(|| left.destination.cmp(&right.destination))
        .then_with(|| left.copy_index.cmp(&right.copy_index))
}

fn node_identifier(destination: u32) -> Option<NodeIdentifier> {
    NodeIdentifier::try_from(destination).ok()
}

fn admission_cost(bytes: usize) -> usize {
    bytes.max(MIN_ADMISSION_BYTES)
}

fn primary_capacity(users: u64) -> usize {
    users
        .saturating_mul(512)
        .clamp(PRIMARY_MIN_BYTES as u64, PRIMARY_MAX_BYTES as u64) as usize
}

fn proactive_capacity(users: u64) -> usize {
    primary_capacity(users).clamp(PROACTIVE_MIN_BYTES, PROACTIVE_MAX_BYTES)
}

fn proactive_credit_burst(users: u64) -> usize {
    (primary_capacity(users) / 32).clamp(PROACTIVE_BURST_MIN_BYTES, PROACTIVE_BURST_MAX_BYTES)
}

fn link_credit_base_capacity(users: u64) -> usize {
    primary_capacity(users)
        .saturating_mul(2)
        .clamp(LINK_CREDIT_MIN_BYTES, LINK_CREDIT_MAX_BASE_BYTES)
}

fn link_speaker_headroom(ema: f64) -> usize {
    (ema.round() as usize)
        .saturating_mul(LINK_SPEAKER_HEADROOM_BYTES)
        .min(LINK_SPEAKER_HEADROOM_MAX_BYTES)
}

fn sample_link_speakers(state: &mut LinkSpeakerState, now: Instant) {
    state
        .speakers
        .retain(|_, last_seen| now.saturating_duration_since(*last_seen) <= LINK_SPEAKER_IDLE);
    let Some(last_sample) = state.last_sample else {
        state.last_sample = Some(now);
        return;
    };
    if now.saturating_duration_since(last_sample) < LINK_SPEAKER_SAMPLE {
        return;
    }
    state.ema = LINK_SPEAKER_EMA_ALPHA * state.speakers.len() as f64
        + (1.0 - LINK_SPEAKER_EMA_ALPHA) * state.ema;
    state.last_sample = Some(now);
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{
        AdaptiveVoiceBudget, MIN_ADMISSION_BYTES, ProactiveCreditRequest,
        compare_overflow_requests, link_credit_base_capacity, link_speaker_headroom,
    };

    fn budget(users: u64) -> (Arc<AtomicU64>, AdaptiveVoiceBudget) {
        let users = Arc::new(AtomicU64::new(users));
        let budget = AdaptiveVoiceBudget::new(users.clone());
        (users, budget)
    }

    #[test]
    fn link_credit_cap_scales_from_half_to_sixteen_megabytes() {
        assert_eq!(link_credit_base_capacity(1), 512 * 1024);
        assert_eq!(link_credit_base_capacity(8_192), 8 * 1024 * 1024);
        assert_eq!(link_speaker_headroom(0.49), 0);
        assert_eq!(link_speaker_headroom(1.0), 128 * 1024);
        assert_eq!(link_speaker_headroom(64.0), 8 * 1024 * 1024);
        assert_eq!(
            link_credit_base_capacity(8_192) + link_speaker_headroom(64.0),
            16 * 1024 * 1024,
        );
    }

    #[test]
    fn link_credit_is_not_transferable_between_first_hops() {
        let budget = AdaptiveVoiceBudget::new(Arc::new(AtomicU64::new(100)));
        budget.mint_link_credit(2, 7, 11, 100);
        let granted = budget.reserve_link_proactive_credit_batch(
            2,
            1,
            &[ProactiveCreditRequest::new(9, 50, 1, 0)],
        );
        assert!(granted[0].is_some());
        let denied = budget.reserve_link_proactive_credit_batch(
            3,
            1,
            &[ProactiveCreditRequest::new(9, 1, 1, 0)],
        );
        assert!(denied[0].is_none());
    }

    #[test]
    fn capacities_follow_live_max_users() {
        let (users, budget) = budget(100);
        assert_eq!(budget.primary_capacity_bytes(), 256 * 1024);
        assert_eq!(budget.proactive_capacity_bytes(), 256 * 1024);
        assert_eq!(budget.proactive_credit_burst_bytes(), 512 * 1024);

        users.store(5_000, Ordering::Relaxed);
        assert_eq!(budget.primary_capacity_bytes(), 2_560_000);
        assert_eq!(budget.proactive_capacity_bytes(), 2_560_000);
        assert_eq!(budget.proactive_credit_burst_bytes(), 5_120_000);

        users.store(100, Ordering::Relaxed);
        assert_eq!(budget.primary_capacity_bytes(), 256 * 1024);
        assert_eq!(budget.proactive_capacity_bytes(), 256 * 1024);
        assert_eq!(budget.proactive_credit_burst_bytes(), 512 * 1024);
    }

    #[test]
    fn capacity_formulas_cap_at_both_ends() {
        let (users, budget) = budget(0);
        assert_eq!(budget.primary_capacity_bytes(), 256 * 1024);
        assert_eq!(budget.proactive_capacity_bytes(), 256 * 1024);
        assert_eq!(budget.proactive_credit_burst_bytes(), 512 * 1024);

        users.store(u64::MAX, Ordering::Relaxed);
        assert_eq!(budget.primary_capacity_bytes(), 4 * 1024 * 1024);
        assert_eq!(budget.proactive_capacity_bytes(), 4 * 1024 * 1024);
        assert_eq!(budget.proactive_credit_burst_bytes(), 8 * 1024 * 1024);
    }

    #[test]
    fn ingress_permits_are_byte_bounded_and_release_on_drop() {
        let (_, budget) = budget(100);
        let first = budget.try_reserve_primary(1).unwrap();
        assert_eq!(first.charged_bytes(), MIN_ADMISSION_BYTES);
        assert_eq!(budget.primary_reserved_bytes(), MIN_ADMISSION_BYTES);

        let remaining = budget.primary_capacity_bytes() - MIN_ADMISSION_BYTES;
        let second = budget.try_reserve_primary(remaining).unwrap();
        assert_eq!(
            budget.primary_reserved_bytes(),
            budget.primary_capacity_bytes()
        );
        assert!(budget.try_reserve_primary(1).is_none());

        drop(second);
        assert_eq!(budget.primary_reserved_bytes(), MIN_ADMISSION_BYTES);
        drop(first);
        assert_eq!(budget.primary_reserved_bytes(), 0);

        let proactive = budget.try_reserve_proactive(1).unwrap();
        assert_eq!(proactive.charged_bytes(), MIN_ADMISSION_BYTES);
        assert_eq!(budget.proactive_reserved_bytes(), MIN_ADMISSION_BYTES);
        drop(proactive);
        assert_eq!(budget.proactive_reserved_bytes(), 0);
    }

    #[test]
    fn lower_limit_blocks_new_work_without_evicting_existing_permits() {
        let (users, budget) = budget(5_000);
        let retained = budget.try_reserve_primary(300_000).unwrap();
        assert_eq!(budget.primary_reserved_bytes(), 300_000);

        users.store(100, Ordering::Relaxed);
        assert_eq!(budget.primary_capacity_bytes(), 256 * 1024);
        assert_eq!(budget.primary_reserved_bytes(), 300_000);
        assert!(budget.try_reserve_primary(1).is_none());

        drop(retained);
        assert_eq!(budget.primary_reserved_bytes(), 0);
        assert!(budget.try_reserve_primary(1).is_some());
    }

    #[test]
    fn tentative_credit_refunds_unless_committed() {
        let (_, budget) = budget(100);
        assert_eq!(budget.mint_proactive_credit(400), 400);
        assert_eq!(budget.proactive_credit_balance_quarters(), 400);
        assert_eq!(budget.proactive_credit_balance_bytes(), 100);

        assert!(budget.try_reserve_proactive_credit(101).is_none());
        {
            let permit = budget.try_reserve_proactive_credit(70).unwrap();
            assert_eq!(permit.reserved_quarters(), 280);
            assert_eq!(budget.proactive_credit_balance_bytes(), 30);
        }
        assert_eq!(budget.proactive_credit_balance_bytes(), 100);

        let permit = budget.try_reserve_proactive_credit(70).unwrap();
        permit.commit();
        assert_eq!(budget.proactive_credit_balance_bytes(), 30);
        budget.repair_credit_snapshot().assert_conserved();
    }

    #[test]
    fn proactive_credit_is_capped_and_reduced_with_live_capacity() {
        let (users, budget) = budget(5_000);
        assert_eq!(budget.mint_proactive_credit(usize::MAX), 320_000);
        assert_eq!(budget.proactive_credit_balance_bytes(), 80_000);

        users.store(100, Ordering::Relaxed);
        // The next bucket operation trims stale burst credit before it can be
        // reserved at the smaller runtime capacity.
        assert!(budget.try_reserve_proactive_credit(16_385).is_none());
        assert_eq!(budget.proactive_credit_balance_bytes(), 16 * 1024);
        budget.repair_credit_snapshot().assert_conserved();
    }

    #[test]
    fn accounting_conserves_credit_across_refund_commit_overflow_and_cap_shrink() {
        let users = Arc::new(AtomicU64::new(5_000));
        let budget = AdaptiveVoiceBudget::new(users.clone());
        budget.mint_proactive_credit(1_600);
        let permit = budget.try_reserve_proactive_credit(200).unwrap();
        budget.repair_credit_snapshot().assert_conserved();
        drop(permit);
        budget.repair_credit_snapshot().assert_conserved();
        budget.try_reserve_proactive_credit(200).unwrap().commit();
        budget.repair_credit_snapshot().assert_conserved();
        budget.mint_proactive_credit(usize::MAX / 2);
        budget.repair_credit_snapshot().assert_conserved();
        users.store(100, Ordering::Relaxed);
        budget.repair_credit_snapshot().assert_conserved();
    }

    #[test]
    fn tentative_credit_occupies_burst_capacity_during_mint_and_refund() {
        let allocator = AdaptiveVoiceBudget::new(Arc::new(AtomicU64::new(100)));
        let cap = allocator.repair_credit.capacity_quarters();
        assert_eq!(allocator.mint_proactive_credit(usize::MAX), cap);
        let permit = allocator.try_reserve_proactive_credit(100).unwrap();
        let reserved = permit.reserved_quarters();
        assert_eq!(allocator.mint_proactive_credit(reserved), 0);
        let held = allocator.repair_credit_snapshot();
        assert_eq!(held.available_quarters + held.tentative_quarters, cap);
        held.assert_conserved();

        drop(permit);
        let refunded = allocator.repair_credit_snapshot();
        assert_eq!(refunded.available_quarters, cap);
        assert_eq!(refunded.tentative_quarters, 0);
        refunded.assert_conserved();
    }

    #[test]
    fn private_fairness_is_permutation_invariant_and_rotates_low_credit() {
        fn zero_reserve_budget() -> AdaptiveVoiceBudget {
            AdaptiveVoiceBudget::new(Arc::new(AtomicU64::new(100)))
        }
        let requests = [
            ProactiveCreditRequest::new(3, 1, 100, 0),
            ProactiveCreditRequest::new(4, 1, 100, 0),
            ProactiveCreditRequest::new(15, 1, 100, 0),
        ];
        let first = zero_reserve_budget();
        let second = zero_reserve_budget();
        first.mint_proactive_credit(4);
        second.mint_proactive_credit(4);
        let first_grants = first.reserve_proactive_credit_batch(7, &requests);
        let reversed = [requests[2], requests[1], requests[0]];
        let second_grants = second.reserve_proactive_credit_batch(7, &reversed);
        let first_destination = first_grants
            .iter()
            .flatten()
            .next()
            .and_then(|permit| permit.destination);
        let second_destination = second_grants
            .iter()
            .flatten()
            .next()
            .and_then(|permit| permit.destination);
        assert_eq!(first_destination, second_destination);

        let rotating = zero_reserve_budget();
        let mut counts = HashMap::<u32, usize>::new();
        for sequence in 0..30 {
            rotating.mint_proactive_credit(4);
            let grants = rotating.reserve_proactive_credit_batch(sequence, &requests);
            let permit = grants.into_iter().flatten().next().unwrap();
            *counts.entry(permit.destination.unwrap()).or_default() += 1;
            permit.commit();
        }

        assert_eq!(counts.len(), 3);
        assert!(counts.values().all(|count| *count >= 9));
    }

    #[test]
    fn capped_private_phase_leaves_work_conserving_utility_ranked_overflow() {
        let make_budget = || AdaptiveVoiceBudget::new(Arc::new(AtomicU64::new(100)));
        let requests = [
            ProactiveCreditRequest::new(3, 1, 1, 0),
            ProactiveCreditRequest::new(4, 1, 10, 0),
            ProactiveCreditRequest::new(15, 1, 100, 0),
            ProactiveCreditRequest::new(8, 1, 1_000, 1),
        ];
        let run = |ordered: &[ProactiveCreditRequest]| {
            let budget = make_budget();
            budget.mint_proactive_credit(12);
            let grants = budget.reserve_proactive_credit_batch(19, ordered);
            let mut granted = grants
                .iter()
                .flatten()
                .map(|permit| {
                    (
                        permit.destination.unwrap(),
                        permit.source == super::RepairCreditSource::DestinationPrivate,
                    )
                })
                .collect::<Vec<_>>();
            granted.sort_unstable();
            assert_eq!(granted.len(), 3, "all affordable credit must be allocated");
            assert_eq!(granted.iter().filter(|(_, private)| *private).count(), 1);
            assert!(granted.iter().any(|(destination, _)| *destination == 8));
            granted
        };
        let forward = run(&requests);
        let reversed = [requests[3], requests[2], requests[1], requests[0]];
        assert_eq!(forward, run(&reversed));

        let private_destination = forward
            .iter()
            .find_map(|(destination, private)| private.then_some(*destination))
            .unwrap();
        let best_remaining_first = if private_destination == 15 { 4 } else { 15 };
        assert!(
            forward
                .iter()
                .any(|(destination, _)| *destination == best_remaining_first)
        );
    }

    #[test]
    fn overflow_aging_eventually_serves_a_continuously_waiting_destination() {
        let budget = AdaptiveVoiceBudget::new(Arc::new(AtomicU64::new(100)));
        let requests = [
            ProactiveCreditRequest::new(3, 1, 100, 1),
            ProactiveCreditRequest::new(4, 1, 140, 1),
        ];
        let mut served_low = None;
        for sequence in 0..17 {
            budget.mint_proactive_credit(4);
            let grants = budget.reserve_proactive_credit_batch(sequence, &requests);
            let permit = grants.into_iter().flatten().next().unwrap();
            if permit.destination == Some(3) {
                served_low = Some(sequence);
            }
            permit.commit();
            if served_low.is_some() {
                break;
            }
        }
        assert!(served_low.is_some_and(|round| round <= 16));
    }

    #[test]
    fn overflow_aging_is_permutation_invariant_and_inactivity_discards_age() {
        let make_budget = || AdaptiveVoiceBudget::new(Arc::new(AtomicU64::new(100)));
        let ordered = [
            ProactiveCreditRequest::new(3, 1, 100, 1),
            ProactiveCreditRequest::new(4, 1, 140, 1),
        ];
        let reversed = [ordered[1], ordered[0]];
        let first = make_budget();
        let second = make_budget();
        for sequence in 0..12 {
            for (budget, requests) in [(&first, ordered.as_slice()), (&second, reversed.as_slice())]
            {
                budget.mint_proactive_credit(4);
                let permit = budget
                    .reserve_proactive_credit_batch(sequence, requests)
                    .into_iter()
                    .flatten()
                    .next()
                    .unwrap();
                assert_eq!(permit.destination, Some(4));
                permit.commit();
            }
        }

        for budget in [&first, &second] {
            budget.mint_proactive_credit(4);
            budget
                .reserve_proactive_credit_batch(12, &ordered[1..])
                .into_iter()
                .flatten()
                .next()
                .unwrap()
                .commit();
        }
        first.mint_proactive_credit(4);
        second.mint_proactive_credit(4);
        let first_winner = first
            .reserve_proactive_credit_batch(13, &ordered)
            .into_iter()
            .flatten()
            .next()
            .unwrap();
        let second_winner = second
            .reserve_proactive_credit_batch(13, &reversed)
            .into_iter()
            .flatten()
            .next()
            .unwrap();
        assert_eq!(first_winner.destination, Some(4));
        assert_eq!(second_winner.destination, Some(4));
    }

    #[test]
    fn overflow_ratio_comparison_uses_u128_and_copy_index_ties() {
        let left = ProactiveCreditRequest::new(3, u32::MAX as usize - 1, u64::MAX - 1, 1);
        let right = ProactiveCreditRequest::new(3, u32::MAX as usize, u64::MAX, 2);
        let forward = compare_overflow_requests(left, right, 16, 16, 7);
        let reverse = compare_overflow_requests(right, left, 16, 16, 7);
        assert!(forward.is_lt());
        assert_eq!(forward, reverse.reverse());

        let first_copy = ProactiveCreditRequest::new(3, 1, 100, 0);
        let second_copy = ProactiveCreditRequest::new(3, 1, 100, 1);
        assert!(compare_overflow_requests(first_copy, second_copy, 0, 0, 7).is_lt());
    }

    #[test]
    fn delayed_commits_reset_overflow_service_to_current_allocator_round() {
        let budget = AdaptiveVoiceBudget::new(Arc::new(AtomicU64::new(100)));
        let request = [ProactiveCreditRequest::new(3, 1, 100, 1)];
        budget.mint_proactive_credit(4);
        let older = budget
            .reserve_proactive_credit_batch(1, &request)
            .into_iter()
            .next()
            .flatten()
            .unwrap();
        budget.mint_proactive_credit(4);
        let newer = budget
            .reserve_proactive_credit_batch(2, &request)
            .into_iter()
            .next()
            .flatten()
            .unwrap();
        budget.mint_proactive_credit(4);
        let current = budget
            .reserve_proactive_credit_batch(3, &request)
            .into_iter()
            .next()
            .flatten()
            .unwrap();
        newer.commit();
        older.commit();
        let state = budget.repair_credit.state.lock();
        assert_eq!(state.overflow_fairness[&3].last_committed_service_round, 3);
        drop(state);
        drop(current);
    }
}
