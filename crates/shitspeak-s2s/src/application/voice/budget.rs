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

use super::metrics::{
    self, RepairBudgetClass, RepairClassStage, RepairCreditStage, RepairDestinationStage,
};

const MIN_ADMISSION_BYTES: usize = 128;
const PRIMARY_MIN_BYTES: usize = 256 * 1024;
const PRIMARY_MAX_BYTES: usize = 4 * 1024 * 1024;
const PROACTIVE_MIN_BYTES: usize = 32 * 1024;
const PROACTIVE_MAX_BYTES: usize = 512 * 1024;
const PROACTIVE_BURST_MIN_BYTES: usize = 16 * 1024;
const PROACTIVE_BURST_MAX_BYTES: usize = 128 * 1024;
const CREDIT_QUARTERS_PER_BYTE: usize = 4;
const DESTINATION_PRIVATE_POOL_PCT: u8 = 25;
const REACTIVE_DEMAND_HOLD: Duration = Duration::from_secs(1);
#[cfg(test)]
const DEFAULT_REACTIVE_RESERVE_PCT: u8 = 30;
#[cfg(test)]
const DEFAULT_REACTIVE_HARD_RESERVE_PCT: u8 = 10;

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
}

impl AdaptiveVoiceBudget {
    #[cfg(test)]
    pub(crate) fn new(max_users: Arc<AtomicU64>) -> Self {
        Self::with_repair_reservations(
            max_users,
            DEFAULT_REACTIVE_RESERVE_PCT,
            DEFAULT_REACTIVE_HARD_RESERVE_PCT,
        )
    }

    pub(crate) fn with_repair_reservations(
        max_users: Arc<AtomicU64>,
        reactive_reserve_pct: u8,
        reactive_hard_reserve_pct: u8,
    ) -> Self {
        debug_assert!(reactive_hard_reserve_pct <= reactive_reserve_pct);
        debug_assert!(reactive_reserve_pct <= 100);
        Self {
            primary: Arc::new(ByteBudget::default()),
            proactive: Arc::new(ByteBudget::default()),
            repair_credit: Arc::new(RepairCreditBucket {
                max_users: max_users.clone(),
                reactive_reserve_pct,
                reactive_hard_reserve_pct,
                state: Mutex::new(RepairCreditState::default()),
            }),
            max_users,
        }
    }

    /// Reserve primary ingress capacity for an original or reactive repair.
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
    pub(crate) fn mint_proactive_credit(&self, accepted_primary_bytes: usize) -> usize {
        self.repair_credit.mint(accepted_primary_bytes)
    }

    /// Reserve proactive-byte credit before queueing alternate repair work.
    /// Dropping the returned permit refunds it; call `commit` only after the
    /// transport accepts the actual send attempt.
    #[cfg(test)]
    pub(crate) fn try_reserve_proactive_credit(
        &self,
        proactive_bytes: usize,
    ) -> Option<ProactiveCreditPermit> {
        self.repair_credit.try_reserve(
            proactive_bytes,
            RepairCreditClass::Proactive,
            RepairCreditSource::Shared,
        )
    }

    /// Reserve a batch of ordinary proactive repair opportunities in a
    /// permutation-independent order. One first copy per destination forms
    /// the private/fair-share phase; remaining copies compete in the shared
    /// overflow phase by benefit per encoded byte.
    pub(crate) fn reserve_proactive_credit_batch(
        &self,
        frame_sequence: u64,
        requests: &[ProactiveCreditRequest],
    ) -> Vec<Option<ProactiveCreditPermit>> {
        self.repair_credit
            .reserve_proactive_batch(frame_sequence, requests)
    }

    /// Reserve reactive repair payload credit. Reactive work consumes its
    /// entitlement first and may use otherwise idle proactive credit.
    pub(crate) fn try_reserve_reactive_credit(
        &self,
        bytes: usize,
    ) -> Option<ProactiveCreditPermit> {
        self.repair_credit.try_reserve(
            bytes,
            RepairCreditClass::Reactive,
            RepairCreditSource::Reactive,
        )
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
        proactive_credit_burst(self.current_users())
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
        self.repair_credit.balance_bytes()
    }

    /// Available proactive credit in quarter-byte units. This is mainly for
    /// aggregate telemetry and tests; admission itself uses exact units.
    #[cfg(test)]
    pub(crate) fn proactive_credit_balance_quarters(&self) -> usize {
        self.repair_credit.balance_quarters()
    }

    pub(crate) fn repair_allocator_state_bytes(
        &self,
    ) -> (usize, usize, usize, usize, usize, usize) {
        self.repair_credit.state_bytes()
    }

    #[cfg(test)]
    fn repair_credit_snapshot(&self) -> RepairCreditAccountingSnapshot {
        self.repair_credit.accounting_snapshot()
    }

    fn current_users(&self) -> u64 {
        self.max_users.load(Ordering::Relaxed)
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
    proactive_quarters: usize,
    reactive_quarters: usize,
    class: RepairCreditClass,
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
            metric_class(self.class),
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
pub(crate) enum RepairCreditClass {
    Proactive,
    Reactive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RepairCreditSource {
    DestinationPrivate,
    Shared,
    Reactive,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ProactiveCreditRequest {
    destination: u32,
    bytes: usize,
    benefit_micros: u64,
    copy_index: usize,
}

impl ProactiveCreditRequest {
    pub(crate) fn new(
        destination: u32,
        bytes: usize,
        benefit_micros: u64,
        copy_index: usize,
    ) -> Self {
        Self {
            destination,
            bytes,
            benefit_micros,
            copy_index,
        }
    }
}

#[derive(Debug, Default)]
struct RepairCreditState {
    proactive_quarters: usize,
    reactive_quarters: usize,
    borrowed_reactive_quarters: usize,
    borrowed_proactive_quarters: usize,
    reactive_mint_remainder: usize,
    reactive_reservations: usize,
    reactive_demand_until: Option<Instant>,
    gross_minted_quarters: usize,
    tentative_quarters: usize,
    committed_quarters: usize,
    cap_discarded_quarters: usize,
    private_round: u64,
    last_private_grant: HashMap<u32, u64>,
    active_destinations: usize,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RepairCreditAccountingSnapshot {
    gross_minted_quarters: usize,
    available_quarters: usize,
    tentative_quarters: usize,
    committed_quarters: usize,
    cap_discarded_quarters: usize,
    proactive_quarters: usize,
    reactive_quarters: usize,
    debt_to_reactive_quarters: usize,
    debt_to_proactive_quarters: usize,
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
    reactive_reserve_pct: u8,
    reactive_hard_reserve_pct: u8,
    state: Mutex<RepairCreditState>,
}

impl RepairCreditBucket {
    /// `accepted_primary_bytes` is itself measured in quarter credits: one
    /// accepted byte produces one quarter of a proactive byte credit.
    fn mint(&self, accepted_primary_bytes: usize) -> usize {
        let cap = self.capacity_quarters();
        let mut state = self.state.lock();
        self.trim_to_capacity(&mut state, cap);
        state.gross_minted_quarters = state
            .gross_minted_quarters
            .saturating_add(accepted_primary_bytes);
        let before = state
            .proactive_quarters
            .saturating_add(state.reactive_quarters);
        let admitted = accepted_primary_bytes.min(cap.saturating_sub(before));
        state.cap_discarded_quarters = state
            .cap_discarded_quarters
            .saturating_add(accepted_primary_bytes - admitted);
        metrics::record_repair_credit_quarters(RepairCreditStage::Minted, accepted_primary_bytes);
        metrics::record_repair_credit_quarters(
            RepairCreditStage::CapDiscarded,
            accepted_primary_bytes - admitted,
        );
        let reactive_target = percentage(cap, self.reactive_reserve_pct);

        let apportioned = admitted
            .saturating_mul(self.reactive_reserve_pct as usize)
            .saturating_add(state.reactive_mint_remainder);
        let desired_reactive_share = apportioned / 100;
        state.reactive_mint_remainder = apportioned % 100;
        let mut reactive_share = desired_reactive_share;
        let mut proactive_share = admitted - desired_reactive_share;
        let effective_hard_reserve = percentage(
            before.saturating_add(admitted),
            self.reactive_hard_reserve_pct,
        );
        let hard_need = effective_hard_reserve.saturating_sub(state.reactive_quarters);
        let hard_shift = hard_need
            .saturating_sub(reactive_share)
            .min(proactive_share);
        reactive_share = reactive_share.saturating_add(hard_shift);
        proactive_share -= hard_shift;
        let reactive_room = reactive_target.saturating_sub(state.reactive_quarters);
        let repay_reactive = proactive_share
            .min(state.borrowed_reactive_quarters)
            .min(reactive_room.saturating_sub(reactive_share.min(reactive_room)));
        state.borrowed_reactive_quarters -= repay_reactive;
        metrics::record_repair_class_bytes(
            RepairBudgetClass::Reactive,
            RepairClassStage::Repaid,
            repay_reactive / CREDIT_QUARTERS_PER_BYTE,
        );
        proactive_share -= repay_reactive;
        let protected_reactive_share = hard_need.min(reactive_share);
        let repay_proactive = reactive_share
            .saturating_sub(protected_reactive_share)
            .min(state.borrowed_proactive_quarters);
        state.borrowed_proactive_quarters -= repay_proactive;
        metrics::record_repair_class_bytes(
            RepairBudgetClass::Proactive,
            RepairClassStage::Repaid,
            repay_proactive / CREDIT_QUARTERS_PER_BYTE,
        );
        reactive_share -= repay_proactive;
        state.reactive_quarters = state
            .reactive_quarters
            .saturating_add(reactive_share.min(reactive_room))
            .saturating_add(repay_reactive);
        state.proactive_quarters = state
            .proactive_quarters
            .saturating_add(proactive_share)
            .saturating_add(repay_proactive)
            .saturating_add(reactive_share.saturating_sub(reactive_room));
        assert_credit_conserved(&state);
        admitted
    }

    fn try_reserve(
        self: &Arc<Self>,
        bytes: usize,
        class: RepairCreditClass,
        source: RepairCreditSource,
    ) -> Option<ProactiveCreditPermit> {
        let reserved_quarters = bytes.checked_mul(CREDIT_QUARTERS_PER_BYTE)?;
        let cap = self.capacity_quarters();
        let mut state = self.state.lock();
        self.trim_to_capacity(&mut state, cap);
        let permit = self.reserve_locked(&mut state, reserved_quarters, class, source);
        if permit.is_none() {
            metrics::record_repair_class_bytes(metric_class(class), RepairClassStage::Shed, bytes);
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
            if let Some(mut permit) = self.reserve_locked(
                &mut state,
                units,
                RepairCreditClass::Proactive,
                RepairCreditSource::DestinationPrivate,
            ) {
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
        overflow.sort_unstable_by(|&left, &right| {
            let left = requests[left];
            let right = requests[right];
            right
                .benefit_micros
                .saturating_mul(left.bytes as u64)
                .cmp(&left.benefit_micros.saturating_mul(right.bytes as u64))
                .then_with(|| {
                    fairness_hash(frame_sequence, left.destination)
                        .cmp(&fairness_hash(frame_sequence, right.destination))
                })
                .then_with(|| left.destination.cmp(&right.destination))
                .then_with(|| left.copy_index.cmp(&right.copy_index))
        });
        for index in overflow {
            let request = requests[index];
            let Some(units) = request.bytes.checked_mul(CREDIT_QUARTERS_PER_BYTE) else {
                continue;
            };
            grants[index] = self.reserve_locked(
                &mut state,
                units,
                RepairCreditClass::Proactive,
                RepairCreditSource::Shared,
            );
            if let Some(permit) = grants[index].as_mut() {
                permit.destination = Some(request.destination);
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
                Some(RepairCreditSource::Reactive) => continue,
                None => RepairDestinationStage::Shed,
            };
            metrics::record_repair_destination_bytes(destination, stage, request.bytes);
            if grant.is_none() {
                metrics::record_repair_class_bytes(
                    RepairBudgetClass::Proactive,
                    RepairClassStage::Shed,
                    request.bytes,
                );
            }
        }
        grants
    }

    fn reserve_locked(
        self: &Arc<Self>,
        state: &mut RepairCreditState,
        reserved_quarters: usize,
        class: RepairCreditClass,
        source: RepairCreditSource,
    ) -> Option<ProactiveCreditPermit> {
        let hard_reserve = percentage(self.capacity_quarters(), self.reactive_hard_reserve_pct);
        let (proactive_quarters, reactive_quarters) = match class {
            RepairCreditClass::Proactive => {
                let proactive = reserved_quarters.min(state.proactive_quarters);
                let needed = reserved_quarters - proactive;
                let reactive_demand_active = state
                    .reactive_demand_until
                    .is_some_and(|until| until > Instant::now());
                let borrowable = if state.reactive_reservations > 0 || reactive_demand_active {
                    0
                } else {
                    state.reactive_quarters.saturating_sub(hard_reserve)
                };
                if needed > borrowable {
                    return None;
                }
                (proactive, needed)
            }
            RepairCreditClass::Reactive => {
                state.reactive_demand_until = Instant::now().checked_add(REACTIVE_DEMAND_HOLD);
                let reactive = reserved_quarters.min(state.reactive_quarters);
                let needed = reserved_quarters - reactive;
                if needed > state.proactive_quarters {
                    return None;
                }
                (needed, reactive)
            }
        };
        state.proactive_quarters -= proactive_quarters;
        state.reactive_quarters -= reactive_quarters;
        state.tentative_quarters = state.tentative_quarters.saturating_add(reserved_quarters);
        if class == RepairCreditClass::Reactive {
            state.reactive_reservations = state.reactive_reservations.saturating_add(1);
        }
        metrics::record_repair_credit_quarters(RepairCreditStage::Reserved, reserved_quarters);
        metrics::record_repair_class_bytes(
            metric_class(class),
            RepairClassStage::Granted,
            reserved_quarters / CREDIT_QUARTERS_PER_BYTE,
        );
        if class == RepairCreditClass::Proactive && reactive_quarters > 0 {
            metrics::record_repair_class_bytes(
                RepairBudgetClass::Proactive,
                RepairClassStage::Borrowed,
                reactive_quarters / CREDIT_QUARTERS_PER_BYTE,
            );
        } else if class == RepairCreditClass::Reactive && proactive_quarters > 0 {
            metrics::record_repair_class_bytes(
                RepairBudgetClass::Reactive,
                RepairClassStage::Borrowed,
                proactive_quarters / CREDIT_QUARTERS_PER_BYTE,
            );
        }
        assert_credit_conserved(state);
        Some(ProactiveCreditPermit {
            bucket: self.clone(),
            reserved_quarters,
            proactive_quarters,
            reactive_quarters,
            class,
            source,
            destination: None,
            private_round: 0,
            committed: false,
        })
    }

    fn proactive_available_locked(&self, state: &RepairCreditState) -> usize {
        let hard_reserve = percentage(self.capacity_quarters(), self.reactive_hard_reserve_pct);
        state
            .proactive_quarters
            .saturating_add(state.reactive_quarters.saturating_sub(hard_reserve))
    }

    fn commit(&self, permit: &ProactiveCreditPermit) {
        let mut state = self.state.lock();
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
            metric_class(permit.class),
            RepairClassStage::Sent,
            permit.reserved_quarters / CREDIT_QUARTERS_PER_BYTE,
        );
        if permit.class == RepairCreditClass::Reactive {
            state.reactive_reservations = state.reactive_reservations.saturating_sub(1);
            let net = permit
                .proactive_quarters
                .min(state.borrowed_reactive_quarters);
            state.borrowed_reactive_quarters -= net;
            state.borrowed_proactive_quarters = state
                .borrowed_proactive_quarters
                .saturating_add(permit.proactive_quarters - net);
        } else if permit.reactive_quarters > 0 {
            let net = permit
                .reactive_quarters
                .min(state.borrowed_proactive_quarters);
            state.borrowed_proactive_quarters -= net;
            state.borrowed_reactive_quarters = state
                .borrowed_reactive_quarters
                .saturating_add(permit.reactive_quarters - net);
        }
        if permit.source == RepairCreditSource::DestinationPrivate
            && let Some(destination) = permit.destination
        {
            state
                .last_private_grant
                .insert(destination, permit.private_round);
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
        if permit.class == RepairCreditClass::Reactive {
            state.reactive_reservations = state.reactive_reservations.saturating_sub(1);
        }
        let room = cap.saturating_sub(
            state
                .proactive_quarters
                .saturating_add(state.reactive_quarters),
        );
        let reactive = permit.reactive_quarters.min(room);
        state.reactive_quarters = state.reactive_quarters.saturating_add(reactive);
        let room = room - reactive;
        state.proactive_quarters = state
            .proactive_quarters
            .saturating_add(permit.proactive_quarters.min(room));
        let refunded = reactive.saturating_add(permit.proactive_quarters.min(room));
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
        state
            .proactive_quarters
            .saturating_add(state.reactive_quarters)
    }

    fn state_bytes(&self) -> (usize, usize, usize, usize, usize, usize) {
        let mut state = self.state.lock();
        let cap = self.capacity_quarters();
        self.trim_to_capacity(&mut state, cap);
        (
            state.proactive_quarters / CREDIT_QUARTERS_PER_BYTE,
            state.reactive_quarters / CREDIT_QUARTERS_PER_BYTE,
            percentage(cap, self.reactive_hard_reserve_pct) / CREDIT_QUARTERS_PER_BYTE,
            state.borrowed_reactive_quarters / CREDIT_QUARTERS_PER_BYTE,
            state.borrowed_proactive_quarters / CREDIT_QUARTERS_PER_BYTE,
            state.active_destinations,
        )
    }

    #[cfg(test)]
    fn accounting_snapshot(&self) -> RepairCreditAccountingSnapshot {
        let mut state = self.state.lock();
        self.trim_to_capacity(&mut state, self.capacity_quarters());
        RepairCreditAccountingSnapshot {
            gross_minted_quarters: state.gross_minted_quarters,
            available_quarters: state
                .proactive_quarters
                .saturating_add(state.reactive_quarters),
            tentative_quarters: state.tentative_quarters,
            committed_quarters: state.committed_quarters,
            cap_discarded_quarters: state.cap_discarded_quarters,
            proactive_quarters: state.proactive_quarters,
            reactive_quarters: state.reactive_quarters,
            debt_to_reactive_quarters: state.borrowed_reactive_quarters,
            debt_to_proactive_quarters: state.borrowed_proactive_quarters,
        }
    }

    fn capacity_quarters(&self) -> usize {
        proactive_credit_burst(self.max_users.load(Ordering::Relaxed))
            .saturating_mul(CREDIT_QUARTERS_PER_BYTE)
    }

    fn trim_to_capacity(&self, state: &mut RepairCreditState, cap: usize) {
        let total = state
            .proactive_quarters
            .saturating_add(state.reactive_quarters);
        let mut excess = total.saturating_sub(cap);
        state.cap_discarded_quarters = state.cap_discarded_quarters.saturating_add(excess);
        metrics::record_repair_credit_quarters(RepairCreditStage::CapDiscarded, excess);
        let trim = excess.min(state.proactive_quarters);
        state.proactive_quarters -= trim;
        excess -= trim;
        state.reactive_quarters = state.reactive_quarters.saturating_sub(excess);
        state.borrowed_reactive_quarters = state
            .borrowed_reactive_quarters
            .min(percentage(cap, self.reactive_reserve_pct));
        state.borrowed_proactive_quarters = state.borrowed_proactive_quarters.min(cap);
        assert_credit_conserved(state);
    }
}

fn assert_credit_conserved(state: &RepairCreditState) {
    debug_assert_eq!(
        state.gross_minted_quarters,
        state
            .proactive_quarters
            .saturating_add(state.reactive_quarters)
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

fn metric_class(class: RepairCreditClass) -> RepairBudgetClass {
    match class {
        RepairCreditClass::Proactive => RepairBudgetClass::Proactive,
        RepairCreditClass::Reactive => RepairBudgetClass::Reactive,
    }
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
    (primary_capacity(users) / 8).clamp(PROACTIVE_MIN_BYTES, PROACTIVE_MAX_BYTES)
}

fn proactive_credit_burst(users: u64) -> usize {
    (primary_capacity(users) / 32).clamp(PROACTIVE_BURST_MIN_BYTES, PROACTIVE_BURST_MAX_BYTES)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{AdaptiveVoiceBudget, MIN_ADMISSION_BYTES, ProactiveCreditRequest, percentage};

    fn budget(users: u64) -> (Arc<AtomicU64>, AdaptiveVoiceBudget) {
        let users = Arc::new(AtomicU64::new(users));
        let budget = AdaptiveVoiceBudget::new(users.clone());
        (users, budget)
    }

    #[test]
    fn capacities_follow_live_max_users() {
        let (users, budget) = budget(100);
        assert_eq!(budget.primary_capacity_bytes(), 256 * 1024);
        assert_eq!(budget.proactive_capacity_bytes(), 32 * 1024);
        assert_eq!(budget.proactive_credit_burst_bytes(), 16 * 1024);

        users.store(5_000, Ordering::Relaxed);
        assert_eq!(budget.primary_capacity_bytes(), 2_560_000);
        assert_eq!(budget.proactive_capacity_bytes(), 320_000);
        assert_eq!(budget.proactive_credit_burst_bytes(), 80_000);

        users.store(100, Ordering::Relaxed);
        assert_eq!(budget.primary_capacity_bytes(), 256 * 1024);
        assert_eq!(budget.proactive_capacity_bytes(), 32 * 1024);
        assert_eq!(budget.proactive_credit_burst_bytes(), 16 * 1024);
    }

    #[test]
    fn capacity_formulas_cap_at_both_ends() {
        let (users, budget) = budget(0);
        assert_eq!(budget.primary_capacity_bytes(), 256 * 1024);
        assert_eq!(budget.proactive_capacity_bytes(), 32 * 1024);
        assert_eq!(budget.proactive_credit_burst_bytes(), 16 * 1024);

        users.store(u64::MAX, Ordering::Relaxed);
        assert_eq!(budget.primary_capacity_bytes(), 4 * 1024 * 1024);
        assert_eq!(budget.proactive_capacity_bytes(), 512 * 1024);
        assert_eq!(budget.proactive_credit_burst_bytes(), 128 * 1024);
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
    fn class_reserve_is_preserved_and_tentative_credit_refunds() {
        let (_, budget) = budget(100);
        assert_eq!(budget.mint_proactive_credit(400), 400);
        assert_eq!(budget.proactive_credit_balance_quarters(), 400);
        assert_eq!(budget.proactive_credit_balance_bytes(), 100);

        assert!(budget.try_reserve_proactive_credit(75).is_none());
        let permit = budget.try_reserve_proactive_credit(70).unwrap();
        assert_eq!(permit.reserved_quarters(), 280);
        assert_eq!(budget.proactive_credit_balance_bytes(), 30);
        drop(permit);
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
    fn reactive_apportionment_is_invariant_to_mint_chunking() {
        let (_, one_chunk) = budget(100);
        let (_, many_chunks) = budget(100);
        one_chunk.mint_proactive_credit(100);
        for _ in 0..100 {
            many_chunks.mint_proactive_credit(1);
        }
        let one = one_chunk.repair_credit_snapshot();
        let many = many_chunks.repair_credit_snapshot();
        one.assert_conserved();
        many.assert_conserved();
        assert_eq!(one.proactive_quarters, many.proactive_quarters);
        assert_eq!(one.reactive_quarters, many.reactive_quarters);
        assert_eq!(one.proactive_quarters, 70);
        assert_eq!(one.reactive_quarters, 30);
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
        budget.try_reserve_reactive_credit(200).unwrap().commit();
        budget.repair_credit_snapshot().assert_conserved();
        budget.mint_proactive_credit(usize::MAX / 2);
        budget.repair_credit_snapshot().assert_conserved();
        users.store(100, Ordering::Relaxed);
        budget.repair_credit_snapshot().assert_conserved();
    }

    #[test]
    fn private_fairness_is_permutation_invariant_and_rotates_low_credit() {
        fn zero_reserve_budget() -> AdaptiveVoiceBudget {
            AdaptiveVoiceBudget::with_repair_reservations(Arc::new(AtomicU64::new(100)), 0, 0)
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
    fn capped_private_phase_leaves_work_conserving_benefit_ranked_overflow() {
        let make_budget =
            || AdaptiveVoiceBudget::with_repair_reservations(Arc::new(AtomicU64::new(100)), 0, 0);
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
    fn symmetric_borrowing_records_directional_debt_and_refill_repayment() {
        let borrowing_budget =
            || AdaptiveVoiceBudget::with_repair_reservations(Arc::new(AtomicU64::new(100)), 30, 0);
        let proactive_borrower = borrowing_budget();
        proactive_borrower.mint_proactive_credit(400);
        proactive_borrower
            .try_reserve_proactive_credit(80)
            .unwrap()
            .commit();
        let borrowed = proactive_borrower.repair_credit_snapshot();
        assert_eq!(borrowed.debt_to_reactive_quarters, 40);
        assert_eq!(borrowed.debt_to_proactive_quarters, 0);
        proactive_borrower.mint_proactive_credit(40);
        let refilled = proactive_borrower.repair_credit_snapshot();
        assert!(refilled.debt_to_reactive_quarters < borrowed.debt_to_reactive_quarters);
        refilled.assert_conserved();

        let reactive_borrower = borrowing_budget();
        reactive_borrower.mint_proactive_credit(400);
        reactive_borrower
            .try_reserve_reactive_credit(40)
            .unwrap()
            .commit();
        let borrowed = reactive_borrower.repair_credit_snapshot();
        assert_eq!(borrowed.debt_to_proactive_quarters, 40);
        assert_eq!(borrowed.debt_to_reactive_quarters, 0);
        reactive_borrower.mint_proactive_credit(40);
        let refilled = reactive_borrower.repair_credit_snapshot();
        assert!(refilled.debt_to_proactive_quarters < borrowed.debt_to_proactive_quarters);
        refilled.assert_conserved();
    }

    #[test]
    fn reactive_demand_hold_blocks_new_proactive_borrowing() {
        let budget =
            AdaptiveVoiceBudget::with_repair_reservations(Arc::new(AtomicU64::new(100)), 30, 0);
        budget.mint_proactive_credit(400);
        assert!(budget.try_reserve_reactive_credit(101).is_none());
        assert!(budget.try_reserve_proactive_credit(75).is_none());
        let owned = budget.try_reserve_proactive_credit(70).unwrap();
        drop(owned);
        budget.repair_credit_snapshot().assert_conserved();
    }

    #[test]
    fn alternating_class_pressure_nets_debt_and_refill_restores_hard_reserve() {
        let allocator =
            AdaptiveVoiceBudget::with_repair_reservations(Arc::new(AtomicU64::new(100)), 30, 0);
        allocator.mint_proactive_credit(400);
        allocator.try_reserve_proactive_credit(80).unwrap().commit();
        assert_eq!(
            allocator.repair_credit_snapshot().debt_to_reactive_quarters,
            40
        );
        allocator.mint_proactive_credit(400);
        allocator.try_reserve_reactive_credit(80).unwrap().commit();
        let reversed = allocator.repair_credit_snapshot();
        assert_eq!(reversed.debt_to_reactive_quarters, 0);
        assert!(reversed.debt_to_proactive_quarters > 0);
        allocator.mint_proactive_credit(400);
        let converged = allocator.repair_credit_snapshot();
        assert_eq!(converged.debt_to_reactive_quarters, 0);
        assert_eq!(converged.debt_to_proactive_quarters, 0);
        converged.assert_conserved();

        let (_, protected) = budget(100);
        protected.mint_proactive_credit(400);
        protected.try_reserve_reactive_credit(40).unwrap().commit();
        protected.mint_proactive_credit(40);
        let restored = protected.repair_credit_snapshot();
        let available = restored
            .proactive_quarters
            .saturating_add(restored.reactive_quarters);
        assert!(restored.reactive_quarters >= percentage(available, 10));
        restored.assert_conserved();
    }
}
