//! Adaptive, byte-based admission limits for voice work.
//!
//! Capacity is sampled when work is reserved. Lowering `max_users` therefore
//! constrains later admission without evicting work which is already queued.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use shitspeak_core::NodeIdentifier;
use tokio::sync::{Notify, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use super::metrics::{
    self, RepairBudgetClass, RepairClassStage, RepairCreditStage, RepairDestinationStage,
};

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
const REACTIVE_DEMAND_HOLD: Duration = Duration::from_secs(1);
const REACTIVE_SCHEDULER_QUANTUM_BYTES: usize = 1_200;
const REACTIVE_RETRY_EPOCH: Duration = Duration::from_millis(100);
const REACTIVE_RETRY_SHARE_PCT: usize = 50;
const REACTIVE_SCHEDULER_RECEIVE_BATCH: usize = 256;
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
    link_credits: Arc<Mutex<HashMap<NodeIdentifier, Arc<RepairCreditBucket>>>>,
    link_schedulers: Arc<Mutex<HashMap<NodeIdentifier, ReactiveCreditScheduler>>>,
    #[allow(dead_code)]
    reactive_scheduler: Arc<OnceLock<ReactiveCreditScheduler>>,
    reactive_scheduler_shutdown: CancellationToken,
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
            repair_credit: Arc::new(RepairCreditBucket::legacy(
                max_users.clone(),
                reactive_reserve_pct,
                reactive_hard_reserve_pct,
            )),
            link_credits: Arc::new(Mutex::new(HashMap::new())),
            link_schedulers: Arc::new(Mutex::new(HashMap::new())),
            reactive_scheduler: Arc::new(OnceLock::new()),
            reactive_scheduler_shutdown: CancellationToken::new(),
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

    pub(crate) async fn reserve_link_reactive_credit_scheduled(
        &self,
        first_hop: NodeIdentifier,
        destination: u32,
        bytes: usize,
        deadline: Instant,
        retry: bool,
    ) -> Option<ProactiveCreditPermit> {
        let scheduler = {
            let mut schedulers = self.link_schedulers.lock();
            schedulers
                .entry(first_hop)
                .or_insert_with(|| {
                    ReactiveCreditScheduler::spawn(
                        self.link_bucket(first_hop),
                        self.reactive_scheduler_shutdown.clone(),
                    )
                })
                .clone()
        };
        scheduler.reserve(destination, bytes, deadline, retry).await
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
    /// overflow phase by marginal utility per encoded byte.
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
    #[cfg(test)]
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

    #[allow(dead_code)]
    pub(crate) async fn reserve_reactive_credit_scheduled(
        &self,
        destination: u32,
        bytes: usize,
        deadline: Instant,
        retry: bool,
    ) -> Option<ProactiveCreditPermit> {
        let scheduler = self.reactive_scheduler.get_or_init(|| {
            ReactiveCreditScheduler::spawn(
                self.repair_credit.clone(),
                self.reactive_scheduler_shutdown.clone(),
            )
        });
        scheduler.reserve(destination, bytes, deadline, retry).await
    }

    pub(crate) fn link_reactive_scheduler_shutdown(&self, shutdown: CancellationToken) {
        let scheduler_shutdown = self.reactive_scheduler_shutdown.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = shutdown.cancelled() => scheduler_shutdown.cancel(),
                _ = scheduler_shutdown.cancelled() => {}
            }
        });
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

    /// Available credit in quarter-byte units on the per-first-hop link
    /// bucket for `first_hop`. Tail, reactive-response, and proactive-copy
    /// dispatch reserve from the link bucket the accepted original flowed
    /// through, so tests that seed credit must assert against this bucket
    /// rather than the shared repair bucket.
    #[cfg(test)]
    pub(crate) fn link_credit_balance_quarters(&self, first_hop: NodeIdentifier) -> usize {
        self.link_credits
            .lock()
            .get(&first_hop)
            .map(|bucket| bucket.balance_quarters())
            .unwrap_or(0)
    }

    pub(crate) fn repair_allocator_state_bytes(
        &self,
    ) -> (usize, usize, usize, usize, usize, usize) {
        let links = self.link_credits.lock();
        if links.is_empty() {
            return self.repair_credit.state_bytes();
        }
        links.values().fold((0, 0, 0, 0, 0, 0), |total, bucket| {
            let state = bucket.state_bytes();
            (
                total.0 + state.0,
                total.1 + state.1,
                total.2 + state.2,
                total.3 + state.3,
                total.4 + state.4,
                total.5 + state.5,
            )
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
            .or_insert_with(|| {
                Arc::new(RepairCreditBucket::link(
                    self.max_users.clone(),
                    self.repair_credit.reactive_reserve_pct,
                    self.repair_credit.reactive_hard_reserve_pct,
                ))
            })
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
    proactive_quarters: usize,
    reactive_quarters: usize,
    class: RepairCreditClass,
    source: RepairCreditSource,
    destination: Option<u32>,
    private_round: u64,
    borrow_id: Option<u64>,
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

#[derive(Clone)]
struct ReactiveCreditScheduler {
    tx: mpsc::UnboundedSender<ReactiveScheduleRequest>,
    next_request_id: Arc<AtomicU64>,
}

struct ReactiveScheduleRequest {
    id: u64,
    destination: u32,
    bytes: usize,
    deadline: Instant,
    enqueued_at: Instant,
    retry: bool,
    response: oneshot::Sender<Option<ProactiveCreditPermit>>,
}

#[derive(Default)]
struct ReactiveDestinationQueue {
    deficit_bytes: usize,
    pending: Vec<ReactiveScheduleRequest>,
}

struct ReactiveScheduleState {
    destinations: HashMap<u32, ReactiveDestinationQueue>,
    retry_epoch_started: Instant,
    retry_bytes: HashMap<u32, usize>,
    service_clock: u64,
    last_service: HashMap<u32, u64>,
}

impl ReactiveScheduleState {
    fn new() -> Self {
        Self {
            destinations: HashMap::new(),
            retry_epoch_started: Instant::now(),
            retry_bytes: HashMap::new(),
            service_clock: 0,
            last_service: HashMap::new(),
        }
    }

    fn enqueue(&mut self, request: ReactiveScheduleRequest) {
        let destination = request.destination;
        let queue = self.destinations.entry(destination).or_default();
        let position = queue
            .pending
            .partition_point(|pending| pending.deadline <= request.deadline);
        queue.pending.insert(position, request);
    }

    fn reset_retry_epoch_if_due(&mut self, now: Instant) {
        if now.saturating_duration_since(self.retry_epoch_started) >= REACTIVE_RETRY_EPOCH {
            self.retry_epoch_started = now;
            self.retry_bytes.clear();
        }
    }

    fn pop_next(
        &mut self,
        retry_cap_bytes: usize,
        now: Instant,
        credit_blocked: &HashSet<u64>,
    ) -> Option<ReactiveScheduleRequest> {
        self.reset_retry_epoch_if_due(now);
        self.remove_expired(now);
        let mut destinations = self.destinations.keys().copied().collect::<Vec<_>>();
        destinations.sort_unstable_by_key(|destination| {
            (
                self.last_service.get(destination).copied().unwrap_or(0),
                *destination,
            )
        });
        if destinations.is_empty() {
            return None;
        }
        let largest_quanta = self
            .destinations
            .iter()
            .filter_map(|(destination, queue)| {
                let retry_used = self.retry_bytes.get(destination).copied().unwrap_or(0);
                queue.pending.iter().find(|request| {
                    !credit_blocked.contains(&request.id)
                        && (!request.retry
                            || retry_used.saturating_add(request.bytes) <= retry_cap_bytes)
                })
            })
            .map(|request| request.bytes.div_ceil(REACTIVE_SCHEDULER_QUANTUM_BYTES))
            .max()
            .unwrap_or(1);
        for _ in 0..largest_quanta.max(1) {
            for &destination in &destinations {
                let Some(queue) = self.destinations.get_mut(&destination) else {
                    continue;
                };
                let retry_used = self.retry_bytes.get(&destination).copied().unwrap_or(0);
                let Some(eligible_index) = queue.pending.iter().position(|request| {
                    !credit_blocked.contains(&request.id)
                        && (!request.retry
                            || retry_used.saturating_add(request.bytes) <= retry_cap_bytes)
                }) else {
                    metrics::record_reactive_scheduler_event(
                        metrics::ReactiveSchedulerEvent::RetryDeferred,
                    );
                    continue;
                };
                let eligible_bytes = queue.pending[eligible_index].bytes;
                queue.deficit_bytes = queue
                    .deficit_bytes
                    .saturating_add(REACTIVE_SCHEDULER_QUANTUM_BYTES);
                if eligible_bytes <= queue.deficit_bytes {
                    let request = queue.pending.remove(eligible_index);
                    // The deficit and service clock are charged only after an
                    // actual permit reaches the requester. A credit miss is
                    // requeued without consuming its fair turn.
                    return Some(request);
                }
            }
        }
        None
    }

    fn record_grant(&mut self, destination: u32, bytes: usize, retry: bool) {
        if let Some(queue) = self.destinations.get_mut(&destination) {
            queue.deficit_bytes = queue.deficit_bytes.saturating_sub(bytes);
            if queue.pending.is_empty() {
                self.destinations.remove(&destination);
            }
        }
        if retry {
            let used = self.retry_bytes.entry(destination).or_default();
            *used = used.saturating_add(bytes);
        }
        self.service_clock = self.service_clock.wrapping_add(1).max(1);
        self.last_service.insert(destination, self.service_clock);
    }

    fn discard_selected(&mut self, destination: u32) {
        if self
            .destinations
            .get(&destination)
            .is_some_and(|queue| queue.pending.is_empty())
        {
            self.destinations.remove(&destination);
        }
    }

    fn requeue(&mut self, request: ReactiveScheduleRequest) {
        self.enqueue(request);
    }

    fn remove_expired(&mut self, now: Instant) {
        let destinations = self.destinations.keys().copied().collect::<Vec<_>>();
        for destination in destinations {
            let Some(queue) = self.destinations.get_mut(&destination) else {
                continue;
            };
            while queue
                .pending
                .first()
                .is_some_and(|request| request.deadline <= now)
            {
                let expired = queue.pending.remove(0);
                metrics::record_reactive_scheduler_event(
                    metrics::ReactiveSchedulerEvent::DeadlineExpired,
                );
                let _ = expired.response.send(None);
            }
            if queue.pending.is_empty() {
                self.destinations.remove(&destination);
                self.retry_bytes.remove(&destination);
            }
        }
    }

    fn active_destinations(&self) -> usize {
        self.destinations.len()
    }

    fn is_empty(&self) -> bool {
        self.destinations.is_empty()
    }

    fn retry_epoch_deadline(&self) -> Instant {
        self.retry_epoch_started + REACTIVE_RETRY_EPOCH
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.destinations
            .values()
            .filter_map(|queue| queue.pending.first().map(|request| request.deadline))
            .min()
    }

    fn publish_metrics(&self, now: Instant) {
        let queued_items = self
            .destinations
            .values()
            .map(|queue| queue.pending.len())
            .sum();
        let queued_encoded_bytes = self
            .destinations
            .values()
            .flat_map(|queue| &queue.pending)
            .map(|request| request.bytes)
            .fold(0usize, usize::saturating_add);
        let oldest_wait = self
            .destinations
            .values()
            .flat_map(|queue| &queue.pending)
            .map(|request| now.saturating_duration_since(request.enqueued_at))
            .max();
        let max_starvation_rounds = self
            .destinations
            .keys()
            .map(|destination| {
                self.service_clock
                    .saturating_sub(self.last_service.get(destination).copied().unwrap_or(0))
                    .min(usize::MAX as u64) as usize
            })
            .max()
            .unwrap_or(0);
        metrics::set_reactive_scheduler_state(
            queued_items,
            queued_encoded_bytes,
            self.active_destinations(),
            oldest_wait,
            max_starvation_rounds,
        );
    }
}

impl ReactiveCreditScheduler {
    fn spawn(repair_credit: Arc<RepairCreditBucket>, shutdown: CancellationToken) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<ReactiveScheduleRequest>();
        tokio::spawn(async move {
            let mut state = ReactiveScheduleState::new();
            loop {
                if state.is_empty() {
                    let request = tokio::select! {
                        _ = shutdown.cancelled() => break,
                        request = rx.recv() => request,
                    };
                    let Some(request) = request else {
                        break;
                    };
                    state.enqueue(request);
                }
                tokio::task::yield_now().await;
                for _ in 0..REACTIVE_SCHEDULER_RECEIVE_BATCH {
                    let Ok(request) = rx.try_recv() else {
                        break;
                    };
                    state.enqueue(request);
                }
                let mut credit_blocked = HashSet::new();
                loop {
                    let retry_cap =
                        repair_credit.reactive_retry_cap_bytes(state.active_destinations());
                    let Some(request) = state.pop_next(retry_cap, Instant::now(), &credit_blocked)
                    else {
                        break;
                    };
                    let destination = request.destination;
                    let bytes = request.bytes;
                    let retry = request.retry;
                    if request.response.is_closed() {
                        metrics::record_reactive_scheduler_event(
                            metrics::ReactiveSchedulerEvent::Cancelled,
                        );
                        state.discard_selected(destination);
                        continue;
                    }
                    let mut permit = repair_credit.try_reserve_waiting_reactive(bytes);
                    if let Some(permit) = permit.as_mut() {
                        permit.destination = Some(destination);
                    }
                    match permit {
                        Some(permit) => match request.response.send(Some(permit)) {
                            Ok(()) => {
                                state.record_grant(destination, bytes, retry);
                                metrics::record_reactive_scheduler_event(
                                    metrics::ReactiveSchedulerEvent::Granted,
                                );
                            }
                            Err(permit) => {
                                drop(permit);
                                metrics::record_reactive_scheduler_event(
                                    metrics::ReactiveSchedulerEvent::Cancelled,
                                );
                                state.discard_selected(destination);
                            }
                        },
                        None => {
                            metrics::record_reactive_scheduler_event(
                                metrics::ReactiveSchedulerEvent::CreditWait,
                            );
                            credit_blocked.insert(request.id);
                            state.requeue(request);
                        }
                    }
                }
                if state.is_empty() {
                    state.publish_metrics(Instant::now());
                    continue;
                }
                state.publish_metrics(Instant::now());
                let retry_deadline = state.retry_epoch_deadline();
                let work_deadline = state.next_deadline().unwrap_or(retry_deadline);
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    request = rx.recv() => match request {
                        Some(request) => state.enqueue(request),
                        None => break,
                    },
                    _ = repair_credit.credit_available.notified() => {}
                    _ = tokio::time::sleep_until(retry_deadline.into()) => {
                        state.reset_retry_epoch_if_due(Instant::now());
                    }
                    _ = tokio::time::sleep_until(work_deadline.into()) => {
                        state.remove_expired(Instant::now());
                    }
                }
            }
            for queue in state.destinations.into_values() {
                for request in queue.pending {
                    metrics::record_reactive_scheduler_event(
                        metrics::ReactiveSchedulerEvent::Shutdown,
                    );
                    let _ = request.response.send(None);
                }
            }
            metrics::set_reactive_scheduler_state(0, 0, 0, None, 0);
        });
        Self {
            tx,
            next_request_id: Arc::new(AtomicU64::new(0)),
        }
    }

    async fn reserve(
        &self,
        destination: u32,
        bytes: usize,
        deadline: Instant,
        retry: bool,
    ) -> Option<ProactiveCreditPermit> {
        if deadline <= Instant::now() {
            return None;
        }
        let (response, rx) = oneshot::channel();
        let id = self
            .next_request_id
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        self.tx
            .send(ReactiveScheduleRequest {
                id,
                destination,
                bytes,
                deadline,
                enqueued_at: Instant::now(),
                retry,
                response,
            })
            .ok()?;
        match tokio::time::timeout_at(deadline.into(), rx).await {
            Ok(Ok(permit)) => permit,
            _ => None,
        }
    }
}

#[derive(Debug, Default)]
struct RepairCreditState {
    proactive_quarters: usize,
    reactive_quarters: usize,
    borrowed_reactive_quarters: usize,
    borrowed_proactive_quarters: usize,
    next_borrow_id: u64,
    tentative_borrows: HashMap<u64, TentativeBorrow>,
    reactive_mint_remainder: usize,
    reactive_reservations: usize,
    reactive_demand_until: Option<Instant>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BorrowDirection {
    ToReactive,
    ToProactive,
}

#[derive(Debug, Clone, Copy)]
struct TentativeBorrow {
    direction: BorrowDirection,
    original_quarters: usize,
    remaining_quarters: usize,
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
    speakers: Option<Mutex<LinkSpeakerState>>,
    state: Mutex<RepairCreditState>,
    credit_available: Notify,
}

#[derive(Debug, Default)]
struct LinkSpeakerState {
    speakers: HashMap<(u32, u64), Instant>,
    ema: f64,
    last_sample: Option<Instant>,
}

impl RepairCreditBucket {
    fn legacy(
        max_users: Arc<AtomicU64>,
        reactive_reserve_pct: u8,
        reactive_hard_reserve_pct: u8,
    ) -> Self {
        Self {
            max_users,
            reactive_reserve_pct,
            reactive_hard_reserve_pct,
            speakers: None,
            state: Mutex::new(RepairCreditState::default()),
            credit_available: Notify::new(),
        }
    }

    fn link(
        max_users: Arc<AtomicU64>,
        reactive_reserve_pct: u8,
        reactive_hard_reserve_pct: u8,
    ) -> Self {
        Self {
            max_users,
            reactive_reserve_pct,
            reactive_hard_reserve_pct,
            speakers: Some(Mutex::new(LinkSpeakerState::default())),
            state: Mutex::new(RepairCreditState::default()),
            credit_available: Notify::new(),
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
        let before_available = state
            .proactive_quarters
            .saturating_add(state.reactive_quarters);
        let occupied = before_available.saturating_add(state.tentative_quarters);
        let admitted = accepted_primary_bytes.min(cap.saturating_sub(occupied));
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
            before_available.saturating_add(admitted),
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
        repay_borrow(&mut state, BorrowDirection::ToReactive, repay_reactive);
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
        repay_borrow(&mut state, BorrowDirection::ToProactive, repay_proactive);
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
        drop(state);
        if admitted > 0 {
            self.credit_available.notify_one();
        }
        admitted
    }

    #[cfg(test)]
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

    fn try_reserve_waiting_reactive(
        self: &Arc<Self>,
        bytes: usize,
    ) -> Option<ProactiveCreditPermit> {
        let reserved_quarters = bytes.checked_mul(CREDIT_QUARTERS_PER_BYTE)?;
        let cap = self.capacity_quarters();
        let mut state = self.state.lock();
        self.trim_to_capacity(&mut state, cap);
        self.reserve_locked(
            &mut state,
            reserved_quarters,
            RepairCreditClass::Reactive,
            RepairCreditSource::Reactive,
        )
    }

    fn reactive_retry_cap_bytes(&self, active_destinations: usize) -> usize {
        let reactive_capacity = percentage(self.capacity_quarters(), self.reactive_reserve_pct)
            / CREDIT_QUARTERS_PER_BYTE;
        percentage(
            reactive_capacity / active_destinations.max(1),
            REACTIVE_RETRY_SHARE_PCT as u8,
        )
        .max(REACTIVE_SCHEDULER_QUANTUM_BYTES)
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
            grants[index] = self.reserve_locked(
                &mut state,
                units,
                RepairCreditClass::Proactive,
                RepairCreditSource::Shared,
            );
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
        let borrow_id = match class {
            RepairCreditClass::Proactive if reactive_quarters > 0 => Some(
                register_tentative_borrow(state, BorrowDirection::ToReactive, reactive_quarters),
            ),
            RepairCreditClass::Reactive if proactive_quarters > 0 => Some(
                register_tentative_borrow(state, BorrowDirection::ToProactive, proactive_quarters),
            ),
            RepairCreditClass::Proactive | RepairCreditClass::Reactive => None,
        };
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
            borrow_id,
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
            metric_class(permit.class),
            RepairClassStage::Sent,
            permit.reserved_quarters / CREDIT_QUARTERS_PER_BYTE,
        );
        if permit.class == RepairCreditClass::Reactive {
            state.reactive_reservations = state.reactive_reservations.saturating_sub(1);
        }
        if let Some(borrow_id) = permit.borrow_id {
            state.tentative_borrows.remove(&borrow_id);
        }
        if permit.source == RepairCreditSource::DestinationPrivate
            && let Some(destination) = permit.destination
        {
            state.last_private_grant.insert(destination, service_round);
        }
        if permit.class == RepairCreditClass::Proactive
            && let Some(destination) = permit.destination
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
        if permit.class == RepairCreditClass::Reactive {
            state.reactive_reservations = state.reactive_reservations.saturating_sub(1);
        }
        let mut proactive_refund = permit.proactive_quarters;
        let mut reactive_refund = permit.reactive_quarters;
        if let Some(borrow_id) = permit.borrow_id
            && let Some(borrow) = state.tentative_borrows.remove(&borrow_id)
        {
            let repaid = borrow
                .original_quarters
                .saturating_sub(borrow.remaining_quarters);
            match borrow.direction {
                BorrowDirection::ToReactive => {
                    state.borrowed_reactive_quarters = state
                        .borrowed_reactive_quarters
                        .saturating_sub(borrow.remaining_quarters);
                    proactive_refund = proactive_refund.saturating_add(repaid);
                    reactive_refund = borrow.remaining_quarters;
                }
                BorrowDirection::ToProactive => {
                    state.borrowed_proactive_quarters = state
                        .borrowed_proactive_quarters
                        .saturating_sub(borrow.remaining_quarters);
                    reactive_refund = reactive_refund.saturating_add(repaid);
                    proactive_refund = borrow.remaining_quarters;
                }
            }
        }
        let occupied = state
            .proactive_quarters
            .saturating_add(state.reactive_quarters)
            .saturating_add(state.tentative_quarters);
        let room = cap.saturating_sub(occupied);
        let reactive = reactive_refund.min(room);
        state.reactive_quarters = state.reactive_quarters.saturating_add(reactive);
        let room = room - reactive;
        let proactive = proactive_refund.min(room);
        state.proactive_quarters = state.proactive_quarters.saturating_add(proactive);
        let refunded = reactive.saturating_add(proactive);
        state.cap_discarded_quarters = state
            .cap_discarded_quarters
            .saturating_add(permit.reserved_quarters.saturating_sub(refunded));
        metrics::record_repair_credit_quarters(
            RepairCreditStage::CapDiscarded,
            permit.reserved_quarters.saturating_sub(refunded),
        );
        assert_credit_conserved(&state);
        drop(state);
        if refunded > 0 {
            self.credit_available.notify_one();
        }
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
        let base = if self.speakers.is_some() {
            link_credit_base_capacity(self.max_users.load(Ordering::Relaxed))
                .saturating_add(self.link_speaker_headroom_bytes())
        } else {
            proactive_credit_burst(self.max_users.load(Ordering::Relaxed))
        };
        base.saturating_mul(CREDIT_QUARTERS_PER_BYTE)
    }

    fn trim_to_capacity(&self, state: &mut RepairCreditState, cap: usize) {
        let available = state
            .proactive_quarters
            .saturating_add(state.reactive_quarters);
        // Tentative permits are already promised to queued work and cannot be
        // evicted when the live burst cap shrinks. They still occupy capacity,
        // so trim all available credit before allowing mint above that cap.
        let allowed_available = cap.saturating_sub(state.tentative_quarters);
        let mut excess = available.saturating_sub(allowed_available);
        state.cap_discarded_quarters = state.cap_discarded_quarters.saturating_add(excess);
        metrics::record_repair_credit_quarters(RepairCreditStage::CapDiscarded, excess);
        let trim = excess.min(state.proactive_quarters);
        state.proactive_quarters -= trim;
        excess -= trim;
        state.reactive_quarters = state.reactive_quarters.saturating_sub(excess);
        assert_credit_conserved(state);
    }
}

fn register_tentative_borrow(
    state: &mut RepairCreditState,
    direction: BorrowDirection,
    quarters: usize,
) -> u64 {
    let mut borrow_id = state.next_borrow_id.wrapping_add(1).max(1);
    while state.tentative_borrows.contains_key(&borrow_id) {
        borrow_id = borrow_id.wrapping_add(1).max(1);
    }
    state.next_borrow_id = borrow_id;
    state.tentative_borrows.insert(
        borrow_id,
        TentativeBorrow {
            direction,
            original_quarters: quarters,
            remaining_quarters: quarters,
        },
    );
    match direction {
        BorrowDirection::ToReactive => {
            state.borrowed_reactive_quarters =
                state.borrowed_reactive_quarters.saturating_add(quarters);
        }
        BorrowDirection::ToProactive => {
            state.borrowed_proactive_quarters =
                state.borrowed_proactive_quarters.saturating_add(quarters);
        }
    }
    borrow_id
}

fn repay_borrow(state: &mut RepairCreditState, direction: BorrowDirection, quarters: usize) {
    let aggregate = match direction {
        BorrowDirection::ToReactive => state.borrowed_reactive_quarters,
        BorrowDirection::ToProactive => state.borrowed_proactive_quarters,
    };
    let repaid = quarters.min(aggregate);
    if repaid == 0 {
        return;
    }
    let tentative_total = state
        .tentative_borrows
        .values()
        .filter(|borrow| borrow.direction == direction)
        .map(|borrow| borrow.remaining_quarters)
        .fold(0usize, usize::saturating_add);
    let committed = aggregate.saturating_sub(tentative_total);
    let mut tentative_repayment = repaid.saturating_sub(committed);
    if tentative_repayment > 0 {
        let mut borrow_ids = state
            .tentative_borrows
            .iter()
            .filter_map(|(borrow_id, borrow)| {
                (borrow.direction == direction && borrow.remaining_quarters > 0)
                    .then_some(*borrow_id)
            })
            .collect::<Vec<_>>();
        borrow_ids.sort_unstable();
        for borrow_id in borrow_ids {
            let Some(borrow) = state.tentative_borrows.get_mut(&borrow_id) else {
                continue;
            };
            let applied = tentative_repayment.min(borrow.remaining_quarters);
            borrow.remaining_quarters -= applied;
            tentative_repayment -= applied;
            if tentative_repayment == 0 {
                break;
            }
        }
    }
    match direction {
        BorrowDirection::ToReactive => state.borrowed_reactive_quarters -= repaid,
        BorrowDirection::ToProactive => state.borrowed_proactive_quarters -= repaid,
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
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use tokio::sync::oneshot;
    use tokio_util::sync::CancellationToken;

    use super::{
        AdaptiveVoiceBudget, MIN_ADMISSION_BYTES, ProactiveCreditRequest, REACTIVE_RETRY_EPOCH,
        ReactiveScheduleRequest, ReactiveScheduleState, compare_overflow_requests,
        link_credit_base_capacity, link_speaker_headroom, percentage,
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
        let budget =
            AdaptiveVoiceBudget::with_repair_reservations(Arc::new(AtomicU64::new(100)), 0, 0);
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

    fn reactive_request(
        destination: u32,
        bytes: usize,
        deadline: Instant,
        retry: bool,
    ) -> (
        ReactiveScheduleRequest,
        oneshot::Receiver<Option<super::ProactiveCreditPermit>>,
    ) {
        let (response, receiver) = oneshot::channel();
        static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(0);
        (
            ReactiveScheduleRequest {
                id: NEXT_REQUEST_ID
                    .fetch_add(1, Ordering::Relaxed)
                    .wrapping_add(1),
                destination,
                bytes,
                deadline,
                enqueued_at: Instant::now(),
                retry,
                response,
            },
            receiver,
        )
    }

    #[test]
    fn reactive_scheduler_uses_edf_within_a_destination() {
        let now = Instant::now();
        let mut state = ReactiveScheduleState::new();
        let (later, _later_rx) = reactive_request(3, 100, now + Duration::from_secs(2), false);
        let (earlier, _earlier_rx) = reactive_request(3, 100, now + Duration::from_secs(1), false);
        state.enqueue(later);
        state.enqueue(earlier);

        let selected = state
            .pop_next(1_200, now, &HashSet::new())
            .expect("earliest request");
        assert_eq!(selected.deadline, now + Duration::from_secs(1));
    }

    #[test]
    fn reactive_scheduler_drr_is_input_order_independent_and_eventually_fair() {
        fn sequence(order: &[u32]) -> Vec<u32> {
            let now = Instant::now();
            let mut state = ReactiveScheduleState::new();
            let mut receivers = Vec::new();
            for &destination in order {
                let (request, receiver) =
                    reactive_request(destination, 600, now + Duration::from_secs(10), false);
                state.enqueue(request);
                receivers.push(receiver);
            }
            let mut granted = Vec::new();
            while !state.is_empty() {
                let request = state
                    .pop_next(1_200, now, &HashSet::new())
                    .expect("schedulable request");
                granted.push(request.destination);
                state.record_grant(request.destination, request.bytes, request.retry);
            }
            drop(receivers);
            granted
        }

        let forward = sequence(&[3, 3, 4, 15]);
        let reversed = sequence(&[15, 4, 3, 3]);
        assert_eq!(forward, reversed);
        assert_eq!(forward, vec![3, 4, 15, 3]);
    }

    #[test]
    fn reactive_scheduler_accumulates_deficit_for_large_frames() {
        let now = Instant::now();
        let mut state = ReactiveScheduleState::new();
        let (request, _receiver) = reactive_request(3, 3_001, now + Duration::from_secs(1), false);
        state.enqueue(request);
        let selected = state
            .pop_next(1_200, now, &HashSet::new())
            .expect("large request must accumulate enough deficit");
        assert_eq!(selected.bytes, 3_001);
    }

    #[test]
    fn retry_cap_defers_retry_without_blocking_fresh_work() {
        let now = Instant::now();
        let mut state = ReactiveScheduleState::new();
        let (first_retry, _first_rx) =
            reactive_request(3, 1_000, now + Duration::from_secs(1), true);
        let (second_retry, _second_rx) =
            reactive_request(3, 1_000, now + Duration::from_secs(2), true);
        let (fresh, _fresh_rx) = reactive_request(3, 100, now + Duration::from_secs(3), false);
        state.enqueue(first_retry);
        state.enqueue(second_retry);
        state.enqueue(fresh);

        let first = state.pop_next(1_200, now, &HashSet::new()).unwrap();
        assert!(first.retry);
        state.record_grant(first.destination, first.bytes, first.retry);
        let uncapped = state.pop_next(1_200, now, &HashSet::new()).unwrap();
        assert!(!uncapped.retry, "fresh work must bypass a capped retry");
        state.record_grant(uncapped.destination, uncapped.bytes, uncapped.retry);
        assert!(state.pop_next(1_200, now, &HashSet::new()).is_none());

        let next_epoch = state.retry_epoch_started + REACTIVE_RETRY_EPOCH;
        let deferred = state
            .pop_next(1_200, next_epoch, &HashSet::new())
            .expect("retry becomes eligible in the next epoch");
        assert!(deferred.retry);
    }

    #[tokio::test]
    async fn reactive_scheduler_waits_for_mint_and_charges_exact_bytes() {
        let (_, budget) = budget(100);
        let waiter = tokio::spawn({
            let budget = budget.clone();
            async move {
                budget
                    .reserve_reactive_credit_scheduled(
                        3,
                        100,
                        Instant::now() + Duration::from_secs(1),
                        false,
                    )
                    .await
            }
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        budget.mint_proactive_credit(400);
        let permit = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap()
            .expect("mint should wake pending reactive work");
        assert_eq!(permit.reserved_quarters(), 400);
        permit.commit();
        let snapshot = budget.repair_credit_snapshot();
        assert_eq!(snapshot.committed_quarters, 400);
        snapshot.assert_conserved();
    }

    #[tokio::test]
    async fn reactive_scheduler_shutdown_releases_waiters_without_credit() {
        let (_, budget) = budget(100);
        let shutdown = CancellationToken::new();
        budget.link_reactive_scheduler_shutdown(shutdown.clone());
        let waiter = tokio::spawn({
            let budget = budget.clone();
            async move {
                budget
                    .reserve_reactive_credit_scheduled(
                        3,
                        100,
                        Instant::now() + Duration::from_secs(30),
                        false,
                    )
                    .await
            }
        });
        tokio::task::yield_now().await;
        shutdown.cancel();
        let permit = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("shutdown must release reactive waiter")
            .unwrap();
        assert!(permit.is_none());
        let snapshot = budget.repair_credit_snapshot();
        assert_eq!(snapshot.tentative_quarters, 0);
        snapshot.assert_conserved();
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
    fn tentative_credit_occupies_burst_capacity_during_mint_and_refund() {
        let allocator =
            AdaptiveVoiceBudget::with_repair_reservations(Arc::new(AtomicU64::new(100)), 0, 0);
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
    fn tentative_borrow_is_repaid_before_commit_without_recreating_debt() {
        let allocator =
            AdaptiveVoiceBudget::with_repair_reservations(Arc::new(AtomicU64::new(100)), 30, 0);
        allocator.mint_proactive_credit(400);
        let permit = allocator.try_reserve_proactive_credit(80).unwrap();
        assert_eq!(
            allocator.repair_credit_snapshot().debt_to_reactive_quarters,
            40
        );
        allocator.mint_proactive_credit(40);
        assert_eq!(
            allocator.repair_credit_snapshot().debt_to_reactive_quarters,
            12
        );
        permit.commit();
        let committed = allocator.repair_credit_snapshot();
        assert_eq!(committed.debt_to_reactive_quarters, 12);
        committed.assert_conserved();
    }

    #[test]
    fn refund_after_tentative_debt_repayment_restores_control_class_balances() {
        fn allocator() -> AdaptiveVoiceBudget {
            AdaptiveVoiceBudget::with_repair_reservations(Arc::new(AtomicU64::new(100)), 30, 0)
        }

        let control = allocator();
        control.mint_proactive_credit(400);
        control.mint_proactive_credit(40);
        let expected = control.repair_credit_snapshot();

        let proactive = allocator();
        proactive.mint_proactive_credit(400);
        let permit = proactive.try_reserve_proactive_credit(80).unwrap();
        proactive.mint_proactive_credit(40);
        drop(permit);
        let refunded = proactive.repair_credit_snapshot();
        assert_eq!(refunded.proactive_quarters, expected.proactive_quarters);
        assert_eq!(refunded.reactive_quarters, expected.reactive_quarters);
        assert_eq!(refunded.debt_to_reactive_quarters, 0);
        refunded.assert_conserved();

        let reactive = allocator();
        reactive.mint_proactive_credit(400);
        let permit = reactive.try_reserve_reactive_credit(40).unwrap();
        reactive.mint_proactive_credit(40);
        drop(permit);
        let refunded = reactive.repair_credit_snapshot();
        assert_eq!(refunded.proactive_quarters, expected.proactive_quarters);
        assert_eq!(refunded.reactive_quarters, expected.reactive_quarters);
        assert_eq!(refunded.debt_to_proactive_quarters, 0);
        refunded.assert_conserved();
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

    #[tokio::test]
    async fn unaffordable_reactive_request_does_not_block_smaller_same_destination_work() {
        let (_, budget) = budget(100);
        budget.mint_proactive_credit(80);
        let deadline = Instant::now() + Duration::from_secs(2);
        let large = tokio::spawn({
            let budget = budget.clone();
            async move {
                budget
                    .reserve_reactive_credit_scheduled(3, 30, deadline, false)
                    .await
            }
        });
        tokio::task::yield_now().await;
        let small = tokio::spawn({
            let budget = budget.clone();
            async move {
                budget
                    .reserve_reactive_credit_scheduled(3, 20, deadline, false)
                    .await
            }
        });
        let permit = tokio::time::timeout(Duration::from_millis(250), small)
            .await
            .expect("smaller request must bypass unaffordable work")
            .unwrap()
            .expect("smaller request should receive available credit");
        assert_eq!(permit.reserved_quarters(), 80);
        permit.commit();
        large.abort();
    }

    #[test]
    fn capped_private_phase_leaves_work_conserving_utility_ranked_overflow() {
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
    fn overflow_aging_eventually_serves_a_continuously_waiting_destination() {
        let budget =
            AdaptiveVoiceBudget::with_repair_reservations(Arc::new(AtomicU64::new(100)), 0, 0);
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
        let make_budget =
            || AdaptiveVoiceBudget::with_repair_reservations(Arc::new(AtomicU64::new(100)), 0, 0);
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
        let budget =
            AdaptiveVoiceBudget::with_repair_reservations(Arc::new(AtomicU64::new(100)), 0, 0);
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
