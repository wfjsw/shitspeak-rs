//! Adaptive, byte-based admission limits for voice work.
//!
//! Capacity is sampled when work is reserved. Lowering `max_users` therefore
//! constrains later admission without evicting work which is already queued.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

const MIN_ADMISSION_BYTES: usize = 128;
const PRIMARY_MIN_BYTES: usize = 256 * 1024;
const PRIMARY_MAX_BYTES: usize = 4 * 1024 * 1024;
const PROACTIVE_MIN_BYTES: usize = 32 * 1024;
const PROACTIVE_MAX_BYTES: usize = 512 * 1024;
const PROACTIVE_BURST_MIN_BYTES: usize = 16 * 1024;
const PROACTIVE_BURST_MAX_BYTES: usize = 128 * 1024;
const CREDIT_QUARTERS_PER_BYTE: usize = 4;

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
    proactive_credit: Arc<ProactiveCreditBucket>,
}

impl AdaptiveVoiceBudget {
    pub(crate) fn new(max_users: Arc<AtomicU64>) -> Self {
        Self {
            primary: Arc::new(ByteBudget::default()),
            proactive: Arc::new(ByteBudget::default()),
            proactive_credit: Arc::new(ProactiveCreditBucket {
                max_users: max_users.clone(),
                balance_quarters: AtomicUsize::new(0),
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
        self.proactive_credit.mint(accepted_primary_bytes)
    }

    /// Reserve proactive-byte credit before attempting to enqueue alternate
    /// repair work. Dropping the returned permit refunds it; call `commit`
    /// only after queue admission succeeds.
    pub(crate) fn try_reserve_proactive_credit(
        &self,
        proactive_bytes: usize,
    ) -> Option<ProactiveCreditPermit> {
        self.proactive_credit.try_reserve(proactive_bytes)
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
        self.proactive_credit.balance_bytes()
    }

    /// Available proactive credit in quarter-byte units. This is mainly for
    /// aggregate telemetry and tests; admission itself uses exact units.
    #[cfg(test)]
    pub(crate) fn proactive_credit_balance_quarters(&self) -> usize {
        self.proactive_credit.balance_quarters()
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
/// A permit refunds itself by default, which keeps queue admission failure
/// cheap and correct. Once the producer has enqueued work it must call
/// [`Self::commit`] so later transport failure cannot recreate credit and
/// trigger a retry storm.
#[derive(Debug)]
pub(crate) struct ProactiveCreditPermit {
    bucket: Arc<ProactiveCreditBucket>,
    reserved_quarters: usize,
    committed: bool,
}

impl ProactiveCreditPermit {
    /// Consume this credit after proactive work was accepted by its queue.
    pub(crate) fn commit(mut self) {
        self.committed = true;
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
        self.bucket.refund(self.reserved_quarters);
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

#[derive(Debug)]
struct ProactiveCreditBucket {
    max_users: Arc<AtomicU64>,
    balance_quarters: AtomicUsize,
}

impl ProactiveCreditBucket {
    /// `accepted_primary_bytes` is itself measured in quarter credits: one
    /// accepted byte produces one quarter of a proactive byte credit.
    fn mint(&self, accepted_primary_bytes: usize) -> usize {
        let cap = self.capacity_quarters();
        let mut current = self.balance_quarters.load(Ordering::Acquire);
        loop {
            let next = current.saturating_add(accepted_primary_bytes).min(cap);
            match self.balance_quarters.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return next.saturating_sub(current),
                Err(actual) => current = actual,
            }
        }
    }

    fn try_reserve(self: &Arc<Self>, proactive_bytes: usize) -> Option<ProactiveCreditPermit> {
        let reserved_quarters = proactive_bytes.checked_mul(CREDIT_QUARTERS_PER_BYTE)?;
        let cap = self.capacity_quarters();
        let mut current = self.balance_quarters.load(Ordering::Acquire);
        loop {
            // Capacity can shrink while credit is idle. Trim on the next
            // operation so no new reservation uses obsolete burst credit.
            if current > cap {
                match self.balance_quarters.compare_exchange_weak(
                    current,
                    cap,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => current = cap,
                    Err(actual) => current = actual,
                }
                continue;
            }
            if current < reserved_quarters {
                return None;
            }
            let next = current - reserved_quarters;
            match self.balance_quarters.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(ProactiveCreditPermit {
                        bucket: self.clone(),
                        reserved_quarters,
                        committed: false,
                    });
                }
                Err(actual) => current = actual,
            }
        }
    }

    fn refund(&self, reserved_quarters: usize) {
        let cap = self.capacity_quarters();
        let mut current = self.balance_quarters.load(Ordering::Acquire);
        loop {
            let next = current.saturating_add(reserved_quarters).min(cap);
            match self.balance_quarters.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }

    fn balance_bytes(&self) -> usize {
        self.balance_quarters() / CREDIT_QUARTERS_PER_BYTE
    }

    fn balance_quarters(&self) -> usize {
        self.balance_quarters.load(Ordering::Acquire)
    }

    fn capacity_quarters(&self) -> usize {
        proactive_credit_burst(self.max_users.load(Ordering::Relaxed))
            .saturating_mul(CREDIT_QUARTERS_PER_BYTE)
    }
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{AdaptiveVoiceBudget, MIN_ADMISSION_BYTES};

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
    fn proactive_credit_refunds_until_queue_admission_is_committed() {
        let (_, budget) = budget(100);
        assert_eq!(budget.mint_proactive_credit(400), 400);
        assert_eq!(budget.proactive_credit_balance_quarters(), 400);
        assert_eq!(budget.proactive_credit_balance_bytes(), 100);

        let permit = budget.try_reserve_proactive_credit(75).unwrap();
        assert_eq!(permit.reserved_quarters(), 300);
        assert_eq!(budget.proactive_credit_balance_bytes(), 25);
        drop(permit);
        assert_eq!(budget.proactive_credit_balance_bytes(), 100);

        let permit = budget.try_reserve_proactive_credit(75).unwrap();
        permit.commit();
        assert_eq!(budget.proactive_credit_balance_bytes(), 25);
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
    }
}
