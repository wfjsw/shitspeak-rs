//! Bounded, priority-aware queues for application gateway work.
//!
//! The queue budget is shared across lanes, while each lane also has its own
//! cap. Commands retain their byte permit until their handler completes so
//! downstream work is included in the backpressure calculation.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::{Notify, mpsc};
use tracing::{trace, warn};

/// Estimates the amount of queue capacity occupied by a command.
pub trait EstimatedCommand {
    /// A stable label used in queue-drop diagnostics.
    fn label(&self) -> &'static str;

    /// The estimated number of bytes retained while this command is queued.
    fn estimated_bytes(&self) -> usize;
}

/// A byte budget shared by one or more gateway lanes.
#[derive(Clone)]
pub struct QueueBudget {
    inner: Arc<QueueBudgetInner>,
    minimum_lane_bytes: usize,
}

struct QueueBudgetInner {
    max_bytes: usize,
    used_bytes: AtomicUsize,
    notify: Notify,
}

impl QueueBudget {
    /// Creates a shared budget with a caller-supplied lane-size floor.
    pub fn new(max_bytes: usize, minimum_lane_bytes: usize) -> Self {
        let minimum_lane_bytes = minimum_lane_bytes.max(1);
        Self {
            inner: Arc::new(QueueBudgetInner {
                max_bytes: max_bytes.max(minimum_lane_bytes),
                used_bytes: AtomicUsize::new(0),
                notify: Notify::new(),
            }),
            minimum_lane_bytes,
        }
    }

    /// The effective global byte budget.
    pub fn max_bytes(&self) -> usize {
        self.inner.max_bytes
    }

    /// Creates a lane limited by both this lane's budget and the shared budget.
    pub fn split(&self, max_bytes: usize) -> QueueLaneBudget {
        QueueLaneBudget {
            global: self.clone(),
            max_bytes: max_bytes.max(self.minimum_lane_bytes),
            used_bytes: Arc::new(AtomicUsize::new(0)),
        }
    }
}

/// A bounded lane within a [`QueueBudget`].
#[derive(Clone)]
pub struct QueueLaneBudget {
    global: QueueBudget,
    max_bytes: usize,
    used_bytes: Arc<AtomicUsize>,
}

impl QueueLaneBudget {
    async fn reserve(&self, bytes: usize) -> Option<QueuePermit> {
        let bytes = bytes.max(1);
        if bytes > self.max_bytes || bytes > self.global.inner.max_bytes {
            return None;
        }
        loop {
            if let Some(permit) = self.try_reserve(bytes) {
                return Some(permit);
            }
            self.global.inner.notify.notified().await;
        }
    }

    fn try_reserve(&self, bytes: usize) -> Option<QueuePermit> {
        let bytes = bytes.max(1);
        if bytes > self.max_bytes || bytes > self.global.inner.max_bytes {
            return None;
        }
        try_add_with_limit(&self.used_bytes, bytes, self.max_bytes)?;
        if try_add_with_limit(
            &self.global.inner.used_bytes,
            bytes,
            self.global.inner.max_bytes,
        )
        .is_none()
        {
            self.used_bytes.fetch_sub(bytes, Ordering::Release);
            return None;
        }
        Some(QueuePermit {
            lane: self.clone(),
            bytes,
        })
    }
}

struct QueuePermit {
    lane: QueueLaneBudget,
    bytes: usize,
}

impl Drop for QueuePermit {
    fn drop(&mut self) {
        self.lane
            .used_bytes
            .fetch_sub(self.bytes, Ordering::Release);
        self.lane
            .global
            .inner
            .used_bytes
            .fetch_sub(self.bytes, Ordering::Release);
        self.lane.global.inner.notify.notify_waiters();
    }
}

struct Queued<T> {
    command: T,
    _permit: QueuePermit,
}

fn try_add_with_limit(counter: &AtomicUsize, add: usize, limit: usize) -> Option<()> {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        let next = current.checked_add(add)?;
        if next > limit {
            return None;
        }
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Some(()),
            Err(actual) => current = actual,
        }
    }
}

/// Sends commands through a bounded adaptive gateway queue.
pub struct AdaptiveSender<T> {
    tx: mpsc::UnboundedSender<Queued<T>>,
    budget: QueueLaneBudget,
}

/// Receives commands sent through an [`AdaptiveSender`].
pub struct AdaptiveReceiver<T> {
    rx: mpsc::UnboundedReceiver<Queued<T>>,
}

impl<T> Clone for AdaptiveSender<T> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            budget: self.budget.clone(),
        }
    }
}

impl<T> AdaptiveSender<T>
where
    T: EstimatedCommand,
{
    /// Creates a sender/receiver pair backed by `budget`.
    pub fn new(budget: QueueLaneBudget) -> (Self, AdaptiveReceiver<T>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { tx, budget }, AdaptiveReceiver { rx })
    }

    /// Waits for capacity before sending, except for commands that can never fit.
    pub async fn send(&self, command: T) -> bool {
        let label = command.label();
        let Some(permit) = self.budget.reserve(command.estimated_bytes()).await else {
            warn!(
                label,
                "s2s gateway command exceeds adaptive queue budget; dropping command"
            );
            return false;
        };
        match self.tx.send(Queued {
            command,
            _permit: permit,
        }) {
            Ok(()) => true,
            Err(_) => {
                trace!(label, "s2s gateway closed; dropping command");
                false
            }
        }
    }

    /// Sends only if capacity is currently available.
    pub fn try_send(&self, command: T) -> bool {
        let label = command.label();
        let Some(permit) = self.budget.try_reserve(command.estimated_bytes()) else {
            warn!(label, "s2s gateway full; dropping command");
            return false;
        };
        match self.tx.send(Queued {
            command,
            _permit: permit,
        }) {
            Ok(()) => true,
            Err(_) => {
                trace!(label, "s2s gateway closed; dropping command");
                false
            }
        }
    }
}

impl<T> AdaptiveReceiver<T> {
    /// Receives the next command and releases its queue capacity immediately.
    pub async fn recv(&mut self) -> Option<T> {
        self.rx.recv().await.map(|queued| queued.command)
    }

    async fn recv_queued(&mut self) -> Option<Queued<T>> {
        self.rx.recv().await
    }
}

/// Runs commands on independent, FIFO-preserving shards selected by `shard_key`.
pub async fn run_sender_sharded_gateway<T, K, H, F>(
    mut rx: AdaptiveReceiver<T>,
    shard_count: usize,
    shard_key: K,
    handler: H,
) where
    T: Send + 'static,
    K: Fn(&T) -> u32,
    H: Fn(T) -> F + Send + Sync + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let shard_count = shard_count.max(1);
    let handler = Arc::new(handler);
    let mut shard_txs = Vec::with_capacity(shard_count);
    let mut workers = Vec::with_capacity(shard_count);

    for _ in 0..shard_count {
        let (tx, mut shard_rx) = mpsc::unbounded_channel::<Queued<T>>();
        shard_txs.push(tx);
        let handler = Arc::clone(&handler);
        workers.push(tokio::spawn(async move {
            while let Some(queued) = shard_rx.recv().await {
                let Queued { command, _permit } = queued;
                handler(command).await;
                drop(_permit);
            }
        }));
    }

    while let Some(queued) = rx.recv_queued().await {
        let shard = shard_key(&queued.command) as usize % shard_count;
        if shard_txs[shard].send(queued).is_err() {
            warn!(shard, "s2s voice gateway shard stopped; dropping command");
        }
    }

    drop(shard_txs);
    for worker in workers {
        if let Err(error) = worker.await {
            warn!(%error, "s2s voice gateway shard failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;
    use tokio::sync::{Barrier, Mutex, Semaphore, mpsc};

    const TEST_MINIMUM_LANE_BYTES: usize = 512 * 1024;

    #[derive(Debug, PartialEq, Eq)]
    struct TestGatewayCommand {
        label: &'static str,
        bytes: usize,
    }

    impl EstimatedCommand for TestGatewayCommand {
        fn label(&self) -> &'static str {
            self.label
        }

        fn estimated_bytes(&self) -> usize {
            self.bytes
        }
    }

    #[derive(Debug)]
    struct ShardedTestCommand {
        sender_session: u32,
        sequence: usize,
        bytes: usize,
    }

    impl EstimatedCommand for ShardedTestCommand {
        fn label(&self) -> &'static str {
            "test_voice"
        }

        fn estimated_bytes(&self) -> usize {
            self.bytes
        }
    }

    #[test]
    fn queue_budget_releases_permits_when_command_is_dropped() {
        let budget = QueueBudget::new(TEST_MINIMUM_LANE_BYTES, TEST_MINIMUM_LANE_BYTES);
        let lane = budget.split(TEST_MINIMUM_LANE_BYTES);
        let permit = lane
            .try_reserve(TEST_MINIMUM_LANE_BYTES * 3 / 4)
            .expect("reserve fits");

        assert!(lane.try_reserve(TEST_MINIMUM_LANE_BYTES / 2).is_none());
        drop(permit);
        assert!(lane.try_reserve(TEST_MINIMUM_LANE_BYTES / 2).is_some());
    }

    #[tokio::test]
    async fn adaptive_sender_drops_voice_style_command_when_budget_is_full() {
        let budget = QueueBudget::new(TEST_MINIMUM_LANE_BYTES, TEST_MINIMUM_LANE_BYTES);
        let (tx, mut rx) = AdaptiveSender::new(budget.split(TEST_MINIMUM_LANE_BYTES));

        assert!(tx.try_send(TestGatewayCommand {
            label: "voice",
            bytes: TEST_MINIMUM_LANE_BYTES * 3 / 4,
        }));
        assert!(!tx.try_send(TestGatewayCommand {
            label: "voice",
            bytes: TEST_MINIMUM_LANE_BYTES / 2,
        }));

        assert_eq!(
            rx.recv().await,
            Some(TestGatewayCommand {
                label: "voice",
                bytes: TEST_MINIMUM_LANE_BYTES * 3 / 4,
            })
        );
        assert!(tx.try_send(TestGatewayCommand {
            label: "voice",
            bytes: TEST_MINIMUM_LANE_BYTES / 2,
        }));
    }

    #[tokio::test]
    async fn adaptive_sender_rejects_oversized_lossless_command_without_waiting() {
        let budget = QueueBudget::new(TEST_MINIMUM_LANE_BYTES, TEST_MINIMUM_LANE_BYTES);
        let (tx, _rx) = AdaptiveSender::new(budget.split(TEST_MINIMUM_LANE_BYTES));

        assert!(
            !tx.send(TestGatewayCommand {
                label: "control",
                bytes: TEST_MINIMUM_LANE_BYTES + 1,
            })
            .await
        );
    }

    #[tokio::test]
    async fn sender_sharded_gateway_preserves_same_sender_fifo() {
        let budget = QueueBudget::new(TEST_MINIMUM_LANE_BYTES, TEST_MINIMUM_LANE_BYTES);
        let (tx, rx) = AdaptiveSender::new(budget.split(TEST_MINIMUM_LANE_BYTES));
        let observed = Arc::new(Mutex::new(Vec::new()));
        let handler_observed = Arc::clone(&observed);
        let runner = tokio::spawn(run_sender_sharded_gateway(
            rx,
            2,
            |command: &ShardedTestCommand| command.sender_session,
            move |command| {
                let observed = Arc::clone(&handler_observed);
                async move {
                    observed.lock().await.push(command.sequence);
                }
            },
        ));

        for sequence in 0..4 {
            assert!(tx.try_send(ShardedTestCommand {
                sender_session: 7,
                sequence,
                bytes: 1,
            }));
        }
        drop(tx);
        runner.await.expect("shard runner completes");

        assert_eq!(*observed.lock().await, vec![0, 1, 2, 3]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sender_sharded_gateway_overlaps_different_senders() {
        let budget = QueueBudget::new(TEST_MINIMUM_LANE_BYTES, TEST_MINIMUM_LANE_BYTES);
        let (tx, rx) = AdaptiveSender::new(budget.split(TEST_MINIMUM_LANE_BYTES));
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let rendezvous = Arc::new(Barrier::new(2));
        let runner = tokio::spawn(run_sender_sharded_gateway(
            rx,
            2,
            |command: &ShardedTestCommand| command.sender_session,
            {
                let active = Arc::clone(&active);
                let max_active = Arc::clone(&max_active);
                let rendezvous = Arc::clone(&rendezvous);
                move |_command| {
                    let active = Arc::clone(&active);
                    let max_active = Arc::clone(&max_active);
                    let rendezvous = Arc::clone(&rendezvous);
                    async move {
                        let now_active = active.fetch_add(1, Ordering::AcqRel) + 1;
                        max_active.fetch_max(now_active, Ordering::AcqRel);
                        rendezvous.wait().await;
                        active.fetch_sub(1, Ordering::AcqRel);
                    }
                }
            },
        ));

        for sender_session in [0, 1] {
            assert!(tx.try_send(ShardedTestCommand {
                sender_session,
                sequence: 0,
                bytes: 1,
            }));
        }
        drop(tx);
        tokio::time::timeout(Duration::from_secs(1), runner)
            .await
            .expect("different sender shards should overlap")
            .expect("shard runner completes");

        assert_eq!(max_active.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn sender_sharded_gateway_retains_permit_until_handler_completes() {
        let budget = QueueBudget::new(TEST_MINIMUM_LANE_BYTES, TEST_MINIMUM_LANE_BYTES);
        let lane = budget.split(TEST_MINIMUM_LANE_BYTES);
        let (tx, rx) = AdaptiveSender::new(lane.clone());
        let (started_tx, mut started_rx) = mpsc::unbounded_channel();
        let release = Arc::new(Semaphore::new(0));
        let handler_release = Arc::clone(&release);
        let runner = tokio::spawn(run_sender_sharded_gateway(
            rx,
            2,
            |command: &ShardedTestCommand| command.sender_session,
            move |_command| {
                let started_tx = started_tx.clone();
                let release = Arc::clone(&handler_release);
                async move {
                    started_tx.send(()).expect("test observer remains open");
                    let permit = release.acquire().await.expect("release semaphore open");
                    permit.forget();
                }
            },
        ));

        assert!(tx.try_send(ShardedTestCommand {
            sender_session: 3,
            sequence: 0,
            bytes: TEST_MINIMUM_LANE_BYTES * 3 / 4,
        }));
        started_rx.recv().await.expect("handler starts");
        assert!(
            lane.try_reserve(TEST_MINIMUM_LANE_BYTES / 2).is_none(),
            "the queued byte permit must remain held during command execution"
        );

        release.add_permits(1);
        drop(tx);
        runner.await.expect("shard runner completes");
        assert!(lane.try_reserve(TEST_MINIMUM_LANE_BYTES / 2).is_some());
    }
}
