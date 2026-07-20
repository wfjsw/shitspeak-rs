use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{Notify, broadcast, mpsc};
use tokio::time::timeout;

use super::*;

const TEST_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug)]
enum RegistrationBehavior {
    None,
    Deliver(u64),
    Reject,
}

#[derive(Debug)]
struct TestError;

impl Display for TestError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("test subscriber rejected registration")
    }
}

impl Error for TestError {}

struct TestSubscriber {
    output_tx: mpsc::Sender<u64>,
    registration: RegistrationBehavior,
    lag_action: LagAction,
    lag_tx: Option<mpsc::UnboundedSender<u64>>,
    block_event: Option<u64>,
    handle_started_tx: Option<mpsc::UnboundedSender<()>>,
    handle_release: Option<Arc<Notify>>,
    panic_event: Option<u64>,
    dropped_deliveries: Option<Arc<AtomicUsize>>,
}

impl TestSubscriber {
    fn new(output_tx: mpsc::Sender<u64>) -> Self {
        Self {
            output_tx,
            registration: RegistrationBehavior::None,
            lag_action: LagAction::Remove,
            lag_tx: None,
            block_event: None,
            handle_started_tx: None,
            handle_release: None,
            panic_event: None,
            dropped_deliveries: None,
        }
    }

    fn with_registration(mut self, registration: RegistrationBehavior) -> Self {
        self.registration = registration;
        self
    }

    fn with_lag_action(
        mut self,
        lag_action: LagAction,
        lag_tx: mpsc::UnboundedSender<u64>,
    ) -> Self {
        self.lag_action = lag_action;
        self.lag_tx = Some(lag_tx);
        self
    }

    fn blocking_on(
        mut self,
        event: u64,
        handle_started_tx: mpsc::UnboundedSender<()>,
        handle_release: Arc<Notify>,
    ) -> Self {
        self.block_event = Some(event);
        self.handle_started_tx = Some(handle_started_tx);
        self.handle_release = Some(handle_release);
        self
    }

    fn panicking_on(mut self, event: u64) -> Self {
        self.panic_event = Some(event);
        self
    }

    fn recording_drops(mut self, dropped_deliveries: Arc<AtomicUsize>) -> Self {
        self.dropped_deliveries = Some(dropped_deliveries);
        self
    }
}

#[async_trait]
impl ShardedSubscriber<u64> for TestSubscriber {
    type Output = u64;
    type Error = TestError;

    async fn on_registered(&mut self) -> Result<Option<Self::Output>, Self::Error> {
        match self.registration {
            RegistrationBehavior::None => Ok(None),
            RegistrationBehavior::Deliver(output) => Ok(Some(output)),
            RegistrationBehavior::Reject => Err(TestError),
        }
    }

    async fn handle(&mut self, event: &u64) -> Result<Self::Output, Self::Error> {
        if self.panic_event == Some(*event) {
            panic!("intentional sharded subscriber test panic");
        }

        if self.block_event == Some(*event) {
            if let Some(started_tx) = self.handle_started_tx.take() {
                let _ = started_tx.send(());
            }
            self.handle_release
                .as_ref()
                .expect("blocked subscriber must have a release notification")
                .notified()
                .await;
        }

        Ok(*event)
    }

    fn deliver(&self, output: Self::Output) -> DeliverResult {
        match self.output_tx.try_send(output) {
            Ok(()) => DeliverResult::Delivered,
            Err(mpsc::error::TrySendError::Full(_)) => {
                if let Some(dropped_deliveries) = &self.dropped_deliveries {
                    dropped_deliveries.fetch_add(1, Ordering::Release);
                }
                DeliverResult::Dropped
            }
            Err(mpsc::error::TrySendError::Closed(_)) => DeliverResult::Remove,
        }
    }

    fn on_lag(&mut self, skipped: u64) -> LagAction {
        if let Some(lag_tx) = &self.lag_tx {
            let _ = lag_tx.send(skipped);
        }
        self.lag_action
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stable_key_assignment_matches_across_pool_instances() {
    let (event_tx_a, _) = broadcast::channel(8);
    let (event_tx_b, _) = broadcast::channel(8);
    let pool_a = ShardedSubscriberPool::new(&event_tx_a, MIN_PROJECTION_SHARDS).unwrap();
    let pool_b = ShardedSubscriberPool::new(&event_tx_b, MIN_PROJECTION_SHARDS).unwrap();
    let (output_tx_a, _output_rx_a) = mpsc::channel(1);
    let (output_tx_b, _output_rx_b) = mpsc::channel(1);

    let registration_a = pool_a
        .register("stable-client-instance", TestSubscriber::new(output_tx_a))
        .await
        .unwrap();
    let registration_b = pool_b
        .register("stable-client-instance", TestSubscriber::new(output_tx_b))
        .await
        .unwrap();

    assert_eq!(registration_a.shard_index(), registration_b.shard_index());
    assert_eq!(
        registration_a.shard_index(),
        stable_shard_index("stable-client-instance", MIN_PROJECTION_SHARDS)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_registration_unregisters_and_drops_subscriber() {
    let (event_tx, _) = broadcast::channel(8);
    let pool = ShardedSubscriberPool::new(&event_tx, MIN_PROJECTION_SHARDS).unwrap();
    let (output_tx, mut output_rx) = mpsc::channel(2);
    let registration = pool
        .register("ephemeral-client", TestSubscriber::new(output_tx))
        .await
        .unwrap();

    event_tx.send(1).unwrap();
    assert_eq!(
        timeout(TEST_TIMEOUT, output_rx.recv()).await.unwrap(),
        Some(1)
    );

    drop(registration);
    assert_eq!(
        timeout(TEST_TIMEOUT, output_rx.recv()).await.unwrap(),
        None,
        "the shard retained the subscriber after its registration was dropped"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_writer_queue_does_not_stall_peer_on_same_shard() {
    let (event_tx, _) = broadcast::channel(8);
    let pool = ShardedSubscriberPool::new(&event_tx, MIN_PROJECTION_SHARDS).unwrap();
    let (slow_tx, mut slow_rx) = mpsc::channel(1);
    let (fast_tx, mut fast_rx) = mpsc::channel(2);
    let dropped_deliveries = Arc::new(AtomicUsize::new(0));

    slow_tx.try_send(99).unwrap();
    let slow_registration = pool
        .register(
            "shared-shard",
            TestSubscriber::new(slow_tx).recording_drops(Arc::clone(&dropped_deliveries)),
        )
        .await
        .unwrap();
    let fast_registration = pool
        .register("shared-shard", TestSubscriber::new(fast_tx))
        .await
        .unwrap();
    assert_eq!(
        slow_registration.shard_index(),
        fast_registration.shard_index()
    );

    event_tx.send(7).unwrap();
    assert_eq!(
        timeout(TEST_TIMEOUT, fast_rx.recv()).await.unwrap(),
        Some(7),
        "a full writer queue stalled another subscriber in the shard"
    );
    timeout(TEST_TIMEOUT, async {
        while dropped_deliveries.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    assert_eq!(slow_rx.recv().await, Some(99));
    event_tx.send(8).unwrap();
    assert_eq!(
        timeout(TEST_TIMEOUT, slow_rx.recv()).await.unwrap(),
        Some(8),
        "a dropped delivery incorrectly removed the slow subscriber"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lag_action_keeps_replayable_subscriber_and_removes_unrecoverable_peer() {
    let (event_tx, _) = broadcast::channel(1);
    let pool = ShardedSubscriberPool::new(&event_tx, MIN_PROJECTION_SHARDS).unwrap();
    let (keep_output_tx, mut keep_output_rx) = mpsc::channel(8);
    let (remove_output_tx, mut remove_output_rx) = mpsc::channel(8);
    let (keep_lag_tx, mut keep_lag_rx) = mpsc::unbounded_channel();
    let (remove_lag_tx, mut remove_lag_rx) = mpsc::unbounded_channel();
    let (handle_started_tx, mut handle_started_rx) = mpsc::unbounded_channel();
    let handle_release = Arc::new(Notify::new());

    let keep_registration = pool
        .register(
            "lagged-shard",
            TestSubscriber::new(keep_output_tx)
                .with_lag_action(LagAction::Keep, keep_lag_tx)
                .blocking_on(1, handle_started_tx, Arc::clone(&handle_release)),
        )
        .await
        .unwrap();
    let remove_registration = pool
        .register(
            "lagged-shard",
            TestSubscriber::new(remove_output_tx).with_lag_action(LagAction::Remove, remove_lag_tx),
        )
        .await
        .unwrap();
    assert_eq!(
        keep_registration.shard_index(),
        remove_registration.shard_index()
    );

    event_tx.send(1).unwrap();
    timeout(TEST_TIMEOUT, handle_started_rx.recv())
        .await
        .unwrap()
        .expect("blocking subscriber did not start handling the event");
    for event in 2..=32 {
        event_tx.send(event).unwrap();
    }
    handle_release.notify_one();

    assert!(
        timeout(TEST_TIMEOUT, keep_lag_rx.recv())
            .await
            .unwrap()
            .expect("keep subscriber did not observe broadcast lag")
            > 0
    );
    assert!(
        timeout(TEST_TIMEOUT, remove_lag_rx.recv())
            .await
            .unwrap()
            .expect("remove subscriber did not observe broadcast lag")
            > 0
    );

    event_tx.send(1_000).unwrap();
    timeout(TEST_TIMEOUT, async {
        while keep_output_rx.recv().await != Some(1_000) {}
    })
    .await
    .expect("subscriber returning LagAction::Keep stopped receiving events");
    timeout(TEST_TIMEOUT, async {
        while remove_output_rx.recv().await.is_some() {}
    })
    .await
    .expect("subscriber returning LagAction::Remove was retained");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shard_panic_is_reported_and_rejects_new_registrations() {
    let (event_tx, _) = broadcast::channel(8);
    let pool = ShardedSubscriberPool::new(&event_tx, MIN_PROJECTION_SHARDS).unwrap();
    let mut health_rx = pool.health();
    let (output_tx, _output_rx) = mpsc::channel(1);
    let registration = pool
        .register(
            "failed-shard",
            TestSubscriber::new(output_tx).panicking_on(13),
        )
        .await
        .unwrap();
    let failed_shard = registration.shard_index();

    event_tx.send(13).unwrap();
    timeout(TEST_TIMEOUT, async {
        loop {
            let failed = matches!(
                health_rx.borrow().shard_status(failed_shard),
                Some(ShardStatus::Failed(_))
            );
            if failed {
                break;
            }
            health_rx.changed().await.unwrap();
        }
    })
    .await
    .expect("pool health did not report the panicked shard");

    let health = health_rx.borrow().clone();
    assert!(!health.is_healthy());
    match health.shard_status(failed_shard) {
        Some(ShardStatus::Failed(message)) => {
            assert!(message.contains("intentional sharded subscriber test panic"));
        }
        status => panic!("unexpected shard status after panic: {status:?}"),
    }

    let (replacement_tx, _replacement_rx) = mpsc::channel(1);
    let replacement = pool
        .register("failed-shard", TestSubscriber::new(replacement_tx))
        .await;
    assert_eq!(replacement.err(), Some(RegistrationError::ShardStopped));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registration_hook_delivers_baseline_before_live_event_and_can_reject() {
    let (event_tx, _) = broadcast::channel(8);
    let pool = ShardedSubscriberPool::new(&event_tx, MIN_PROJECTION_SHARDS).unwrap();
    let (output_tx, mut output_rx) = mpsc::channel(2);
    let _registration = pool
        .register(
            "baseline-client",
            TestSubscriber::new(output_tx).with_registration(RegistrationBehavior::Deliver(41)),
        )
        .await
        .unwrap();

    event_tx.send(42).unwrap();
    assert_eq!(output_rx.recv().await, Some(41));
    assert_eq!(output_rx.recv().await, Some(42));

    let (rejected_tx, _rejected_rx) = mpsc::channel(1);
    let rejected = pool
        .register(
            "rejected-client",
            TestSubscriber::new(rejected_tx).with_registration(RegistrationBehavior::Reject),
        )
        .await;
    assert_eq!(rejected.err(), Some(RegistrationError::SubscriberRejected));
}
