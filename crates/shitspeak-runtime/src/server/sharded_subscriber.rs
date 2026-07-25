use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use futures_util::{FutureExt as _, StreamExt as _, stream};
use parking_lot::Mutex;
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, oneshot, watch};

pub(crate) const MIN_PROJECTION_SHARDS: usize = 4;
pub(crate) const MAX_PROJECTION_SHARDS: usize = 8;
const MAX_CONCURRENT_LAG_RECOVERIES: usize = 8;

/// The outcome of a synchronous, non-blocking delivery attempt.
///
/// `Dropped` is for subscribers which record their own replay/resync need and
/// can safely remain registered. `Remove` unregisters the subscriber, which is
/// the conservative response to a closed or persistently full writer queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeliverResult {
    Delivered,
    // The production projection disconnects on queue pressure, but the
    // generic pool deliberately supports subscribers that recover in place.
    #[allow(dead_code)]
    Dropped,
    Remove,
}

/// Decision made by a subscriber after the shard's broadcast receiver lags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LagAction {
    /// The subscriber has marked itself for replay/resynchronization.
    Keep,
    /// The subscriber cannot recover in place and must be unregistered.
    Remove,
}

/// Per-client projection state owned and called exclusively by one shard.
#[async_trait]
pub(crate) trait ShardedSubscriber<Event>: Send + 'static
where
    Event: Send + Sync + 'static,
{
    type Output: Send + 'static;
    type Error: std::error::Error + Send + Sync + 'static;

    /// Runs inside the owning shard before registration becomes visible.
    ///
    /// A projection subscriber can use this to replay from its transferred
    /// baseline to the current log tail. Any returned output is delivered
    /// non-blockingly before the registration acknowledgement is sent.
    async fn on_registered(&mut self) -> Result<Option<Self::Output>, Self::Error> {
        Ok(None)
    }

    async fn handle(&mut self, event: &Event) -> Result<Self::Output, Self::Error>;

    /// Must not block. Implementations should normally use bounded `try_send`.
    fn deliver(&self, output: Self::Output) -> DeliverResult;

    /// Called when the shard removes a subscriber because handling, delivery,
    /// or lag recovery failed. It must not block.
    fn on_remove(&self) {}

    /// Broadcast lag is explicit and conservative by default.
    fn on_lag(&mut self, _skipped: u64) -> LagAction {
        LagAction::Remove
    }

    /// Runs immediately after [`Self::on_lag`] elects to keep the subscriber.
    ///
    /// This is separate from `on_lag` so the cheap keep/remove decision remains
    /// synchronous while log-backed subscribers can perform asynchronous
    /// recovery without waiting for another live event to wake the shard.
    async fn recover_lag(&mut self) -> Result<Option<Self::Output>, Self::Error> {
        Ok(None)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ShardStatus {
    Starting,
    Running,
    Stopped,
    EventSourceClosed,
    Failed(Arc<str>),
}

#[derive(Clone, Debug)]
pub(crate) struct PoolHealth {
    shard_statuses: Arc<[ShardStatus]>,
}

impl PoolHealth {
    #[cfg(test)]
    pub(crate) fn is_healthy(&self) -> bool {
        self.shard_statuses
            .iter()
            .all(|status| matches!(status, ShardStatus::Starting | ShardStatus::Running))
    }

    pub(crate) fn shard_status(&self, shard_index: usize) -> Option<&ShardStatus> {
        self.shard_statuses.get(shard_index)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum PoolBuildError {
    #[error(
        "projection shard count must be between {MIN_PROJECTION_SHARDS} and {MAX_PROJECTION_SHARDS}, got {0}"
    )]
    InvalidShardCount(usize),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum RegistrationError {
    #[error("projection shard task is no longer running")]
    ShardStopped,
    #[error("projection subscriber rejected during registration")]
    SubscriberRejected,
}

pub(crate) struct ShardedSubscriberPool<Event, Subscriber>
where
    Event: Clone + Send + Sync + 'static,
    Subscriber: ShardedSubscriber<Event>,
{
    shards: Vec<Shard<Event, Subscriber>>,
    next_registration_id: AtomicU64,
    health_rx: watch::Receiver<PoolHealth>,
}

impl<Event, Subscriber> ShardedSubscriberPool<Event, Subscriber>
where
    Event: Clone + Send + Sync + 'static,
    Subscriber: ShardedSubscriber<Event>,
{
    /// Starts one long-lived task and one broadcast receiver per shard.
    pub(crate) fn new(
        event_tx: &broadcast::Sender<Event>,
        shard_count: usize,
    ) -> Result<Self, PoolBuildError> {
        if !(MIN_PROJECTION_SHARDS..=MAX_PROJECTION_SHARDS).contains(&shard_count) {
            return Err(PoolBuildError::InvalidShardCount(shard_count));
        }

        let initial_health = PoolHealth {
            shard_statuses: vec![ShardStatus::Starting; shard_count].into(),
        };
        let statuses = Arc::new(Mutex::new(initial_health.shard_statuses.to_vec()));
        let (health_tx, health_rx) = watch::channel(initial_health);
        let mut shards = Vec::with_capacity(shard_count);

        for shard_index in 0..shard_count {
            let (command_tx, command_rx) = mpsc::unbounded_channel();
            let event_rx = event_tx.subscribe();
            let shard_statuses = Arc::clone(&statuses);
            let shard_health_tx = health_tx.clone();

            tokio::spawn(async move {
                set_shard_status(
                    &shard_statuses,
                    &shard_health_tx,
                    shard_index,
                    ShardStatus::Running,
                );

                let result = AssertUnwindSafe(run_shard::<Event, Subscriber>(
                    shard_index,
                    event_rx,
                    command_rx,
                ))
                .catch_unwind()
                .await;

                let status = match result {
                    Ok(WorkerExit::Shutdown) => ShardStatus::Stopped,
                    Ok(WorkerExit::EventSourceClosed) => ShardStatus::EventSourceClosed,
                    Ok(WorkerExit::CommandSourceClosed) => ShardStatus::Stopped,
                    Err(payload) => ShardStatus::Failed(panic_message(payload)),
                };
                set_shard_status(&shard_statuses, &shard_health_tx, shard_index, status);
            });

            shards.push(Shard {
                command_tx,
                _event: PhantomData,
            });
        }
        drop(health_tx);

        Ok(Self {
            shards,
            next_registration_id: AtomicU64::new(1),
            health_rx,
        })
    }

    pub(crate) fn health(&self) -> watch::Receiver<PoolHealth> {
        self.health_rx.clone()
    }

    /// Transfers a subscriber into its stable shard and waits for the atomic
    /// registration point. Events published after this returns are ordered
    /// after registration by the shard's command-first event loop.
    pub(crate) async fn register<Key>(
        &self,
        key: &Key,
        subscriber: Subscriber,
    ) -> Result<Registration<Subscriber>, RegistrationError>
    where
        Key: Hash + ?Sized,
    {
        let shard_index = stable_shard_index(key, self.shards.len());
        let registration_id = self.next_registration_id.fetch_add(1, Ordering::Relaxed);
        let shard = &self.shards[shard_index];
        let (registered_tx, registered_rx) = oneshot::channel();
        // Construct the RAII guard before the first cancellation point. If
        // this future is dropped after the shard accepts the subscriber but
        // before the acknowledgement is observed, the guard still enqueues
        // the matching unregister command.
        let registration = Registration {
            registration_id,
            shard_index,
            command_tx: shard.command_tx.clone(),
            active: true,
        };

        shard
            .command_tx
            .send(ShardCommand::Register {
                registration_id,
                subscriber,
                registered_tx,
            })
            .map_err(|_| RegistrationError::ShardStopped)?;
        registered_rx
            .await
            .map_err(|_| RegistrationError::ShardStopped)??;

        Ok(registration)
    }
}

impl<Event, Subscriber> Drop for ShardedSubscriberPool<Event, Subscriber>
where
    Event: Clone + Send + Sync + 'static,
    Subscriber: ShardedSubscriber<Event>,
{
    fn drop(&mut self) {
        for shard in &self.shards {
            let _ = shard.command_tx.send(ShardCommand::Shutdown);
        }
    }
}

pub(crate) struct Registration<Subscriber> {
    registration_id: u64,
    shard_index: usize,
    command_tx: mpsc::UnboundedSender<ShardCommand<Subscriber>>,
    active: bool,
}

impl<Subscriber> Registration<Subscriber> {
    pub(crate) fn shard_index(&self) -> usize {
        self.shard_index
    }

    fn send_unregister(&mut self) {
        if self.active {
            let _ = self.command_tx.send(ShardCommand::Unregister {
                registration_id: self.registration_id,
            });
            self.active = false;
        }
    }
}

impl<Subscriber> Drop for Registration<Subscriber> {
    fn drop(&mut self) {
        self.send_unregister();
    }
}

struct Shard<Event, Subscriber> {
    command_tx: mpsc::UnboundedSender<ShardCommand<Subscriber>>,
    _event: PhantomData<fn(Event)>,
}

enum ShardCommand<Subscriber> {
    Register {
        registration_id: u64,
        subscriber: Subscriber,
        registered_tx: oneshot::Sender<Result<(), RegistrationError>>,
    },
    Unregister {
        registration_id: u64,
    },
    Shutdown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WorkerExit {
    Shutdown,
    EventSourceClosed,
    CommandSourceClosed,
}

async fn run_shard<Event, Subscriber>(
    shard_index: usize,
    mut event_rx: broadcast::Receiver<Event>,
    mut command_rx: mpsc::UnboundedReceiver<ShardCommand<Subscriber>>,
) -> WorkerExit
where
    Event: Clone + Send + Sync + 'static,
    Subscriber: ShardedSubscriber<Event>,
{
    let mut subscribers = HashMap::<u64, Subscriber>::new();

    loop {
        tokio::select! {
            command = command_rx.recv() => {
                match command {
                    Some(ShardCommand::Register {
                        registration_id,
                        mut subscriber,
                        registered_tx,
                    }) => {
                        if registered_tx.is_closed() {
                            continue;
                        }

                        let registration_output = match subscriber.on_registered().await {
                            Ok(output) => output,
                            Err(error) => {
                                tracing::warn!(
                                    shard_index,
                                    registration_id,
                                    error = %error,
                                    "rejecting sharded subscriber during registration"
                                );
                                let _ = registered_tx
                                    .send(Err(RegistrationError::SubscriberRejected));
                                continue;
                            }
                        };
                        // The connection may have gone away while baseline
                        // replay was running. Do not deliver or retain it.
                        if registered_tx.is_closed() {
                            continue;
                        }
                        let accepted = registration_output
                            .map(|output| subscriber.deliver(output) != DeliverResult::Remove)
                            .unwrap_or(true);
                        if !accepted {
                            subscriber.on_remove();
                            let _ = registered_tx.send(Err(RegistrationError::SubscriberRejected));
                            continue;
                        }

                        subscribers.insert(registration_id, subscriber);
                        if registered_tx.send(Ok(())).is_err() {
                            subscribers.remove(&registration_id);
                        }
                    }
                    Some(ShardCommand::Unregister { registration_id }) => {
                        subscribers.remove(&registration_id);
                    }
                    Some(ShardCommand::Shutdown) => return WorkerExit::Shutdown,
                    None => return WorkerExit::CommandSourceClosed,
                }
            }
            event = event_rx.recv() => {
                match event {
                    Ok(event) => process_event(shard_index, &mut subscribers, &event).await,
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        crate::observability::record_client_projection_lag(
                            crate::observability::ClientProjectionLagSource::Shard,
                            skipped,
                        );
                        process_lag(shard_index, &mut subscribers, skipped).await;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        return WorkerExit::EventSourceClosed;
                    }
                }
            }
        }
    }
}

async fn process_lag<Event, Subscriber>(
    shard_index: usize,
    subscribers: &mut HashMap<u64, Subscriber>,
    skipped: u64,
) where
    Event: Send + Sync + 'static,
    Subscriber: ShardedSubscriber<Event>,
{
    // Recovery commonly scans shared repositories. Run the subscribers in a
    // lagged shard concurrently so recovery time is bounded by the slowest
    // subscriber rather than the sum of every subscriber's scan time.
    let lagged = std::mem::take(subscribers);
    let recovered = stream::iter(lagged.into_iter().map(
        |(registration_id, mut subscriber)| async move {
            let result = if subscriber.on_lag(skipped) == LagAction::Remove {
                DeliverResult::Remove
            } else {
                match subscriber.recover_lag().await {
                    Ok(Some(output)) => subscriber.deliver(output),
                    Ok(None) => DeliverResult::Delivered,
                    Err(error) => {
                        tracing::warn!(
                            shard_index,
                            registration_id,
                            skipped,
                            error = %error,
                            "removing sharded subscriber after lag recovery failed"
                        );
                        DeliverResult::Remove
                    }
                }
            };

            if result == DeliverResult::Remove {
                subscriber.on_remove();
                tracing::warn!(
                    shard_index,
                    registration_id,
                    skipped,
                    "removing lagged sharded subscriber"
                );
                None
            } else {
                Some((registration_id, subscriber))
            }
        },
    ))
    .buffer_unordered(MAX_CONCURRENT_LAG_RECOVERIES)
    .collect::<Vec<_>>()
    .await;
    subscribers.extend(recovered.into_iter().flatten());
}

async fn process_event<Event, Subscriber>(
    shard_index: usize,
    subscribers: &mut HashMap<u64, Subscriber>,
    event: &Event,
) where
    Event: Send + Sync + 'static,
    Subscriber: ShardedSubscriber<Event>,
{
    // IDs are copied so a failed/dropped subscriber can be removed only after
    // its mutable borrow ends. Each subscriber still observes events in order.
    let registration_ids: Vec<u64> = subscribers.keys().copied().collect();
    for registration_id in registration_ids {
        let result = {
            let Some(subscriber) = subscribers.get_mut(&registration_id) else {
                continue;
            };
            match subscriber.handle(event).await {
                Ok(output) => subscriber.deliver(output),
                Err(error) => {
                    tracing::warn!(
                        shard_index,
                        registration_id,
                        error = %error,
                        "removing failed sharded subscriber"
                    );
                    DeliverResult::Remove
                }
            }
        };

        if result == DeliverResult::Remove {
            if let Some(subscriber) = subscribers.remove(&registration_id) {
                subscriber.on_remove();
            }
        }
    }
}

fn set_shard_status(
    statuses: &Mutex<Vec<ShardStatus>>,
    health_tx: &watch::Sender<PoolHealth>,
    shard_index: usize,
    status: ShardStatus,
) {
    let mut statuses = statuses.lock();
    statuses[shard_index] = status;
    let snapshot = PoolHealth {
        shard_statuses: statuses.clone().into(),
    };
    let _ = health_tx.send(snapshot);
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> Arc<str> {
    if let Some(message) = payload.downcast_ref::<&str>() {
        Arc::from(*message)
    } else if let Some(message) = payload.downcast_ref::<String>() {
        Arc::from(message.as_str())
    } else {
        Arc::from("projection shard panicked")
    }
}

fn stable_shard_index<Key>(key: &Key, shard_count: usize) -> usize
where
    Key: Hash + ?Sized,
{
    let mut hasher = StableFnv1a64::default();
    key.hash(&mut hasher);
    (hasher.finish() % shard_count as u64) as usize
}

struct StableFnv1a64(u64);

impl Default for StableFnv1a64 {
    fn default() -> Self {
        Self(0xcbf29ce484222325)
    }
}

impl Hasher for StableFnv1a64 {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }

    fn write_u8(&mut self, value: u8) {
        self.write(&value.to_le_bytes());
    }

    fn write_u16(&mut self, value: u16) {
        self.write(&value.to_le_bytes());
    }

    fn write_u32(&mut self, value: u32) {
        self.write(&value.to_le_bytes());
    }

    fn write_u64(&mut self, value: u64) {
        self.write(&value.to_le_bytes());
    }

    fn write_u128(&mut self, value: u128) {
        self.write(&value.to_le_bytes());
    }

    fn write_usize(&mut self, value: usize) {
        self.write_u64(value as u64);
    }

    fn write_i8(&mut self, value: i8) {
        self.write(&value.to_le_bytes());
    }

    fn write_i16(&mut self, value: i16) {
        self.write(&value.to_le_bytes());
    }

    fn write_i32(&mut self, value: i32) {
        self.write(&value.to_le_bytes());
    }

    fn write_i64(&mut self, value: i64) {
        self.write(&value.to_le_bytes());
    }

    fn write_i128(&mut self, value: i128) {
        self.write(&value.to_le_bytes());
    }

    fn write_isize(&mut self, value: isize) {
        self.write_i64(value as i64);
    }
}

#[cfg(test)]
#[path = "sharded_subscriber_tests.rs"]
mod tests;
