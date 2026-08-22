//! Byte-bounded queue that favors the newest items under pressure.
//!
//! Unlike a regular bounded channel, sending never waits for capacity. A new
//! item evicts as many of the oldest queued items as necessary to fit. Items
//! larger than the entire queue are rejected without changing the queue.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use parking_lot::Mutex;
use tokio::sync::Notify;

/// Supplies the number of bytes an item consumes in this queue.
pub(crate) trait LatestWinsQueueItem {
    fn estimated_queue_bytes(&self) -> usize;
}

struct Entry<T> {
    item: T,
    bytes: usize,
}

struct State<T> {
    items: VecDeque<Entry<T>>,
    depth_bytes: usize,
    closed: bool,
    cancelled: bool,
}

struct Inner<T> {
    state: Mutex<State<T>>,
    capacity_bytes: usize,
    sender_count: AtomicUsize,
    receiver_alive: AtomicUsize,
    notify: Notify,
}

/// Sending half of a latest-wins queue.
pub(crate) struct LatestWinsSender<T> {
    inner: Arc<Inner<T>>,
}

/// Receiving half of a latest-wins queue.
///
/// The queue has a single receiver so that dequeue order is unambiguous.
pub(crate) struct LatestWinsReceiver<T> {
    inner: Arc<Inner<T>>,
}

/// Result of successfully adding an item to the queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LatestWinsSendResult {
    evicted_items: usize,
    evicted_bytes: usize,
    depth_items: usize,
    depth_bytes: usize,
}

impl LatestWinsSendResult {
    pub(crate) fn evicted_items(self) -> usize {
        self.evicted_items
    }

    pub(crate) fn evicted_bytes(self) -> usize {
        self.evicted_bytes
    }

    pub(crate) fn depth_items(self) -> usize {
        self.depth_items
    }

    pub(crate) fn depth_bytes(self) -> usize {
        self.depth_bytes
    }
}

/// Error returned when a newest item cannot be queued.
#[derive(Debug)]
pub(crate) enum LatestWinsSendError<T> {
    Closed(T),
    TooLarge {
        item: T,
        item_bytes: usize,
        capacity_bytes: usize,
    },
}

/// Error returned by [`LatestWinsReceiver::try_recv`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TryRecvLatestWinsError {
    Empty,
    Closed,
}

impl<T> LatestWinsSendError<T> {
    pub(crate) fn into_item(self) -> T {
        match self {
            Self::Closed(item) | Self::TooLarge { item, .. } => item,
        }
    }
}

/// Result of cancelling a queue and discarding its buffered items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LatestWinsCancelResult {
    discarded_items: usize,
    discarded_bytes: usize,
}

impl LatestWinsCancelResult {
    pub(crate) fn discarded_items(self) -> usize {
        self.discarded_items
    }

    pub(crate) fn discarded_bytes(self) -> usize {
        self.discarded_bytes
    }
}

/// Creates a byte-bounded, single-receiver latest-wins queue.
pub(crate) fn latest_wins_queue<T>(
    capacity_bytes: usize,
) -> (LatestWinsSender<T>, LatestWinsReceiver<T>) {
    let inner = Arc::new(Inner {
        state: Mutex::new(State {
            items: VecDeque::new(),
            depth_bytes: 0,
            closed: false,
            cancelled: false,
        }),
        // A zero-byte queue cannot make progress. Keeping the normalization
        // here also makes zero-size item accounting deterministic.
        capacity_bytes: capacity_bytes.max(1),
        sender_count: AtomicUsize::new(1),
        receiver_alive: AtomicUsize::new(1),
        notify: Notify::new(),
    });
    (
        LatestWinsSender {
            inner: Arc::clone(&inner),
        },
        LatestWinsReceiver { inner },
    )
}

impl<T> Clone for LatestWinsSender<T> {
    fn clone(&self) -> Self {
        self.inner.sender_count.fetch_add(1, Ordering::Relaxed);
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T> LatestWinsSender<T>
where
    T: LatestWinsQueueItem,
{
    /// Adds an item, evicting the oldest buffered items when necessary.
    pub(crate) fn try_send(&self, item: T) -> Result<LatestWinsSendResult, LatestWinsSendError<T>> {
        let item_bytes = item.estimated_queue_bytes().max(1);
        if item_bytes > self.inner.capacity_bytes {
            return Err(LatestWinsSendError::TooLarge {
                item,
                item_bytes,
                capacity_bytes: self.inner.capacity_bytes,
            });
        }

        let result = {
            let mut state = self.inner.state.lock();
            if state.closed
                || state.cancelled
                || self.inner.receiver_alive.load(Ordering::Acquire) == 0
            {
                return Err(LatestWinsSendError::Closed(item));
            }

            let mut evicted_items = 0usize;
            let mut evicted_bytes = 0usize;
            while state.depth_bytes.saturating_add(item_bytes) > self.inner.capacity_bytes {
                let Some(evicted) = state.items.pop_front() else {
                    break;
                };
                state.depth_bytes = state.depth_bytes.saturating_sub(evicted.bytes);
                evicted_items = evicted_items.saturating_add(1);
                evicted_bytes = evicted_bytes.saturating_add(evicted.bytes);
            }

            state.depth_bytes = state.depth_bytes.saturating_add(item_bytes);
            state.items.push_back(Entry {
                item,
                bytes: item_bytes,
            });
            LatestWinsSendResult {
                evicted_items,
                evicted_bytes,
                depth_items: state.items.len(),
                depth_bytes: state.depth_bytes,
            }
        };
        self.inner.notify.notify_one();
        Ok(result)
    }

    /// Prevents further sends while allowing the receiver to drain the queue.
    pub(crate) fn close(&self) {
        close_inner(&self.inner);
    }

    /// Prevents further sends and immediately discards buffered items.
    pub(crate) fn cancel(&self) -> LatestWinsCancelResult {
        cancel_inner(&self.inner)
    }

    pub(crate) fn is_closed(&self) -> bool {
        let state = self.inner.state.lock();
        state.closed || state.cancelled
    }

    pub(crate) fn capacity_bytes(&self) -> usize {
        self.inner.capacity_bytes
    }

    pub(crate) fn depth_bytes(&self) -> usize {
        self.inner.state.lock().depth_bytes
    }
}

impl<T> Drop for LatestWinsSender<T> {
    fn drop(&mut self) {
        if self.inner.sender_count.fetch_sub(1, Ordering::AcqRel) == 1 {
            close_inner(&self.inner);
        }
    }
}

impl<T> LatestWinsReceiver<T> {
    /// Receives the next buffered item, or `None` once closed and drained.
    pub(crate) async fn recv(&mut self) -> Option<T> {
        loop {
            let notified = self.inner.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            {
                let mut state = self.inner.state.lock();
                if state.cancelled {
                    return None;
                }
                if let Some(entry) = state.items.pop_front() {
                    state.depth_bytes = state.depth_bytes.saturating_sub(entry.bytes);
                    return Some(entry.item);
                }
                if state.closed {
                    return None;
                }
            }

            notified.await;
        }
    }

    pub(crate) fn is_closed(&self) -> bool {
        let state = self.inner.state.lock();
        state.closed || state.cancelled
    }

    pub(crate) fn depth_bytes(&self) -> usize {
        self.inner.state.lock().depth_bytes
    }

    /// Non-blocking receive of the next buffered item, if one is ready.
    pub(crate) fn try_recv(&mut self) -> Result<T, TryRecvLatestWinsError> {
        let mut state = self.inner.state.lock();
        if state.cancelled {
            return Err(TryRecvLatestWinsError::Closed);
        }
        if let Some(entry) = state.items.pop_front() {
            state.depth_bytes = state.depth_bytes.saturating_sub(entry.bytes);
            return Ok(entry.item);
        }
        if state.closed {
            Err(TryRecvLatestWinsError::Closed)
        } else {
            Err(TryRecvLatestWinsError::Empty)
        }
    }
}

impl<T> Drop for LatestWinsReceiver<T> {
    fn drop(&mut self) {
        self.inner.receiver_alive.store(0, Ordering::Release);
        cancel_inner(&self.inner);
    }
}

fn close_inner<T>(inner: &Inner<T>) {
    let should_notify = {
        let mut state = inner.state.lock();
        let was_open = !state.closed && !state.cancelled;
        state.closed = true;
        was_open
    };
    if should_notify {
        inner.notify.notify_waiters();
    }
}

fn cancel_inner<T>(inner: &Inner<T>) -> LatestWinsCancelResult {
    let result = {
        let mut state = inner.state.lock();
        let result = LatestWinsCancelResult {
            discarded_items: state.items.len(),
            discarded_bytes: state.depth_bytes,
        };
        state.items.clear();
        state.depth_bytes = 0;
        state.closed = true;
        state.cancelled = true;
        result
    };
    inner.notify.notify_waiters();
    result
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct Item {
        id: u8,
        bytes: usize,
    }

    impl Item {
        fn new(id: u8, bytes: usize) -> Self {
            Self { id, bytes }
        }
    }

    impl LatestWinsQueueItem for Item {
        fn estimated_queue_bytes(&self) -> usize {
            self.bytes
        }
    }

    #[tokio::test]
    async fn newest_item_evicts_oldest_until_it_fits() {
        let (tx, mut rx) = latest_wins_queue(10);
        tx.try_send(Item::new(1, 4)).expect("first item");
        tx.try_send(Item::new(2, 4)).expect("second item");

        let result = tx.try_send(Item::new(3, 5)).expect("newest item");
        assert_eq!(result.evicted_items(), 1);
        assert_eq!(result.evicted_bytes(), 4);
        assert_eq!(result.depth_items(), 2);
        assert_eq!(result.depth_bytes(), 9);
        assert_eq!(rx.recv().await, Some(Item::new(2, 4)));
        assert_eq!(rx.recv().await, Some(Item::new(3, 5)));
    }

    #[tokio::test]
    async fn oversized_item_is_rejected_without_evicting_existing_items() {
        let (tx, mut rx) = latest_wins_queue(10);
        tx.try_send(Item::new(1, 4)).expect("existing item");

        match tx.try_send(Item::new(2, 11)) {
            Err(LatestWinsSendError::TooLarge {
                item,
                item_bytes,
                capacity_bytes,
            }) => {
                assert_eq!(item, Item::new(2, 11));
                assert_eq!(item_bytes, 11);
                assert_eq!(capacity_bytes, 10);
            }
            other => panic!("unexpected send result: {other:?}"),
        }
        assert_eq!(tx.depth_bytes(), 4);
        assert_eq!(rx.recv().await, Some(Item::new(1, 4)));
    }

    #[tokio::test]
    async fn graceful_close_rejects_sends_and_drains_buffered_items() {
        let (tx, mut rx) = latest_wins_queue(10);
        tx.try_send(Item::new(1, 4)).expect("existing item");
        tx.close();

        assert!(tx.is_closed());
        assert!(rx.is_closed());
        assert!(matches!(
            tx.try_send(Item::new(2, 1)),
            Err(LatestWinsSendError::Closed(Item { id: 2, .. }))
        ));
        assert_eq!(rx.recv().await, Some(Item::new(1, 4)));
        assert_eq!(rx.recv().await, None);
    }

    #[tokio::test]
    async fn cancel_discards_items_and_wakes_a_blocked_receiver() {
        let (tx, mut rx) = latest_wins_queue::<Item>(10);
        tx.try_send(Item::new(1, 4)).expect("first item");
        let result = tx.cancel();
        assert_eq!(result.discarded_items(), 1);
        assert_eq!(result.discarded_bytes(), 4);
        assert_eq!(rx.depth_bytes(), 0);
        assert_eq!(rx.recv().await, None);

        let (tx, mut rx) = latest_wins_queue::<Item>(10);
        let waiter = tokio::spawn(async move { rx.recv().await });
        tokio::task::yield_now().await;
        tx.cancel();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .expect("cancel should wake receiver")
                .expect("receiver task"),
            None
        );
    }

    #[tokio::test]
    async fn dropping_last_sender_closes_after_drain() {
        let (tx, mut rx) = latest_wins_queue(10);
        let tx_clone = tx.clone();
        tx.try_send(Item::new(1, 4)).expect("existing item");
        drop(tx);
        assert!(!rx.is_closed());
        drop(tx_clone);

        assert_eq!(rx.recv().await, Some(Item::new(1, 4)));
        assert_eq!(rx.recv().await, None);
    }

    #[test]
    fn dropping_receiver_closes_sender_and_returns_item() {
        let (tx, rx) = latest_wins_queue(10);
        drop(rx);

        let err = tx.try_send(Item::new(1, 4)).expect_err("receiver is gone");
        assert_eq!(err.into_item(), Item::new(1, 4));
    }

    #[test]
    fn try_recv_returns_items_without_blocking() {
        let (tx, mut rx) = latest_wins_queue::<Item>(10);
        assert_eq!(rx.try_recv(), Err(TryRecvLatestWinsError::Empty));
        tx.try_send(Item::new(1, 4)).expect("first item");
        assert_eq!(rx.try_recv(), Ok(Item::new(1, 4)));
        assert_eq!(rx.try_recv(), Err(TryRecvLatestWinsError::Empty));

        tx.close();
        assert_eq!(rx.try_recv(), Err(TryRecvLatestWinsError::Closed));
    }

    #[tokio::test]
    async fn zero_sized_items_still_consume_capacity() {
        let (tx, mut rx) = latest_wins_queue(1);
        tx.try_send(Item::new(1, 0)).expect("first item");
        let result = tx.try_send(Item::new(2, 0)).expect("second item");
        assert_eq!(result.evicted_items(), 1);
        assert_eq!(result.evicted_bytes(), 1);
        assert_eq!(rx.recv().await, Some(Item::new(2, 0)));
    }
}
