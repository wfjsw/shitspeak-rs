use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::{Notify, mpsc};

use super::connection::OutboundFrame;
use super::manager::InboundMessage;

const DEFAULT_MEMORY_FRACTION_DIVISOR: u64 = 20;
const DEFAULT_MIN_BUDGET_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_FALLBACK_BUDGET_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_MAX_BUDGET_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const QUEUE_ITEM_OVERHEAD_BYTES: usize = 256;
const MIN_LANE_BYTES: usize = 512 * 1024;

pub trait AdaptiveQueueItem {
    fn estimated_queue_bytes(&self) -> usize;
}

impl AdaptiveQueueItem for InboundMessage {
    fn estimated_queue_bytes(&self) -> usize {
        QUEUE_ITEM_OVERHEAD_BYTES.saturating_add(self.payload().len())
    }
}

impl AdaptiveQueueItem for OutboundFrame {
    fn estimated_queue_bytes(&self) -> usize {
        QUEUE_ITEM_OVERHEAD_BYTES.saturating_add(self.payload().len())
    }
}

#[derive(Clone)]
pub struct AdaptiveQueueBudget {
    inner: Arc<AdaptiveQueueBudgetInner>,
}

struct AdaptiveQueueBudgetInner {
    max_bytes: usize,
    used_bytes: AtomicUsize,
    notify: Notify,
}

impl AdaptiveQueueBudget {
    pub(crate) fn auto() -> Self {
        Self::new(auto_budget_bytes())
    }

    pub fn new(max_bytes: usize) -> Self {
        Self {
            inner: Arc::new(AdaptiveQueueBudgetInner {
                max_bytes: max_bytes.max(MIN_LANE_BYTES),
                used_bytes: AtomicUsize::new(0),
                notify: Notify::new(),
            }),
        }
    }

    pub fn max_bytes(&self) -> usize {
        self.inner.max_bytes
    }

    pub fn split(&self, max_bytes: usize) -> AdaptiveLaneBudget {
        AdaptiveLaneBudget {
            global: self.clone(),
            max_bytes: max_bytes.max(MIN_LANE_BYTES).min(self.inner.max_bytes),
            used_bytes: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[derive(Clone)]
pub struct AdaptiveLaneBudget {
    global: AdaptiveQueueBudget,
    max_bytes: usize,
    used_bytes: Arc<AtomicUsize>,
}

impl AdaptiveLaneBudget {
    pub(crate) async fn reserve(&self, bytes: usize) -> Option<AdaptiveQueuePermit> {
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

    pub(crate) fn try_reserve(&self, bytes: usize) -> Option<AdaptiveQueuePermit> {
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
        Some(AdaptiveQueuePermit {
            lane: self.clone(),
            bytes,
        })
    }

    pub(crate) fn depth_bytes(&self) -> usize {
        self.used_bytes.load(Ordering::Acquire)
    }

    pub(crate) fn max_bytes(&self) -> usize {
        self.max_bytes
    }
}

pub(crate) struct AdaptiveQueuePermit {
    lane: AdaptiveLaneBudget,
    bytes: usize,
}

impl Drop for AdaptiveQueuePermit {
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
    item: T,
    _permit: AdaptiveQueuePermit,
}

pub struct AdaptiveQueueSender<T> {
    tx: mpsc::UnboundedSender<Queued<T>>,
    budget: AdaptiveLaneBudget,
}

pub struct AdaptiveQueueReceiver<T> {
    rx: mpsc::UnboundedReceiver<Queued<T>>,
}

impl<T> Clone for AdaptiveQueueSender<T> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            budget: self.budget.clone(),
        }
    }
}

impl<T> AdaptiveQueueSender<T>
where
    T: AdaptiveQueueItem,
{
    pub fn new(budget: AdaptiveLaneBudget) -> (Self, AdaptiveQueueReceiver<T>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { tx, budget }, AdaptiveQueueReceiver { rx })
    }

    pub(crate) fn try_send(&self, item: T) -> Result<(), TryAdaptiveSendError<T>> {
        let Some(permit) = self.budget.try_reserve(item.estimated_queue_bytes()) else {
            return Err(TryAdaptiveSendError::Full(item));
        };
        self.tx
            .send(Queued {
                item,
                _permit: permit,
            })
            .map_err(|err| TryAdaptiveSendError::Closed(err.0.item))
    }

    pub async fn send(&self, item: T) -> Result<(), SendAdaptiveError<T>> {
        let Some(permit) = self.budget.reserve(item.estimated_queue_bytes()).await else {
            return Err(SendAdaptiveError(item));
        };
        self.tx
            .send(Queued {
                item,
                _permit: permit,
            })
            .map_err(|err| SendAdaptiveError(err.0.item))
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }

    pub(crate) fn depth_bytes(&self) -> usize {
        self.budget.depth_bytes()
    }

    pub(crate) fn capacity_bytes(&self) -> usize {
        self.budget.max_bytes()
    }
}

impl<T> AdaptiveQueueReceiver<T> {
    pub async fn recv(&mut self) -> Option<T> {
        self.rx.recv().await.map(|queued| queued.item)
    }

    pub fn try_recv(&mut self) -> Result<T, mpsc::error::TryRecvError> {
        self.rx.try_recv().map(|queued| queued.item)
    }
}

#[derive(Debug)]
pub(crate) enum TryAdaptiveSendError<T> {
    Full(T),
    Closed(T),
}

pub struct SendAdaptiveError<T>(pub T);

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

fn auto_budget_bytes() -> usize {
    let detected = available_memory_bytes().map(|bytes| {
        bytes
            .checked_div(DEFAULT_MEMORY_FRACTION_DIVISOR)
            .unwrap_or(DEFAULT_FALLBACK_BUDGET_BYTES)
    });
    let bytes = detected.unwrap_or(DEFAULT_FALLBACK_BUDGET_BYTES);
    bytes
        .clamp(DEFAULT_MIN_BUDGET_BYTES, DEFAULT_MAX_BUDGET_BYTES)
        .min(usize::MAX as u64) as usize
}

#[cfg(windows)]
fn available_memory_bytes() -> Option<u64> {
    use std::mem::size_of;
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    let mut status = MEMORYSTATUSEX {
        dwLength: size_of::<MEMORYSTATUSEX>() as u32,
        dwMemoryLoad: 0,
        ullTotalPhys: 0,
        ullAvailPhys: 0,
        ullTotalPageFile: 0,
        ullAvailPageFile: 0,
        ullTotalVirtual: 0,
        ullAvailVirtual: 0,
        ullAvailExtendedVirtual: 0,
    };
    let ok = unsafe { GlobalMemoryStatusEx(&mut status) };
    (ok != 0).then_some(status.ullAvailPhys)
}

#[cfg(not(windows))]
fn available_memory_bytes() -> Option<u64> {
    parse_mem_available_from_proc().or_else(parse_cgroup_memory_available)
}

#[cfg(not(windows))]
fn parse_mem_available_from_proc() -> Option<u64> {
    let contents = std::fs::read_to_string("/proc/meminfo").ok()?;
    contents.lines().find_map(|line| {
        let rest = line.strip_prefix("MemAvailable:")?.trim();
        let kb = rest.split_whitespace().next()?.parse::<u64>().ok()?;
        kb.checked_mul(1024)
    })
}

#[cfg(not(windows))]
fn parse_cgroup_memory_available() -> Option<u64> {
    let max_text = std::fs::read_to_string("/sys/fs/cgroup/memory.max").ok()?;
    let max_text = max_text.trim();
    if max_text == "max" {
        return None;
    }
    let max = max_text.parse::<u64>().ok()?;
    let current = std::fs::read_to_string("/sys/fs/cgroup/memory.current")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())?;
    max.checked_sub(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct Item(usize);

    impl AdaptiveQueueItem for Item {
        fn estimated_queue_bytes(&self) -> usize {
            self.0
        }
    }

    #[test]
    fn permit_release_restores_lane_capacity() {
        let budget = AdaptiveQueueBudget::new(1024 * 1024);
        let lane = budget.split(1024 * 1024);
        let permit = lane.try_reserve(768 * 1024).expect("reserve fits");
        assert!(lane.try_reserve(512 * 1024).is_none());
        drop(permit);
        assert!(lane.try_reserve(512 * 1024).is_some());
    }

    #[tokio::test]
    async fn sender_drops_when_adaptive_budget_is_full() {
        let budget = AdaptiveQueueBudget::new(1024 * 1024);
        let (tx, mut rx) = AdaptiveQueueSender::new(budget.split(1024 * 1024));

        assert!(tx.try_send(Item(768 * 1024)).is_ok());
        assert!(matches!(
            tx.try_send(Item(512 * 1024)),
            Err(TryAdaptiveSendError::Full(_))
        ));
        assert_eq!(rx.recv().await, Some(Item(768 * 1024)));
        assert!(tx.try_send(Item(512 * 1024)).is_ok());
    }
}
