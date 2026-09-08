//! Diagnostic wrapper: requested Rust live bytes and bounded live samples.
//! Native allocations bypassing GlobalAlloc are outside the Rust counters.

use std::alloc::{GlobalAlloc, Layout};
use std::cell::Cell;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::time::Instant;

use serde::Serialize;

mod output;
pub use mimalloc::MiMalloc;
pub use output::{Observation, start_from_env};

const FRAMES: usize = 24;
const SAMPLE_BYTES: usize = 1024 * 1024;
static NEXT_THREAD: AtomicU64 = AtomicU64::new(1);
thread_local! {
    static THREAD: Cell<u64> = const { Cell::new(0) };
    static RANDOM: Cell<u64> = const { Cell::new(0) };
    static IN_PROFILER: Cell<bool> = const { Cell::new(false) };
}

fn thread_id() -> u64 {
    THREAD
        .try_with(|id| {
            if id.get() == 0 {
                id.set(NEXT_THREAD.fetch_add(1, Relaxed));
            }
            id.get()
        })
        .unwrap_or(0)
}

struct Suppress;
impl Suppress {
    fn enter() -> Option<Self> {
        IN_PROFILER
            .try_with(|flag| if flag.replace(true) { None } else { Some(Self) })
            .ok()
            .flatten()
    }
}
impl Drop for Suppress {
    fn drop(&mut self) {
        let _ = IN_PROFILER.try_with(|flag| flag.set(false));
    }
}

#[derive(Clone, Copy, Serialize)]
struct Sample {
    id: u64,
    address: usize,
    bytes: usize,
    initial_bytes: usize,
    thread: u64,
    #[serde(skip)]
    born: Option<Instant>,
    age_ms: u64,
    reallocations: u64,
    frames: [usize; FRAMES],
    frame_count: usize,
}
impl Sample {
    const EMPTY: Self = Self {
        id: 0,
        address: 0,
        bytes: 0,
        initial_bytes: 0,
        thread: 0,
        born: None,
        age_ms: 0,
        reallocations: 0,
        frames: [0; FRAMES],
        frame_count: 0,
    };
}

struct Slot {
    address: AtomicUsize,
    sample: Mutex<Sample>,
}
impl Slot {
    const EMPTY: Self = Self {
        address: AtomicUsize::new(0),
        sample: Mutex::new(Sample::EMPTY),
    };
}

#[derive(Default)]
struct Counters {
    live_bytes: AtomicUsize,
    live_objects: AtomicUsize,
    peak_bytes: AtomicUsize,
    allocated_bytes: AtomicU64,
    freed_bytes: AtomicU64,
    allocations: AtomicU64,
    frees: AtomicU64,
    reallocations: AtomicU64,
    failures: AtomicU64,
    admitted: AtomicU64,
    collisions: AtomicU64,
    sampled_frees: AtomicU64,
    cross_thread_frees: AtomicU64,
    unknown_thread_frees: AtomicU64,
}
impl Counters {
    const fn new() -> Self {
        Self {
            live_bytes: AtomicUsize::new(0),
            live_objects: AtomicUsize::new(0),
            peak_bytes: AtomicUsize::new(0),
            allocated_bytes: AtomicU64::new(0),
            freed_bytes: AtomicU64::new(0),
            allocations: AtomicU64::new(0),
            frees: AtomicU64::new(0),
            reallocations: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            admitted: AtomicU64::new(0),
            collisions: AtomicU64::new(0),
            sampled_frees: AtomicU64::new(0),
            cross_thread_frees: AtomicU64::new(0),
            unknown_thread_frees: AtomicU64::new(0),
        }
    }
    fn add(&self, bytes: usize) {
        self.allocated_bytes.fetch_add(bytes as u64, Relaxed);
        let live = self.live_bytes.fetch_add(bytes, Relaxed) + bytes;
        self.peak_bytes.fetch_max(live, Relaxed);
    }
    fn subtract(&self, bytes: usize) {
        self.freed_bytes.fetch_add(bytes as u64, Relaxed);
        self.live_bytes.fetch_sub(bytes, Relaxed);
    }
}

/// N fixed hash slots bound retained profiling metadata independently of traffic.
/// Samples colliding with occupied slots are discarded and counted. No allocation
/// headers or allocator options are changed.
pub struct ProfiledAllocator<A, const N: usize = 4096> {
    inner: A,
    counters: Counters,
    slots: [Slot; N],
    sampling: AtomicBool,
    sample_bytes: AtomicUsize,
}
impl<A, const N: usize> ProfiledAllocator<A, N> {
    pub const fn new(inner: A) -> Self {
        assert!(N > 0);
        Self {
            inner,
            counters: Counters::new(),
            slots: [const { Slot::EMPTY }; N],
            sampling: AtomicBool::new(false),
            sample_bytes: AtomicUsize::new(SAMPLE_BYTES),
        }
    }
    fn slot(&self, address: usize) -> &Slot {
        let key = (address as u64).wrapping_mul(0x9e3779b97f4a7c15);
        &self.slots[((key ^ (key >> 32)) as usize) % N]
    }
    fn take(&self, address: usize) -> Option<Sample> {
        let slot = self.slot(address);
        if slot.address.load(Relaxed) != address {
            return None;
        }
        let guard = slot.sample.lock().unwrap_or_else(|e| e.into_inner());
        if slot.address.load(Relaxed) != address {
            return None;
        }
        slot.address.store(0, Relaxed);
        Some(*guard)
    }
    fn insert(&self, sample: Sample) {
        let slot = self.slot(sample.address);
        let mut guard = slot.sample.lock().unwrap_or_else(|e| e.into_inner());
        if slot.address.load(Relaxed) != 0 {
            self.counters.collisions.fetch_add(1, Relaxed);
            return;
        }
        *guard = sample;
        slot.address.store(sample.address, Relaxed);
    }
    fn sample(&self, address: usize, bytes: usize) {
        if !self.sampling.load(Relaxed) {
            return;
        }
        let threshold = self.sample_bytes.load(Relaxed);
        let selected = RANDOM
            .try_with(|state| {
                let mut x = state.get();
                if x == 0 {
                    x = thread_id().wrapping_mul(0x9e3779b97f4a7c15).max(1);
                }
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                state.set(x);
                x as usize % threshold < bytes
            })
            .unwrap_or(false);
        if !selected {
            return;
        }
        let Some(_suppress) = Suppress::enter() else {
            return;
        };
        let mut sample = Sample {
            address,
            bytes,
            initial_bytes: bytes,
            thread: thread_id(),
            born: Some(Instant::now()),
            ..Sample::EMPTY
        };
        // Symbolization is deferred. Backtrace's own allocations cannot recurse
        // into sampling, and no sample-table lock is held while unwinding.
        backtrace::trace(|frame| {
            sample.frames[sample.frame_count] = frame.ip() as usize;
            sample.frame_count += 1;
            sample.frame_count < FRAMES
        });
        sample.id = self.counters.admitted.fetch_add(1, Relaxed) + 1;
        self.insert(sample);
    }
    fn snapshot(&self) -> Snapshot {
        let c = &self.counters;
        let mut samples = Vec::new();
        for slot in &self.slots {
            if slot.address.load(Relaxed) == 0 {
                continue;
            }
            let sample = {
                let guard = slot.sample.lock().unwrap_or_else(|e| e.into_inner());
                if slot.address.load(Relaxed) == 0 {
                    continue;
                }
                *guard
            };
            samples.push(Sample {
                age_ms: sample
                    .born
                    .map(|t| t.elapsed().as_millis() as u64)
                    .unwrap_or(0),
                ..sample
            });
        }
        Snapshot {
            live_bytes: c.live_bytes.load(Relaxed),
            live_objects: c.live_objects.load(Relaxed),
            peak_bytes: c.peak_bytes.load(Relaxed),
            allocated_bytes: c.allocated_bytes.load(Relaxed),
            freed_bytes: c.freed_bytes.load(Relaxed),
            allocations: c.allocations.load(Relaxed),
            frees: c.frees.load(Relaxed),
            reallocations: c.reallocations.load(Relaxed),
            failures: c.failures.load(Relaxed),
            admitted: c.admitted.load(Relaxed),
            collisions: c.collisions.load(Relaxed),
            sampled_frees: c.sampled_frees.load(Relaxed),
            cross_thread_frees: c.cross_thread_frees.load(Relaxed),
            unknown_thread_frees: c.unknown_thread_frees.load(Relaxed),
            sample_bytes: self.sample_bytes.load(Relaxed),
            sampling: self.sampling.load(Relaxed),
            samples,
        }
    }
}

#[derive(Serialize)]
struct Snapshot {
    live_bytes: usize,
    live_objects: usize,
    peak_bytes: usize,
    allocated_bytes: u64,
    freed_bytes: u64,
    allocations: u64,
    frees: u64,
    reallocations: u64,
    failures: u64,
    admitted: u64,
    collisions: u64,
    sampled_frees: u64,
    cross_thread_frees: u64,
    unknown_thread_frees: u64,
    sample_bytes: usize,
    sampling: bool,
    samples: Vec<Sample>,
}

// SAFETY: Delegates every operation using the caller's original layout. Metadata
// is removed before freeing/reallocating so another thread cannot reuse the
// address before old metadata is removed. Failed realloc preserves live counts.
unsafe impl<A: GlobalAlloc, const N: usize> GlobalAlloc for ProfiledAllocator<A, N> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { self.inner.alloc(layout) };
        self.allocated(ptr, layout.size());
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { self.inner.alloc_zeroed(layout) };
        self.allocated(ptr, layout.size());
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if let Some(sample) = self.take(ptr as usize) {
            self.counters.sampled_frees.fetch_add(1, Relaxed);
            let current = thread_id();
            if current == 0 {
                self.counters.unknown_thread_frees.fetch_add(1, Relaxed);
            } else if current != sample.thread {
                self.counters.cross_thread_frees.fetch_add(1, Relaxed);
            }
        }
        self.counters.subtract(layout.size());
        self.counters.live_objects.fetch_sub(1, Relaxed);
        self.counters.frees.fetch_add(1, Relaxed);
        unsafe { self.inner.dealloc(ptr, layout) };
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let previous = self.take(ptr as usize);
        let next = unsafe { self.inner.realloc(ptr, layout, new_size) };
        if next.is_null() {
            self.counters.failures.fetch_add(1, Relaxed);
            if let Some(sample) = previous {
                self.insert(sample);
            }
            return next;
        }
        self.counters.reallocations.fetch_add(1, Relaxed);
        if new_size >= layout.size() {
            self.counters.add(new_size - layout.size());
        } else {
            self.counters.subtract(layout.size() - new_size);
        }
        if let Some(mut sample) = previous {
            sample.address = next as usize;
            sample.bytes = new_size;
            sample.reallocations += 1;
            self.insert(sample);
        } else {
            self.sample(next as usize, new_size);
        }
        next
    }
}
impl<A, const N: usize> ProfiledAllocator<A, N> {
    fn allocated(&self, ptr: *mut u8, bytes: usize) {
        if ptr.is_null() {
            self.counters.failures.fetch_add(1, Relaxed);
            return;
        }
        self.counters.add(bytes);
        self.counters.live_objects.fetch_add(1, Relaxed);
        self.counters.allocations.fetch_add(1, Relaxed);
        self.sample(ptr as usize, bytes);
    }
}

#[cfg(test)]
mod tests;
