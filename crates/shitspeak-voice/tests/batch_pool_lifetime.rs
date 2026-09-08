use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::RefCell;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use shitspeak_voice::udp_batch::DatagramBatch;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static WATCHED: AtomicUsize = AtomicUsize::new(0);
static FREED: AtomicBool = AtomicBool::new(false);

struct TrackingAllocator;

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr as usize == WATCHED.load(Ordering::Relaxed) {
            FREED.store(true, Ordering::Relaxed);
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

fn watch_payload(batch: &mut DatagramBatch) {
    batch
        .try_push_zeroed(SocketAddr::from(([127, 0, 0, 1], 64738)), 16, |buffer| {
            buffer.fill(42);
            FREED.store(false, Ordering::Relaxed);
            WATCHED.store(buffer.as_ptr() as usize, Ordering::Relaxed);
            Ok::<_, std::convert::Infallible>(())
        })
        .unwrap();
}

#[test]
fn pooled_storage_stays_allocated_until_thread_exit() {
    let _serial = TEST_LOCK.lock().unwrap();
    let worker = std::thread::spawn(|| {
        {
            let mut batch = DatagramBatch::new();
            watch_payload(&mut batch);
        }
        assert!(
            !FREED.load(Ordering::Relaxed),
            "the pool must own live storage after the batch is dropped"
        );

        {
            let mut batch = DatagramBatch::new();
            assert!(batch.is_empty());
            batch
                .try_push_zeroed(SocketAddr::from(([127, 0, 0, 1], 64738)), 16, |buffer| {
                    assert_eq!(buffer.as_ptr() as usize, WATCHED.load(Ordering::Relaxed));
                    assert_eq!(buffer, &[0; 16]);
                    buffer.fill(17);
                    Ok::<_, std::convert::Infallible>(())
                })
                .unwrap();
        }
        assert!(!FREED.load(Ordering::Relaxed));
    });
    let result = worker.join();
    WATCHED.store(0, Ordering::Relaxed);
    result.unwrap();
    assert!(
        FREED.load(Ordering::Relaxed),
        "thread exit must release pooled storage"
    );
}

#[test]
fn batch_can_be_dropped_after_its_thread_pool_is_destroyed() {
    let _serial = TEST_LOCK.lock().unwrap();
    let worker = std::thread::spawn(|| {
        thread_local! {
            static LATE_BATCH: RefCell<Option<DatagramBatch>> = const { RefCell::new(None) };
        }

        // Initialize this slot first so its destructor runs after the pool's.
        LATE_BATCH.with(|slot| {
            let mut batch = DatagramBatch::new();
            watch_payload(&mut batch);
            *slot.borrow_mut() = Some(batch);
        });
    });
    let result = worker.join();
    WATCHED.store(0, Ordering::Relaxed);
    result.unwrap();
    assert!(FREED.load(Ordering::Relaxed));
}
