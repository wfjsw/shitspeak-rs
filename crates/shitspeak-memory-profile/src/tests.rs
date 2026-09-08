use super::*;
use std::alloc::System;
use std::ptr;

#[test]
fn live_bytes_follow_zeroed_alloc_growth_shrink_and_free() {
    let allocator = ProfiledAllocator::<_, 8>::new(System);
    allocator.sampling.store(true, Relaxed);
    allocator.sample_bytes.store(1, Relaxed);
    unsafe {
        let small = Layout::from_size_align(128, 64).unwrap();
        let ptr = allocator.alloc_zeroed(small);
        assert!(!ptr.is_null());
        assert_eq!(ptr as usize % 64, 0);
        assert!(std::slice::from_raw_parts(ptr, 128).iter().all(|v| *v == 0));
        let first = allocator.snapshot();
        assert_eq!(first.live_bytes, 128);
        assert_eq!(first.samples.len(), 1);
        assert!(first.samples[0].frame_count > 0);
        let id = first.samples[0].id;
        let ptr = allocator.realloc(ptr, small, 8192);
        assert!(!ptr.is_null());
        assert_eq!(allocator.snapshot().live_bytes, 8192);
        let ptr = allocator.realloc(ptr, Layout::from_size_align(8192, 64).unwrap(), 64);
        assert!(!ptr.is_null());
        let shrunk = allocator.snapshot();
        assert_eq!(shrunk.live_bytes, 64);
        assert_eq!(shrunk.samples[0].id, id);
        assert_eq!(shrunk.samples[0].reallocations, 2);
        allocator.dealloc(ptr, Layout::from_size_align(64, 64).unwrap());
        let end = allocator.snapshot();
        assert_eq!(end.live_bytes, 0);
        assert_eq!(end.live_objects, 0);
        assert_eq!(end.allocated_bytes, end.freed_bytes);
        assert!(end.samples.is_empty());
    }
}

struct FailResize;
unsafe impl GlobalAlloc for FailResize {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, _: *mut u8, _: Layout, _: usize) -> *mut u8 {
        ptr::null_mut()
    }
}

struct FailAlloc;
unsafe impl GlobalAlloc for FailAlloc {
    unsafe fn alloc(&self, _: Layout) -> *mut u8 {
        ptr::null_mut()
    }
    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {
        unreachable!()
    }
}
#[test]
fn failed_allocation_is_not_counted_as_live() {
    let allocator = ProfiledAllocator::<_, 8>::new(FailAlloc);
    assert!(unsafe { allocator.alloc(Layout::new::<u64>()) }.is_null());
    let snapshot = allocator.snapshot();
    assert_eq!(snapshot.live_bytes, 0);
    assert_eq!(snapshot.live_objects, 0);
    assert_eq!(snapshot.failures, 1);
}

struct MoveResize;
unsafe impl GlobalAlloc for MoveResize {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        unsafe {
            let next = System.alloc(Layout::from_size_align(size, layout.align()).unwrap());
            if !next.is_null() {
                ptr::copy_nonoverlapping(ptr, next, layout.size().min(size));
                System.dealloc(ptr, layout);
            }
            next
        }
    }
}
#[test]
fn moving_realloc_rekeys_sample_without_retaining_old_pointer() {
    let allocator = ProfiledAllocator::<_, 8>::new(MoveResize);
    allocator.sampling.store(true, Relaxed);
    allocator.sample_bytes.store(1, Relaxed);
    unsafe {
        let layout = Layout::new::<u64>();
        let original = allocator.alloc(layout);
        original.cast::<u64>().write(42);
        let next = allocator.realloc(original, layout, 1024);
        assert_ne!(original, next);
        assert_eq!(next.cast::<u64>().read(), 42);
        let snapshot = allocator.snapshot();
        assert_eq!(snapshot.samples.len(), 1);
        assert_eq!(snapshot.samples[0].address, next as usize);
        allocator.dealloc(next, Layout::from_size_align(1024, layout.align()).unwrap());
        assert_eq!(allocator.snapshot().live_bytes, 0);
    }
}
#[test]
fn failed_realloc_preserves_original_live_allocation() {
    let allocator = ProfiledAllocator::<_, 8>::new(FailResize);
    allocator.sampling.store(true, Relaxed);
    allocator.sample_bytes.store(1, Relaxed);
    unsafe {
        let layout = Layout::from_size_align(128, 8).unwrap();
        let ptr = allocator.alloc(layout);
        assert!(allocator.realloc(ptr, layout, 256).is_null());
        let state = allocator.snapshot();
        assert_eq!(state.live_bytes, 128);
        assert_eq!(state.live_objects, 1);
        assert_eq!(state.failures, 1);
        assert_eq!(state.samples.len(), 1);
        allocator.dealloc(ptr, layout);
        assert_eq!(allocator.snapshot().live_bytes, 0);
    }
}

#[test]
fn cross_thread_free_releases_sample_and_counter() {
    let allocator = ProfiledAllocator::<_, 8>::new(mimalloc::MiMalloc);
    allocator.sampling.store(true, Relaxed);
    allocator.sample_bytes.store(1, Relaxed);
    let layout = Layout::from_size_align(4096, 8).unwrap();
    let address = unsafe { allocator.alloc(layout) } as usize;
    assert_ne!(address, 0);
    std::thread::scope(|scope| {
        let allocator = &allocator;
        scope
            .spawn(move || unsafe { allocator.dealloc(address as *mut u8, layout) })
            .join()
            .unwrap();
    });
    let state = allocator.snapshot();
    assert_eq!(state.cross_thread_frees, 1);
    assert_eq!(state.live_bytes, 0);
    assert!(state.samples.is_empty());
}

#[test]
fn collision_does_not_overwrite_live_sample() {
    let allocator = ProfiledAllocator::<_, 1>::new(System);
    allocator.sampling.store(true, Relaxed);
    allocator.sample_bytes.store(1, Relaxed);
    unsafe {
        let layout = Layout::from_size_align(256, 8).unwrap();
        let first = allocator.alloc(layout);
        let second = allocator.alloc(layout);
        assert!(!first.is_null() && !second.is_null());
        let state = allocator.snapshot();
        assert_eq!(state.live_bytes, 512);
        assert_eq!(state.samples.len(), 1);
        assert_eq!(state.collisions, 1);
        allocator.dealloc(second, layout);
        assert_eq!(allocator.snapshot().samples[0].address, first as usize);
        allocator.dealloc(first, layout);
        assert!(allocator.snapshot().samples.is_empty());
    }
}

#[test]
fn live_objects_distinguish_retention_from_churn() {
    let allocator = ProfiledAllocator::<_, 8>::new(System);
    let layout = Layout::from_size_align(1024, 8).unwrap();
    unsafe {
        let retained = allocator.alloc(layout);
        for _ in 0..1000 {
            let transient = allocator.alloc(layout);
            allocator.dealloc(transient, layout);
        }
        let state = allocator.snapshot();
        assert_eq!(state.live_bytes, 1024);
        assert_eq!(state.live_objects, 1);
        assert_eq!(state.allocated_bytes, 1001 * 1024);
        allocator.dealloc(retained, layout);
        assert_eq!(allocator.snapshot().live_bytes, 0);
    }
}

#[test]
fn concurrent_alloc_free_and_snapshot_do_not_deadlock() {
    let allocator = ProfiledAllocator::<_, 64>::new(mimalloc::MiMalloc);
    allocator.sampling.store(true, Relaxed);
    allocator.sample_bytes.store(4096, Relaxed);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let allocator = &allocator;
            scope.spawn(move || {
                for _ in 0..1000 {
                    unsafe {
                        let layout = Layout::from_size_align(512, 8).unwrap();
                        let ptr = allocator.alloc(layout);
                        assert!(!ptr.is_null());
                        allocator.dealloc(ptr, layout);
                    }
                }
            });
        }
        for _ in 0..100 {
            let _ = allocator.snapshot();
        }
    });
    let state = allocator.snapshot();
    assert_eq!(state.live_bytes, 0);
    assert_eq!(state.live_objects, 0);
    assert!(state.samples.is_empty());
}
