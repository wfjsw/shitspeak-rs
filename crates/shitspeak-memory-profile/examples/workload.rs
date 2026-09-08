//! Local diagnostic verification and allocator microbenchmark; no networking.
use shitspeak_memory_profile::{MiMalloc, ProfiledAllocator};
use std::alloc::{GlobalAlloc, Layout};
use std::hint::black_box;
use std::time::{Duration, Instant};

#[global_allocator]
static ALLOCATOR: ProfiledAllocator<MiMalloc> = ProfiledAllocator::new(MiMalloc);

#[inline(never)]
fn retain_two_megabytes() -> Vec<u8> {
    vec![42; 2 * 1024 * 1024]
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _observation = shitspeak_memory_profile::start_from_env(&ALLOCATOR)?;
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "retention".into());
    if mode == "retention" {
        std::thread::sleep(Duration::from_secs(2));
        {
            let mut retained = Vec::new();
            for _ in 0..4 {
                retained.push(retain_two_megabytes());
                std::thread::sleep(Duration::from_secs(1));
            }
            black_box(&retained);
            std::thread::sleep(Duration::from_secs(2));
        }
        std::thread::sleep(Duration::from_secs(3));
    } else {
        let allocator: &dyn GlobalAlloc = if mode == "raw" { &MiMalloc } else { &ALLOCATOR };
        // Let observer initialization finish outside the timed interval.
        std::thread::sleep(Duration::from_millis(250));
        let start = Instant::now();
        for i in 0..1_000_000 {
            let layout = Layout::from_size_align([128, 1008, 4096, 65536][i % 4], 16)?;
            unsafe {
                let pointer = allocator.alloc(layout);
                assert!(!pointer.is_null());
                pointer.write_volatile(7);
                black_box(pointer);
                allocator.dealloc(pointer, layout);
            }
        }
        println!(
            "{mode}: {} ms for 1000000 alloc/free pairs",
            start.elapsed().as_millis()
        );
    }
    Ok(())
}
