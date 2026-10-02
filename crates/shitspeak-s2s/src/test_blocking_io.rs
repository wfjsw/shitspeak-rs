//! Test-only hooks for proving that blocking file work stays off the async
//! runtime.
//!
//! A test registers a directory as slow; every hooked blocking file operation
//! under that directory then sleeps for the registered delay. Running the
//! operation on a `current_thread` runtime next to a ticking task shows
//! whether the sleep (standing in for a stalled fsync) blocks the runtime.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::Mutex;

static SLOW_DIRECTORIES: Mutex<Vec<(PathBuf, Duration)>> = Mutex::new(Vec::new());

/// Makes every hooked blocking operation under `directory` sleep for
/// `delay` until the returned guard is dropped.
pub(crate) fn slow_down(directory: &Path, delay: Duration) -> SlowDirectory {
    SLOW_DIRECTORIES
        .lock()
        .push((directory.to_path_buf(), delay));
    SlowDirectory {
        directory: directory.to_path_buf(),
    }
}

/// Sleeps on the calling thread when `path` lies under a slow directory.
pub(crate) fn pause(path: &Path) {
    let delay = SLOW_DIRECTORIES
        .lock()
        .iter()
        .find(|(directory, _)| path.starts_with(directory))
        .map(|(_, delay)| *delay);
    if let Some(delay) = delay {
        std::thread::sleep(delay);
    }
}

pub(crate) struct SlowDirectory {
    directory: PathBuf,
}

impl Drop for SlowDirectory {
    fn drop(&mut self) {
        SLOW_DIRECTORIES
            .lock()
            .retain(|(directory, _)| *directory != self.directory);
    }
}

/// Runs `operation` next to a task that ticks every few milliseconds and
/// returns the operation's output with the number of ticks observed. On a
/// `current_thread` runtime the ticker only advances while the operation
/// yields, so a blocking call on the runtime thread shows as zero ticks.
pub(crate) async fn ticks_during<F: Future>(operation: F) -> (F::Output, usize) {
    let ticks = Arc::new(AtomicUsize::new(0));
    let ticker = {
        let ticks = Arc::clone(&ticks);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(5)).await;
                ticks.fetch_add(1, Ordering::Relaxed);
            }
        })
    };
    tokio::time::sleep(Duration::from_millis(1)).await;
    let before = ticks.load(Ordering::Relaxed);
    let output = operation.await;
    let ticked = ticks.load(Ordering::Relaxed) - before;
    ticker.abort();
    (output, ticked)
}
