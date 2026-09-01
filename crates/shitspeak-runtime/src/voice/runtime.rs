use std::future::Future;
use std::sync::{Arc, OnceLock};

use parking_lot::Mutex;
use tokio::runtime::{Handle, Runtime};

#[derive(Clone)]
pub(crate) struct VoiceTaskExecutor {
    inner: Arc<VoiceTaskExecutorInner>,
}

struct VoiceTaskExecutorInner {
    handle: Handle,
    runtime: Mutex<Option<Runtime>>,
}

impl VoiceTaskExecutor {
    fn new(worker_threads: usize) -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads.max(1))
            .thread_name("voice-runtime-worker")
            .enable_all()
            .build()?;
        let handle = runtime.handle().clone();
        Ok(Self {
            inner: Arc::new(VoiceTaskExecutorInner {
                handle,
                runtime: Mutex::new(Some(runtime)),
            }),
        })
    }

    pub(crate) fn shared(worker_threads: usize) -> std::io::Result<Self> {
        static EXECUTOR: OnceLock<Result<VoiceTaskExecutor, String>> = OnceLock::new();
        match EXECUTOR.get_or_init(|| Self::new(worker_threads).map_err(|error| error.to_string()))
        {
            Ok(executor) => Ok(executor.clone()),
            Err(error) => Err(std::io::Error::other(error.clone())),
        }
    }

    pub(crate) fn handle(&self) -> &Handle {
        &self.inner.handle
    }

    pub(crate) fn spawn<F>(&self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.inner.handle.spawn(future)
    }
}

impl Drop for VoiceTaskExecutorInner {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.get_mut().take() {
            runtime.shutdown_background();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::VoiceTaskExecutor;

    #[test]
    fn spawned_tasks_run_on_voice_workers() {
        let executor = VoiceTaskExecutor::new(2).expect("voice runtime");
        let (tx, rx) = std::sync::mpsc::channel();
        executor.spawn(async move {
            let name = std::thread::current().name().unwrap_or_default().to_owned();
            tx.send(name).expect("test receiver remains open");
        });

        let thread_name = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("voice task completes");
        assert!(thread_name.starts_with("voice-runtime-worker"));
    }
}
