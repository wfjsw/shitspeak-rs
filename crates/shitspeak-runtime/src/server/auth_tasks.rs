use std::future::Future;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use tokio::runtime::{Handle, Runtime};
use tracing::Instrument as _;

use shitspeak_auth::{
    AuthenticateAuxiliaryData, AuthenticateResult, AuthenticationRejection, Authenticator,
    ExternalAuthClaims, RegisteredUser, ReloadableAuthenticator,
};

/// Runs bulk/background work away from the latency-sensitive server runtime.
///
/// Each runtime is deliberately bounded and its worker threads are given
/// a lower OS scheduling priority where the platform supports it. This keeps
/// CPU-bound authentication and bulk ACL projection from occupying the workers
/// that service TCP/UDP pings and voice.
#[derive(Clone)]
pub(super) struct BackgroundTaskExecutor {
    inner: Arc<BackgroundTaskExecutorInner>,
}

struct BackgroundTaskExecutorInner {
    handle: Handle,
    runtime: Mutex<Option<Runtime>>,
    admission: Option<Arc<tokio::sync::Semaphore>>,
}

impl BackgroundTaskExecutor {
    pub(super) fn new(
        workload: &'static str,
        configured_concurrency: usize,
    ) -> std::io::Result<Self> {
        let worker_threads = background_worker_threads(configured_concurrency);
        Self::new_with_worker_threads(workload, configured_concurrency, worker_threads)
    }

    pub(super) fn new_with_worker_threads(
        workload: &'static str,
        configured_concurrency: usize,
        worker_threads: usize,
    ) -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads.max(1))
            .thread_name(format!("{workload}-runtime-worker"))
            .on_thread_start(lower_current_thread_priority)
            .enable_all()
            .build()?;
        let handle = runtime.handle().clone();
        tracing::info!(
            worker_threads = worker_threads.max(1),
            configured_concurrency,
            workload,
            "started isolated low-priority background runtime"
        );
        Ok(Self {
            inner: Arc::new(BackgroundTaskExecutorInner {
                handle,
                runtime: Mutex::new(Some(runtime)),
                admission: (configured_concurrency != 0)
                    .then(|| Arc::new(tokio::sync::Semaphore::new(configured_concurrency))),
            }),
        })
    }

    pub(super) async fn run<F, T>(&self, future: F) -> Result<T, tokio::task::JoinError>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let _admission = match &self.inner.admission {
            Some(admission) => Some(
                Arc::clone(admission)
                    .acquire_owned()
                    .await
                    .expect("background task admission semaphore should remain open"),
            ),
            None => None,
        };
        let span = tracing::Span::current();
        let mut task = AbortOnDrop::new(self.inner.handle.spawn(future.instrument(span)));
        let result = task
            .handle
            .as_mut()
            .expect("background task handle must exist")
            .await;
        task.handle.take();
        result
    }
}

struct AbortOnDrop<T> {
    handle: Option<tokio::task::JoinHandle<T>>,
}

impl<T> AbortOnDrop<T> {
    fn new(handle: tokio::task::JoinHandle<T>) -> Self {
        Self {
            handle: Some(handle),
        }
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

impl Drop for BackgroundTaskExecutorInner {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.get_mut().take() {
            // Server instances are commonly dropped from async contexts in
            // tests and during shutdown. Avoid Tokio's blocking Runtime drop.
            runtime.shutdown_background();
        }
    }
}

fn background_worker_threads(configured_concurrency: usize) -> usize {
    let active_cpus = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1);
    let reserved_for_realtime = active_cpus.saturating_sub(1).max(1);

    // An unlimited producer still needs a bounded CPU executor. Async I/O
    // remains concurrent; only simultaneous CPU polling is restricted.
    configured_concurrency.max(1).min(reserved_for_realtime)
}

#[cfg(target_os = "linux")]
fn lower_current_thread_priority() {
    // Linux schedules each thread (task ID) independently for nice values.
    let thread_id = unsafe { libc::syscall(libc::SYS_gettid) } as libc::id_t;
    let result = unsafe { libc::setpriority(libc::PRIO_PROCESS, thread_id, 10) };
    if result != 0 {
        tracing::warn!(
            error = %std::io::Error::last_os_error(),
            "could not lower background worker priority"
        );
    }
}

#[cfg(windows)]
fn lower_current_thread_priority() {
    use windows_sys::Win32::System::Threading::{
        GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_LOWEST,
    };

    let result = unsafe { SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST) };
    if result == 0 {
        tracing::warn!(
            error = %std::io::Error::last_os_error(),
            "could not lower background worker priority"
        );
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn lower_current_thread_priority() {}

/// Authenticator facade used by non-login call sites (web auth, blob updates,
/// user queries, and expiry reauth) so backend CPU cannot escape onto the main
/// runtime.
pub(super) struct ScheduledAuthenticator {
    inner: Arc<ReloadableAuthenticator>,
    executor: BackgroundTaskExecutor,
}

impl ScheduledAuthenticator {
    pub(super) fn new(
        inner: Arc<ReloadableAuthenticator>,
        executor: BackgroundTaskExecutor,
    ) -> Self {
        Self { inner, executor }
    }

    async fn run_or<T: Send + 'static>(
        &self,
        future: impl Future<Output = T> + Send + 'static,
        fallback: impl FnOnce() -> T,
    ) -> T {
        match self.executor.run(future).await {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(%error, "isolated auth task failed");
                fallback()
            }
        }
    }
}

#[async_trait]
impl Authenticator for ScheduledAuthenticator {
    async fn authenticate(
        &self,
        username: &str,
        password: Option<&str>,
        auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Result<AuthenticateResult, AuthenticationRejection> {
        let inner = Arc::clone(&self.inner);
        let username = username.to_owned();
        let password = password.map(ToOwned::to_owned);
        let auxiliary_data = auxiliary_data.clone();
        self.run_or(
            async move {
                inner
                    .authenticate(&username, password.as_deref(), &auxiliary_data)
                    .await
            },
            || Err(AuthenticationRejection::RetryLater),
        )
        .await
    }

    async fn authenticate_external(
        &self,
        claims: &ExternalAuthClaims,
        auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Result<AuthenticateResult, AuthenticationRejection> {
        let inner = Arc::clone(&self.inner);
        let claims = claims.clone();
        let auxiliary_data = auxiliary_data.clone();
        self.run_or(
            async move { inner.authenticate_external(&claims, &auxiliary_data).await },
            || Err(AuthenticationRejection::RetryLater),
        )
        .await
    }

    async fn get_user_texture(&self, user_id: u32) -> Option<Bytes> {
        let inner = Arc::clone(&self.inner);
        self.run_or(async move { inner.get_user_texture(user_id).await }, || {
            None
        })
        .await
    }

    async fn get_user_comment(&self, user_id: u32) -> Option<String> {
        let inner = Arc::clone(&self.inner);
        self.run_or(async move { inner.get_user_comment(user_id).await }, || {
            None
        })
        .await
    }

    async fn set_user_texture(&self, user_id: u32, data: Bytes) -> Result<(), ()> {
        let inner = Arc::clone(&self.inner);
        self.run_or(
            async move { inner.set_user_texture(user_id, data).await },
            || Err(()),
        )
        .await
    }

    async fn set_user_comment(&self, user_id: u32, comment: String) -> Result<(), ()> {
        let inner = Arc::clone(&self.inner);
        self.run_or(
            async move { inner.set_user_comment(user_id, comment).await },
            || Err(()),
        )
        .await
    }

    async fn get_registered_users(&self, name_filter: &str) -> Vec<RegisteredUser> {
        let inner = Arc::clone(&self.inner);
        let name_filter = name_filter.to_owned();
        self.run_or(
            async move { inner.get_registered_users(&name_filter).await },
            Vec::new,
        )
        .await
    }

    async fn unregister_user(&self, user_id: u32) -> Result<(), ()> {
        let inner = Arc::clone(&self.inner);
        self.run_or(async move { inner.unregister_user(user_id).await }, || {
            Err(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use super::BackgroundTaskExecutor;

    #[tokio::test(flavor = "current_thread")]
    async fn cpu_bound_auth_does_not_block_main_runtime_timer() {
        let executor = BackgroundTaskExecutor::new("auth", 1).expect("auth executor");
        let release = Arc::new(AtomicBool::new(false));
        let task_release = Arc::clone(&release);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();

        let task = tokio::spawn(async move {
            executor
                .run(async move {
                    started_tx.send(()).expect("signal auth start");
                    while !task_release.load(Ordering::Acquire) {
                        std::hint::spin_loop();
                    }
                })
                .await
                .expect("auth task")
        });
        tokio::time::timeout(Duration::from_secs(1), started_rx)
            .await
            .expect("auth task should start")
            .expect("auth start signal sender should not be dropped");

        tokio::time::timeout(
            Duration::from_millis(250),
            tokio::time::sleep(Duration::from_millis(10)),
        )
        .await
        .expect("main runtime timer should remain responsive");

        release.store(true, Ordering::Release);
        task.await.expect("auth dispatcher task");
    }

    #[test]
    fn executor_reserves_a_cpu_for_realtime_work() {
        let active_cpus = std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(1);
        assert_eq!(
            super::background_worker_threads(usize::MAX),
            active_cpus.saturating_sub(1).max(1)
        );
        assert_eq!(super::background_worker_threads(0), 1);
    }
}
