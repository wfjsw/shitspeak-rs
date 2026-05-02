pub mod overlay;
pub mod transport;

// Temporary placeholder so the legacy `Server` (src/server.rs) still compiles
// while the s2s subsystem is being rebuilt layer-by-layer on top of the new
// `transport` module. Will be replaced with a real manager wired to
// ConnectionManager + overlay + replication in subsequent work.
pub struct S2SManager;

impl S2SManager {
    pub fn initialize(_config: &crate::config::Config) -> Self {
        Self
    }
    pub fn log_startup_summary(&self) {}
    pub fn spawn_runtime_task(
        self: std::sync::Arc<Self>,
        _shutdown: tokio::sync::watch::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async {})
    }
}
