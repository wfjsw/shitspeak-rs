pub mod overlay;
pub mod replications;
pub mod transport;

#[cfg(test)]
pub(crate) mod testing;

// Bootstrap stub for the s2s subsystem. Currently exposes no real overlay
// — the existing `Server` (src/server.rs) only relies on it as an opaque
// "is initialized" marker. Real wiring (`ConnectionManager` + overlay +
// `ReplicationManager`) lands when the rest of the layer-by-layer rebuild
// catches up. The `replications` field is plumbed so call sites that need
// to register repository handlers have somewhere to reach for it.
pub struct S2SManager {
    overlay: Option<overlay::OverlayNetwork>,
    replications: Option<std::sync::Arc<replications::ReplicationManager>>,
}

impl S2SManager {
    pub fn initialize(_config: &crate::config::Config) -> Self {
        Self {
            overlay: None,
            replications: None,
        }
    }

    /// Attach a fully-started overlay and spin up the `ReplicationManager`
    /// on top of it. Idempotent on repeated calls with the same overlay.
    pub fn attach_overlay(&mut self, overlay: overlay::OverlayNetwork) {
        let repl = replications::ReplicationManager::new(overlay.clone());
        self.overlay = Some(overlay);
        self.replications = Some(repl);
    }

    pub fn overlay(&self) -> Option<&overlay::OverlayNetwork> {
        self.overlay.as_ref()
    }

    pub fn replications(&self) -> Option<&std::sync::Arc<replications::ReplicationManager>> {
        self.replications.as_ref()
    }

    pub fn log_startup_summary(&self) {}

    pub fn spawn_runtime_task(
        self: std::sync::Arc<Self>,
        _shutdown: tokio::sync::watch::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async {})
    }
}
