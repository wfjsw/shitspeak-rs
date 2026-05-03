pub mod application;
pub mod overlay;
pub mod replications;
pub mod transport;

#[cfg(test)]
pub(crate) mod testing;

// Bootstrap stub for the s2s subsystem. Currently exposes no real overlay
// — the existing `Server` (src/server.rs) only relies on it as an opaque
// "is initialized" marker. Real wiring (`ConnectionManager` + overlay +
// `ReplicationManager` + `ApplicationLayer`) lands when the rest of the
// layer-by-layer rebuild catches up. The `replications` and `application`
// fields are plumbed so call sites that need to register repository
// handlers or dispatch moderation / voice traffic have somewhere to
// reach for them.
pub struct S2SManager {
    overlay: Option<overlay::OverlayNetwork>,
    replications: Option<std::sync::Arc<replications::ReplicationManager>>,
    application: Option<std::sync::Arc<application::ApplicationLayer>>,
    application_config: application::ApplicationConfig,
    transport_tuning: transport::TransportTuning,
    overlay_tuning: overlay::OverlayTuning,
    replication_config: replications::ReplicationConfig,
}

impl S2SManager {
    pub fn initialize(_config: &crate::config::Config) -> Self {
        Self {
            overlay: None,
            replications: None,
            application: None,
            application_config: _config.s2s.application.clone(),
            transport_tuning: _config.s2s.transport.clone(),
            overlay_tuning: _config.s2s.overlay.clone(),
            replication_config: _config.s2s.replications.clone().into(),
        }
    }

    /// Apply the operator-configured transport tunables on top of a
    /// caller-built [`transport::TransportConfig`] (which still owns
    /// PKI paths, listeners, and the rest).
    pub fn apply_transport_tuning(
        &self,
        cfg: transport::TransportConfig,
    ) -> transport::TransportConfig {
        self.transport_tuning.apply(cfg)
    }

    /// Apply the operator-configured overlay tunables on top of a
    /// caller-built [`overlay::OverlayConfig`].
    pub fn apply_overlay_tuning(
        &self,
        cfg: overlay::OverlayConfig,
    ) -> overlay::OverlayConfig {
        self.overlay_tuning.apply(cfg)
    }

    /// Resolved replication tunables, ready to hand to
    /// [`replications::ReplicationManager::with_config`].
    pub fn replication_config(&self) -> &replications::ReplicationConfig {
        &self.replication_config
    }

    /// Attach a fully-started overlay and spin up the `ReplicationManager`
    /// and `ApplicationLayer` on top of it. Idempotent on repeated calls
    /// with the same overlay.
    pub fn attach_overlay(&mut self, overlay: overlay::OverlayNetwork) {
        let repl = replications::ReplicationManager::with_config(
            overlay.clone(),
            self.replication_config.clone(),
        );
        let app = application::ApplicationLayer::new(
            overlay.clone(),
            self.application_config.clone(),
        );
        self.overlay = Some(overlay);
        self.replications = Some(repl);
        self.application = Some(app);
    }

    pub fn overlay(&self) -> Option<&overlay::OverlayNetwork> {
        self.overlay.as_ref()
    }

    pub fn replications(&self) -> Option<&std::sync::Arc<replications::ReplicationManager>> {
        self.replications.as_ref()
    }

    pub fn application(&self) -> Option<&std::sync::Arc<application::ApplicationLayer>> {
        self.application.as_ref()
    }

    pub fn log_startup_summary(&self) {}

    pub fn spawn_runtime_task(
        self: std::sync::Arc<Self>,
        _shutdown: tokio::sync::watch::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async {})
    }
}
