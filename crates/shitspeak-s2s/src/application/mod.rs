//! Application-layer (L3) services on top of the L2 [overlay].
//!
//! Two services live here, each registered against a distinct overlay
//! `service_tag`:
//!
//! * **Moderation** ([`MODERATION_SERVICE_TAG`] = 2) — fire-and-forget
//!   RPC that ships a moderator's intent from the originating node to
//!   the owner of the target client. The owner applies the mutation
//!   through its existing `GlobalStateWriteGuard` path; the resulting
//!   delta propagates back to every node via owner-scoped replication
//!   (handled at L3 by [`crate::replications`]).
//!
//! * **Voice** ([`VOICE_SERVICE_TAG`] = 3) — broadcast (default) or
//!   targeted (opt-in) cross-node fan-out of voice frames. Receivers
//!   never decode the audio payload; they reorder by `(sender, epoch)`
//!   and hand the bytes straight to local per-client encryption +
//!   send. Reorder caps and deadlines are operator-tunable.
//!
//! ## Lifecycle
//!
//! [`ApplicationLayer::new`] registers both `ServiceInbound` handlers
//! against the overlay's `ServiceRegistry` and spawns the per-service
//! dispatch tasks. [`ApplicationLayer::shutdown`] cancels every task
//! via the shared cancellation token and unregisters both tags.
//!
//! [overlay]: crate::overlay

pub mod config;
pub mod error;
pub mod moderation;
pub mod plugin_data;
pub mod proto;
pub mod text_message;
pub mod user_stats;
pub mod voice;

use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::overlay::OverlayNetwork;

pub use config::{ApplicationConfig, DeliveryStrategy, VoiceConfig};
pub use error::ApplicationError;
pub use moderation::ModerationService;
pub use plugin_data::PluginDataService;
pub use proto::{
    MODERATION_SERVICE_TAG, PLUGIN_DATA_SERVICE_TAG, TEXT_MESSAGE_SERVICE_TAG,
    USER_STATS_SERVICE_TAG, VOICE_REPAIR_SERVICE_TAG, VOICE_SERVICE_TAG,
};
pub use text_message::TextMessageService;
pub use user_stats::UserStatsService;
pub use voice::VoiceService;

/// Public entry-point for the L3 application layer. Cheap to clone —
/// internally an `Arc`.
#[derive(Clone)]
pub struct ApplicationLayer {
    inner: Arc<ApplicationInner>,
}

struct ApplicationInner {
    overlay: OverlayNetwork,
    moderation: Arc<ModerationService>,
    plugin_data: Arc<PluginDataService>,
    text_message: Arc<TextMessageService>,
    user_stats: Arc<UserStatsService>,
    voice: Arc<VoiceService>,
    shutdown: CancellationToken,
}

impl ApplicationLayer {
    /// Build the application layer on top of an already-started overlay.
    /// Spawns per-service dispatch tasks and registers the L3 handlers.
    pub fn new(overlay: OverlayNetwork, cfg: ApplicationConfig) -> Arc<Self> {
        let shutdown = CancellationToken::new();
        let moderation = ModerationService::new(overlay.clone(), shutdown.child_token());
        let plugin_data = PluginDataService::new(overlay.clone(), shutdown.child_token());
        let text_message = TextMessageService::new(overlay.clone(), shutdown.child_token());
        let user_stats = UserStatsService::new(overlay.clone(), shutdown.child_token());
        let voice = VoiceService::new(overlay.clone(), cfg.voice, shutdown.child_token());

        overlay.register_service(MODERATION_SERVICE_TAG, moderation.inbound_handler());
        overlay.register_service(PLUGIN_DATA_SERVICE_TAG, plugin_data.inbound_handler());
        overlay.register_service(TEXT_MESSAGE_SERVICE_TAG, text_message.inbound_handler());
        overlay.register_service(USER_STATS_SERVICE_TAG, user_stats.inbound_handler());
        overlay.register_service(VOICE_SERVICE_TAG, voice.inbound_handler());
        overlay.register_service(VOICE_REPAIR_SERVICE_TAG, voice.repair_inbound_handler());

        let inner = Arc::new(ApplicationInner {
            overlay,
            moderation,
            plugin_data,
            text_message,
            user_stats,
            voice,
            shutdown,
        });
        Arc::new(Self { inner })
    }

    pub fn moderation(&self) -> &Arc<ModerationService> {
        &self.inner.moderation
    }

    pub fn plugin_data(&self) -> &Arc<PluginDataService> {
        &self.inner.plugin_data
    }

    pub fn text_message(&self) -> &Arc<TextMessageService> {
        &self.inner.text_message
    }

    pub fn user_stats(&self) -> &Arc<UserStatsService> {
        &self.inner.user_stats
    }

    pub fn voice(&self) -> &Arc<VoiceService> {
        &self.inner.voice
    }

    /// Cancel all background tasks and unregister the L3 handlers.
    pub async fn shutdown(&self) {
        self.inner.shutdown.cancel();
        self.inner
            .overlay
            .unregister_service(MODERATION_SERVICE_TAG);
        self.inner
            .overlay
            .unregister_service(PLUGIN_DATA_SERVICE_TAG);
        self.inner
            .overlay
            .unregister_service(TEXT_MESSAGE_SERVICE_TAG);
        self.inner
            .overlay
            .unregister_service(USER_STATS_SERVICE_TAG);
        self.inner.overlay.unregister_service(VOICE_SERVICE_TAG);
        self.inner
            .overlay
            .unregister_service(VOICE_REPAIR_SERVICE_TAG);
    }
}
