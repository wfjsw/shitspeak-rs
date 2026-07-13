//! Local delivery: dispatch an inbound `OverlayData` whose `dsts`
//! includes self into the registered `ServiceInbound` for its tag.

use bytes::Bytes;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::warn;

use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::{MessageClass, ServiceLevel};

use super::{OverlayInboundMessage, ServiceRegistry};

static NO_SERVICE_REGISTERED_WARNED: AtomicBool = AtomicBool::new(false);

/// Resolve the handler for `tag` and invoke it. The handler runs
/// synchronously on the inbound dispatcher; the convention is that it
/// returns quickly (typically by enqueuing onto an internal mpsc).
pub fn deliver(
    services: &ServiceRegistry,
    tag: u32,
    from: NodeIdentifier,
    level: ServiceLevel,
    class: MessageClass,
    body: Bytes,
) {
    deliver_with_remote_playout(services, tag, from, level, class, body, None, false);
}

/// Deliver a local service frame with optional source-installed remote voice
/// playout state. The state belongs to the versioned tree control plane, not
/// the per-frame data envelope.
pub fn deliver_with_remote_playout(
    services: &ServiceRegistry,
    tag: u32,
    from: NodeIdentifier,
    level: ServiceLevel,
    class: MessageClass,
    body: Bytes,
    remote_playout_delay_ms: Option<u64>,
    is_distribution_repair: bool,
) {
    if let Some(h) = services.get(tag) {
        h.handle(OverlayInboundMessage {
            from,
            level,
            class,
            body,
            remote_playout_delay_ms,
            is_distribution_repair,
        });
    } else if !NO_SERVICE_REGISTERED_WARNED.load(Ordering::Relaxed) {
        warn!(tag, %from, "no service registered; dropping inbound overlay data");
        NO_SERVICE_REGISTERED_WARNED.store(true, Ordering::Relaxed);
    }
}
