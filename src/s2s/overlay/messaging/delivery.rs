//! Local delivery: dispatch an inbound `OverlayData` whose `dsts`
//! includes self into the registered `ServiceInbound` for its tag.

use bytes::Bytes;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::warn;

use crate::s2s::transport::{MessageClass, ServiceLevel};
use crate::types::NodeIdentifier;

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
    if let Some(h) = services.get(tag) {
        h.handle(OverlayInboundMessage {
            from,
            level,
            class,
            body,
        });
    } else if !NO_SERVICE_REGISTERED_WARNED.load(Ordering::Relaxed) {
        warn!(tag, %from, "no service registered; dropping inbound overlay data");
        NO_SERVICE_REGISTERED_WARNED.store(true, Ordering::Relaxed);
    }
}
