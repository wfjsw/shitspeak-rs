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
    deliver_with_origin_boot_epoch(services, tag, from, 0, level, class, body);
}

/// Deliver a local service frame with origin-incarnation metadata asserted by
/// the overlay envelope.
pub(crate) fn deliver_with_origin_boot_epoch(
    services: &ServiceRegistry,
    tag: u32,
    from: NodeIdentifier,
    origin_boot_epoch: u64,
    level: ServiceLevel,
    class: MessageClass,
    body: Bytes,
) {
    deliver_with_origin_boot_epoch_and_remote_playout(
        services,
        tag,
        from,
        origin_boot_epoch,
        level,
        class,
        body,
        None,
        false,
    );
}

/// Deliver a local service frame with compatibility distribution metadata.
///
/// `remote_playout_delay_ms` is retained for mixed-version API compatibility.
/// New overlay delivery paths leave it unset: voice is released by the S2S
/// reorderer without a server-side playout schedule.
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
    deliver_with_origin_boot_epoch_and_remote_playout(
        services,
        tag,
        from,
        0,
        level,
        class,
        body,
        remote_playout_delay_ms,
        is_distribution_repair,
    );
}

/// Deliver a local service frame with compatibility distribution metadata and
/// origin-incarnation metadata asserted by the overlay envelope.
#[allow(clippy::too_many_arguments)]
pub(crate) fn deliver_with_origin_boot_epoch_and_remote_playout(
    services: &ServiceRegistry,
    tag: u32,
    from: NodeIdentifier,
    origin_boot_epoch: u64,
    level: ServiceLevel,
    class: MessageClass,
    body: Bytes,
    remote_playout_delay_ms: Option<u64>,
    is_distribution_repair: bool,
) {
    if let Some(h) = services.get(tag) {
        h.handle(OverlayInboundMessage {
            from,
            origin_boot_epoch,
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
