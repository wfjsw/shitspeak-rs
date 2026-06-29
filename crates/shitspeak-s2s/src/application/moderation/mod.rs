//! Moderation routing — fire-and-forget RPC to the owner node of a target
//! client.
//!
//! ## Flow
//!
//! 1. Originator (the node that holds the moderator's connection) runs
//!    its existing local ACL evaluation against the actor.
//! 2. If denied, the originator writes `PermissionDenied` to the moderator
//!    locally — no S2S traffic.
//! 3. If allowed, the originator wraps the intent in a [`ModerationEnvelope`]
//!    and ships it via [`overlay::send_unicast`](crate::overlay::OverlayNetwork::send_unicast)
//!    to the owner of the target client (extracted from the composite
//!    `ClientSessionIdentifier`). No reply is sent back on this channel —
//!    successful application propagates back via owner-scoped replication
//!    of `ClientGlobalState` (`tag = 1`).
//! 4. The owner runs a sanity check (target still exists; for channel
//!    moves, the `expected_from_channel` matches reality) and applies the
//!    mutation through its existing `GlobalStateWriteGuard` path.
//!
//! See [`crate::application`] for the full design rationale.

pub mod runtime;

pub use runtime::{
    MODERATION_CLASS, MODERATION_LEVEL, ModerationApplier, ModerationDelivery, ModerationInbound,
    ModerationService, ModerationTransport, OverlayModerationTransport,
};
