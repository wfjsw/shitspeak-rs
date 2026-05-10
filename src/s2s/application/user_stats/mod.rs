//! UserStats request/reply RPC, routed to the *owner* of the target client.
//!
//! ## Why an owner-routed RPC
//!
//! Mumble's `UserStats` query asks for live state (TCP/UDP packet counters,
//! ping windows, idle/online seconds, version banner) of an arbitrary
//! session. In a multi-node cluster, the only place those counters
//! actually live is the node that holds the target's TCP connection —
//! replication only carries `ClientGlobalState`, not per-connection
//! counters. So when a moderator on node A asks for stats of a target
//! owned by node B, A must round-trip to B.
//!
//! ## Wire shape
//!
//! Two messages over the same `USER_STATS_SERVICE_TAG = 4`:
//!
//! * `UserStatsRequest{ request_id, actor_session, target_session,
//!   stats_only }` — A → B
//! * `UserStatsReply{ request_id, found, payload }` — B → A
//!
//! `payload` is an *already-encoded* `MumbleProto.UserStats` body that A
//! forwards to the moderator's TLS stream as-is, so B is the only side
//! that touches the Mumble proto.
//!
//! ## Send side
//!
//! [`UserStatsService::dispatch_request`] allocates a fresh
//! `request_id`, parks a oneshot in the pending-request map, ships the
//! envelope via overlay unicast, and awaits the reply with a configurable
//! timeout. On timeout / overlay error the pending entry is reaped.
//!
//! ## Apply side
//!
//! Inbound envelopes pass through the central dispatch task and split
//! by kind:
//!   * `Request` → handed to a swappable [`UserStatsResponder`] which
//!     returns the encoded payload; the dispatch task then unicasts a
//!     `Reply` back to the originator.
//!   * `Reply`   → looked up by `request_id` in the pending map; if
//!     found, the parked oneshot is completed.
//!
//! See [`crate::s2s::application`] for the full L3 design.

pub mod runtime;

pub use runtime::{
    OverlayUserStatsTransport, UserStatsApplyOutcome, UserStatsDelivery, UserStatsResponder,
    UserStatsService, UserStatsTransport, USER_STATS_CLASS, USER_STATS_LEVEL,
};
