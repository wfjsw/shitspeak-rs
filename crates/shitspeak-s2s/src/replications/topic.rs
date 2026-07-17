//! Type erasure for heterogeneous strict / owner topic registries.
//!
//! Each registered topic carries a different `Op` type. The manager needs to
//! store them all in one map keyed by topic-string, so we expose a small
//! object-safe trait for inbound dispatch and shutdown.

use async_trait::async_trait;

use super::proto::{BlobBody, OwnerBody, StrictBody};
use crate::overlay::MembershipEvent;
use shitspeak_core::NodeIdentifier;

/// Runtime-side trait for a strict (Tempo) topic. The manager holds an
/// `Arc<dyn ErasedStrictRuntime>` per topic and feeds inbound frames in.
#[async_trait]
pub trait ErasedStrictRuntime: Send + Sync + 'static {
    /// Inbound `StrictMessage` body addressed to this topic.
    async fn dispatch(
        &self,
        from: NodeIdentifier,
        origin_boot_epoch: u64,
        origin_authenticated: bool,
        body: StrictBody,
    );
    /// Membership event broadcast — used to detect shrunk alive set.
    fn on_membership(&self, ev: &MembershipEvent);
    /// Whether this concrete topic can safely participate in the current
    /// strict v2 advertisement. This is intentionally independent of the
    /// local LSA value so the manager can probe before it promotes the LSA.
    fn strict_v2_advertisement_prerequisites_ready(&self) -> bool;
    /// Cancel any background work owned by this topic.
    fn shutdown(&self);
}

/// Runtime-side trait for an owner-scoped topic.
#[async_trait]
pub trait ErasedOwnerRuntime: Send + Sync + 'static {
    async fn dispatch(&self, from: NodeIdentifier, body: OwnerBody);
    fn on_membership(&self, ev: &MembershipEvent);
    fn shutdown(&self);
}

#[async_trait::async_trait]
pub trait ErasedBlobRuntime: Send + Sync + 'static {
    /// Inbound `BlobMessage` body addressed to this topic.
    async fn dispatch(&self, from: NodeIdentifier, body: BlobBody);
    /// Membership event broadcast.
    fn on_membership(&self, ev: &MembershipEvent);
    fn shutdown(&self);
}

/// Inbound frame the manager pushes onto the dispatch mpsc.
pub struct InboundFrame {
    pub from: NodeIdentifier,
    pub(crate) origin_boot_epoch: u64,
    /// `true` only when a detached certificate proof binds the strict
    /// payload to this logical origin. Proofless legacy frames remain
    /// decodable for rolling-upgrade compatibility, but strict dispatch drops
    /// them before they can affect protocol state.
    pub(crate) origin_authenticated: bool,
    pub topic: String,
    pub body: InboundBody,
}

pub enum InboundBody {
    Strict(StrictBody),
    Owner(OwnerBody),
    Blob(BlobBody),
}
