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
    async fn dispatch(&self, from: NodeIdentifier, body: StrictBody);
    /// Membership event broadcast — used to detect shrunk alive set.
    fn on_membership(&self, ev: &MembershipEvent);
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
    pub topic: String,
    pub body: InboundBody,
}

pub enum InboundBody {
    Strict(StrictBody),
    Owner(OwnerBody),
    Blob(BlobBody),
}
