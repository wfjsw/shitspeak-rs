//! Type erasure for heterogeneous strict / owner topic registries.
//!
//! Each registered topic carries a different `Op` type. The manager needs to
//! store them all in one map keyed by topic-string, so we expose a small
//! object-safe trait for inbound dispatch and shutdown.

use std::sync::Arc;

use async_trait::async_trait;

use super::proto::{OwnerBody, StrictBody};
use crate::s2s::overlay::MembershipEvent;
use crate::types::NodeIdentifier;

/// Runtime-side trait for a strict (Tempo) topic. The manager holds an
/// `Arc<dyn ErasedStrictRuntime>` per topic and feeds inbound frames in.
#[async_trait]
pub(crate) trait ErasedStrictRuntime: Send + Sync + 'static {
    /// Inbound `StrictMessage` body addressed to this topic.
    async fn dispatch(&self, from: NodeIdentifier, body: StrictBody);
    /// Membership event broadcast — used to detect shrunk alive set.
    fn on_membership(&self, ev: &MembershipEvent);
    /// Cancel any background work owned by this topic.
    fn shutdown(&self);
}

/// Runtime-side trait for an owner-scoped topic.
#[async_trait]
pub(crate) trait ErasedOwnerRuntime: Send + Sync + 'static {
    async fn dispatch(&self, from: NodeIdentifier, body: OwnerBody);
    fn on_membership(&self, ev: &MembershipEvent);
    fn shutdown(&self);
}

/// Inbound frame the manager pushes onto the dispatch mpsc.
pub(crate) struct InboundFrame {
    pub from: NodeIdentifier,
    pub topic: String,
    pub body: InboundBody,
}

pub(crate) enum InboundBody {
    Strict(StrictBody),
    Owner(OwnerBody),
}

/// Convenience: erase a concrete strict runtime.
pub(crate) fn erase_strict<R: ErasedStrictRuntime>(r: Arc<R>) -> Arc<dyn ErasedStrictRuntime> {
    r
}

/// Convenience: erase a concrete owner runtime.
pub(crate) fn erase_owner<R: ErasedOwnerRuntime>(r: Arc<R>) -> Arc<dyn ErasedOwnerRuntime> {
    r
}
