use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{ACL, acl::CompiledEffectiveAcl};

/// Replicated two-phase delete marker for a channel subtree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingDeleteState {
    pub nonce: u64,
    pub started_at_ms: i64,
    pub origin_node: u16,
}

/// A single Mumble channel.
///
/// `description_hash` holds the 40-character lowercase SHA-1 hex of the
/// channel description blob.  The raw text is stored only in
/// `ChannelBlobStore` and never kept in memory here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    pub id: u32,
    pub name: String,
    pub position: i32,
    pub max_users: u32,
    pub parent_id: Option<u32>,
    pub inherit_acl: bool,
    /// Linked channel IDs (bidirectional; both sides are stored).
    pub links: HashSet<u32>,
    /// SHA-1 hex of description blob; `None` = no description.
    pub description_hash: Option<String>,
    pub acls: Vec<ACL>,
    #[serde(default)]
    pub pending_delete: Option<PendingDeleteState>,
    /// Derived effective ACL program. It is rebuilt by the channel repository
    /// and is never part of replicated or persisted channel state.
    #[serde(skip)]
    pub(crate) effective_acl_cache: Option<CompiledEffectiveAcl>,
}

impl Channel {
    pub fn new(
        id: u32,
        name: impl Into<String>,
        position: i32,
        max_users: u32,
        parent_id: Option<u32>,
    ) -> Self {
        Channel {
            id,
            name: name.into(),
            position,
            max_users,
            parent_id,
            inherit_acl: true,
            links: HashSet::new(),
            description_hash: None,
            acls: Vec::new(),
            pending_delete: None,
            effective_acl_cache: None,
        }
    }

    /// Rebuild the derived ACL program for this channel.
    pub(crate) fn rebuild_effective_acl_cache(&mut self, ancestors: &[Channel]) {
        self.effective_acl_cache = Some(crate::acl::compile_effective_acl(self, ancestors));
    }

    /// Discard derived ACL state after mutating ACL-relevant channel fields.
    ///
    /// Most callers should let `ChannelRepository` maintain this cache. This
    /// method exists for short-lived channel clones that override ACL fields.
    #[doc(hidden)]
    pub fn clear_effective_acl_cache(&mut self) {
        self.effective_acl_cache = None;
    }

    /// Whether this channel can be evaluated without loading its ancestors.
    pub fn has_effective_acl_cache(&self) -> bool {
        self.effective_acl_cache
            .as_ref()
            .is_some_and(|cache| cache.is_current(self))
    }

    /// Target-to-root ancestor IDs captured by the derived ACL program.
    pub fn effective_acl_ancestor_ids(&self) -> Option<&[u32]> {
        self.effective_acl_cache
            .as_ref()
            .filter(|cache| cache.is_current(self))
            .map(CompiledEffectiveAcl::ancestor_ids)
    }

    /// Whether evaluating this ACL program can depend on the client's home
    /// channel hierarchy.
    pub fn effective_acl_depends_on_home_channel(&self) -> bool {
        self.effective_acl_cache
            .as_ref()
            .filter(|cache| cache.is_current(self))
            .is_some_and(CompiledEffectiveAcl::depends_on_home_channel)
    }

    pub fn has_description(&self) -> bool {
        self.description_hash
            .as_ref()
            .map_or(false, |h| !h.is_empty())
    }

    /// Bit-31 of the ID marks a channel as temporary (created by a client
    /// via `MakeTempChannel`).
    pub fn is_temporary(&self) -> bool {
        (self.id & 0x8000_0000u32) != 0
    }

    pub fn is_root(&self) -> bool {
        self.parent_id.is_none()
    }

    pub fn is_pending_delete(&self) -> bool {
        self.pending_delete.is_some()
    }
}

/// A lightweight patch used by `ChannelRepository` WAL entries to describe
/// which fields of an existing channel changed.  `None` means "unchanged".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelPatch {
    pub name: Option<String>,
    pub position: Option<i32>,
    pub max_users: Option<u32>,
    /// `Some(None)` = clear description; `Some(Some(hash))` = set new hash.
    pub description_hash: Option<Option<String>>,
    /// `Some(None)` = make root; `Some(Some(id))` = reparent.
    pub parent_id: Option<Option<u32>>,
}
