use std::{borrow::Cow, collections::HashSet};

use serde::{Deserialize, Serialize};

use crate::acl::ACL;

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
        }
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
