//! Per-member status types as exposed to callers.
//!
//! In Phase 2 the LSDB is the single source of truth for membership; the
//! soft `Suspect/Dead` distinction from Phase 1's SWIM model has been
//! removed. A peer is either present in the LSDB with a non-tombstone
//! LSA (Alive), gracefully gone (Left, tombstone LSA seen), or its LSA
//! has aged out (Failed).

/// Public lifecycle status of one cluster member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MemberStatus {
    Alive = 0,
    Failed = 1,
    Left = 2,
}

impl MemberStatus {
    /// True if this status indicates a peer we should still try to talk to.
    pub fn is_reachable(self) -> bool {
        matches!(self, MemberStatus::Alive)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            MemberStatus::Alive => "alive",
            MemberStatus::Failed => "failed",
            MemberStatus::Left => "left",
        }
    }
}
