use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ChannelRepoError {
    #[error("channel operation requires a non-empty server id")]
    InvalidServerId,

    #[error("channel {0} not found")]
    NotFound(u32),

    #[error("parent channel {0} not found")]
    ParentNotFound(u32),

    #[error("a channel named '{0}' already exists in that parent")]
    NameConflict(String),

    #[error("cannot delete the root channel")]
    CannotDeleteRoot,

    #[error("cannot move a channel into one of its own descendants")]
    CannotMoveIntoDescendant,

    #[error("temporary channel {0} cannot have child channels")]
    TemporaryChannelCannotHaveChildren(u32),

    #[error("temporary channel {0} cannot be linked")]
    TemporaryChannelCannotBeLinked(u32),

    #[error("WAL I/O error: {0}")]
    WalIo(#[from] io::Error),

    #[error("WAL corrupt at line {line}: {reason}")]
    WalCorrupt { line: usize, reason: String },

    #[error(
        "strict snapshot operation-id ledger is missing {missing} locally applied operation(s)"
    )]
    StrictSnapshotOperationIdsIncomplete { missing: usize },
}
