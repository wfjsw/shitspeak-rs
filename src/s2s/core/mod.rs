pub mod consensus;
pub mod overlay;
pub mod replication;
pub mod transport;

/// Cluster node identifier — thin wrapper around the Mumble session-id space (u16).
pub type NodeId = u16;
