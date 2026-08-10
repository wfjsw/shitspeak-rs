//! Shared test utilities for the s2s subsystem.
//!
//! Anything here is gated by `#[cfg(test)]` and is reachable to every s2s
//! test via `crate::testing::*`. Keep this module focused on
//! cross-layer shared scaffolding (PKI, ports, cluster harness, chaos,
//! wait helpers); layer-specific mocks (e.g., the replications `MockNet`)
//! belong with the layer they exercise.
//!
//! Layout:
//!   * [`chaos`] — per-node inbound chaos middleware (overlay-aware).
//!   * [`cluster`] — multi-node cluster builder atop transport + overlay.
//!   * [`wait`] — predicate-driven sleep loops.

#![cfg(any(test, feature = "test-support"))]

pub mod chaos;
pub mod cluster;
pub mod wait;

// Convenient re-exports for the most common items so callers can write
// `crate::testing::{Cluster, mint_pki, wait_until}` without paying
// attention to file layout.
pub use chaos::{FaultSelector, LinkChaos, MessageType};
pub use cluster::{
    Capture, Cluster, Node, full_mesh_seeds, line_seeds, overlay_cfg, transport_cfg,
};
pub use shitspeak_s2s_transport::testing::{
    Pki, install_provider_once, loopback, mint_pki, pick_free_port, pick_free_udp_port,
    s2s_network_test_guard,
};
pub use wait::{wait_for_full_alive_mesh, wait_for_full_routing, wait_until, wait_until_with};

/// Write a valid, freshly checkpointed generation-zero terminal journal as a
/// standalone SQLite fixture. This deliberately goes through the production
/// journal and SQLite serialization paths instead of manufacturing rows in a
/// test with schema-specific SQL.
pub fn write_checkpoint_terminal_fixture(
    destination: impl AsRef<std::path::Path>,
    topic: &str,
    repository_version: u64,
) -> std::io::Result<()> {
    let root = tempfile::TempDir::new()?;
    {
        let mut journal = crate::replications::strict::terminal_journal::TerminalJournal::load(
            Some(root.path().to_path_buf()),
            topic,
        )
        .map_err(std::io::Error::other)?;
        journal
            .checkpoint(repository_version)
            .map_err(std::io::Error::other)?;
    }

    let source = root
        .path()
        .join("strict-terminal-journal")
        .join(format!("topic-{}.sqlite3", hex::encode(topic.as_bytes())));
    let connection =
        rusqlite::Connection::open_with_flags(source, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(std::io::Error::other)?;
    let image = connection
        .serialize(rusqlite::MAIN_DB)
        .map_err(std::io::Error::other)?;
    std::fs::write(destination, &*image)
}
