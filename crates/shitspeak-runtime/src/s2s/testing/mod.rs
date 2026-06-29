//! Shared test utilities for the s2s subsystem.
//!
//! Anything here is gated by `#[cfg(test)]` and is reachable to every s2s
//! test via `crate::s2s::testing::*`. Keep this module focused on
//! cross-layer shared scaffolding (PKI, ports, cluster harness, chaos,
//! wait helpers); layer-specific mocks (e.g., the replications `MockNet`)
//! belong with the layer they exercise.
//!
//! Layout:
//!   * [`pki`] — CA + per-node certificate minting, rustls provider init.
//!   * [`ports`] — loopback `SocketAddr` + free-port pickers.
//!   * [`chaos`] — per-node inbound chaos middleware (overlay-aware).
//!   * [`cluster`] — multi-node cluster builder atop transport + overlay.
//!   * [`wait`] — predicate-driven sleep loops.

#![cfg(test)]

pub mod chaos;
pub mod cluster;
pub mod pki;
pub mod ports;
pub mod wait;

// Convenient re-exports for the most common items so callers can write
// `crate::s2s::testing::{Cluster, mint_pki, wait_until}` without paying
// attention to file layout.
pub use chaos::{LinkChaos, MessageType};
pub use cluster::{
    Capture, Cluster, Node, full_mesh_seeds, line_seeds, overlay_cfg, s2s_network_test_guard,
    transport_cfg,
};
pub use pki::{Pki, install_provider_once, mint_pki};
pub use ports::{loopback, pick_free_port, pick_free_udp_port};
pub use wait::{wait_for_full_alive_mesh, wait_for_full_routing, wait_until, wait_until_with};
