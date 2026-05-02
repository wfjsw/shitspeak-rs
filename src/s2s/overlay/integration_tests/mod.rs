//! Phase-2 end-to-end tests for the overlay network.
//!
//! Cross-layer test scaffolding (PKI, [`Cluster`](crate::s2s::testing::Cluster),
//! [`LinkChaos`](crate::s2s::testing::LinkChaos), wait helpers) lives in
//! [`crate::s2s::testing`]. This file just hosts the
//! `#[tokio::test]` scenarios.

mod scenarios;
