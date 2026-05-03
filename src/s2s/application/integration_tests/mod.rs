//! End-to-end tests for the application (L3) layer.
//!
//! Each scenario brings up a real [`Cluster`](crate::s2s::testing::Cluster)
//! of overlay nodes, attaches an [`ApplicationLayer`] on top, and asserts
//! cross-node behavior end-to-end (envelope decode, audio sink delivery,
//! ordering, etc).

mod scenarios;
