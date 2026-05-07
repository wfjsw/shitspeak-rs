//! Two-client integration tests for the Mumble server.
//!
//! These tests spin up a real `Server` on an ephemeral 127.0.0.1 port and
//! connect two test clients over TLS. They exercise the auth flow, the
//! channel tree burst, self/moderator actions, channel CRUD, ACLs, channel
//! moves, and voice routing (both TCP-tunneled and real UDP with OCB2).
//!
//! The harness lives under [`harness`] and the scenarios under [`scenarios`].
//! All tests are gated by `#[cfg(test)]`, matching the s2s convention.

#![cfg(test)]

pub mod harness;
pub mod scenarios;
