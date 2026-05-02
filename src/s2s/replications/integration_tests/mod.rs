//! Cluster integration tests against a real overlay (loopback mTLS,
//! Hello/HelloAck, LSDB, Dijkstra). Reuses the overlay's own test harness.

#![cfg(test)]

mod harness;
mod scenarios;
