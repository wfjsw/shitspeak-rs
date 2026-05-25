//! Direct-link Hello protocol + neighbor monitoring.
//!
//! Replaces the SWIM ticker. Owns:
//!   * The Hello/HelloAck round-trip protocol (see `hello.rs`).
//!   * The direct-neighbor table — peers with a live L1 stream + their
//!     last cost readings — see `monitor.rs`.

pub mod hello;
pub mod monitor;

pub use hello::{
    HelloContext, handle_hello_ack, respond_to_hello, send_hello, spawn_hello_task,
    spawn_link_up_watcher,
};
pub use monitor::{NeighborMonitor, NeighborSnapshot};
