//! Plugin data fanout across S2S.
//!
//! Mumble `PluginDataTransmission` targets explicit receiver sessions.
//! In a cluster, the originator groups those sessions by owning node,
//! sends one envelope per node, and the receiver forwards the payload to
//! locally-owned sessions.

pub mod runtime;

pub use runtime::{
    OverlayPluginDataTransport, PluginDataDelivery, PluginDataService, PluginDataSink,
    PluginDataTransport, ServerPluginDataSink, PLUGIN_DATA_CLASS, PLUGIN_DATA_LEVEL,
};
