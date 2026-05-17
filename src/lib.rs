#![allow(warnings)]
#![allow(
    dead_code,
    unused_variables,
    unused_imports,
    unused_must_use,
    unused_assignments
)]

// Library root — re-exports modules for benchmarks and tests.

pub mod acl;
pub mod api;
pub mod ban_repository;
pub mod blob_store;
pub mod channel_handler;
pub mod channel_repository;
pub mod channels;
pub mod client;
pub mod client_certificate_verifier;
pub mod client_repository;
pub mod codec_info;
pub mod config;
pub mod constants;
pub mod context_action;
pub mod errors;
pub mod geoip;
pub mod localization;
pub mod messages;
pub mod protocol_version;
pub mod proxy_protocol;
pub mod register;
pub mod s2s;
pub mod server;
pub mod types;
pub mod utils;
pub mod voice;
pub mod voice_crypto;

#[cfg(test)]
mod integration_tests;

pub mod mumble_proto {
    include!(concat!(env!("OUT_DIR"), "/mumble_proto.rs"));
}

pub mod mumble_udp {
    include!(concat!(env!("OUT_DIR"), "/mumble_udp.rs"));
}

pub mod s2s_transport_proto {
    include!(concat!(env!("OUT_DIR"), "/s2s_transport.rs"));
}

pub mod s2s_overlay_proto {
    include!(concat!(env!("OUT_DIR"), "/s2s_overlay.rs"));
}

pub mod s2s_replication_proto {
    include!(concat!(env!("OUT_DIR"), "/s2s_replication.rs"));
}

pub mod s2s_application_proto {
    include!(concat!(env!("OUT_DIR"), "/s2s_application.rs"));
}
