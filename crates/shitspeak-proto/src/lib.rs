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

    /// Bit assignments used by `LinkStateAdvert` capability masks.
    pub mod link_state_advert_capabilities {
        /// The origin may be used as a transit router.
        pub const ROUTING_TRANSIT: u32 = 1 << 0;

        /// The origin advertises strict replication.
        pub const SERVICE_STRICT_REPLICATION: u32 = 1 << 0;
        /// The origin advertises content/blob replication.
        pub const SERVICE_CONTENT_REPLICATION: u32 = 1 << 1;
        /// The origin advertises owner-scoped replication.
        pub const SERVICE_OWNER_REPLICATION: u32 = 1 << 2;
        /// The origin advertises application voice service.
        pub const SERVICE_VOICE: u32 = 1 << 3;
    }
}

pub mod s2s_replication_proto {
    include!(concat!(env!("OUT_DIR"), "/s2s_replication.rs"));
}

pub mod s2s_application_proto {
    include!(concat!(env!("OUT_DIR"), "/s2s_application.rs"));
}
