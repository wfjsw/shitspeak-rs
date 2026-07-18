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

pub mod s2s_upper_layer_proto {
    include!(concat!(env!("OUT_DIR"), "/s2s_upper_layer.rs"));
}

pub mod s2s_replication_proto {
    include!(concat!(env!("OUT_DIR"), "/s2s_replication.rs"));
}

pub mod s2s_application_proto {
    include!(concat!(env!("OUT_DIR"), "/s2s_application.rs"));
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use crate::s2s_overlay_proto::LinkStateAdvert;

    #[test]
    fn upper_layer_capabilities_preserve_absent_and_explicitly_empty_states() {
        // A legacy peer can carry tag 16 without knowing about the opaque
        // capability envelope at tag 18.
        let legacy = LinkStateAdvert::decode([0x80, 0x01, 0x02].as_slice()).unwrap();
        assert_eq!(legacy.strict_replication_protocol_version, 2);
        assert_eq!(legacy.upper_layer_capabilities, None);

        // An upgraded peer can authoritatively advertise no upper-layer
        // capabilities. This must not be confused with a legacy omission.
        let explicit_empty = LinkStateAdvert::decode([0x92, 0x01, 0x00].as_slice()).unwrap();
        assert_eq!(explicit_empty.upper_layer_capabilities, Some(Vec::new()));

        let mut reencoded = Vec::new();
        explicit_empty.encode(&mut reencoded).unwrap();
        assert_eq!(reencoded, [0x92, 0x01, 0x00]);
    }
}
