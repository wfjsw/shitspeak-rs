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
