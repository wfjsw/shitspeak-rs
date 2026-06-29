pub mod acl {
    pub use shitspeak_core::ACLPermissions;
}

pub mod client {
    pub mod client_session_identifier {
        pub use shitspeak_core::{ClientSessionIdentifier, ClientSessionIdentifierError};
    }
}

pub mod constants {
    pub use shitspeak_core::constants::{
        APP_PROTO_VER, MAX_LOCAL_SESSION_ID, MAX_NODE_ID, MTU, PROTOBUF_INTRODUCED_VERSION,
    };

    pub fn release() -> String {
        let app_name = option_env!("APP_NAME").unwrap_or("ShitSpeak");
        let app_version = option_env!("APP_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"));
        format!("{app_name} {app_version} (unknown) [1970-01-01T00:00:00]")
    }
}

pub mod protocol_version {
    pub use shitspeak_core::ProtocolVersion;
}

pub mod mumble_proto {
    pub use shitspeak_proto::mumble_proto::*;
}

pub mod mumble_udp {
    pub use shitspeak_proto::mumble_udp::*;
}

pub mod errors;
pub mod messages;
