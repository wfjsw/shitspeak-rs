pub mod client {
    pub mod client_session_identifier {
        pub use shitspeak_core::{ClientSessionIdentifier, ClientSessionIdentifierError};
    }
}

pub mod constants {
    pub use shitspeak_core::constants::MTU;
}

pub mod messages {
    pub use shitspeak_messages::messages::*;
}

pub mod mumble_udp {
    pub use shitspeak_proto::mumble_udp::*;
}

pub mod protocol_version {
    pub use shitspeak_core::ProtocolVersion;
}

pub mod codec;
pub mod ping;
pub mod routing_queue;
pub mod udp_batch;

pub mod voice {
    pub use crate::{codec, ping, routing_queue, udp_batch};
}
