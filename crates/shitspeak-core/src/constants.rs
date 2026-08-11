use crate::ProtocolVersion;

pub const MAX_NODE_ID: u16 = 0x0FFF;
pub const MAX_LOCAL_SESSION_ID: u32 = 0x0FFFFF;
pub const MTU: usize = 1600;

pub const APP_PROTO_VER: ProtocolVersion = ProtocolVersion {
    major: 1,
    minor: 6,
    patch: 870,
};

pub const PROTOBUF_INTRODUCED_VERSION: ProtocolVersion = ProtocolVersion {
    major: 1,
    minor: 5,
    patch: 0,
};
