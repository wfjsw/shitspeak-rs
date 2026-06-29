//! Reject type enum matching the Mumble protocol `Reject_RejectType` enum.

/// Reject types for `Reject` messages.
/// Values must match the Mumble protocol `Reject_RejectType` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum RejectType {
    None = 0,
    WrongVersion = 1,
    InvalidUsername = 2,
    WrongUserPw = 3,
    WrongServerPw = 4,
    UsernameInUse = 5,
    ServerFull = 6,
    NoCertificate = 7,
    AuthenticatorFail = 8,
    NoNewConnections = 9,
}

// Compile-time check: ensure our enum values match the proto.
const _: () = {
    use crate::mumble_proto::reject::RejectType as ProtoRejectType;
    assert!(RejectType::None as i32 == ProtoRejectType::None as i32);
    assert!(RejectType::WrongVersion as i32 == ProtoRejectType::WrongVersion as i32);
    assert!(RejectType::InvalidUsername as i32 == ProtoRejectType::InvalidUsername as i32);
    assert!(RejectType::WrongUserPw as i32 == ProtoRejectType::WrongUserPw as i32);
    assert!(RejectType::WrongServerPw as i32 == ProtoRejectType::WrongServerPw as i32);
    assert!(RejectType::UsernameInUse as i32 == ProtoRejectType::UsernameInUse as i32);
    assert!(RejectType::ServerFull as i32 == ProtoRejectType::ServerFull as i32);
    assert!(RejectType::NoCertificate as i32 == ProtoRejectType::NoCertificate as i32);
    assert!(RejectType::AuthenticatorFail as i32 == ProtoRejectType::AuthenticatorFail as i32);
    assert!(RejectType::NoNewConnections as i32 == ProtoRejectType::NoNewConnections as i32);
};

impl RejectType {
    /// Convert from the proto enum value, logging a warning for unknown values.
    pub fn from_proto(v: i32) -> Self {
        match v {
            0 => RejectType::None,
            1 => RejectType::WrongVersion,
            2 => RejectType::InvalidUsername,
            3 => RejectType::WrongUserPw,
            4 => RejectType::WrongServerPw,
            5 => RejectType::UsernameInUse,
            6 => RejectType::ServerFull,
            7 => RejectType::NoCertificate,
            8 => RejectType::AuthenticatorFail,
            9 => RejectType::NoNewConnections,
            other => {
                tracing::warn!("Unknown RejectType value: {}", other);
                RejectType::None
            }
        }
    }
}
