use std::borrow::Cow;

use crate::messages::Message;

/// Deny types for `PermissionDenied` messages.
/// Values must match the Mumble protocol `PermissionDenied_DenyType` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum DenyType {
    Text = 0,
    Permission = 1,
    SuperUser = 2,
    ChannelName = 3,
    TextTooLong = 4,
    H9k = 5,
    TemporaryChannel = 6,
    MissingCertificate = 7,
    UserName = 8,
    ChannelFull = 9,
    NestingLimit = 10,
    ChannelCountLimit = 11,
    ChannelListenerLimit = 12,
    UserListenerLimit = 13,
}

// Compile-time check: ensure our enum values match the proto.
// If these constants change in the proto, this will fail to compile.
const _: () = {
    use crate::mumble_proto::permission_denied::DenyType as ProtoDenyType;
    assert!(DenyType::Text as i32 == ProtoDenyType::Text as i32);
    assert!(DenyType::Permission as i32 == ProtoDenyType::Permission as i32);
    assert!(DenyType::SuperUser as i32 == ProtoDenyType::SuperUser as i32);
    assert!(DenyType::ChannelName as i32 == ProtoDenyType::ChannelName as i32);
    assert!(DenyType::TextTooLong as i32 == ProtoDenyType::TextTooLong as i32);
    assert!(DenyType::H9k as i32 == ProtoDenyType::H9k as i32);
    assert!(DenyType::TemporaryChannel as i32 == ProtoDenyType::TemporaryChannel as i32);
    assert!(DenyType::MissingCertificate as i32 == ProtoDenyType::MissingCertificate as i32);
    assert!(DenyType::UserName as i32 == ProtoDenyType::UserName as i32);
    assert!(DenyType::ChannelFull as i32 == ProtoDenyType::ChannelFull as i32);
    assert!(DenyType::NestingLimit as i32 == ProtoDenyType::NestingLimit as i32);
    assert!(DenyType::ChannelCountLimit as i32 == ProtoDenyType::ChannelCountLimit as i32);
    assert!(DenyType::ChannelListenerLimit as i32 == ProtoDenyType::ChannelListenerLimit as i32);
    assert!(DenyType::UserListenerLimit as i32 == ProtoDenyType::UserListenerLimit as i32);
};

#[derive(Debug, Clone)]
pub struct PermissionDenied {
    pub r#type: DenyType,
    pub session: u32,
    pub channel_id: Option<u32>,
    pub reason: Option<Cow<'static, str>>,
    pub name: Option<Cow<'static, str>>,
    pub permission: Option<u32>,
}

impl PermissionDenied {
    /// Build a `PermissionDenied` for a missing permission on a channel.
    pub fn for_permission(
        session: u32,
        channel_id: Option<u32>,
        perm: crate::acl::ACLPermissions,
    ) -> Self {
        Self {
            r#type: DenyType::Permission,
            session,
            channel_id,
            reason: None,
            name: None,
            permission: Some(perm as u32),
        }
    }
}

impl DenyType {
    /// Convert from the proto enum value, logging a warning for unknown values.
    fn from_proto(v: i32) -> Self {
        match v {
            0 => DenyType::Text,
            1 => DenyType::Permission,
            2 => DenyType::SuperUser,
            3 => DenyType::ChannelName,
            4 => DenyType::TextTooLong,
            5 => DenyType::H9k,
            6 => DenyType::TemporaryChannel,
            7 => DenyType::MissingCertificate,
            8 => DenyType::UserName,
            9 => DenyType::ChannelFull,
            10 => DenyType::NestingLimit,
            11 => DenyType::ChannelCountLimit,
            12 => DenyType::ChannelListenerLimit,
            13 => DenyType::UserListenerLimit,
            other => {
                tracing::warn!("Unknown PermissionDenied DenyType value: {}", other);
                DenyType::Text
            }
        }
    }
}

impl From<crate::mumble_proto::PermissionDenied> for PermissionDenied {
    fn from(proto: crate::mumble_proto::PermissionDenied) -> Self {
        Self {
            r#type: proto.r#type.map_or(DenyType::Text, DenyType::from_proto),
            session: proto.session.unwrap_or(0),
            channel_id: proto.channel_id,
            reason: proto.reason.map(Cow::Owned),
            name: proto.name.map(Cow::Owned),
            permission: proto.permission,
        }
    }
}

impl Default for PermissionDenied {
    fn default() -> Self {
        Self {
            r#type: DenyType::Text,
            session: 0,
            channel_id: None,
            reason: None,
            name: None,
            permission: None,
        }
    }
}

impl Into<crate::mumble_proto::PermissionDenied> for PermissionDenied {
    fn into(self) -> crate::mumble_proto::PermissionDenied {
        crate::mumble_proto::PermissionDenied {
            r#type: Some(self.r#type as i32),
            session: Some(self.session),
            channel_id: self.channel_id,
            reason: self.reason.map(Cow::into_owned),
            name: self.name.map(Cow::into_owned),
            permission: self.permission,
        }
    }
}

impl Into<Message> for PermissionDenied {
    fn into(self) -> Message {
        Message::PermissionDenied(self.into())
    }
}
