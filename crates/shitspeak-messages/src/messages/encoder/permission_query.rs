use crate::messages::Message;

/// Mumble's client-side marker that a channel permission value is cached.
///
/// This is not a real ACL permission. Servers include it in PermissionQuery
/// replies so a zero-permission channel can still be distinguished from an
/// unknown permission cache entry.
pub const CLIENT_PERMISSION_CACHE_BIT: u32 = 0x0800_0000;

#[derive(Debug, Clone, Default)]
pub struct PermissionQuery {
    pub channel_id: Option<u32>,
    pub permissions: Option<u32>,
    pub flush: Option<bool>,
}

impl PermissionQuery {
    pub fn for_channel_permissions(channel_id: u32, permissions: u32) -> Self {
        Self {
            channel_id: Some(channel_id),
            permissions: Some(mark_client_permissions_cached(permissions)),
            flush: None,
        }
    }

    pub fn refresh_channel_permissions(channel_id: u32, permissions: u32) -> Self {
        Self {
            channel_id: Some(channel_id),
            permissions: Some(mark_client_permissions_cached(permissions)),
            flush: Some(false),
        }
    }

    pub fn flush_cache() -> Self {
        Self {
            channel_id: None,
            permissions: None,
            flush: Some(true),
        }
    }
}

pub fn mark_client_permissions_cached(permissions: u32) -> u32 {
    permissions | CLIENT_PERMISSION_CACHE_BIT
}

impl From<crate::mumble_proto::PermissionQuery> for PermissionQuery {
    fn from(proto: crate::mumble_proto::PermissionQuery) -> Self {
        Self {
            channel_id: proto.channel_id,
            permissions: proto.permissions,
            flush: proto.flush,
        }
    }
}

impl From<PermissionQuery> for crate::mumble_proto::PermissionQuery {
    fn from(value: PermissionQuery) -> Self {
        crate::mumble_proto::PermissionQuery {
            channel_id: value.channel_id,
            permissions: value.permissions,
            flush: value.flush,
        }
    }
}

impl From<PermissionQuery> for Message {
    fn from(value: PermissionQuery) -> Self {
        Message::PermissionQuery(value.into())
    }
}
