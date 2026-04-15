use enumflags2::{bitflags, BitFlags};
use serde::{Deserialize, Serialize};

use crate::client::group::{is_member_in_group, ClientMembershipQuery};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ACL {
    pub user_id: Option<i32>,
    pub group: Option<String>,

    pub apply_here: bool,
    pub apply_subs: bool,

    pub allow: BitFlags<ACLPermissions>,
    pub deny: BitFlags<ACLPermissions>,
}

#[bitflags]
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ACLPermissions {
    // None        = 0x0,
    Write = 0x1,
    Traverse = 0x2,
    Enter = 0x4,
    Speak = 0x8,
    MuteDeafen = 0x10,
    Move = 0x20,
    MakeChannel = 0x40,
    LinkChannel = 0x80,
    Whisper = 0x100,
    TextMessage = 0x200,
    TempChannel = 0x400,
    Listen = 0x800,

    // Root channel only
    Kick = 0x10000,
    Ban = 0x20000,
    Register = 0x40000,
    SelfRegister = 0x80000,
    ResetUserContent = 0x100000,
}

impl ACL {
    pub fn new() -> Self {
        ACL {
            user_id: None,
            group: None,
            apply_here: false,
            apply_subs: false,
            allow: BitFlags::empty(),
            deny: BitFlags::empty(),
        }
    }

    pub fn is_user_acl(&self) -> bool {
        self.user_id.is_some()
    }

    pub fn is_channel_acl(&self) -> bool {
        self.user_id.is_none()
    }

    pub fn match_user(&self, user_id: i32) -> bool {
        match self.user_id {
            Some(id) => id == user_id,
            None => false,
        }
    }

    pub fn match_group(
        &self,
        current_channel_id: u32,
        target_channel_id: Option<u32>,
        join_passwords: &[&str],
        client: &ClientMembershipQuery,
    ) -> bool {
        match &self.group {
            Some(group_name) => is_member_in_group(
                group_name,
                current_channel_id,
                target_channel_id,
                join_passwords,
                client,
            ),
            None => false,
        }
    }
}

impl Default for ACL {
    fn default() -> Self {
        Self::new()
    }
}
