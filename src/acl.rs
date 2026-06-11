use enumflags2::{BitFlags, bitflags};
use serde::{Deserialize, Serialize};

use crate::client::group::{ClientMembershipQuery, is_member_in_group};

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

    pub fn is_group_acl(&self) -> bool {
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

fn default_permissions() -> BitFlags<ACLPermissions> {
    ACLPermissions::Traverse
        | ACLPermissions::Enter
        | ACLPermissions::Speak
        | ACLPermissions::Whisper
        | ACLPermissions::TextMessage
        | ACLPermissions::Listen
}

fn write_implied_permissions() -> BitFlags<ACLPermissions> {
    ACLPermissions::Traverse
        | ACLPermissions::Enter
        | ACLPermissions::MuteDeafen
        | ACLPermissions::Move
        | ACLPermissions::MakeChannel
        | ACLPermissions::LinkChannel
        | ACLPermissions::TextMessage
        | ACLPermissions::TempChannel
        | ACLPermissions::Listen
}

fn root_only_permissions() -> BitFlags<ACLPermissions> {
    ACLPermissions::Kick
        | ACLPermissions::Ban
        | ACLPermissions::Register
        | ACLPermissions::SelfRegister
        | ACLPermissions::ResetUserContent
}

/// Evaluate the effective permissions for a user on a given channel.
///
/// Walks the ACL chain in Mumble order: root to target, applying each channel's
/// ACL entries in list order. Later ACL entries overwrite earlier decisions for
/// the same permission bit.
pub fn evaluate_permission(
    channel: &crate::channels::Channel,
    ancestors: &[crate::channels::Channel],
    user_id: Option<u32>,
    client: &ClientMembershipQuery,
    current_channel_id: u32,
) -> BitFlags<ACLPermissions> {
    evaluate_permission_with_behavior(
        channel,
        ancestors,
        user_id,
        client,
        current_channel_id,
        false,
    )
}

/// Evaluate permissions with configurable ACL compatibility behavior.
pub(crate) fn evaluate_permission_with_behavior(
    channel: &crate::channels::Channel,
    ancestors: &[crate::channels::Channel],
    user_id: Option<u32>,
    client: &ClientMembershipQuery,
    current_channel_id: u32,
    explicit_enter_deny_overrides_write: bool,
) -> BitFlags<ACLPermissions> {
    let mut permissions = default_permissions();
    let mut enter_explicitly_denied = false;
    let target_id = channel.id;
    let chain = effective_acl_chain(channel, ancestors);

    for ch in chain {
        let is_target_channel = ch.id == target_id;

        for acl in &ch.acls {
            let applies = if is_target_channel {
                acl.apply_here
            } else {
                acl.apply_subs
            };
            if !applies {
                continue;
            }

            let matches = if let Some(uid) = acl.user_id {
                user_id.is_some_and(|u| u as i32 == uid)
            } else {
                acl.match_group(current_channel_id, Some(ch.id), &[], client)
            };
            if !matches {
                continue;
            }

            permissions.insert(acl.allow);
            if acl.allow.contains(ACLPermissions::Enter) {
                enter_explicitly_denied = false;
            }
            permissions.remove(acl.deny);
            if acl.deny.contains(ACLPermissions::Enter) {
                enter_explicitly_denied = true;
            }
        }

        if !permissions.contains(ACLPermissions::Traverse)
            && !permissions.contains(ACLPermissions::Write)
        {
            return BitFlags::empty();
        }
    }

    if permissions.contains(ACLPermissions::Write) {
        permissions.insert(write_implied_permissions());
        if explicit_enter_deny_overrides_write && enter_explicitly_denied {
            permissions.remove(ACLPermissions::Enter);
        }
        if target_id == 0 {
            permissions.insert(root_only_permissions());
        }
    }

    if target_id != 0 {
        permissions.remove(root_only_permissions());
    }

    permissions
}

fn effective_acl_chain<'a>(
    channel: &'a crate::channels::Channel,
    ancestors: &'a [crate::channels::Channel],
) -> Vec<&'a crate::channels::Channel> {
    let mut inherited: Vec<&crate::channels::Channel> = Vec::new();
    for ancestor in ancestors.iter().rev() {
        inherited.push(ancestor);
        if !ancestor.inherit_acl {
            inherited.clear();
            inherited.push(ancestor);
        }
    }

    if !channel.inherit_acl {
        inherited.clear();
    }
    inherited.push(channel);
    inherited
}

/// Check whether the effective ACL chain has any deny rules on the given permission.
/// Used to compute `is_enter_restricted` for `ChannelState` messages.
pub fn channel_has_effective_restriction(
    channel: &crate::channels::Channel,
    ancestors: &[crate::channels::Channel],
    perm: ACLPermissions,
) -> bool {
    let target_id = channel.id;
    effective_acl_chain(channel, ancestors)
        .into_iter()
        .any(|ch| {
            let is_target_channel = ch.id == target_id;
            ch.acls.iter().any(|acl| {
                let applies = if is_target_channel {
                    acl.apply_here
                } else {
                    acl.apply_subs
                };
                applies && (acl.deny.contains(perm) || acl.deny.contains(ACLPermissions::Traverse))
            })
        })
}
