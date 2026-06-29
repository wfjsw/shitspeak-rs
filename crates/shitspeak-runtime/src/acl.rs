use enumflags2::BitFlags;
use serde::{Deserialize, Serialize};

use crate::client::group::{
    ChannelHierarchy, ClientMembershipQuery, group_depends_on_home_channel, is_member_in_group,
};

pub use shitspeak_core::ACLPermissions;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ACL {
    pub user_id: Option<i32>,
    pub group: Option<String>,

    pub apply_here: bool,
    pub apply_subs: bool,

    pub allow: BitFlags<ACLPermissions>,
    pub deny: BitFlags<ACLPermissions>,
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
        evaluation_channel: ChannelHierarchy<'_>,
        acl_channel: Option<ChannelHierarchy<'_>>,
        join_passwords: &[&str],
        client: &ClientMembershipQuery,
    ) -> bool {
        match &self.group {
            Some(group_name) => is_member_in_group(
                group_name,
                evaluation_channel,
                acl_channel,
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
) -> BitFlags<ACLPermissions> {
    evaluate_permission_with_behavior(channel, ancestors, user_id, client, false)
}

/// Evaluate permissions with configurable ACL compatibility behavior.
pub(crate) fn evaluate_permission_with_behavior(
    channel: &crate::channels::Channel,
    ancestors: &[crate::channels::Channel],
    user_id: Option<u32>,
    client: &ClientMembershipQuery,
    explicit_enter_deny_overrides_write: bool,
) -> BitFlags<ACLPermissions> {
    let mut permissions = default_permissions();
    let mut enter_explicitly_denied = false;
    let target_id = channel.id;
    let chain = effective_acl_chain(channel, ancestors);
    let target_ancestor_ids: Vec<u32> = ancestors.iter().map(|ancestor| ancestor.id).collect();
    let evaluation_channel = ChannelHierarchy::new(target_id, &target_ancestor_ids);

    for index in 0..chain.len() {
        let ch = chain[index];
        let is_target_channel = ch.id == target_id;
        let acl_ancestor_ids: Vec<u32> = chain[..index]
            .iter()
            .rev()
            .map(|ancestor| ancestor.id)
            .collect();
        let acl_channel = ChannelHierarchy::new(ch.id, &acl_ancestor_ids);

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
                acl.match_group(evaluation_channel, Some(acl_channel), &[], client)
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

fn any_applicable_effective_acl(
    channel: &crate::channels::Channel,
    ancestors: &[crate::channels::Channel],
    mut predicate: impl FnMut(&ACL, ChannelHierarchy<'_>, ChannelHierarchy<'_>) -> bool,
) -> bool {
    let target_id = channel.id;
    let chain = effective_acl_chain(channel, ancestors);
    let target_ancestor_ids: Vec<u32> = ancestors.iter().map(|ancestor| ancestor.id).collect();
    let evaluation_channel = ChannelHierarchy::new(target_id, &target_ancestor_ids);

    for index in 0..chain.len() {
        let ch = chain[index];
        let is_target_channel = ch.id == target_id;
        let acl_ancestor_ids: Vec<u32> = chain[..index]
            .iter()
            .rev()
            .map(|ancestor| ancestor.id)
            .collect();
        let acl_channel = ChannelHierarchy::new(ch.id, &acl_ancestor_ids);

        for acl in &ch.acls {
            let applies = if is_target_channel {
                acl.apply_here
            } else {
                acl.apply_subs
            };
            if applies && predicate(acl, evaluation_channel, acl_channel) {
                return true;
            }
        }
    }

    false
}

pub(crate) fn effective_acl_chain_has_home_channel_dependent_group(
    channel: &crate::channels::Channel,
    ancestors: &[crate::channels::Channel],
) -> bool {
    any_applicable_effective_acl(channel, ancestors, |acl, _, _| {
        acl.group
            .as_deref()
            .is_some_and(group_depends_on_home_channel)
    })
}

pub(crate) fn effective_acl_chain_home_channel_match_changes(
    channel: &crate::channels::Channel,
    ancestors: &[crate::channels::Channel],
    old_home: ChannelHierarchy<'_>,
    new_home: ChannelHierarchy<'_>,
) -> bool {
    any_applicable_effective_acl(
        channel,
        ancestors,
        |acl, evaluation_channel, acl_channel| {
            let Some(group) = acl.group.as_deref() else {
                return false;
            };
            if !group_depends_on_home_channel(group) {
                return false;
            }

            let old_query = ClientMembershipQuery::new(&[], true, &[], None, false, None)
                .with_home_channel(old_home);
            let new_query = ClientMembershipQuery::new(&[], true, &[], None, false, None)
                .with_home_channel(new_home);
            let old_match = is_member_in_group(
                group,
                evaluation_channel,
                Some(acl_channel),
                &[],
                &old_query,
            );
            let new_match = is_member_in_group(
                group,
                evaluation_channel,
                Some(acl_channel),
                &[],
                &new_query,
            );
            old_match != new_match
        },
    )
}

/// Check whether the effective ACL chain has any deny rules on the given permission.
/// Used to compute `is_enter_restricted` for `ChannelState` messages.
pub fn channel_has_effective_restriction(
    channel: &crate::channels::Channel,
    ancestors: &[crate::channels::Channel],
    perm: ACLPermissions,
) -> bool {
    any_applicable_effective_acl(channel, ancestors, |acl, _, _| {
        acl.deny.contains(perm) || acl.deny.contains(ACLPermissions::Traverse)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels::Channel;
    use crate::client::group::{ChannelHierarchy, ClientMembershipQuery};

    fn membership<'a>(
        home_channel_id: u32,
        home_ancestors: &'a [u32],
    ) -> ClientMembershipQuery<'a> {
        ClientMembershipQuery::new(&[], true, &[], None, false, None)
            .with_home_channel(ChannelHierarchy::new(home_channel_id, home_ancestors))
    }

    fn group_acl(
        group: &str,
        allow: BitFlags<ACLPermissions>,
        deny: BitFlags<ACLPermissions>,
    ) -> ACL {
        ACL {
            user_id: None,
            group: Some(group.to_owned()),
            apply_here: true,
            apply_subs: false,
            allow,
            deny,
        }
    }

    #[test]
    fn in_group_uses_client_home_channel_when_evaluating_destination_permissions() {
        let mut destination = Channel::new(2, "Command", 0, 0, Some(1));
        destination.acls = vec![
            group_acl("all", BitFlags::empty(), ACLPermissions::Speak.into()),
            group_acl("in", ACLPermissions::Speak.into(), BitFlags::empty()),
        ];
        let ancestors = vec![
            Channel::new(1, "Fleet", 0, 0, Some(0)),
            Channel::new(0, "Root", 0, 0, None),
        ];

        let local_member = membership(2, &[1, 0]);
        let remote_member = membership(3, &[1, 0]);

        assert!(
            evaluate_permission(&destination, &ancestors, Some(1), &local_member)
                .contains(ACLPermissions::Speak)
        );
        assert!(
            !evaluate_permission(&destination, &ancestors, Some(2), &remote_member)
                .contains(ACLPermissions::Speak)
        );
    }

    #[test]
    fn sub_group_matches_clients_under_destination_parent_with_target_context() {
        let mut destination = Channel::new(2, "Command", 0, 0, Some(1));
        destination.acls = vec![
            group_acl("all", BitFlags::empty(), ACLPermissions::Speak.into()),
            group_acl("~sub,-1,0", ACLPermissions::Speak.into(), BitFlags::empty()),
        ];
        let ancestors = vec![
            Channel::new(1, "Fleet", 0, 0, Some(0)),
            Channel::new(0, "Root", 0, 0, None),
        ];

        let fleet_descendant = membership(4, &[3, 1, 0]);
        let outside_fleet = membership(6, &[5, 0]);

        assert!(
            evaluate_permission(&destination, &ancestors, Some(1), &fleet_descendant)
                .contains(ACLPermissions::Speak)
        );
        assert!(
            !evaluate_permission(&destination, &ancestors, Some(2), &outside_fleet)
                .contains(ACLPermissions::Speak)
        );
    }
}
