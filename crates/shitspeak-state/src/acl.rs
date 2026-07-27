use std::{collections::BTreeSet, sync::Arc};

#[cfg(test)]
use std::cell::Cell;

use enumflags2::BitFlags;
use serde::{Deserialize, Serialize};

use crate::{
    ChannelHierarchy, ChannelReference, ClientMembershipQuery, group_depends_on_home_channel,
    is_member_in_group,
};

pub use shitspeak_core::ACLPermissions;

#[cfg(test)]
thread_local! {
    static EFFECTIVE_ACL_COMPILE_COUNT: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_effective_acl_compile_count() {
    EFFECTIVE_ACL_COMPILE_COUNT.set(0);
}

#[cfg(test)]
pub(crate) fn effective_acl_compile_count() -> usize {
    EFFECTIVE_ACL_COMPILE_COUNT.get()
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

/// Connected viewers that may observe a permission change from an ACL edit.
///
/// Exact user ACLs and ordinary client-group ACLs can be scoped cheaply. All
/// other group expressions depend on authentication, tokens, certificates,
/// addresses, channel placement, inversion, or target-channel context and are
/// therefore represented conservatively as all viewers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AclViewerScope {
    all_viewers: bool,
    user_ids: BTreeSet<i32>,
    plain_client_groups: BTreeSet<String>,
}

impl AclViewerScope {
    pub fn includes_all_viewers(&self) -> bool {
        self.all_viewers
    }

    pub fn user_ids(&self) -> &BTreeSet<i32> {
        &self.user_ids
    }

    pub fn plain_client_groups(&self) -> &BTreeSet<String> {
        &self.plain_client_groups
    }

    pub fn is_empty(&self) -> bool {
        !self.all_viewers && self.user_ids.is_empty() && self.plain_client_groups.is_empty()
    }

    fn include_acl(&mut self, acl: &ACL) {
        if self.all_viewers {
            return;
        }
        if let Some(user_id) = acl.user_id {
            self.user_ids.insert(user_id);
            return;
        }
        let Some(group) = acl.group.as_deref() else {
            return;
        };
        if is_plain_client_group(group) {
            self.plain_client_groups
                .insert(group.trim().to_ascii_lowercase());
        } else {
            self.all_viewers = true;
            self.user_ids.clear();
            self.plain_client_groups.clear();
        }
    }

    fn include_all(&mut self) {
        self.all_viewers = true;
        self.user_ids.clear();
        self.plain_client_groups.clear();
    }
}

/// Permission effects for one ACL application mode (`apply_here` or
/// `apply_subs`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AclPermissionChange {
    raw_permissions: BitFlags<ACLPermissions>,
    effective_permissions: BitFlags<ACLPermissions>,
    restriction_may_change: bool,
    viewer_scope: AclViewerScope,
}

impl AclPermissionChange {
    pub fn raw_permissions(&self) -> BitFlags<ACLPermissions> {
        self.raw_permissions
    }

    pub fn effective_permissions(&self) -> BitFlags<ACLPermissions> {
        self.effective_permissions
    }

    pub fn restriction_may_change(&self) -> bool {
        self.restriction_may_change
    }

    pub fn viewer_scope(&self) -> &AclViewerScope {
        &self.viewer_scope
    }

    pub fn is_empty(&self) -> bool {
        self.effective_permissions.is_empty() && !self.restriction_may_change
    }

    fn include_acl(&mut self, acl: &ACL) {
        let permissions = acl.allow | acl.deny;
        if permissions.is_empty() {
            return;
        }
        self.raw_permissions.insert(permissions);
        self.restriction_may_change |= acl
            .deny
            .intersects(ACLPermissions::Traverse | ACLPermissions::Enter);
        self.viewer_scope.include_acl(acl);
    }

    fn finalize(&mut self) {
        self.effective_permissions = expand_acl_permission_change(self.raw_permissions);
    }

    fn include_all(&mut self) {
        self.raw_permissions = BitFlags::all();
        self.effective_permissions = BitFlags::all();
        self.restriction_may_change = true;
        self.viewer_scope.include_all();
    }
}

/// Conservative impact classification for replacing a channel's ACL state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AclChangeImpact {
    state_changed: bool,
    inheritance_changed: bool,
    apply_here: AclPermissionChange,
    apply_subs: AclPermissionChange,
}

impl AclChangeImpact {
    pub fn state_changed(&self) -> bool {
        self.state_changed
    }

    pub fn inheritance_changed(&self) -> bool {
        self.inheritance_changed
    }

    pub fn apply_here(&self) -> &AclPermissionChange {
        &self.apply_here
    }

    pub fn apply_subs(&self) -> &AclPermissionChange {
        &self.apply_subs
    }

    pub fn is_semantically_empty(&self) -> bool {
        self.apply_here.is_empty() && self.apply_subs.is_empty()
    }
}

/// Classify which permission paths may change when replacing channel ACLs.
///
/// Equal prefixes and suffixes are ignored. The remaining entries are the
/// smallest contiguous edit region that is always safe for ordered ACL
/// evaluation. An inheritance toggle is deliberately classified as affecting
/// every permission and viewer because inherited rules are not available to
/// this operation-local helper.
pub fn classify_acl_change(
    old_inherit_acl: bool,
    old_acls: &[ACL],
    new_inherit_acl: bool,
    new_acls: &[ACL],
) -> AclChangeImpact {
    let state_changed = old_inherit_acl != new_inherit_acl || old_acls != new_acls;
    if !state_changed {
        return AclChangeImpact::default();
    }

    let inheritance_changed = old_inherit_acl != new_inherit_acl;
    let mut impact = AclChangeImpact {
        state_changed,
        inheritance_changed,
        ..Default::default()
    };
    if inheritance_changed {
        impact.apply_here.include_all();
        impact.apply_subs.include_all();
        return impact;
    }

    let prefix_len = old_acls
        .iter()
        .zip(new_acls)
        .take_while(|(old, new)| old == new)
        .count();
    let remaining_old = old_acls.len().saturating_sub(prefix_len);
    let remaining_new = new_acls.len().saturating_sub(prefix_len);
    let suffix_len = old_acls[prefix_len..]
        .iter()
        .rev()
        .zip(new_acls[prefix_len..].iter().rev())
        .take_while(|(old, new)| old == new)
        .count()
        .min(remaining_old)
        .min(remaining_new);

    let old_changed_end = old_acls.len().saturating_sub(suffix_len);
    let new_changed_end = new_acls.len().saturating_sub(suffix_len);
    for acl in old_acls[prefix_len..old_changed_end]
        .iter()
        .chain(&new_acls[prefix_len..new_changed_end])
    {
        if acl.apply_here {
            impact.apply_here.include_acl(acl);
        }
        if acl.apply_subs {
            impact.apply_subs.include_acl(acl);
        }
    }
    impact.apply_here.finalize();
    impact.apply_subs.finalize();
    impact
}

fn expand_acl_permission_change(permissions: BitFlags<ACLPermissions>) -> BitFlags<ACLPermissions> {
    if permissions.intersects(ACLPermissions::Traverse | ACLPermissions::Write) {
        BitFlags::all()
    } else {
        permissions
    }
}

fn is_plain_client_group(group: &str) -> bool {
    if matches!(group.chars().next(), Some('!' | '~' | '#' | '$' | '%')) {
        return false;
    }
    !matches!(
        group,
        "all" | "none" | "auth" | "strong" | "in" | "out" | "sub"
    ) && !group.starts_with("sub,")
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompiledHierarchy {
    channel_id: u32,
    ancestors: Arc<[u32]>,
}

impl CompiledHierarchy {
    fn from_channels<A: ChannelReference>(channel_id: u32, ancestors: &[A]) -> Self {
        Self {
            channel_id,
            ancestors: ancestors
                .iter()
                .map(|channel| channel.as_ref().id)
                .collect::<Vec<_>>()
                .into(),
        }
    }

    fn as_hierarchy(&self) -> ChannelHierarchy<'_> {
        ChannelHierarchy::new(self.channel_id, self.ancestors.as_ref())
    }
}

/// One ordered ACL operation with enough context to evaluate its raw
/// principal expression without consulting the channel tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompiledAclEntry {
    user_id: Option<i32>,
    group: Option<String>,
    allow: BitFlags<ACLPermissions>,
    deny: BitFlags<ACLPermissions>,
    evaluation_channel: CompiledHierarchy,
    acl_channel: CompiledHierarchy,
}

impl CompiledAclEntry {
    fn matches(&self, user_id: Option<u32>, client: &ClientMembershipQuery) -> bool {
        if let Some(expected_user_id) = self.user_id {
            return user_id.is_some_and(|user_id| user_id as i32 == expected_user_id);
        }

        self.group.as_deref().is_some_and(|group| {
            is_member_in_group(
                group,
                self.evaluation_channel.as_hierarchy(),
                Some(self.acl_channel.as_hierarchy()),
                &[],
                client,
            )
        })
    }

    fn depends_on_home_channel(&self) -> bool {
        self.group
            .as_deref()
            .is_some_and(group_depends_on_home_channel)
    }

    fn group_matches(&self, client: &ClientMembershipQuery) -> bool {
        self.group.as_deref().is_some_and(|group| {
            is_member_in_group(
                group,
                self.evaluation_channel.as_hierarchy(),
                Some(self.acl_channel.as_hierarchy()),
                &[],
                client,
            )
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompiledPathStage {
    entries: Vec<CompiledAclEntry>,
}

/// A compiled ACL chain owned by one channel entry.
///
/// `destination` is the flattened root-to-target rule stream. `path` contains
/// a separate flattened stream for every actual ancestor, because Traverse is
/// gated at each path segment rather than only at the destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CompiledEffectiveAcl {
    destination: Vec<CompiledAclEntry>,
    path: Vec<CompiledPathStage>,
    path_has_home_channel_dependent_group: bool,
    ancestor_ids: Vec<u32>,
    source_id: u32,
    source_parent_id: Option<u32>,
    source_inherit_acl: bool,
    source_acls: Vec<ACL>,
}

impl CompiledEffectiveAcl {
    pub(crate) fn ancestor_ids(&self) -> &[u32] {
        &self.ancestor_ids
    }

    pub(crate) fn depends_on_home_channel(&self) -> bool {
        self.path_has_home_channel_dependent_group
            || self
                .destination
                .iter()
                .any(CompiledAclEntry::depends_on_home_channel)
    }

    pub(crate) fn is_current(&self, channel: &crate::Channel) -> bool {
        self.source_id == channel.id
            && self.source_parent_id == channel.parent_id
            && self.source_inherit_acl == channel.inherit_acl
            && self.source_acls == channel.acls
    }
}

pub(crate) fn compile_effective_acl<A: ChannelReference>(
    channel: &crate::Channel,
    ancestors: &[A],
) -> CompiledEffectiveAcl {
    #[cfg(test)]
    EFFECTIVE_ACL_COMPILE_COUNT.with(|count| count.set(count.get() + 1));

    let destination = compile_acl_chain(channel, ancestors, false);
    let path = (0..ancestors.len())
        .rev()
        .map(|index| CompiledPathStage {
            entries: compile_acl_chain(ancestors[index].as_ref(), &ancestors[index + 1..], true),
        })
        .collect::<Vec<_>>();
    let path_has_home_channel_dependent_group = path.iter().any(|stage| {
        stage.entries.iter().any(|entry| {
            entry.depends_on_home_channel()
                && (entry.allow | entry.deny)
                    .intersects(ACLPermissions::Traverse | ACLPermissions::Write)
        })
    });

    CompiledEffectiveAcl {
        destination,
        path,
        path_has_home_channel_dependent_group,
        ancestor_ids: ancestors
            .iter()
            .map(|ancestor| ancestor.as_ref().id)
            .collect(),
        source_id: channel.id,
        source_parent_id: channel.parent_id,
        source_inherit_acl: channel.inherit_acl,
        source_acls: channel.acls.clone(),
    }
}

fn compile_acl_chain<A: ChannelReference>(
    channel: &crate::Channel,
    ancestors: &[A],
    acl_uses_full_hierarchy: bool,
) -> Vec<CompiledAclEntry> {
    let evaluation_channel = CompiledHierarchy::from_channels(channel.id, ancestors);
    let inherited_len = effective_inherited_len(channel, ancestors);
    let mut entries = Vec::new();

    for index in (0..inherited_len).rev() {
        let ancestor = ancestors[index].as_ref();
        append_compiled_entries(
            &mut entries,
            &ancestor.acls,
            false,
            &evaluation_channel,
            CompiledHierarchy::from_channels(
                ancestor.id,
                if acl_uses_full_hierarchy {
                    &ancestors[index + 1..]
                } else {
                    &ancestors[index + 1..inherited_len]
                },
            ),
        );
    }

    let local_acl_channel = if acl_uses_full_hierarchy {
        evaluation_channel.clone()
    } else {
        CompiledHierarchy::from_channels(channel.id, &ancestors[..inherited_len])
    };
    append_compiled_entries(
        &mut entries,
        &channel.acls,
        true,
        &evaluation_channel,
        local_acl_channel,
    );
    entries
}

fn append_compiled_entries(
    entries: &mut Vec<CompiledAclEntry>,
    acls: &[ACL],
    apply_here: bool,
    evaluation_channel: &CompiledHierarchy,
    acl_channel: CompiledHierarchy,
) {
    entries.extend(acls.iter().filter_map(|acl| {
        let applies = if apply_here {
            acl.apply_here
        } else {
            acl.apply_subs
        };
        applies.then(|| CompiledAclEntry {
            user_id: acl.user_id,
            group: acl.group.clone(),
            allow: acl.allow,
            deny: acl.deny,
            evaluation_channel: evaluation_channel.clone(),
            acl_channel: acl_channel.clone(),
        })
    }));
}

/// Evaluate the effective permissions for a user on a given channel.
///
/// Walks the ACL chain in Mumble order: root to target, applying each channel's
/// ACL entries in list order. Later ACL entries overwrite earlier decisions for
/// the same permission bit.
pub fn evaluate_permission(
    channel: &crate::Channel,
    ancestors: &[crate::Channel],
    user_id: Option<u32>,
    client: &ClientMembershipQuery,
) -> BitFlags<ACLPermissions> {
    evaluate_permission_with_behavior(channel, ancestors, user_id, client, false)
}

/// Evaluate effective permissions using shared channel ancestors.
pub fn evaluate_permission_shared(
    channel: &crate::Channel,
    ancestors: &[Arc<crate::Channel>],
    user_id: Option<u32>,
    client: &ClientMembershipQuery,
) -> BitFlags<ACLPermissions> {
    evaluate_permission_with_behavior_shared(channel, ancestors, user_id, client, false)
}

/// Evaluate permissions with configurable ACL compatibility behavior.
pub fn evaluate_permission_with_behavior(
    channel: &crate::Channel,
    ancestors: &[crate::Channel],
    user_id: Option<u32>,
    client: &ClientMembershipQuery,
    explicit_enter_deny_overrides_write: bool,
) -> BitFlags<ACLPermissions> {
    evaluate_permission_impl(
        channel,
        ancestors,
        user_id,
        client,
        explicit_enter_deny_overrides_write,
    )
}

/// Evaluate permissions with configurable ACL behavior using shared ancestors.
pub fn evaluate_permission_with_behavior_shared(
    channel: &crate::Channel,
    ancestors: &[Arc<crate::Channel>],
    user_id: Option<u32>,
    client: &ClientMembershipQuery,
    explicit_enter_deny_overrides_write: bool,
) -> BitFlags<ACLPermissions> {
    evaluate_permission_impl(
        channel,
        ancestors,
        user_id,
        client,
        explicit_enter_deny_overrides_write,
    )
}

fn evaluate_permission_impl<A: ChannelReference>(
    channel: &crate::Channel,
    ancestors: &[A],
    user_id: Option<u32>,
    client: &ClientMembershipQuery,
    explicit_enter_deny_overrides_write: bool,
) -> BitFlags<ACLPermissions> {
    if let Some(compiled) = channel
        .effective_acl_cache
        .as_ref()
        .filter(|compiled| compiled.is_current(channel))
    {
        return evaluate_compiled_acl(
            channel.id,
            compiled,
            user_id,
            client,
            explicit_enter_deny_overrides_write,
        );
    }

    if !ancestor_path_allows_traverse(ancestors, user_id, client) {
        return BitFlags::empty();
    }

    evaluate_channel_acl(
        channel,
        ancestors,
        user_id,
        client,
        explicit_enter_deny_overrides_write,
    )
}

fn evaluate_compiled_acl(
    channel_id: u32,
    compiled: &CompiledEffectiveAcl,
    user_id: Option<u32>,
    client: &ClientMembershipQuery,
    explicit_enter_deny_overrides_write: bool,
) -> BitFlags<ACLPermissions> {
    for stage in &compiled.path {
        let mut traverse = true;
        let mut write = false;
        for entry in &stage.entries {
            if !entry.matches(user_id, client) {
                continue;
            }
            if entry.allow.contains(ACLPermissions::Traverse) {
                traverse = true;
            }
            if entry.deny.contains(ACLPermissions::Traverse) {
                traverse = false;
            }
            if entry.allow.contains(ACLPermissions::Write) {
                write = true;
            }
            if entry.deny.contains(ACLPermissions::Write) {
                write = false;
            }
        }
        if !traverse && !write {
            return BitFlags::empty();
        }
    }

    let mut permissions = default_permissions();
    let mut enter_explicitly_denied = false;
    for entry in &compiled.destination {
        if !entry.matches(user_id, client) {
            continue;
        }
        permissions.insert(entry.allow);
        if entry.allow.contains(ACLPermissions::Enter) {
            enter_explicitly_denied = false;
        }
        permissions.remove(entry.deny);
        if entry.deny.contains(ACLPermissions::Enter) {
            enter_explicitly_denied = true;
        }
    }

    finalize_permissions(
        channel_id,
        permissions,
        enter_explicitly_denied,
        explicit_enter_deny_overrides_write,
    )
}

fn evaluate_channel_acl<A: ChannelReference>(
    channel: &crate::Channel,
    ancestors: &[A],
    user_id: Option<u32>,
    client: &ClientMembershipQuery,
    explicit_enter_deny_overrides_write: bool,
) -> BitFlags<ACLPermissions> {
    let mut permissions = default_permissions();
    let mut enter_explicitly_denied = false;
    let target_id = channel.id;
    let evaluation_channel = ChannelHierarchy::from_channels(target_id, ancestors);
    let inherited_len = effective_inherited_len(channel, ancestors);
    let target_acl_channel =
        ChannelHierarchy::from_channels(target_id, &ancestors[..inherited_len]);

    for index in (0..inherited_len).rev() {
        let ancestor = ancestors[index].as_ref();
        let acl_channel =
            ChannelHierarchy::from_channels(ancestor.id, &ancestors[index + 1..inherited_len]);
        apply_permission_acl_entries(
            &ancestor.acls,
            ancestor.id == target_id,
            evaluation_channel,
            acl_channel,
            user_id,
            client,
            &mut permissions,
            &mut enter_explicitly_denied,
        );
    }
    apply_permission_acl_entries(
        &channel.acls,
        true,
        evaluation_channel,
        target_acl_channel,
        user_id,
        client,
        &mut permissions,
        &mut enter_explicitly_denied,
    );

    finalize_permissions(
        target_id,
        permissions,
        enter_explicitly_denied,
        explicit_enter_deny_overrides_write,
    )
}

fn finalize_permissions(
    channel_id: u32,
    mut permissions: BitFlags<ACLPermissions>,
    enter_explicitly_denied: bool,
    explicit_enter_deny_overrides_write: bool,
) -> BitFlags<ACLPermissions> {
    if !permissions.contains(ACLPermissions::Traverse)
        && !permissions.contains(ACLPermissions::Write)
    {
        return BitFlags::empty();
    }

    if permissions.contains(ACLPermissions::Write) {
        permissions.insert(write_implied_permissions());
        if explicit_enter_deny_overrides_write && enter_explicitly_denied {
            permissions.remove(ACLPermissions::Enter);
        }
        if channel_id == 0 {
            permissions.insert(root_only_permissions());
        }
    }

    if channel_id != 0 {
        permissions.remove(root_only_permissions());
    }

    permissions
}

#[allow(clippy::too_many_arguments)]
fn apply_permission_acl_entries(
    acls: &[ACL],
    apply_here: bool,
    evaluation_channel: ChannelHierarchy<'_>,
    acl_channel: ChannelHierarchy<'_>,
    user_id: Option<u32>,
    client: &ClientMembershipQuery,
    permissions: &mut BitFlags<ACLPermissions>,
    enter_explicitly_denied: &mut bool,
) {
    for acl in acls {
        let applies = if apply_here {
            acl.apply_here
        } else {
            acl.apply_subs
        };
        if !applies {
            continue;
        }

        let matches = if let Some(uid) = acl.user_id {
            user_id.is_some_and(|user_id| user_id as i32 == uid)
        } else {
            acl.match_group(evaluation_channel, Some(acl_channel), &[], client)
        };
        if !matches {
            continue;
        }

        permissions.insert(acl.allow);
        if acl.allow.contains(ACLPermissions::Enter) {
            *enter_explicitly_denied = false;
        }
        permissions.remove(acl.deny);
        if acl.deny.contains(ACLPermissions::Enter) {
            *enter_explicitly_denied = true;
        }
    }
}

/// Check each actual ancestor as its own ACL target. This keeps a local
/// `apply_here` Traverse deny as a hard path barrier without preventing the
/// destination from overriding an inherited `apply_subs` deny.
///
/// Only Traverse and Write participate in the path gate. Borrowed channel
/// slices avoid recursively evaluating every permission or rebuilding ID
/// vectors for each ancestor.
fn ancestor_path_allows_traverse<A: ChannelReference>(
    ancestors: &[A],
    user_id: Option<u32>,
    client: &ClientMembershipQuery,
) -> bool {
    (0..ancestors.len()).rev().all(|index| {
        channel_allows_path_traverse(
            ancestors[index].as_ref(),
            &ancestors[index + 1..],
            user_id,
            client,
        )
    })
}

fn channel_allows_path_traverse<A: ChannelReference>(
    channel: &crate::Channel,
    ancestors: &[A],
    user_id: Option<u32>,
    client: &ClientMembershipQuery,
) -> bool {
    let evaluation_channel = ChannelHierarchy::from_channels(channel.id, ancestors);
    let mut traverse = true;
    let mut write = false;
    let inherited_len = if channel.inherit_acl {
        ancestors
            .iter()
            .position(|ancestor| !ancestor.as_ref().inherit_acl)
            .map_or(ancestors.len(), |index| index + 1)
    } else {
        0
    };

    for index in (0..inherited_len).rev() {
        let ancestor = ancestors[index].as_ref();
        let acl_channel = ChannelHierarchy::from_channels(ancestor.id, &ancestors[index + 1..]);
        apply_path_acl_entries(
            &ancestor.acls,
            false,
            evaluation_channel,
            acl_channel,
            user_id,
            client,
            &mut traverse,
            &mut write,
        );
    }
    apply_path_acl_entries(
        &channel.acls,
        true,
        evaluation_channel,
        evaluation_channel,
        user_id,
        client,
        &mut traverse,
        &mut write,
    );
    traverse || write
}

#[allow(clippy::too_many_arguments)]
fn apply_path_acl_entries(
    acls: &[ACL],
    apply_here: bool,
    evaluation_channel: ChannelHierarchy<'_>,
    acl_channel: ChannelHierarchy<'_>,
    user_id: Option<u32>,
    client: &ClientMembershipQuery,
    traverse: &mut bool,
    write: &mut bool,
) {
    for acl in acls {
        let applies = if apply_here {
            acl.apply_here
        } else {
            acl.apply_subs
        };
        if !applies {
            continue;
        }
        let matches = if let Some(uid) = acl.user_id {
            user_id.is_some_and(|user_id| user_id as i32 == uid)
        } else {
            acl.match_group(evaluation_channel, Some(acl_channel), &[], client)
        };
        if !matches {
            continue;
        }
        if acl.allow.contains(ACLPermissions::Traverse) {
            *traverse = true;
        }
        if acl.deny.contains(ACLPermissions::Traverse) {
            *traverse = false;
        }
        if acl.allow.contains(ACLPermissions::Write) {
            *write = true;
        }
        if acl.deny.contains(ACLPermissions::Write) {
            *write = false;
        }
    }
}

fn effective_inherited_len<A: ChannelReference>(
    channel: &crate::Channel,
    ancestors: &[A],
) -> usize {
    if !channel.inherit_acl {
        return 0;
    }

    ancestors
        .iter()
        .position(|ancestor| !ancestor.as_ref().inherit_acl)
        .map_or(ancestors.len(), |index| index + 1)
}

fn any_applicable_effective_acl<A: ChannelReference>(
    channel: &crate::Channel,
    ancestors: &[A],
    mut predicate: impl FnMut(&ACL, ChannelHierarchy<'_>, ChannelHierarchy<'_>) -> bool,
) -> bool {
    let target_id = channel.id;
    let evaluation_channel = ChannelHierarchy::from_channels(target_id, ancestors);
    let inherited_len = effective_inherited_len(channel, ancestors);
    let target_acl_channel =
        ChannelHierarchy::from_channels(target_id, &ancestors[..inherited_len]);

    for index in (0..inherited_len).rev() {
        let ch = ancestors[index].as_ref();
        let acl_channel =
            ChannelHierarchy::from_channels(ch.id, &ancestors[index + 1..inherited_len]);
        for acl in &ch.acls {
            let applies = if ch.id == target_id {
                acl.apply_here
            } else {
                acl.apply_subs
            };
            if applies && predicate(acl, evaluation_channel, acl_channel) {
                return true;
            }
        }
    }

    for acl in &channel.acls {
        if acl.apply_here && predicate(acl, evaluation_channel, target_acl_channel) {
            return true;
        }
    }

    false
}

pub fn effective_acl_chain_has_home_channel_dependent_group(
    channel: &crate::Channel,
    ancestors: &[crate::Channel],
) -> bool {
    effective_acl_chain_has_home_channel_dependent_group_impl(channel, ancestors)
}

/// Check home-channel dependence using shared channel ancestors.
pub fn effective_acl_chain_has_home_channel_dependent_group_shared(
    channel: &crate::Channel,
    ancestors: &[Arc<crate::Channel>],
) -> bool {
    effective_acl_chain_has_home_channel_dependent_group_impl(channel, ancestors)
}

fn effective_acl_chain_has_home_channel_dependent_group_impl<A: ChannelReference>(
    channel: &crate::Channel,
    ancestors: &[A],
) -> bool {
    if let Some(compiled) = channel
        .effective_acl_cache
        .as_ref()
        .filter(|compiled| compiled.is_current(channel))
    {
        return compiled.depends_on_home_channel();
    }

    path_gate_has_home_channel_dependent_group(ancestors)
        || any_applicable_effective_acl(channel, ancestors, |acl, _, _| {
            acl.group
                .as_deref()
                .is_some_and(group_depends_on_home_channel)
        })
}

pub fn effective_acl_chain_home_channel_match_changes(
    channel: &crate::Channel,
    ancestors: &[crate::Channel],
    old_home: ChannelHierarchy<'_>,
    new_home: ChannelHierarchy<'_>,
) -> bool {
    effective_acl_chain_home_channel_match_changes_impl(channel, ancestors, old_home, new_home)
}

/// Check whether a home-channel move changes matching using shared ancestors.
pub fn effective_acl_chain_home_channel_match_changes_shared(
    channel: &crate::Channel,
    ancestors: &[Arc<crate::Channel>],
    old_home: ChannelHierarchy<'_>,
    new_home: ChannelHierarchy<'_>,
) -> bool {
    effective_acl_chain_home_channel_match_changes_impl(channel, ancestors, old_home, new_home)
}

fn effective_acl_chain_home_channel_match_changes_impl<A: ChannelReference>(
    channel: &crate::Channel,
    ancestors: &[A],
    old_home: ChannelHierarchy<'_>,
    new_home: ChannelHierarchy<'_>,
) -> bool {
    if let Some(compiled) = channel
        .effective_acl_cache
        .as_ref()
        .filter(|compiled| compiled.is_current(channel))
    {
        if compiled.path_has_home_channel_dependent_group {
            return true;
        }

        let old_query = ClientMembershipQuery::new(&[], true, &[], None, false, None)
            .with_home_channel(old_home);
        let new_query = ClientMembershipQuery::new(&[], true, &[], None, false, None)
            .with_home_channel(new_home);
        return compiled.destination.iter().any(|entry| {
            entry.depends_on_home_channel()
                && entry.group_matches(&old_query) != entry.group_matches(&new_query)
        });
    }

    if path_gate_has_home_channel_dependent_group(ancestors) {
        return true;
    }

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

fn path_gate_has_home_channel_dependent_group<A: ChannelReference>(ancestors: &[A]) -> bool {
    ancestors.iter().any(|ancestor| {
        ancestor.as_ref().acls.iter().any(|acl| {
            (acl.apply_here || acl.apply_subs)
                && (acl.allow | acl.deny)
                    .intersects(ACLPermissions::Traverse | ACLPermissions::Write)
                && acl
                    .group
                    .as_deref()
                    .is_some_and(group_depends_on_home_channel)
        })
    })
}

/// Check whether the effective ACL chain has any deny rules on the given permission.
/// Used to compute `is_enter_restricted` for `ChannelState` messages.
pub fn channel_has_effective_restriction(
    channel: &crate::Channel,
    ancestors: &[crate::Channel],
    perm: ACLPermissions,
) -> bool {
    channel_has_effective_restriction_impl(channel, ancestors, perm)
}

/// Check an effective restriction using shared channel ancestors.
pub fn channel_has_effective_restriction_shared(
    channel: &crate::Channel,
    ancestors: &[Arc<crate::Channel>],
    perm: ACLPermissions,
) -> bool {
    channel_has_effective_restriction_impl(channel, ancestors, perm)
}

fn channel_has_effective_restriction_impl<A: ChannelReference>(
    channel: &crate::Channel,
    ancestors: &[A],
    perm: ACLPermissions,
) -> bool {
    if let Some(compiled) = channel
        .effective_acl_cache
        .as_ref()
        .filter(|compiled| compiled.is_current(channel))
    {
        return compiled.destination.iter().any(|entry| {
            entry.deny.contains(perm) || entry.deny.contains(ACLPermissions::Traverse)
        });
    }

    any_applicable_effective_acl(channel, ancestors, |acl, _, _| {
        acl.deny.contains(perm) || acl.deny.contains(ACLPermissions::Traverse)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Channel;
    use crate::{ChannelHierarchy, ClientMembershipQuery};

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

    fn scoped_acl(
        user_id: Option<i32>,
        group: Option<&str>,
        apply_here: bool,
        apply_subs: bool,
        allow: BitFlags<ACLPermissions>,
        deny: BitFlags<ACLPermissions>,
    ) -> ACL {
        ACL {
            user_id,
            group: group.map(str::to_owned),
            apply_here,
            apply_subs,
            allow,
            deny,
        }
    }

    fn assert_cached_equivalent(
        channel: &Channel,
        ancestors: &[Channel],
        user_id: Option<u32>,
        client: &ClientMembershipQuery<'_>,
        explicit_enter_deny_overrides_write: bool,
    ) -> BitFlags<ACLPermissions> {
        let expected = evaluate_permission_with_behavior(
            channel,
            ancestors,
            user_id,
            client,
            explicit_enter_deny_overrides_write,
        );
        let mut cached = channel.clone();
        cached.rebuild_effective_acl_cache(ancestors);
        let actual = evaluate_permission_with_behavior(
            &cached,
            &[],
            user_id,
            client,
            explicit_enter_deny_overrides_write,
        );
        assert_eq!(actual, expected);
        actual
    }

    #[test]
    fn compiled_acl_matches_dynamic_and_multiple_group_ordering() {
        let root = Channel::new(0, "Root", 0, 0, None);
        let parent = Channel::new(1, "Parent", 0, 0, Some(0));
        let mut destination = Channel::new(2, "Destination", 0, 0, Some(1));
        destination.acls = vec![
            scoped_acl(
                None,
                Some("all"),
                true,
                false,
                BitFlags::empty(),
                ACLPermissions::Speak.into(),
            ),
            scoped_acl(
                None,
                Some("operators"),
                true,
                false,
                ACLPermissions::Speak.into(),
                BitFlags::empty(),
            ),
            scoped_acl(
                None,
                Some("muted"),
                true,
                false,
                BitFlags::empty(),
                ACLPermissions::Speak.into(),
            ),
            scoped_acl(
                None,
                Some("~sub,-1,0"),
                true,
                false,
                ACLPermissions::Whisper.into(),
                BitFlags::empty(),
            ),
            scoped_acl(
                Some(7),
                None,
                true,
                false,
                ACLPermissions::Speak.into(),
                BitFlags::empty(),
            ),
        ];
        let ancestors = [parent, root];
        let groups = ["operators", "muted"];
        let member = ClientMembershipQuery::new(&groups, true, &[], None, false, None)
            .with_home_channel(ChannelHierarchy::new(4, &[3, 1, 0]));

        let privileged =
            assert_cached_equivalent(&destination, &ancestors, Some(7), &member, false);
        assert!(privileged.contains(ACLPermissions::Speak));
        assert!(privileged.contains(ACLPermissions::Whisper));

        let ordinary = assert_cached_equivalent(&destination, &ancestors, Some(8), &member, false);
        assert!(!ordinary.contains(ACLPermissions::Speak));
        assert!(ordinary.contains(ACLPermissions::Whisper));
    }

    #[test]
    fn compiled_acl_preserves_every_actual_path_barrier() {
        let root = Channel::new(0, "Root", 0, 0, None);
        let mut boundary = Channel::new(1, "Boundary", 0, 0, Some(0));
        boundary.inherit_acl = false;
        boundary.acls = vec![scoped_acl(
            None,
            Some("all"),
            true,
            true,
            BitFlags::empty(),
            ACLPermissions::Traverse.into(),
        )];
        let mut parent = Channel::new(2, "Parent", 0, 0, Some(1));
        parent.acls = vec![scoped_acl(
            None,
            Some("all"),
            true,
            true,
            ACLPermissions::Traverse.into(),
            BitFlags::empty(),
        )];
        let mut destination = Channel::new(3, "Destination", 0, 0, Some(2));
        destination.acls = vec![scoped_acl(
            None,
            Some("all"),
            true,
            false,
            ACLPermissions::Traverse.into(),
            BitFlags::empty(),
        )];
        let ancestors = [parent, boundary, root];
        let client = membership(3, &[2, 1, 0]);

        assert!(
            assert_cached_equivalent(&destination, &ancestors, Some(7), &client, false).is_empty()
        );
    }

    #[test]
    fn compiled_acl_preserves_write_modifiers_and_explicit_enter_behavior() {
        let mut destination = Channel::new(0, "Root", 0, 0, None);
        destination.acls = vec![
            scoped_acl(
                None,
                Some("editors"),
                true,
                false,
                ACLPermissions::Write.into(),
                BitFlags::empty(),
            ),
            scoped_acl(
                None,
                Some("editors"),
                true,
                false,
                BitFlags::empty(),
                ACLPermissions::Enter.into(),
            ),
        ];
        let groups = ["editors"];
        let client = ClientMembershipQuery::new(&groups, true, &[], None, false, None);

        let permissions = assert_cached_equivalent(&destination, &[], Some(7), &client, true);
        assert!(permissions.contains(ACLPermissions::Write));
        assert!(permissions.contains(ACLPermissions::Kick));
        assert!(!permissions.contains(ACLPermissions::Enter));
    }

    #[test]
    fn directly_mutated_channel_does_not_use_stale_compiled_acl() {
        let mut channel = Channel::new(0, "Root", 0, 0, None);
        channel.acls = vec![group_acl(
            "all",
            ACLPermissions::Write.into(),
            BitFlags::empty(),
        )];
        channel.rebuild_effective_acl_cache::<Channel>(&[]);
        assert!(channel.has_effective_acl_cache());

        channel.acls.clear();
        assert!(!channel.has_effective_acl_cache());
        let client = membership(0, &[]);
        let permissions = evaluate_permission(&channel, &[], Some(7), &client);
        assert!(!permissions.contains(ACLPermissions::Write));
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

    #[test]
    fn local_traverse_allow_overrides_inherited_deny() {
        let mut root = Channel::new(0, "Root", 0, 0, None);
        root.acls = vec![
            scoped_acl(
                None,
                Some("all"),
                true,
                false,
                ACLPermissions::Traverse.into(),
                BitFlags::empty(),
            ),
            scoped_acl(
                None,
                Some("all"),
                false,
                true,
                BitFlags::empty(),
                ACLPermissions::Traverse.into(),
            ),
        ];
        let mut child = Channel::new(1, "Allowed", 0, 0, Some(0));
        child.acls = vec![scoped_acl(
            None,
            Some("all"),
            true,
            true,
            ACLPermissions::Traverse.into(),
            BitFlags::empty(),
        )];
        let client = membership(0, &[]);

        assert!(
            evaluate_permission(&child, &[root], Some(1), &client)
                .contains(ACLPermissions::Traverse)
        );
    }

    #[test]
    fn local_traverse_allow_does_not_bypass_denied_ancestor() {
        let root = Channel::new(0, "Root", 0, 0, None);
        let mut parent = Channel::new(1, "Hidden parent", 0, 0, Some(0));
        parent.acls = vec![scoped_acl(
            None,
            Some("all"),
            true,
            false,
            BitFlags::empty(),
            ACLPermissions::Traverse.into(),
        )];
        let mut child = Channel::new(2, "Still hidden", 0, 0, Some(1));
        child.acls = vec![scoped_acl(
            None,
            Some("all"),
            true,
            true,
            ACLPermissions::Traverse.into(),
            BitFlags::empty(),
        )];
        let client = membership(0, &[]);

        assert!(evaluate_permission(&child, &[parent, root], Some(1), &client).is_empty());
    }

    #[test]
    fn effective_chain_keeps_root_to_target_order_after_inheritance_cutoff() {
        let mut root = Channel::new(0, "Excluded root", 0, 0, None);
        root.acls = vec![scoped_acl(
            None,
            Some("all"),
            false,
            true,
            BitFlags::empty(),
            ACLPermissions::Whisper.into(),
        )];

        let mut boundary = Channel::new(1, "Boundary", 0, 0, Some(0));
        boundary.inherit_acl = false;
        boundary.acls = vec![scoped_acl(
            None,
            Some("all"),
            false,
            true,
            BitFlags::empty(),
            ACLPermissions::Speak.into(),
        )];

        let mut parent = Channel::new(2, "Parent", 0, 0, Some(1));
        parent.acls = vec![scoped_acl(
            None,
            Some("all"),
            false,
            true,
            ACLPermissions::Speak.into(),
            BitFlags::empty(),
        )];

        let child = Channel::new(3, "Child", 0, 0, Some(2));
        let client = membership(0, &[]);
        let permissions = evaluate_permission(&child, &[parent, boundary, root], Some(1), &client);

        assert!(permissions.contains(ACLPermissions::Speak));
        assert!(permissions.contains(ACLPermissions::Whisper));
    }

    #[test]
    fn acl_change_classifier_detects_exact_noop() {
        let acls = vec![group_acl(
            "all",
            ACLPermissions::Speak.into(),
            BitFlags::empty(),
        )];

        let impact = classify_acl_change(true, &acls, true, &acls);

        assert!(!impact.state_changed());
        assert!(!impact.inheritance_changed());
        assert!(impact.is_semantically_empty());
        assert!(impact.apply_here().viewer_scope().is_empty());
        assert!(impact.apply_subs().viewer_scope().is_empty());
    }

    #[test]
    fn acl_change_classifier_separates_here_and_sub_permissions() {
        let old = vec![scoped_acl(
            Some(7),
            None,
            true,
            false,
            ACLPermissions::Speak.into(),
            BitFlags::empty(),
        )];
        let new = vec![scoped_acl(
            Some(9),
            None,
            false,
            true,
            ACLPermissions::TextMessage.into(),
            BitFlags::empty(),
        )];

        let impact = classify_acl_change(true, &old, true, &new);

        assert_eq!(impact.apply_here().raw_permissions(), ACLPermissions::Speak);
        assert_eq!(
            impact.apply_subs().raw_permissions(),
            ACLPermissions::TextMessage
        );
        assert_eq!(
            impact.apply_here().viewer_scope().user_ids(),
            &BTreeSet::from([7])
        );
        assert_eq!(
            impact.apply_subs().viewer_scope().user_ids(),
            &BTreeSet::from([9])
        );
    }

    #[test]
    fn traverse_or_write_change_conservatively_expands_to_all_permissions() {
        for permission in [ACLPermissions::Traverse, ACLPermissions::Write] {
            let new = vec![scoped_acl(
                Some(7),
                None,
                true,
                false,
                permission.into(),
                BitFlags::empty(),
            )];

            let impact = classify_acl_change(true, &[], true, &new);

            assert_eq!(impact.apply_here().raw_permissions(), permission);
            assert_eq!(impact.apply_here().effective_permissions(), BitFlags::all());
        }
    }

    #[test]
    fn inheritance_change_is_conservative_for_both_application_modes() {
        let impact = classify_acl_change(false, &[], true, &[]);

        assert!(impact.state_changed());
        assert!(impact.inheritance_changed());
        for change in [impact.apply_here(), impact.apply_subs()] {
            assert_eq!(change.raw_permissions(), BitFlags::all());
            assert_eq!(change.effective_permissions(), BitFlags::all());
            assert!(change.restriction_may_change());
            assert!(change.viewer_scope().includes_all_viewers());
        }
    }

    #[test]
    fn restriction_change_only_tracks_enter_or_traverse_denies() {
        let speak_deny = vec![scoped_acl(
            None,
            Some("moderator"),
            true,
            false,
            BitFlags::empty(),
            ACLPermissions::Speak.into(),
        )];
        let enter_deny = vec![scoped_acl(
            None,
            Some("moderator"),
            true,
            false,
            BitFlags::empty(),
            ACLPermissions::Enter.into(),
        )];

        assert!(
            !classify_acl_change(true, &[], true, &speak_deny)
                .apply_here()
                .restriction_may_change()
        );
        assert!(
            classify_acl_change(true, &[], true, &enter_deny)
                .apply_here()
                .restriction_may_change()
        );
    }

    #[test]
    fn viewer_scope_keeps_plain_groups_but_falls_back_for_dynamic_groups() {
        let plain = vec![
            scoped_acl(
                Some(42),
                Some("all"),
                true,
                false,
                ACLPermissions::Speak.into(),
                BitFlags::empty(),
            ),
            scoped_acl(
                None,
                Some(" Moderators "),
                true,
                false,
                ACLPermissions::TextMessage.into(),
                BitFlags::empty(),
            ),
        ];
        let plain_impact = classify_acl_change(true, &[], true, &plain);
        let scope = plain_impact.apply_here().viewer_scope();
        assert!(!scope.includes_all_viewers());
        assert_eq!(scope.user_ids(), &BTreeSet::from([42]));
        assert_eq!(
            scope.plain_client_groups(),
            &BTreeSet::from(["moderators".to_owned()])
        );

        for dynamic_group in ["all", "auth", "!moderators", "~sub", "#@token", "%#US"] {
            let dynamic = vec![scoped_acl(
                None,
                Some(dynamic_group),
                true,
                false,
                ACLPermissions::Speak.into(),
                BitFlags::empty(),
            )];
            assert!(
                classify_acl_change(true, &[], true, &dynamic)
                    .apply_here()
                    .viewer_scope()
                    .includes_all_viewers(),
                "{dynamic_group} must use conservative viewer scope"
            );
        }
    }

    #[test]
    fn classifier_ignores_unchanged_prefix_and_suffix_subjects() {
        let prefix = scoped_acl(
            None,
            Some("all"),
            true,
            false,
            ACLPermissions::Speak.into(),
            BitFlags::empty(),
        );
        let suffix = scoped_acl(
            None,
            Some("auth"),
            true,
            false,
            ACLPermissions::Enter.into(),
            BitFlags::empty(),
        );
        let old = vec![
            prefix.clone(),
            scoped_acl(
                Some(7),
                None,
                true,
                false,
                ACLPermissions::TextMessage.into(),
                BitFlags::empty(),
            ),
            suffix.clone(),
        ];
        let new = vec![
            prefix,
            scoped_acl(
                Some(9),
                None,
                true,
                false,
                ACLPermissions::TextMessage.into(),
                BitFlags::empty(),
            ),
            suffix,
        ];

        let impact = classify_acl_change(true, &old, true, &new);

        assert!(!impact.apply_here().viewer_scope().includes_all_viewers());
        assert_eq!(
            impact.apply_here().viewer_scope().user_ids(),
            &BTreeSet::from([7, 9])
        );
    }
}
