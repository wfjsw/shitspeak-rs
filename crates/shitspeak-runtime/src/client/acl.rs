//! Client-side ACL evaluation helpers.
//!
//! This module provides `compute_permissions_for_client`, which evaluates
//! effective permissions for a given client on a given channel by walking
//! the ACL chain.  It is used by message handlers and the TCP loop.

use std::{collections::HashSet, sync::Arc};

use crate::client::Client;
use crate::server::Server;

use shitspeak_state::{ACL, ACLPermissions, AclViewerScope, Channel, ChannelTreeSnapshot};

/// Borrowed string storage that avoids a heap allocation for ordinary ACL
/// subjects, which generally have only a handful of groups and tokens.
struct BorrowedStrs<'a, const INLINE: usize> {
    inline: [&'a str; INLINE],
    inline_len: usize,
    overflow: Option<Vec<&'a str>>,
}

impl<'a, const INLINE: usize> BorrowedStrs<'a, INLINE> {
    fn from_strings(values: impl IntoIterator<Item = &'a String>) -> Self {
        let mut values = values.into_iter();
        let mut inline = [""; INLINE];
        let mut inline_len = 0;

        while inline_len < INLINE {
            let Some(value) = values.next() else {
                return Self {
                    inline,
                    inline_len,
                    overflow: None,
                };
            };
            inline[inline_len] = value.as_str();
            inline_len += 1;
        }

        let overflow = values.next().map(|first_overflow| {
            let (remaining, _) = values.size_hint();
            let mut overflow = Vec::with_capacity(INLINE + 1 + remaining);
            overflow.extend_from_slice(&inline);
            overflow.push(first_overflow.as_str());
            overflow.extend(values.map(String::as_str));
            overflow
        });

        Self {
            inline,
            inline_len,
            overflow,
        }
    }

    fn as_slice(&self) -> &[&'a str] {
        self.overflow
            .as_deref()
            .unwrap_or(&self.inline[..self.inline_len])
    }
}

/// The ACL portion of one channel before an operation changed it.
///
/// Fan-out reconciliation uses this to evaluate the same tree snapshot both
/// before and after an ACL update without rebuilding or mutating the snapshot.
#[derive(Clone, Debug)]
pub(crate) struct ChannelAclOverride {
    channel_id: u32,
    inherit_acl: bool,
    acls: Vec<ACL>,
}

impl ChannelAclOverride {
    pub(crate) fn new(channel_id: u32, inherit_acl: bool, acls: Vec<ACL>) -> Self {
        Self {
            channel_id,
            inherit_acl,
            acls,
        }
    }

    fn apply_to(&self, channel: &Channel) -> Channel {
        let mut channel = channel.clone();
        channel.inherit_acl = self.inherit_acl;
        channel.acls.clone_from(&self.acls);
        channel
    }
}

/// Operation-scoped ACL inputs for one client.
///
/// Constructing the context captures all client state and performs the GeoIP
/// lookup once. Permission checks after that are synchronous and use the
/// stable channel tree snapshot rather than reacquiring repository locks.
#[derive(Clone)]
pub(crate) struct ClientAclEvaluationContext {
    snapshot: Arc<ChannelTreeSnapshot>,
    session: u32,
    user_id: Option<u32>,
    groups: HashSet<String>,
    tokens: HashSet<String>,
    certificate_hash: Option<Vec<u8>>,
    verified: bool,
    real_ip_address: std::net::IpAddr,
    ip_geo_asn: Option<u32>,
    ip_geo_country: Option<String>,
    home_channel_id: u32,
    home_ancestor_ids: Vec<u32>,
    is_superuser: bool,
    debug_acl_enter: bool,
    explicit_enter_deny_overrides_write: bool,
}

impl ClientAclEvaluationContext {
    pub(crate) async fn new(
        server: &Arc<Box<Server>>,
        client: &Arc<Box<Client>>,
        snapshot: Arc<ChannelTreeSnapshot>,
        home_channel_override: Option<u32>,
    ) -> Self {
        let home_channel_id =
            home_channel_override.unwrap_or_else(|| client.get_current_channel_id());
        let home_ancestor_ids = snapshot
            .ancestor_ids(home_channel_id)
            .unwrap_or_default()
            .to_vec();
        let real_ip_address = client.get_real_ip_address();
        let ip_geo = server.lookup_ip_geo_metadata(real_ip_address).await;

        Self {
            snapshot,
            session: u32::from(client.get_session_id()),
            user_id: client.get_user_id(),
            groups: client.get_groups_clone(),
            tokens: client.get_tokens_clone(),
            certificate_hash: client.get_certificate_hash().map(<[u8]>::to_vec),
            verified: client.is_verified(),
            real_ip_address,
            ip_geo_asn: ip_geo.as_ref().and_then(|geo| geo.asn()),
            ip_geo_country: ip_geo
                .as_ref()
                .and_then(|geo| geo.country_code())
                .map(str::to_owned),
            home_channel_id,
            home_ancestor_ids,
            is_superuser: client.is_superuser(),
            debug_acl_enter: server.get_debug_acl_enter(),
            explicit_enter_deny_overrides_write: server.get_explicit_enter_deny_overrides_write(),
        }
    }

    pub(crate) fn evaluate(&self, channel_id: u32) -> enumflags2::BitFlags<ACLPermissions> {
        self.evaluate_inner(channel_id, None)
    }

    pub(crate) fn evaluate_with_acl_override(
        &self,
        channel_id: u32,
        acl_override: &ChannelAclOverride,
    ) -> enumflags2::BitFlags<ACLPermissions> {
        self.evaluate_inner(channel_id, Some(acl_override))
    }

    pub(crate) fn is_enter_restricted(&self, channel_id: u32) -> bool {
        self.is_enter_restricted_inner(channel_id, None)
    }

    pub(crate) fn is_enter_restricted_with_acl_override(
        &self,
        channel_id: u32,
        acl_override: &ChannelAclOverride,
    ) -> bool {
        self.is_enter_restricted_inner(channel_id, Some(acl_override))
    }

    fn is_enter_restricted_inner(
        &self,
        channel_id: u32,
        acl_override: Option<&ChannelAclOverride>,
    ) -> bool {
        let Some(snapshot_channel) = self.snapshot.channel(channel_id) else {
            return false;
        };
        let overridden_channel = acl_override
            .filter(|acl_override| acl_override.channel_id == channel_id)
            .map(|acl_override| acl_override.apply_to(snapshot_channel));
        let channel = overridden_channel.as_ref().unwrap_or(snapshot_channel);
        let ancestors = self
            .snapshot
            .ancestor_ids(channel_id)
            .unwrap_or_default()
            .iter()
            .filter_map(|ancestor_id| {
                let ancestor = self.snapshot.channel(*ancestor_id)?;
                Some(match acl_override {
                    Some(acl_override) if acl_override.channel_id == *ancestor_id => {
                        acl_override.apply_to(ancestor)
                    }
                    _ => ancestor.clone(),
                })
            })
            .collect::<Vec<_>>();
        shitspeak_state::channel_has_effective_restriction(
            channel,
            &ancestors,
            ACLPermissions::Traverse,
        ) || shitspeak_state::channel_has_effective_restriction(
            channel,
            &ancestors,
            ACLPermissions::Enter,
        )
    }

    fn evaluate_inner(
        &self,
        channel_id: u32,
        acl_override: Option<&ChannelAclOverride>,
    ) -> enumflags2::BitFlags<ACLPermissions> {
        let Some(snapshot_channel) = self.snapshot.channel(channel_id) else {
            tracing::trace!(
                session = self.session,
                channel_id,
                "ACL snapshot compute found no channel"
            );
            return enumflags2::BitFlags::empty();
        };

        let overridden_channel = acl_override
            .filter(|acl_override| acl_override.channel_id == channel_id)
            .map(|acl_override| acl_override.apply_to(snapshot_channel));
        let channel = overridden_channel.as_ref().unwrap_or(snapshot_channel);
        let ancestors = self
            .snapshot
            .ancestor_ids(channel_id)
            .unwrap_or_default()
            .iter()
            .filter_map(|ancestor_id| {
                let ancestor = self.snapshot.channel(*ancestor_id)?;
                Some(match acl_override {
                    Some(acl_override) if acl_override.channel_id == *ancestor_id => {
                        acl_override.apply_to(ancestor)
                    }
                    _ => ancestor.clone(),
                })
            })
            .collect::<Vec<_>>();

        let group_refs = BorrowedStrs::<8>::from_strings(&self.groups);
        let token_refs = BorrowedStrs::<8>::from_strings(&self.tokens);
        let membership = shitspeak_state::ClientMembershipQuery::new(
            group_refs.as_slice(),
            self.user_id.is_some(),
            token_refs.as_slice(),
            self.certificate_hash.as_deref(),
            self.verified,
            Some(self.real_ip_address),
        )
        .with_ip_metadata(self.ip_geo_asn, self.ip_geo_country.as_deref())
        .with_home_channel(shitspeak_state::ChannelHierarchy::new(
            self.home_channel_id,
            &self.home_ancestor_ids,
        ));

        let permissions = shitspeak_state::evaluate_permission_with_behavior(
            channel,
            &ancestors,
            self.user_id,
            &membership,
            self.explicit_enter_deny_overrides_write,
        );
        let permissions = elevate_superuser_permissions(
            permissions,
            channel_id,
            self.is_superuser,
            self.debug_acl_enter,
        );

        tracing::trace!(
            session = self.session,
            channel_id,
            user_id = self.user_id,
            home_channel_id = self.home_channel_id,
            is_superuser = self.is_superuser,
            debug_acl_enter = self.debug_acl_enter,
            explicit_enter_deny_overrides_write = self.explicit_enter_deny_overrides_write,
            has_acl_override = acl_override.is_some(),
            permissions = ?permissions,
            "Computed snapshot ACL permissions"
        );

        permissions
    }
}

/// Whether an operation-local ACL viewer scope can affect this client.
///
/// The state classifier only exposes exact user ids and ordinary client
/// groups here. Dynamic group expressions are classified as all-viewer by
/// the repository and therefore never reach the exact matching branches.
pub(crate) fn client_matches_acl_viewer_scope(
    client: &Arc<Box<Client>>,
    scope: &AclViewerScope,
) -> bool {
    if scope.includes_all_viewers() {
        return true;
    }
    if client
        .get_user_id()
        .is_some_and(|user_id| scope.user_ids().contains(&(user_id as i32)))
    {
        return true;
    }
    client.get_groups_clone().iter().any(|group| {
        scope
            .plain_client_groups()
            .contains(&group.trim().to_ascii_lowercase())
    })
}

fn elevate_superuser_permissions(
    permissions: enumflags2::BitFlags<ACLPermissions>,
    channel_id: u32,
    is_superuser: bool,
    debug_acl_enter: bool,
) -> enumflags2::BitFlags<ACLPermissions> {
    if !is_superuser {
        return permissions;
    }

    let allow_speak = permissions.contains(ACLPermissions::Speak);
    let allow_whisper = permissions.contains(ACLPermissions::Whisper);
    let allow_enter = permissions.contains(ACLPermissions::Enter);
    let mut elevated: enumflags2::BitFlags<ACLPermissions> = enumflags2::BitFlags::all();
    elevated.remove(ACLPermissions::Speak | ACLPermissions::Whisper);
    if !debug_acl_enter {
        elevated.remove(ACLPermissions::Enter);
    }
    if allow_speak {
        elevated.insert(ACLPermissions::Speak);
    }
    if allow_whisper {
        elevated.insert(ACLPermissions::Whisper);
    }
    if !debug_acl_enter && allow_enter {
        elevated.insert(ACLPermissions::Enter);
    }
    if channel_id != 0 {
        elevated.remove(
            ACLPermissions::Kick
                | ACLPermissions::Ban
                | ACLPermissions::Register
                | ACLPermissions::SelfRegister
                | ACLPermissions::ResetUserContent,
        );
    }
    elevated
}

/// Compute effective permissions for a client on a given channel.
pub async fn compute_permissions_for_client(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_id: u32,
) -> enumflags2::BitFlags<shitspeak_state::ACLPermissions> {
    compute_permissions_for_client_inner(server, client, channel_id, None, None).await
}

/// Compute permissions as if the client were already in `channel_id`.
///
/// This is intentionally separate from the normal helper: moving into a
/// channel must check Enter permissions from the client's real current channel,
/// but the resulting suppress state depends on Speak after the move.
pub async fn compute_permissions_for_client_as_if_in_channel(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_id: u32,
) -> enumflags2::BitFlags<shitspeak_state::ACLPermissions> {
    compute_permissions_for_client_with_home_channel(server, client, channel_id, channel_id).await
}

/// Compute permissions for `channel_id` using an explicit home channel.
///
/// Client-log projection uses this when the live client has already advanced
/// beyond the entry currently being rendered. Explicit-home evaluations are
/// deliberately uncached because the cache is keyed to the live home state.
pub(crate) async fn compute_permissions_for_client_with_home_channel(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_id: u32,
    home_channel_id: u32,
) -> enumflags2::BitFlags<shitspeak_state::ACLPermissions> {
    compute_permissions_for_client_inner(server, client, channel_id, Some(home_channel_id), None)
        .await
}

pub(crate) async fn compute_permissions_for_client_with_identity(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_id: u32,
    user_id: Option<u32>,
    groups: HashSet<String>,
    is_superuser: bool,
) -> enumflags2::BitFlags<shitspeak_state::ACLPermissions> {
    compute_permissions_for_client_inner(
        server,
        client,
        channel_id,
        None,
        Some((user_id, groups, is_superuser)),
    )
    .await
}

async fn compute_permissions_for_client_inner(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_id: u32,
    home_channel_override: Option<u32>,
    identity_override: Option<(Option<u32>, HashSet<String>, bool)>,
) -> enumflags2::BitFlags<ACLPermissions> {
    let session = u32::from(client.get_session_id());
    let is_superuser = identity_override
        .as_ref()
        .map_or_else(|| client.is_superuser(), |(_, _, value)| *value);
    let debug_acl_enter = server.get_debug_acl_enter();
    let explicit_enter_deny_overrides_write = server.get_explicit_enter_deny_overrides_write();

    let channels = server.get_channels();
    let (client_acl_subject_generation, client_acl_home_generation) =
        client.get_acl_cache_generations();
    let use_acl_cache =
        !is_superuser && home_channel_override.is_none() && identity_override.is_none();

    let cached_permissions = if use_acl_cache {
        client.with_server_id(|server_id| {
            let channel_acl_generation =
                channels.channel_acl_generation_for_channel(server_id, channel_id);
            let (permissions, depends_on_home_channel) = client.get_cached_acl_permissions(
                channel_id,
                channel_acl_generation,
                client_acl_subject_generation,
                client_acl_home_generation,
                explicit_enter_deny_overrides_write,
            )?;
            let (current_subject_generation, current_home_generation) =
                client.get_acl_cache_generations();
            (channels.channel_acl_generation_for_channel(server_id, channel_id)
                == channel_acl_generation
                && current_subject_generation == client_acl_subject_generation
                && (!depends_on_home_channel
                    || current_home_generation == client_acl_home_generation))
                .then_some(permissions)
        })
    } else {
        None
    };
    if let Some(permissions) = cached_permissions {
        tracing::trace!(
            session,
            channel_id,
            permissions = ?permissions,
            "ACL cache hit"
        );
        return permissions;
    }

    let server_id = client.server_id();
    let (channel_acl_generation, channel, ancestors) = channels
        .get_channel_with_ancestors_for_acl_in_server(&server_id, channel_id)
        .await;
    let Some(channel) = channel else {
        tracing::trace!(session, channel_id, "ACL compute found no channel");
        return enumflags2::BitFlags::empty();
    };
    let depends_on_home_channel =
        shitspeak_state::effective_acl_chain_has_home_channel_dependent_group(&channel, &ancestors);

    let (user_id, groups) = match identity_override {
        Some((user_id, groups, _)) => (user_id, groups),
        None => (client.get_user_id(), client.get_groups_clone()),
    };
    let group_refs = BorrowedStrs::<8>::from_strings(&groups);
    let tokens = client.get_tokens_clone();
    let token_refs = BorrowedStrs::<8>::from_strings(&tokens);
    let home_channel_id = home_channel_override.unwrap_or_else(|| client.get_current_channel_id());
    let home_ancestors: Vec<u32> = if home_channel_id == channel_id {
        ancestors.iter().map(|ancestor| ancestor.id).collect()
    } else {
        channels
            .get_ancestors_in_server(&server_id, home_channel_id)
            .await
            .into_iter()
            .map(|ancestor| ancestor.id)
            .collect()
    };
    let home_channel = shitspeak_state::ChannelHierarchy::new(home_channel_id, &home_ancestors);
    let ip_geo = server
        .lookup_ip_geo_metadata(client.get_real_ip_address())
        .await;
    let ip_geo_asn = ip_geo.as_ref().and_then(|geo| geo.asn());
    let ip_geo_country = ip_geo.as_ref().and_then(|geo| geo.country_code());

    let membership = shitspeak_state::ClientMembershipQuery::new(
        group_refs.as_slice(),
        user_id.is_some(),
        token_refs.as_slice(),
        client.get_certificate_hash(),
        client.is_verified(),
        Some(client.get_real_ip_address()),
    )
    .with_ip_metadata(ip_geo_asn, ip_geo_country)
    .with_home_channel(home_channel);

    tracing::trace!(
        session,
        channel_id,
        user_id,
        authenticated = membership.authenticated(),
        groups = ?group_refs.as_slice(),
        tokens = ?token_refs.as_slice(),
        home_channel_id,
        home_channel_override,
        ancestors = ancestors.len(),
        is_superuser,
        explicit_enter_deny_overrides_write,
        "Computing ACL permissions"
    );

    let mut permissions = shitspeak_state::evaluate_permission_with_behavior(
        &channel,
        &ancestors,
        user_id,
        &membership,
        explicit_enter_deny_overrides_write,
    );

    permissions =
        elevate_superuser_permissions(permissions, channel_id, is_superuser, debug_acl_enter);

    tracing::trace!(
        session,
        channel_id,
        user_id,
        is_superuser,
        debug_acl_enter,
        explicit_enter_deny_overrides_write,
        permissions = ?permissions,
        "Computed ACL permissions"
    );

    if use_acl_cache {
        client.with_server_id(|current_server_id| {
            let (current_subject_generation, current_home_generation) =
                client.get_acl_cache_generations();
            if current_server_id == server_id
                && channels.channel_acl_generation_for_channel(current_server_id, channel_id)
                    == channel_acl_generation
                && current_subject_generation == client_acl_subject_generation
                && (!depends_on_home_channel
                    || current_home_generation == client_acl_home_generation)
            {
                client.cache_acl_permissions(
                    channel_id,
                    channel_acl_generation,
                    client_acl_subject_generation,
                    client_acl_home_generation,
                    depends_on_home_channel,
                    explicit_enter_deny_overrides_write,
                    permissions,
                );
            }
        });
    }

    permissions
}

#[cfg(test)]
mod tests {
    use super::{BorrowedStrs, ChannelAclOverride, elevate_superuser_permissions};
    use shitspeak_state::{ACL, ACLPermissions, Channel};

    #[test]
    fn superuser_elevation_preserves_acl_controlled_voice_and_enter_permissions() {
        let evaluated = ACLPermissions::Speak | ACLPermissions::Enter;
        let elevated = elevate_superuser_permissions(evaluated, 7, true, false);

        assert!(elevated.contains(ACLPermissions::Speak));
        assert!(!elevated.contains(ACLPermissions::Whisper));
        assert!(elevated.contains(ACLPermissions::Enter));
        assert!(!elevated.contains(ACLPermissions::Kick));

        let denied_enter =
            elevate_superuser_permissions(enumflags2::BitFlags::empty(), 7, true, false);
        assert!(!denied_enter.contains(ACLPermissions::Enter));

        let debug_enter =
            elevate_superuser_permissions(enumflags2::BitFlags::empty(), 7, true, true);
        assert!(debug_enter.contains(ACLPermissions::Enter));
    }

    #[test]
    fn acl_override_only_replaces_acl_state() {
        let mut channel = Channel::new(7, "target", 3, 42, Some(1));
        channel.inherit_acl = true;
        channel.acls.push(ACL::new());

        let mut old_acl = ACL::new();
        old_acl.group = Some("all".to_owned());
        old_acl.deny = ACLPermissions::Traverse.into();
        let overridden =
            ChannelAclOverride::new(7, false, vec![old_acl.clone()]).apply_to(&channel);

        assert_eq!(overridden.id, channel.id);
        assert_eq!(overridden.name, channel.name);
        assert_eq!(overridden.parent_id, channel.parent_id);
        assert_eq!(overridden.position, channel.position);
        assert_eq!(overridden.max_users, channel.max_users);
        assert!(!overridden.inherit_acl);
        assert_eq!(overridden.acls, vec![old_acl]);
    }

    #[test]
    fn borrowed_strings_stay_inline_until_capacity_is_exceeded() {
        let values = ["one".to_owned(), "two".to_owned()];
        let refs = BorrowedStrs::<2>::from_strings(&values);

        assert!(refs.overflow.is_none());
        assert_eq!(refs.as_slice(), ["one", "two"]);

        let values = ["one".to_owned(), "two".to_owned(), "three".to_owned()];
        let refs = BorrowedStrs::<2>::from_strings(&values);

        assert!(refs.overflow.is_some());
        assert_eq!(refs.as_slice(), ["one", "two", "three"]);
    }
}
