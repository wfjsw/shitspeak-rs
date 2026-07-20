//! Client-side ACL evaluation helpers.
//!
//! This module provides `compute_permissions_for_client`, which evaluates
//! effective permissions for a given client on a given channel by walking
//! the ACL chain.  It is used by message handlers and the TCP loop.

use std::sync::Arc;

use crate::client::Client;
use crate::server::Server;

/// Compute effective permissions for a client on a given channel.
pub async fn compute_permissions_for_client(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_id: u32,
) -> enumflags2::BitFlags<shitspeak_state::ACLPermissions> {
    compute_permissions_for_client_inner(server, client, channel_id, None).await
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
    compute_permissions_for_client_inner(server, client, channel_id, Some(home_channel_id)).await
}

async fn compute_permissions_for_client_inner(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_id: u32,
    home_channel_override: Option<u32>,
) -> enumflags2::BitFlags<shitspeak_state::ACLPermissions> {
    use shitspeak_state::ACLPermissions;

    let session = u32::from(client.get_session_id());
    let is_superuser = client.is_superuser();
    let debug_acl_enter = server.get_debug_acl_enter();
    let explicit_enter_deny_overrides_write = server.get_explicit_enter_deny_overrides_write();

    let channels = server.get_channels();
    let server_id = client.server_id();
    let (client_acl_subject_generation, client_acl_home_generation) =
        client.get_acl_cache_generations();
    let channel_acl_generation =
        channels.channel_acl_generation_for_channel(&server_id, channel_id);
    let cache_session = u64::from(session);
    let cache_client_instance = client.client_instance_id();
    let use_acl_cache = !is_superuser && home_channel_override.is_none();

    if use_acl_cache
        && let Some(cache_hit) = channels
            .get_cached_permissions_in_server_with_generations(
                &server_id,
                cache_session,
                cache_client_instance,
                channel_id,
                channel_acl_generation,
                client_acl_subject_generation,
                client_acl_home_generation,
                explicit_enter_deny_overrides_write,
            )
            .await
    {
        let (current_subject_generation, current_home_generation) =
            client.get_acl_cache_generations();
        if channels.channel_acl_generation_for_channel(&server_id, channel_id)
            == channel_acl_generation
            && current_subject_generation == client_acl_subject_generation
            && (!cache_hit.depends_on_home_channel()
                || current_home_generation == client_acl_home_generation)
        {
            let permissions = cache_hit.permissions();
            tracing::trace!(
                session,
                channel_id,
                permissions = ?permissions,
                "ACL cache hit"
            );
            return permissions;
        }
    }

    let (channel_acl_generation, channel, ancestors) = channels
        .get_channel_with_ancestors_for_acl_in_server(&server_id, channel_id)
        .await;
    let Some(channel) = channel else {
        tracing::trace!(session, channel_id, "ACL compute found no channel");
        return enumflags2::BitFlags::empty();
    };
    let depends_on_home_channel =
        shitspeak_state::effective_acl_chain_has_home_channel_dependent_group(&channel, &ancestors);

    let user_id = client.get_user_id();
    let groups: Vec<String> = client.get_groups_clone().into_iter().collect();
    let group_refs: Vec<&str> = groups.iter().map(|s| s.as_str()).collect();
    let tokens: Vec<String> = client.get_tokens_clone().into_iter().collect();
    let token_refs: Vec<&str> = tokens.iter().map(|s| s.as_str()).collect();
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
        &group_refs,
        user_id.is_some(),
        &token_refs,
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
        groups = ?group_refs,
        tokens = ?token_refs,
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

    if is_superuser {
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
        permissions = elevated;
    }

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

    let (current_subject_generation, current_home_generation) = client.get_acl_cache_generations();
    if use_acl_cache
        && channels.channel_acl_generation_for_channel(&server_id, channel_id)
            == channel_acl_generation
        && current_subject_generation == client_acl_subject_generation
        && (!depends_on_home_channel || current_home_generation == client_acl_home_generation)
    {
        channels
            .cache_permissions_in_server_with_generations(
                &server_id,
                cache_session,
                cache_client_instance,
                channel_id,
                channel_acl_generation,
                client_acl_subject_generation,
                client_acl_home_generation,
                depends_on_home_channel,
                explicit_enter_deny_overrides_write,
                permissions,
            )
            .await;
    }

    permissions
}
