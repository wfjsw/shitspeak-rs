//! Client-side ACL evaluation helpers.
//!
//! This module provides `compute_permissions_for_client`, which evaluates
//! effective permissions for a given client on a given channel by walking
//! the ACL chain.  It is used by message handlers and the TCP loop.

use std::sync::Arc;

use crate::client::Client;
use crate::server::Server;

/// Compute effective permissions for a client on a given channel.
pub(crate) async fn compute_permissions_for_client(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_id: u32,
) -> enumflags2::BitFlags<crate::acl::ACLPermissions> {
    use crate::acl::ACLPermissions;

    let session = u32::from(client.get_session_id());
    let is_superuser = client.is_superuser();
    let debug_acl_enter = server.get_debug_acl_enter();

    let channels = server.get_channels();
    let server_id = client.server_id();
    let client_acl_generation = client.get_acl_generation();
    let channel_acl_generation = channels.channel_acl_generation();
    let cache_session = u64::from(session);
    let use_acl_cache = !is_superuser;

    if use_acl_cache
        && let Some(permissions) = channels
            .get_cached_permissions_in_server(
                &server_id,
                cache_session,
                channel_id,
                channel_acl_generation,
                client_acl_generation,
            )
            .await
    {
        tracing::trace!(
            session,
            channel_id,
            permissions = ?permissions,
            "ACL cache hit"
        );
        return permissions;
    }

    let (channel_acl_generation, channel, ancestors) = channels
        .get_channel_with_ancestors_for_acl_in_server(&server_id, channel_id)
        .await;
    let Some(channel) = channel else {
        tracing::trace!(session, channel_id, "ACL compute found no channel");
        return enumflags2::BitFlags::empty();
    };

    let user_id = client.get_user_id();
    let groups: Vec<String> = client.get_groups_clone().into_iter().collect();
    let group_refs: Vec<&str> = groups.iter().map(|s| s.as_str()).collect();
    let tokens: Vec<String> = client.get_tokens_clone().into_iter().collect();
    let token_refs: Vec<&str> = tokens.iter().map(|s| s.as_str()).collect();

    let membership = crate::client::group::ClientMembershipQuery {
        groups: &group_refs,
        authenticated: user_id.is_some(),
        access_tokens: &token_refs,
        cert_hash: client.get_certificate_hash(),
        has_verified_cert_chain: client.is_verified(),
        ip_address: Some(client.get_real_ip_address()),
        asn: None,
        country_code: None,
    };

    tracing::trace!(
        session,
        channel_id,
        user_id,
        authenticated = membership.authenticated,
        groups = ?group_refs,
        tokens = ?token_refs,
        ancestors = ancestors.len(),
        is_superuser,
        "Computing ACL permissions"
    );

    let mut permissions =
        crate::acl::evaluate_permission(&channel, &ancestors, user_id, &membership, channel_id);

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
        permissions = ?permissions,
        "Computed ACL permissions"
    );

    if use_acl_cache
        && channels.channel_acl_generation() == channel_acl_generation
        && client.get_acl_generation() == client_acl_generation
    {
        channels
            .cache_permissions_in_server(
                &server_id,
                cache_session,
                channel_id,
                channel_acl_generation,
                client_acl_generation,
                permissions,
            )
            .await;
    }

    permissions
}
