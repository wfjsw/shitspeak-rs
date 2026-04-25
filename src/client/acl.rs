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
    // Superuser bypasses all ACL checks
    if client.is_superuser().await {
        return enumflags2::BitFlags::all();
    }

    // Single lock acquisition for channel + ancestors
    let (channel, ancestors) = server.get_channels().get_channel_with_ancestors(channel_id).await;
    let Some(channel) = channel else {
        return enumflags2::BitFlags::empty();
    };

    let user_id = client.get_user_id().await;
    let groups: Vec<String> = client.get_groups_clone().await.into_iter().collect();
    let group_refs: Vec<&str> = groups.iter().map(|s| s.as_str()).collect();
    let tokens: Vec<String> = client.get_tokens_clone().await.into_iter().collect();
    let token_refs: Vec<&str> = tokens.iter().map(|s| s.as_str()).collect();

    let membership = crate::client::group::ClientMembershipQuery {
        groups: &group_refs,
        authenticated: client.is_authenticated().await,
        access_tokens: &token_refs,
        cert_hash: client.get_certificate_hash(),
        has_verified_cert_chain: client.has_certificate(),
        ip_address: Some(client.get_real_ip_address()),
        asn: None,
        country_code: None,
    };

    crate::acl::evaluate_permission(
        &channel,
        &ancestors,
        user_id,
        &membership,
        channel_id,
    )
}
