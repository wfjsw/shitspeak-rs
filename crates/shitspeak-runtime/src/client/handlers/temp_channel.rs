use crate::{client_repository::ClientRepository, server::Server};
use shitspeak_state::{ChannelOp, ChannelRepository};
use std::sync::Arc;

/// Commit deletion when a temporary channel has no known occupants.
/// A user racing this decision is relocated when the deletion is applied.
pub async fn reap_if_empty_temporary(
    channels: &Arc<ChannelRepository>,
    clients: &Arc<ClientRepository>,
    server_id: &str,
    channel_id: u32,
) -> bool {
    if !channels
        .get_channel_in_server(server_id, channel_id)
        .await
        .is_some_and(|ch| ch.is_temporary())
        || clients
            .has_client_in_channel_in_server(server_id, channel_id)
            .await
    {
        return false;
    }
    match channels
        .delete_channel_in_server(server_id, channel_id)
        .await
    {
        Ok(_) => true,
        Err(error) => {
            tracing::warn!(channel_id, %error, "failed to reap empty temporary channel");
            false
        }
    }
}

pub async fn reap_if_empty_temporary_on_server(
    server: &Server,
    server_id: &str,
    channel_id: u32,
) -> bool {
    let channels = server.get_channels();
    let clients = server.get_clients();
    if !channels
        .get_channel_in_server(server_id, channel_id)
        .await
        .is_some_and(|ch| ch.is_temporary())
        || clients
            .has_client_in_channel_in_server(server_id, channel_id)
            .await
    {
        return false;
    }
    let result = server
        .s2s_manager()
        .propose_channel_op(
            server_id,
            ChannelOp::DeleteChannel {
                id: channel_id,
                nonce: None,
            },
        )
        .await;
    if result.should_apply_locally() {
        channels
            .delete_channel_in_server(server_id, channel_id)
            .await
            .is_ok()
    } else {
        result.is_proposed()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use shitspeak_state::{Channel, ChannelRepoTuning, ChannelRepository, ChannelRootConfig};
    use tokio::sync::mpsc;

    use crate::{
        client::{Client, client_session_identifier::ClientSessionIdentifier},
        client_repository::ClientRepository,
        types::DEFAULT_SERVER_ID,
    };

    use super::reap_if_empty_temporary;

    fn tuning() -> ChannelRepoTuning {
        ChannelRepoTuning {
            log_max_entries: 100,
            snapshot_every_ops: 100,
            snapshot_every_secs: 60,
            wal_compaction_expire_count: 100,
        }
    }

    fn channel_repository() -> Arc<ChannelRepository> {
        ChannelRepository::new_in_memory(1, ChannelRootConfig::new("Root"), tuning())
    }

    fn peer() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30001)
    }

    fn local() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738)
    }

    // ── Invariant 1: temporary channels cannot be parents ───────────────────────
    //
    // The handler in channel_state.rs checks `parent.is_temporary()` and returns
    // PermissionDenied(TemporaryChannel) for both create and reparent operations.
    // These tests verify that the detection mechanism produces the correct result.

    #[tokio::test]
    async fn temp_channel_is_detected_as_temporary() {
        let channels = channel_repository();
        let temp_id = channels
            .next_channel_id_in_server(DEFAULT_SERVER_ID, true)
            .await;
        channels
            .create_channel_in_server(
                DEFAULT_SERVER_ID,
                Channel::new(temp_id, "Temp", 0, 0, Some(0)),
            )
            .await
            .unwrap();

        let ch = channels
            .get_channel_in_server(DEFAULT_SERVER_ID, temp_id)
            .await
            .unwrap();
        assert!(
            ch.is_temporary(),
            "channel with bit-31 set must be detected as temporary so the \
             handler can reject it as a parent"
        );
    }

    #[tokio::test]
    async fn non_temp_channel_is_not_detected_as_temporary() {
        let channels = channel_repository();
        // Root channel (id=0) is always non-temporary.
        let root = channels
            .get_channel_in_server(DEFAULT_SERVER_ID, 0)
            .await
            .unwrap();
        assert!(
            !root.is_temporary(),
            "root channel must not be detected as temporary"
        );
    }

    // ── Invariant 2: creator is moved into the temp channel ─────────────────────
    //
    // After channel_state.rs creates a temporary channel it calls
    // client.set_current_channel_id(new_id, ...).  The tests below verify that
    // set_current_channel_id correctly updates the channel index so a subsequent
    // occupancy query reflects the move.

    #[tokio::test]
    async fn creator_in_temp_channel_is_visible_in_occupancy_index() {
        let channels = channel_repository();
        let clients = Arc::new(ClientRepository::new(1, 128));

        let temp_id = channels
            .next_channel_id_in_server(DEFAULT_SERVER_ID, true)
            .await;
        channels
            .create_channel_in_server(
                DEFAULT_SERVER_ID,
                Channel::new(temp_id, "Temp", 0, 0, Some(0)),
            )
            .await
            .unwrap();

        let (tx, _rx) = mpsc::channel(8);
        let creator = clients
            .allocate_web_client_in_server(
                crate::types::DEFAULT_SERVER_ID,
                peer().ip(),
                peer(),
                local(),
                tx,
            )
            .await;

        // Simulate what the handler does: move creator into new temp channel.
        creator.set_current_channel_id(
            temp_id,
            &clients,
            channels.current_version_in_server(DEFAULT_SERVER_ID),
        );

        let occupants = clients
            .get_local_clients_in_channel_in_server(DEFAULT_SERVER_ID, temp_id)
            .await;
        assert_eq!(
            occupants.len(),
            1,
            "after the creator is moved in, the channel occupancy must be 1"
        );
        assert_eq!(
            creator.get_current_channel_id(),
            temp_id,
            "creator's current channel must be the new temp channel"
        );
    }

    // ── Invariant 3: temp channel is reaped when it becomes empty ───────────────

    #[tokio::test]
    async fn reap_deletes_empty_temporary_channel() {
        let channels = channel_repository();
        let clients = Arc::new(ClientRepository::new(1, 128));

        let temp_id = channels
            .next_channel_id_in_server(DEFAULT_SERVER_ID, true)
            .await;
        channels
            .create_channel_in_server(
                DEFAULT_SERVER_ID,
                Channel::new(temp_id, "Temp", 0, 0, Some(0)),
            )
            .await
            .unwrap();

        assert!(
            channels
                .get_channel_in_server(DEFAULT_SERVER_ID, temp_id)
                .await
                .is_some(),
            "channel must exist before reap"
        );

        let reaped = reap_if_empty_temporary(&channels, &clients, DEFAULT_SERVER_ID, temp_id).await;

        assert!(reaped, "empty temporary channel must be reaped");
        assert!(
            channels
                .get_channel_in_server(DEFAULT_SERVER_ID, temp_id)
                .await
                .is_none(),
            "channel must be gone after reap"
        );
    }

    #[tokio::test]
    async fn reap_does_not_delete_occupied_temporary_channel() {
        let channels = channel_repository();
        let clients = Arc::new(ClientRepository::new(1, 128));

        let temp_id = channels
            .next_channel_id_in_server(DEFAULT_SERVER_ID, true)
            .await;
        channels
            .create_channel_in_server(
                DEFAULT_SERVER_ID,
                Channel::new(temp_id, "Temp", 0, 0, Some(0)),
            )
            .await
            .unwrap();

        let (tx, _rx) = mpsc::channel(8);
        let client = clients
            .allocate_web_client_in_server(
                crate::types::DEFAULT_SERVER_ID,
                peer().ip(),
                peer(),
                local(),
                tx,
            )
            .await;
        client.set_current_channel_id(
            temp_id,
            &clients,
            channels.current_version_in_server(DEFAULT_SERVER_ID),
        );

        let reaped = reap_if_empty_temporary(&channels, &clients, DEFAULT_SERVER_ID, temp_id).await;

        assert!(!reaped, "occupied temporary channel must not be reaped");
        assert!(
            channels
                .get_channel_in_server(DEFAULT_SERVER_ID, temp_id)
                .await
                .is_some(),
            "channel must still exist"
        );
    }

    #[tokio::test]
    async fn reap_does_not_delete_temporary_channel_with_remote_occupant() {
        let channels = channel_repository();
        let clients = Arc::new(ClientRepository::new(1, 128));

        let temp_id = channels
            .next_channel_id_in_server(DEFAULT_SERVER_ID, true)
            .await;
        channels
            .create_channel_in_server(
                DEFAULT_SERVER_ID,
                Channel::new(temp_id, "Temp", 0, 0, Some(0)),
            )
            .await
            .unwrap();

        let remote_session = ClientSessionIdentifier::new(2, 7).unwrap();
        let remote = Arc::new(Client::new_remote_in_server(
            DEFAULT_SERVER_ID.to_owned(),
            remote_session,
            peer().ip(),
            peer(),
            None,
            local(),
            None,
            chrono::Utc::now(),
            99,
        ));
        {
            let mut state = remote.write_global_state_direct();
            state.set_current_channel_id(temp_id);
        }
        clients.add_remote_client(remote_session, remote).await;

        let reaped = reap_if_empty_temporary(&channels, &clients, DEFAULT_SERVER_ID, temp_id).await;

        assert!(
            !reaped,
            "temporary channel with a replicated remote occupant must not be reaped"
        );
        assert!(
            channels
                .get_channel_in_server(DEFAULT_SERVER_ID, temp_id)
                .await
                .is_some(),
            "channel must remain while any node has an occupant"
        );
    }

    #[tokio::test]
    async fn reap_does_not_delete_non_temporary_channel() {
        let channels = channel_repository();
        let clients = Arc::new(ClientRepository::new(1, 128));

        channels
            .create_channel_in_server(DEFAULT_SERVER_ID, Channel::new(1, "Normal", 0, 0, Some(0)))
            .await
            .unwrap();

        let reaped = reap_if_empty_temporary(&channels, &clients, DEFAULT_SERVER_ID, 1).await;

        assert!(!reaped, "non-temporary channel must not be reaped");
        assert!(
            channels
                .get_channel_in_server(DEFAULT_SERVER_ID, 1)
                .await
                .is_some(),
            "non-temporary channel must still exist"
        );
    }

    #[tokio::test]
    async fn reap_fires_after_last_user_moves_out() {
        let channels = channel_repository();
        let clients = Arc::new(ClientRepository::new(1, 128));

        let temp_id = channels
            .next_channel_id_in_server(DEFAULT_SERVER_ID, true)
            .await;
        channels
            .create_channel_in_server(
                DEFAULT_SERVER_ID,
                Channel::new(temp_id, "Temp", 0, 0, Some(0)),
            )
            .await
            .unwrap();

        let (tx, _rx) = mpsc::channel(8);
        let client = clients
            .allocate_web_client_in_server(
                crate::types::DEFAULT_SERVER_ID,
                peer().ip(),
                peer(),
                local(),
                tx,
            )
            .await;
        client.set_current_channel_id(
            temp_id,
            &clients,
            channels.current_version_in_server(DEFAULT_SERVER_ID),
        );

        // Channel occupied — must not be reaped.
        let reaped = reap_if_empty_temporary(&channels, &clients, DEFAULT_SERVER_ID, temp_id).await;
        assert!(!reaped, "should not reap while occupied");

        // Simulate the user moving away (as user_state.rs does).
        client.set_current_channel_id(
            0,
            &clients,
            channels.current_version_in_server(DEFAULT_SERVER_ID),
        );

        // Channel now empty — must be reaped.
        let reaped = reap_if_empty_temporary(&channels, &clients, DEFAULT_SERVER_ID, temp_id).await;
        assert!(
            reaped,
            "temp channel must be reaped after the last occupant moves out"
        );
        assert!(
            channels
                .get_channel_in_server(DEFAULT_SERVER_ID, temp_id)
                .await
                .is_none(),
            "channel must be gone"
        );
    }

    #[tokio::test]
    async fn reap_fires_after_last_user_disconnects() {
        let channels = channel_repository();
        let clients = Arc::new(ClientRepository::new(1, 128));

        let temp_id = channels
            .next_channel_id_in_server(DEFAULT_SERVER_ID, true)
            .await;
        channels
            .create_channel_in_server(
                DEFAULT_SERVER_ID,
                Channel::new(temp_id, "Temp", 0, 0, Some(0)),
            )
            .await
            .unwrap();

        let (tx, _rx) = mpsc::channel(8);
        let client = clients
            .allocate_web_client_in_server(
                crate::types::DEFAULT_SERVER_ID,
                peer().ip(),
                peer(),
                local(),
                tx,
            )
            .await;
        let session_id = client.get_session_id();
        client.set_current_channel_id(
            temp_id,
            &clients,
            channels.current_version_in_server(DEFAULT_SERVER_ID),
        );

        assert_eq!(
            clients
                .get_local_clients_in_channel_in_server(DEFAULT_SERVER_ID, temp_id)
                .await
                .len(),
            1,
            "precondition: one occupant"
        );

        // Simulate the disconnect path: remove client then reap.
        clients
            .remove_client_in_server(DEFAULT_SERVER_ID, session_id)
            .await;

        let reaped = reap_if_empty_temporary(&channels, &clients, DEFAULT_SERVER_ID, temp_id).await;
        assert!(
            reaped,
            "temp channel must be reaped after the occupant disconnects"
        );
        assert!(
            channels
                .get_channel_in_server(DEFAULT_SERVER_ID, temp_id)
                .await
                .is_none(),
            "channel must be gone"
        );
    }
}
