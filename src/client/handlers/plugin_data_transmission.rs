use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::client::client_session_identifier::ClientSessionIdentifier;
use crate::{
    client::Client,
    errors::MessageHandlerError,
    messages::{encoder::PluginDataTransmission, Message},
    s2s::application::proto::PluginDataEnvelope,
    server::Server,
};

pub async fn handle_plugin_data_transmission(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: PluginDataTransmission,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated() {
        return Err(MessageHandlerError::protocol_violation(
            "PluginDataTransmission message received before authentication",
        ));
    }

    let sender_session = u32::from(sender.get_session_id());
    tracing::debug!(
        session = sender_session,
        receivers = msg.receiver_sessions.len(),
        data_id = msg.data_id.as_deref(),
        "PluginDataTransmission handler"
    );

    let mut unique_receivers = BTreeSet::new();
    for receiver in msg.receiver_sessions {
        if receiver != sender_session {
            unique_receivers.insert(receiver);
        }
    }
    if unique_receivers.is_empty() {
        return Ok(());
    }

    let relay = PluginDataTransmission {
        sender_session: Some(sender_session),
        receiver_sessions: unique_receivers.iter().copied().collect(),
        data: msg.data,
        data_id: msg.data_id,
    };
    let relay_message: Message = relay.clone().into();
    let local_node_id = server.get_clients().local_node_id();
    let mut remote_by_node: BTreeMap<u16, Vec<u32>> = BTreeMap::new();

    for receiver in &relay.receiver_sessions {
        let id = ClientSessionIdentifier::from(*receiver);
        if id.get_node_id() == local_node_id {
            server.get_clients().send_to(id, &relay_message).await;
        } else {
            remote_by_node
                .entry(id.get_node_id())
                .or_default()
                .push(*receiver);
        }
    }

    if remote_by_node.is_empty() {
        return Ok(());
    }

    if let Some(app) = server.s2s_manager().application() {
        for (node_id, receiver_sessions) in remote_by_node {
            let envelope = PluginDataEnvelope {
                sender_session,
                receiver_sessions,
                data: relay.data.clone().unwrap_or_default(),
                data_id: relay.data_id.clone(),
            };
            if let Err(e) = app.plugin_data().dispatch(node_id, envelope).await {
                tracing::warn!(
                    error = %e,
                    node_id,
                    "plugin data dispatch failed",
                );
            }
        }
    } else {
        tracing::trace!("cross-node PluginDataTransmission dropped: ApplicationLayer not attached");
    }

    Ok(())
}
