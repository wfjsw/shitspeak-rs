use std::sync::Arc;

use crate::context_action::{Context, Operation, context};
use shitspeak_messages::messages::encoder::{ContextAction, ContextActionModify};

pub(crate) const ACTION_ID: &str = "shitspeak.toggle_superuser_visibility";
pub(crate) const HIDE_LABEL: &str = "Hide me";
pub(crate) const SHOW_LABEL: &str = "Show me";

pub(crate) fn action(hidden: bool) -> ContextActionModify {
    ContextActionModify {
        action: ACTION_ID.to_owned(),
        text: Some(if hidden { SHOW_LABEL } else { HIDE_LABEL }.to_owned()),
        context: Some(context::SERVER),
        operation: Some(Operation::Add as i32),
    }
}

pub(crate) async fn handle(
    server: &Arc<Box<crate::server::Server>>,
    sender: &Arc<Box<crate::client::Client>>,
    message: &ContextAction,
) -> bool {
    if message.action != ACTION_ID {
        return false;
    }
    if !sender.is_superuser() {
        return true;
    }

    let hidden = sender.is_hidden_from_regular_users();
    if !hidden {
        let mut state = sender.write_global_state_as(server.get_clients(), None, None);
        state.set_hidden_from_regular_users(true);
    } else {
        let server_id = sender.server_id();
        loop {
            let evaluated_channel_id = sender.get_current_channel_id();
            let evaluated_channel_version =
                server.get_channels().current_version_in_server(&server_id);
            let suppress_for_acl = !crate::client::acl::compute_permissions_for_client(
                server,
                sender,
                evaluated_channel_id,
            )
            .await
            .contains(shitspeak_state::ACLPermissions::Speak);
            let mut state = sender.write_global_state_as(
                server.get_clients(),
                None,
                Some(evaluated_channel_version),
            );
            if state.get_current_channel_id() != evaluated_channel_id
                || server.get_channels().current_version_in_server(&server_id)
                    != evaluated_channel_version
            {
                continue;
            }
            state.set_hidden_from_regular_users(false);
            state.set_suppress(suppress_for_acl);
            break;
        }
    }
    refresh_context_menu(server, sender).await;
    true
}

pub(crate) async fn refresh_context_menu(
    server: &Arc<Box<crate::server::Server>>,
    client: &Arc<Box<crate::client::Client>>,
) {
    if !client.is_authenticated() {
        return;
    }

    let tail_action = client
        .is_superuser()
        .then(|| action(client.is_hidden_from_regular_users()));
    let modifications = server
        .context_actions()
        .rebuild_context_with_tail(Context::SERVER, ACTION_ID, tail_action)
        .await;

    let messages = modifications
        .into_iter()
        .map(Into::into)
        .collect::<Vec<shitspeak_messages::messages::Message>>();
    if let Err(error) = client.write_proto_message_batch(&messages).await {
        tracing::debug!(
            error = %error,
            session = u32::from(client.get_session_id()),
            "failed to refresh superuser visibility context menu"
        );
    }
}
