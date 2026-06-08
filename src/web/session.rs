use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::api::{
    AuthenticateAuxiliaryData, AuthenticateResult, AuthenticationRejection, Authenticator,
};
use crate::channel_handler::SessionChannelShadow;
use crate::client::user_info::Credential;
use crate::client::visibility::UserVisibilityState;
use crate::client::{AsyncMessageHandlerExt, Client};
use crate::config::{WebAuthMode, WebConfig};
use crate::messages::Message;
use crate::messages::encoder::{CodecVersion, ServerConfig, ServerSync};
use crate::server::Server;
use crate::web::protocol::{
    AuthRequest, ClientCommand, ServerEvent, WebChannelState, WebCodecVersion, WebPermissionDenied,
    WebServerConfig, WebServerSync, WebUserRemove, WebUserState, WebVolumeAdjustment,
};

#[derive(Clone)]
pub struct WebSessionContext {
    config: WebConfig,
    authenticator: Option<Arc<dyn Authenticator>>,
    server: Option<Arc<Box<Server>>>,
    provisional_server_id: String,
    real_ip: IpAddr,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
}

impl WebSessionContext {
    pub fn new(
        config: WebConfig,
        authenticator: Option<Arc<dyn Authenticator>>,
        server: Option<Arc<Box<Server>>>,
        provisional_server_id: Option<String>,
        real_ip: IpAddr,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> Self {
        Self {
            config,
            authenticator,
            server,
            provisional_server_id: provisional_server_id
                .unwrap_or_else(crate::types::default_server_id),
            real_ip,
            peer_addr,
            local_addr,
        }
    }

    pub fn config(&self) -> &WebConfig {
        &self.config
    }

    pub fn server(&self) -> Option<&Arc<Box<Server>>> {
        self.server.as_ref()
    }

    pub fn real_ip(&self) -> IpAddr {
        self.real_ip
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn auxiliary_data(&self, session_id: u32) -> AuthenticateAuxiliaryData {
        AuthenticateAuxiliaryData {
            certificate_hash: None,
            session_id,
            ip_address: self.real_ip,
            version: None,
            client_name: Some("shitspeak-web".to_string()),
            os_name: Some("browser".to_string()),
            os_version: None,
        }
    }

    pub fn requires_authentication(&self) -> bool {
        (self.config.auth.password_enabled
            && self.config.auth.modes.contains(&WebAuthMode::Password))
            || self.config.auth.modes.contains(&WebAuthMode::Sso)
    }

    pub async fn authenticate(
        &self,
        session_id: u32,
        auth: AuthRequest,
    ) -> Result<AuthenticateResult, AuthenticationRejection> {
        let Some(authenticator) = self.authenticator.as_ref() else {
            return Err(AuthenticationRejection::RetryLater);
        };

        match auth {
            AuthRequest::Password { username, password } => {
                if !self.config.auth.password_enabled
                    || !self.config.auth.modes.contains(&WebAuthMode::Password)
                {
                    return Err(AuthenticationRejection::RetryLater);
                }
                let auxiliary = self.auxiliary_data(session_id);
                authenticator
                    .authenticate(&username, Some(password.as_str()), &auxiliary)
                    .await
            }
            AuthRequest::Sso { token: _ } => Err(AuthenticationRejection::RetryLater),
        }
    }

    pub async fn allocate_authenticated_client(
        &self,
        result: AuthenticateResult,
        outbound_tx: mpsc::Sender<Message>,
        transport: WebSessionTransport,
        cache_username: Option<&str>,
    ) -> Option<(Arc<Box<Server>>, Arc<Box<Client>>, u32, Option<String>)> {
        let server = Arc::clone(self.server.as_ref()?);
        let client = match transport {
            WebSessionTransport::WebRtc => {
                server
                    .get_clients()
                    .allocate_web_client_in_server(
                        result
                            .virtual_server_id
                            .clone()
                            .unwrap_or_else(|| self.provisional_server_id.clone()),
                        self.real_ip,
                        self.peer_addr,
                        self.local_addr,
                        outbound_tx,
                    )
                    .await
            }
            WebSessionTransport::Moq => {
                server
                    .get_clients()
                    .allocate_moq_client_in_server(
                        result
                            .virtual_server_id
                            .clone()
                            .unwrap_or_else(|| self.provisional_server_id.clone()),
                        self.real_ip,
                        self.peer_addr,
                        self.local_addr,
                        outbound_tx,
                    )
                    .await
            }
        };

        let display_name = result.display_name.clone();
        configure_authenticated_client(&server, &client, result, cache_username).await;
        Some((
            server,
            Arc::clone(&client),
            u32::from(client.get_session_id()),
            display_name,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSessionTransport {
    WebRtc,
    Moq,
}

pub async fn configure_authenticated_client(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    result: AuthenticateResult,
    cache_username: Option<&str>,
) {
    let channel_cache_key =
        crate::user_channel_cache::user_channel_cache_key(result.user_id, cache_username);
    client.set_language(result.language);
    client.set_max_bandwidth(result.max_bandwidth);
    client.set_protocol_version(Some(crate::protocol_version::ProtocolVersion::new(1, 5, 0)));
    {
        let mut gs = client.write_global_state(server.get_clients());
        gs.set_user_id(result.user_id);
        gs.set_display_name(result.display_name);
        gs.set_groups(result.groups.into_iter().collect());
    }
    if let Some(username) = cache_username {
        let mut ext = client.user_info_extended().await;
        ext.set_credential(Credential::new(username.to_owned(), None));
    }

    let server_id = client.server_id();
    let restored_channels = crate::user_channel_cache::resolve_login_channels(
        server,
        client,
        channel_cache_key.as_deref(),
    )
    .await;
    let target_ch = restored_channels.current_channel_id;
    client.set_current_channel_id(
        target_ch,
        server.get_clients(),
        server.get_channels().current_version_in_server(&server_id),
    );
    if !restored_channels.listening_channel_ids.is_empty() {
        let mut gs = client.write_global_state(server.get_clients());
        for channel_id in &restored_channels.listening_channel_ids {
            gs.listen_channel(*channel_id);
        }
    }
    if let Some(cache_key) = channel_cache_key.as_deref() {
        if let Err(error) = server
            .get_user_channel_cache()
            .remember_last_channel(cache_key, target_ch)
            .await
        {
            tracing::warn!(
                error = %error,
                cache_key,
                "failed to stage user last channel cache"
            );
        }
        if !restored_channels.listening_channel_ids.is_empty() {
            if let Err(error) = server
                .get_user_channel_cache()
                .remember_listening_channels(
                    cache_key,
                    restored_channels.listening_channel_ids.iter().copied(),
                )
                .await
            {
                tracing::warn!(
                    error = %error,
                    cache_key,
                    "failed to stage user listening channel cache"
                );
            }
        }
    }
    client.set_authenticated(true);
    server
        .get_clients()
        .publish_client_in_server(&server_id, client.get_session_id())
        .await;
    crate::voice::spawn_voice_routing_task(Arc::clone(server), Arc::clone(client));
}

pub fn control_message_from_command(
    client: &Arc<Box<Client>>,
    command: ClientCommand,
) -> Option<Message> {
    match command {
        ClientCommand::Authenticate { .. } => None,
        ClientCommand::JoinChannel { channel_id } => Some(
            crate::messages::encoder::UserState {
                session: Some(client.get_session_id()),
                channel_id: Some(channel_id),
                ..Default::default()
            }
            .into(),
        ),
        ClientCommand::SendText { text } => Some(
            crate::messages::encoder::TextMessage {
                actor: None,
                session: Vec::new(),
                channel_id: vec![client.get_current_channel_id()],
                tree_id: Vec::new(),
                message: text,
            }
            .into(),
        ),
        ClientCommand::SetMute { muted } => Some(
            crate::messages::encoder::UserState {
                session: Some(client.get_session_id()),
                self_mute: Some(muted),
                ..Default::default()
            }
            .into(),
        ),
        ClientCommand::SetDeaf { deafened } => Some(
            crate::messages::encoder::UserState {
                session: Some(client.get_session_id()),
                self_deaf: Some(deafened),
                ..Default::default()
            }
            .into(),
        ),
        ClientCommand::VoiceControl { .. } => None,
    }
}

pub async fn apply_control_command(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    command: ClientCommand,
) -> Result<Option<ServerEvent>, String> {
    if let ClientCommand::VoiceControl { epoch, .. } = command {
        return Ok(Some(ServerEvent::VoiceControlAck { epoch }));
    }

    let Some(message) = control_message_from_command(client, command) else {
        return Ok(None);
    };

    client
        .handle_message(server, message)
        .await
        .map(|()| None)
        .map_err(|error| error.to_string())
}

pub fn server_event_from_message(message: Message) -> Option<ServerEvent> {
    match message {
        Message::UserState(user_state) => Some(ServerEvent::UserState(web_user_state(
            user_state.try_into().ok()?,
        ))),
        Message::UserRemove(remove) => Some(ServerEvent::UserRemove(WebUserRemove {
            session: remove.session,
            actor: remove.actor,
            reason: remove.reason,
            ban: remove.ban,
        })),
        Message::ChannelState(channel_state) => Some(ServerEvent::ChannelState(web_channel_state(
            channel_state.into(),
        ))),
        Message::ChannelRemove(remove) => Some(ServerEvent::ChannelRemove {
            channel_id: remove.channel_id,
        }),
        Message::ServerSync(sync) => Some(ServerEvent::ServerSync(web_server_sync(sync.into()))),
        Message::ServerConfig(config) => {
            Some(ServerEvent::ServerConfig(web_server_config(config.into())))
        }
        Message::PermissionDenied(denied) => Some(ServerEvent::PermissionDenied(
            web_permission_denied(denied.into()),
        )),
        Message::CodecVersion(codec) => Some(ServerEvent::CodecVersion(WebCodecVersion {
            alpha: codec.alpha,
            beta: codec.beta,
            prefer_alpha: codec.prefer_alpha,
            opus: codec.opus,
        })),
        Message::TextMessage(text) => Some(ServerEvent::TextMessage {
            sender_session: text.actor.unwrap_or_default(),
            target_sessions: text.session,
            channel_ids: text.channel_id,
            tree_ids: text.tree_id,
            text: text.message,
        }),
        _ => None,
    }
}

pub fn web_user_state(user_state: crate::messages::encoder::UserState) -> WebUserState {
    WebUserState {
        session: user_state.session.map(u32::from),
        actor: user_state.actor.map(u32::from),
        name: user_state.name,
        user_id: user_state.user_id,
        channel_id: user_state.channel_id,
        mute: user_state.mute,
        deaf: user_state.deaf,
        suppress: user_state.suppress,
        self_mute: user_state.self_mute,
        self_deaf: user_state.self_deaf,
        texture: user_state.texture.map(base64_payload),
        plugin_context: user_state.plugin_context.map(base64_payload),
        plugin_identity: user_state.plugin_identity,
        comment: user_state.comment,
        hash: user_state.hash,
        comment_hash: user_state.comment_hash.map(base64_payload),
        texture_hash: user_state.texture_hash.map(base64_payload),
        priority_speaker: user_state.priority_speaker,
        recording: user_state.recording,
        listening_channel_add: user_state.listening_channel_add,
        listening_channel_remove: user_state.listening_channel_remove,
        listening_volume_adjustment: user_state
            .listening_volume_adjustment
            .into_iter()
            .map(|entry| WebVolumeAdjustment {
                listening_channel: entry.listening_channel,
                volume_adjustment: entry.volume_adjustment,
            })
            .collect(),
    }
}

pub fn web_channel_state(channel_state: crate::messages::encoder::ChannelState) -> WebChannelState {
    WebChannelState {
        channel_id: channel_state.channel_id,
        parent: channel_state.parent,
        name: channel_state.name,
        links: channel_state.links,
        description: channel_state.description,
        links_add: channel_state.links_add,
        links_remove: channel_state.links_remove,
        temporary: channel_state.temporary,
        position: channel_state.position,
        description_hash: channel_state.description_hash.map(base64_payload),
        max_users: channel_state.max_users,
        is_enter_restricted: channel_state.is_enter_restricted,
        can_enter: channel_state.can_enter,
    }
}

pub fn web_server_sync(sync: crate::messages::encoder::ServerSync) -> WebServerSync {
    WebServerSync {
        session: sync.session.map(u32::from),
        max_bandwidth: sync.max_bandwidth,
        welcome_text: sync.welcome_text,
        permissions: sync.permissions.map(|p| p.bits()),
    }
}

pub fn web_server_config(config: crate::messages::encoder::ServerConfig) -> WebServerConfig {
    WebServerConfig {
        max_bandwidth: config.max_bandwidth,
        welcome_text: config.welcome_text,
        allow_html: config.allow_html,
        message_length: config.message_length,
        image_message_length: config.image_message_length,
        max_users: config.max_users,
        recording_allowed: None,
    }
}

pub fn web_permission_denied(
    denied: crate::messages::encoder::PermissionDenied,
) -> WebPermissionDenied {
    WebPermissionDenied {
        deny_type: Some(web_deny_type_name(denied.r#type).to_string()),
        session: Some(denied.session),
        channel_id: denied.channel_id,
        reason: denied.reason.map(std::borrow::Cow::into_owned),
        name: denied.name.map(std::borrow::Cow::into_owned),
        permission: denied.permission,
    }
}

pub async fn initial_server_events(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
) -> Vec<ServerEvent> {
    let server_id = client.server_id();
    let channels = server.get_channels().get_all_in_server(&server_id).await;
    let channels_by_id = channels
        .into_iter()
        .map(|channel| (channel.id, channel))
        .collect::<HashMap<_, _>>();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(0u32);
    let mut visited = std::collections::HashSet::new();
    let mut events = Vec::new();

    while let Some(channel_id) = queue.pop_front() {
        if !visited.insert(channel_id) {
            continue;
        }

        let Some(channel) = channels_by_id.get(&channel_id) else {
            continue;
        };
        let channel_state =
            crate::channel_handler::build_channel_state_message(server, client, channel).await;
        if let Some(event) = server_event_from_message(channel_state.into()) {
            events.push(event);
        }

        let mut children = channels_by_id
            .values()
            .filter(|candidate| candidate.parent_id == Some(channel_id))
            .map(|candidate| candidate.id)
            .collect::<Vec<_>>();
        children.sort_unstable();
        for child in children {
            queue.push_back(child);
        }
    }

    let session_id = client.get_session_id();
    for visible in server
        .get_clients()
        .get_all_clients_in_server(&server_id)
        .await
    {
        if !visible.is_authenticated() {
            continue;
        }
        if visible.get_session_id() == session_id {
            continue;
        }
        let user_state: Message = visible.build_user_state_for_broadcast().into();
        for message in crate::client::visibility::project_message_with_shadow(
            server,
            client,
            user_visibility,
            channel_shadow,
            &server_id,
            &user_state,
        )
        .await
        {
            push_message_event(&mut events, message);
        }
    }

    let self_state: Message = client.build_user_state_for_broadcast().into();
    for message in crate::client::visibility::project_message_with_shadow(
        server,
        client,
        user_visibility,
        channel_shadow,
        &server_id,
        &self_state,
    )
    .await
    {
        push_message_event(&mut events, message);
    }

    let root_permissions =
        crate::client::acl::compute_permissions_for_client(server, client, 0).await;
    push_message_event(
        &mut events,
        ServerSync {
            session: Some(u32::from(session_id)),
            max_bandwidth: Some(client.max_bandwidth(server.get_max_bandwidth())),
            welcome_text: server.get_welcome_text(),
            permissions: Some(root_permissions),
        }
        .into(),
    );

    push_message_event(
        &mut events,
        ServerConfig {
            max_bandwidth: None,
            welcome_text: None,
            allow_html: Some(server.get_allow_html()),
            message_length: Some(server.get_max_text_message_length()),
            image_message_length: Some(server.get_max_image_message_length()),
            max_users: Some(server.get_max_users() as u32),
        }
        .into(),
    );

    push_message_event(
        &mut events,
        CodecVersion {
            alpha: -2147483637,
            beta: 0,
            prefer_alpha: false,
            opus: Some(true),
        }
        .into(),
    );

    events
}

pub async fn send_initial_server_state_with(
    mut send: impl FnMut(ServerEvent) -> io::Result<()>,
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
) -> io::Result<()> {
    for event in initial_server_events(server, client, channel_shadow, user_visibility).await {
        send(event)?;
    }
    Ok(())
}

async fn push_message_with_synthetic(
    events: &mut Vec<ServerEvent>,
    server: &Arc<Box<Server>>,
    channel_shadow: &mut SessionChannelShadow,
    server_id: &str,
    message: &Message,
) {
    push_message_event(events, message.clone());
    let synthetic = crate::channel_handler::sync_shadow_for_client_message(
        server,
        server.get_channels(),
        channel_shadow,
        server_id,
        message,
    )
    .await;
    for message in synthetic {
        push_message_event(events, message);
    }
}

fn push_message_event(events: &mut Vec<ServerEvent>, message: Message) {
    if let Some(event) = server_event_from_message(message) {
        events.push(event);
    }
}

fn base64_payload(bytes: bytes::Bytes) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn web_deny_type_name(deny_type: crate::messages::encoder::DenyType) -> &'static str {
    match deny_type {
        crate::messages::encoder::DenyType::Text => "text",
        crate::messages::encoder::DenyType::Permission => "permission",
        crate::messages::encoder::DenyType::SuperUser => "super_user",
        crate::messages::encoder::DenyType::ChannelName => "channel_name",
        crate::messages::encoder::DenyType::TextTooLong => "text_too_long",
        crate::messages::encoder::DenyType::H9k => "h9k",
        crate::messages::encoder::DenyType::TemporaryChannel => "temporary_channel",
        crate::messages::encoder::DenyType::MissingCertificate => "missing_certificate",
        crate::messages::encoder::DenyType::UserName => "user_name",
        crate::messages::encoder::DenyType::ChannelFull => "channel_full",
        crate::messages::encoder::DenyType::NestingLimit => "nesting_limit",
        crate::messages::encoder::DenyType::ChannelCountLimit => "channel_count_limit",
        crate::messages::encoder::DenyType::ChannelListenerLimit => "channel_listener_limit",
        crate::messages::encoder::DenyType::UserListenerLimit => "user_listener_limit",
    }
}
