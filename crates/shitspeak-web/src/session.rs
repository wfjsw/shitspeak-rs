use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::protocol::{
    AuthRequest, ClientCommand, ServerEvent, WebChannelState, WebCodecVersion, WebPermissionDenied,
    WebServerConfig, WebServerSync, WebUserRemove, WebUserState, WebVolumeAdjustment,
};
use shitspeak_auth::{
    AuthenticateAuxiliaryData, AuthenticateResult, AuthenticationRejection, Authenticator,
    canonical_authenticator_ip, normalize_virtual_server_id,
};
use shitspeak_runtime::channel_handler::{ChannelTreeShadow, SessionChannelShadow};
use shitspeak_runtime::client::user_info::Credential;
use shitspeak_runtime::client::visibility::UserVisibilityState;
use shitspeak_runtime::client::{AsyncMessageHandlerExt, Client};
use shitspeak_runtime::messages::Message;
use shitspeak_runtime::messages::encoder::{CodecVersion, ServerConfig, ServerSync};
use shitspeak_runtime::server::Server;
use shitspeak_runtime::types::DEFAULT_SERVER_ID;
use shitspeak_runtime_config::{WebAuthMode, WebConfig};

#[derive(Clone)]
pub struct WebSessionContext {
    config: WebConfig,
    authenticator: Option<Arc<dyn Authenticator>>,
    server: Option<Arc<Box<Server>>>,
    provisional_server_id: String,
    real_ip: IpAddr,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    tls_ja4: Option<String>,
    uses_proxy_protocol: bool,
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
        tls_ja4: Option<String>,
        uses_proxy_protocol: bool,
    ) -> Self {
        Self {
            config,
            authenticator,
            server,
            provisional_server_id: provisional_server_id
                .unwrap_or_else(shitspeak_runtime::types::default_server_id),
            real_ip,
            peer_addr,
            local_addr,
            tls_ja4,
            uses_proxy_protocol,
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
            auth_session_id: None,
            certificate_hash: None,
            session_id,
            ip_address: canonical_authenticator_ip(self.real_ip),
            tls_ja4: self.tls_ja4.clone(),
            uses_proxy_protocol: self.uses_proxy_protocol,
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
    ) -> Result<(AuthenticateResult, Option<Credential>), AuthenticationRejection> {
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
                let result = authenticator
                    .authenticate(&username, Some(password.as_str()), &auxiliary)
                    .await?;
                if result.user_id == Some(u32::MAX) {
                    return Err(AuthenticationRejection::RetryLater);
                }
                Ok((result, Some(Credential::new(username, Some(password)))))
            }
            AuthRequest::Sso { token: _ } => Err(AuthenticationRejection::RetryLater),
        }
    }

    pub async fn allocate_authenticated_client(
        &self,
        mut result: AuthenticateResult,
        outbound_tx: mpsc::Sender<Message>,
        transport: WebSessionTransport,
        credential: Option<Credential>,
    ) -> Option<(Arc<Box<Server>>, Arc<Box<Client>>, u32, Option<String>)> {
        result.virtual_server_id = normalize_virtual_server_id(result.virtual_server_id);
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
        if configure_authenticated_client(&server, &client, result, credential)
            .await
            .is_err()
        {
            let server_id = client.server_id();
            server
                .get_clients()
                .remove_client_instance_in_server(
                    &server_id,
                    client.get_session_id(),
                    client.client_instance_id(),
                )
                .await;
            return None;
        }
        Some((
            server,
            Arc::clone(&client),
            u32::from(client.get_session_id()),
            display_name,
        ))
    }

    pub async fn allocate_unauthenticated_client(
        &self,
        outbound_tx: mpsc::Sender<Message>,
        transport: WebSessionTransport,
    ) -> Option<(Arc<Box<Server>>, Arc<Box<Client>>)> {
        let server = Arc::clone(self.server.as_ref()?);
        let client = match transport {
            WebSessionTransport::WebRtc => {
                server
                    .get_clients()
                    .allocate_web_client_in_server(
                        self.provisional_server_id.clone(),
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
                        self.provisional_server_id.clone(),
                        self.real_ip,
                        self.peer_addr,
                        self.local_addr,
                        outbound_tx,
                    )
                    .await
            }
        };
        Some((server, client))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSessionTransport {
    WebRtc,
    Moq,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigureAuthenticatedClientError {
    MissingRequiredGroup,
    ServerFull,
}

impl ConfigureAuthenticatedClientError {
    pub fn reason(self) -> &'static str {
        match self {
            Self::MissingRequiredGroup => "missing required group",
            Self::ServerFull => "server full",
        }
    }
}

pub async fn configure_authenticated_client(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    result: AuthenticateResult,
    credential: Option<Credential>,
) -> Result<(), ConfigureAuthenticatedClientError> {
    client
        .in_tracing_span(configure_authenticated_client_inner(
            server, client, result, credential,
        ))
        .await
}

async fn configure_authenticated_client_inner(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    mut result: AuthenticateResult,
    credential: Option<Credential>,
) -> Result<(), ConfigureAuthenticatedClientError> {
    let cache_username = credential
        .as_ref()
        .map(|credential| credential.username.clone());
    result.virtual_server_id = normalize_virtual_server_id(result.virtual_server_id);
    let auth_session_id = result.auth_session_id.clone();
    let authenticated_until = result.authenticated_until;
    let authentication_expiry_action = result.authentication_expiry_action;
    let initial_texture_url = result.texture_url.clone();
    let initial_comment_url = result.comment_url.clone();
    if let Some(auth_server_id) = result.virtual_server_id.as_deref() {
        let provisional_server_id = client.server_id();
        if auth_server_id != provisional_server_id {
            if server
                .get_clients()
                .move_local_client_to_server(
                    &provisional_server_id,
                    client.get_session_id(),
                    auth_server_id,
                )
                .await
                .is_none()
            {
                tracing::warn!(
                    provisional_server_id,
                    auth_server_id,
                    session = u32::from(client.get_session_id()),
                    "failed to move authenticated web client to authenticator-selected server"
                );
            }
        }
    }
    let server_id = client.server_id();
    let channel_cache_key = shitspeak_runtime::user_channel_cache::user_channel_cache_key(
        &server_id,
        result.fqdn.as_deref(),
        result.user_id,
        client.get_certificate_hash(),
        cache_username.as_deref(),
    );
    let legacy_channel_cache_key = (server_id == DEFAULT_SERVER_ID)
        .then(|| {
            shitspeak_runtime::user_channel_cache::legacy_user_channel_cache_key(
                result.fqdn.as_deref(),
                result.user_id,
                client.get_certificate_hash(),
                cache_username.as_deref(),
            )
        })
        .flatten();
    if server
        .get_clients()
        .authenticated_client_count_in_server(&server_id)
        >= server.get_max_users()
    {
        return Err(ConfigureAuthenticatedClientError::ServerFull);
    }
    {
        let config = server.read_config();
        if !config.required_groups.is_empty()
            && !result
                .groups
                .iter()
                .any(|group| config.required_groups.contains(group))
        {
            return Err(ConfigureAuthenticatedClientError::MissingRequiredGroup);
        }
    }
    if !server
        .get_clients()
        .try_reserve_authenticated_client_in_server(
            &server_id,
            client.get_session_id(),
            server.get_max_users(),
        )
        .await
    {
        return Err(ConfigureAuthenticatedClientError::ServerFull);
    }
    client.set_language(result.language);
    client.set_max_bandwidth(result.max_bandwidth);
    client.set_protocol_version(Some(
        shitspeak_runtime::protocol_version::ProtocolVersion::new(1, 5, 0),
    ));
    {
        let mut gs = client.write_global_state_direct();
        gs.set_user_id(result.user_id);
        gs.set_fqdn(result.fqdn);
        gs.set_display_name(result.display_name);
        gs.set_superuser(result.is_superuser);
        gs.set_groups(result.groups.into_iter().collect());
        gs.set_texture_blob(initial_texture_url, None);
        gs.set_comment_blob(initial_comment_url, None);
    }
    if let Some(credential) = credential {
        let mut ext = client.user_info_extended().await;
        ext.set_credential(credential);
    }

    if let (Some(legacy_key), Some(cache_key)) = (
        legacy_channel_cache_key.as_deref(),
        channel_cache_key.as_deref(),
    ) {
        if let Err(error) = server
            .get_user_channel_cache()
            .migrate_key(legacy_key, cache_key)
            .await
        {
            tracing::warn!(
                error = %error,
                legacy_key,
                cache_key,
                "failed to migrate user channel cache identity"
            );
        }
    }

    let restored_channels = shitspeak_runtime::user_channel_cache::resolve_login_channels(
        server,
        client,
        channel_cache_key.as_deref(),
    )
    .await;
    let target_ch = restored_channels.current_channel_id;
    {
        let previous_channel_id = client.get_current_channel_id();
        let mut gs = client.write_global_state_direct();
        if gs.set_current_channel_id(target_ch) {
            tracing::info!(
                server_id = %client.server_id(),
                session = u32::from(client.get_session_id()),
                user_id = ?gs.get_user_id(),
                display_name = ?gs.get_display_name_opt(),
                previous_channel_id,
                channel_id = target_ch,
                "client entered channel"
            );
        }
    }
    if !restored_channels.listening_channel_ids.is_empty() {
        let mut gs = client.write_global_state_direct();
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
    client.complete_authentication(
        auth_session_id,
        authenticated_until,
        authentication_expiry_action,
    );
    client.stage_session_blob_resolution(result.user_id, result.texture_url, result.comment_url);
    server
        .get_clients()
        .publish_client_in_server(&server_id, client.get_session_id())
        .await;
    tracing::info!(
        server_id = %server_id,
        session = u32::from(client.get_session_id()),
        user_id = ?client.get_user_id(),
        display_name = ?client.display_name_opt(),
        cache_username = cache_username.as_deref(),
        transport = ?client.transport_kind(),
        "client authenticated"
    );
    shitspeak_runtime::voice::spawn_voice_routing_task(Arc::clone(server), Arc::clone(client));
    Ok(())
}

pub fn control_message_from_command(
    client: &Arc<Box<Client>>,
    command: ClientCommand,
) -> Option<Message> {
    match command {
        ClientCommand::Authenticate { .. } => None,
        ClientCommand::JoinChannel { channel_id } => Some(
            shitspeak_runtime::messages::encoder::UserState {
                session: Some(client.get_session_id()),
                channel_id: Some(channel_id),
                ..Default::default()
            }
            .into(),
        ),
        ClientCommand::SendText { text } => Some(
            shitspeak_runtime::messages::encoder::TextMessage {
                actor: None,
                session: Vec::new(),
                channel_id: vec![client.get_current_channel_id()],
                tree_id: Vec::new(),
                message: text,
            }
            .into(),
        ),
        ClientCommand::SetMute { muted } => Some(
            shitspeak_runtime::messages::encoder::UserState {
                session: Some(client.get_session_id()),
                self_mute: Some(muted),
                ..Default::default()
            }
            .into(),
        ),
        ClientCommand::SetDeaf { deafened } => Some(
            shitspeak_runtime::messages::encoder::UserState {
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

pub(crate) async fn client_is_current(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
) -> bool {
    server
        .get_clients()
        .get_client_in_server(&client.server_id(), client.get_session_id())
        .await
        .is_some_and(|current| Arc::ptr_eq(&current, client))
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

pub fn web_user_state(user_state: shitspeak_runtime::messages::encoder::UserState) -> WebUserState {
    let user_id_cleared = user_state.user_id == Some(u32::MAX);
    WebUserState {
        session: user_state.session.map(u32::from),
        actor: user_state.actor.map(u32::from),
        name: user_state.name,
        user_id: user_state.user_id.filter(|user_id| *user_id != u32::MAX),
        user_id_cleared,
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

pub fn web_channel_state(
    channel_state: shitspeak_runtime::messages::encoder::ChannelState,
) -> WebChannelState {
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

pub fn web_server_sync(sync: shitspeak_runtime::messages::encoder::ServerSync) -> WebServerSync {
    WebServerSync {
        session: sync.session.map(u32::from),
        max_bandwidth: sync.max_bandwidth,
        welcome_text: sync.welcome_text,
        permissions: sync.permissions.map(|p| p.bits()),
    }
}

pub fn web_server_config(
    config: shitspeak_runtime::messages::encoder::ServerConfig,
) -> WebServerConfig {
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
    denied: shitspeak_runtime::messages::encoder::PermissionDenied,
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
    channel_tree_shadow: &mut ChannelTreeShadow,
    channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
) -> Vec<ServerEvent> {
    let server_id = client.server_id();
    let channels = server.get_channels().ordered_snapshot_in_server(&server_id);
    initial_server_events_with_channel_snapshot(
        server,
        client,
        &channels,
        channel_tree_shadow,
        channel_shadow,
        user_visibility,
    )
    .await
}

pub async fn initial_server_events_with_channel_snapshot(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channels: &shitspeak_state::OrderedChannelSnapshot,
    channel_tree_shadow: &mut ChannelTreeShadow,
    channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
) -> Vec<ServerEvent> {
    let server_id = client.server_id();
    let mut events = Vec::new();

    for message in
        shitspeak_runtime::channel_handler::build_visible_ordered_channel_snapshot_messages(
            server,
            client,
            channels,
            channel_tree_shadow,
            server.get_send_permission_info(),
        )
        .await
    {
        push_message_event(&mut events, message);
    }

    let session_id = client.get_session_id();
    for visible in server
        .get_clients()
        .get_all_clients_in_server(&server_id)
        .await
    {
        if !visible.is_authenticated() || !visible.is_published() {
            continue;
        }
        if visible.get_session_id() == session_id {
            continue;
        }
        let user_state: Message = visible.build_user_state_for_broadcast().into();
        for message in shitspeak_runtime::channel_handler::project_message_with_visibility_shadows(
            server,
            client,
            channel_tree_shadow,
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
    for message in shitspeak_runtime::channel_handler::project_message_with_visibility_shadows(
        server,
        client,
        channel_tree_shadow,
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
        shitspeak_runtime::client::acl::compute_permissions_for_client(server, client, 0).await;
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
    channel_tree_shadow: &mut ChannelTreeShadow,
    channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
) -> io::Result<()> {
    for event in initial_server_events(
        server,
        client,
        channel_tree_shadow,
        channel_shadow,
        user_visibility,
    )
    .await
    {
        send(event)?;
    }
    Ok(())
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

fn web_deny_type_name(deny_type: shitspeak_runtime::messages::encoder::DenyType) -> &'static str {
    match deny_type {
        shitspeak_runtime::messages::encoder::DenyType::Text => "text",
        shitspeak_runtime::messages::encoder::DenyType::Permission => "permission",
        shitspeak_runtime::messages::encoder::DenyType::SuperUser => "super_user",
        shitspeak_runtime::messages::encoder::DenyType::ChannelName => "channel_name",
        shitspeak_runtime::messages::encoder::DenyType::TextTooLong => "text_too_long",
        shitspeak_runtime::messages::encoder::DenyType::H9k => "h9k",
        shitspeak_runtime::messages::encoder::DenyType::TemporaryChannel => "temporary_channel",
        shitspeak_runtime::messages::encoder::DenyType::MissingCertificate => "missing_certificate",
        shitspeak_runtime::messages::encoder::DenyType::UserName => "user_name",
        shitspeak_runtime::messages::encoder::DenyType::ChannelFull => "channel_full",
        shitspeak_runtime::messages::encoder::DenyType::NestingLimit => "nesting_limit",
        shitspeak_runtime::messages::encoder::DenyType::ChannelCountLimit => "channel_count_limit",
        shitspeak_runtime::messages::encoder::DenyType::ChannelListenerLimit => {
            "channel_listener_limit"
        }
        shitspeak_runtime::messages::encoder::DenyType::UserListenerLimit => "user_listener_limit",
    }
}

#[cfg(test)]
mod tests {
    use super::web_user_state;

    #[test]
    fn mumble_deregistration_sentinel_becomes_explicit_web_clear() {
        let user_state = shitspeak_runtime::messages::encoder::UserState {
            user_id: Some(u32::MAX),
            ..Default::default()
        };

        let state = web_user_state(user_state);
        assert_eq!(state.user_id, None);
        assert!(state.user_id_cleared);
    }
}
