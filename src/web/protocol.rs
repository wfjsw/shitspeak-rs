use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthRequest {
    Password { username: String, password: String },
    Sso { token: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VoiceTarget {
    Normal,
    ServerLoopback,
    Slot(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientCommand {
    Authenticate {
        auth: AuthRequest,
    },
    JoinChannel {
        channel_id: u32,
    },
    SendText {
        text: String,
    },
    SetMute {
        muted: bool,
    },
    SetDeaf {
        deafened: bool,
    },
    VoiceControl {
        ptt: bool,
        target: VoiceTarget,
        epoch: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IceConnectionState {
    New,
    Checking,
    Connected,
    Completed,
    Disconnected,
    Failed,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpeakerAssigned {
    pub ssrc: u32,
    pub speaker_session: u32,
    pub track_id: String,
    pub epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VoiceSegment {
    pub ssrc: u32,
    pub speaker_session: u32,
    pub context: String,
    pub channel_id: u32,
    pub rtp_timestamp: u32,
    pub epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebVolumeAdjustment {
    pub listening_channel: u32,
    pub volume_adjustment: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebUserState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mute: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deaf: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppress: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_mute: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_deaf: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub texture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub texture_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority_speaker: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recording: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listening_channel_add: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listening_channel_remove: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listening_volume_adjustment: Vec<WebVolumeAdjustment>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebUserRemove {
    pub session: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ban: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebChannelState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links_add: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links_remove: Vec<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temporary: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_users: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_enter_restricted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub can_enter: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebServerSync {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bandwidth: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub welcome_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebServerConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bandwidth: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub welcome_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_html: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_length: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_message_length: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_users: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recording_allowed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebPermissionDenied {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebCodecVersion {
    pub alpha: i32,
    pub beta: i32,
    pub prefer_alpha: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opus: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WebTransportKind {
    WebRtc,
    Moq,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebMoqGatewayConfig {
    pub url: Option<String>,
    pub max_speaker_tracks: u32,
    pub audio_bitrate: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebGatewayConfig {
    pub max_speaker_slots: u32,
    pub audio_bitrate: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transports: Vec<WebTransportKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moq: Option<WebMoqGatewayConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerEvent {
    GatewayConfig(WebGatewayConfig),
    Authenticated {
        session: u32,
        display_name: Option<String>,
    },
    AuthenticationRejected {
        reason: String,
    },
    IceConnectionState {
        state: IceConnectionState,
    },
    SpeakerAssigned(SpeakerAssigned),
    VoiceSegmentStart(VoiceSegment),
    VoiceSegmentEnd(VoiceSegment),
    VoiceControlAck {
        epoch: u64,
    },
    UserState(WebUserState),
    UserRemove(WebUserRemove),
    ChannelState(WebChannelState),
    ChannelRemove {
        channel_id: u32,
    },
    ServerSync(WebServerSync),
    ServerConfig(WebServerConfig),
    PermissionDenied(WebPermissionDenied),
    CodecVersion(WebCodecVersion),
    TextMessage {
        sender_session: u32,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        target_sessions: Vec<u32>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        channel_ids: Vec<u32>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        tree_ids: Vec<u32>,
        text: String,
    },
    Error {
        message: String,
    },
}

pub fn encode_server_event(event: &ServerEvent) -> Result<String, serde_json::Error> {
    serde_json::to_string(event)
}

pub fn decode_client_command(input: &str) -> Result<ClientCommand, serde_json::Error> {
    serde_json::from_str(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_auth_command_roundtrips() {
        let command = ClientCommand::Authenticate {
            auth: AuthRequest::Password {
                username: "alice".to_string(),
                password: "secret".to_string(),
            },
        };

        let wire = serde_json::to_string(&command).unwrap();
        let decoded = decode_client_command(&wire).unwrap();
        assert_eq!(decoded, command);
    }

    #[test]
    fn speaker_assigned_event_uses_ssrc_epoch_mapping() {
        let event = ServerEvent::SpeakerAssigned(SpeakerAssigned {
            ssrc: 22,
            speaker_session: 7,
            track_id: "speaker-7".to_string(),
            epoch: 4,
        });

        let wire = encode_server_event(&event).unwrap();
        assert!(wire.contains("speaker_assigned"));
        assert!(wire.contains("speaker-7"));
    }

    #[test]
    fn gateway_config_event_advertises_speaker_slots() {
        let event = ServerEvent::GatewayConfig(WebGatewayConfig {
            max_speaker_slots: 8,
            audio_bitrate: 48_000,
            transports: vec![WebTransportKind::WebRtc, WebTransportKind::Moq],
            moq: Some(WebMoqGatewayConfig {
                url: Some("https://voice.example.test/web/moq".to_string()),
                max_speaker_tracks: 6,
                audio_bitrate: 32_000,
            }),
        });

        let wire = encode_server_event(&event).unwrap();
        assert!(wire.contains(r#""type":"gateway_config""#));
        assert!(wire.contains(r#""max_speaker_slots":8"#));
        assert!(wire.contains(r#""transports":["web_rtc","moq"]"#));
        assert!(wire.contains(r#""max_speaker_tracks":6"#));
    }

    #[test]
    fn user_state_event_skips_absent_patch_fields() {
        let event = ServerEvent::UserState(WebUserState {
            session: Some(7),
            actor: None,
            name: Some("Alice".to_string()),
            user_id: None,
            channel_id: Some(0),
            mute: None,
            deaf: None,
            suppress: None,
            self_mute: None,
            self_deaf: None,
            texture: None,
            plugin_context: None,
            plugin_identity: None,
            comment: None,
            hash: None,
            comment_hash: None,
            texture_hash: None,
            priority_speaker: None,
            recording: None,
            listening_channel_add: Vec::new(),
            listening_channel_remove: Vec::new(),
            listening_volume_adjustment: Vec::new(),
        });

        let wire = encode_server_event(&event).unwrap();
        assert!(wire.contains(r#""type":"user_state""#));
        assert!(wire.contains(r#""name":"Alice""#));
        assert!(!wire.contains("self_mute"));
    }
}
