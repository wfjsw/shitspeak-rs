use bytes::Bytes;
use core::option::Option;

use crate::{
    client::client_session_identifier::ClientSessionIdentifier,
    messages::{Message, errors::UserStateProtocolError},
};

#[derive(Debug, Clone)]
pub struct VolumeAdjustment {
    pub listening_channel: u32,
    pub volume_adjustment: f32,
}

impl TryFrom<crate::mumble_proto::user_state::VolumeAdjustment> for VolumeAdjustment {
    fn try_from(
        proto: crate::mumble_proto::user_state::VolumeAdjustment,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            listening_channel: proto
                .listening_channel
                .ok_or(UserStateProtocolError::VolumeAdjustmentMissingListeningChannel)?,
            volume_adjustment: proto
                .volume_adjustment
                .ok_or(UserStateProtocolError::VolumeAdjustmentMissingValue)?,
        })
    }

    type Error = UserStateProtocolError;
}

#[derive(Debug, Clone)]
pub struct UserState {
    pub session: Option<ClientSessionIdentifier>,
    pub actor: Option<ClientSessionIdentifier>,
    pub name: Option<String>,
    pub user_id: Option<u32>,
    pub channel_id: Option<u32>,
    pub mute: Option<bool>,
    pub deaf: Option<bool>,
    pub suppress: Option<bool>,
    pub self_mute: Option<bool>,
    pub self_deaf: Option<bool>,
    pub texture: Option<Bytes>,
    pub plugin_context: Option<Bytes>,
    pub plugin_identity: Option<String>,
    pub comment: Option<String>,
    pub hash: Option<String>,
    pub comment_hash: Option<Bytes>,
    pub texture_hash: Option<Bytes>,
    pub priority_speaker: Option<bool>,
    pub recording: Option<bool>,
    pub temporary_access_tokens: Vec<String>,
    pub listening_channel_add: Vec<u32>,
    pub listening_channel_remove: Vec<u32>,
    pub listening_volume_adjustment: Vec<VolumeAdjustment>,
}

impl TryFrom<crate::mumble_proto::UserState> for UserState {
    fn try_from(proto: crate::mumble_proto::UserState) -> Result<Self, Self::Error> {
        Ok(Self {
            session: proto.session.map(|a| a.into()),
            actor: proto.actor.map(|a| a.into()),
            name: proto.name,
            user_id: proto.user_id,
            channel_id: proto.channel_id,
            mute: proto.mute,
            deaf: proto.deaf,
            suppress: proto.suppress,
            self_mute: proto.self_mute,
            self_deaf: proto.self_deaf,
            texture: proto.texture.map(Bytes::from),
            plugin_context: proto.plugin_context.map(Bytes::from),
            plugin_identity: proto.plugin_identity,
            comment: proto.comment,
            hash: proto.hash,
            comment_hash: proto.comment_hash.map(Bytes::from),
            texture_hash: proto.texture_hash.map(Bytes::from),
            priority_speaker: proto.priority_speaker,
            recording: proto.recording,
            temporary_access_tokens: proto.temporary_access_tokens,
            listening_channel_add: proto.listening_channel_add,
            listening_channel_remove: proto.listening_channel_remove,
            listening_volume_adjustment: proto
                .listening_volume_adjustment
                .into_iter()
                .map(|va| va.try_into())
                .collect::<Result<_, _>>()?,
        })
    }

    type Error = UserStateProtocolError;
}

impl UserState {}

impl Default for UserState {
    fn default() -> Self {
        Self {
            session: None,
            actor: None,
            name: None,
            user_id: None,
            channel_id: None,
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
            temporary_access_tokens: Vec::new(),
            listening_channel_add: Vec::new(),
            listening_channel_remove: Vec::new(),
            listening_volume_adjustment: Vec::new(),
        }
    }
}

impl Into<crate::mumble_proto::UserState> for UserState {
    fn into(self) -> crate::mumble_proto::UserState {
        crate::mumble_proto::UserState {
            session: self.session.map(|s| u32::from(s)),
            actor: self.actor.map(|a| u32::from(a)),
            name: self.name,
            user_id: self.user_id,
            channel_id: self.channel_id,
            mute: self.mute,
            deaf: self.deaf,
            suppress: self.suppress,
            self_mute: self.self_mute,
            self_deaf: self.self_deaf,
            texture: self.texture.map(|b| b.to_vec()),
            plugin_context: self.plugin_context.map(|b| b.to_vec()),
            plugin_identity: self.plugin_identity,
            comment: self.comment,
            hash: self.hash,
            comment_hash: self.comment_hash.map(|b| b.to_vec()),
            texture_hash: self.texture_hash.map(|b| b.to_vec()),
            priority_speaker: self.priority_speaker,
            recording: self.recording,
            temporary_access_tokens: self.temporary_access_tokens,
            listening_channel_add: self.listening_channel_add,
            listening_channel_remove: self.listening_channel_remove,
            listening_volume_adjustment: self
                .listening_volume_adjustment
                .into_iter()
                .map(|va| crate::mumble_proto::user_state::VolumeAdjustment {
                    listening_channel: Some(va.listening_channel),
                    volume_adjustment: Some(va.volume_adjustment),
                })
                .collect(),
        }
    }
}

impl Into<Message> for UserState {
    fn into(self) -> Message {
        Message::UserState(self.into())
    }
}
