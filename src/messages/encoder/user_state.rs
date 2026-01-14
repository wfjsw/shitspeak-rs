use core::option::Option;

use crate::{client::client_session_identifier::ClientSessionIdentifier, messages::{Message, errors::UserStateProtocolError}};

#[derive(Debug, Clone)]
pub struct VolumeAdjustment {
        listening_channel: u32,
        volume_adjustment: f32,
}

impl TryFrom<crate::mumble_proto::user_state::VolumeAdjustment> for VolumeAdjustment {
    fn try_from(proto: crate::mumble_proto::user_state::VolumeAdjustment) -> Result<Self, Self::Error> {
        Ok(Self {
            listening_channel: proto.listening_channel.ok_or(UserStateProtocolError::VolumeAdjustmentMissingListeningChannel)?,
            volume_adjustment: proto.volume_adjustment.ok_or(UserStateProtocolError::VolumeAdjustmentMissingValue)?,
        })
    }

    type Error = UserStateProtocolError;
}

#[derive(Debug, Clone)]
pub struct UserState {
    session: ClientSessionIdentifier,
    actor: Option<ClientSessionIdentifier>,
    name: Option<String>,
    user_id: Option<u32>,
    channel_id: Option<u32>,
    mute: Option<bool>,
    deaf: Option<bool>,
    suppress: Option<bool>,
    self_mute: Option<bool>,
    self_deaf: Option<bool>,
    texture: Option<Vec<u8>>,
    plugin_context: Option<Vec<u8>>,
    plugin_identity: Option<String>,
    comment: Option<String>,
    hash: Option<String>,
    comment_hash: Option<Vec<u8>>,
    texture_hash: Option<Vec<u8>>,
    priority_speaker: Option<bool>,
    recording: Option<bool>,
    temporary_access_tokens: Vec<String>,
    listening_channel_add: Vec<u32>,
    listening_channel_remove: Vec<u32>,
    listening_volume_adjustment: Vec<VolumeAdjustment>,
}

impl TryFrom<crate::mumble_proto::UserState> for UserState {
    fn try_from(proto: crate::mumble_proto::UserState) -> Result<Self, Self::Error> {
        Ok(Self {
            session: proto.session.ok_or(UserStateProtocolError::MissingSessionId)?.into(),
            actor: proto.actor.map(|a| a.into()),
            name: proto.name,
            user_id: proto.user_id,
            channel_id: proto.channel_id,
            mute: proto.mute,
            deaf: proto.deaf,
            suppress: proto.suppress,
            self_mute: proto.self_mute,
            self_deaf: proto.self_deaf,
            texture: proto.texture,
            plugin_context: proto.plugin_context,
            plugin_identity: proto.plugin_identity,
            comment: proto.comment,
            hash: proto.hash,
            comment_hash: proto.comment_hash,
            texture_hash: proto.texture_hash,
            priority_speaker: proto.priority_speaker,
            recording: proto.recording,
            temporary_access_tokens: proto.temporary_access_tokens,
            listening_channel_add: proto.listening_channel_add,
            listening_channel_remove: proto.listening_channel_remove,
            listening_volume_adjustment: proto.listening_volume_adjustment.into_iter().map(|va| va.try_into()).collect::<Result<_, _>>()?,
        })
    }

    type Error = UserStateProtocolError;
}

impl UserState {
}

impl Into<crate::mumble_proto::UserState> for UserState {
    fn into(self) -> crate::mumble_proto::UserState {
        crate::mumble_proto::UserState {
            session: Some(u32::from(self.session)),
            actor: self.actor.map(|a| u32::from(a)),
            name: self.name,
            user_id: self.user_id,
            channel_id: self.channel_id,
            mute: self.mute,
            deaf: self.deaf,
            suppress: self.suppress,
            self_mute: self.self_mute,
            self_deaf: self.self_deaf,
            texture: self.texture,
            plugin_context: self.plugin_context,
            plugin_identity: self.plugin_identity,
            comment: self.comment,
            hash: self.hash,
            comment_hash: self.comment_hash,
            texture_hash: self.texture_hash,
            priority_speaker: self.priority_speaker,
            recording: self.recording,
            temporary_access_tokens: self.temporary_access_tokens,
            listening_channel_add: self.listening_channel_add,
            listening_channel_remove: self.listening_channel_remove,
            listening_volume_adjustment: self.listening_volume_adjustment.into_iter().map(|va| crate::mumble_proto::user_state::VolumeAdjustment {
                listening_channel: Some(va.listening_channel),
                volume_adjustment: Some(va.volume_adjustment),
            }).collect(),
        }
    }
}

impl Into<Message> for UserState {
    fn into(self) -> Message {
        Message::UserState(self.into())
    }
}
