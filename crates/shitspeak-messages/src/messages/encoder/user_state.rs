use bytes::Bytes;
use core::option::Option;

use crate::{
    client::client_session_identifier::ClientSessionIdentifier,
    messages::{Message, errors::UserStateProtocolError},
};

#[derive(Debug, Clone, Default)]
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

#[derive(Debug, Clone, Default)]
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
            session: proto.session.map(ClientSessionIdentifier::from),
            actor: proto.actor.map(ClientSessionIdentifier::from),
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
                .map(VolumeAdjustment::try_from)
                .collect::<Result<_, _>>()?,
        })
    }

    type Error = UserStateProtocolError;
}

impl From<UserState> for crate::mumble_proto::UserState {
    fn from(user_state: UserState) -> Self {
        crate::mumble_proto::UserState {
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
            texture: user_state.texture.map(|b| b.to_vec()),
            plugin_context: user_state.plugin_context.map(|b| b.to_vec()),
            plugin_identity: user_state.plugin_identity,
            comment: user_state.comment,
            hash: user_state.hash,
            comment_hash: user_state.comment_hash.map(|b| b.to_vec()),
            texture_hash: user_state.texture_hash.map(|b| b.to_vec()),
            priority_speaker: user_state.priority_speaker,
            recording: user_state.recording,
            temporary_access_tokens: user_state.temporary_access_tokens,
            listening_channel_add: user_state.listening_channel_add,
            listening_channel_remove: user_state.listening_channel_remove,
            listening_volume_adjustment: user_state
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

impl From<UserState> for Message {
    fn from(user_state: UserState) -> Self {
        Message::UserState(user_state.into())
    }
}
