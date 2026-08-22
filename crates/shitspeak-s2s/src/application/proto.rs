//! Encode/decode helpers for the application-layer envelopes.
//!
//! The outer overlay envelope (`OverlayData`) is provided by L2; this
//! module deals only with the bytes we put into the envelope's `payload`.

use bytes::{Bytes, BytesMut};
use prost::Message as _;

use shitspeak_proto::s2s_application_proto as pb;

pub use pb::{
    ModerationEnvelope, PluginDataEnvelope, TextMessageEnvelope, UserRemovePatch, UserStatePatch,
    UserStatsEnvelope, UserStatsReply, UserStatsRequest, VoiceFrame, VoiceIntent,
    VoiceIntentNormal, VoiceIntentTarget, VoicePathFeedback, VoiceRepairRequest,
    VoiceTargetChannel, moderation_envelope::Command as ModerationCommand,
    user_stats_envelope::Kind as UserStatsKind, voice_intent::Kind as VoiceIntentKind,
};

/// Reserved overlay service tag for moderation envelopes.
pub const MODERATION_SERVICE_TAG: u32 = 2;

/// Reserved overlay service tag for voice frames.
pub const VOICE_SERVICE_TAG: u32 = 3;

/// Reserved overlay service tag for S2S voice repair requests.
pub const VOICE_REPAIR_SERVICE_TAG: u32 = 7;
pub const VOICE_PATH_FEEDBACK_SERVICE_TAG: u32 = 8;

/// Reserved overlay service tag for the UserStats request/reply RPC.
pub const USER_STATS_SERVICE_TAG: u32 = 4;

/// Reserved overlay service tag for plugin-data fanout.
pub const PLUGIN_DATA_SERVICE_TAG: u32 = 5;

/// Reserved overlay service tag for text-message fanout.
pub const TEXT_MESSAGE_SERVICE_TAG: u32 = 6;

pub fn encode_moderation(env: &ModerationEnvelope) -> Result<Bytes, prost::EncodeError> {
    let mut buf = BytesMut::with_capacity(env.encoded_len());
    env.encode(&mut buf)?;
    Ok(buf.freeze())
}

pub fn decode_moderation(src: &[u8]) -> Result<ModerationEnvelope, prost::DecodeError> {
    ModerationEnvelope::decode(src)
}

pub fn encode_voice(frame: &VoiceFrame) -> Result<Bytes, prost::EncodeError> {
    let mut buf = BytesMut::with_capacity(frame.encoded_len());
    frame.encode(&mut buf)?;
    Ok(buf.freeze())
}

pub fn decode_voice(src: &[u8]) -> Result<VoiceFrame, prost::DecodeError> {
    VoiceFrame::decode(src)
}

pub fn encode_voice_repair_request(
    request: &VoiceRepairRequest,
) -> Result<Bytes, prost::EncodeError> {
    let mut buf = BytesMut::with_capacity(request.encoded_len());
    request.encode(&mut buf)?;
    Ok(buf.freeze())
}

pub fn decode_voice_repair_request(src: &[u8]) -> Result<VoiceRepairRequest, prost::DecodeError> {
    VoiceRepairRequest::decode(src)
}

pub fn encode_voice_path_feedback(
    feedback: &VoicePathFeedback,
) -> Result<Bytes, prost::EncodeError> {
    let mut buf = BytesMut::with_capacity(feedback.encoded_len());
    feedback.encode(&mut buf)?;
    Ok(buf.freeze())
}

pub fn decode_voice_path_feedback(src: &[u8]) -> Result<VoicePathFeedback, prost::DecodeError> {
    VoicePathFeedback::decode(src)
}

pub fn encode_user_stats(env: &UserStatsEnvelope) -> Result<Bytes, prost::EncodeError> {
    let mut buf = BytesMut::with_capacity(env.encoded_len());
    env.encode(&mut buf)?;
    Ok(buf.freeze())
}

pub fn decode_user_stats(src: &[u8]) -> Result<UserStatsEnvelope, prost::DecodeError> {
    UserStatsEnvelope::decode(src)
}

pub fn encode_plugin_data(env: &PluginDataEnvelope) -> Result<Bytes, prost::EncodeError> {
    let mut buf = BytesMut::with_capacity(env.encoded_len());
    env.encode(&mut buf)?;
    Ok(buf.freeze())
}

pub fn decode_plugin_data(src: &[u8]) -> Result<PluginDataEnvelope, prost::DecodeError> {
    PluginDataEnvelope::decode(src)
}

pub fn encode_text_message(env: &TextMessageEnvelope) -> Result<Bytes, prost::EncodeError> {
    let mut buf = BytesMut::with_capacity(env.encoded_len());
    env.encode(&mut buf)?;
    Ok(buf.freeze())
}

pub fn decode_text_message(src: &[u8]) -> Result<TextMessageEnvelope, prost::DecodeError> {
    TextMessageEnvelope::decode(src)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn moderation_envelope_roundtrip_user_state() {
        let env = ModerationEnvelope {
            actor_session: 0xABC_12345,
            target_session: 0xDEF_67890,
            issued_at_ms: 1_700_000_000_000,
            server_id: shitspeak_core::default_server_id(),
            command: Some(ModerationCommand::UserState(UserStatePatch {
                channel_id: Some(7),
                mute: Some(true),
                deaf: None,
                suppress: None,
                priority_speaker: None,
                listening_channel_add: vec![],
                listening_channel_remove: vec![],
                expected_from_channel: Some(3),
            })),
        };
        let bytes = encode_moderation(&env).unwrap();
        let decoded = decode_moderation(&bytes).unwrap();
        assert_eq!(decoded, env);
    }

    #[test]
    fn moderation_envelope_roundtrip_user_remove() {
        let env = ModerationEnvelope {
            actor_session: 1,
            target_session: 2,
            issued_at_ms: 0,
            server_id: shitspeak_core::default_server_id(),
            command: Some(ModerationCommand::UserRemove(UserRemovePatch {
                reason: Some("test".to_string()),
                ban: true,
                ban_certificate: Some(true),
                ban_ip: Some(true),
            })),
        };
        let bytes = encode_moderation(&env).unwrap();
        let decoded = decode_moderation(&bytes).unwrap();
        assert_eq!(decoded, env);
    }

    #[test]
    fn voice_frame_roundtrip() {
        let frame = VoiceFrame {
            sender_session: 0xABC_12345,
            server_id: shitspeak_core::default_server_id(),
            sender_epoch: 1_700_000_000_000_000,
            s2s_seq: 42,
            target_kind: 0,
            is_terminator: false,
            payload: Bytes::from_static(&[1, 2, 3, 4, 5]),
            intent: Some(VoiceIntent {
                kind: Some(VoiceIntentKind::Normal(VoiceIntentNormal {
                    source_channel: 7,
                })),
            }),
            proactive_copy: false,
            fec_parity: true,
            fec_member_seqs: vec![1, 2, 3, 4],
            fec_terminator_mask: 2,
            fec_parity_index: 1,
        };
        let bytes = encode_voice(&frame).unwrap();
        let decoded = decode_voice(&bytes).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn voice_tail_ack_roundtrip() {
        let request = VoiceRepairRequest {
            sender_session: 0xABC,
            sender_epoch: 42,
            first_seq: 17,
            last_seq: 17,
            request_sent_unix_ms: 0,
            request_ttl_ms: 750,
            tail_ack: true,
        };
        let bytes = encode_voice_repair_request(&request).unwrap();
        assert_eq!(decode_voice_repair_request(&bytes).unwrap(), request);
    }

    #[test]
    fn plugin_data_envelope_roundtrip() {
        let env = PluginDataEnvelope {
            sender_session: 0xABC_12345,
            receiver_sessions: vec![0xDEF_67890, 0xDEF_67891],
            data: Bytes::from_static(b"plugin"),
            data_id: Some("test.plugin".to_string()),
            server_id: shitspeak_core::default_server_id(),
        };

        let bytes = encode_plugin_data(&env).unwrap();
        let decoded = decode_plugin_data(&bytes).unwrap();
        assert_eq!(decoded, env);
    }

    #[test]
    fn text_message_envelope_roundtrip() {
        let env = TextMessageEnvelope {
            sender_session: 0xABC_12345,
            receiver_sessions: vec![0xDEF_67890],
            session: vec![0xDEF_67890],
            channel_id: vec![7],
            tree_id: vec![0],
            message: "hello".to_string(),
            server_id: shitspeak_core::default_server_id(),
        };

        let bytes = encode_text_message(&env).unwrap();
        let decoded = decode_text_message(&bytes).unwrap();
        assert_eq!(decoded, env);
    }
}
