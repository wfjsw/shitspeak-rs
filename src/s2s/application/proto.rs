//! Encode/decode helpers for the application-layer envelopes.
//!
//! The outer overlay envelope (`OverlayData`) is provided by L2; this
//! module deals only with the bytes we put into the envelope's `payload`.

use bytes::{Bytes, BytesMut};
use prost::Message as _;

use crate::s2s_application_proto as pb;

pub use pb::{
    moderation_envelope::Command as ModerationCommand, ModerationEnvelope, UserRemovePatch,
    UserStatePatch, VoiceFrame,
};

/// Reserved overlay service tag for moderation envelopes.
pub const MODERATION_SERVICE_TAG: u32 = 2;

/// Reserved overlay service tag for voice frames.
pub const VOICE_SERVICE_TAG: u32 = 3;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn moderation_envelope_roundtrip_user_state() {
        let env = ModerationEnvelope {
            actor_session: 0xABC_12345,
            target_session: 0xDEF_67890,
            issued_at_ms: 1_700_000_000_000,
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
            command: Some(ModerationCommand::UserRemove(UserRemovePatch {
                reason: Some("test".to_string()),
                ban: true,
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
            sender_epoch: 1_700_000_000_000_000,
            s2s_seq: 42,
            target_kind: 0,
            is_terminator: false,
            payload: Bytes::from_static(&[1, 2, 3, 4, 5]),
        };
        let bytes = encode_voice(&frame).unwrap();
        let decoded = decode_voice(&bytes).unwrap();
        assert_eq!(decoded, frame);
    }
}
