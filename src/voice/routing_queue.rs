use crate::voice::codec::Audio;

pub struct VoiceRoutingPayload {
    pub decoded_audio: Audio,
}
