use crate::voice::codec::DecodedAudio;

pub struct VoiceRoutingPayload {
    pub decoded_audio: DecodedAudio,
    pub is_udp: bool,
}
