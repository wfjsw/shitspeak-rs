use std::time::{Duration, Instant};

use crate::voice::codec::Audio;

pub struct VoiceRoutingPayload {
    decoded_audio: Audio,
    enqueued_at: Instant,
}

impl VoiceRoutingPayload {
    pub fn new(decoded_audio: Audio) -> Self {
        Self {
            decoded_audio,
            enqueued_at: Instant::now(),
        }
    }

    pub fn decoded_audio(&self) -> &Audio {
        &self.decoded_audio
    }

    pub fn enqueue_age(&self) -> Duration {
        self.enqueued_at.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::messages::encoder::AudioTarget;
    use crate::voice::codec::{AudioPayload, OpusPayload, PacketFormat};

    #[test]
    fn payload_preserves_audio_and_tracks_enqueue_age() {
        let audio = Audio {
            target: AudioTarget::Normal,
            sender_session: None,
            frame_number: 42,
            audio_payload: AudioPayload::Opus(OpusPayload {
                frame: Bytes::from_static(b"voice"),
                is_terminator: false,
            }),
            positional_data: None,
            volume_adjustment: 1.0,
            format: PacketFormat::Legacy,
        };

        let payload = VoiceRoutingPayload::new(audio.clone());

        assert_eq!(payload.decoded_audio(), &audio);
        assert!(payload.enqueue_age() < Duration::from_secs(1));
    }
}
