use crate::messages::Message;

#[derive(Debug, Clone, Default)]
pub struct VoiceTarget {
    pub id: Option<u32>,
    pub targets: Vec<shitspeak_proto::mumble_proto::voice_target::Target>,
}

impl From<shitspeak_proto::mumble_proto::VoiceTarget> for VoiceTarget {
    fn from(proto: shitspeak_proto::mumble_proto::VoiceTarget) -> Self {
        Self {
            id: proto.id,
            targets: proto.targets,
        }
    }
}

impl From<VoiceTarget> for shitspeak_proto::mumble_proto::VoiceTarget {
    fn from(voice_target: VoiceTarget) -> Self {
        shitspeak_proto::mumble_proto::VoiceTarget {
            id: voice_target.id,
            targets: voice_target.targets,
        }
    }
}

impl From<VoiceTarget> for Message {
    fn from(voice_target: VoiceTarget) -> Self {
        Message::VoiceTarget(voice_target.into())
    }
}
