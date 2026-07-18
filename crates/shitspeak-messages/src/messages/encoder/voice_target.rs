use crate::messages::Message;

#[derive(Debug, Clone, Default)]
pub struct VoiceTarget {
    pub id: Option<u32>,
    pub targets: Vec<crate::mumble_proto::voice_target::Target>,
}

impl From<crate::mumble_proto::VoiceTarget> for VoiceTarget {
    fn from(proto: crate::mumble_proto::VoiceTarget) -> Self {
        Self {
            id: proto.id,
            targets: proto.targets,
        }
    }
}

impl From<VoiceTarget> for crate::mumble_proto::VoiceTarget {
    fn from(voice_target: VoiceTarget) -> Self {
        crate::mumble_proto::VoiceTarget {
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
