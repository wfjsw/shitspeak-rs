use crate::messages::Message;

#[derive(Debug, Clone)]
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

impl Default for VoiceTarget {
    fn default() -> Self {
        Self {
            id: None,
            targets: Vec::new(),
        }
    }
}

impl Into<crate::mumble_proto::VoiceTarget> for VoiceTarget {
    fn into(self) -> crate::mumble_proto::VoiceTarget {
        crate::mumble_proto::VoiceTarget {
            id: self.id,
            targets: self.targets,
        }
    }
}

impl Into<Message> for VoiceTarget {
    fn into(self) -> Message {
        Message::VoiceTarget(self.into())
    }
}
