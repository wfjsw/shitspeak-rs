use prost::Message as _;
use paste::paste;
use crate::messages::message_type::MessageType;

macro_rules! handle_message_arm {
    ($self:ident, $message:ident) => {
        match crate::mumble_proto::$message::decode(&*$self.content) {
            Ok(message) => paste! { crate::messages::handlers::[<handle_ $message:snake>](message) },
            Err(_) => todo!(),
        }
    };
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Message {
    message_type: MessageType,
    content: Vec<u8>,
}

impl Message {
    pub fn new(message_type: MessageType, content: Vec<u8>) -> Self {
        Self {
            message_type,
            content,
        }
    }

    pub fn message_type(&self) -> MessageType {
        self.message_type
    }

    pub fn content(&self) -> &[u8] {
        &self.content
    }

    pub fn handle(&self) {
        match self.message_type {
            MessageType::ACL => handle_message_arm!(self, Acl),
            MessageType::BanList => handle_message_arm!(self, BanList),
            MessageType::ChannelRemove => handle_message_arm!(self, ChannelRemove),
            MessageType::ChannelState => handle_message_arm!(self, ChannelState),
            _ => todo!(),
        }
    }
}
