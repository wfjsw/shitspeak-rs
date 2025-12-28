use crate::messages::Message;

#[derive(Debug)]
pub struct MessageTypeNotForIncoming {
    pub message: Message,
}

impl std::fmt::Display for MessageTypeNotForIncoming {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Message type not for incoming: {}", self.message)
    }
}

impl std::error::Error for MessageTypeNotForIncoming {}

impl MessageTypeNotForIncoming {
    pub fn new(message: Message) -> Self {
        MessageTypeNotForIncoming { message }
    }
}
