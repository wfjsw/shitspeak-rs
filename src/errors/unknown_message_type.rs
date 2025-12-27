#[derive(Debug)]
pub struct UnknownMessageTypeError {
    pub message_type: u16,
}

impl std::fmt::Display for UnknownMessageTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Unknown message type: {}", self.message_type)
    }
}

impl std::error::Error for UnknownMessageTypeError {}

impl UnknownMessageTypeError {
    pub fn new(message_type: u16) -> Self {
        UnknownMessageTypeError { message_type }
    }
}
