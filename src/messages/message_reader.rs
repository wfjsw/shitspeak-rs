use crate::{errors::MessageLengthExceededError, messages::Message};
pub trait ReadMessageExt {
    async fn read_proto_message(&mut self) -> Result<Message, ReadProtoMessageError>;
}

#[derive(Debug)]
pub enum ReadProtoMessageError {
    IOError(std::io::Error),
    MessageLengthExceeded(MessageLengthExceededError),
}

impl From<std::io::Error> for ReadProtoMessageError {
    fn from(err: std::io::Error) -> Self {
        ReadProtoMessageError::IOError(err)
    }
}

impl From<MessageLengthExceededError> for ReadProtoMessageError {
    fn from(err: MessageLengthExceededError) -> Self {
        ReadProtoMessageError::MessageLengthExceeded(err)
    }
}

impl std::fmt::Display for ReadProtoMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadProtoMessageError::IOError(err) => write!(f, "IO error: {}", err),
            ReadProtoMessageError::MessageLengthExceeded(err) => write!(f, "{}", err),
        }
    }
}

impl std::error::Error for ReadProtoMessageError {}

impl<T: tokio::io::AsyncReadExt + Unpin> ReadMessageExt for T {
    async fn read_proto_message(&mut self) -> Result<Message, ReadProtoMessageError> {
        const MAX_MESSAGE_LENGTH: usize = 8 * 1024 * 1024;

        let message_type = self.read_u16().await?;
        let message_length = self.read_u32().await? as usize;

        if message_length > MAX_MESSAGE_LENGTH {
            return Err(MessageLengthExceededError::new(MAX_MESSAGE_LENGTH, message_length).into());
        }

        let mut buffer = vec![0u8; message_length];
        self.read_exact(&mut buffer).await?;

        Message::from_proto(message_type, buffer)
    }
}
