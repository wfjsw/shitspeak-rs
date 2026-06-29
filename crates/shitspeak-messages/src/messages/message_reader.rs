use crate::{
    errors::{MessageLengthExceededError, ReadProtoMessageError},
    messages::Message,
};
use bytes::BytesMut;
pub trait ReadMessageExt {
    async fn read_proto_message(&mut self) -> Result<Message, ReadProtoMessageError>;
}

impl<T: tokio::io::AsyncReadExt + Unpin> ReadMessageExt for T {
    async fn read_proto_message(&mut self) -> Result<Message, ReadProtoMessageError> {
        const MAX_MESSAGE_LENGTH: usize = 0x7fffff;

        let message_type = self.read_u16().await?;
        let message_length = self.read_u32().await? as usize;

        if message_length > MAX_MESSAGE_LENGTH {
            return Err(MessageLengthExceededError::new(MAX_MESSAGE_LENGTH, message_length).into());
        }

        let mut buffer = BytesMut::zeroed(message_length);
        self.read_exact(&mut buffer).await?;

        Ok(Message::from_proto(message_type, buffer.freeze())?)
    }
}
