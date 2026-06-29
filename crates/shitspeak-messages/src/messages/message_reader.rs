use crate::{
    errors::{MessageLengthExceededError, ReadProtoMessageError},
    messages::Message,
};
use bytes::BytesMut;
use std::future::Future;

pub trait ReadMessageExt {
    fn read_proto_message(
        &mut self,
    ) -> impl Future<Output = Result<Message, ReadProtoMessageError>> + Send + '_;
}

impl<T: tokio::io::AsyncReadExt + Unpin + Send> ReadMessageExt for T {
    fn read_proto_message(
        &mut self,
    ) -> impl Future<Output = Result<Message, ReadProtoMessageError>> + Send + '_ {
        async move {
            const MAX_MESSAGE_LENGTH: usize = 0x7fffff;

            let message_type = self.read_u16().await?;
            let message_length = self.read_u32().await? as usize;

            if message_length > MAX_MESSAGE_LENGTH {
                return Err(
                    MessageLengthExceededError::new(MAX_MESSAGE_LENGTH, message_length).into(),
                );
            }

            let mut buffer = BytesMut::zeroed(message_length);
            self.read_exact(&mut buffer).await?;

            Ok(Message::from_proto(message_type, buffer.freeze())?)
        }
    }
}
