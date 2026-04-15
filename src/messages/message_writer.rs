use crate::{errors::WriteProtoMessageError, messages::Message};

pub trait WriteMessageExt {
    async fn write_proto_message(&mut self, message: &Message) -> Result<(), WriteProtoMessageError>;

    /// Encode all `messages` into a single flat buffer and issue one `write_all`.
    ///
    /// When sending a burst of messages (e.g. the full channel tree + user
    /// states during authentication), calling `write_proto_message` in a loop
    /// would issue at least 3 syscalls per message (write_u16, write_u32,
    /// write_all).  This helper collapses the entire burst into a single
    /// contiguous allocation and a single `write_all`, matching the spirit of
    /// `sendmmsg` on the UDP path.
    async fn write_proto_message_batch(&mut self, messages: &[Message]) -> Result<(), WriteProtoMessageError>;
}

impl<T: tokio::io::AsyncWriteExt + Unpin> WriteMessageExt for T {
    async fn write_proto_message(&mut self, message: &Message) -> Result<(), WriteProtoMessageError> {
        let proto_tag = message.proto_tag();
        let length = message.encoded_len();
        // Encode header + payload into one buffer to minimise syscalls.
        let mut buf = Vec::with_capacity(6 + length);
        buf.extend_from_slice(&proto_tag.to_be_bytes());
        buf.extend_from_slice(&(length as u32).to_be_bytes());
        message.to_proto(&mut buf)?;
        self.write_all(&buf).await?;
        Ok(())
    }

    async fn write_proto_message_batch(&mut self, messages: &[Message]) -> Result<(), WriteProtoMessageError> {
        if messages.is_empty() {
            return Ok(());
        }

        // Pre-calculate total capacity: 6 bytes header + payload per message.
        let total = messages
            .iter()
            .map(|m| 6 + m.encoded_len())
            .sum();

        let mut buf: Vec<u8> = Vec::with_capacity(total);

        for msg in messages {
            buf.extend_from_slice(&msg.proto_tag().to_be_bytes());
            buf.extend_from_slice(&(msg.encoded_len() as u32).to_be_bytes());
            msg.to_proto(&mut buf)?;
        }

        self.write_all(&buf).await?;
        Ok(())
    }
}
