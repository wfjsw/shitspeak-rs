use crate::messages::Message;
pub trait ReadMessageExt {
    async fn read_proto_message(&mut self) -> Result<Message, Box<dyn std::error::Error>>;
}

impl<T: tokio::io::AsyncReadExt + Unpin> ReadMessageExt for T {
    async fn read_proto_message(&mut self) -> Result<Message, Box<dyn std::error::Error>> {
        let message_type = self.read_u16().await?;
        let message_length = self.read_u32().await?;

        if message_length > 8 * 1024 * 1024 {
            return Err("Message length exceeds maximum allowed size".into());
        }

        let mut buffer = vec![0u8; message_length as usize];
        self.read_exact(&mut buffer).await?;

        Message::from_proto(message_type, buffer)
    }
}
