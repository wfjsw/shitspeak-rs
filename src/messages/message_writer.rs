use crate::{messages::Message};

pub trait WriteMessageExt {
    async fn write_proto_message(&mut self, message: &Message) -> Result<(), Box<dyn std::error::Error>>;
}

impl<T: tokio::io::AsyncWriteExt + Unpin> WriteMessageExt for T {
    async fn write_proto_message(&mut self, message: &Message) -> Result<(), Box<dyn std::error::Error>> {
        let proto_tag = message.proto_tag();
        let length = message.encoded_len();
        self.write_u16(proto_tag).await?;
        self.write_u32(length as u32).await?;
        let buffer = message.to_proto_vec()?;
        self.write_all(&buffer).await?;
        Ok(())
    }
}
