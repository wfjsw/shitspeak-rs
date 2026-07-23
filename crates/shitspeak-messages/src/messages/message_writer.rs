use crate::{errors::WriteProtoMessageError, messages::Message};
use bytes::BytesMut;
use std::future::Future;

pub trait WriteMessageExt {
    fn write_proto_message<'a>(
        &'a mut self,
        message: &'a Message,
    ) -> impl Future<Output = Result<(), WriteProtoMessageError>> + Send + 'a;

    /// Encode all `messages` into a single flat buffer and issue one `write_all`.
    ///
    /// When sending a burst of messages (e.g. the full channel tree + user
    /// states during authentication), calling `write_proto_message` in a loop
    /// would issue at least 3 syscalls per message (write_u16, write_u32,
    /// write_all).  This helper collapses the entire burst into a single
    /// contiguous allocation and a single `write_all`, matching the spirit of
    /// `sendmmsg` on the UDP path.
    fn write_proto_message_batch<'a>(
        &'a mut self,
        messages: &'a [Message],
    ) -> impl Future<Output = Result<(), WriteProtoMessageError>> + Send + 'a;
}

impl<T: tokio::io::AsyncWriteExt + Unpin + Send> WriteMessageExt for T {
    // The explicit future type preserves the trait's public `Send` guarantee.
    #[allow(clippy::manual_async_fn)]
    fn write_proto_message<'a>(
        &'a mut self,
        message: &'a Message,
    ) -> impl Future<Output = Result<(), WriteProtoMessageError>> + Send + 'a {
        async move {
            let proto_tag = message.proto_tag();
            let length = message.encoded_len();
            // Encode header + payload into one buffer to minimise syscalls.
            let mut buf = BytesMut::with_capacity(6 + length);
            buf.extend_from_slice(&proto_tag.to_be_bytes());
            buf.extend_from_slice(&(length as u32).to_be_bytes());
            message.to_proto(&mut buf)?;
            self.write_all(&buf).await?;
            Ok(())
        }
    }

    // The explicit future type preserves the trait's public `Send` guarantee.
    #[allow(clippy::manual_async_fn)]
    fn write_proto_message_batch<'a>(
        &'a mut self,
        messages: &'a [Message],
    ) -> impl Future<Output = Result<(), WriteProtoMessageError>> + Send + 'a {
        async move {
            if messages.is_empty() {
                return Ok(());
            }

            // Cache each payload length while calculating the exact capacity.
            // Protobuf `encoded_len` walks the message, so recomputing it for
            // every frame header is material during large authentication bursts.
            const INLINE_LENGTH_CAPACITY: usize = 8;
            let mut inline_lengths = [0; INLINE_LENGTH_CAPACITY];
            let mut heap_lengths = Vec::new();
            let payload_lengths = if messages.len() <= INLINE_LENGTH_CAPACITY {
                &mut inline_lengths[..messages.len()]
            } else {
                heap_lengths.resize(messages.len(), 0);
                &mut heap_lengths
            };
            let mut total = messages.len() * 6;
            for (message, payload_len) in messages.iter().zip(payload_lengths.iter_mut()) {
                *payload_len = message.encoded_len();
                total += *payload_len;
            }

            let mut buf = BytesMut::with_capacity(total);

            for (msg, payload_len) in messages.iter().zip(payload_lengths.iter().copied()) {
                buf.extend_from_slice(&msg.proto_tag().to_be_bytes());
                buf.extend_from_slice(&(payload_len as u32).to_be_bytes());
                msg.to_proto(&mut buf)?;
            }

            self.write_all(&buf).await?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use shitspeak_proto::mumble_proto::Version;
    use tokio::io::AsyncReadExt as _;

    #[tokio::test]
    async fn batch_writer_preserves_message_framing() {
        let version = Version {
            version_v1: Some(0x0102_0304),
            release: Some("test".to_owned()),
            ..Version::default()
        };
        let messages = [
            Message::Version(version),
            Message::UDPTunnel(Bytes::from_static(&[0x80, 0x01, 0x02, 0x03])),
        ];

        let mut expected = Vec::new();
        for message in &messages {
            let payload = message.to_proto_vec().unwrap();
            expected.extend_from_slice(&message.proto_tag().to_be_bytes());
            expected.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            expected.extend_from_slice(&payload);
        }

        let (mut writer, mut reader) = tokio::io::duplex(256);
        writer.write_proto_message_batch(&messages).await.unwrap();
        drop(writer);

        let mut actual = Vec::new();
        reader.read_to_end(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
    }
}
