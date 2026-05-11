use crate::errors::{
    from_proto_to_message_error::FromProtoToMessageError, MessageLengthExceededError,
    UnknownMessageTypeError,
};

#[derive(Debug)]
pub enum ReadProtoMessageError {
    IOError(std::io::Error),
    ProtobufDecodeError(prost::DecodeError),
    MessageLengthExceeded(MessageLengthExceededError),
    UnknownMessageType(UnknownMessageTypeError),
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

impl From<prost::DecodeError> for ReadProtoMessageError {
    fn from(err: prost::DecodeError) -> Self {
        ReadProtoMessageError::ProtobufDecodeError(err)
    }
}

impl From<UnknownMessageTypeError> for ReadProtoMessageError {
    fn from(err: UnknownMessageTypeError) -> Self {
        ReadProtoMessageError::UnknownMessageType(err)
    }
}

impl From<FromProtoToMessageError> for ReadProtoMessageError {
    fn from(err: FromProtoToMessageError) -> Self {
        match err {
            FromProtoToMessageError::ProtobufDecodeError(e) => {
                ReadProtoMessageError::ProtobufDecodeError(e)
            }
            FromProtoToMessageError::UnknownMessageType(e) => {
                ReadProtoMessageError::UnknownMessageType(e)
            }
        }
    }
}

impl std::fmt::Display for ReadProtoMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadProtoMessageError::IOError(err) => write!(f, "IO error: {}", err),
            ReadProtoMessageError::MessageLengthExceeded(err) => write!(f, "{}", err),
            ReadProtoMessageError::ProtobufDecodeError(err) => {
                write!(f, "Protobuf decode error: {}", err)
            }
            ReadProtoMessageError::UnknownMessageType(err) => write!(f, "{}", err),
        }
    }
}

impl std::error::Error for ReadProtoMessageError {}
