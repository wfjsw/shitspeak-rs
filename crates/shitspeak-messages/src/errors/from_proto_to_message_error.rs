use crate::errors::UnknownMessageTypeError;

#[derive(Debug)]
pub enum FromProtoToMessageError {
    ProtobufDecodeError(prost::DecodeError),
    UnknownMessageType(UnknownMessageTypeError),
}

impl From<UnknownMessageTypeError> for FromProtoToMessageError {
    fn from(err: UnknownMessageTypeError) -> Self {
        FromProtoToMessageError::UnknownMessageType(err)
    }
}

impl From<prost::DecodeError> for FromProtoToMessageError {
    fn from(err: prost::DecodeError) -> Self {
        FromProtoToMessageError::ProtobufDecodeError(err)
    }
}

impl std::fmt::Display for FromProtoToMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FromProtoToMessageError::ProtobufDecodeError(err) => {
                write!(f, "Protobuf decode error: {}", err)
            }
            FromProtoToMessageError::UnknownMessageType(err) => write!(f, "{}", err),
        }
    }
}

impl std::error::Error for FromProtoToMessageError {}
