#[derive(Debug)]
pub enum WriteProtoMessageError {
    IOError(std::io::Error),
    ProtobufEncodeError(prost::EncodeError),
}

impl From<std::io::Error> for WriteProtoMessageError {
    fn from(err: std::io::Error) -> Self {
        WriteProtoMessageError::IOError(err)
    }
}

impl From<prost::EncodeError> for WriteProtoMessageError {
    fn from(err: prost::EncodeError) -> Self {
        WriteProtoMessageError::ProtobufEncodeError(err)
    }
}

impl std::fmt::Display for WriteProtoMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WriteProtoMessageError::IOError(err) => write!(f, "IO error: {}", err),
            WriteProtoMessageError::ProtobufEncodeError(err) => write!(f, "Protobuf encode error: {}", err),
        }
    }
}

impl std::error::Error for WriteProtoMessageError {}
