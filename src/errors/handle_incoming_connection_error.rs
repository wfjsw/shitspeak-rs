use crate::{errors::{ReadProtoMessageError, WriteProtoMessageError}, proxy_protocol::GetProxyProtocolRealIpError};

#[derive(Debug)]
pub enum HandleIncomingConnectionError {
    IOError(std::io::Error),
    ReadProtoMessageError(ReadProtoMessageError),
    WriteProtoMessageError(WriteProtoMessageError),
    GetProxyProtocolRealIpError(GetProxyProtocolRealIpError),
}

impl From<std::io::Error> for HandleIncomingConnectionError {
    fn from(err: std::io::Error) -> Self {
        HandleIncomingConnectionError::IOError(err)
    }
}

impl From<ReadProtoMessageError> for HandleIncomingConnectionError {
    fn from(err: ReadProtoMessageError) -> Self {
        HandleIncomingConnectionError::ReadProtoMessageError(err)
    }
}

impl From<WriteProtoMessageError> for HandleIncomingConnectionError {
    fn from(err: WriteProtoMessageError) -> Self {
        HandleIncomingConnectionError::WriteProtoMessageError(err)
    }
}

impl From<GetProxyProtocolRealIpError> for HandleIncomingConnectionError {
    fn from(err: GetProxyProtocolRealIpError) -> Self {
        HandleIncomingConnectionError::GetProxyProtocolRealIpError(err)
    }
}

impl std::fmt::Display for HandleIncomingConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandleIncomingConnectionError::IOError(err) => write!(f, "IO error: {}", err),
            HandleIncomingConnectionError::ReadProtoMessageError(err) => {
                write!(f, "Read proto message error: {}", err)
            }
            HandleIncomingConnectionError::WriteProtoMessageError(err) => {
                write!(f, "Write proto message error: {}", err)
            }
            HandleIncomingConnectionError::GetProxyProtocolRealIpError(err) => {
                write!(f, "Get proxy protocol real IP error: {}", err)
            }
        }
    }
}

impl std::error::Error for HandleIncomingConnectionError {}
