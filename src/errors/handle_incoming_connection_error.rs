use crate::{
    errors::{AuthRejection, MessageHandlerError, ReadProtoMessageError, WriteProtoMessageError},
    proxy_protocol::GetProxyProtocolRealIpError,
};

#[derive(Debug)]
pub enum HandleIncomingConnectionError {
    IOError(std::io::Error),
    ReadProtoMessageError(ReadProtoMessageError),
    WriteProtoMessageError(WriteProtoMessageError),
    GetProxyProtocolRealIpError(GetProxyProtocolRealIpError),
    /// The client's log gap is unrecoverable (log pruned past last-seen version).
    ClientLogGapUnrecoverable,
    /// The client's channel log gap is unrecoverable.
    ChannelLogGapUnrecoverable,
    /// Failed to write a message to the client (connection lost).
    ClientWriteFailed(WriteProtoMessageError),
    /// Authentication was rejected after the server sent a Reject message.
    AuthRejected(AuthRejection),
    /// The client's message handler returned an error.
    MessageHandlerFailed(MessageHandlerError),
    /// A spawned message handler task panicked or was cancelled.
    MessageHandlerTaskFailed(tokio::task::JoinError),
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
            HandleIncomingConnectionError::ClientLogGapUnrecoverable => {
                write!(f, "Client log gap unrecoverable (log pruned)")
            }
            HandleIncomingConnectionError::ChannelLogGapUnrecoverable => {
                write!(f, "Channel log gap unrecoverable (log pruned)")
            }
            HandleIncomingConnectionError::ClientWriteFailed(err) => {
                write!(f, "Client write failed: {}", err)
            }
            HandleIncomingConnectionError::AuthRejected(err) => {
                write!(f, "Client authentication rejected: {}", err)
            }
            HandleIncomingConnectionError::MessageHandlerFailed(err) => {
                write!(f, "Client message handler failed: {}", err)
            }
            HandleIncomingConnectionError::MessageHandlerTaskFailed(err) => {
                write!(f, "Client message handler task failed: {}", err)
            }
        }
    }
}

impl HandleIncomingConnectionError {
    /// Returns `true` when the error represents a peer that closed the
    /// connection without sending TLS `close_notify` — a normal occurrence
    /// with many Mumble clients and should not be logged as a warning.
    pub fn is_clean_disconnect(&self) -> bool {
        let io_err = match self {
            HandleIncomingConnectionError::IOError(e) => e,
            HandleIncomingConnectionError::ReadProtoMessageError(
                ReadProtoMessageError::IOError(e),
            ) => e,
            _ => return false,
        };
        io_err.kind() == std::io::ErrorKind::UnexpectedEof
    }
}

impl std::error::Error for HandleIncomingConnectionError {}
