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
    /// The client did not complete Authenticate before the configured deadline.
    AuthenticateTimeout(std::time::Duration),
    /// Failed to write a message to the client (connection lost).
    ClientWriteFailed(WriteProtoMessageError),
    /// The per-client writer task panicked or was cancelled.
    ClientWriterTaskFailed(tokio::task::JoinError),
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
            HandleIncomingConnectionError::AuthenticateTimeout(timeout) => {
                write!(
                    f,
                    "Client did not authenticate within {}ms",
                    timeout.as_millis()
                )
            }
            HandleIncomingConnectionError::ClientWriteFailed(err) => {
                write!(f, "Client write failed: {}", err)
            }
            HandleIncomingConnectionError::ClientWriterTaskFailed(err) => {
                write!(f, "Client writer task failed: {}", err)
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
    /// connection without sending TLS `close_notify`, or before the server
    /// could finish a pending write. This is a normal occurrence with many
    /// Mumble clients and should not be logged as a warning.
    pub fn is_clean_disconnect(&self) -> bool {
        match self {
            HandleIncomingConnectionError::IOError(err) => raw_io_error_is_peer_disconnect(err),
            HandleIncomingConnectionError::ReadProtoMessageError(err) => err.is_peer_disconnect(),
            HandleIncomingConnectionError::WriteProtoMessageError(err)
            | HandleIncomingConnectionError::ClientWriteFailed(err) => err.is_peer_disconnect(),
            HandleIncomingConnectionError::MessageHandlerFailed(err) => err.is_peer_disconnect(),
            _ => false,
        }
    }
}

impl std::error::Error for HandleIncomingConnectionError {}

fn raw_io_error_is_peer_disconnect(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::UnexpectedEof
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn io_error(kind: std::io::ErrorKind) -> std::io::Error {
        std::io::Error::new(kind, "test peer disconnect")
    }

    #[test]
    fn clean_disconnect_includes_write_side_peer_close_errors() {
        for kind in [
            std::io::ErrorKind::BrokenPipe,
            std::io::ErrorKind::ConnectionAborted,
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::UnexpectedEof,
        ] {
            let err = HandleIncomingConnectionError::ClientWriteFailed(
                WriteProtoMessageError::from(io_error(kind)),
            );
            assert!(
                err.is_clean_disconnect(),
                "{kind:?} should be treated as a clean peer disconnect"
            );
        }
    }

    #[test]
    fn clean_disconnect_includes_handler_write_peer_close_errors() {
        let err = HandleIncomingConnectionError::MessageHandlerFailed(
            MessageHandlerError::WriteProtoMessageError(WriteProtoMessageError::from(io_error(
                std::io::ErrorKind::BrokenPipe,
            ))),
        );
        assert!(err.is_clean_disconnect());
    }

    #[test]
    fn clean_disconnect_excludes_non_disconnect_write_errors() {
        let err = HandleIncomingConnectionError::ClientWriteFailed(WriteProtoMessageError::from(
            io_error(std::io::ErrorKind::PermissionDenied),
        ));
        assert!(!err.is_clean_disconnect());
    }
}
