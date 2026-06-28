use std::borrow::Cow;

use crate::{
    errors::{
        AuthRejection, MessageTypeNotForIncoming, ReadProtoMessageError, WriteProtoMessageError,
    },
    messages::{
        encoder::{PermissionDenied, RejectType},
        errors::MessageProtocolError,
    },
};

#[derive(Debug)]
pub enum MessageHandlerError {
    AuthRejection(AuthRejection),
    ProtocolViolation(Cow<'static, str>),
    WriteProtoMessageError(WriteProtoMessageError),
    ReadProtoMessageError(ReadProtoMessageError),
    MessageTypeNotForIncoming(MessageTypeNotForIncoming),
    MessageProtocolError(MessageProtocolError),
    /// A handler wants to send a PermissionDenied message back to the client.
    /// The caller (handle_message) is responsible for writing it.
    PermissionDenied(PermissionDenied),
}

impl From<WriteProtoMessageError> for MessageHandlerError {
    fn from(err: WriteProtoMessageError) -> Self {
        MessageHandlerError::WriteProtoMessageError(err)
    }
}

impl From<ReadProtoMessageError> for MessageHandlerError {
    fn from(err: ReadProtoMessageError) -> Self {
        MessageHandlerError::ReadProtoMessageError(err)
    }
}

impl From<AuthRejection> for MessageHandlerError {
    fn from(err: AuthRejection) -> Self {
        MessageHandlerError::AuthRejection(err)
    }
}

impl From<RejectType> for MessageHandlerError {
    fn from(err: RejectType) -> Self {
        MessageHandlerError::AuthRejection(AuthRejection::new(err))
    }
}

impl From<MessageTypeNotForIncoming> for MessageHandlerError {
    fn from(err: MessageTypeNotForIncoming) -> Self {
        MessageHandlerError::MessageTypeNotForIncoming(err)
    }
}

impl From<MessageProtocolError> for MessageHandlerError {
    fn from(err: MessageProtocolError) -> Self {
        MessageHandlerError::MessageProtocolError(err)
    }
}

impl From<PermissionDenied> for MessageHandlerError {
    fn from(err: PermissionDenied) -> Self {
        MessageHandlerError::PermissionDenied(err)
    }
}

impl MessageHandlerError {
    pub fn protocol_violation(reason: impl Into<Cow<'static, str>>) -> Self {
        MessageHandlerError::ProtocolViolation(reason.into())
    }

    pub fn is_peer_disconnect(&self) -> bool {
        match self {
            MessageHandlerError::WriteProtoMessageError(err) => err.is_peer_disconnect(),
            MessageHandlerError::ReadProtoMessageError(err) => err.is_peer_disconnect(),
            _ => false,
        }
    }
}

impl std::fmt::Display for MessageHandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageHandlerError::AuthRejection(e) => write!(f, "Authentication rejected: {}", e),
            MessageHandlerError::ProtocolViolation(reason) => {
                write!(f, "Protocol violation: {}", reason)
            }
            MessageHandlerError::WriteProtoMessageError(e) => {
                write!(f, "Write proto message error: {}", e)
            }
            MessageHandlerError::ReadProtoMessageError(e) => {
                write!(f, "Read proto message error: {}", e)
            }
            MessageHandlerError::MessageTypeNotForIncoming(e) => {
                write!(f, "Message type not for incoming: {}", e)
            }
            MessageHandlerError::MessageProtocolError(e) => {
                write!(f, "Message protocol error: {}", e)
            }
            MessageHandlerError::PermissionDenied(deny) => {
                write!(f, "Permission denied: {:?}", deny.reason)
            }
        }
    }
}

impl std::error::Error for MessageHandlerError {}
