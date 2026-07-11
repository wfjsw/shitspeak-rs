mod auth_rejection;
mod handle_incoming_connection_error;
mod message_handler_error;
mod message_type_not_for_incoming;
mod proxy_protocol_header_too_large;

pub use auth_rejection::AuthRejection;
pub use handle_incoming_connection_error::HandleIncomingConnectionError;
pub use message_handler_error::MessageHandlerError;
pub use message_type_not_for_incoming::MessageTypeNotForIncoming;
pub use proxy_protocol_header_too_large::ProxyProtocolHeaderTooLargeError;
pub use shitspeak_messages::errors::{
    FromProtoToMessageError, MessageLengthExceededError, ReadProtoMessageError,
    UnknownMessageTypeError, WriteProtoMessageError,
};
