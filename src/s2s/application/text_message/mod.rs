//! Text message fanout across S2S.
//!
//! The originator resolves channel/tree targets to concrete receiver sessions
//! using its replicated view, then groups those sessions by owning node. The
//! destination node writes the original `TextMessage` shape to locally-owned
//! recipients.

pub mod runtime;

pub use runtime::{
    OverlayTextMessageTransport, TEXT_MESSAGE_CLASS, TEXT_MESSAGE_LEVEL, TextMessageDelivery,
    TextMessageService, TextMessageSink, TextMessageTransport,
};
