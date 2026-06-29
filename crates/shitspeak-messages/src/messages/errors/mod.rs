mod audio;
mod ping;
mod user_state;
use std::fmt::Display;

pub use audio::*;
pub use ping::*;
pub use user_state::*;

#[derive(Debug)]
pub enum MessageProtocolError {
    PingProtocolError(PingProtocolError),
    UserStateProtocolError(UserStateProtocolError),
    AudioProtocolError(AudioProtocolError),
}

impl Display for MessageProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageProtocolError::PingProtocolError(e) => {
                write!(f, "Ping protocol error: {}", e)
            }
            MessageProtocolError::UserStateProtocolError(e) => {
                write!(f, "UserState protocol error: {}", e)
            }
            MessageProtocolError::AudioProtocolError(e) => {
                write!(f, "Audio protocol error: {}", e)
            }
        }
    }
}

impl std::error::Error for MessageProtocolError {}
