#[derive(Debug)]
pub enum AudioProtocolError {
    InvalidPositionalDataLength(usize),
}

impl std::fmt::Display for AudioProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AudioProtocolError::InvalidPositionalDataLength(n) => write!(
                f,
                "Audio positional_data must be empty or exactly 3 floats, got {n}"
            ),
        }
    }
}

impl std::error::Error for AudioProtocolError {}

impl From<AudioProtocolError> for super::MessageProtocolError {
    fn from(err: AudioProtocolError) -> Self {
        super::MessageProtocolError::AudioProtocolError(err)
    }
}
