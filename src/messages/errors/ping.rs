#[derive(Debug)]
pub enum PingProtocolError {
    MissingTimestamp,
}

impl std::fmt::Display for PingProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Add display implementations for each variant here
            PingProtocolError::MissingTimestamp => {
                write!(f, "Ping message is missing a timestamp")
            }
        }
    }
}

impl std::error::Error for PingProtocolError {}

impl From<PingProtocolError> for super::MessageProtocolError {
    fn from(err: PingProtocolError) -> Self {
        super::MessageProtocolError::PingProtocolError(err)
    }
}
