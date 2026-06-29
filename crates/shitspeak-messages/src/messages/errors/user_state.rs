#[derive(Debug)]
pub enum UserStateProtocolError {
    MissingSessionId,
    VolumeAdjustmentMissingListeningChannel,
    VolumeAdjustmentMissingValue,
}

impl std::fmt::Display for UserStateProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Add display implementations for each variant here
            UserStateProtocolError::MissingSessionId => {
                write!(f, "UserState message is missing a session ID")
            }
            UserStateProtocolError::VolumeAdjustmentMissingListeningChannel => {
                write!(
                    f,
                    "VolumeAdjustment is missing a required listening channel"
                )
            }
            UserStateProtocolError::VolumeAdjustmentMissingValue => {
                write!(f, "VolumeAdjustment is missing a required value")
            }
        }
    }
}

impl std::error::Error for UserStateProtocolError {}

impl From<UserStateProtocolError> for super::MessageProtocolError {
    fn from(err: UserStateProtocolError) -> Self {
        super::MessageProtocolError::UserStateProtocolError(err)
    }
}
