#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MessageLengthExceededError {
    expected_size: usize,
    actual_size: usize,
}

impl MessageLengthExceededError {
    pub fn new(expected_size: usize, actual_size: usize) -> Self {
        Self {
            expected_size,
            actual_size,
        }
    }
}

impl std::fmt::Display for MessageLengthExceededError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Message length exceeded: expected {}, got {}",
            self.expected_size, self.actual_size
        )
    }
}

impl std::error::Error for MessageLengthExceededError {}
