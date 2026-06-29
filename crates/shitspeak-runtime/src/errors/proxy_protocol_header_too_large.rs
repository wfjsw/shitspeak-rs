#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProxyProtocolHeaderTooLargeError {
    expected_size: usize,
    actual_size: usize,
}

impl std::fmt::Display for ProxyProtocolHeaderTooLargeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Proxy protocol header is too large: expected {} bytes, got {} bytes",
            self.expected_size, self.actual_size
        )
    }
}

impl std::error::Error for ProxyProtocolHeaderTooLargeError {}

impl ProxyProtocolHeaderTooLargeError {
    pub fn new(expected_size: usize, actual_size: usize) -> Self {
        Self {
            expected_size,
            actual_size,
        }
    }
}
