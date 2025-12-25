#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionState {
    Connected,
    ServerSentVersion,
    ClientSentVersion,
    Authenticated,
    Ready,
    Dead
}

impl Default for ConnectionState {
    fn default() -> Self {
        ConnectionState::Connected
    }
}
