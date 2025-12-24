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
