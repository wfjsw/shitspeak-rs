pub enum UserState {
    Connected,
    ServerSentVersion,
    ClientSentVersion,
    Authenticated,
    Ready,
    Dead
}

impl Default for UserState {
    fn default() -> Self {
        UserState::Connected
    }
}
