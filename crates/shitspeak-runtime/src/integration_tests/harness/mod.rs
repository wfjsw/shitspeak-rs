//! Shared test harness for two-client integration scenarios.

pub mod test_authenticator;
pub mod test_client;
pub mod test_server;

pub use test_authenticator::{AuthenticatorAdapter, TestAuthenticator};
pub use test_client::{ManualNativeClient, TestClient};
pub use test_server::{
    TestS2sServerOpts, TestServer, TestServerOpts, TestStrictReplicationState,
    spawn_s2s_test_server, spawn_s2s_test_server_with_config, spawn_s2s_test_server_with_state,
    spawn_test_server, test_user_channel_cache_key,
};

/// Payload of a voice frame. Scenarios only care that a frame arrives, so one
/// fixed buffer serves them all; the server never decodes it.
pub(crate) const SAMPLE_OPUS: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
