//! Shared test harness for two-client integration scenarios.

pub mod test_authenticator;
pub mod test_client;
pub mod test_server;

pub use test_authenticator::{AuthenticatorAdapter, TestAuthenticator};
pub use test_client::{ManualNativeClient, TestClient};
pub use test_server::{
    TestS2sServerOpts, TestServer, TestServerOpts, spawn_s2s_test_server,
    spawn_s2s_test_server_with_config, spawn_test_server,
};
