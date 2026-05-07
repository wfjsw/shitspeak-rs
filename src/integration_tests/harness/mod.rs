//! Shared test harness for two-client integration scenarios.

pub mod test_authenticator;
pub mod test_client;
pub mod test_server;

pub use test_authenticator::{AuthenticatorAdapter, TestAuthenticator};
pub use test_client::TestClient;
pub use test_server::{spawn_test_server, TestServer, TestServerOpts};
