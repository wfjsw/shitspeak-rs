#![allow(warnings)]
#![allow(dead_code, unused_variables, unused_imports, unused_must_use, unused_assignments)]

use crate::{config::Config, server::Server};

mod acl;
mod api;
mod ban_repository;
mod blob_store;
mod channel_handler;
mod channel_repository;
mod channels;
mod client;
mod client_certificate_verifier;
mod client_repository;
mod codec_info;
mod config;
mod config_watcher;
mod constants;
mod context_action;
mod errors;
mod geoip;
mod messages;
mod protocol_version;
mod proxy_protocol;
mod register;
mod s2s;
mod server;
mod types;
mod utils;
mod voice;
mod voice_crypto;

mod mumble_proto {
    include!(concat!(env!("OUT_DIR"), "/mumble_proto.rs"));
}

mod mumble_udp {
    include!(concat!(env!("OUT_DIR"), "/mumble_udp.rs"));
}

mod s2s_transport_proto {
    include!(concat!(env!("OUT_DIR"), "/s2s_transport.rs"));
}

mod s2s_overlay_proto {
    include!(concat!(env!("OUT_DIR"), "/s2s_overlay.rs"));
}

/// Minimal no-op authenticator used when no external auth backend is wired up.
struct NoopAuthenticator;

#[async_trait::async_trait]
impl api::Authenticator for NoopAuthenticator {
    async fn authenticate(
        &self,
        username: &str,
        _password: Option<&str>,
        _auxiliary_data: &api::AuthenticateAuxiliaryData,
    ) -> Result<api::AuthenticateResult, api::AuthenticationRejection> {
        // Accept everyone with no user ID (guests only).
        // Users with username "admin" get the "admin" group for superuser privileges.
        let groups = if username == "admin" {
            vec!["admin".to_owned()]
        } else {
            Vec::new()
        };
        Ok(api::AuthenticateResult {
            user_id: None,
            display_name: Some(username.to_owned()),
            groups,
            texture_url: None,
            comment_url: None,
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Config::load();
    let server = Server::new(config, NoopAuthenticator).await?;

    // Shutdown signal: dropping the sender notifies all spawned tasks.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());

    // Spawn the hot config reload watcher.
    let _watcher = config_watcher::spawn_config_watcher(server.clone(), shutdown_rx);

    // Graceful shutdown: wait for Ctrl-C while the server runs.
    tokio::select! {
        result = server.run(shutdown_tx) => {
            if let Err(e) = result {
                tracing::error!("Server exited with error: {e}");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received Ctrl-C, shutting down.");
        }
    }

    Ok(())
}
