#![allow(warnings)]
#![allow(
    dead_code,
    unused_variables,
    unused_imports,
    unused_must_use,
    unused_assignments
)]

use crate::{api::ReloadableAuthenticator, config::Config, server::Server};

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
mod http_client;
mod localization;
mod logging;
mod messages;
mod protocol_version;
mod proxy_protocol;
mod register;
mod s2s;
mod server;
mod types;
mod user_channel_cache;
mod utils;
mod voice;
mod web;

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

mod s2s_replication_proto {
    include!(concat!(env!("OUT_DIR"), "/s2s_replication.rs"));
}

mod s2s_application_proto {
    include!(concat!(env!("OUT_DIR"), "/s2s_application.rs"));
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    logging::init("shitspeak-rs")?;

    // Probe the AES + GF(2^128) backends once at launch (each logs its
    // choice via `tracing::info!`).
    crate::client::crypt::probe_aes_backend();
    crate::client::crypt::probe_gf128_backend();

    let config = Config::load();
    let authenticator = ReloadableAuthenticator::from_wasm_path(
        config.authenticator_wasm_path.as_deref(),
        config.blob_storage_dir.as_deref(),
    )?;
    let server = Server::new_with_reloadable_authenticator(config, authenticator).await?;

    // Spawn the hot config reload watcher.
    let _watcher = config_watcher::spawn_config_watcher(server.clone(), server.shutdown_receiver());

    // Graceful shutdown: wait for Ctrl-C while the server runs.  On Ctrl-C,
    // signal shutdown and then wait for Server::run to reach its cleanup path.
    let server_run = server.run();
    tokio::pin!(server_run);

    tokio::select! {
        result = &mut server_run => {
            if let Err(e) = result {
                tracing::error!("Server exited with error: {e}");
            }
            return Ok(());
        }
        signal = tokio::signal::ctrl_c() => {
            match signal {
                Ok(()) => tracing::info!("Received Ctrl-C, shutting down."),
                Err(e) => tracing::error!("Failed to listen for Ctrl-C: {e}"),
            }
            server.shutdown();
        }
    }

    tokio::select! {
        result = &mut server_run => {
            if let Err(e) = result {
                tracing::error!("Server exited with error: {e}");
            }
        }
        signal = tokio::signal::ctrl_c() => {
            match signal {
                Ok(()) => tracing::warn!("Received Ctrl-C again, forcing shutdown."),
                Err(e) => tracing::error!("Failed to listen for additional Ctrl-C: {e}"),
            }
            std::process::exit(130);
        }
    }

    Ok(())
}
