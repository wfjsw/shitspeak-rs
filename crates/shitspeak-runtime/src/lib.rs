pub mod blob_store;
pub mod channel_handler;
pub mod client;
pub mod client_certificate_verifier;
pub mod client_repository;
pub mod codec_info;
pub mod config_watcher;
pub mod constants;
pub mod context_action;
pub mod errors;
pub mod forwarder;
pub mod geoip;
pub mod http_client;
pub mod localization;
pub mod logging;
pub mod messages {
    pub use shitspeak_messages::messages::*;
}
pub mod observability;
pub mod privacy;
pub mod protocol_version;
pub mod proxy_protocol;
pub mod rate_limits;
pub mod register;
pub mod runtime_workers;
pub mod s2s;
pub mod server;
pub(crate) mod tcp_packet_collector;
pub mod tls_fingerprint;
pub(crate) mod toggle_superuser_visibility;
pub mod types;
pub mod user_channel_cache;
pub mod utils;
pub mod voice;

#[cfg(test)]
mod integration_tests;

pub struct ServerBuilder {
    extensions: server::ServerExtensions,
    config_path: std::path::PathBuf,
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self {
            extensions: server::ServerExtensions::default(),
            config_path: std::path::PathBuf::from("config.toml"),
        }
    }
}

impl ServerBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_extension(mut self, extensions: server::ServerExtensions) -> Self {
        self.extensions = extensions;
        self
    }

    pub fn with_config_path(mut self, config_path: impl AsRef<std::path::Path>) -> Self {
        self.config_path = config_path.as_ref().to_path_buf();
        self
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        use crate::server::Server;
        use shitspeak_auth::ReloadableAuthenticator;
        use shitspeak_runtime_config::Config;

        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");

        let logging_guard = logging::init("shitspeak-rs", &self.config_path)?;
        let runtime_workers = runtime_workers::runtime_worker_allocation();
        tracing::info!(
            main_workers = runtime_workers.main(),
            s2s_workers = runtime_workers.s2s(),
            acl_bulk_workers = runtime_workers.acl_bulk(),
            "runtime worker allocation resolved"
        );

        shitspeak_client_crypto::probe_aes_backend();
        shitspeak_client_crypto::probe_gf128_backend();

        let config = Config::load_from(&self.config_path);
        let dispatch_tuning =
            voice::dispatch_tuning::resolve_voice_dispatch_plan(config.voice.dispatch()).await?;
        let dispatch_plan = dispatch_tuning.plan();
        tracing::info!(
            source = dispatch_plan.source().as_str(),
            elapsed_ms = dispatch_tuning.elapsed().as_millis(),
            rayon_workers = dispatch_tuning.rayon_workers(),
            small_payload_threshold = dispatch_plan.small_payload().fanout_threshold(),
            small_payload_min_len = dispatch_plan.small_payload().rayon_min_len(),
            small_payload_breakpoints = ?dispatch_plan.small_payload().breakpoints(),
            large_payload_threshold = dispatch_plan.large_payload().fanout_threshold(),
            large_payload_min_len = dispatch_plan.large_payload().rayon_min_len(),
            large_payload_breakpoints = ?dispatch_plan.large_payload().breakpoints(),
            "voice dispatch tuning resolved"
        );
        voice::metrics::record_dispatch_tuning(dispatch_plan, dispatch_tuning.elapsed());
        let authenticator = ReloadableAuthenticator::from_config(&config)?;
        let server =
            Server::new_with_reloadable_authenticator_and_extensions_and_voice_dispatch_plan(
                config,
                authenticator,
                self.extensions,
                dispatch_plan,
            )
            .await?;

        let _watcher = config_watcher::spawn_config_watcher(
            server.clone(),
            server.shutdown_receiver(),
            self.config_path,
        );

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
                logging_guard.flush();
                std::process::exit(130);
            }
        }

        Ok(())
    }
}

pub async fn run_server_with_extensions(
    extensions: server::ServerExtensions,
) -> Result<(), Box<dyn std::error::Error>> {
    ServerBuilder::new().with_extension(extensions).run().await
}

pub async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    run_server_with_extensions(server::ServerExtensions::default()).await
}
