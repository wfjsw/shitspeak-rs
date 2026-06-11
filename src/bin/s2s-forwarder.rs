use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use serde::Deserialize;
use shitspeak_rs::config::S2sConfig;
use shitspeak_rs::logging;
use shitspeak_rs::s2s::overlay::OverlayNetwork;
use shitspeak_rs::s2s::status;
use shitspeak_rs::s2s::transport::ConnectionManager;
use tokio::sync::watch;
use tracing::{info, warn};

#[derive(Debug, Deserialize)]
struct ForwarderConfig {
    #[serde(default)]
    register_hostname: Option<String>,
    #[serde(default)]
    s2s: S2sConfig,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let _logging_guard = logging::init("s2s-forwarder")?;

    run().await
}

async fn run() -> Result<(), Box<dyn Error>> {
    let config = load_config()?;
    if !config.s2s.is_enabled() {
        return Err("s2s-forwarder requires [s2s].enabled = true".into());
    }

    let auto_advertise_host = config
        .register_hostname
        .as_deref()
        .map(str::trim)
        .filter(|host| !host.is_empty());
    let transport_config = config
        .s2s
        .transport_config_with_auto_advertise_host(auto_advertise_host)?
        .ok_or("s2s-forwarder requires an S2S transport config")?;

    let mut overlay_config = config.s2s.overlay_config();
    if !overlay_config.route_transit_messages() {
        warn!("s2s-forwarder forces overlay transit routing on");
        overlay_config = overlay_config.with_route_transit_messages(true);
    }

    let (transport, inbound) = ConnectionManager::start(transport_config).await?;
    let overlay = OverlayNetwork::start_with_max_users(
        transport.clone(),
        inbound,
        overlay_config,
        Arc::new(AtomicU64::new(0)),
    )
    .await?;

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let status_task = config.s2s.status_http_listen.and_then(|listen| {
        match status::spawn_status_server(listen, overlay.clone(), transport.clone(), shutdown_rx) {
            Ok(task) => Some(task),
            Err(error) => {
                warn!(%listen, %error, "s2s topology HTTP server startup failed");
                None
            }
        }
    });

    info!(
        node = overlay.local_node_id(),
        "s2s overlay forwarder started"
    );

    tokio::signal::ctrl_c().await?;
    info!("received Ctrl-C, shutting down s2s overlay forwarder");

    let _ = shutdown_tx.send(());
    if let Some(task) = status_task {
        let _ = task.await;
    }
    overlay.shutdown().await;
    transport.shutdown().await;

    info!("s2s overlay forwarder stopped");
    Ok(())
}

fn load_config() -> Result<ForwarderConfig, Box<dyn Error>> {
    Ok(config::Config::builder()
        .add_source(config::File::with_name("config"))
        .add_source(config::Environment::with_prefix("SHITSPEAK").separator("_"))
        .build()?
        .try_deserialize()?)
}
