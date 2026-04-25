//! Public server registration with the Mumble server list.
//!
//! Periodically sends an XML payload to the configured registry URL so that
//! the server appears in the public server browser.
//!
//! Based on Murmur's `Register.cpp`.

use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use tracing::{info, warn};

use crate::config::Config;
use crate::server::Server;

/// Default Mumble public server registry URL.
const DEFAULT_REGISTRY_URL: &str = "https://publist-registration.mumble.info/v1/register";

/// Initial registration delay range: 60–120 seconds after startup.
const INITIAL_DELAY_MIN_SECS: u64 = 60;
const INITIAL_DELAY_MAX_SECS: u64 = 120;

/// Re-registration interval: ~1 hour with ±5 minutes jitter.
const REGISTER_INTERVAL_SECS: u64 = 3600;
const REGISTER_JITTER_SECS: u64 = 300;

/// Build the XML registration payload.
async fn build_register_xml(server: &Arc<Box<Server>>, config: &Config) -> String {
    let user_count = server.get_clients().len().await;
    let channel_count = server.get_channels().len().await;

    let host = config
        .register_hostname
        .as_deref()
        .unwrap_or("")
        .to_string();

    let port = config
        .listen
        .split(':')
        .nth(1)
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(64738);

    let location = config.register_location.as_deref().unwrap_or("");

    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<server>\n");

    // Server name
    xml.push_str("  <name>");
    xml.push_str(&escape_xml(&config.register_name));
    xml.push_str("</name>\n");

    // Host
    xml.push_str("  <host>");
    xml.push_str(&escape_xml(&host));
    xml.push_str("</host>\n");

    // Port
    xml.push_str("  <port>");
    xml.push_str(&port.to_string());
    xml.push_str("</port>\n");

    // Password (registry auth)
    if let Some(ref pw) = config.register_password {
        xml.push_str("  <password>");
        xml.push_str(&escape_xml(pw));
        xml.push_str("</password>\n");
    }

    // URL
    xml.push_str("  <url></url>\n");

    // User count
    xml.push_str("  <users>");
    xml.push_str(&user_count.to_string());
    xml.push_str("</users>\n");

    // Channel count
    xml.push_str("  <channels>");
    xml.push_str(&channel_count.to_string());
    xml.push_str("</channels>\n");

    // Location (optional)
    if !location.is_empty() {
        xml.push_str("  <location>");
        xml.push_str(&escape_xml(location));
        xml.push_str("</location>\n");
    }

    // OS info
    xml.push_str("  <os>");
    xml.push_str(&escape_xml(&std::env::consts::OS));
    xml.push_str("</os>\n");

    // OS version
    xml.push_str("  <os_version></os_version>\n");

    // Mumble version compatibility
    xml.push_str("  <version>");
    xml.push_str(&crate::constants::APP_PROTO_VER.to_string());
    xml.push_str("</version>\n");

    xml.push_str("</server>\n");
    xml
}

/// Escape special XML characters in a string.
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Check whether registration should be attempted based on config.
fn should_register(config: &Config) -> bool {
    !config.register_name.is_empty()
        && config.register_password.is_some()
        && config.register_url.is_some()
        && config.udp_ping_enabled
}

/// Spawn the periodic public server registration task.
///
/// Returns a `JoinHandle` that can be awaited for graceful shutdown.
/// The task listens on `shutdown_rx` and exits when the server shuts down.
pub fn spawn_register_task(
    server: Arc<Box<Server>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Read initial config
        let config = server.read_config().clone();

        if !should_register(&config) {
            info!(
                "Not registering server as public (missing register_name, register_password, \
                 register_url, or udp_ping_enabled)"
            );
            return;
        }

        let registry_url = config
            .register_url
            .as_deref()
            .unwrap_or(DEFAULT_REGISTRY_URL)
            .to_string();

        info!(
            "Public server registration enabled: name=\"{}\", url=\"{}\"",
            config.register_name, registry_url
        );

        // Initial delay with jitter (using time-based pseudo-randomness)
        let initial_delay_secs = {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let seed = now.subsec_micros() as u64;
            INITIAL_DELAY_MIN_SECS + (seed % (INITIAL_DELAY_MAX_SECS - INITIAL_DELAY_MIN_SECS + 1))
        };

        info!(
            "First registration attempt in {} seconds",
            initial_delay_secs
        );

        // Wait for initial delay or shutdown
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(initial_delay_secs)) => {}
            _ = shutdown_rx.changed() => {
                info!("Registration task shutting down before first attempt");
                return;
            }
        }

        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to build HTTP client for registration");

        loop {
            // Re-read config in case it was hot-reloaded
            let config = server.read_config().clone();

            if !should_register(&config) {
                info!("Registration disabled via config reload; stopping registration task");
                return;
            }

            let registry_url = config
                .register_url
                .as_deref()
                .unwrap_or(DEFAULT_REGISTRY_URL)
                .to_string();

            let xml = build_register_xml(&server, &config).await;

            info!("Registering server with public list at {}", registry_url);

            match client
                .post(&registry_url)
                .header("Content-Type", "text/xml")
                .body(xml.clone())
                .send()
                .await
            {
                Ok(resp) => {
                    if resp.status().is_success() {
                        match resp.text().await {
                            Ok(body) => info!("Registration successful: {}", body.trim()),
                            Err(e) => warn!("Registration response read failed: {}", e),
                        }
                    } else {
                        warn!(
                            "Registration failed with status {}: {:?}",
                            resp.status(),
                            resp.text().await.unwrap_or_default()
                        );
                    }
                }
                Err(e) => {
                    warn!("Registration request failed: {}", e);
                }
            }

            // Wait for next interval with jitter, or shutdown
            let next_delay_secs = {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                let seed = now.subsec_micros() as u64;
                REGISTER_INTERVAL_SECS + (seed % (REGISTER_JITTER_SECS + 1))
            };

            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(next_delay_secs)) => {}
                _ = shutdown_rx.changed() => {
                    info!("Registration task shutting down");
                    return;
                }
            }
        }
    })
}
