//! Public server registration with the Mumble server list.
//!
//! Periodically sends an XML payload to the fixed registry URL so that
//! the server appears in the public server browser.
//!
//! Based on Murmur's `Register.cpp`.

use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
use tracing::{info, warn};

use crate::server::Server;
use crate::types::DEFAULT_SERVER_ID;
use shitspeak_runtime_config::Config;

/// Mumble public server registry submission URL.
const REGISTRY_URL: &str = "https://publist-registration.mumble.info/v1/register";

/// Initial registration delay range: 60–120 seconds after startup.
const INITIAL_DELAY_MIN_SECS: u64 = 60;
const INITIAL_DELAY_MAX_SECS: u64 = 120;

/// Re-registration interval: ~1 hour with ±5 minutes jitter.
const REGISTER_INTERVAL_SECS: u64 = 3600;
const REGISTER_JITTER_SECS: u64 = 300;
const REGISTRATION_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

struct RegistrationCredentials {
    digest: String,
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
}

/// Build the XML registration payload.
async fn build_register_xml(server: &Arc<Box<Server>>, config: &Config, digest: &str) -> String {
    let user_count = server.get_clients().len_in_server(DEFAULT_SERVER_ID).await;
    let channel_count = server.get_channels().len_in_server(DEFAULT_SERVER_ID).await;

    build_register_xml_with_counts(config, digest, user_count, channel_count)
}

fn build_register_xml_with_counts(
    config: &Config,
    digest: &str,
    user_count: usize,
    channel_count: usize,
) -> String {
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
    let advertised_url = config.register_url.as_deref().unwrap_or("");

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

    // Public server URL
    xml.push_str("  <url>");
    xml.push_str(&escape_xml(advertised_url));
    xml.push_str("</url>\n");

    // SHA-1 of the DER-encoded leaf TLS certificate. The public registry uses
    // this to verify that the registration request represents the server it
    // subsequently probes.
    xml.push_str("  <digest>");
    xml.push_str(digest);
    xml.push_str("</digest>\n");

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
    xml.push_str(&config.server_protocol_version.to_string());
    xml.push_str("</version>\n");

    xml.push_str("</server>\n");
    xml
}

async fn load_registration_credentials(config: &Config) -> Result<RegistrationCredentials, String> {
    let certificate_pem = tokio::fs::read(&config.cert_path)
        .await
        .map_err(|error| format!("read TLS certificate {:?}: {error}", config.cert_path))?;
    let private_key_pem = tokio::fs::read(&config.key_path)
        .await
        .map_err(|error| format!("read TLS private key {:?}: {error}", config.key_path))?;

    registration_credentials_from_pem(&certificate_pem, &private_key_pem)
}

fn registration_credentials_from_pem(
    certificate_pem: &[u8],
    private_key_pem: &[u8],
) -> Result<RegistrationCredentials, String> {
    let certificate_chain = CertificateDer::pem_slice_iter(certificate_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("parse TLS certificate: {error}"))?;
    let leaf_certificate = certificate_chain
        .first()
        .ok_or_else(|| "TLS certificate PEM contains no certificates".to_owned())?;
    let private_key = PrivateKeyDer::from_pem_slice(private_key_pem)
        .map_err(|error| format!("parse TLS private key: {error}"))?;

    Ok(RegistrationCredentials {
        digest: hex::encode(digest(&SHA1_FOR_LEGACY_USE_ONLY, leaf_certificate.as_ref()).as_ref()),
        certificate_chain,
        private_key,
    })
}

fn build_registration_client(
    credentials: RegistrationCredentials,
) -> Result<reqwest::Client, String> {
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(credentials.certificate_chain, credentials.private_key)
        .map_err(|error| format!("configure registration client certificate: {error}"))?;
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    reqwest::Client::builder()
        .timeout(REGISTRATION_HTTP_TIMEOUT)
        .tls_backend_preconfigured(tls_config)
        .build()
        .map_err(|error| format!("build registration HTTP client: {error}"))
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
                 advertised register_url, or udp_ping_enabled)"
            );
            return;
        }

        info!(
            "Public server registration enabled: name=\"{}\", registry_url=\"{}\", \
             advertised_url=\"{}\"",
            config.register_name,
            REGISTRY_URL,
            config.register_url.as_deref().unwrap_or("")
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

        loop {
            // Re-read config in case it was hot-reloaded
            let config = server.read_config().clone();

            if !should_register(&config) {
                info!("Registration disabled via config reload; stopping registration task");
                return;
            }

            match load_registration_credentials(&config).await {
                Ok(credentials) => {
                    let xml = build_register_xml(&server, &config, &credentials.digest).await;

                    match build_registration_client(credentials) {
                        Ok(client) => {
                            info!("Registering server with public list at {}", REGISTRY_URL);

                            match client
                                .post(REGISTRY_URL)
                                .header("Content-Type", "text/xml")
                                .body(xml)
                                .send()
                                .await
                            {
                                Ok(resp) => {
                                    if resp.status().is_success() {
                                        match resp.text().await {
                                            Ok(body) => {
                                                info!("Registration successful: {}", body.trim())
                                            }
                                            Err(e) => {
                                                warn!("Registration response read failed: {}", e)
                                            }
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
                        }
                        Err(error) => {
                            warn!(%error, "Registration skipped: failed to build mTLS client");
                        }
                    }
                }
                Err(error) => {
                    warn!(%error, "Registration skipped: failed to load TLS identity");
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_config(raw: &str) -> Config {
        ::config::Config::builder()
            .add_source(::config::File::from_str(raw, ::config::FileFormat::Toml))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("config deserialize")
    }

    #[test]
    fn register_url_is_written_to_xml_url_element() {
        let config = parse_config(
            r#"
                listen = "127.0.0.1:64738"
                register_name = "test"
                register_password = "secret"
                register_url = "mumble://voice.example.test:64738/?title=ShitSpeak&region=us"
                register_hostname = "voice.example.test"
                cert_path = "cert.pem"
                key_path = "key.pem"
                send_version = true
                send_build_info = true
                send_os_info = true
                allowed_proxies = []
                min_client_version = 0
                max_users = 100
            "#,
        );

        let digest = "0123456789abcdef0123456789abcdef01234567";
        let xml = build_register_xml_with_counts(&config, digest, 12, 3);

        assert!(xml.contains(
            "<url>mumble://voice.example.test:64738/?title=ShitSpeak&amp;region=us</url>"
        ));
        assert!(xml.contains(&format!("<digest>{digest}</digest>")));
        assert!(xml.contains("<users>12</users>"));
        assert!(xml.contains("<channels>3</channels>"));
    }

    #[test]
    fn registration_credentials_digest_the_leaf_certificate() {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate certificate");
        let certificate_pem = certificate.cert.pem();
        let private_key_pem = certificate.key_pair.serialize_pem();
        let leaf_certificate = CertificateDer::pem_slice_iter(certificate_pem.as_bytes())
            .next()
            .expect("certificate PEM contains a leaf certificate")
            .expect("parse leaf certificate");

        let credentials = registration_credentials_from_pem(
            certificate_pem.as_bytes(),
            private_key_pem.as_bytes(),
        )
        .expect("load registration credentials");
        let expected_digest =
            hex::encode(digest(&SHA1_FOR_LEGACY_USE_ONLY, leaf_certificate.as_ref()).as_ref());

        assert_eq!(credentials.digest, expected_digest);
        build_registration_client(credentials).expect("build mTLS registration client");
    }

    #[test]
    fn registry_submission_url_is_fixed_to_mumble_endpoint() {
        assert_eq!(
            REGISTRY_URL,
            "https://publist-registration.mumble.info/v1/register"
        );
    }
}
