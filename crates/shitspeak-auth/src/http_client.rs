use std::time::Duration;

use reqwest::Client;

pub(crate) fn build_with_webpki_fallback(
    timeout: Duration,
    label: &str,
) -> Result<Client, reqwest::Error> {
    match Client::builder().timeout(timeout).build() {
        Ok(client) => Ok(client),
        Err(system_error) => {
            tracing::warn!(
                "{label}: failed to build HTTP client with platform certificate verifier: \
                 {system_error}; falling back to bundled WebPKI roots"
            );
            Client::builder()
                .timeout(timeout)
                .tls_backend_preconfigured(webpki_rustls_config())
                .build()
        }
    }
}

fn webpki_rustls_config() -> rustls::ClientConfig {
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}
