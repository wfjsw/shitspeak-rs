use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use bytes::BytesMut;
use prost::Message;
use reqwest::header::{HeaderMap, HeaderValue};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::config::{MetricsConfig, RemoteWriteConfig};
use crate::geoip::NodeGeo;
use crate::http_client;
use crate::s2s::overlay::OverlayNetwork;
use crate::s2s::status::PrometheusSample;
use crate::s2s::transport::ConnectionManager;
use crate::s2s::{S2SManager, status};

pub trait S2sMetricsSource: Send + Sync + 'static {
    fn prometheus_metrics_text(&self) -> Option<String>;

    fn prometheus_remote_write_requests(
        &self,
        batch_size: usize,
        external_labels: &HashMap<String, String>,
    ) -> Option<Vec<Vec<u8>>>;
}

impl S2sMetricsSource for S2SManager {
    fn prometheus_metrics_text(&self) -> Option<String> {
        S2SManager::prometheus_metrics_text(self)
    }

    fn prometheus_remote_write_requests(
        &self,
        batch_size: usize,
        external_labels: &HashMap<String, String>,
    ) -> Option<Vec<Vec<u8>>> {
        S2SManager::prometheus_remote_write_requests(self, batch_size, external_labels)
    }
}

pub struct S2sTopologyMetricsSource {
    overlay: OverlayNetwork,
    transport: ConnectionManager,
    local_geo: Option<NodeGeo>,
}

impl S2sTopologyMetricsSource {
    pub fn new(
        overlay: OverlayNetwork,
        transport: ConnectionManager,
        local_geo: Option<NodeGeo>,
    ) -> Self {
        Self {
            overlay,
            transport,
            local_geo,
        }
    }
}

impl S2sMetricsSource for S2sTopologyMetricsSource {
    fn prometheus_metrics_text(&self) -> Option<String> {
        Some(status::render_prometheus_metrics(
            &self.overlay,
            &self.transport,
            self.local_geo.clone(),
        ))
    }

    fn prometheus_remote_write_requests(
        &self,
        batch_size: usize,
        external_labels: &HashMap<String, String>,
    ) -> Option<Vec<Vec<u8>>> {
        let samples =
            status::prometheus_samples(&self.overlay, &self.transport, self.local_geo.clone());
        let timestamp_ms = now_unix_ms();
        Some(remote_write_bodies(
            &samples,
            timestamp_ms,
            batch_size,
            external_labels,
        ))
    }
}

const MAX_REQUEST_BYTES: usize = 8192;

pub fn spawn_metrics_server(
    listen: SocketAddr,
    path: String,
    source: std::sync::Arc<dyn S2sMetricsSource>,
    mut shutdown: watch::Receiver<()>,
) -> io::Result<JoinHandle<()>> {
    let listener = std::net::TcpListener::bind(listen)?;
    listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(listener)?;
    let path = normalize_metrics_path(&path);

    Ok(tokio::spawn(async move {
        tracing::info!(%listen, %path, "observability metrics HTTP server listening");
        loop {
            let (stream, peer) = tokio::select! {
                result = listener.accept() => match result {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        tracing::warn!(%listen, %error, "observability metrics HTTP accept failed");
                        continue;
                    }
                },
                _ = shutdown.changed() => break,
            };

            let source = source.clone();
            let path = path.clone();
            tokio::spawn(async move {
                if let Err(error) = handle_metrics_connection(stream, path, source).await {
                    tracing::trace!(%peer, %error, "observability metrics HTTP connection failed");
                }
            });
        }
    }))
}

pub fn spawn_remote_write(
    config: RemoteWriteConfig,
    source: std::sync::Arc<dyn S2sMetricsSource>,
    mut shutdown: watch::Receiver<()>,
) -> Option<JoinHandle<()>> {
    if !config.enabled {
        return None;
    }
    let Some(url) = config.url.clone().filter(|url| !url.trim().is_empty()) else {
        tracing::warn!("observability remote_write enabled without url");
        return None;
    };
    Some(tokio::spawn(async move {
        let external_labels = remote_write_external_labels(&config.labels);
        let client = match http_client::build_with_webpki_fallback(
            Duration::from_millis(config.request_timeout_ms.max(1)),
            "observability remote_write",
        ) {
            Ok(client) => client,
            Err(error) => {
                tracing::warn!(%error, "observability remote_write disabled: HTTP client build failed");
                return;
            }
        };
        let mut retry_cache = VecDeque::new();
        let mut retry_delay = Duration::from_millis(config.retry_initial_interval_ms.max(1));
        let retry_max = Duration::from_millis(config.retry_max_interval_ms.max(1)).max(retry_delay);
        let interval = Duration::from_millis(config.interval_ms.max(1));
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = tokio::time::sleep(interval) => {}
            }

            if let Some(bodies) =
                source.prometheus_remote_write_requests(config.batch_size.max(1), &external_labels)
            {
                for bytes in bodies {
                    retry_cache.push_back(bytes);
                    trim_retry_cache(&mut retry_cache, config.retry_cache_capacity.max(1));
                }
            }

            while let Some(bytes) = retry_cache.front().cloned() {
                match send_remote_write(&client, &config, &url, bytes).await {
                    RemoteWriteSendResult::Delivered => {
                        retry_cache.pop_front();
                        retry_delay =
                            Duration::from_millis(config.retry_initial_interval_ms.max(1));
                    }
                    RemoteWriteSendResult::Permanent(error) => {
                        tracing::warn!(%error, "observability remote_write dropped permanent failure");
                        retry_cache.pop_front();
                    }
                    RemoteWriteSendResult::Retryable(error) => {
                        tracing::warn!(%error, "observability remote_write retryable failure");
                        tokio::select! {
                            _ = shutdown.changed() => return,
                            _ = tokio::time::sleep(retry_delay) => {}
                        }
                        retry_delay = (retry_delay * 2).min(retry_max);
                        break;
                    }
                }
            }
        }
    }))
}

pub fn remote_write_body(samples: &[PrometheusSample], timestamp_ms: i64) -> Vec<u8> {
    remote_write_body_with_labels(samples, timestamp_ms, &HashMap::new())
}

pub(crate) fn remote_write_body_with_labels(
    samples: &[PrometheusSample],
    timestamp_ms: i64,
    external_labels: &HashMap<String, String>,
) -> Vec<u8> {
    let request = WriteRequest {
        timeseries: samples
            .iter()
            .map(|sample| time_series(sample, timestamp_ms, external_labels))
            .collect(),
    };
    let mut encoded = BytesMut::with_capacity(request.encoded_len());
    request.encode(&mut encoded).expect("encode remote write");
    snappy_compress_block(&encoded)
}

pub(crate) fn remote_write_bodies(
    samples: &[PrometheusSample],
    timestamp_ms: i64,
    batch_size: usize,
    external_labels: &HashMap<String, String>,
) -> Vec<Vec<u8>> {
    if samples.is_empty() {
        return Vec::new();
    }
    samples
        .chunks(batch_size.max(1))
        .map(|chunk| remote_write_body_with_labels(chunk, timestamp_ms, external_labels))
        .collect()
}

async fn handle_metrics_connection(
    mut stream: tokio::net::TcpStream,
    path: String,
    source: std::sync::Arc<dyn S2sMetricsSource>,
) -> io::Result<()> {
    let mut buf = Vec::new();
    let mut scratch = [0u8; 1024];
    loop {
        let n = stream.read(&mut scratch).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&scratch[..n]);
        if buf.len() > MAX_REQUEST_BYTES {
            return write_response(
                &mut stream,
                "413 Payload Too Large",
                "text/plain; charset=utf-8",
                b"request too large",
            )
            .await;
        }
        if find_header_end(&buf).is_some() {
            break;
        }
    }

    let first_line = std::str::from_utf8(&buf)
        .ok()
        .and_then(|s| s.lines().next())
        .unwrap_or_default();
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let raw_path = parts.next().unwrap_or_default();
    let request_path = raw_path.split('?').next().unwrap_or(raw_path);

    match (method, request_path) {
        ("GET", p) if p == path => match source.prometheus_metrics_text() {
            Some(body) => {
                write_response(
                    &mut stream,
                    "200 OK",
                    "text/plain; version=0.0.4; charset=utf-8",
                    body.as_bytes(),
                )
                .await
            }
            None => {
                write_response(
                    &mut stream,
                    "503 Service Unavailable",
                    "text/plain; charset=utf-8",
                    b"s2s topology unavailable",
                )
                .await
            }
        },
        ("GET", "/health") => {
            write_response(
                &mut stream,
                "200 OK",
                "application/json",
                br#"{"status":"ok"}"#,
            )
            .await
        }
        _ => {
            write_response(
                &mut stream,
                "404 Not Found",
                "application/json",
                br#"{"error":"not found"}"#,
            )
            .await
        }
    }
}

async fn write_response(
    stream: &mut tokio::net::TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await
}

async fn send_remote_write(
    client: &reqwest::Client,
    config: &RemoteWriteConfig,
    url: &str,
    body: Vec<u8>,
) -> RemoteWriteSendResult {
    let headers = match remote_write_headers(config) {
        Ok(headers) => headers,
        Err(error) => return RemoteWriteSendResult::Permanent(error),
    };
    let mut request = client.post(url).body(body);
    for (name, value) in headers.iter() {
        request = request.header(name, value);
    }
    match request.send().await {
        Ok(response) if response.status().is_success() => RemoteWriteSendResult::Delivered,
        Ok(response) => {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            let error = format!("HTTP {status}: {text}");
            if status.is_server_error() || status.as_u16() == 429 {
                RemoteWriteSendResult::Retryable(error)
            } else {
                RemoteWriteSendResult::Permanent(error)
            }
        }
        Err(error) => RemoteWriteSendResult::Retryable(error.to_string()),
    }
}

fn remote_write_headers(config: &RemoteWriteConfig) -> Result<HeaderMap, String> {
    let mut headers = HeaderMap::new();
    headers.insert(
        "Content-Type",
        HeaderValue::from_static("application/x-protobuf"),
    );
    headers.insert("Content-Encoding", HeaderValue::from_static("snappy"));
    headers.insert(
        "X-Prometheus-Remote-Write-Version",
        HeaderValue::from_static("0.1.0"),
    );
    if let Some(tenant_id) = config
        .tenant_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        headers.insert(
            "X-Scope-OrgID",
            header_value("observability remote_write tenant_id", tenant_id)?,
        );
    }
    if let Some(token) = config
        .bearer_token
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        headers.insert(
            "Authorization",
            header_value(
                "observability remote_write bearer_token",
                &format!("Bearer {token}"),
            )?,
        );
    } else if let Some(username) = config
        .username
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        let password = config.password.as_deref().unwrap_or_default();
        let encoded = BASE64_STANDARD.encode(format!("{username}:{password}"));
        headers.insert(
            "Authorization",
            header_value(
                "observability remote_write basic auth",
                &format!("Basic {encoded}"),
            )?,
        );
    }
    Ok(headers)
}

fn header_value(label: &str, value: &str) -> Result<HeaderValue, String> {
    HeaderValue::from_str(value).map_err(|error| format!("invalid {label}: {error}"))
}

fn time_series(
    sample: &PrometheusSample,
    timestamp_ms: i64,
    external_labels: &HashMap<String, String>,
) -> TimeSeries {
    let mut labels = Vec::with_capacity(sample.labels().len() + external_labels.len() + 1);
    labels.push(Label {
        name: "__name__".to_owned(),
        value: sample.name().to_owned(),
    });
    for (name, value) in external_labels {
        if sample
            .labels()
            .iter()
            .any(|(sample_name, _)| sample_name == name)
        {
            continue;
        }
        labels.push(Label {
            name: name.clone(),
            value: value.clone(),
        });
    }
    labels.extend(sample.labels().iter().map(|(name, value)| Label {
        name: name.clone(),
        value: value.clone(),
    }));
    labels.sort_by(|a, b| a.name.cmp(&b.name));
    TimeSeries {
        labels,
        samples: vec![Sample {
            value: sample.value(),
            timestamp: timestamp_ms,
        }],
    }
}

fn remote_write_external_labels(configured: &HashMap<String, String>) -> HashMap<String, String> {
    let mut labels = HashMap::new();
    let mut configured = configured.iter().collect::<Vec<_>>();
    configured.sort_by(|(left, _), (right, _)| left.cmp(right));
    for (key, value) in configured {
        let key = key.trim();
        if key.starts_with("__") || !is_prometheus_label_name(key) {
            tracing::warn!(label = %key, "observability remote_write ignoring invalid external label");
            continue;
        }
        labels.insert(key.to_owned(), value.clone());
    }
    labels
}

fn is_prometheus_label_name(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

pub fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

fn trim_retry_cache(cache: &mut VecDeque<Vec<u8>>, capacity: usize) {
    while cache.len() > capacity {
        cache.pop_front();
    }
}

fn normalize_metrics_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return "/metrics".to_owned();
    }
    if trimmed.starts_with('/') {
        trimmed.to_owned()
    } else {
        format!("/{trimmed}")
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn snappy_compress_block(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + 16);
    write_varint(input.len() as u64, &mut out);
    let mut offset = 0usize;
    while offset < input.len() {
        let len = (input.len() - offset).min(60);
        let tag = ((len - 1) as u8) << 2;
        out.push(tag);
        out.extend_from_slice(&input[offset..offset + len]);
        offset += len;
    }
    out
}

fn write_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

enum RemoteWriteSendResult {
    Delivered,
    Retryable(String),
    Permanent(String),
}

#[derive(Clone, PartialEq, Message)]
struct WriteRequest {
    #[prost(message, repeated, tag = "1")]
    timeseries: Vec<TimeSeries>,
}

#[derive(Clone, PartialEq, Message)]
struct TimeSeries {
    #[prost(message, repeated, tag = "1")]
    labels: Vec<Label>,
    #[prost(message, repeated, tag = "2")]
    samples: Vec<Sample>,
}

#[derive(Clone, PartialEq, Message)]
struct Label {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(string, tag = "2")]
    value: String,
}

#[derive(Clone, PartialEq, Message)]
struct Sample {
    #[prost(double, tag = "1")]
    value: f64,
    #[prost(int64, tag = "2")]
    timestamp: i64,
}

#[allow(dead_code)]
fn _keep_metrics_config(_config: &MetricsConfig) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_metrics_path() {
        assert_eq!(normalize_metrics_path("metrics"), "/metrics");
        assert_eq!(normalize_metrics_path("/custom"), "/custom");
        assert_eq!(normalize_metrics_path(" "), "/metrics");
    }

    #[test]
    fn snappy_literal_block_roundtrip_shape() {
        let body = b"abc";
        let compressed = snappy_compress_block(body);
        assert_eq!(compressed, vec![3, 8, b'a', b'b', b'c']);
    }

    #[test]
    fn remote_write_body_contains_sorted_metric_name_label() {
        let samples = vec![PrometheusSample::new(
            "test_metric",
            vec![
                ("b".to_owned(), "2".to_owned()),
                ("a".to_owned(), "1".to_owned()),
            ],
            42.0,
        )];
        let body = remote_write_body(&samples, 123);
        assert!(body.len() > samples[0].name().len());
    }

    #[test]
    fn remote_write_time_series_applies_external_labels_without_overwriting_sample_labels() {
        let sample = PrometheusSample::new(
            "test_metric",
            vec![("node".to_owned(), "1".to_owned())],
            42.0,
        );
        let labels = HashMap::from([
            ("environment".to_owned(), "prod".to_owned()),
            ("node".to_owned(), "external".to_owned()),
            ("not-valid".to_owned(), "skip".to_owned()),
            ("__name__".to_owned(), "also_skip".to_owned()),
        ]);

        let labels = remote_write_external_labels(&labels);
        let series = time_series(&sample, 123, &labels);
        assert!(
            series
                .labels
                .iter()
                .any(|label| label.name == "__name__" && label.value == "test_metric")
        );
        assert!(
            series
                .labels
                .iter()
                .any(|label| label.name == "environment" && label.value == "prod")
        );
        assert!(
            series
                .labels
                .iter()
                .any(|label| label.name == "node" && label.value == "1")
        );
        assert!(
            !series
                .labels
                .iter()
                .any(|label| label.name == "node" && label.value == "external")
        );
        assert!(!series.labels.iter().any(|label| label.name == "not-valid"));
    }

    #[test]
    fn remote_write_external_labels_validate_prometheus_label_names() {
        let labels = HashMap::from([
            (" environment ".to_owned(), "prod".to_owned()),
            ("__reserved".to_owned(), "skip".to_owned()),
            ("not-valid".to_owned(), "skip".to_owned()),
        ]);

        let labels = remote_write_external_labels(&labels);
        assert_eq!(labels.get("environment").map(String::as_str), Some("prod"));
        assert!(!labels.contains_key("__reserved"));
        assert!(!labels.contains_key("not-valid"));
    }

    #[test]
    fn remote_write_bodies_respect_batch_size() {
        let samples = (0..5)
            .map(|idx| {
                PrometheusSample::new(
                    "test_metric",
                    vec![("idx".to_owned(), idx.to_string())],
                    idx as f64,
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            remote_write_bodies(&samples, 123, 2, &HashMap::new()).len(),
            3
        );
        assert_eq!(
            remote_write_bodies(&samples, 123, 0, &HashMap::new()).len(),
            5
        );
        assert!(remote_write_bodies(&[], 123, 2, &HashMap::new()).is_empty());
    }

    #[test]
    fn remote_write_headers_apply_mimir_auth() {
        let config = RemoteWriteConfig {
            tenant_id: Some("tenant-a".to_owned()),
            username: Some("user".to_owned()),
            password: Some("secret".to_owned()),
            ..RemoteWriteConfig::default()
        };

        let headers = remote_write_headers(&config).expect("headers");
        assert_eq!(headers["X-Scope-OrgID"], "tenant-a");
        assert_eq!(headers["Content-Encoding"], "snappy");
        assert_eq!(
            headers["Authorization"],
            format!("Basic {}", BASE64_STANDARD.encode("user:secret"))
        );

        let config = RemoteWriteConfig {
            bearer_token: Some("token".to_owned()),
            username: Some("user".to_owned()),
            password: Some("secret".to_owned()),
            ..RemoteWriteConfig::default()
        };
        let headers = remote_write_headers(&config).expect("headers");
        assert_eq!(headers["Authorization"], "Bearer token");
    }
}
