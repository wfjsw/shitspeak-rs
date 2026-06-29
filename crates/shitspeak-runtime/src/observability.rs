use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use bytes::BytesMut;
use prost::Message;
use reqwest::header::{HeaderMap, HeaderValue};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::channel_repository::ChannelRepository;
use crate::client_repository::ClientRepository;
use crate::config::{MetricsConfig, RemoteWriteConfig};
use crate::geoip::NodeGeo;
use crate::http_client;
use crate::s2s::overlay::OverlayNetwork;
use crate::s2s::status::PrometheusSample;
use crate::s2s::transport::ConnectionManager;
use crate::s2s::{S2SManager, status};
use crate::types::DEFAULT_SERVER_ID;

#[async_trait]
pub trait S2sMetricsSource: Send + Sync + 'static {
    async fn prometheus_metrics_text(&self) -> Option<String>;

    async fn prometheus_remote_write_requests(
        &self,
        batch_size: usize,
        external_labels: &HashMap<String, String>,
    ) -> Option<Vec<Vec<u8>>>;
}

#[async_trait]
impl S2sMetricsSource for S2SManager {
    async fn prometheus_metrics_text(&self) -> Option<String> {
        S2SManager::prometheus_metrics_text(self)
    }

    async fn prometheus_remote_write_requests(
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

#[async_trait]
impl S2sMetricsSource for S2sTopologyMetricsSource {
    async fn prometheus_metrics_text(&self) -> Option<String> {
        Some(status::render_prometheus_metrics(
            &self.overlay,
            &self.transport,
            self.local_geo.clone(),
        ))
    }

    async fn prometheus_remote_write_requests(
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

pub struct ServerMetricsSource {
    s2s: Arc<S2SManager>,
    clients: Arc<ClientRepository>,
    channels: Arc<ChannelRepository>,
}

impl ServerMetricsSource {
    pub fn new(
        s2s: Arc<S2SManager>,
        clients: Arc<ClientRepository>,
        channels: Arc<ChannelRepository>,
    ) -> Self {
        Self {
            s2s,
            clients,
            channels,
        }
    }

    async fn consensus_samples(&self) -> Vec<PrometheusSample> {
        let snapshot =
            ConsensusMetricsSnapshot::from_repositories(&self.clients, &self.channels).await;
        consensus_samples_from_snapshot(&snapshot)
    }
}

#[async_trait]
impl S2sMetricsSource for ServerMetricsSource {
    async fn prometheus_metrics_text(&self) -> Option<String> {
        let mut body = self.s2s.prometheus_metrics_text().unwrap_or_default();
        if !body.is_empty() && !body.ends_with('\n') {
            body.push('\n');
        }
        render_consensus_metrics_into(&mut body, &self.consensus_samples().await);
        Some(body)
    }

    async fn prometheus_remote_write_requests(
        &self,
        batch_size: usize,
        external_labels: &HashMap<String, String>,
    ) -> Option<Vec<Vec<u8>>> {
        let mut samples = self.s2s.prometheus_samples().unwrap_or_default();
        samples.extend(self.consensus_samples().await);
        let timestamp_ms = now_unix_ms();
        Some(remote_write_bodies(
            &samples,
            timestamp_ms,
            batch_size,
            external_labels,
        ))
    }
}

struct ConsensusMetricsSnapshot {
    channel_versions: Vec<(String, u64)>,
    client_versions: Vec<(u16, u64)>,
    client_version_vector: String,
    total_clients: usize,
    total_channels: usize,
    channels_by_server: Vec<(String, usize)>,
}

impl ConsensusMetricsSnapshot {
    async fn from_repositories(clients: &ClientRepository, channels: &ChannelRepository) -> Self {
        let (client_snapshot, client_versions) = clients.snapshot_with_versions().await;
        let total_clients = client_snapshot.len();
        drop(client_snapshot);
        let mut client_versions = client_versions.into_iter().collect::<Vec<_>>();
        let local_node_id = clients.local_node_id();
        client_versions.retain(|(node_id, _)| *node_id != local_node_id);
        client_versions.push((local_node_id, clients.current_version()));
        client_versions.sort_by_key(|(node_id, _)| *node_id);

        let mut server_ids = channels.known_server_ids();
        if server_ids.is_empty() {
            server_ids.push(DEFAULT_SERVER_ID.to_owned());
        }
        server_ids.sort();
        server_ids.dedup();

        let mut channel_versions = Vec::with_capacity(server_ids.len());
        let mut channels_by_server = Vec::with_capacity(server_ids.len());
        let mut total_channels = 0usize;
        for server_id in server_ids {
            channel_versions.push((
                server_id.clone(),
                channels.current_version_in_server(&server_id),
            ));
            let channel_count = channels.len_in_server(&server_id).await;
            total_channels += channel_count;
            channels_by_server.push((server_id, channel_count));
        }

        let client_version_vector = serialize_client_version_vector(&client_versions);
        Self {
            channel_versions,
            client_versions,
            client_version_vector,
            total_clients,
            total_channels,
            channels_by_server,
        }
    }
}

fn render_consensus_metrics_into(out: &mut String, samples: &[PrometheusSample]) {
    for (name, help) in CONSENSUS_METRIC_HEADERS {
        render_prometheus_header(out, name, help, "gauge");
    }
    for sample in samples {
        render_prometheus_sample(out, sample);
    }
}

fn consensus_samples_from_snapshot(snapshot: &ConsensusMetricsSnapshot) -> Vec<PrometheusSample> {
    let mut samples = Vec::new();
    samples.push(PrometheusSample::new(
        "shitspeak_consensus_client_repository_version_vector",
        vec![("vector".to_owned(), snapshot.client_version_vector.clone())],
        1.0,
    ));
    for (node_id, version) in &snapshot.client_versions {
        samples.push(PrometheusSample::new(
            "shitspeak_consensus_client_repository_node_version",
            vec![("node".to_owned(), node_id.to_string())],
            *version as f64,
        ));
    }
    for (server_id, version) in &snapshot.channel_versions {
        samples.push(PrometheusSample::new(
            "shitspeak_consensus_channel_repository_version",
            vec![("server_id".to_owned(), server_id.clone())],
            *version as f64,
        ));
    }
    samples.push(PrometheusSample::new(
        "shitspeak_consensus_clients_total",
        Vec::new(),
        snapshot.total_clients as f64,
    ));
    samples.push(PrometheusSample::new(
        "shitspeak_consensus_channels_total",
        Vec::new(),
        snapshot.total_channels as f64,
    ));
    for (server_id, count) in &snapshot.channels_by_server {
        samples.push(PrometheusSample::new(
            "shitspeak_consensus_channels_by_server",
            vec![("server_id".to_owned(), server_id.clone())],
            *count as f64,
        ));
    }
    samples
}

fn serialize_client_version_vector(versions: &[(u16, u64)]) -> String {
    if versions.is_empty() {
        return "empty".to_owned();
    }
    versions
        .iter()
        .map(|(node_id, version)| format!("{node_id}:{version}"))
        .collect::<Vec<_>>()
        .join(",")
}

const CONSENSUS_METRIC_HEADERS: &[(&str, &str)] = &[
    (
        "shitspeak_consensus_channel_repository_version",
        "Current channel repository version by server scope.",
    ),
    (
        "shitspeak_consensus_client_repository_version_vector",
        "Current client repository version vector serialized as sorted node:version pairs.",
    ),
    (
        "shitspeak_consensus_client_repository_node_version",
        "Current client repository version for each known node.",
    ),
    (
        "shitspeak_consensus_clients_total",
        "Total materialized clients in the client repository.",
    ),
    (
        "shitspeak_consensus_channels_total",
        "Total materialized channels in the channel repository.",
    ),
    (
        "shitspeak_consensus_channels_by_server",
        "Materialized channels in the channel repository by server scope.",
    ),
];

fn render_prometheus_header(out: &mut String, name: &str, help: &str, kind: &str) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push(' ');
    out.push_str(kind);
    out.push('\n');
}

fn render_prometheus_sample(out: &mut String, sample: &PrometheusSample) {
    out.push_str(sample.name());
    if !sample.labels().is_empty() {
        out.push('{');
        for (index, (key, value)) in sample.labels().iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str(key);
            out.push_str("=\"");
            escape_prometheus_label_value(out, value);
            out.push('"');
        }
        out.push('}');
    }
    out.push(' ');
    out.push_str(&format_prometheus_value(sample.value()));
    out.push('\n');
}

fn format_prometheus_value(value: f64) -> String {
    if value.is_nan() {
        "NaN".to_owned()
    } else if value == f64::INFINITY {
        "+Inf".to_owned()
    } else if value == f64::NEG_INFINITY {
        "-Inf".to_owned()
    } else {
        value.to_string()
    }
}

fn escape_prometheus_label_value(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
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

            if let Some(bodies) = source
                .prometheus_remote_write_requests(config.batch_size.max(1), &external_labels)
                .await
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
        ("GET", p) if p == path => match source.prometheus_metrics_text().await {
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

    #[test]
    fn client_version_vector_serialization_is_stable() {
        assert_eq!(serialize_client_version_vector(&[]), "empty");
        assert_eq!(
            serialize_client_version_vector(&[(1, 7), (2, 11), (9, 0)]),
            "1:7,2:11,9:0"
        );
    }

    #[test]
    fn consensus_metrics_render_counts_versions_and_vector() {
        let snapshot = ConsensusMetricsSnapshot {
            channel_versions: vec![("alpha".to_owned(), 12), ("default".to_owned(), 7)],
            client_versions: vec![(1, 3), (2, 5)],
            client_version_vector: "1:3,2:5".to_owned(),
            total_clients: 4,
            total_channels: 9,
            channels_by_server: vec![("alpha".to_owned(), 2), ("default".to_owned(), 7)],
        };
        let samples = consensus_samples_from_snapshot(&snapshot);
        let mut rendered = String::new();
        render_consensus_metrics_into(&mut rendered, &samples);

        assert!(rendered.contains("# TYPE shitspeak_consensus_channel_repository_version gauge\n"));
        assert!(
            rendered
                .contains("shitspeak_consensus_channel_repository_version{server_id=\"alpha\"} 12")
        );
        assert!(rendered.contains(
            "shitspeak_consensus_client_repository_version_vector{vector=\"1:3,2:5\"} 1"
        ));
        assert!(
            rendered.contains("shitspeak_consensus_client_repository_node_version{node=\"2\"} 5")
        );
        assert!(rendered.contains("shitspeak_consensus_clients_total 4"));
        assert!(rendered.contains("shitspeak_consensus_channels_total 9"));
        assert!(
            rendered.contains("shitspeak_consensus_channels_by_server{server_id=\"default\"} 7")
        );
    }
}
