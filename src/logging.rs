use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use config::{Config as ConfigCrate, Environment, File};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;

use crate::http_client;

const DEFAULT_LOKI_BATCH_SIZE: usize = 128;
const DEFAULT_LOKI_FLUSH_INTERVAL_MS: u64 = 1_000;
const DEFAULT_LOKI_QUEUE_CAPACITY: usize = 4_096;
const DEFAULT_LOKI_REQUEST_TIMEOUT_MS: u64 = 5_000;
const LOKI_PUSH_PATH: &str = "/loki/api/v1/push";

#[derive(Debug, Deserialize, Default)]
struct LoggingRootConfig {
    #[serde(default)]
    logging: LoggingConfig,
}

#[derive(Debug, Deserialize, Default)]
struct LoggingConfig {
    #[serde(default)]
    loki: LokiConfig,
}

#[derive(Debug, Clone, Deserialize)]
struct LokiConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    bearer_token: Option<String>,
    #[serde(default)]
    labels: HashMap<String, String>,
    #[serde(default = "default_loki_batch_size")]
    batch_size: usize,
    #[serde(default = "default_loki_flush_interval_ms")]
    flush_interval_ms: u64,
    #[serde(default = "default_loki_queue_capacity")]
    queue_capacity: usize,
    #[serde(default = "default_loki_request_timeout_ms")]
    request_timeout_ms: u64,
}

impl Default for LokiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: None,
            tenant_id: None,
            username: None,
            password: None,
            bearer_token: None,
            labels: HashMap::new(),
            batch_size: DEFAULT_LOKI_BATCH_SIZE,
            flush_interval_ms: DEFAULT_LOKI_FLUSH_INTERVAL_MS,
            queue_capacity: DEFAULT_LOKI_QUEUE_CAPACITY,
            request_timeout_ms: DEFAULT_LOKI_REQUEST_TIMEOUT_MS,
        }
    }
}

impl LokiConfig {
    fn push_url(&self) -> Option<String> {
        let url = self.url.as_deref()?.trim().trim_end_matches('/');
        if url.is_empty() {
            return None;
        }
        if url.ends_with(LOKI_PUSH_PATH) || url.ends_with("/api/prom/push") {
            Some(url.to_string())
        } else {
            Some(format!("{url}{LOKI_PUSH_PATH}"))
        }
    }

    fn enabled(&self) -> bool {
        self.enabled
    }

    fn batch_size(&self) -> usize {
        self.batch_size.max(1)
    }

    fn queue_capacity(&self) -> usize {
        self.queue_capacity.max(1)
    }

    fn flush_interval(&self) -> Duration {
        Duration::from_millis(self.flush_interval_ms.max(1))
    }

    fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms.max(1))
    }
}

pub fn init(service_name: &'static str) -> Result<(), Box<dyn Error>> {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_line_number(true);
    let config = load_logging_config()?;

    if config.loki.enabled() {
        let layer = LokiLayer::spawn(config.loki, service_name)?;
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .with(layer)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .init();
    }

    Ok(())
}

fn load_logging_config() -> Result<LoggingConfig, config::ConfigError> {
    ConfigCrate::builder()
        .add_source(File::with_name("config").required(false))
        .add_source(Environment::with_prefix("SHITSPEAK").separator("_"))
        .build()?
        .try_deserialize::<LoggingRootConfig>()
        .map(|root| root.logging)
}

fn default_loki_batch_size() -> usize {
    DEFAULT_LOKI_BATCH_SIZE
}

fn default_loki_flush_interval_ms() -> u64 {
    DEFAULT_LOKI_FLUSH_INTERVAL_MS
}

fn default_loki_queue_capacity() -> usize {
    DEFAULT_LOKI_QUEUE_CAPACITY
}

fn default_loki_request_timeout_ms() -> u64 {
    DEFAULT_LOKI_REQUEST_TIMEOUT_MS
}

struct LokiLayer {
    tx: mpsc::Sender<LokiEntry>,
}

impl LokiLayer {
    fn spawn(config: LokiConfig, service_name: &'static str) -> Result<Self, Box<dyn Error>> {
        let push_url = config
            .push_url()
            .ok_or("logging.loki.enabled=true requires logging.loki.url")?;
        let queue_capacity = config.queue_capacity();
        let batch_size = config.batch_size();
        let flush_interval = config.flush_interval();
        let request_timeout = config.request_timeout();
        let labels = base_labels(service_name, &config.labels);
        let client = http_client::build_with_webpki_fallback(request_timeout, "loki logging")?;
        let (tx, rx) = mpsc::channel(queue_capacity);

        tokio::spawn(run_loki_sender(
            rx,
            LokiSender {
                client,
                push_url,
                tenant_id: config.tenant_id,
                username: config.username,
                password: config.password,
                bearer_token: config.bearer_token,
                labels,
                batch_size,
                flush_interval,
            },
        ));

        Ok(Self { tx })
    }
}

impl<S> Layer<S> for LokiLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);

        let mut fields = visitor.fields;
        fields.insert(
            "level".to_string(),
            serde_json::Value::String(metadata.level().to_string()),
        );
        fields.insert(
            "target".to_string(),
            serde_json::Value::String(metadata.target().to_string()),
        );
        fields.insert(
            "name".to_string(),
            serde_json::Value::String(metadata.name().to_string()),
        );
        if let Some(file) = metadata.file() {
            fields.insert(
                "file".to_string(),
                serde_json::Value::String(file.to_string()),
            );
        }
        if let Some(line) = metadata.line() {
            fields.insert("line".to_string(), serde_json::Value::from(line));
        }
        if let Some(scope) = ctx.event_scope(event) {
            let spans = scope
                .from_root()
                .map(|span| serde_json::Value::String(span.name().to_string()))
                .collect::<Vec<_>>();
            if !spans.is_empty() {
                fields.insert("spans".to_string(), serde_json::Value::Array(spans));
            }
        }

        let line = serde_json::Value::Object(fields).to_string();
        let _ = self.tx.try_send(LokiEntry {
            timestamp_ns: unix_timestamp_ns(),
            level: metadata.level().to_string(),
            line,
        });
    }
}

#[derive(Default)]
struct EventVisitor {
    fields: serde_json::Map<String, serde_json::Value>,
}

impl EventVisitor {
    fn insert(&mut self, field: &Field, value: serde_json::Value) {
        self.fields.insert(field.name().to_string(), value);
    }
}

impl Visit for EventVisitor {
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert(field, serde_json::Value::Bool(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert(field, serde_json::Value::from(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert(field, serde_json::Value::from(value));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.insert(field, serde_json::Value::from(value));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.insert(field, serde_json::Value::String(value.to_string()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.insert(field, serde_json::Value::String(format!("{value:?}")));
    }
}

struct LokiEntry {
    timestamp_ns: String,
    level: String,
    line: String,
}

struct LokiSender {
    client: reqwest::Client,
    push_url: String,
    tenant_id: Option<String>,
    username: Option<String>,
    password: Option<String>,
    bearer_token: Option<String>,
    labels: BTreeMap<String, String>,
    batch_size: usize,
    flush_interval: Duration,
}

async fn run_loki_sender(mut rx: mpsc::Receiver<LokiEntry>, sender: LokiSender) {
    let mut pending = Vec::with_capacity(sender.batch_size);
    let mut interval = tokio::time::interval(sender.flush_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            entry = rx.recv() => {
                match entry {
                    Some(entry) => {
                        pending.push(entry);
                        if pending.len() >= sender.batch_size {
                            flush_loki_batch(&sender, &mut pending).await;
                        }
                    }
                    None => {
                        flush_loki_batch(&sender, &mut pending).await;
                        break;
                    }
                }
            }
            _ = interval.tick() => {
                flush_loki_batch(&sender, &mut pending).await;
            }
        }
    }
}

async fn flush_loki_batch(sender: &LokiSender, pending: &mut Vec<LokiEntry>) {
    if pending.is_empty() {
        return;
    }

    let payload = build_push_request(&sender.labels, pending.drain(..));
    let body = match serde_json::to_vec(&payload) {
        Ok(body) => body,
        Err(error) => {
            eprintln!("loki logging: failed to encode log batch: {error}");
            return;
        }
    };

    let mut request = sender
        .client
        .post(&sender.push_url)
        .header("Content-Type", "application/json")
        .body(body);

    if let Some(tenant_id) = sender
        .tenant_id
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        request = request.header("X-Scope-OrgID", tenant_id);
    }
    if let Some(token) = sender
        .bearer_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        request = request.bearer_auth(token);
    } else if let (Some(username), Some(password)) = (
        sender.username.as_deref().filter(|value| !value.is_empty()),
        sender.password.as_deref(),
    ) {
        request = request.basic_auth(username, Some(password));
    }

    match request.send().await {
        Ok(response) if response.status().is_success() => {}
        Ok(response) => {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            eprintln!("loki logging: push failed with HTTP {status}: {text}");
        }
        Err(error) => {
            eprintln!("loki logging: push failed: {error}");
        }
    }
}

fn build_push_request(
    base_labels: &BTreeMap<String, String>,
    entries: impl IntoIterator<Item = LokiEntry>,
) -> LokiPushRequest {
    let mut streams = BTreeMap::<BTreeMap<String, String>, Vec<[String; 2]>>::new();

    for entry in entries {
        let mut labels = base_labels.clone();
        labels.insert("level".to_string(), entry.level.to_ascii_lowercase());
        streams
            .entry(labels)
            .or_default()
            .push([entry.timestamp_ns, entry.line]);
    }

    LokiPushRequest {
        streams: streams
            .into_iter()
            .map(|(stream, values)| LokiStream { stream, values })
            .collect(),
    }
}

fn base_labels(
    service_name: &str,
    configured: &HashMap<String, String>,
) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert("service".to_string(), service_name.to_string());

    if let Some(hostname) = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        labels.insert("instance".to_string(), hostname);
    }

    for (key, value) in configured {
        let key = key.trim();
        if is_loki_label_name(key) {
            labels.insert(key.to_string(), value.clone());
        } else {
            eprintln!("loki logging: ignoring invalid Loki label name {key:?}");
        }
    }

    labels
}

fn is_loki_label_name(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn unix_timestamp_ns() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (duration.as_secs() as u128 * 1_000_000_000 + duration.subsec_nanos() as u128).to_string()
}

#[derive(Serialize)]
struct LokiPushRequest {
    streams: Vec<LokiStream>,
}

#[derive(Serialize)]
struct LokiStream {
    stream: BTreeMap<String, String>,
    values: Vec<[String; 2]>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loki_push_url_accepts_base_or_push_endpoint() {
        let mut cfg = LokiConfig::default();
        cfg.url = Some("http://localhost:3100".to_string());
        assert_eq!(
            cfg.push_url().as_deref(),
            Some("http://localhost:3100/loki/api/v1/push")
        );

        cfg.url = Some("http://localhost:3100/loki/api/v1/push".to_string());
        assert_eq!(
            cfg.push_url().as_deref(),
            Some("http://localhost:3100/loki/api/v1/push")
        );
    }

    #[test]
    fn loki_payload_groups_entries_by_level_label() {
        let mut labels = BTreeMap::new();
        labels.insert("service".to_string(), "test".to_string());
        let payload = build_push_request(
            &labels,
            vec![
                LokiEntry {
                    timestamp_ns: "1".to_string(),
                    level: "INFO".to_string(),
                    line: "{}".to_string(),
                },
                LokiEntry {
                    timestamp_ns: "2".to_string(),
                    level: "ERROR".to_string(),
                    line: "{}".to_string(),
                },
            ],
        );

        assert_eq!(payload.streams.len(), 2);
        assert!(payload.streams.iter().any(|stream| {
            stream
                .stream
                .get("level")
                .is_some_and(|value| value == "info")
        }));
        assert!(payload.streams.iter().any(|stream| {
            stream
                .stream
                .get("level")
                .is_some_and(|value| value == "error")
        }));
    }

    #[test]
    fn invalid_label_names_are_ignored() {
        let mut configured = HashMap::new();
        configured.insert("valid_label".to_string(), "yes".to_string());
        configured.insert("not-valid".to_string(), "no".to_string());

        let labels = base_labels("svc", &configured);

        assert_eq!(labels.get("valid_label").map(String::as_str), Some("yes"));
        assert!(!labels.contains_key("not-valid"));
    }
}
