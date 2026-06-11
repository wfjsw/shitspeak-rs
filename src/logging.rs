use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::fmt;
use std::io;
use std::panic;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock, mpsc as std_mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use config::{Config as ConfigCrate, Environment, File};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber, span};
use tracing_subscriber::Layer;
use tracing_subscriber::field::RecordFields;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::fmt::format::{DefaultFields, FormatEvent, FormatFields, Writer};
use tracing_subscriber::fmt::writer::MakeWriter;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;

use crate::http_client;

const DEFAULT_LOKI_BATCH_SIZE: usize = 128;
const DEFAULT_LOKI_FLUSH_INTERVAL_MS: u64 = 1_000;
const DEFAULT_LOKI_LEVEL: &str = "debug";
const DEFAULT_LOKI_QUEUE_CAPACITY: usize = 4_096;
const DEFAULT_LOKI_REQUEST_TIMEOUT_MS: u64 = 5_000;
const LOKI_PUSH_PATH: &str = "/loki/api/v1/push";

static LOKI_FLUSH_HANDLE: OnceLock<Mutex<Option<LokiFlushHandle>>> = OnceLock::new();
static PANIC_HOOK_INSTALLED: OnceLock<()> = OnceLock::new();

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
    #[serde(default = "default_loki_level")]
    level: String,
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
            level: default_loki_level(),
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

    fn level_filter(&self) -> Result<LevelFilter, Box<dyn Error>> {
        let level = self.level.trim();
        let level = if level.is_empty() {
            DEFAULT_LOKI_LEVEL
        } else {
            level
        };
        LevelFilter::from_str(&level.to_ascii_lowercase())
            .map_err(|error| format!("invalid logging.loki.level {level:?}: {error}").into())
    }
}

pub struct LoggingGuard {
    flush_handle: Option<LokiFlushHandle>,
}

impl LoggingGuard {
    pub fn flush(&self) {
        if let Some(handle) = &self.flush_handle {
            handle.flush_blocking();
        }
    }
}

impl Drop for LoggingGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.flush_handle.take() {
            handle.shutdown_blocking();
            clear_global_loki_flush_handle();
        }
    }
}

pub fn init(service_name: &'static str) -> Result<LoggingGuard, Box<dyn Error>> {
    let cli_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_line_number(true);
    let config = load_logging_config()?;

    if config.loki.enabled() {
        let loki_filter = config.loki.level_filter()?;
        let (loki_formatter, flush_handle) = LokiEventFormatter::spawn(config.loki, service_name)?;
        let loki_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(NoopMakeWriter)
            .fmt_fields(LokiFields::default())
            .event_format(loki_formatter);
        tracing_subscriber::registry()
            .with(fmt_layer.with_filter(cli_filter))
            .with(LokiMetadataLayer::default().with_filter(loki_filter))
            .with(loki_layer.with_filter(loki_filter))
            .init();
        set_global_loki_flush_handle(flush_handle.clone());
        install_panic_hook();
        Ok(LoggingGuard {
            flush_handle: Some(flush_handle),
        })
    } else {
        tracing_subscriber::registry()
            .with(fmt_layer.with_filter(cli_filter))
            .init();
        Ok(LoggingGuard { flush_handle: None })
    }
}

pub fn flush() {
    if let Some(handle) = global_loki_flush_handle() {
        handle.flush_blocking();
    }
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

fn default_loki_level() -> String {
    DEFAULT_LOKI_LEVEL.to_string()
}

fn default_loki_queue_capacity() -> usize {
    DEFAULT_LOKI_QUEUE_CAPACITY
}

fn default_loki_request_timeout_ms() -> u64 {
    DEFAULT_LOKI_REQUEST_TIMEOUT_MS
}

#[derive(Clone)]
struct LokiFlushHandle {
    command_tx: mpsc::UnboundedSender<LokiCommand>,
    timeout: Duration,
}

impl LokiFlushHandle {
    fn flush_blocking(&self) {
        self.send_and_wait(LokiCommand::flush);
    }

    fn shutdown_blocking(&self) {
        self.send_and_wait(LokiCommand::shutdown);
    }

    fn send_and_wait(&self, command: impl FnOnce(std_mpsc::Sender<()>) -> LokiCommand) {
        let (ack_tx, ack_rx) = std_mpsc::channel();
        if self.command_tx.send(command(ack_tx)).is_ok() {
            let _ = ack_rx.recv_timeout(self.timeout);
        }
    }
}

enum LokiCommand {
    Flush(std_mpsc::Sender<()>),
    Shutdown(std_mpsc::Sender<()>),
}

impl LokiCommand {
    fn flush(ack: std_mpsc::Sender<()>) -> Self {
        Self::Flush(ack)
    }

    fn shutdown(ack: std_mpsc::Sender<()>) -> Self {
        Self::Shutdown(ack)
    }
}

struct LokiEventFormatter {
    tx: mpsc::Sender<LokiEntry>,
    line_formatter: tracing_subscriber::fmt::format::Format,
}

impl LokiEventFormatter {
    fn spawn(
        config: LokiConfig,
        service_name: &'static str,
    ) -> Result<(Self, LokiFlushHandle), Box<dyn Error>> {
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
        let (command_tx, command_rx) = mpsc::unbounded_channel();

        tokio::spawn(run_loki_sender(
            rx,
            command_rx,
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

        Ok((
            Self {
                tx,
                line_formatter: tracing_subscriber::fmt::format().with_line_number(true),
            },
            LokiFlushHandle {
                command_tx,
                timeout: request_timeout.saturating_add(Duration::from_secs(1)),
            },
        ))
    }
}

impl<S, N> FormatEvent<S, N> for LokiEventFormatter
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        _writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut line = String::new();
        self.line_formatter
            .format_event(ctx, Writer::new(&mut line), event)?;
        trim_trailing_newline(&mut line);

        let _ = self.tx.try_send(loki_entry_from_event(ctx, event, line));
        Ok(())
    }
}

#[derive(Default)]
struct LokiMetadataLayer;

impl<S> Layer<S> for LokiMetadataLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else {
            return;
        };
        let mut visitor = EventVisitor::for_span();
        attrs.record(&mut visitor);
        span.extensions_mut().insert(SpanFields {
            fields: visitor.fields,
        });
    }

    fn on_record(&self, id: &span::Id, values: &span::Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else {
            return;
        };
        let mut visitor = EventVisitor::for_span();
        values.record(&mut visitor);
        let mut extensions = span.extensions_mut();
        let span_fields = extensions.get_mut::<SpanFields>();
        match span_fields {
            Some(span_fields) => {
                span_fields.fields.extend(visitor.fields);
            }
            None => {
                extensions.insert(SpanFields {
                    fields: visitor.fields,
                });
            }
        }
    }
}

#[derive(Default)]
struct LokiFields {
    inner: DefaultFields,
}

impl<'writer> FormatFields<'writer> for LokiFields {
    fn format_fields<R: RecordFields>(&self, writer: Writer<'writer>, fields: R) -> fmt::Result {
        self.inner.format_fields(writer, fields)
    }
}

fn loki_entry_from_event<S, N>(
    ctx: &FmtContext<'_, S, N>,
    event: &Event<'_>,
    line: String,
) -> LokiEntry
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    let metadata = event.metadata();
    let mut visitor = EventVisitor::for_event();
    event.record(&mut visitor);

    let mut fields = serde_json::Map::new();
    if let Some(scope) = ctx.event_scope() {
        let mut spans = Vec::new();
        for span in scope.from_root() {
            spans.push(serde_json::Value::String(span.name().to_string()));
            let extensions = span.extensions();
            if let Some(span_fields) = extensions.get::<SpanFields>() {
                fields.extend(span_fields.fields.clone());
            }
        }
        if !spans.is_empty() {
            fields.insert("spans".to_string(), serde_json::Value::Array(spans));
        }
    }
    fields.extend(visitor.fields);

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

    LokiEntry {
        timestamp_ns: unix_timestamp_ns(),
        level: metadata.level().to_string(),
        line,
        metadata: structured_metadata(fields),
    }
}

struct SpanFields {
    fields: serde_json::Map<String, serde_json::Value>,
}

struct EventVisitor {
    fields: serde_json::Map<String, serde_json::Value>,
    capture_message: bool,
}

impl EventVisitor {
    fn for_event() -> Self {
        Self {
            fields: serde_json::Map::new(),
            capture_message: true,
        }
    }

    fn for_span() -> Self {
        Self {
            fields: serde_json::Map::new(),
            capture_message: false,
        }
    }

    fn insert(&mut self, field: &Field, value: serde_json::Value) {
        if self.capture_message && field.name() == "message" {
            drop(value);
            return;
        }
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

    fn record_error(&mut self, field: &Field, value: &(dyn Error + 'static)) {
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
    metadata: BTreeMap<String, String>,
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

async fn run_loki_sender(
    mut rx: mpsc::Receiver<LokiEntry>,
    mut command_rx: mpsc::UnboundedReceiver<LokiCommand>,
    sender: LokiSender,
) {
    let mut pending = Vec::with_capacity(sender.batch_size);
    let mut interval = tokio::time::interval(sender.flush_interval);
    let mut command_rx_closed = false;
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
            command = command_rx.recv(), if !command_rx_closed => {
                match command {
                    Some(LokiCommand::Flush(ack)) => {
                        drain_loki_entries(&mut rx, &sender, &mut pending).await;
                        flush_loki_batch(&sender, &mut pending).await;
                        let _ = ack.send(());
                    }
                    Some(LokiCommand::Shutdown(ack)) => {
                        drain_loki_entries(&mut rx, &sender, &mut pending).await;
                        flush_loki_batch(&sender, &mut pending).await;
                        let _ = ack.send(());
                        break;
                    }
                    None => {
                        command_rx_closed = true;
                    }
                }
            }
            _ = interval.tick() => {
                flush_loki_batch(&sender, &mut pending).await;
            }
        }
    }
}

async fn drain_loki_entries(
    rx: &mut mpsc::Receiver<LokiEntry>,
    sender: &LokiSender,
    pending: &mut Vec<LokiEntry>,
) {
    while let Ok(entry) = rx.try_recv() {
        pending.push(entry);
        if pending.len() >= sender.batch_size {
            flush_loki_batch(sender, pending).await;
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
    let mut streams = BTreeMap::<BTreeMap<String, String>, Vec<LokiValue>>::new();

    for entry in entries {
        let mut labels = base_labels.clone();
        labels.insert("level".to_string(), entry.level.to_ascii_lowercase());
        streams.entry(labels).or_default().push(LokiValue(
            entry.timestamp_ns,
            entry.line,
            entry.metadata,
        ));
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

fn structured_metadata(
    fields: serde_json::Map<String, serde_json::Value>,
) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    for (key, value) in fields {
        insert_structured_metadata(
            &mut metadata,
            sanitize_loki_metadata_key(&key),
            metadata_value_to_string(value),
        );
    }
    metadata
}

fn insert_structured_metadata(metadata: &mut BTreeMap<String, String>, key: String, value: String) {
    if !metadata.contains_key(&key) {
        metadata.insert(key, value);
        return;
    }

    for index in 2.. {
        let candidate = format!("{key}_{index}");
        if !metadata.contains_key(&candidate) {
            metadata.insert(candidate, value);
            return;
        }
    }
}

fn sanitize_loki_metadata_key(value: &str) -> String {
    let mut key = String::with_capacity(value.len().max(1));
    for (index, ch) in value.chars().enumerate() {
        if index == 0 {
            if ch == '_' || ch.is_ascii_alphabetic() {
                key.push(ch);
            } else {
                key.push('_');
                if ch.is_ascii_digit() {
                    key.push(ch);
                }
            }
            continue;
        }

        if ch == '_' || ch.is_ascii_alphanumeric() {
            key.push(ch);
        } else {
            key.push('_');
        }
    }

    if key.is_empty() { "_".to_string() } else { key }
}

fn metadata_value_to_string(value: serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value,
        serde_json::Value::Null => "null".to_string(),
        value => value.to_string(),
    }
}

fn trim_trailing_newline(line: &mut String) {
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
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
    values: Vec<LokiValue>,
}

#[derive(Serialize)]
struct LokiValue(String, String, BTreeMap<String, String>);

#[derive(Clone, Copy)]
struct NoopMakeWriter;

struct NoopWriter;

impl<'writer> MakeWriter<'writer> for NoopMakeWriter {
    type Writer = NoopWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        NoopWriter
    }
}

impl io::Write for NoopWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn set_global_loki_flush_handle(handle: LokiFlushHandle) {
    let lock = LOKI_FLUSH_HANDLE.get_or_init(|| Mutex::new(None));
    let mut guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = Some(handle);
}

fn clear_global_loki_flush_handle() {
    if let Some(lock) = LOKI_FLUSH_HANDLE.get() {
        let mut guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = None;
    }
}

fn global_loki_flush_handle() -> Option<LokiFlushHandle> {
    let lock = LOKI_FLUSH_HANDLE.get()?;
    let guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.clone()
}

fn install_panic_hook() {
    PANIC_HOOK_INSTALLED.get_or_init(|| {
        let previous_hook = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            let message = panic_message(info);
            if let Some(location) = info.location() {
                tracing::error!(
                    panic = true,
                    panic_message = %message,
                    panic_file = location.file(),
                    panic_line = location.line(),
                    panic_column = location.column(),
                    "process panicked"
                );
            } else {
                tracing::error!(
                    panic = true,
                    panic_message = %message,
                    "process panicked"
                );
            }
            flush();
            previous_hook(info);
        }));
    });
}

fn panic_message(info: &panic::PanicHookInfo<'_>) -> String {
    if let Some(message) = info.payload().downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = info.payload().downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_string()
    }
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
        let mut metadata = BTreeMap::new();
        metadata.insert("target".to_string(), "test_target".to_string());
        let payload = build_push_request(
            &labels,
            vec![
                LokiEntry {
                    timestamp_ns: "1".to_string(),
                    level: "INFO".to_string(),
                    line: "{}".to_string(),
                    metadata: metadata.clone(),
                },
                LokiEntry {
                    timestamp_ns: "2".to_string(),
                    level: "ERROR".to_string(),
                    line: "{}".to_string(),
                    metadata,
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
    fn loki_payload_serializes_structured_metadata_as_third_value() {
        let mut labels = BTreeMap::new();
        labels.insert("service".to_string(), "test".to_string());
        let mut metadata = BTreeMap::new();
        metadata.insert("client_ip".to_string(), "192.0.2.1".to_string());
        metadata.insert("client_port".to_string(), "64738".to_string());
        metadata.insert("session".to_string(), "42".to_string());
        let payload = build_push_request(
            &labels,
            vec![LokiEntry {
                timestamp_ns: "1".to_string(),
                level: "DEBUG".to_string(),
                line: "2026-06-08T00:00:00Z DEBUG test: hello".to_string(),
                metadata,
            }],
        );

        let payload = serde_json::to_value(payload).expect("payload serializes");
        let value = &payload["streams"][0]["values"][0];

        assert_eq!(value.as_array().map(Vec::len), Some(3));
        assert_eq!(value[0], "1");
        assert_eq!(value[1], "2026-06-08T00:00:00Z DEBUG test: hello");
        assert_eq!(value[2]["client_ip"], "192.0.2.1");
        assert_eq!(value[2]["client_port"], "64738");
        assert_eq!(value[2]["session"], "42");
    }

    #[test]
    fn loki_config_default_level_is_debug() {
        let cfg = LokiConfig::default();

        assert_eq!(cfg.level, "debug");
        assert_eq!(cfg.level_filter().unwrap(), LevelFilter::DEBUG);
    }

    #[test]
    fn loki_structured_metadata_sanitizes_keys_and_stringifies_values() {
        let mut fields = serde_json::Map::new();
        fields.insert(
            "error.sources".to_string(),
            serde_json::Value::String("source".to_string()),
        );
        fields.insert("123bad".to_string(), serde_json::Value::from(5));
        fields.insert(
            "client-ip".to_string(),
            serde_json::Value::String("ip".to_string()),
        );
        fields.insert(
            "client_ip".to_string(),
            serde_json::Value::String("ip2".to_string()),
        );

        let metadata = structured_metadata(fields);

        assert_eq!(
            metadata.get("error_sources").map(String::as_str),
            Some("source")
        );
        assert_eq!(metadata.get("_123bad").map(String::as_str), Some("5"));
        assert_eq!(metadata.get("client_ip").map(String::as_str), Some("ip"));
        assert_eq!(metadata.get("client_ip_2").map(String::as_str), Some("ip2"));
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
