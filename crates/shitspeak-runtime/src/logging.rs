use std::collections::{BTreeMap, HashMap, VecDeque};
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
use tracing_subscriber::field::{MakeVisitor, RecordFields, VisitOutput};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::fmt::format::{
    DefaultFields, DefaultVisitor, FormatEvent, FormatFields, Writer,
};
use tracing_subscriber::fmt::writer::MakeWriter;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;

use crate::http_client;
use crate::types::NodeIdentifier;
use shitspeak_runtime_config::S2sConfig;

mod span_format;

use span_format::ScopedSpanEventFormatter;

const DEFAULT_LOKI_BATCH_SIZE: usize = 128;
const DEFAULT_LOKI_FILTER_TARGET: &str = "shitspeak_rs";
const DEFAULT_LOKI_FLUSH_INTERVAL_MS: u64 = 1_000;
const DEFAULT_LOKI_LEVEL: &str = "debug";
const DEFAULT_LOKI_QUEUE_CAPACITY: usize = 4_096;
const DEFAULT_LOKI_REQUEST_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_LOKI_RETRY_INITIAL_INTERVAL_MS: u64 = 1_000;
const DEFAULT_LOKI_RETRY_MAX_INTERVAL_MS: u64 = 30_000;
const LOKI_PUSH_PATH: &str = "/loki/api/v1/push";
const TARGET_LOKI_PUSH_BODY_BYTES: usize = 50_000_000;
const MAX_LOKI_PUSH_BODY_BYTES: usize = 100_000_000;
const MAX_LOKI_RESPONSE_BODY_LOG_CHARS: usize = 4_096;

static LOKI_FLUSH_HANDLE: OnceLock<Mutex<Option<LokiFlushHandle>>> = OnceLock::new();
static PANIC_HOOK_INSTALLED: OnceLock<()> = OnceLock::new();

#[derive(Debug, Deserialize, Default)]
struct LoggingRootConfig {
    #[serde(default)]
    logging: LoggingConfig,
    #[serde(default)]
    s2s: S2sConfig,
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
    #[serde(default)]
    filter: Option<String>,
    #[serde(default = "default_loki_level")]
    level: String,
    #[serde(default = "default_loki_queue_capacity")]
    queue_capacity: usize,
    #[serde(default = "default_loki_request_timeout_ms")]
    request_timeout_ms: u64,
    #[serde(default)]
    retry_cache_capacity: Option<usize>,
    #[serde(default = "default_loki_retry_initial_interval_ms")]
    retry_initial_interval_ms: u64,
    #[serde(default = "default_loki_retry_max_interval_ms")]
    retry_max_interval_ms: u64,
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
            filter: None,
            level: default_loki_level(),
            queue_capacity: DEFAULT_LOKI_QUEUE_CAPACITY,
            request_timeout_ms: DEFAULT_LOKI_REQUEST_TIMEOUT_MS,
            retry_cache_capacity: None,
            retry_initial_interval_ms: DEFAULT_LOKI_RETRY_INITIAL_INTERVAL_MS,
            retry_max_interval_ms: DEFAULT_LOKI_RETRY_MAX_INTERVAL_MS,
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

    fn retry_cache_capacity(&self) -> usize {
        self.retry_cache_capacity
            .unwrap_or_else(|| self.queue_capacity())
            .max(1)
    }

    fn retry_initial_interval(&self) -> Duration {
        Duration::from_millis(self.retry_initial_interval_ms.max(1))
    }

    fn retry_max_interval(&self) -> Duration {
        let initial = self.retry_initial_interval();
        Duration::from_millis(self.retry_max_interval_ms.max(1)).max(initial)
    }

    fn normalized_level(&self) -> Result<String, Box<dyn Error>> {
        let level = self.level.trim();
        let level = if level.is_empty() {
            DEFAULT_LOKI_LEVEL
        } else {
            level
        };
        let level = level.to_ascii_lowercase();
        LevelFilter::from_str(&level)
            .map_err(|error| format!("invalid logging.loki.level {level:?}: {error}"))?;
        Ok(level)
    }

    fn filter_directive(&self) -> Result<String, Box<dyn Error>> {
        if let Some(filter) = self
            .filter
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return Ok(filter.to_string());
        }

        Ok(format!(
            "{DEFAULT_LOKI_FILTER_TARGET}={}",
            self.normalized_level()?
        ))
    }

    fn event_filter(&self) -> Result<tracing_subscriber::EnvFilter, Box<dyn Error>> {
        let filter = self.filter_directive()?;
        tracing_subscriber::EnvFilter::try_new(&filter)
            .map_err(|error| format!("invalid logging.loki.filter {filter:?}: {error}").into())
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

pub fn init(
    service_name: &'static str,
    config_path: impl AsRef<std::path::Path>,
) -> Result<LoggingGuard, Box<dyn Error>> {
    let cli_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_line_number(true)
        .fmt_fields(LokiFields::default())
        .event_format(ScopedSpanEventFormatter {
            display_timestamp: true,
            use_ansi: false,
        });
    let root = load_logging_config(config_path)?;

    if root.logging.loki.enabled() {
        let node_id = logging_node_id(&root.s2s);
        let loki_event_filter = root.logging.loki.event_filter()?;
        let (loki_formatter, flush_handle) =
            LokiEventFormatter::spawn(root.logging.loki, service_name, node_id)?;
        let loki_layer = tracing_subscriber::fmt::layer()
            .with_ansi(true)
            .with_writer(NoopMakeWriter)
            .fmt_fields(LokiFields::default())
            .event_format(loki_formatter);
        tracing_subscriber::registry()
            .with(SpanFieldsLayer::default())
            .with(fmt_layer.with_filter(cli_filter))
            .with(loki_layer.with_filter(loki_event_filter))
            .init();
        set_global_loki_flush_handle(flush_handle.clone());
        install_panic_hook();
        Ok(LoggingGuard {
            flush_handle: Some(flush_handle),
        })
    } else {
        tracing_subscriber::registry()
            .with(SpanFieldsLayer::default())
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

fn load_logging_config(
    config_path: impl AsRef<std::path::Path>,
) -> Result<LoggingRootConfig, config::ConfigError> {
    ConfigCrate::builder()
        .add_source(File::from(config_path.as_ref().to_path_buf()).required(false))
        .add_source(Environment::with_prefix("SHITSPEAK").separator("_"))
        .add_source(
            Environment::with_prefix("SHITSPEAK")
                .prefix_separator("_")
                .separator("__"),
        )
        .build()?
        .try_deserialize::<LoggingRootConfig>()
}

fn logging_node_id(s2s: &S2sConfig) -> NodeIdentifier {
    match s2s.local_node_id() {
        Ok(node_id) => node_id,
        Err(error) => {
            eprintln!("loki logging: failed to resolve local S2S node id label; using 0: {error}");
            0
        }
    }
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

fn default_loki_retry_initial_interval_ms() -> u64 {
    DEFAULT_LOKI_RETRY_INITIAL_INTERVAL_MS
}

fn default_loki_retry_max_interval_ms() -> u64 {
    DEFAULT_LOKI_RETRY_MAX_INTERVAL_MS
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
    line_formatter: ScopedSpanEventFormatter,
}

impl LokiEventFormatter {
    fn spawn(
        config: LokiConfig,
        service_name: &'static str,
        node_id: NodeIdentifier,
    ) -> Result<(Self, LokiFlushHandle), Box<dyn Error>> {
        let push_url = config
            .push_url()
            .ok_or("logging.loki.enabled=true requires logging.loki.url")?;
        let queue_capacity = config.queue_capacity();
        let batch_size = config.batch_size();
        let flush_interval = config.flush_interval();
        let request_timeout = config.request_timeout();
        let retry_cache_capacity = config.retry_cache_capacity();
        let retry_initial_interval = config.retry_initial_interval();
        let retry_max_interval = config.retry_max_interval();
        let labels = base_labels(service_name, &config.labels, node_id);
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
                retry_cache_capacity,
                retry_initial_interval,
                retry_max_interval,
            },
        ));

        Ok((
            Self {
                tx,
                line_formatter: ScopedSpanEventFormatter {
                    display_timestamp: false,
                    use_ansi: true,
                },
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
struct SpanFieldsLayer;

impl<S> Layer<S> for SpanFieldsLayer
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
        let mut visitor = LokiFieldVisitor {
            inner: self.inner.make_visitor(writer),
        };
        fields.record(&mut visitor);
        visitor.inner.finish()
    }
}

struct LokiFieldVisitor<'writer> {
    inner: DefaultVisitor<'writer>,
}

impl LokiFieldVisitor<'_> {
    fn display(field: &Field) -> bool {
        !matches!(
            field.name(),
            "client_cert_hash"
                | "client_tls_ja3"
                | "client_tls_ja4"
                | "client_tls_ja4t"
                | "client_tls_ja4x"
                | "client_tls_ja4l"
                | "client_connection_sni"
                | "client_real_ip"
                | "client_connection_remote_ip"
                | "client_connection_remote_port"
                | "client_connection_local_port"
                | "client_node"
                | "client_local_session_id"
                | "client_auth_session_id"
                | "client_user_id"
                | "client_user_name"
                | "client_fqdn"
                | "virtual_server_id"
        )
    }
}

impl Visit for LokiFieldVisitor<'_> {
    fn record_bool(&mut self, field: &Field, value: bool) {
        if Self::display(field) {
            self.inner.record_bool(field, value);
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        if Self::display(field) {
            self.inner.record_i64(field, value);
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        if Self::display(field) {
            self.inner.record_u64(field, value);
        }
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        if Self::display(field) {
            self.inner.record_f64(field, value);
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if Self::display(field) && !(field.name() == "fqdn" && value.is_empty()) {
            self.inner.record_str(field, value);
        }
    }

    fn record_error(&mut self, field: &Field, value: &(dyn Error + 'static)) {
        if Self::display(field) {
            self.inner.record_error(field, value);
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if Self::display(field) {
            self.inner.record_debug(field, value);
        }
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

pub(super) struct SpanFields {
    pub(super) fields: serde_json::Map<String, serde_json::Value>,
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
        self.insert(
            field,
            serde_json::Value::String(metadata_debug_to_string(value)),
        );
    }
}

#[derive(Clone)]
struct LokiEntry {
    timestamp_ns: String,
    level: String,
    line: String,
    metadata: BTreeMap<String, String>,
}

struct LokiBatch {
    entries: Vec<LokiEntry>,
    next_retry_at: tokio::time::Instant,
    retry_delay: Duration,
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
    retry_cache_capacity: usize,
    retry_initial_interval: Duration,
    retry_max_interval: Duration,
}

async fn run_loki_sender(
    mut rx: mpsc::Receiver<LokiEntry>,
    mut command_rx: mpsc::UnboundedReceiver<LokiCommand>,
    sender: LokiSender,
) {
    let mut pending = Vec::with_capacity(sender.batch_size);
    let mut retry_cache = VecDeque::new();
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
                            flush_loki_batch(&sender, &mut pending, &mut retry_cache).await;
                        }
                    }
                    None => {
                        flush_loki_batch(&sender, &mut pending, &mut retry_cache).await;
                        break;
                    }
                }
            }
            command = command_rx.recv(), if !command_rx_closed => {
                match command {
                    Some(LokiCommand::Flush(ack)) => {
                        drain_loki_entries(&mut rx, &sender, &mut pending, &mut retry_cache).await;
                        flush_loki_retry_cache(&sender, &mut retry_cache, true).await;
                        flush_loki_batch(&sender, &mut pending, &mut retry_cache).await;
                        let _ = ack.send(());
                    }
                    Some(LokiCommand::Shutdown(ack)) => {
                        drain_loki_entries(&mut rx, &sender, &mut pending, &mut retry_cache).await;
                        flush_loki_retry_cache(&sender, &mut retry_cache, true).await;
                        flush_loki_batch(&sender, &mut pending, &mut retry_cache).await;
                        let _ = ack.send(());
                        break;
                    }
                    None => {
                        command_rx_closed = true;
                    }
                }
            }
            _ = interval.tick() => {
                flush_loki_retry_cache(&sender, &mut retry_cache, false).await;
                flush_loki_batch(&sender, &mut pending, &mut retry_cache).await;
            }
        }
    }
}

async fn drain_loki_entries(
    rx: &mut mpsc::Receiver<LokiEntry>,
    sender: &LokiSender,
    pending: &mut Vec<LokiEntry>,
    retry_cache: &mut VecDeque<LokiBatch>,
) {
    while let Ok(entry) = rx.try_recv() {
        pending.push(entry);
        if pending.len() >= sender.batch_size {
            flush_loki_batch(sender, pending, retry_cache).await;
        }
    }
}

async fn flush_loki_batch(
    sender: &LokiSender,
    pending: &mut Vec<LokiEntry>,
    retry_cache: &mut VecDeque<LokiBatch>,
) {
    if pending.is_empty() {
        return;
    }

    for prepared_batch in prepare_loki_push_batches(&sender.labels, std::mem::take(pending)) {
        let LokiPreparedPush::Ready { entries, body } = prepared_batch else {
            let LokiPreparedPush::OversizedEntry { payload_bytes } = prepared_batch else {
                unreachable!("all prepared Loki push variants are handled")
            };
            eprintln!(
                "loki logging: dropping log entry because its encoded payload exceeds the hard limit \
                 (payload_bytes={payload_bytes}, max_payload_bytes={MAX_LOKI_PUSH_BODY_BYTES})"
            );
            continue;
        };

        match send_loki_body(sender, body, entries.len()).await {
            LokiPushResult::Delivered => {}
            LokiPushResult::Retryable(error) => {
                let entry_count = entries.len();
                cache_loki_retry_batch(sender, retry_cache, entries, sender.retry_initial_interval);
                eprintln!(
                    "loki logging: push failed; caching batch for retry \
                     (batch_entries={entry_count}, retry_in_ms={}, cached_entries={}/{}): {error}",
                    sender.retry_initial_interval.as_millis(),
                    loki_cached_entry_count(retry_cache),
                    sender.retry_cache_capacity,
                );
            }
            LokiPushResult::Permanent(error) => {
                eprintln!(
                    "loki logging: dropping log batch (batch_entries={}): {error}",
                    entries.len()
                );
            }
        }
    }
}

async fn flush_loki_retry_cache(
    sender: &LokiSender,
    retry_cache: &mut VecDeque<LokiBatch>,
    force: bool,
) {
    if retry_cache.is_empty() {
        return;
    }

    let now = tokio::time::Instant::now();
    let mut deferred = VecDeque::with_capacity(retry_cache.len());
    while let Some(batch) = retry_cache.pop_front() {
        if !force && batch.next_retry_at > now {
            deferred.push_back(batch);
            continue;
        }

        for prepared_batch in prepare_loki_push_batches(&sender.labels, batch.entries) {
            let LokiPreparedPush::Ready { entries, body } = prepared_batch else {
                let LokiPreparedPush::OversizedEntry { payload_bytes } = prepared_batch else {
                    unreachable!("all prepared Loki push variants are handled")
                };
                eprintln!(
                    "loki logging: dropping cached log entry because its encoded payload exceeds the hard limit \
                     (payload_bytes={payload_bytes}, max_payload_bytes={MAX_LOKI_PUSH_BODY_BYTES})"
                );
                continue;
            };

            match send_loki_body(sender, body, entries.len()).await {
                LokiPushResult::Delivered => {}
                LokiPushResult::Retryable(error) => {
                    let next_delay = batch
                        .retry_delay
                        .saturating_mul(2)
                        .min(sender.retry_max_interval);
                    let entry_count = entries.len();
                    let retry_batch = LokiBatch {
                        entries,
                        next_retry_at: tokio::time::Instant::now() + next_delay,
                        retry_delay: next_delay,
                    };
                    eprintln!(
                        "loki logging: retry failed; keeping batch cached \
                         (batch_entries={entry_count}, next_retry_in_ms={}): {error}",
                        next_delay.as_millis(),
                    );
                    deferred.push_back(retry_batch);
                }
                LokiPushResult::Permanent(error) => {
                    eprintln!(
                        "loki logging: dropping cached log batch (batch_entries={}): {error}",
                        entries.len()
                    );
                }
            }
        }
    }

    *retry_cache = deferred;
    trim_loki_retry_cache(sender, retry_cache);
}

fn loki_cached_entry_count(retry_cache: &VecDeque<LokiBatch>) -> usize {
    retry_cache.iter().map(|batch| batch.entries.len()).sum()
}

fn cache_loki_retry_batch(
    sender: &LokiSender,
    retry_cache: &mut VecDeque<LokiBatch>,
    entries: Vec<LokiEntry>,
    retry_delay: Duration,
) {
    if entries.is_empty() {
        return;
    }

    let retry_delay = retry_delay.min(sender.retry_max_interval);
    retry_cache.push_back(LokiBatch {
        entries,
        next_retry_at: tokio::time::Instant::now() + retry_delay,
        retry_delay,
    });
    trim_loki_retry_cache(sender, retry_cache);
}

fn trim_loki_retry_cache(sender: &LokiSender, retry_cache: &mut VecDeque<LokiBatch>) {
    let mut cached_entries = retry_cache
        .iter()
        .map(|batch| batch.entries.len())
        .sum::<usize>();
    while cached_entries > sender.retry_cache_capacity {
        let Some(mut batch) = retry_cache.pop_front() else {
            break;
        };
        if cached_entries.saturating_sub(batch.entries.len()) >= sender.retry_cache_capacity {
            cached_entries = cached_entries.saturating_sub(batch.entries.len());
            eprintln!(
                "loki logging: dropping {} cached entries after retry cache overflow",
                batch.entries.len()
            );
            continue;
        }

        let overflow = cached_entries - sender.retry_cache_capacity;
        batch.entries.drain(..overflow);
        cached_entries -= overflow;
        eprintln!("loki logging: dropping {overflow} cached entries after retry cache overflow");
        retry_cache.push_front(batch);
    }
}

enum LokiPushResult {
    Delivered,
    Retryable(String),
    Permanent(String),
}

enum LokiPreparedPush {
    Ready {
        entries: Vec<LokiEntry>,
        body: Vec<u8>,
    },
    OversizedEntry {
        payload_bytes: usize,
    },
}

fn prepare_loki_push_batches(
    base_labels: &BTreeMap<String, String>,
    entries: Vec<LokiEntry>,
) -> Vec<LokiPreparedPush> {
    prepare_loki_push_batches_with_limits(
        base_labels,
        entries,
        TARGET_LOKI_PUSH_BODY_BYTES,
        MAX_LOKI_PUSH_BODY_BYTES,
    )
}

fn prepare_loki_push_batches_with_limits(
    base_labels: &BTreeMap<String, String>,
    entries: Vec<LokiEntry>,
    target_body_bytes: usize,
    max_body_bytes: usize,
) -> Vec<LokiPreparedPush> {
    let estimated_batches = split_loki_entries_by_estimated_size(entries, target_body_bytes);
    let mut prepared = Vec::with_capacity(estimated_batches.len());
    for batch in estimated_batches {
        prepare_loki_push_batch(base_labels, batch, max_body_bytes, &mut prepared);
    }
    prepared
}

fn split_loki_entries_by_estimated_size(
    entries: Vec<LokiEntry>,
    target_body_bytes: usize,
) -> Vec<Vec<LokiEntry>> {
    let mut batches = Vec::new();
    let mut batch = Vec::new();
    let mut estimated_bytes = 0usize;

    for entry in entries {
        let entry_bytes = estimated_loki_entry_size(&entry);
        if !batch.is_empty() && estimated_bytes.saturating_add(entry_bytes) > target_body_bytes {
            batches.push(std::mem::take(&mut batch));
            estimated_bytes = 0;
        }
        estimated_bytes = estimated_bytes.saturating_add(entry_bytes);
        batch.push(entry);
    }
    if !batch.is_empty() {
        batches.push(batch);
    }
    batches
}

fn estimated_loki_entry_size(entry: &LokiEntry) -> usize {
    entry
        .timestamp_ns
        .len()
        .saturating_add(entry.line.len())
        .saturating_add(
            entry
                .metadata
                .iter()
                .map(|(key, value)| key.len().saturating_add(value.len()).saturating_add(8))
                .sum::<usize>(),
        )
        .saturating_add(32)
}

fn prepare_loki_push_batch(
    base_labels: &BTreeMap<String, String>,
    entries: Vec<LokiEntry>,
    max_body_bytes: usize,
    prepared: &mut Vec<LokiPreparedPush>,
) {
    let payload = build_push_request(base_labels, entries.iter().cloned());
    let body = match serde_json::to_vec(&payload) {
        Ok(body) => body,
        Err(error) => {
            eprintln!("loki logging: dropping log batch because it could not be encoded: {error}");
            return;
        }
    };
    if body.len() <= max_body_bytes {
        prepared.push(LokiPreparedPush::Ready { entries, body });
    } else if entries.len() == 1 {
        prepared.push(LokiPreparedPush::OversizedEntry {
            payload_bytes: body.len(),
        });
    } else {
        let split_at = entries.len() / 2;
        let mut latter = entries;
        let former = latter.drain(..split_at).collect();
        prepare_loki_push_batch(base_labels, former, max_body_bytes, prepared);
        prepare_loki_push_batch(base_labels, latter, max_body_bytes, prepared);
    }
}

async fn send_loki_body(sender: &LokiSender, body: Vec<u8>, entry_count: usize) -> LokiPushResult {
    let payload_bytes = body.len();

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
        Ok(response) if response.status().is_success() => LokiPushResult::Delivered,
        Ok(response) => {
            let status = response.status();
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("not-provided")
                .to_string();
            let text = response.text().await.unwrap_or_default();
            let message = format_loki_http_error(
                &sender.push_url,
                status,
                &retry_after,
                entry_count,
                payload_bytes,
                &text,
            );
            if status.is_server_error() || status.as_u16() == 429 {
                LokiPushResult::Retryable(message)
            } else {
                LokiPushResult::Permanent(message)
            }
        }
        Err(error) => LokiPushResult::Retryable(format_loki_transport_error(
            &error,
            entry_count,
            payload_bytes,
        )),
    }
}

fn format_loki_transport_error(
    error: &reqwest::Error,
    entry_count: usize,
    payload_bytes: usize,
) -> String {
    let mut source_chain = Vec::new();
    let mut source = error.source();
    while let Some(cause) = source {
        source_chain.push(cause.to_string());
        source = cause.source();
    }

    let source_chain = if source_chain.is_empty() {
        "none".to_string()
    } else {
        source_chain.join(" -> ")
    };
    format!(
        "transport error (batch_entries={entry_count}, payload_bytes={payload_bytes}, \
         timeout={}, connect={}, request={}, body={}): {error}; source_chain={source_chain}",
        error.is_timeout(),
        error.is_connect(),
        error.is_request(),
        error.is_body(),
    )
}

fn format_loki_http_error(
    push_url: &str,
    status: reqwest::StatusCode,
    retry_after: &str,
    entry_count: usize,
    payload_bytes: usize,
    response_body: &str,
) -> String {
    let response_body = loki_response_body_for_log(response_body);
    format!(
        "HTTP push failed (endpoint={}, status={status}, retry_after={retry_after}, \
         batch_entries={entry_count}, payload_bytes={payload_bytes}, response_body={response_body:?})",
        loki_endpoint_for_log(push_url),
    )
}

fn loki_endpoint_for_log(push_url: &str) -> String {
    let Ok(url) = reqwest::Url::parse(push_url) else {
        return "invalid-configured-url".to_string();
    };
    let origin = url.origin().ascii_serialization();
    if origin == "null" {
        return "invalid-configured-url".to_string();
    }
    format!("{origin}{}", url.path())
}

fn loki_response_body_for_log(response_body: &str) -> String {
    let mut characters = response_body.chars();
    let excerpt = characters
        .by_ref()
        .take(MAX_LOKI_RESPONSE_BODY_LOG_CHARS)
        .collect::<String>();
    if characters.next().is_some() {
        format!("{excerpt}… [truncated at {MAX_LOKI_RESPONSE_BODY_LOG_CHARS} characters]")
    } else {
        excerpt
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
    node_id: NodeIdentifier,
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

    labels.insert("node_id".to_string(), node_id.to_string());

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
    strip_ansi_escape_codes(&metadata_value_to_display_string(value))
}

fn metadata_value_to_display_string(value: serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value,
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::Array(values) => {
            let values = values
                .into_iter()
                .map(metadata_value_to_display_string)
                .collect::<Vec<_>>();
            format!("[{}]", values.join(", "))
        }
        serde_json::Value::Object(values) => {
            let values = values
                .into_iter()
                .map(|(key, value)| format!("{key}: {}", metadata_value_to_display_string(value)))
                .collect::<Vec<_>>();
            format!("{{{}}}", values.join(", "))
        }
    }
}

fn metadata_debug_to_string(value: &dyn fmt::Debug) -> String {
    strip_ansi_escape_codes(&unquote_debug_string_literals(&format!("{value:?}")))
}

fn unquote_debug_string_literals(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    let mut in_string = false;

    while let Some(ch) = chars.next() {
        match (in_string, ch) {
            (false, '"') => in_string = true,
            (true, '"') => in_string = false,
            (true, '\\') => append_debug_escape(&mut out, &mut chars),
            _ => out.push(ch),
        }
    }

    out
}

fn append_debug_escape(out: &mut String, chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    let Some(ch) = chars.next() else {
        return;
    };

    match ch {
        '"' => out.push('\''),
        '\\' => out.push('\\'),
        'n' | 'r' | 't' => out.push(' '),
        '0' => out.push('0'),
        'u' if chars.next_if_eq(&'{').is_some() => {
            let mut scalar = String::new();
            for ch in chars.by_ref() {
                if ch == '}' {
                    break;
                }
                scalar.push(ch);
            }
            if let Ok(value) = u32::from_str_radix(&scalar, 16)
                && let Some(ch) = char::from_u32(value)
                && !ch.is_control()
            {
                out.push(ch);
            }
        }
        other => out.push(other),
    }
}

fn strip_ansi_escape_codes(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '\u{1b}' {
            out.push(ch);
            continue;
        }

        match chars.peek().copied() {
            Some('[') => {
                chars.next();
                for ch in chars.by_ref() {
                    if ('@'..='~').contains(&ch) {
                        break;
                    }
                }
            }
            Some(']') => {
                chars.next();
                while let Some(ch) = chars.next() {
                    if ch == '\u{7}' {
                        break;
                    }
                    if ch == '\u{1b}' && chars.next_if_eq(&'\\').is_some() {
                        break;
                    }
                }
            }
            _ => {}
        }
    }

    out
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
    fn logging_config_uses_the_explicit_config_path() {
        let directory = tempfile::tempdir().expect("create config directory");
        let config_path = directory.path().join("node-1.toml");
        std::fs::write(
            &config_path,
            r#"
[logging.loki]
enabled = true
url = "https://loki.example"

[s2s]
node_id = 1
"#,
        )
        .expect("write explicit config");

        let config = load_logging_config(&config_path).expect("load explicit config");

        assert!(config.logging.loki.enabled());
        assert_eq!(
            config.logging.loki.push_url().as_deref(),
            Some("https://loki.example/loki/api/v1/push")
        );
    }

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
    fn loki_client_span_keeps_full_metadata_but_limits_displayed_identity() {
        let (tx, mut rx) = mpsc::channel(1);
        let formatter = LokiEventFormatter {
            tx,
            line_formatter: ScopedSpanEventFormatter {
                display_timestamp: false,
                use_ansi: true,
            },
        };
        let subscriber = tracing_subscriber::registry().with(SpanFieldsLayer).with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(NoopMakeWriter)
                .fmt_fields(LokiFields::default())
                .event_format(formatter),
        );

        tracing::subscriber::with_default(subscriber, || {
            let server = tracing::info_span!("server", virtual_server_id = "provisional");
            server.record("virtual_server_id", "tenant-alpha");
            let _server_entered = server.enter();
            let span = tracing::info_span!(
                "client",
                client_cert_hash = "certificate-hash",
                client_tls_ja3 = "771,4865-4866,10-11,23,0",
                client_tls_ja4 = "t13d1516h2_8daaf6152771_02713d6af862",
                client_tls_ja4t = "64240_2-1-3-4_1460_8",
                client_tls_ja4x = "aabbccddeeff_112233445566_778899aabbcc",
                client_tls_ja4l = "125_57_150",
                client_connection_sni = "voice.example.test",
                client_real_ip = "203.0.113.8",
                client_connection_remote_ip = "192.0.2.4",
                client_connection_remote_port = 54_321_u16,
                client_connection_local_port = 64_738_u16,
                client_node = 7_u16,
                client_local_session_id = 42_u32,
                client_auth_session_id = tracing::field::Empty,
                client_user_id = tracing::field::Empty,
                client_user_name = tracing::field::Empty,
                client_fqdn = tracing::field::Empty,
            );
            span.record("client_auth_session_id", "auth-session-123");
            span.record("client_user_id", 99_u32);
            span.record("client_user_name", "Alice");
            span.record("client_fqdn", "alice@example.test");
            let _entered = span.enter();
            tracing::info!("client event");
        });

        let entry = rx.try_recv().expect("client event should be captured");
        assert_eq!(
            entry.metadata.get("virtual_server_id").map(String::as_str),
            Some("tenant-alpha")
        );
        assert_eq!(
            entry.metadata.get("spans").map(String::as_str),
            Some("[server, client]")
        );
        for (key, value) in [
            ("client_cert_hash", "certificate-hash"),
            ("client_tls_ja3", "771,4865-4866,10-11,23,0"),
            ("client_tls_ja4", "t13d1516h2_8daaf6152771_02713d6af862"),
            ("client_tls_ja4t", "64240_2-1-3-4_1460_8"),
            ("client_tls_ja4x", "aabbccddeeff_112233445566_778899aabbcc"),
            ("client_tls_ja4l", "125_57_150"),
            ("client_connection_sni", "voice.example.test"),
            ("client_real_ip", "203.0.113.8"),
            ("client_connection_remote_ip", "192.0.2.4"),
            ("client_connection_remote_port", "54321"),
            ("client_connection_local_port", "64738"),
            ("client_node", "7"),
            ("client_local_session_id", "42"),
            ("client_auth_session_id", "auth-session-123"),
            ("client_user_id", "99"),
            ("client_user_name", "Alice"),
            ("client_fqdn", "alice@example.test"),
        ] {
            assert_eq!(entry.metadata.get(key).map(String::as_str), Some(value));
        }
        for key in ["real_ip", "client_port", "node", "session", "fqdn", "id"] {
            assert!(
                !entry.metadata.contains_key(key),
                "display field leaked into structured metadata: {key}"
            );
        }

        let rendered_line = strip_ansi_escape_codes(&entry.line);
        assert!(
            rendered_line.contains(
                "server{id=tenant-alpha} client{real_ip=203.0.113.8 client_port=54321 node=7 session=42 fqdn=alice@example.test}"
            ),
            "unexpected client scope: {rendered_line}",
        );
        assert!(
            entry.line.contains("\x1b[1mserver{id=tenant-alpha}\x1b[0m"),
            "server scope lost its ANSI emphasis: {}",
            entry.line
        );
        assert!(
            !entry.line.contains("server:client:"),
            "redundant default span prefix remained: {}",
            entry.line
        );
        for field in [
            "client_cert_hash",
            "client_tls_ja3",
            "client_tls_ja4",
            "client_tls_ja4t",
            "client_tls_ja4x",
            "client_tls_ja4l",
            "client_connection_sni",
            "client_real_ip",
            "client_connection_remote_ip",
            "client_connection_remote_port",
            "client_connection_local_port",
            "client_node",
            "client_local_session_id",
            "client_auth_session_id",
            "client_user_id",
            "client_user_name",
            "client_fqdn",
        ] {
            assert!(
                !entry.line.contains(field),
                "line unexpectedly includes {field}: {}",
                entry.line
            );
        }
    }

    #[test]
    fn loki_client_span_omits_an_unavailable_fqdn_from_the_line() {
        let (tx, mut rx) = mpsc::channel(1);
        let formatter = LokiEventFormatter {
            tx,
            line_formatter: ScopedSpanEventFormatter {
                display_timestamp: false,
                use_ansi: false,
            },
        };
        let subscriber = tracing_subscriber::registry().with(SpanFieldsLayer).with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(NoopMakeWriter)
                .fmt_fields(LokiFields::default())
                .event_format(formatter),
        );

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(
                "client",
                client_real_ip = "203.0.113.8",
                client_connection_remote_port = 54_321_u16,
                client_connection_local_port = 64_738_u16,
                client_node = 7_u16,
                client_local_session_id = 42_u32,
                client_fqdn = tracing::field::Empty,
            );
            span.record("client_fqdn", "");
            let _entered = span.enter();
            tracing::info!("client event");
        });

        let entry = rx.try_recv().expect("client event should be captured");
        assert_eq!(
            entry.metadata.get("client_fqdn").map(String::as_str),
            Some("")
        );
        assert!(
            entry
                .line
                .contains("client{real_ip=203.0.113.8 client_port=54321 node=7 session=42}"),
            "{}",
            entry.line
        );
        assert!(!entry.line.contains("fqdn"), "{}", entry.line);
    }

    #[test]
    fn loki_config_default_filter_only_captures_shitspeak_rs() {
        let cfg = LokiConfig::default();

        assert_eq!(cfg.level, "debug");
        assert_eq!(
            cfg.filter_directive().unwrap(),
            "shitspeak_rs=debug".to_string()
        );
        cfg.event_filter().expect("default filter parses");
    }

    #[test]
    fn loki_config_filter_overrides_level_fallback() {
        let cfg = LokiConfig {
            filter: Some("shitspeak_rs=info,tower_http=warn".to_string()),
            level: "trace".to_string(),
            ..Default::default()
        };

        assert_eq!(
            cfg.filter_directive().unwrap(),
            "shitspeak_rs=info,tower_http=warn"
        );
        cfg.event_filter().expect("explicit filter parses");
    }

    #[test]
    fn loki_retry_defaults_are_bounded_and_valid() {
        let cfg = LokiConfig::default();

        assert_eq!(cfg.retry_cache_capacity(), cfg.queue_capacity());
        assert_eq!(
            cfg.retry_initial_interval(),
            Duration::from_millis(DEFAULT_LOKI_RETRY_INITIAL_INTERVAL_MS)
        );
        assert_eq!(
            cfg.retry_max_interval(),
            Duration::from_millis(DEFAULT_LOKI_RETRY_MAX_INTERVAL_MS)
        );
    }

    #[test]
    fn loki_retry_cache_trims_oldest_entries() {
        let sender = test_loki_sender(3);
        let mut cache = VecDeque::new();

        cache_loki_retry_batch(
            &sender,
            &mut cache,
            vec![
                test_loki_entry("1"),
                test_loki_entry("2"),
                test_loki_entry("3"),
            ],
            Duration::from_millis(1),
        );
        cache_loki_retry_batch(
            &sender,
            &mut cache,
            vec![test_loki_entry("4"), test_loki_entry("5")],
            Duration::from_millis(1),
        );

        let retained = cache
            .iter()
            .flat_map(|batch| batch.entries.iter())
            .map(|entry| entry.timestamp_ns.as_str())
            .collect::<Vec<_>>();

        assert_eq!(retained, vec!["3", "4", "5"]);
    }

    #[tokio::test]
    async fn loki_connection_failure_includes_transport_diagnostics() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("reserve a localhost port for a refused connection");
        let address = listener
            .local_addr()
            .expect("reserved listener has a local address");
        drop(listener);

        let mut sender = test_loki_sender(1);
        sender.push_url = format!("http://{address}/loki/api/v1/push");
        let prepared = prepare_loki_push_batches(&sender.labels, vec![test_loki_entry("1")]);
        let [LokiPreparedPush::Ready { entries, body }] = prepared.as_slice() else {
            panic!("small log entry produces one sendable request");
        };
        let result = send_loki_body(&sender, body.clone(), entries.len()).await;

        let LokiPushResult::Retryable(diagnostics) = result else {
            panic!("a refused connection must be retried");
        };
        assert!(diagnostics.contains("transport error (batch_entries=1, payload_bytes="));
        assert!(diagnostics.contains("connect=true"));
        assert!(diagnostics.contains("request=true"));
        assert!(diagnostics.contains("source_chain="));
        assert!(!diagnostics.ends_with("source_chain=none"));
    }

    #[test]
    fn loki_http_failure_includes_actionable_safe_diagnostics() {
        let diagnostics = format_loki_http_error(
            "https://alice:secret@loki.example/loki/api/v1/push?api_key=top-secret",
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            "10",
            2,
            99,
            "rate limit\ntry later",
        );

        assert!(diagnostics.contains("endpoint=https://loki.example/loki/api/v1/push"));
        assert!(diagnostics.contains("status=429 Too Many Requests"));
        assert!(diagnostics.contains("retry_after=10"));
        assert!(diagnostics.contains("batch_entries=2"));
        assert!(diagnostics.contains("payload_bytes=99"));
        assert!(diagnostics.contains("response_body=\"rate limit\\ntry later\""));
        assert!(!diagnostics.contains("alice"));
        assert!(!diagnostics.contains("secret"));
        assert!(!diagnostics.contains("api_key"));
    }

    #[test]
    fn loki_pushes_target_50_mb_and_never_exceed_the_100_mb_hard_cap() {
        assert_eq!(TARGET_LOKI_PUSH_BODY_BYTES, 50_000_000);
        assert_eq!(MAX_LOKI_PUSH_BODY_BYTES, 100_000_000);
    }

    #[test]
    fn loki_push_batches_are_split_to_the_hard_encoded_size_limit() {
        let labels = BTreeMap::new();
        let entries = (1..=4)
            .map(|timestamp| LokiEntry {
                timestamp_ns: timestamp.to_string(),
                level: "INFO".to_string(),
                line: "x".repeat(100),
                metadata: BTreeMap::new(),
            })
            .collect();

        let batches = prepare_loki_push_batches_with_limits(&labels, entries, 10_000, 350);
        let ready_batches = batches
            .iter()
            .filter_map(|batch| match batch {
                LokiPreparedPush::Ready { entries, body } => Some((entries, body)),
                LokiPreparedPush::OversizedEntry { .. } => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(ready_batches.len(), 2);
        assert!(ready_batches.iter().all(|(_, body)| body.len() <= 350));
        assert_eq!(
            ready_batches
                .iter()
                .flat_map(|(entries, _)| entries.iter())
                .map(|entry| entry.timestamp_ns.as_str())
                .collect::<Vec<_>>(),
            vec!["1", "2", "3", "4"]
        );
    }

    #[test]
    fn loki_push_drops_a_single_entry_over_the_hard_encoded_size_limit() {
        let batches = prepare_loki_push_batches_with_limits(
            &BTreeMap::new(),
            vec![LokiEntry {
                timestamp_ns: "1".to_string(),
                level: "INFO".to_string(),
                line: "x".repeat(500),
                metadata: BTreeMap::new(),
            }],
            50,
            100,
        );

        assert!(matches!(
            batches.as_slice(),
            [LokiPreparedPush::OversizedEntry { payload_bytes }] if *payload_bytes > 100
        ));
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
    fn loki_structured_metadata_formats_containers_without_json_string_escapes() {
        let mut fields = serde_json::Map::new();
        fields.insert(
            "spans".to_string(),
            serde_json::Value::Array(vec![serde_json::Value::String("client".to_string())]),
        );

        let metadata = structured_metadata(fields);

        assert_eq!(metadata.get("spans").map(String::as_str), Some("[client]"));
    }

    #[test]
    fn loki_debug_metadata_unquotes_debug_string_literals() {
        let formatted = metadata_debug_to_string(&format_args!(
            "SeedAddress {{ addr: {:?}, transport: Tcp }}",
            "hk.mumble.winterco.org:64739"
        ));

        assert_eq!(
            formatted,
            "SeedAddress { addr: hk.mumble.winterco.org:64739, transport: Tcp }"
        );
        assert!(!formatted.contains("\\\""));
        assert!(!formatted.contains('"'));
    }

    #[test]
    fn loki_metadata_strips_ansi_escape_codes() {
        let mut fields = serde_json::Map::new();
        fields.insert(
            "client".to_string(),
            serde_json::Value::String("\u{1b}[32mgreen\u{1b}[0m".to_string()),
        );

        let metadata = structured_metadata(fields);

        assert_eq!(metadata.get("client").map(String::as_str), Some("green"));
    }

    #[test]
    fn invalid_label_names_are_ignored() {
        let mut configured = HashMap::new();
        configured.insert("valid_label".to_string(), "yes".to_string());
        configured.insert("not-valid".to_string(), "no".to_string());

        let labels = base_labels("svc", &configured, 7);

        assert_eq!(labels.get("valid_label").map(String::as_str), Some("yes"));
        assert!(!labels.contains_key("not-valid"));
    }

    #[test]
    fn base_labels_include_node_id() {
        let mut configured = HashMap::new();
        configured.insert("node_id".to_string(), "configured".to_string());

        let labels = base_labels("svc", &configured, 42);

        assert_eq!(labels.get("node_id").map(String::as_str), Some("42"));
    }

    fn test_loki_sender(retry_cache_capacity: usize) -> LokiSender {
        LokiSender {
            client: reqwest::Client::new(),
            push_url: "http://127.0.0.1:3100/loki/api/v1/push".to_string(),
            tenant_id: None,
            username: None,
            password: None,
            bearer_token: None,
            labels: BTreeMap::new(),
            batch_size: 128,
            flush_interval: Duration::from_millis(1000),
            retry_cache_capacity,
            retry_initial_interval: Duration::from_millis(1),
            retry_max_interval: Duration::from_millis(10),
        }
    }

    fn test_loki_entry(timestamp_ns: &str) -> LokiEntry {
        LokiEntry {
            timestamp_ns: timestamp_ns.to_string(),
            level: "INFO".to_string(),
            line: "line".to_string(),
            metadata: BTreeMap::new(),
        }
    }
}
