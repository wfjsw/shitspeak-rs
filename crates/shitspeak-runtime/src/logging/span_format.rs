use std::fmt;

use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::fmt::format::{FormatEvent, FormatFields, Writer};
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
use tracing_subscriber::registry::LookupSpan;

use super::SpanFields;

pub(super) struct ScopedSpanEventFormatter {
    pub(super) display_timestamp: bool,
    pub(super) use_ansi: bool,
}

impl<S, N> FormatEvent<S, N> for ScopedSpanEventFormatter
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let use_ansi = self.use_ansi || writer.has_ansi_escapes();
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                let extensions = span.extensions();
                let Some(fields) = extensions.get::<SpanFields>() else {
                    continue;
                };
                if let Some(display) = format_scoped_span(span.name(), fields) {
                    write_bold(&mut writer, &display, use_ansi)?;
                    writer.write_char(' ')?;
                }
            }
        }

        if self.display_timestamp {
            write_dimmed(&mut writer, use_ansi, |writer| {
                SystemTime.format_time(&mut writer.by_ref())
            })?;
            writer.write_char(' ')?;
        }

        write_level(&mut writer, event.metadata().level(), use_ansi)?;
        writer.write_char(' ')?;
        write_dimmed(&mut writer, use_ansi, |writer| {
            write!(writer, "{}:", event.metadata().target())
        })?;
        if let Some(line) = event.metadata().line() {
            write_dimmed(&mut writer, use_ansi, |writer| write!(writer, "{line}:"))?;
        }
        writer.write_char(' ')?;
        ctx.format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

fn write_bold(writer: &mut Writer<'_>, value: &str, use_ansi: bool) -> fmt::Result {
    write_styled(writer, "\x1b[1m", value, use_ansi)
}

fn write_dimmed(
    writer: &mut Writer<'_>,
    use_ansi: bool,
    write_value: impl FnOnce(&mut Writer<'_>) -> fmt::Result,
) -> fmt::Result {
    if use_ansi {
        writer.write_str("\x1b[2m")?;
        write_value(writer)?;
        writer.write_str("\x1b[0m")
    } else {
        write_value(writer)
    }
}

fn write_level(writer: &mut Writer<'_>, level: &tracing::Level, use_ansi: bool) -> fmt::Result {
    let (color, value) = match *level {
        tracing::Level::TRACE => ("35", "TRACE"),
        tracing::Level::DEBUG => ("34", "DEBUG"),
        tracing::Level::INFO => ("32", " INFO"),
        tracing::Level::WARN => ("33", " WARN"),
        tracing::Level::ERROR => ("31", "ERROR"),
    };
    if use_ansi {
        write!(writer, "\x1b[{color}m{value}\x1b[0m")
    } else {
        writer.write_str(value)
    }
}

fn write_styled(writer: &mut Writer<'_>, style: &str, value: &str, use_ansi: bool) -> fmt::Result {
    if use_ansi {
        writer.write_str(style)?;
        writer.write_str(value)?;
        writer.write_str("\x1b[0m")
    } else {
        writer.write_str(value)
    }
}

trait SpanFormatter<Fields> {
    const SPAN_NAME: &'static str;

    fn format(fields: &Fields) -> Option<String>;
}

struct ClientSpanFormatter;

impl SpanFormatter<SpanFields> for ClientSpanFormatter {
    const SPAN_NAME: &'static str = "client";

    fn format(fields: &SpanFields) -> Option<String> {
        fields
            .fields
            .contains_key("client_real_ip")
            .then(|| ClientSpanDisplay::new(fields).to_string())
    }
}

struct ServerSpanFormatter;

impl SpanFormatter<SpanFields> for ServerSpanFormatter {
    const SPAN_NAME: &'static str = "server";

    fn format(fields: &SpanFields) -> Option<String> {
        fields
            .fields
            .contains_key("virtual_server_id")
            .then(|| ServerSpanDisplay::new(fields).to_string())
    }
}

fn format_scoped_span(name: &str, fields: &SpanFields) -> Option<String> {
    match name {
        ClientSpanFormatter::SPAN_NAME => ClientSpanFormatter::format(fields),
        ServerSpanFormatter::SPAN_NAME => ServerSpanFormatter::format(fields),
        _ => None,
    }
}

struct ClientSpanDisplay<'a> {
    fields: &'a serde_json::Map<String, serde_json::Value>,
}

impl<'a> ClientSpanDisplay<'a> {
    fn new(fields: &'a SpanFields) -> Self {
        Self {
            fields: &fields.fields,
        }
    }

    fn value(&self, name: &str) -> Option<&str> {
        self.fields.get(name)?.as_str()
    }

    fn rendered_value(&self, name: &str) -> String {
        self.fields
            .get(name)
            .map(|value| {
                value
                    .as_str()
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| value.to_string())
            })
            .unwrap_or_default()
    }
}

impl fmt::Display for ClientSpanDisplay<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "client{{")?;
        for (index, (metadata_name, display_name)) in [
            ("client_real_ip", "real_ip"),
            ("client_connection_remote_port", "client_port"),
            ("client_node", "node"),
            ("client_local_session_id", "session"),
        ]
        .into_iter()
        .enumerate()
        {
            if index > 0 {
                formatter.write_str(" ")?;
            }
            write!(
                formatter,
                "{display_name}={}",
                self.rendered_value(metadata_name)
            )?;
        }
        if let Some(fqdn) = self.value("client_fqdn").filter(|fqdn| !fqdn.is_empty()) {
            write!(formatter, " fqdn={fqdn}")?;
        }
        formatter.write_str("}")
    }
}

struct ServerSpanDisplay<'a> {
    fields: &'a serde_json::Map<String, serde_json::Value>,
}

impl<'a> ServerSpanDisplay<'a> {
    fn new(fields: &'a SpanFields) -> Self {
        Self {
            fields: &fields.fields,
        }
    }
}

impl fmt::Display for ServerSpanDisplay<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let server_id = self
            .fields
            .get("virtual_server_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        write!(formatter, "server{{id={server_id}}}")
    }
}
