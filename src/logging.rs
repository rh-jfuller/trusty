use std::{
    collections::VecDeque,
    fmt,
    io::{self, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex, OnceLock,
    },
};

use serde_json::Value;
use tracing::level_filters::LevelFilter;
use tracing::{field::Field, field::Visit, Event, Subscriber};
use tracing_subscriber::{
    fmt::writer::MakeWriter,
    layer::{Context, Layer},
    prelude::*,
    EnvFilter,
};

static FULL_DIAGNOSTICS: AtomicBool = AtomicBool::new(false);
static DEBUG_MODE: AtomicBool = AtomicBool::new(false);
static TUI_ACTIVE: AtomicBool = AtomicBool::new(false);
static LOG_BUFFER: OnceLock<Mutex<LogBuffer>> = OnceLock::new();

const MAX_LOG_LINES: usize = 200;
const MAX_LOG_LINE_CHARS: usize = 400;

#[derive(Default)]
struct LogBuffer {
    lines: VecDeque<String>,
}

impl LogBuffer {
    fn push(&mut self, line: String) {
        if self.lines.len() == MAX_LOG_LINES {
            self.lines.pop_front();
        }
        self.lines.push_back(line);
    }

    fn snapshot(&self) -> Vec<String> {
        self.lines.iter().cloned().collect()
    }
}

#[derive(Default)]
struct LogEventVisitor {
    message: Option<String>,
    fields: Vec<String>,
}

impl LogEventVisitor {
    fn record_field(&mut self, name: &str, value: String) {
        let normalized_name = name
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .map(|character| character.to_ascii_lowercase())
            .collect::<String>();
        let value = if is_sensitive_field(&normalized_name) {
            "[REDACTED]".to_owned()
        } else {
            value
        };
        if name == "message" {
            self.message = Some(value);
        } else {
            self.fields.push(format!("{name}={value}"));
        }
    }
}

impl Visit for LogEventVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let value = format!("{value:?}");
        let value = if field.name() == "message" {
            value
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .unwrap_or(&value)
                .to_owned()
        } else {
            value
        };
        self.record_field(field.name(), value);
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_field(field.name(), value.to_owned());
    }
}

struct LogBufferLayer;

impl<S> Layer<S> for LogBufferLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        let mut visitor = LogEventVisitor::default();
        event.record(&mut visitor);

        let metadata = event.metadata();
        let target = metadata
            .target()
            .rsplit("::")
            .next()
            .unwrap_or(metadata.target());
        let mut message = visitor.message.unwrap_or_default();
        if !visitor.fields.is_empty() {
            if !message.is_empty() {
                message.push(' ');
            }
            message.push_str(&visitor.fields.join(" "));
        }
        let line = format!("{} {target}: {message}", metadata.level())
            .chars()
            .take(MAX_LOG_LINE_CHARS)
            .collect();
        let mut buffer = log_buffer()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        buffer.push(line);
    }
}

struct DiagnosticWriter;

impl<'a> MakeWriter<'a> for DiagnosticWriter {
    type Writer = Box<dyn Write + Send>;

    fn make_writer(&'a self) -> Self::Writer {
        if TUI_ACTIVE.load(Ordering::Relaxed) {
            Box::new(io::sink())
        } else {
            Box::new(io::stderr())
        }
    }
}

fn log_buffer() -> &'static Mutex<LogBuffer> {
    LOG_BUFFER.get_or_init(|| Mutex::new(LogBuffer::default()))
}

pub fn init(verbosity: u8, debug: bool) -> anyhow::Result<()> {
    let filter_level = filter_level(verbosity, debug);
    FULL_DIAGNOSTICS.store(full_diagnostics(verbosity, debug), Ordering::Relaxed);
    DEBUG_MODE.store(debug, Ordering::Relaxed);

    let filter = EnvFilter::default()
        .add_directive(LevelFilter::OFF.into())
        .add_directive(format!("trusty_cli={filter_level}").parse()?);

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_writer(DiagnosticWriter))
        .with(LogBufferLayer)
        .try_init()
        .map_err(|error| anyhow::anyhow!("initializing diagnostic logging: {error}"))
}

pub fn debug_mode_enabled() -> bool {
    DEBUG_MODE.load(Ordering::Relaxed)
}

pub fn set_tui_active(active: bool) {
    TUI_ACTIVE.store(active, Ordering::Relaxed);
}

pub fn recent_logs() -> Vec<String> {
    log_buffer()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .snapshot()
}

pub fn full_diagnostics_enabled() -> bool {
    FULL_DIAGNOSTICS.load(Ordering::Relaxed)
}

pub fn redact_sensitive_fields(value: &Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| {
                    let normalized = key
                        .chars()
                        .filter(char::is_ascii_alphanumeric)
                        .map(|character| character.to_ascii_lowercase())
                        .collect::<String>();
                    let value = if is_sensitive_field(&normalized) {
                        Value::String("[REDACTED]".to_owned())
                    } else {
                        redact_sensitive_fields(value)
                    };
                    (key.clone(), value)
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(redact_sensitive_fields).collect()),
        value => value.clone(),
    }
}

fn filter_level(verbosity: u8, debug: bool) -> LevelFilter {
    if debug || verbosity >= 3 {
        LevelFilter::TRACE
    } else {
        match verbosity {
            0 => LevelFilter::WARN,
            1 => LevelFilter::INFO,
            _ => LevelFilter::DEBUG,
        }
    }
}

fn full_diagnostics(verbosity: u8, debug: bool) -> bool {
    debug || verbosity >= 4
}

fn is_sensitive_field(field: &str) -> bool {
    [
        "token",
        "authorization",
        "secret",
        "password",
        "credential",
        "cookie",
        "apikey",
        "privatekey",
    ]
    .iter()
    .any(|sensitive| field.contains(sensitive))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_verbosity_increases_the_log_level() {
        assert_eq!(filter_level(0, false), LevelFilter::WARN);
        assert_eq!(filter_level(1, false), LevelFilter::INFO);
        assert_eq!(filter_level(2, false), LevelFilter::DEBUG);
        assert_eq!(filter_level(3, false), LevelFilter::TRACE);
        assert_eq!(filter_level(4, false), LevelFilter::TRACE);
        assert_eq!(filter_level(0, true), LevelFilter::TRACE);
        assert!(!full_diagnostics(3, false));
        assert!(full_diagnostics(4, false));
        assert!(full_diagnostics(0, true));
    }

    #[test]
    fn redaction_covers_sensitive_fields_recursively() {
        let value = serde_json::json!({
            "access_token": "bearer-token",
            "accessToken": "camel-token",
            "api_key": "api-key-value",
            "nested": [{
                "client-secret": "oauth-secret",
                "clientSecret": "camel-secret",
                "authorization": "Bearer another-token",
                "name": "visible"
            }]
        });

        let redacted = redact_sensitive_fields(&value);

        assert_eq!(redacted["access_token"], "[REDACTED]");
        assert_eq!(redacted["accessToken"], "[REDACTED]");
        assert_eq!(redacted["api_key"], "[REDACTED]");
        assert_eq!(redacted["nested"][0]["client-secret"], "[REDACTED]");
        assert_eq!(redacted["nested"][0]["clientSecret"], "[REDACTED]");
        assert_eq!(redacted["nested"][0]["authorization"], "[REDACTED]");
        assert_eq!(redacted["nested"][0]["name"], "visible");
    }

    #[test]
    fn log_buffer_is_bounded_and_log_fields_are_redacted() {
        let mut buffer = LogBuffer::default();
        for index in 0..=MAX_LOG_LINES {
            buffer.push(format!("event {index}"));
        }

        let logs = buffer.snapshot();
        assert_eq!(logs.len(), MAX_LOG_LINES);
        assert_eq!(logs.first().map(String::as_str), Some("event 1"));
        assert_eq!(logs.last().map(String::as_str), Some("event 200"));

        let mut visitor = LogEventVisitor::default();
        visitor.record_field("message", "request failed".to_owned());
        visitor.record_field("accessToken", "secret-value".to_owned());
        assert_eq!(visitor.message.as_deref(), Some("request failed"));
        assert_eq!(visitor.fields, vec!["accessToken=[REDACTED]"]);
    }
}
