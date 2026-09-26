use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::Value;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

static FULL_DIAGNOSTICS: AtomicBool = AtomicBool::new(false);

pub fn init(verbosity: u8, debug: bool) -> anyhow::Result<()> {
    let filter_level = filter_level(verbosity, debug);
    FULL_DIAGNOSTICS.store(full_diagnostics(verbosity, debug), Ordering::Relaxed);

    let filter = EnvFilter::default()
        .add_directive(LevelFilter::OFF.into())
        .add_directive(format!("trusty_cli={filter_level}").parse()?);

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init()
        .map_err(|error| anyhow::anyhow!("initializing diagnostic logging: {error}"))
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
}
