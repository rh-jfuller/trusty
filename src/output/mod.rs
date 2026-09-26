mod json;
pub mod tui;

use std::io::{stdin, stdout, IsTerminal};

use anyhow::bail;
use clap::ValueEnum;
use serde_json::Value;

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum OutputFormat {
    /// Use the TUI in a terminal and JSON when piped
    #[default]
    Auto,
    /// Emit raw JSON for scripts and other tools
    Json,
    /// Force the interactive terminal UI
    Tui,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputMode {
    Json,
    Tui,
}

impl OutputFormat {
    pub fn resolve(self) -> anyhow::Result<OutputMode> {
        match self {
            Self::Json => Ok(OutputMode::Json),
            Self::Tui if stdin().is_terminal() && stdout().is_terminal() => Ok(OutputMode::Tui),
            Self::Tui => bail!("TUI output requires an interactive terminal; use --format json"),
            Self::Auto if stdin().is_terminal() && stdout().is_terminal() => Ok(OutputMode::Tui),
            Self::Auto => Ok(OutputMode::Json),
        }
    }
}

pub fn print_json(value: &Value) -> anyhow::Result<()> {
    json::print(value)
}
