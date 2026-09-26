pub mod api;
pub mod cli;
pub mod commands;
pub mod config;
pub mod output;

use clap::Parser;
use std::process::ExitCode;

use crate::{api::ApiClient, cli::Cli};

pub async fn run() -> anyhow::Result<ExitCode> {
    let cli = Cli::parse();
    let client = ApiClient::new(&cli.config).await?;
    cli.command.run(&client).await?;
    Ok(ExitCode::SUCCESS)
}
