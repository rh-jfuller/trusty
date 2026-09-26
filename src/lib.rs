pub mod api;
pub mod cli;
pub mod commands;
pub mod config;
pub mod logging;
pub mod output;

use clap::Parser;
use std::process::ExitCode;

use crate::{
    api::ApiClient,
    cli::Cli,
    config::Config,
    output::{OutputFormat, OutputMode},
};

pub async fn run() -> anyhow::Result<ExitCode> {
    let cli = Cli::parse();
    logging::init(cli.verbosity, cli.debug)?;
    tracing::info!("starting trusty");
    if let Some(command) = &cli.command {
        let client = ApiClient::new(&cli.config).await?;
        command.run(&client).await?;
    } else if OutputFormat::Auto.resolve()? == OutputMode::Tui {
        run_entity_menu(&cli.config).await?;
    } else {
        Cli::print_help()?;
    }

    Ok(ExitCode::SUCCESS)
}

async fn run_entity_menu(config: &Config) -> anyhow::Result<()> {
    let mut client = None;
    let mut selected = 0;
    while let Some((resource, new_selection)) = output::tui::main_menu(selected).await? {
        selected = new_selection;
        if client.is_none() {
            client = Some(ApiClient::new(config).await?);
        }
        if let Some(client) = &client {
            commands::run_entity_list(client, resource).await?;
        }
    }
    Ok(())
}
