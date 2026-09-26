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
    let client = ApiClient::new(config).await?;
    let counts = output::tui::EntityCountCache::default();
    let mut selected = 0;
    let mut theme = output::tui::ThemeMode::default();
    let instance_label = ApiClient::configured_instance_label(&config.url);
    while let Some((resource, new_selection)) =
        output::tui::main_menu(selected, &instance_label, &client, &counts, &mut theme).await?
    {
        selected = new_selection;
        commands::run_entity_list(&client, resource, &counts, theme).await?;
    }
    Ok(())
}
