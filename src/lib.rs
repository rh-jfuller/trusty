pub mod api;
pub mod cli;
pub mod commands;
pub mod config;
pub mod logging;
pub mod output;
pub mod settings;

use clap::Parser;
use std::process::ExitCode;
use tokio::sync::watch;

use crate::{
    api::ApiClient,
    cli::Cli,
    config::Config,
    output::{OutputFormat, OutputMode},
    settings::AppSettings,
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
    let mut settings = AppSettings::load()?;
    let (client_sender, mut client_updates) = watch::channel(None::<Result<ApiClient, String>>);
    let config_for_client = config.clone();
    let client_initializer = client_sender.clone();
    tokio::spawn(async move {
        let client = ApiClient::new(&config_for_client)
            .await
            .map_err(|error| error.to_string());
        client_initializer.send_replace(Some(client));
    });
    let counts = output::tui::EntityCountCache::default();
    let mut selected = 0;
    let instance_label = ApiClient::configured_instance_label(&config.url);
    while let Some((resource, new_selection)) = output::tui::main_menu(
        selected,
        &instance_label,
        &mut client_updates,
        &counts,
        &mut settings,
    )
    .await?
    {
        selected = new_selection;
        let client = loop {
            if let Some(result) = client_updates.borrow().clone() {
                break result.map_err(anyhow::Error::msg)?;
            }
            client_updates.changed().await.map_err(|_| {
                anyhow::anyhow!("API client initialization task ended unexpectedly")
            })?;
        };
        commands::run_entity_list(&client, resource, &counts, &settings).await?;
    }
    drop(client_sender);
    Ok(())
}
