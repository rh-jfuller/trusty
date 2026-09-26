use clap::Subcommand;

use crate::{
    api::{self, ApiClient, ListResource},
    commands::{self, ListOptions, OutputOptions},
};

#[derive(Debug, Subcommand)]
pub enum AdvisoryCommands {
    /// List advisories, optionally using Trustify's query syntax
    List {
        #[command(flatten)]
        options: ListOptions,

        #[command(flatten)]
        output: OutputOptions,
    },

    /// Get an advisory by key
    Get {
        /// Advisory key, such as a UUID or document digest
        key: String,

        #[command(flatten)]
        output: OutputOptions,
    },
}

impl AdvisoryCommands {
    pub async fn run(&self, client: &ApiClient) -> anyhow::Result<()> {
        match self {
            Self::List { options, output } => {
                commands::list_resource(
                    client,
                    ListResource::Advisory,
                    "Advisories",
                    options,
                    output,
                )
                .await?;
            }
            Self::Get { key, output } => {
                let mode = output.format.resolve()?;
                let response = api::advisory::get(client, key).await?;
                commands::show_record(client, response, "Advisory", mode).await?;
            }
        }
        Ok(())
    }
}
