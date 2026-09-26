use clap::Subcommand;

use crate::{
    api::{self, ApiClient, ListResource},
    commands::{self, ListOptions, OutputOptions},
};

#[derive(Debug, Subcommand)]
pub enum WeaknessCommands {
    /// List weaknesses, optionally using Trustify's query syntax
    List {
        #[command(flatten)]
        options: ListOptions,

        #[command(flatten)]
        output: OutputOptions,
    },

    /// Get a weakness by its identifier, such as a CWE ID
    Get {
        /// Weakness identifier, such as a CWE ID
        id: String,

        #[command(flatten)]
        output: OutputOptions,
    },
}

impl WeaknessCommands {
    pub async fn run(&self, client: &ApiClient) -> anyhow::Result<()> {
        match self {
            Self::List { options, output } => {
                commands::list_resource(
                    client,
                    ListResource::Weakness,
                    "Weaknesses",
                    options,
                    output,
                )
                .await?;
            }
            Self::Get { id, output } => {
                let mode = output.format.resolve()?;
                let response = api::weakness::get(client, id).await?;
                commands::show_record(client, response, "Weakness", mode).await?;
            }
        }
        Ok(())
    }
}
