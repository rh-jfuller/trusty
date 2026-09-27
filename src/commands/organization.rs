use clap::Subcommand;

use crate::{
    api::{self, ApiClient, ListResource},
    commands::{self, ListOptions, OutputOptions},
};

#[derive(Debug, Subcommand)]
pub enum OrganizationCommands {
    /// List organizations, optionally using Trustify's query syntax
    List {
        #[command(flatten)]
        options: ListOptions,

        #[command(flatten)]
        output: OutputOptions,
    },

    /// Get an organization by UUID
    Get {
        /// Organization UUID
        id: String,

        #[command(flatten)]
        output: OutputOptions,
    },
}

impl OrganizationCommands {
    pub async fn run(&self, client: &ApiClient) -> anyhow::Result<()> {
        match self {
            Self::List { options, output } => {
                commands::list_resource(
                    client,
                    ListResource::Organization,
                    "Organizations",
                    options,
                    output,
                )
                .await?;
            }
            Self::Get { id, output } => {
                let mode = output.format.resolve()?;
                let response = api::organization::get(client, id).await?;
                commands::show_record(client, response, "Organization", mode).await?;
            }
        }
        Ok(())
    }
}
