use clap::Subcommand;

use crate::{
    api::{self, ApiClient, ListResource},
    commands::{self, ListOptions, OutputOptions},
};

#[derive(Debug, Subcommand)]
pub enum PackageCommands {
    /// Search packages by name, Package URL, CPE, or Trustify query
    Search {
        #[command(flatten)]
        options: ListOptions,

        #[command(flatten)]
        output: OutputOptions,
    },

    /// Get package details by name, Package URL, or CPE
    Get {
        /// Package name, Package URL, or CPE
        key: String,

        #[command(flatten)]
        output: OutputOptions,
    },
}

impl PackageCommands {
    pub async fn run(&self, client: &ApiClient) -> anyhow::Result<()> {
        match self {
            Self::Search { options, output } => {
                commands::list_resource(client, ListResource::Package, "Packages", options, output)
                    .await?;
            }
            Self::Get { key, output } => {
                let mode = output.format.resolve()?;
                let response = api::package::get(client, key).await?;
                commands::show_record(response, "Package", mode).await?;
            }
        }
        Ok(())
    }
}
