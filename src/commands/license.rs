use clap::Subcommand;

use crate::{
    api::{ApiClient, ListResource},
    commands::{self, ListOptions, OutputOptions},
};

#[derive(Debug, Subcommand)]
pub enum LicenseCommands {
    /// List licenses found in SBOMs
    List {
        #[command(flatten)]
        options: ListOptions,

        #[command(flatten)]
        output: OutputOptions,
    },
}

impl LicenseCommands {
    pub async fn run(&self, client: &ApiClient) -> anyhow::Result<()> {
        match self {
            Self::List { options, output } => {
                commands::list_resource(client, ListResource::License, "Licenses", options, output)
                    .await?;
            }
        }
        Ok(())
    }
}
