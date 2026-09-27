use clap::Subcommand;

use crate::{
    api::{self, ApiClient, ListResource},
    commands::{self, ListOptions, OutputOptions},
};

#[derive(Debug, Subcommand)]
pub enum ProductCommands {
    /// List products, optionally using Trustify's query syntax
    List {
        #[command(flatten)]
        options: ListOptions,

        #[command(flatten)]
        output: OutputOptions,
    },

    /// Get a product by UUID
    Get {
        /// Product UUID
        id: String,

        #[command(flatten)]
        output: OutputOptions,
    },
}

impl ProductCommands {
    pub async fn run(&self, client: &ApiClient) -> anyhow::Result<()> {
        match self {
            Self::List { options, output } => {
                commands::list_resource(client, ListResource::Product, "Products", options, output)
                    .await?;
            }
            Self::Get { id, output } => {
                let mode = output.format.resolve()?;
                let response = api::product::get(client, id).await?;
                commands::show_record(client, response, "Product", mode).await?;
            }
        }
        Ok(())
    }
}
