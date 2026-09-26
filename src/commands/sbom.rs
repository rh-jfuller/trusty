use clap::Subcommand;

use crate::api::{sbom as sbom_api, ApiClient};

#[derive(Debug, Subcommand)]
pub enum SbomCommands {
    /// List SBOMs, optionally using Trustify's query syntax
    List {
        /// Trustify query expression (for example: `name~openssl`)
        #[arg(short, long)]
        query: Option<String>,

        /// Maximum number of results
        #[arg(long)]
        limit: Option<u32>,

        /// Number of results to skip
        #[arg(long)]
        offset: Option<u32>,

        /// Result sort expression
        #[arg(long)]
        sort: Option<String>,
    },

    /// Get an SBOM by ID
    Get {
        /// SBOM identifier
        id: String,
    },
}

impl SbomCommands {
    pub async fn run(&self, client: &ApiClient) -> anyhow::Result<()> {
        let response = match self {
            Self::List {
                query,
                limit,
                offset,
                sort,
            } => {
                sbom_api::list(
                    client,
                    &sbom_api::ListParams {
                        query: query.clone(),
                        limit: *limit,
                        offset: *offset,
                        sort: sort.clone(),
                    },
                )
                .await?
            }
            Self::Get { id } => sbom_api::get(client, id).await?,
        };

        println!("{}", serde_json::to_string_pretty(&response)?);
        Ok(())
    }
}
