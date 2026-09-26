use clap::Subcommand;

use crate::api::{sbom as sbom_api, ApiClient};
use crate::output::{self, OutputFormat, OutputMode};

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

        /// Output mode: auto selects the TUI for a terminal and JSON when piped
        #[arg(long, value_enum, default_value = "auto")]
        format: OutputFormat,
    },

    /// Get an SBOM by ID
    Get {
        /// SBOM identifier
        id: String,

        /// Output mode: auto selects the TUI for a terminal and JSON when piped
        #[arg(long, value_enum, default_value = "auto")]
        format: OutputFormat,
    },
}

impl SbomCommands {
    pub async fn run(&self, client: &ApiClient) -> anyhow::Result<()> {
        match self {
            Self::List {
                query,
                limit,
                offset,
                sort,
                format,
            } => {
                let mode = format.resolve()?;
                let params = sbom_api::ListParams {
                    query: query.clone(),
                    limit: *limit,
                    offset: *offset,
                    sort: sort.clone(),
                };
                match mode {
                    OutputMode::Json => {
                        let response = sbom_api::list(client, &params).await?;
                        output::print_json(&response)?;
                    }
                    OutputMode::Tui => {
                        let page_size = params.limit.unwrap_or(20).max(1);
                        let params = sbom_api::ListParams {
                            limit: Some(page_size),
                            ..params
                        };
                        let response = sbom_api::list(client, &params).await?;
                        output::tui::browse_sboms(client, params, response).await?;
                    }
                }
                Ok(())
            }
            Self::Get { id, format } => {
                let mode = format.resolve()?;
                let response = sbom_api::get(client, id).await?;
                match mode {
                    OutputMode::Json => output::print_json(&response)?,
                    OutputMode::Tui => output::tui::show_detail(response).await?,
                }
                Ok(())
            }
        }
    }
}
