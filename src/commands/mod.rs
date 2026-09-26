mod advisory;
mod license;
mod package;
mod sbom;
mod vulnerability;

use clap::{Args, Subcommand};
use serde_json::Value;

use crate::{
    api::{self, ApiClient, ListParams, ListResource},
    output::{self, OutputFormat, OutputMode},
};

#[derive(Clone, Debug, Default, Args)]
pub struct ListOptions {
    /// Trustify query expression
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
}

impl From<&ListOptions> for ListParams {
    fn from(options: &ListOptions) -> Self {
        Self {
            query: options.query.clone(),
            limit: options.limit,
            offset: options.offset,
            sort: options.sort.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
pub struct OutputOptions {
    /// Output mode: auto selects the TUI for a terminal and JSON when piped
    #[arg(long, value_enum, default_value = "auto")]
    pub format: OutputFormat,
}

pub async fn list_resource(
    client: &ApiClient,
    resource: ListResource,
    title: &str,
    options: &ListOptions,
    output_options: &OutputOptions,
) -> anyhow::Result<()> {
    let mode = output_options.format.resolve()?;
    let mut params = ListParams::from(options);
    if mode == OutputMode::Tui {
        params.limit = Some(params.limit.unwrap_or(20).max(1));
    }
    let response = api::list_resource(client, resource, &params).await?;

    match mode {
        OutputMode::Json => output::print_json(&response)?,
        OutputMode::Tui => {
            if resource == ListResource::Sbom {
                output::tui::browse_sboms(client, params, response).await?;
            } else {
                output::tui::browse_records(client, resource, title, params, response).await?;
            }
        }
    }
    Ok(())
}

pub async fn show_record(response: Value, title: &str, mode: OutputMode) -> anyhow::Result<()> {
    match mode {
        OutputMode::Json => output::print_json(&response)?,
        OutputMode::Tui => output::tui::show_detail_as(title, response).await?,
    }
    Ok(())
}

pub async fn run_entity_list(client: &ApiClient, resource: ListResource) -> anyhow::Result<()> {
    let options = ListOptions::default();
    let output_options = OutputOptions {
        format: OutputFormat::Tui,
    };
    let title = match resource {
        ListResource::Sbom => "SBOMs",
        ListResource::Advisory => "Advisories",
        ListResource::License => "Licenses",
        ListResource::Package => "Packages",
        ListResource::Vulnerability => "Vulnerabilities",
    };
    list_resource(client, resource, title, &options, &output_options).await
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Browse and inspect SBOMs
    Sbom {
        #[command(subcommand)]
        command: sbom::SbomCommands,
    },

    /// Browse and inspect vulnerabilities
    #[command(visible_alias = "vulnerability")]
    Vuln {
        #[command(subcommand)]
        command: vulnerability::VulnerabilityCommands,
    },

    /// Browse and inspect security advisories
    Advisory {
        #[command(subcommand)]
        command: advisory::AdvisoryCommands,
    },

    /// Browse licenses found in SBOMs
    License {
        #[command(subcommand)]
        command: license::LicenseCommands,
    },

    /// Search and inspect software packages/components
    #[command(visible_alias = "component")]
    Package {
        #[command(subcommand)]
        command: package::PackageCommands,
    },
}

impl Commands {
    pub async fn run(&self, client: &ApiClient) -> anyhow::Result<()> {
        match self {
            Self::Sbom { command } => command.run(client).await,
            Self::Vuln { command } => command.run(client).await,
            Self::Advisory { command } => command.run(client).await,
            Self::License { command } => command.run(client).await,
            Self::Package { command } => command.run(client).await,
        }
    }
}
