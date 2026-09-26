mod advisory;
mod exploit;
mod license;
mod mcp;
mod organization;
mod package;
mod product;
mod sbom;
mod vulnerability;
mod weakness;

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
            total: false,
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
        params.total = true;
    }
    let response = api::list_resource(client, resource, &params).await?;

    match mode {
        OutputMode::Json => output::print_json(&response)?,
        OutputMode::Tui => {
            if resource == ListResource::Sbom {
                output::tui::browse_sboms(
                    client,
                    params,
                    response,
                    output::tui::ThemeMode::default(),
                )
                .await?;
            } else {
                output::tui::browse_records(
                    client,
                    resource,
                    title,
                    params,
                    response,
                    output::tui::ThemeMode::default(),
                )
                .await?;
            }
        }
    }
    Ok(())
}

pub async fn show_record(
    client: &ApiClient,
    response: Value,
    title: &str,
    mode: OutputMode,
) -> anyhow::Result<()> {
    match mode {
        OutputMode::Json => output::print_json(&response)?,
        OutputMode::Tui => {
            output::tui::show_detail_as_on(title, response, &client.instance_label(), client)
                .await?
        }
    }
    Ok(())
}

pub async fn run_entity_list(
    client: &ApiClient,
    resource: ListResource,
    counts: &output::tui::EntityCountCache,
    theme: output::tui::ThemeMode,
) -> anyhow::Result<()> {
    let cached_total = counts.total(resource);
    let page_size = 20;
    let params = ListParams {
        limit: Some(page_size),
        total: cached_total.is_none(),
        ..ListParams::default()
    };
    let title = match resource {
        ListResource::Sbom => "SBOMs",
        ListResource::Advisory => "Advisories",
        ListResource::Exploit => "Exploits",
        ListResource::License => "Licenses",
        ListResource::Organization => "Organizations",
        ListResource::Package => "Packages",
        ListResource::Product => "Products",
        ListResource::Vulnerability => "Vulnerabilities",
        ListResource::Weakness => "Weaknesses",
    };
    let mut response = api::list_resource(client, resource, &params).await?;
    if let Some(total) = cached_total {
        response["total"] = Value::from(total);
    } else if let Some(total) = response.get("total").and_then(Value::as_u64) {
        counts.set_total(resource, Some(total));
    }

    if resource == ListResource::Sbom {
        output::tui::browse_sboms(client, params, response, theme).await
    } else {
        output::tui::browse_records(client, resource, title, params, response, theme).await
    }
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

    /// Browse and inspect known exploits
    Exploit {
        #[command(subcommand)]
        command: exploit::ExploitCommands,
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

    /// Browse and inspect products
    Product {
        #[command(subcommand)]
        command: product::ProductCommands,
    },

    /// Browse and inspect organizations
    Organization {
        #[command(subcommand)]
        command: organization::OrganizationCommands,
    },

    /// Browse and inspect weaknesses
    Weakness {
        #[command(subcommand)]
        command: weakness::WeaknessCommands,
    },

    /// Run the Trusty MCP server over standard input/output
    Mcp,
}

impl Commands {
    pub async fn run(&self, client: &ApiClient) -> anyhow::Result<()> {
        match self {
            Self::Sbom { command } => command.run(client).await,
            Self::Vuln { command } => command.run(client).await,
            Self::Advisory { command } => command.run(client).await,
            Self::Exploit { command } => command.run(client).await,
            Self::License { command } => command.run(client).await,
            Self::Package { command } => command.run(client).await,
            Self::Product { command } => command.run(client).await,
            Self::Organization { command } => command.run(client).await,
            Self::Weakness { command } => command.run(client).await,
            Self::Mcp => mcp::run(client.clone()).await,
        }
    }
}
