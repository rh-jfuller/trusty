mod advisory;
mod exploit;
mod license;
mod mcp;
mod organization;
mod package;
mod product;
mod sbom;
mod scan;
mod vulnerability;
mod weakness;

use clap::{Args, Subcommand};
use serde_json::Value;

use crate::{
    api::{self, ApiClient, ListParams, ListResource},
    output::{self, OutputFormat, OutputMode},
    settings::{AppSettings, DEFAULT_PAGE_SIZE},
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
            advisories: false,
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
    let mut settings = if mode == OutputMode::Tui {
        Some(AppSettings::load()?)
    } else {
        None
    };
    let mut params = ListParams::from(options);
    if mode == OutputMode::Tui {
        let default_page_size = settings
            .as_ref()
            .map(|settings| settings.page_size)
            .unwrap_or(DEFAULT_PAGE_SIZE);
        params.limit = Some(params.limit.unwrap_or(default_page_size).max(1));
        params.total = resource != ListResource::Sbom;
        if params.sort.is_none() {
            params.sort = settings
                .as_ref()
                .and_then(|settings| settings.default_sort(resource))
                .map(str::to_owned);
        }
        params.advisories = false;
    }
    let mut request_params = params.clone();
    if resource == ListResource::Vulnerability {
        if let Some(settings) = &settings {
            settings.apply_default_severity_filter(&mut request_params);
        }
    }
    let response = api::list_resource(client, resource, &request_params).await?;

    match mode {
        OutputMode::Json => output::print_json(&response)?,
        OutputMode::Tui => {
            let settings = settings
                .as_mut()
                .expect("TUI settings are loaded for TUI output");
            if resource == ListResource::Sbom {
                output::tui::browse_sboms(client, params, response, settings).await?;
            } else {
                output::tui::browse_records(client, resource, title, params, response, settings)
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
            let settings = AppSettings::load()?;
            output::tui::show_detail_as_on(
                title,
                response,
                &client.instance_label(),
                client,
                settings.theme,
            )
            .await?
        }
    }
    Ok(())
}

pub async fn run_entity_list(
    client: &ApiClient,
    resource: ListResource,
    counts: &output::tui::EntityCountCache,
    settings: &mut AppSettings,
) -> anyhow::Result<()> {
    let cached_total = counts.total(resource);
    let has_default_severity_filter = resource == ListResource::Vulnerability
        && settings.remember_severity_filter
        && settings.default_severity_filter().is_some();
    let page_size = settings.page_size.max(1);
    let params = ListParams {
        limit: Some(page_size),
        sort: settings.default_sort(resource).map(str::to_owned),
        total: resource != ListResource::Sbom
            && (cached_total.is_none() || has_default_severity_filter),
        advisories: false,
        ..ListParams::default()
    };
    let title = match resource {
        ListResource::Sbom => "SBOMs",
        ListResource::Advisory => "Advisories",
        ListResource::Exploit => "Exploits",
        ListResource::License => "Licenses",
        ListResource::Organization => "Organizations",
        ListResource::Package => "PURLs",
        ListResource::Product => "Products",
        ListResource::Vulnerability => "Vulnerabilities",
        ListResource::Weakness => "Weaknesses",
    };
    let mut request_params = params.clone();
    if resource == ListResource::Vulnerability {
        settings.apply_default_severity_filter(&mut request_params);
    }
    let mut response = api::list_resource(client, resource, &request_params).await?;
    if !has_default_severity_filter {
        if let Some(total) = cached_total {
            response["total"] = Value::from(total);
        } else if let Some(total) = response.get("total").and_then(Value::as_u64) {
            counts.set_total(resource, Some(total));
        }
    }

    if resource == ListResource::Sbom {
        output::tui::browse_sboms(client, params, response, settings).await
    } else {
        output::tui::browse_records(client, resource, title, params, response, settings).await
    }
}

pub(crate) async fn run_scan_tui(client: &ApiClient) -> anyhow::Result<()> {
    scan::run(client, None, scan::ScanFormat::Tui).await
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Browse and inspect SBOMs
    Sbom {
        #[command(subcommand)]
        command: sbom::SbomCommands,
    },

    /// Scan directories, SBOMs, container images, or components for vulnerabilities
    Scan {
        /// Scan target: dir:PATH, sbom:PATH, pkg:PURL, name:COMPONENT, registry:IMAGE, or oci-archive:PATH; optional with --format tui
        target: Option<String>,

        /// Output format
        #[arg(long, value_enum, default_value = "text")]
        format: scan::ScanFormat,
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
            Self::Scan { target, format } => scan::run(client, target.as_deref(), *format).await,
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
