use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, ContentBlock},
    tool, tool_handler, tool_router,
    transport::stdio,
    ServerHandler, ServiceExt,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

use crate::api::{self, ApiClient, ApiError, ListParams};

#[derive(Debug, Deserialize, JsonSchema)]
struct ListArgs {
    /// Trustify query expression, for example `name~openssl`.
    query: Option<String>,
    /// Maximum number of results to return.
    limit: Option<u32>,
    /// Number of results to skip.
    offset: Option<u32>,
    /// Trustify sort expression.
    sort: Option<String>,
}

impl From<ListArgs> for ListParams {
    fn from(args: ListArgs) -> Self {
        Self {
            query: args.query,
            limit: args.limit,
            offset: args.offset,
            sort: args.sort,
            total: false,
            advisories: false,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
struct IdArgs {
    /// Resource identifier.
    id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct KeyArgs {
    /// Advisory key, such as a UUID or document digest.
    key: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct VulnerabilityArgs {
    /// Vulnerability identifier, such as a CVE ID.
    id: String,
    /// Include contributing-advisory score details.
    scores: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct PurlArgs {
    /// Full Package URL or opaque PURL identifier.
    key: String,
}

struct TrustyMcp {
    client: ApiClient,
}

impl TrustyMcp {
    fn new(client: ApiClient) -> Self {
        Self { client }
    }

    fn tool_result(result: Result<Value, ApiError>) -> CallToolResult {
        match result {
            Ok(value) => {
                let text =
                    serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
                CallToolResult::success(vec![ContentBlock::text(text)])
            }
            Err(error) => CallToolResult::error(vec![ContentBlock::text(error.to_string())]),
        }
    }
}

#[tool_router]
impl TrustyMcp {
    #[tool(
        description = "List SBOMs. Supports Trustify query, pagination, and sorting.",
        annotations(read_only_hint = true)
    )]
    async fn list_sboms(&self, Parameters(args): Parameters<ListArgs>) -> CallToolResult {
        let params = ListParams::from(args);
        Self::tool_result(api::sbom::list(&self.client, &params).await)
    }

    #[tool(
        description = "Get an SBOM by its identifier.",
        annotations(read_only_hint = true)
    )]
    async fn get_sbom(&self, Parameters(args): Parameters<IdArgs>) -> CallToolResult {
        Self::tool_result(api::sbom::get(&self.client, &args.id).await)
    }

    #[tool(
        description = "List security advisories. Supports Trustify query, pagination, and sorting.",
        annotations(read_only_hint = true)
    )]
    async fn list_advisories(&self, Parameters(args): Parameters<ListArgs>) -> CallToolResult {
        let params = ListParams::from(args);
        Self::tool_result(api::advisory::list(&self.client, &params).await)
    }

    #[tool(
        description = "Get an advisory by its UUID, document ID, or digest.",
        annotations(read_only_hint = true)
    )]
    async fn get_advisory(&self, Parameters(args): Parameters<KeyArgs>) -> CallToolResult {
        Self::tool_result(api::advisory::get(&self.client, &args.key).await)
    }

    #[tool(
        description = "List known exploits. Supports Trustify query, pagination, and sorting.",
        annotations(read_only_hint = true)
    )]
    async fn list_exploits(&self, Parameters(args): Parameters<ListArgs>) -> CallToolResult {
        let params = ListParams::from(args);
        Self::tool_result(api::exploit::list(&self.client, &params).await)
    }

    #[tool(
        description = "Get an exploit by its identifier.",
        annotations(read_only_hint = true)
    )]
    async fn get_exploit(&self, Parameters(args): Parameters<IdArgs>) -> CallToolResult {
        Self::tool_result(api::exploit::get(&self.client, &args.id).await)
    }

    #[tool(
        description = "List vulnerabilities. Supports Trustify query, pagination, and sorting.",
        annotations(read_only_hint = true)
    )]
    async fn list_vulnerabilities(&self, Parameters(args): Parameters<ListArgs>) -> CallToolResult {
        let params = ListParams::from(args);
        Self::tool_result(api::vulnerability::list(&self.client, &params).await)
    }

    #[tool(
        description = "Get a vulnerability by CVE or other identifier; optionally include contributing-advisory scores.",
        annotations(read_only_hint = true)
    )]
    async fn get_vulnerability(
        &self,
        Parameters(args): Parameters<VulnerabilityArgs>,
    ) -> CallToolResult {
        Self::tool_result(
            api::vulnerability::get(&self.client, &args.id, args.scores.unwrap_or(false)).await,
        )
    }

    #[tool(
        description = "Search Package URLs. Supports Trustify query, pagination, and sorting.",
        annotations(read_only_hint = true)
    )]
    async fn search_packages(&self, Parameters(args): Parameters<ListArgs>) -> CallToolResult {
        let params = ListParams::from(args);
        Self::tool_result(api::package::search(&self.client, &params).await)
    }

    #[tool(
        description = "Get details for a Package URL or opaque PURL identifier.",
        annotations(read_only_hint = true)
    )]
    async fn get_package(&self, Parameters(args): Parameters<PurlArgs>) -> CallToolResult {
        Self::tool_result(api::package::get(&self.client, &args.key).await)
    }

    #[tool(
        description = "List licenses. Supports Trustify query, pagination, and sorting.",
        annotations(read_only_hint = true)
    )]
    async fn list_licenses(&self, Parameters(args): Parameters<ListArgs>) -> CallToolResult {
        let params = ListParams::from(args);
        Self::tool_result(api::license::list(&self.client, &params).await)
    }

    #[tool(
        description = "List organizations. Supports Trustify query, pagination, and sorting.",
        annotations(read_only_hint = true)
    )]
    async fn list_organizations(&self, Parameters(args): Parameters<ListArgs>) -> CallToolResult {
        let params = ListParams::from(args);
        Self::tool_result(api::organization::list(&self.client, &params).await)
    }

    #[tool(
        description = "Get an organization by UUID.",
        annotations(read_only_hint = true)
    )]
    async fn get_organization(&self, Parameters(args): Parameters<IdArgs>) -> CallToolResult {
        Self::tool_result(api::organization::get(&self.client, &args.id).await)
    }

    #[tool(
        description = "List products. Supports Trustify query, pagination, and sorting.",
        annotations(read_only_hint = true)
    )]
    async fn list_products(&self, Parameters(args): Parameters<ListArgs>) -> CallToolResult {
        let params = ListParams::from(args);
        Self::tool_result(api::product::list(&self.client, &params).await)
    }

    #[tool(
        description = "Get a product by UUID.",
        annotations(read_only_hint = true)
    )]
    async fn get_product(&self, Parameters(args): Parameters<IdArgs>) -> CallToolResult {
        Self::tool_result(api::product::get(&self.client, &args.id).await)
    }

    #[tool(
        description = "List weaknesses. Supports Trustify query, pagination, and sorting.",
        annotations(read_only_hint = true)
    )]
    async fn list_weaknesses(&self, Parameters(args): Parameters<ListArgs>) -> CallToolResult {
        let params = ListParams::from(args);
        Self::tool_result(api::weakness::list(&self.client, &params).await)
    }

    #[tool(
        description = "Get a weakness by its identifier, such as a CWE ID.",
        annotations(read_only_hint = true)
    )]
    async fn get_weakness(&self, Parameters(args): Parameters<IdArgs>) -> CallToolResult {
        Self::tool_result(api::weakness::get(&self.client, &args.id).await)
    }
}

#[tool_handler(
    name = "trusty",
    instructions = "Read-only tools for searching and retrieving data from a Trustify instance."
)]
impl ServerHandler for TrustyMcp {}

pub async fn run(client: ApiClient) -> anyhow::Result<()> {
    let service = TrustyMcp::new(client).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_tools_for_all_supported_resources() {
        let router = TrustyMcp::tool_router();

        for name in [
            "list_sboms",
            "get_sbom",
            "list_advisories",
            "get_advisory",
            "list_exploits",
            "get_exploit",
            "list_vulnerabilities",
            "get_vulnerability",
            "search_packages",
            "get_package",
            "list_licenses",
            "list_products",
            "get_product",
            "list_weaknesses",
            "get_weakness",
            "list_organizations",
            "get_organization",
        ] {
            assert!(router.map.contains_key(name), "missing MCP tool: {name}");
        }
    }
}
