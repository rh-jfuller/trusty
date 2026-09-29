mod client;
mod error;

pub mod advisory;
pub mod exploit;
pub mod license;
pub mod organization;
pub mod package;
pub mod product;
pub mod sbom;
pub mod vulnerability;
pub mod weakness;

pub use client::ApiClient;
pub use error::ApiError;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ListResource {
    Sbom,
    Advisory,
    Exploit,
    License,
    Organization,
    Package,
    Product,
    Vulnerability,
    Weakness,
}

#[derive(Clone, Debug, Default)]
pub struct ListParams {
    pub query: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub sort: Option<String>,
    pub total: bool,
    pub advisories: bool,
}

pub async fn list_resource(
    client: &ApiClient,
    resource: ListResource,
    params: &ListParams,
) -> Result<serde_json::Value, ApiError> {
    match resource {
        ListResource::Sbom => sbom::list(client, params).await,
        ListResource::Advisory => advisory::list(client, params).await,
        ListResource::Exploit => exploit::list(client, params).await,
        ListResource::License => license::list(client, params).await,
        ListResource::Organization => organization::list(client, params).await,
        ListResource::Package => package::search(client, params).await,
        ListResource::Product => product::list(client, params).await,
        ListResource::Vulnerability => vulnerability::list(client, params).await,
        ListResource::Weakness => weakness::list(client, params).await,
    }
}
