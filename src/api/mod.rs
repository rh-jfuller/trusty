mod client;
mod error;

pub mod advisory;
pub mod license;
pub mod package;
pub mod sbom;
pub mod vulnerability;

pub use client::ApiClient;
pub use error::ApiError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListResource {
    Sbom,
    Advisory,
    License,
    Package,
    Vulnerability,
}

#[derive(Debug, Default)]
pub struct ListParams {
    pub query: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub sort: Option<String>,
}

pub async fn list_resource(
    client: &ApiClient,
    resource: ListResource,
    params: &ListParams,
) -> Result<serde_json::Value, ApiError> {
    match resource {
        ListResource::Sbom => sbom::list(client, params).await,
        ListResource::Advisory => advisory::list(client, params).await,
        ListResource::License => license::list(client, params).await,
        ListResource::Package => package::search(client, params).await,
        ListResource::Vulnerability => vulnerability::list(client, params).await,
    }
}
