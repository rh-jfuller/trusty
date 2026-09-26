use crate::api::{ApiClient, ApiError};

#[derive(Debug, Default)]
pub struct ListParams {
    pub query: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub sort: Option<String>,
}

pub async fn list(client: &ApiClient, params: &ListParams) -> Result<serde_json::Value, ApiError> {
    client.list_sboms(params).await
}

pub async fn get(client: &ApiClient, id: &str) -> Result<serde_json::Value, ApiError> {
    client.get_sbom(id).await
}
