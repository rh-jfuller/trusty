pub use crate::api::ListParams;

use crate::api::{ApiClient, ApiError};

pub async fn list(client: &ApiClient, params: &ListParams) -> Result<serde_json::Value, ApiError> {
    client.list_sboms(params).await
}

pub async fn get(client: &ApiClient, id: &str) -> Result<serde_json::Value, ApiError> {
    client.get_sbom(id).await
}
