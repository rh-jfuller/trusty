pub use crate::api::ListParams;

use serde_json::Value;
use trustify_client::api::ClientSbomExt;

use crate::api::{ApiClient, ApiError};

pub async fn list(client: &ApiClient, params: &ListParams) -> Result<serde_json::Value, ApiError> {
    client.list_sboms(params).await
}

pub async fn get(client: &ApiClient, id: &str) -> Result<serde_json::Value, ApiError> {
    client.get_sbom(id).await
}

pub async fn advisories(client: &ApiClient, id: &str) -> Result<Value, ApiError> {
    tracing::debug!(operation = "sbom.advisories", id, "Trustify API request");
    let api = client.generated_api();
    let id = id.to_owned();

    client
        .send_with_refresh(move || {
            let api = api.clone();
            let id = id.clone();
            async move { api.get_sbom_advisories().id(id).send().await }
        })
        .await
}

pub async fn packages(
    client: &ApiClient,
    id: &str,
    params: &ListParams,
) -> Result<Value, ApiError> {
    tracing::debug!(
        operation = "sbom.packages",
        id,
        limit = params.limit,
        offset = params.offset,
        total = params.total,
        "Trustify API request"
    );
    let api = client.generated_api();
    let id = id.to_owned();
    let limit = params.limit;
    let offset = params.offset;
    let total = params.total;

    client
        .send_with_refresh(move || {
            let api = api.clone();
            let id = id.clone();
            async move {
                let mut request = api.list_packages().id(id);
                if let Some(limit) = limit {
                    request = request.limit(i64::from(limit));
                }
                if let Some(offset) = offset {
                    request = request.offset(i64::from(offset));
                }
                if total {
                    request = request.total(true);
                }
                request.send().await
            }
        })
        .await
}
