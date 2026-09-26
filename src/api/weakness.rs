use serde_json::Value;

use crate::api::{ApiClient, ApiError, ListParams};

// trustify-client 0.1.1 models these as PaginatedResultsLicenseSummary and
// LicenseSummary, while Trustify returns WeaknessSummary and WeaknessDetails.
// Use the authenticated raw JSON path until its OpenAPI response types are fixed.
pub async fn list(client: &ApiClient, params: &ListParams) -> Result<Value, ApiError> {
    tracing::debug!(
        operation = "weakness.list",
        query = ?params.query,
        limit = params.limit,
        offset = params.offset,
        sort = ?params.sort,
        total = params.total,
        "Trustify API request"
    );
    let mut query = Vec::with_capacity(4);
    if let Some(value) = params.query.as_deref() {
        query.push(("q", value.to_owned()));
    }
    if let Some(value) = params.limit {
        query.push(("limit", value.to_string()));
    }
    if let Some(value) = params.offset {
        query.push(("offset", value.to_string()));
    }
    if let Some(value) = params.sort.as_deref() {
        query.push(("sort", value.to_owned()));
    }
    if params.total {
        query.push(("total", "true".to_owned()));
    }

    client
        .raw_api_get("weakness.list", &["weakness"], &query)
        .await
}

pub async fn get(client: &ApiClient, id: &str) -> Result<Value, ApiError> {
    tracing::debug!(operation = "weakness.get", id, "Trustify API request");
    client
        .raw_api_get("weakness.get", &["weakness", id], &[])
        .await
}
