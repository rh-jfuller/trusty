use serde_json::Value;
use trustify_client::api::ClientAdvisoryExt;

use crate::api::{ApiClient, ApiError, ListParams};

pub async fn list(client: &ApiClient, params: &ListParams) -> Result<Value, ApiError> {
    tracing::debug!(
        operation = "advisory.list",
        query = ?params.query,
        limit = params.limit,
        offset = params.offset,
        sort = ?params.sort,
        "Trustify API request"
    );
    let api = client.generated_api();
    let query = params.query.clone();
    let limit = params.limit;
    let offset = params.offset;
    let sort = params.sort.clone();

    client
        .send_with_refresh(move || {
            let api = api.clone();
            let query = query.clone();
            let sort = sort.clone();
            async move {
                let mut request = api.list_advisories();
                if let Some(query) = query {
                    request = request.q(query);
                }
                if let Some(limit) = limit {
                    request = request.limit(i64::from(limit));
                }
                if let Some(offset) = offset {
                    request = request.offset(i64::from(offset));
                }
                if let Some(sort) = sort {
                    request = request.sort(sort);
                }
                request.send().await
            }
        })
        .await
}

pub async fn get(client: &ApiClient, key: &str) -> Result<Value, ApiError> {
    tracing::debug!(operation = "advisory.get", key, "Trustify API request");
    let api = client.generated_api();
    let key = key.to_owned();

    client
        .send_with_refresh(move || {
            let api = api.clone();
            let key = key.clone();
            async move { api.get_advisory().key(key).send().await }
        })
        .await
}
