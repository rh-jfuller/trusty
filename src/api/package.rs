use serde_json::Value;
use trustify_client::api::ClientPurlExt;

use crate::api::{ApiClient, ApiError, ListParams};

pub async fn search(client: &ApiClient, params: &ListParams) -> Result<Value, ApiError> {
    tracing::debug!(
        operation = "package.search",
        query = ?params.query,
        limit = params.limit,
        offset = params.offset,
        sort = ?params.sort,
        total = params.total,
        "Trustify API request"
    );
    let api = client.generated_api();
    let query = params.query.clone();
    let limit = params.limit;
    let offset = params.offset;
    let sort = params.sort.clone();
    let total = params.total;

    client
        .send_with_refresh(move || {
            let api = api.clone();
            let query = query.clone();
            let sort = sort.clone();
            async move {
                let mut request = api.list_purl();
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
                if total {
                    request = request.total(true);
                }
                request.send().await
            }
        })
        .await
}

pub async fn get(client: &ApiClient, key: &str) -> Result<Value, ApiError> {
    tracing::debug!(operation = "package.get", key, "Trustify API request");
    let api = client.generated_api();
    let key = key.to_owned();

    client
        .send_with_refresh(move || {
            let api = api.clone();
            let key = key.clone();
            async move { api.get_purl().key(key).send().await }
        })
        .await
}
