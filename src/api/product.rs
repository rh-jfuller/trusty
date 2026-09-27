use serde_json::Value;
use trustify_client::api::ClientProductExt;

use crate::api::{ApiClient, ApiError, ListParams};

pub async fn list(client: &ApiClient, params: &ListParams) -> Result<Value, ApiError> {
    tracing::debug!(
        operation = "product.list",
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
                let mut request = api.list_products();
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

pub async fn get(client: &ApiClient, id: &str) -> Result<Value, ApiError> {
    tracing::debug!(operation = "product.get", id, "Trustify API request");
    let api = client.generated_api();
    let id = id.to_owned();

    client
        .send_with_refresh(move || {
            let api = api.clone();
            let id = id.clone();
            async move { api.get_product().id(id).send().await }
        })
        .await
}
