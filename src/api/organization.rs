use std::collections::HashSet;

use serde_json::Value;
use trustify_client::api::ClientOrganizationExt;

use crate::api::{ApiClient, ApiError, ListParams};

pub async fn list(client: &ApiClient, params: &ListParams) -> Result<Value, ApiError> {
    tracing::debug!(
        operation = "organization.list",
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
    let response = client
        .send_with_refresh(move || {
            let api = api.clone();
            let query = query.clone();
            let sort = sort.clone();
            async move {
                let mut request = api.list_organizations();
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
        .await?;
    let all_items_received = params.offset.unwrap_or_default() == 0
        && response
            .get("total")
            .and_then(Value::as_u64)
            .is_some_and(|total| {
                response
                    .get("items")
                    .and_then(Value::as_array)
                    .is_some_and(|items| items.len() as u64 >= total)
            });
    Ok(deduplicate_organizations(response, all_items_received))
}

fn deduplicate_organizations(mut response: Value, all_items_received: bool) -> Value {
    let Some(items) = response.get_mut("items").and_then(Value::as_array_mut) else {
        return response;
    };

    let mut ids = HashSet::new();
    let mut name_websites = HashSet::new();
    items.retain(|item| {
        if let Some(id) = item.get("id").and_then(Value::as_str) {
            if !ids.insert(id.to_owned()) {
                return false;
            }
        }

        let Some(name) = item
            .get("name")
            .and_then(Value::as_str)
            .map(normalize_name)
            .filter(|name| !name.is_empty())
        else {
            return true;
        };
        let Some(website) = item
            .get("website")
            .and_then(Value::as_str)
            .map(normalize_website)
            .filter(|website| !website.is_empty())
        else {
            return true;
        };

        name_websites.insert((name, website))
    });
    if all_items_received {
        let unique_count = items.len() as u64;
        response["total"] = Value::from(unique_count);
    }
    response
}

fn normalize_name(name: &str) -> String {
    name.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn normalize_website(website: &str) -> String {
    let website = website.trim();
    if let Ok(url) = url::Url::parse(website) {
        let host = url.host_str().unwrap_or_default().to_lowercase();
        let port = url
            .port()
            .map(|port| format!(":{port}"))
            .unwrap_or_default();
        let path = url.path().trim_end_matches('/');
        let query = url
            .query()
            .map(|query| format!("?{query}"))
            .unwrap_or_default();
        format!("{host}{port}{path}{query}")
    } else {
        website.trim_end_matches('/').to_lowercase()
    }
}

pub async fn get(client: &ApiClient, id: &str) -> Result<Value, ApiError> {
    tracing::debug!(operation = "organization.get", id, "Trustify API request");
    let api = client.generated_api();
    let id = id.to_owned();

    client
        .send_with_refresh(move || {
            let api = api.clone();
            let id = id.clone();
            async move { api.get_organization().id(id).send().await }
        })
        .await
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::deduplicate_organizations;

    #[test]
    fn list_deduplicates_normalized_name_and_website_pairs() {
        let response = deduplicate_organizations(
            json!({
                "items": [
                    {
                        "id": "org-1",
                        "name": "Example, Inc.",
                        "website": "https://EXAMPLE.com/"
                    },
                    {
                        "id": "org-2",
                        "name": " example,   INC. ",
                        "website": "http://example.com"
                    },
                    {
                        "id": "org-3",
                        "name": "Example, Inc.",
                        "website": "https://example.org"
                    },
                    {
                        "id": "org-4",
                        "name": "Other Organization",
                        "website": "https://example.com"
                    }
                ],
                "total": 4
            }),
            true,
        );

        assert_eq!(response["items"].as_array().unwrap().len(), 3);
        assert_eq!(response["total"], 3);
        assert_eq!(response["items"][0]["id"], "org-1");
        assert_eq!(response["items"][1]["id"], "org-3");
        assert_eq!(response["items"][2]["id"], "org-4");
    }

    #[test]
    fn list_deduplicates_repeated_ids_without_names_or_websites() {
        let response = deduplicate_organizations(
            json!({
                "items": [
                    {"id": "org-1"},
                    {"id": "org-1"},
                    {"id": "org-2"}
                ]
            }),
            false,
        );

        assert_eq!(response["items"].as_array().unwrap().len(), 2);
    }
}
