use serde_json::Value;

use crate::api::{ApiClient, ApiError};

#[derive(Debug, Default)]
pub struct ListParams {
    pub query: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub sort: Option<String>,
}

impl ListParams {
    fn query_pairs(&self) -> Vec<(String, String)> {
        let mut pairs = Vec::new();
        if let Some(query) = &self.query {
            pairs.push(("q".to_owned(), query.clone()));
        }
        if let Some(limit) = self.limit {
            pairs.push(("limit".to_owned(), limit.to_string()));
        }
        if let Some(offset) = self.offset {
            pairs.push(("offset".to_owned(), offset.to_string()));
        }
        if let Some(sort) = &self.sort {
            pairs.push(("sort".to_owned(), sort.clone()));
        }
        pairs
    }
}

pub async fn list(client: &ApiClient, params: &ListParams) -> Result<Value, ApiError> {
    client.get_json(&["sbom"], &params.query_pairs()).await
}

pub async fn get(client: &ApiClient, id: &str) -> Result<Value, ApiError> {
    client.get_json(&["sbom", id], &[]).await
}
