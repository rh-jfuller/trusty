use std::{future::Future, sync::Arc, time::Duration, time::Instant};

use reqwest::{Client, StatusCode, Url};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::RwLock;
use trustify_client::{
    api::{ClientSbomExt, Error as TrustifyError, ResponseValue},
    AccessTokenProvider, RetryPolicy, TrustifyClient,
};

use crate::{
    api::{sbom::ListParams, ApiError},
    config::Config,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
enum TokenEndpointAuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
}

#[derive(Clone)]
struct OAuthCredentials {
    token_endpoint: Url,
    auth_method: TokenEndpointAuthMethod,
    client_id: String,
    client_secret: String,
}

#[derive(Clone)]
struct SharedTokenProvider(Arc<RwLock<Option<String>>>);

#[async_trait::async_trait]
impl AccessTokenProvider for SharedTokenProvider {
    async fn access_token(&self) -> Result<Option<String>, String> {
        Ok(self.0.read().await.clone())
    }
}

#[derive(Clone)]
pub struct ApiClient {
    http: Client,
    client: TrustifyClient,
    api_url: Url,
    token: Option<Arc<RwLock<Option<String>>>>,
    oauth: Option<OAuthCredentials>,
}

impl ApiClient {
    pub fn configured_instance_label(url: &str) -> String {
        let Ok(mut url) = Url::parse(url) else {
            return "(invalid URL)".to_owned();
        };
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return "(invalid URL)".to_owned();
        }

        let has_v3_api_root = url
            .path_segments()
            .map(|segments| {
                let segments: Vec<_> = segments.filter(|segment| !segment.is_empty()).collect();
                segments.ends_with(&["api", "v3"])
            })
            .unwrap_or(false);
        if has_v3_api_root {
            if let Ok(mut segments) = url.path_segments_mut() {
                segments.pop_if_empty();
                segments.pop();
                segments.pop();
            }
        }

        let _ = url.set_username("");
        let _ = url.set_password(None);
        url.set_query(None);
        url.set_fragment(None);
        url.to_string().trim_end_matches('/').to_owned()
    }

    pub fn instance_label(&self) -> String {
        Self::configured_instance_label(self.api_url.as_str())
    }

    pub async fn new(config: &Config) -> Result<Self, ApiError> {
        config
            .validate()
            .map_err(|message| ApiError::InvalidConfiguration(message.to_owned()))?;

        let mut base_url = Url::parse(&config.url)
            .map_err(|error| ApiError::InvalidConfiguration(format!("invalid API URL: {error}")))?;
        if !matches!(base_url.scheme(), "http" | "https") {
            return Err(ApiError::InvalidConfiguration(
                "API URL must use http or https".to_owned(),
            ));
        }
        if base_url.query().is_some() || base_url.fragment().is_some() {
            return Err(ApiError::InvalidConfiguration(
                "API URL must not contain a query or fragment".to_owned(),
            ));
        }

        // Accept either a service root or an API root, and normalize both to
        // the v3 API root before appending resource paths.
        let has_v3_api_root = base_url
            .path_segments()
            .map(|segments| {
                let segments: Vec<_> = segments.filter(|segment| !segment.is_empty()).collect();
                segments.ends_with(&["api", "v3"])
            })
            .unwrap_or(false);
        if !has_v3_api_root {
            let mut segments = base_url.path_segments_mut().map_err(|_| {
                ApiError::InvalidConfiguration("API URL cannot be used as a base URL".to_owned())
            })?;
            segments.pop_if_empty();
            segments.extend(["api", "v3"]);
        }

        let authentication = if config.token.is_some() {
            "bearer token"
        } else if config.client_id.is_some() {
            "OAuth2 client credentials"
        } else {
            "none"
        };
        tracing::info!(
            scheme = base_url.scheme(),
            host = base_url.host_str().unwrap_or_default(),
            port = ?base_url.port(),
            path = base_url.path(),
            "configuring Trustify API client"
        );
        tracing::debug!(authentication, "selected authentication method");

        let http = Client::builder().timeout(REQUEST_TIMEOUT).build()?;
        let oauth = match (&config.issuer_url, &config.client_id, &config.client_secret) {
            (Some(issuer_url), Some(client_id), Some(client_secret)) => {
                let (token_endpoint, auth_method) =
                    discover_token_endpoint(&http, issuer_url).await?;
                Some(OAuthCredentials {
                    token_endpoint,
                    auth_method,
                    client_id: client_id.clone(),
                    client_secret: client_secret.clone(),
                })
            }
            _ => None,
        };
        let token = match (&config.token, &oauth) {
            (Some(token), _) => Some(token.clone()),
            (None, Some(oauth)) => Some(get_token(&http, oauth).await?),
            (None, None) => None,
        };

        let api_url = base_url.clone();

        // Generated endpoint paths include `/api/v3`; pass the service root to
        // the bindings even when TRUSTIFY_URL already names the API root.
        let mut service_url = base_url;
        {
            let mut segments = service_url.path_segments_mut().map_err(|_| {
                ApiError::InvalidConfiguration("API URL cannot be used as a base URL".to_owned())
            })?;
            segments.pop_if_empty();
            segments.pop();
            segments.pop();
        }

        let token = token.map(|token| Arc::new(RwLock::new(Some(token))));
        let mut client_builder = TrustifyClient::builder(service_url.as_str())
            .request_timeout(REQUEST_TIMEOUT)
            .retry_policy(RetryPolicy::for_idempotent_requests(2));
        if let Some(token) = &token {
            client_builder = client_builder.token_provider(SharedTokenProvider(token.clone()));
        }
        let client = client_builder
            .build()
            .map_err(|error| ApiError::InvalidConfiguration(error.to_string()))?;

        Ok(Self {
            http,
            client,
            api_url,
            token,
            oauth,
        })
    }

    pub async fn list_sboms(&self, params: &ListParams) -> Result<Value, ApiError> {
        tracing::debug!(
            operation = "sbom.list",
            query = ?params.query,
            limit = params.limit,
            offset = params.offset,
            sort = ?params.sort,
            total = params.total,
            "Trustify API request"
        );
        let api = self.client.api().clone();
        let query = params.query.clone();
        let limit = params.limit;
        let offset = params.offset;
        let sort = params.sort.clone();
        let total = params.total;

        self.send_with_refresh(move || {
            let api = api.clone();
            let query = query.clone();
            let sort = sort.clone();
            async move {
                let mut request = api.list_sboms();
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

    pub async fn get_sbom(&self, id: &str) -> Result<Value, ApiError> {
        tracing::debug!(operation = "sbom.get", id, "Trustify API request");
        let api = self.client.api().clone();
        let id = id.to_owned();

        self.send_with_refresh(move || {
            let api = api.clone();
            let id = id.clone();
            async move { api.get_sbom().id(id).send().await }
        })
        .await
    }

    pub(crate) fn generated_api(&self) -> trustify_client::api::Client {
        self.client.api().clone()
    }

    pub(crate) async fn send_with_refresh<T, F, Fut>(&self, mut send: F) -> Result<Value, ApiError>
    where
        T: Serialize,
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<ResponseValue<T>, TrustifyError<()>>>,
    {
        let mut token_refreshed = false;
        loop {
            let started = Instant::now();
            tracing::trace!("sending generated Trustify API request");
            match send().await {
                Ok(response) => {
                    let value = serde_json::to_value(response.into_inner())?;
                    tracing::trace!(
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        "Trustify API request succeeded"
                    );
                    if crate::logging::full_diagnostics_enabled() {
                        let redacted = crate::logging::redact_sensitive_fields(&value);
                        tracing::trace!(response = %redacted, "Trustify API response body");
                    }
                    return Ok(value);
                }
                Err(error)
                    if trustify_error_status(&error) == Some(StatusCode::UNAUTHORIZED.as_u16())
                        && !token_refreshed
                        && self.oauth.is_some() =>
                {
                    tracing::warn!(
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        "Trustify rejected the access token; refreshing OAuth credentials"
                    );
                    token_refreshed = true;
                    let token =
                        get_token(&self.http, self.oauth.as_ref().expect("checked above")).await?;
                    if let Some(token_state) = &self.token {
                        *token_state.write().await = Some(token);
                    }
                }
                Err(error) => {
                    tracing::debug!(
                        status = ?trustify_error_status(&error),
                        error_category = trustify_error_category(&error),
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        "Trustify API request failed"
                    );
                    return Err(trustify_error(error).await);
                }
            }
        }
    }
}

fn trustify_error_status(error: &TrustifyError<()>) -> Option<u16> {
    match error {
        TrustifyError::ErrorResponse(response) => Some(response.status().as_u16()),
        TrustifyError::UnexpectedResponse(response) => Some(response.status().as_u16()),
        _ => None,
    }
}

fn trustify_error_category(error: &TrustifyError<()>) -> &'static str {
    match error {
        TrustifyError::ErrorResponse(_) => "http_error_response",
        TrustifyError::UnexpectedResponse(_) => "unexpected_response",
        _ => "client_error",
    }
}

async fn trustify_error(error: TrustifyError<()>) -> ApiError {
    match error {
        TrustifyError::ErrorResponse(response) => ApiError::HttpStatus {
            status: StatusCode::from_u16(response.status().as_u16())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            body: String::new(),
        },
        TrustifyError::UnexpectedResponse(response) => {
            let status = StatusCode::from_u16(response.status().as_u16())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let body = response.text().await.unwrap_or_default();
            ApiError::HttpStatus { status, body }
        }
        error => ApiError::Client(error.to_string()),
    }
}

async fn discover_token_endpoint(
    http: &Client,
    issuer_url: &str,
) -> Result<(Url, TokenEndpointAuthMethod), ApiError> {
    tracing::debug!("discovering OAuth2 token endpoint");
    let issuer = Url::parse(issuer_url)
        .map_err(|error| ApiError::Oidc(format!("invalid issuer URL: {error}")))?;
    validate_http_url(&issuer, "issuer URL")?;
    if issuer.query().is_some() || issuer.fragment().is_some() {
        return Err(ApiError::Oidc(
            "issuer URL must not contain a query or fragment".to_owned(),
        ));
    }

    let mut discovery_url = issuer.clone();
    {
        let mut segments = discovery_url
            .path_segments_mut()
            .map_err(|_| ApiError::Oidc("issuer URL cannot be used as a base URL".to_owned()))?;
        segments.pop_if_empty();
        segments.extend([".well-known", "openid-configuration"]);
    }

    let response = http.get(discovery_url).send().await?;
    let status = response.status();
    let body = response.bytes().await?;
    if !status.is_success() {
        return Err(ApiError::Authentication {
            status,
            body: String::from_utf8_lossy(&body).into_owned(),
        });
    }

    let metadata: Value = serde_json::from_slice(&body)
        .map_err(|error| ApiError::Oidc(format!("invalid discovery document: {error}")))?;
    let discovered_issuer = metadata
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::Oidc("discovery document is missing issuer".to_owned()))?;
    if discovered_issuer != issuer_url {
        return Err(ApiError::Oidc(
            "discovery document issuer does not match ISSUER_URL".to_owned(),
        ));
    }

    let token_endpoint = metadata
        .get("token_endpoint")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::Oidc("discovery document is missing token_endpoint".to_owned()))?;
    let token_endpoint = Url::parse(token_endpoint)
        .map_err(|error| ApiError::Oidc(format!("invalid token_endpoint URL: {error}")))?;
    validate_http_url(&token_endpoint, "token_endpoint URL")?;
    if token_endpoint.fragment().is_some() {
        return Err(ApiError::Oidc(
            "token_endpoint URL must not contain a fragment".to_owned(),
        ));
    }

    let auth_method = match metadata.get("token_endpoint_auth_methods_supported") {
        None => TokenEndpointAuthMethod::ClientSecretBasic,
        Some(Value::Array(methods)) => {
            if methods
                .iter()
                .any(|method| method.as_str() == Some("client_secret_basic"))
            {
                TokenEndpointAuthMethod::ClientSecretBasic
            } else if methods
                .iter()
                .any(|method| method.as_str() == Some("client_secret_post"))
            {
                TokenEndpointAuthMethod::ClientSecretPost
            } else {
                return Err(ApiError::Oidc(
                    "token endpoint does not advertise client_secret_basic or client_secret_post"
                        .to_owned(),
                ));
            }
        }
        Some(_) => {
            return Err(ApiError::Oidc(
                "token_endpoint_auth_methods_supported must be an array".to_owned(),
            ));
        }
    };

    Ok((token_endpoint, auth_method))
}

fn validate_http_url(url: &Url, description: &str) -> Result<(), ApiError> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ApiError::Oidc(format!(
            "{description} must use http or https"
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ApiError::Oidc(format!(
            "{description} must not contain credentials"
        )));
    }
    Ok(())
}

async fn get_token(http: &Client, oauth: &OAuthCredentials) -> Result<String, ApiError> {
    tracing::info!("requesting OAuth2 client-credentials token");
    tracing::debug!(
        auth_method = match oauth.auth_method {
            TokenEndpointAuthMethod::ClientSecretBasic => "client_secret_basic",
            TokenEndpointAuthMethod::ClientSecretPost => "client_secret_post",
        },
        "authenticating OAuth2 token request"
    );
    let request = http.post(oauth.token_endpoint.clone());
    let request = match oauth.auth_method {
        TokenEndpointAuthMethod::ClientSecretBasic => request
            .basic_auth(&oauth.client_id, Some(&oauth.client_secret))
            .form(&[("grant_type", "client_credentials")]),
        TokenEndpointAuthMethod::ClientSecretPost => request.form(&[
            ("grant_type", "client_credentials"),
            ("client_id", oauth.client_id.as_str()),
            ("client_secret", oauth.client_secret.as_str()),
        ]),
    };
    let response = request.send().await?;

    let status = response.status();
    tracing::trace!(
        http_status = status.as_u16(),
        "OAuth2 token endpoint responded"
    );
    let body = response.bytes().await?;
    if !status.is_success() {
        return Err(ApiError::Authentication {
            status,
            body: String::from_utf8_lossy(&body).into_owned(),
        });
    }

    let token_response: Value = serde_json::from_slice(&body)
        .map_err(|error| ApiError::Oidc(format!("invalid token response: {error}")))?;
    let access_token = token_response
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| ApiError::Oidc("token response is missing access_token".to_owned()))?;
    let token_type = token_response
        .get("token_type")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::Oidc("token response is missing token_type".to_owned()))?;
    if !token_type.eq_ignore_ascii_case("bearer") {
        return Err(ApiError::Oidc(format!(
            "unsupported OAuth2 token type: {token_type}"
        )));
    }

    Ok(access_token.to_owned())
}

#[cfg(test)]
mod tests {
    use super::ApiClient;

    #[test]
    fn instance_label_shows_the_service_root_without_credentials() {
        assert_eq!(
            ApiClient::configured_instance_label(
                "https://user:secret@trustify.example/tenant/api/v3"
            ),
            "https://trustify.example/tenant"
        );
        assert_eq!(
            ApiClient::configured_instance_label("http://localhost:8080/api/v3"),
            "http://localhost:8080"
        );
        assert_eq!(
            ApiClient::configured_instance_label("not a URL"),
            "(invalid URL)"
        );
    }
}
