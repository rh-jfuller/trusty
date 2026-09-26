use std::time::Duration;

use reqwest::{Client, StatusCode, Url};
use serde_json::Value;
use tokio::{sync::RwLock, time::sleep};

use crate::{api::ApiError, config::Config};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_ATTEMPTS: usize = 3;

#[derive(Clone, Copy)]
enum TokenEndpointAuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
}

struct OAuthCredentials {
    token_endpoint: Url,
    auth_method: TokenEndpointAuthMethod,
    client_id: String,
    client_secret: String,
}

pub struct ApiClient {
    http: Client,
    base_url: Url,
    token: RwLock<Option<String>>,
    oauth: Option<OAuthCredentials>,
}

impl ApiClient {
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

        Ok(Self {
            http,
            base_url,
            token: RwLock::new(token),
            oauth,
        })
    }

    pub async fn get_json(
        &self,
        path_segments: &[&str],
        query: &[(String, String)],
    ) -> Result<Value, ApiError> {
        let url = self.api_url(path_segments)?;
        let mut attempt = 0;
        let mut token_refreshed = false;

        loop {
            let token = self.token.read().await.clone();
            let mut request = self.http.get(url.clone()).query(query);
            if let Some(token) = token {
                request = request.bearer_auth(token);
            }

            match request.send().await {
                Err(error)
                    if attempt + 1 < MAX_ATTEMPTS && (error.is_timeout() || error.is_connect()) =>
                {
                    attempt += 1;
                    sleep(retry_delay(attempt)).await;
                }
                Err(error) => return Err(ApiError::Request(error)),
                Ok(response) => {
                    if response.status() == StatusCode::UNAUTHORIZED && !token_refreshed {
                        if let Some(oauth) = &self.oauth {
                            token_refreshed = true;
                            let token = get_token(&self.http, oauth).await?;
                            *self.token.write().await = Some(token);
                            continue;
                        }
                    }

                    if attempt + 1 < MAX_ATTEMPTS && is_retryable(response.status()) {
                        attempt += 1;
                        sleep(retry_delay(attempt)).await;
                        continue;
                    }

                    let status = response.status();
                    let body = response.bytes().await?;
                    if !status.is_success() {
                        return Err(ApiError::HttpStatus {
                            status,
                            body: String::from_utf8_lossy(&body).into_owned(),
                        });
                    }
                    return Ok(serde_json::from_slice(&body)?);
                }
            }
        }
    }

    fn api_url(&self, path_segments: &[&str]) -> Result<Url, ApiError> {
        let mut url = self.base_url.clone();
        {
            let mut segments = url.path_segments_mut().map_err(|_| {
                ApiError::InvalidConfiguration("API URL cannot be used as a base URL".to_owned())
            })?;
            segments.pop_if_empty();
            segments.extend(path_segments.iter().copied());
        }
        Ok(url)
    }
}

fn is_retryable(status: StatusCode) -> bool {
    status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS
}

fn retry_delay(attempt: usize) -> Duration {
    Duration::from_millis(100 * attempt as u64)
}

async fn discover_token_endpoint(
    http: &Client,
    issuer_url: &str,
) -> Result<(Url, TokenEndpointAuthMethod), ApiError> {
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
