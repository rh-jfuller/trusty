use reqwest::StatusCode;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),

    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("authentication failed with HTTP {status}: {body}")]
    Authentication { status: StatusCode, body: String },

    #[error("OIDC authentication error: {0}")]
    Oidc(String),

    #[error("Trustify returned HTTP {status}: {body}")]
    HttpStatus { status: StatusCode, body: String },

    #[error("Trustify returned invalid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
}
