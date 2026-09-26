use clap::Args;

#[derive(Clone, Debug, Args)]
pub struct Config {
    /// Trustify API base URL
    #[arg(
        short = 'u',
        long,
        env = "TRUSTIFY_URL",
        default_value = "http://localhost:8080/api/v3",
        global = true
    )]
    pub url: String,

    /// Static bearer token
    #[arg(long, env = "TRUSTIFY_TOKEN", global = true, hide_env_values = true)]
    pub token: Option<String>,

    /// OAuth2 issuer URL for client-credentials authentication
    #[arg(long, env = "ISSUER_URL", global = true)]
    pub issuer_url: Option<String>,

    /// OAuth2 client ID
    #[arg(long, env = "CLIENT_ID", global = true)]
    pub client_id: Option<String>,

    /// OAuth2 client secret
    #[arg(long, env = "CLIENT_SECRET", global = true, hide_env_values = true)]
    pub client_secret: Option<String>,
}

impl Config {
    pub fn validate(&self) -> Result<(), &'static str> {
        let credentials = [
            self.issuer_url.is_some(),
            self.client_id.is_some(),
            self.client_secret.is_some(),
        ];
        let credential_count = credentials.into_iter().filter(|set| *set).count();

        if credential_count != 0 && credential_count != credentials.len() {
            return Err("issuer URL, client ID, and client secret must be provided together");
        }

        if self.token.is_some() && credential_count == credentials.len() {
            return Err("use either a bearer token or OAuth2 client credentials, not both");
        }

        Ok(())
    }
}
