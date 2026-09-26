use std::{
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

use serde_json::Value;
use wiremock::{
    matchers::{body_string_contains, header, method, path, query_param},
    Mock, MockServer, Request, Respond, ResponseTemplate,
};

fn run_cli(server: &MockServer, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_trusty"))
        .args(["--url", &server.uri(), "--token", "test-token"])
        .env_remove("ISSUER_URL")
        .env_remove("CLIENT_ID")
        .env_remove("CLIENT_SECRET")
        .args(args)
        .output()
        .expect("run trusty")
}

fn sbom_summary(id: &str, name: &str) -> Value {
    serde_json::json!({
        "authors": [],
        "data_licenses": [],
        "described_by": [],
        "id": id,
        "ingested": "2024-01-01T00:00:00Z",
        "labels": {},
        "name": name,
        "number_of_packages": 0,
        "published": null,
        "sha256": "sha256",
        "sha384": "sha384",
        "sha512": "sha512",
        "size": 0,
        "suppliers": []
    })
}

struct TokenSequence(AtomicUsize);

impl Respond for TokenSequence {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let access_token = if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
            "expired-token"
        } else {
            "refreshed-token"
        };
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": access_token,
            "token_type": "Bearer"
        }))
    }
}

#[tokio::test]
async fn sbom_list_sends_v3_query_and_bearer_token_and_prints_json() {
    let server = MockServer::start().await;
    let response = serde_json::json!({"items": [sbom_summary("sbom-1", "fixture")], "total": 1});

    Mock::given(method("GET"))
        .and(path("/api/v3/sbom"))
        .and(query_param("q", "name~openssl&version>=1"))
        .and(query_param("limit", "5"))
        .and(query_param("offset", "10"))
        .and(query_param("sort", "ingested:desc"))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;

    let output = run_cli(
        &server,
        &[
            "sbom",
            "list",
            "--query",
            "name~openssl&version>=1",
            "--limit",
            "5",
            "--offset",
            "10",
            "--sort",
            "ingested:desc",
            "--format",
            "json",
        ],
    );

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout: Value = serde_json::from_slice(&output.stdout).expect("JSON output");
    assert_eq!(stdout, response);
}

#[tokio::test]
async fn forced_tui_requires_an_interactive_terminal() {
    let server = MockServer::start().await;
    let output = run_cli(&server, &["sbom", "list", "--format", "tui"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires an interactive terminal"));
}

#[tokio::test]
async fn sbom_get_uses_v3_detail_endpoint_and_preserves_response() {
    let server = MockServer::start().await;
    let id = "urn:uuid:123e4567-e89b-12d3-a456-426614174000";
    let response = sbom_summary(id, "fixture");

    Mock::given(method("GET"))
        .and(path(format!("/api/v3/sbom/{id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;

    let output = run_cli(&server, &["sbom", "get", id]);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout: Value = serde_json::from_slice(&output.stdout).expect("JSON output");
    assert_eq!(stdout, response);
}

#[tokio::test]
async fn sbom_get_reports_http_errors_with_failure_exit_code() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v3/sbom/missing"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .expect(1)
        .mount(&server)
        .await;

    let output = run_cli(&server, &["sbom", "get", "missing"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("HTTP 404"));
}

#[tokio::test]
async fn oauth_client_credentials_fetches_and_uses_access_token() {
    let server = MockServer::start().await;
    let issuer_url = format!("{}/realms/test", server.uri());
    let token_endpoint = format!("{}/oauth/token", server.uri());

    Mock::given(method("GET"))
        .and(path("/realms/test/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": issuer_url.clone(),
            "token_endpoint": token_endpoint,
            "token_endpoint_auth_methods_supported": ["client_secret_post"]
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains("client_id=test-client"))
        .and(body_string_contains("client_secret=test-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "oauth-token",
            "token_type": "Bearer"
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v3/sbom"))
        .and(header("authorization", "Bearer oauth-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [],
            "total": 0
        })))
        .expect(1)
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trusty"))
        .args(["--url", &server.uri()])
        .env_remove("TRUSTIFY_TOKEN")
        .env("ISSUER_URL", issuer_url)
        .env("CLIENT_ID", "test-client")
        .env("CLIENT_SECRET", "test-secret")
        .args(["sbom", "list"])
        .output()
        .expect("run trusty");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout: Value = serde_json::from_slice(&output.stdout).expect("automatic JSON output");
    assert_eq!(stdout["total"], 0);
}

#[tokio::test]
async fn oauth_client_credentials_are_refetched_after_api_unauthorized() {
    let server = MockServer::start().await;
    let issuer_url = server.uri();
    let token_endpoint = format!("{}/oauth/token", server.uri());

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": issuer_url.clone(),
            "token_endpoint": token_endpoint
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(header(
            "authorization",
            "Basic dGVzdC1jbGllbnQ6dGVzdC1zZWNyZXQ=",
        ))
        .and(body_string_contains("grant_type=client_credentials"))
        .respond_with(TokenSequence(AtomicUsize::new(0)))
        .expect(2)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v3/sbom"))
        .and(header("authorization", "Bearer expired-token"))
        .respond_with(ResponseTemplate::new(401).set_body_string("expired"))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v3/sbom"))
        .and(header("authorization", "Bearer refreshed-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [],
            "total": 0
        })))
        .expect(1)
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trusty"))
        .args(["--url", &server.uri()])
        .env_remove("TRUSTIFY_TOKEN")
        .env("ISSUER_URL", issuer_url)
        .env("CLIENT_ID", "test-client")
        .env("CLIENT_SECRET", "test-secret")
        .args(["sbom", "list"])
        .output()
        .expect("run trusty");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout: Value = serde_json::from_slice(&output.stdout).expect("automatic JSON output");
    assert_eq!(stdout["total"], 0);
}

#[tokio::test]
async fn oidc_discovery_issuer_must_match_issuer_url() {
    let server = MockServer::start().await;
    let issuer_url = server.uri();

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": "https://different-issuer.example",
            "token_endpoint": format!("{}/oauth/token", server.uri())
        })))
        .expect(1)
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trusty"))
        .args(["--url", &server.uri()])
        .env_remove("TRUSTIFY_TOKEN")
        .env("ISSUER_URL", issuer_url)
        .env("CLIENT_ID", "test-client")
        .env("CLIENT_SECRET", "test-secret")
        .args(["sbom", "list"])
        .output()
        .expect("run trusty");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not match ISSUER_URL"));
}

#[test]
fn help_is_available_without_connection_configuration() {
    let output = Command::new(env!("CARGO_BIN_EXE_trusty"))
        .arg("--help")
        .output()
        .expect("run trusty");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("sbom"));
    assert!(stdout.contains("--url"));
    assert!(stdout.contains("[default: http://localhost:8080/api/v3]"));
    assert!(stdout.contains("--issuer-url"));
}

#[tokio::test]
async fn url_and_token_can_come_from_environment() {
    let server = MockServer::start().await;
    let trustify_url = format!("{}/tenant/api/v3", server.uri());

    Mock::given(method("GET"))
        .and(path("/tenant/api/v3/sbom"))
        .and(header("authorization", "Bearer env-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [],
            "total": 0
        })))
        .expect(1)
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trusty"))
        .env("TRUSTIFY_URL", trustify_url)
        .env("TRUSTIFY_TOKEN", "env-token")
        .env_remove("ISSUER_URL")
        .env_remove("CLIENT_ID")
        .env_remove("CLIENT_SECRET")
        .args(["sbom", "list"])
        .output()
        .expect("run trusty");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
