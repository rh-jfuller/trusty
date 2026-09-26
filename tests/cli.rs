use std::{
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

use serde_json::Value;
use wiremock::{
    matchers::{body_string_contains, header, method, path, path_regex, query_param},
    Mock, MockServer, Request, Respond, ResponseTemplate,
};

use trusty_cli::{
    api::{self, ApiClient, ListParams},
    config::Config,
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

fn assert_json_output(output: Output, expected: Value) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout: Value = serde_json::from_slice(&output.stdout).expect("JSON output");
    assert_eq!(stdout, expected);
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
async fn vulnerability_list_uses_v3_endpoint_query_and_bearer_token() {
    let server = MockServer::start().await;
    let response = serde_json::json!({"items": [], "total": 0});

    Mock::given(method("GET"))
        .and(path("/api/v3/vulnerability"))
        .and(query_param("q", "title~openssl"))
        .and(query_param("limit", "10"))
        .and(query_param("offset", "5"))
        .and(query_param("sort", "id:desc"))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;

    let output = run_cli(
        &server,
        &[
            "vuln",
            "list",
            "--query",
            "title~openssl",
            "--limit",
            "10",
            "--offset",
            "5",
            "--sort",
            "id:desc",
            "--format",
            "json",
        ],
    );

    assert_json_output(output, response);
}

#[tokio::test]
async fn advisory_list_uses_v3_endpoint_and_query() {
    let server = MockServer::start().await;
    let response = serde_json::json!({"items": [], "total": 0});

    Mock::given(method("GET"))
        .and(path("/api/v3/advisory"))
        .and(query_param("q", "title~kernel"))
        .and(query_param("limit", "8"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;

    let output = run_cli(
        &server,
        &[
            "advisory",
            "list",
            "--query",
            "title~kernel",
            "--limit",
            "8",
        ],
    );

    assert_json_output(output, response);
}

#[tokio::test]
async fn verbosity_and_debug_logs_go_to_stderr_without_contaminating_json_output() {
    let server = MockServer::start().await;
    let response = serde_json::json!({"items": [], "total": 0});

    Mock::given(method("GET"))
        .and(path("/api/v3/advisory"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(2)
        .mount(&server)
        .await;

    let verbose = run_cli(&server, &["advisory", "list", "-v"]);
    assert!(
        verbose.status.success(),
        "{}",
        String::from_utf8_lossy(&verbose.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&verbose.stdout).expect("JSON stdout"),
        response
    );
    let verbose_stderr = String::from_utf8_lossy(&verbose.stderr);
    assert!(verbose_stderr.contains("starting trusty"));
    assert!(!verbose_stderr.contains("test-token"));

    let output = run_cli(&server, &["advisory", "list", "--debug"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout: Value = serde_json::from_slice(&output.stdout).expect("JSON stdout");
    assert_eq!(stdout, response);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("starting trusty"));
    assert!(stderr.contains("Trustify API response body"));
    assert!(!stderr.contains("test-token"));
}

#[test]
fn bare_noninteractive_invocation_prints_help_without_parsing_the_api_url() {
    let output = Command::new(env!("CARGO_BIN_EXE_trusty"))
        .args(["--url", "not a URL"])
        .env_remove("TRUSTIFY_TOKEN")
        .env_remove("ISSUER_URL")
        .env_remove("CLIENT_ID")
        .env_remove("CLIENT_SECRET")
        .output()
        .expect("run trusty without a subcommand");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage: trusty"));
    assert!(stdout.contains("sbom"));
}

#[tokio::test]
async fn license_list_uses_v3_endpoint_and_query() {
    let server = MockServer::start().await;
    let response = serde_json::json!({"items": [], "total": 0});

    Mock::given(method("GET"))
        .and(path("/api/v3/license"))
        .and(query_param("q", "license~MIT"))
        .and(query_param("offset", "3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;

    let output = run_cli(
        &server,
        &[
            "license",
            "list",
            "--query",
            "license~MIT",
            "--offset",
            "3",
            "--format",
            "json",
        ],
    );

    assert_json_output(output, response);
}

#[tokio::test]
async fn product_exploit_organization_and_weakness_lists_are_available() {
    let server = MockServer::start().await;
    let product_response = serde_json::json!({
        "items": [{"id": "product-1", "name": "Example Product", "vendor": null, "versions": []}],
        "total": 1
    });
    let exploit_response = serde_json::json!({
        "items": [{
            "cve_id": "CVE-2025-1234",
            "date_reported": "2025-01-02",
            "id": "kev-1",
            "metadata": {},
            "remediation_due_date": null,
            "source": "cisa-kev"
        }],
        "total": 1
    });
    let organization_response = serde_json::json!({
        "items": [{
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "name": "Example Organization",
            "cpe_key": "cpe:/a:example",
            "website": "https://example.com"
        }],
        "total": 1
    });
    let weakness_response = serde_json::json!({
        "items": [{"id": "CWE-79", "description": "Cross-site scripting"}],
        "total": 1
    });

    for (resource, response) in [
        ("product", &product_response),
        ("exploit", &exploit_response),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/api/v3/{resource}")))
            .and(query_param("q", "name~example"))
            .and(query_param("limit", "5"))
            .and(query_param("offset", "2"))
            .and(query_param("sort", "name:asc"))
            .and(header("authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;
    }
    for (resource, response) in [
        ("organization", &organization_response),
        ("weakness", &weakness_response),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/api/v3/{resource}")))
            .and(query_param("q", "name~example"))
            .and(query_param("limit", "5"))
            .and(query_param("offset", "2"))
            .and(query_param("sort", "name:asc"))
            .and(header("authorization", "Bearer test-token"))
            .and(header("api-version", "0.6.2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;
    }

    for (args, expected) in [
        (vec!["product", "list"], &product_response),
        (vec!["exploit", "list"], &exploit_response),
        (vec!["organization", "list"], &organization_response),
        (vec!["weakness", "list"], &weakness_response),
    ] {
        let mut command = args;
        command.extend([
            "--query",
            "name~example",
            "--limit",
            "5",
            "--offset",
            "2",
            "--sort",
            "name:asc",
            "--format",
            "json",
        ]);
        assert_json_output(run_cli(&server, &command), expected.clone());
    }
}

#[tokio::test]
async fn product_exploit_organization_and_weakness_get_commands_are_available() {
    let server = MockServer::start().await;
    let product_id = "123e4567-e89b-12d3-a456-426614174001";
    let organization_id = "123e4567-e89b-12d3-a456-426614174002";
    let product_response = serde_json::json!({
        "id": product_id,
        "name": "Example Product",
        "vendor": null,
        "versions": []
    });
    let exploit_response = serde_json::json!({
        "cve_id": "CVE-2025-1234",
        "date_reported": "2025-01-02",
        "id": "kev-1",
        "metadata": {},
        "remediation_due_date": null,
        "source": "cisa-kev"
    });
    let organization_response = serde_json::json!({
        "advisories": [],
        "cpe_key": "cpe:/a:example",
        "id": organization_id,
        "name": "Example Organization",
        "website": "https://example.com"
    });
    let weakness_response = serde_json::json!({
        "id": "CWE-79",
        "description": "Cross-site scripting",
        "extended_description": "A more complete description"
    });

    for (resource, id, response) in [
        ("product", product_id, &product_response),
        ("organization", organization_id, &organization_response),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/api/v3/{resource}/{id}")))
            .and(header("authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/api/v3/exploit/kev-1"))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&exploit_response))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v3/weakness/CWE-79"))
        .and(header("authorization", "Bearer test-token"))
        .and(header("api-version", "0.6.2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&weakness_response))
        .expect(1)
        .mount(&server)
        .await;

    for (args, expected) in [
        (vec!["product", "get", product_id], &product_response),
        (vec!["exploit", "get", "kev-1"], &exploit_response),
        (
            vec!["organization", "get", organization_id],
            &organization_response,
        ),
        (vec!["weakness", "get", "CWE-79"], &weakness_response),
    ] {
        let mut command = args;
        command.extend(["--format", "json"]);
        assert_json_output(run_cli(&server, &command), expected.clone());
    }
}

#[tokio::test]
async fn package_search_uses_purl_endpoint() {
    let server = MockServer::start().await;
    let response = serde_json::json!({"items": [], "total": 0});

    Mock::given(method("GET"))
        .and(path("/api/v3/purl"))
        .and(query_param("q", "name~openssl"))
        .and(query_param("limit", "12"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;

    let output = run_cli(
        &server,
        &[
            "package",
            "search",
            "--query",
            "name~openssl",
            "--limit",
            "12",
            "--format",
            "json",
        ],
    );

    assert_json_output(output, response);
}

#[tokio::test]
async fn package_purl_alias_and_resource_get_commands_are_available() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/vulnerability/CVE-2024-1234"))
        .and(query_param("scores", "true"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v3/advisory/advisory-123"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v3/purl/example-package"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .expect(1)
        .mount(&server)
        .await;

    let vuln = run_cli(
        &server,
        &[
            "vuln",
            "get",
            "CVE-2024-1234",
            "--scores",
            "--format",
            "json",
        ],
    );
    assert_eq!(vuln.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&vuln.stderr).contains("HTTP 404"));

    let advisory = run_cli(
        &server,
        &["advisory", "get", "advisory-123", "--format", "json"],
    );
    assert_eq!(advisory.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&advisory.stderr).contains("HTTP 404"));

    let component = run_cli(
        &server,
        &["component", "get", "example-package", "--format", "json"],
    );
    assert_eq!(component.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&component.stderr).contains("HTTP 404"));
}

#[tokio::test]
async fn forced_tui_requires_an_interactive_terminal() {
    let server = MockServer::start().await;
    let output = run_cli(&server, &["sbom", "list", "--format", "tui"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires an interactive terminal"));

    let output = run_cli(&server, &["vuln", "list", "--format", "tui"]);
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
async fn all_list_resources_request_total_when_enabled() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(
            r"^/api/v3/(sbom|advisory|exploit|license|organization|purl|product|vulnerability|weakness)$",
        ))
        .and(query_param("limit", "0"))
        .and(query_param("total", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [],
            "total": 0
        })))
        .expect(9)
        .mount(&server)
        .await;

    let client = ApiClient::new(&Config {
        url: server.uri(),
        token: Some("test-token".to_owned()),
        issuer_url: None,
        client_id: None,
        client_secret: None,
    })
    .await
    .expect("valid API client");
    let params = ListParams {
        limit: Some(0),
        total: true,
        ..ListParams::default()
    };

    for result in [
        api::sbom::list(&client, &params).await,
        api::advisory::list(&client, &params).await,
        api::exploit::list(&client, &params).await,
        api::license::list(&client, &params).await,
        api::organization::list(&client, &params).await,
        api::package::search(&client, &params).await,
        api::product::list(&client, &params).await,
        api::vulnerability::list(&client, &params).await,
        api::weakness::list(&client, &params).await,
    ] {
        assert!(result.is_ok(), "list request should include total=true");
    }
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
async fn oauth_refresh_is_preserved_for_raw_weakness_responses() {
    let server = MockServer::start().await;
    let issuer_url = server.uri();
    let token_endpoint = format!("{}/oauth/token", server.uri());
    let response = serde_json::json!({
        "items": [{"id": "CWE-79", "description": "Cross-site scripting"}],
        "total": 1
    });

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
        .and(path("/api/v3/weakness"))
        .and(header("authorization", "Bearer expired-token"))
        .respond_with(ResponseTemplate::new(401).set_body_string("expired"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v3/weakness"))
        .and(header("authorization", "Bearer refreshed-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_trusty"))
        .args(["--url", &server.uri()])
        .env_remove("TRUSTIFY_TOKEN")
        .env("ISSUER_URL", issuer_url)
        .env("CLIENT_ID", "test-client")
        .env("CLIENT_SECRET", "test-secret")
        .args(["weakness", "list", "--format", "json"])
        .output()
        .expect("run trusty");

    assert_json_output(output, response);
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
    assert!(stdout.contains("vuln"));
    assert!(stdout.contains("advisory"));
    assert!(stdout.contains("license"));
    assert!(stdout.contains("package"));
    assert!(stdout.contains("component"));
    assert!(stdout.contains("product"));
    assert!(stdout.contains("exploit"));
    assert!(stdout.contains("weakness"));
    assert!(stdout.contains("organization"));
    assert!(stdout.contains("--url"));
    assert!(stdout.contains("[default: http://localhost:8080/api/v3]"));
    assert!(stdout.contains("--issuer-url"));
    assert!(stdout.contains("--verbose"));
    assert!(stdout.contains("--debug"));
    assert!(stdout.contains("interactive entity menu"));
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
