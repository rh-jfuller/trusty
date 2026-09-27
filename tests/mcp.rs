use std::{io::Write, process::Command, process::Stdio};

use serde_json::{json, Value};
use wiremock::{
    matchers::{header, method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

#[tokio::test]
async fn stdio_server_lists_tools_and_forwards_a_tool_call() {
    let api = MockServer::start().await;
    let advisory_response = json!({"items": [], "total": 0});
    Mock::given(method("GET"))
        .and(path("/api/v3/advisory"))
        .and(query_param("q", "title~critical"))
        .and(query_param("limit", "5"))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&advisory_response))
        .expect(1)
        .mount(&api)
        .await;

    let requests = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0"}
            }
        }),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "list_advisories",
                "arguments": {"query": "title~critical", "limit": 5}
            }
        }),
    ];
    let input = requests
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    let api_url = api.uri();
    let mut child = Command::new(env!("CARGO_BIN_EXE_trusty"))
        .args(["--url", &api_url, "--token", "test-token", "mcp"])
        .env_remove("ISSUER_URL")
        .env_remove("CLIENT_ID")
        .env_remove("CLIENT_SECRET")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start MCP server");
    child
        .stdin
        .take()
        .expect("MCP stdin")
        .write_all(format!("{input}\n").as_bytes())
        .expect("write MCP requests");

    let output = child.wait_with_output().expect("wait for MCP server");
    assert!(
        output.status.success(),
        "MCP server failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let responses = String::from_utf8(output.stdout)
        .expect("MCP stdout is UTF-8")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("MCP JSON-RPC response"))
        .collect::<Vec<_>>();

    let tools = responses
        .iter()
        .find(|response| response["id"] == 2)
        .expect("tools/list response");
    let tool_list = tools["result"]["tools"].as_array().expect("tool list");
    for name in [
        "list_advisories",
        "list_products",
        "get_product",
        "list_exploits",
        "get_exploit",
        "list_weaknesses",
        "get_weakness",
        "list_organizations",
        "get_organization",
    ] {
        assert!(
            tool_list.iter().any(|tool| tool["name"] == name),
            "missing MCP tool {name}"
        );
    }

    let call = responses
        .iter()
        .find(|response| response["id"] == 3)
        .expect("tools/call response");
    assert_eq!(call["result"]["isError"], false, "{call}");
    let text = call["result"]["content"][0]["text"]
        .as_str()
        .expect("tool result text");
    assert_eq!(
        serde_json::from_str::<Value>(text).unwrap(),
        advisory_response
    );
}
