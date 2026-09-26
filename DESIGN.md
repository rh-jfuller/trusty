# trusty design

## Purpose

`trusty` is a Rust command-line client for Trustify. It should cover the common
read and search workflows people currently use the web UI for, then grow into a
local scanner and CI gate. It talks to Trustify's HTTP API; it does not connect
to Trustify's database or depend on Trustify's private workspace crates.

The project is deliberately incremental: ship a useful read-only client first,
then add scanning and policy features as separately testable milestones.

## Naming and packaging

- Cargo package and crates.io name: `trusty-cli`.
- Executable name: `trusty`.
- Start with one publishable package containing the binary and its Rust modules.
  This keeps the dependency and release surface small while still allowing
  reusable client functionality to be exposed from the crate where useful.
- Follow the existing Trustify CLI's conventions where they help: Clap derive
  commands, an asynchronous HTTP client, shared API error handling, resource
  command modules, and JSON output. Do not bring over its v2 endpoint paths or
  destructive management commands as defaults.

## Goals

1. Connect to an existing Trustify instance using its v3 API.
2. List, search, and inspect the main entities available through v3 endpoints.
3. Analyze a local SBOM against the configured Trustify instance.
4. Provide a predictable non-zero result for CI when a configured vulnerability
   threshold is exceeded.
5. Add local document validation and broader scan inputs over time, without
   requiring users to install a separate UI or scanner stack.
6. Keep the common test suite runnable without a Trustify server; add a real
   server integration path for contract coverage.

## Initial user experience

The command layout should be resource-oriented, with a shared query model:

```text
trusty --url https://trustify.example sbom list --query 'name~openssl' \
  --limit 20 --sort 'ingested:desc' --format table
trusty advisory list --query 'title~openssl' --format json
trusty vulnerability get CVE-2024-1234
trusty purl get 'pkg:cargo/example@1.2.3'
```

Initial browse/search scope is SBOMs, advisories, vulnerabilities, and PURLs,
plus other read-only entities where the current v3 API provides a useful list
or detail operation. The v3 OpenAPI document is the source of truth for routes
and request/response details. Do not silently fall back to v2 when a v3 route is
missing.

List commands should pass Trustify's native `q`, `limit`, `offset`, and `sort`
parameters through rather than introducing a second query language. Query
values must be URL-encoded by the HTTP client. JSON output should preserve the
API response shape for scripting; table output is for interactive use. Keep
progress and diagnostics on stderr so stdout remains pipe-friendly.

## Connection and API client

- Base URL: `--url` or `TRUSTIFY_URL`, defaulting to
  `http://localhost:8080/api/v3` for local Trustify development. A service root
  is also accepted and normalized to the v3 API root.
- Authentication: allow unauthenticated access for public instances, a bearer
  token, and OIDC-discovered OAuth2 client-credentials using `ISSUER_URL`,
  `CLIENT_ID`, and `CLIENT_SECRET`. Verify the discovered issuer, use its
  advertised token endpoint and client-authentication method, and reacquire a
  client-credentials token once after an API 401. Prefer environment variables
  for secrets; support the corresponding CLI options for parity. Do not persist
  credentials in the first release.
- Use one shared `reqwest` client with a finite timeout, structured errors
  (connection, timeout, HTTP status/body, and decode errors), and retries only
  for transient failures on idempotent requests. Avoid retrying writes.
- Keep API responses as `serde_json::Value` initially. This avoids a large,
  version-coupled model layer and allows unknown fields to pass through. Add
  typed models only where scan/gate logic needs stable fields.
- Keep resource paths and query serialization in small API modules; commands
  should not construct URLs ad hoc.
- Use v3 endpoints under `/api/v3`. For scan, the current API includes SBOM
  PURL extraction and vulnerability analysis operations; confirm their exact
  request/response contract against OpenAPI before implementing the adapter.

## Scan and CI gate

The first scan flow should be a deliberately thin, server-backed path:

```text
trusty scan sbom ./bom.json --fail-on high
```

1. Read one local SPDX or CycloneDX SBOM.
2. Ask the Trustify v3 API to extract package URLs and analyze them for known
   vulnerabilities (or use the equivalent current v3 operation if the OpenAPI
   contract changes).
3. Render a human-readable summary or machine-readable JSON.
4. Return success when the selected policy passes and a distinct policy-failure
   exit code when it does not.

The first policy surface should be small: severity threshold, whether resolved
findings are included, and explicit CVE ignore entries if the API response
supports them. Keep policy evaluation deterministic and separate from HTTP and
rendering. Start with documented exit codes: `0` pass, `1` policy failure, and
`2` invocation, input, authentication, or service error. JSON mode must include
the same pass/fail result as the process exit status.

Directory, package-manager lockfile, container registry, and OCI archive
cataloging are follow-on scan inputs, not requirements for the first scan
release. The Rust scanning experiment in Trustify PR #2527 is a source of
workflow and target ideas, not a requirement to implement every cataloger at
once.

The Python CI-gate experiment in Trustify PR #2535 is a reference for future
policy needs (license rules, deny/ignore lists, SARIF/JUnit, and Conforma/OPA).
Do not start with a plugin framework or multiple policy formats. Add those only
when the simple severity gate has real users and clear extension points.

## Validation and dependencies

- Add an offline `validate` command after the API and scan paths are stable.
- Evaluate the standalone `scheck` crate for local SBOM/CSAF rule validation,
  reusing Trustify's rule semantics where practical without depending on
  Trustify's application crates.
- Add CSAF structural/semantic validation as a separate increment. Evaluate
  `scm-rs` crates such as `csaf-rs` and `csaf-walker` for the exact validation
  capability needed; verify crate availability, maintenance, API fit, and
  license compatibility before selecting dependencies.
- Use `packageurl` (from scm-rs) only if it materially helps local scan inputs;
  the initial server-backed SBOM path should avoid needless local format
  parsing dependencies.
- Keep dependencies narrow and avoid a general-purpose scanner framework until
  multiple concrete scan inputs require one.

## Suggested crate layout

```text
src/
  main.rs                 # process exit mapping
  lib.rs                  # crate entry points, if useful to consumers
  cli.rs                  # Clap definitions
  config.rs               # URL and auth configuration
  api/
    client.rs             # HTTP, auth, timeout, retry, response handling
    error.rs
    sbom.rs
    advisory.rs
    vulnerability.rs
    purl.rs
  commands/
    sbom.rs
    advisory.rs
    vulnerability.rs
    purl.rs
    scan.rs               # added with scan milestone
    validate.rs           # added with validation milestone
  output.rs               # JSON/table rendering
tests/
  cli.rs                  # command behavior against a mock HTTP server
  trustify.rs             # opt-in real-instance contract/smoke tests
```

Keep a single binary/library package for the initial releases. Split crates only
if the client API, scanner, or validator becomes independently reusable and the
split has a concrete maintenance benefit.

## Testing strategy

Every feature should have tests at its boundary:

- Unit tests for config precedence, URL/query construction, exit-code mapping,
  severity/policy decisions, and JSON/table rendering.
- Mock HTTP tests for the expected v3 path, encoded query, authentication
  header, pagination, non-success response handling, and server JSON parsing.
- Black-box CLI tests for help/argument behavior, stdout/stderr separation,
  output formats, and CI gate exit codes.
- Optional live tests against `TRUSTIFY_TEST_URL` for v3 contract checks. These
  should use known fixtures and be separate from the fast default test suite.
- Add a container-based integration profile once the real API test needs are
  settled: run a pinned Trustify image with its required database/auth setup,
  wait for readiness, load a small fixture, run the CLI, and tear the stack
  down. Reuse the Trustify project's supported development/test setup instead
  of maintaining a second server configuration.

## Delivery roadmap

### P0 — project foundation

Create the `trusty-cli` package and `trusty` binary, establish formatting,
linting, unit/CLI test commands, and publish-ready crate metadata. No container
image yet.

### P1 — Trustify v3 browse and search

Implement URL/auth configuration, shared HTTP client, list/get/search for the
initial entities, JSON/table output, and mock-backed endpoint tests. Verify all
routes and query semantics against the current OpenAPI contract.

### P2 — SBOM scan and CI gate

Implement local SPDX/CycloneDX SBOM scan through v3 PURL extraction and
vulnerability analysis, stable JSON output, `--fail-on`, exit codes, and
fixture-backed policy tests. Add opt-in live Trustify coverage.

### P3 — local validation and policy growth

Add scheck validation and CSAF validation after dependency and API review. Grow
the CI policy surface only in response to concrete requirements; consider
SARIF/JUnit and license policies here.

### P4 — broader scan inputs

Add directory, lockfile, registry, and OCI inputs incrementally. Reuse suitable
scm-rs/cataloger crates where they provide tested functionality; each input
must have a clear support boundary and fixture-based tests.

### P5 — distribution

Publish the crate and binary through crates.io/releases. Add a non-root,
versioned container image and publish the same build to Quay, GitHub Container
Registry (`ghcr.io`), and Docker Hub (`docker.io`) from release automation.
Document tags and architecture support. Keep the image pipeline independent
from the core CLI test suite.

## First implementation checkpoint

The first code increment should complete P0 and the smallest useful slice of
P1: `trusty --help`, `trusty sbom list`, and `trusty sbom get`, with URL/auth
configuration, JSON output, mock HTTP tests, and no dependency on a running
Trustify instance for the default test command.
