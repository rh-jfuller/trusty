# trusty

Rust command-line client for Trustify. The package will be published as
[`trusty-cli`](https://crates.io/crates/trusty-cli) and installs the `trusty`
binary.

## Getting started

The API URL defaults to `http://localhost:8080/api/v3`. Set `TRUSTIFY_URL` or
pass `--url` to connect to another instance. Both a service root (for example,
`https://trustify.example`) and a v3 API root are accepted:

```shell
export TRUSTIFY_URL=https://trustify.example
trusty sbom list --limit 20
trusty sbom list --query 'name~openssl' --sort 'ingested:desc'
trusty sbom list --limit 20 --format json
trusty sbom get SBOM_ID
trusty vuln list --query 'title~openssl'
trusty vuln get CVE-2024-1234 --scores
trusty advisory list --query 'title~openssl'
trusty license list --query 'license~Apache'
trusty package search --query 'name~openssl'
trusty component get 'pkg:cargo/example@1.2.3'
```

`package` is also available as `component`. The vulnerability, advisory,
license, and package list/search commands accept `--query`, `--limit`,
`--offset`, and `--sort`.

Run `trusty` without a subcommand in an interactive terminal to open the main
entity menu. Choose SBOMs, vulnerabilities, advisories, licenses, or
packages/components to open that entity's browser. Leaving a browser returns to
the menu; `q` or `Esc` in the menu exits. Without an interactive terminal,
`trusty` prints help instead.

In an interactive terminal, list/search commands open a pageable row browser:
`j`/`k` or arrow keys move, Enter opens the selected record, `/` searches,
`n`/`p` change pages, and `q` leaves the browser. From the bare-command menu,
leaving the browser returns to the entity picker. SBOM rows show ID, name, published date,
package count, and suppliers; other resource rows show available summary fields.
Get commands show a detail view in an interactive terminal. When stdin or stdout
is piped, output defaults to raw JSON; `--format json` always selects JSON, and
`--format tui` forces the interactive view when attached to a terminal.

Use `-v` for informational logs, `-vv` for API operation details, `-vvv` for
request timings, and `-vvvv` for full response diagnostics. `--debug` enables the
same maximum detail. Logs go to stderr, keeping JSON stdout machine-readable,
and credential fields in diagnostic responses are redacted.

Use `--token` or `TRUSTIFY_TOKEN` for a static bearer token. For OIDC
client-credentials authentication, set `ISSUER_URL`, `CLIENT_ID`, and
`CLIENT_SECRET` (or `--issuer-url`, `--client-id`, and `--client-secret`). The
CLI reads the issuer's `.well-known/openid-configuration` metadata to locate
the token endpoint, uses its advertised client authentication method, and
reacquires a client-credentials token once if Trustify returns HTTP 401.

Run `trusty --help` or `trusty sbom --help` for command options.

## MCP server

Run `trusty mcp` to expose Trustify's read-only operations as Model Context
Protocol tools over stdio. MCP clients should launch `trusty` with `mcp` as its
argument and provide the same `TRUSTIFY_URL` and authentication environment
variables used by the CLI. For example:

```json
{
  "mcpServers": {
    "trusty": {
      "command": "/path/to/trusty",
      "args": ["mcp"],
      "env": {
        "TRUSTIFY_URL": "https://trustify.example/api/v3",
        "TRUSTIFY_TOKEN": "your-token"
      }
    }
  }
}
```

The server provides `list_sboms`, `get_sbom`, `list_advisories`,
`get_advisory`, `list_vulnerabilities`, `get_vulnerability`,
`search_packages`, `get_package`, and `list_licenses`. List/search tools accept
Trustify query expressions plus optional pagination and sorting arguments.
Protocol messages use stdout; diagnostic logs remain on stderr.

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
