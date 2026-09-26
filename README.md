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
```

In an interactive terminal, `sbom list` opens a pageable browser: `j`/`k` or
arrow keys move, Enter opens the selected SBOM, `/` searches, `n`/`p` change
pages, and `q` exits. When stdout or stdin is piped, output defaults to raw JSON;
`--format json` always selects that mode, and `--format tui` forces the browser
when attached to a terminal. The list columns are ID, name, published date,
package count, and suppliers.

Use `--token` or `TRUSTIFY_TOKEN` for a static bearer token. For OIDC
client-credentials authentication, set `ISSUER_URL`, `CLIENT_ID`, and
`CLIENT_SECRET` (or `--issuer-url`, `--client-id`, and `--client-secret`). The
CLI reads the issuer's `.well-known/openid-configuration` metadata to locate
the token endpoint, uses its advertised client authentication method, and
reacquires a client-credentials token once if Trustify returns HTTP 401.

Run `trusty --help` or `trusty sbom --help` for command options.

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
