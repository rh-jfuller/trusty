# Releasing trusty-cli

## Prerequisites

- Push access to this repository
- A `CARGO_REGISTRY_TOKEN` secret configured in GitHub Actions
- Optional: a `crates-io` GitHub environment with deployment protection rules
- The required `trustify-client` version already published to crates.io

## Release process

### 1. Prepare and merge a release change

Update the package version in the root `Cargo.toml`:

```toml
[package]
version = "0.2.0"
```

Run the checks locally and merge the version bump:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo publish --locked --dry-run
```

The CLI consumes `trustify-client` from crates.io. If a release updates this
dependency to a version that is not published yet, publish that version first
and update the version requirement here before releasing `trusty-cli`.

### 2. Tag and push

Create a tag matching the package version and push it:

```sh
git tag v0.2.0
git push origin main v0.2.0
```

Prerelease tags such as `v0.2.0-rc.1` are also validated. The tag version must
match the version in `Cargo.toml`.

### 3. Automatic validation and publishing

Pushing a `v*` tag triggers `.github/workflows/release.yml`:

| Job | What it does |
| --- | --- |
| `init` | Extracts the tag version and identifies stable releases |
| `check` | Verifies the package version, runs formatting, Clippy and tests, then runs `cargo publish --dry-run` |
| `publish` | Publishes stable releases to crates.io; skipped for prereleases |

Check the Actions run and verify the published package at
[crates.io/crates/trusty-cli](https://crates.io/crates/trusty-cli).

## Secrets

| Secret | Where to set it | Purpose |
| --- | --- | --- |
| `CARGO_REGISTRY_TOKEN` | Repository or `crates-io` environment secrets | Authorizes publishing; create it at [crates.io/settings/tokens](https://crates.io/settings/tokens) |
| `GITHUB_TOKEN` | Provided automatically | Not required by this workflow |

## Prereleases

Push a matching prerelease tag, for example:

```sh
git tag v0.2.0-rc.1
git push origin v0.2.0-rc.1
```

Prerelease tags run all validation and packaging checks but do not publish to
crates.io. Publish the stable version with a new matching version bump and tag.

## Troubleshooting

**Version mismatch:** Update `Cargo.toml` or recreate the tag so both versions
match. Do not reuse a published version.

**Publish or dry-run fails resolving `trustify-client`:** Ensure the version
required by `Cargo.toml` has been published to crates.io and that the version
requirement here matches it.

**crates.io authentication fails:** Check that `CARGO_REGISTRY_TOKEN` is
configured for the `crates-io` environment and has permission to publish
`trusty-cli`.
