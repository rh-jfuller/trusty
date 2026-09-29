use std::{
    collections::BTreeMap,
    fs,
    io::{stdin, stdout, Cursor, IsTerminal, Read},
    path::{Component, Path, PathBuf},
};

use anyhow::{bail, Context};
use clap::ValueEnum;
use flate2::read::GzDecoder;
use oci_client::{
    client::{ClientConfig, ClientProtocol},
    secrets::RegistryAuth,
    Client as OciClient, Reference,
};
use serde::Serialize;
use serde_json::Value;
use tar::Archive;
use walkdir::WalkDir;

use crate::{
    api::{self, ApiClient, ListParams},
    output,
};

const MAX_INPUT_SIZE: u64 = 256 * 1024 * 1024;
const MAX_LAYER_SIZE: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ScanFormat {
    Text,
    Json,
    Tui,
}

#[derive(Clone, Debug, Serialize)]
struct Package {
    purl: String,
    name: String,
    version: String,
}

#[derive(Debug)]
enum Target {
    Directory(PathBuf),
    Sbom(PathBuf),
    Purl(String),
    Component(String),
    Registry(String),
    OciArchive(PathBuf),
}

impl Target {
    fn parse(target: &str) -> anyhow::Result<Self> {
        if let Some(path) = target.strip_prefix("dir:") {
            let path = PathBuf::from(path);
            if !path.is_dir() {
                bail!("directory does not exist: {}", path.display());
            }
            return Ok(Self::Directory(path));
        }
        if let Some(path) = target.strip_prefix("sbom:") {
            let path = PathBuf::from(path);
            if !path.is_file() {
                bail!("SBOM file does not exist: {}", path.display());
            }
            return Ok(Self::Sbom(path));
        }
        if target.starts_with("pkg:") {
            validate_purl(target)?;
            return Ok(Self::Purl(target.to_owned()));
        }
        if let Some(name) = target
            .strip_prefix("name:")
            .or_else(|| target.strip_prefix("component:"))
        {
            if name.trim().is_empty() {
                bail!("component name must not be empty");
            }
            return Ok(Self::Component(name.trim().to_owned()));
        }
        if let Some(image) = target.strip_prefix("registry:") {
            if image.trim().is_empty() {
                bail!("container image reference must not be empty");
            }
            return Ok(Self::Registry(image.to_owned()));
        }
        if let Some(path) = target.strip_prefix("oci-archive:") {
            let path = PathBuf::from(path);
            if !path.is_file() {
                bail!("OCI archive does not exist: {}", path.display());
            }
            return Ok(Self::OciArchive(path));
        }

        let path = PathBuf::from(target);
        if path.is_dir() {
            return Ok(Self::Directory(path));
        }
        if path.is_file() {
            return Ok(Self::Sbom(path));
        }
        if target.contains('/') && !target.contains(' ') {
            return Ok(Self::Registry(target.to_owned()));
        }
        if !target.trim().is_empty() {
            return Ok(Self::Component(target.trim().to_owned()));
        }
        bail!("scan target must not be empty")
    }
}

pub async fn run(
    client: &ApiClient,
    target: Option<&str>,
    format: ScanFormat,
) -> anyhow::Result<()> {
    match format {
        ScanFormat::Text | ScanFormat::Json => {
            let target = target
                .filter(|target| !target.trim().is_empty())
                .context("scan target is required; use --format tui to enter one interactively")?;
            let result = scan_target(client, target).await?;
            match format {
                ScanFormat::Text => print_text_result(&result),
                ScanFormat::Json => output::print_json(&result)?,
                ScanFormat::Tui => unreachable!(),
            }
        }
        ScanFormat::Tui => {
            if !stdin().is_terminal() || !stdout().is_terminal() {
                bail!("scan TUI requires an interactive terminal");
            }
            let settings = crate::settings::AppSettings::load()?;
            let client = client.clone();
            output::tui::run_scan(
                target.unwrap_or_default().to_owned(),
                client.instance_label(),
                settings.theme,
                move |target| {
                    let client = client.clone();
                    async move { scan_target(&client, &target).await }
                },
            )
            .await?;
        }
    }
    Ok(())
}

async fn scan_target(client: &ApiClient, target: &str) -> anyhow::Result<Value> {
    let parsed = Target::parse(target)?;
    let packages = match &parsed {
        Target::Directory(path) => catalog_directory(path)?,
        Target::Sbom(path) => catalog_sbom_file(path)?,
        Target::Purl(purl) => vec![package_from_purl(purl)],
        Target::Component(name) => resolve_component(client, name).await?,
        Target::Registry(image) => scan_registry(image).await?,
        Target::OciArchive(path) => scan_oci_archive(path)?,
    };
    let packages = deduplicate_packages(packages);
    if packages.is_empty() {
        bail!("no versioned PURLs found for scan target '{target}'");
    }

    let purls: Vec<_> = packages
        .iter()
        .filter(|package| !package.version.is_empty())
        .map(|package| package.purl.clone())
        .collect();
    if purls.is_empty() {
        bail!("no versioned PURLs found for scan target '{target}'");
    }
    let analysis = api::vulnerability::analyze(client, &purls).await?;
    let result = serde_json::json!({
        "target": target,
        "package_count": packages.len(),
        "analyzed_package_count": purls.len(),
        "packages": packages,
        "analysis": analysis,
    });

    Ok(result)
}

async fn resolve_component(client: &ApiClient, name: &str) -> anyhow::Result<Vec<Package>> {
    let query = format!("name~{}", escape_query_value(name));
    let response = api::package::search(
        client,
        &ListParams {
            query: Some(query),
            limit: Some(1000),
            ..ListParams::default()
        },
    )
    .await?;

    let mut purls = Vec::new();
    collect_purls(&response, &mut purls);
    let packages = purls
        .into_iter()
        .filter(|purl| purl_matches_component(purl, name))
        .map(|purl| package_from_purl(&purl))
        .collect();
    Ok(deduplicate_packages(packages))
}

fn purl_matches_component(purl: &str, requested_name: &str) -> bool {
    let without_scheme = purl.strip_prefix("pkg:").unwrap_or(purl);
    let without_subpath = without_scheme.split('#').next().unwrap_or(without_scheme);
    let without_qualifiers = without_subpath.split('?').next().unwrap_or(without_subpath);
    let package_path = without_qualifiers
        .split_once('/')
        .map(|(_, path)| path)
        .unwrap_or(without_qualifiers);
    let package_path = package_path
        .rsplit_once('@')
        .map(|(path, _)| path)
        .unwrap_or(package_path)
        .replace("%40", "@");
    let requested_name = requested_name.trim().replace("%40", "@");
    package_path.eq_ignore_ascii_case(&requested_name)
        || package_path
            .rsplit('/')
            .next()
            .is_some_and(|component| component.eq_ignore_ascii_case(&requested_name))
}

fn catalog_directory(root: &Path) -> anyhow::Result<Vec<Package>> {
    let mut packages = Vec::new();
    let walker = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            entry.depth() == 0
                || !entry.file_type().is_dir()
                || !matches!(
                    entry.file_name().to_str(),
                    Some(".git" | "node_modules" | "target" | "vendor")
                )
        });

    for entry in walker {
        let entry = match entry {
            Ok(entry) if entry.file_type().is_file() => entry,
            Ok(_) => continue,
            Err(error) => {
                tracing::debug!(%error, "skipping unreadable directory entry");
                continue;
            }
        };
        let path = entry.path();
        let path_string = path.to_string_lossy();
        if path_string.ends_with("var/lib/dpkg/status") {
            packages.extend(catalog_dpkg_status(path)?);
            continue;
        }
        if path_string.ends_with("lib/apk/db/installed") {
            packages.extend(catalog_apk_installed(path)?);
            continue;
        }
        match entry.file_name().to_str().unwrap_or_default() {
            "Cargo.lock" => packages.extend(catalog_cargo_lock(path)?),
            "package-lock.json" => packages.extend(catalog_npm_lock(path)?),
            "go.sum" => packages.extend(catalog_go_sum(path)?),
            "requirements.txt" => packages.extend(catalog_requirements(path)?),
            "pyproject.toml" => packages.extend(catalog_pyproject(path)?),
            "poetry.lock" | "uv.lock" => packages.extend(catalog_python_lock(path)?),
            "Pipfile.lock" => packages.extend(catalog_pipfile_lock(path)?),
            "gradle.lockfile" => packages.extend(catalog_gradle_lock(path)?),
            name if name.ends_with(".rpm") => packages.extend(catalog_rpm_filename(path)),
            name if name.ends_with(".json") => {
                if let Ok(value) = read_json(path) {
                    if is_sbom(&value) {
                        packages.extend(extract_sbom_packages(&value));
                    }
                }
            }
            _ => {}
        }
    }

    Ok(deduplicate_packages(packages))
}

fn catalog_sbom_file(path: &Path) -> anyhow::Result<Vec<Package>> {
    let value = read_json(path).with_context(|| {
        format!(
            "could not parse SBOM '{}'; SPDX and CycloneDX JSON are supported",
            path.display()
        )
    })?;
    if !is_sbom(&value) {
        bail!(
            "'{}' is not a recognized SPDX or CycloneDX JSON SBOM",
            path.display()
        );
    }
    Ok(deduplicate_packages(extract_sbom_packages(&value)))
}

fn read_json(path: &Path) -> anyhow::Result<Value> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_INPUT_SIZE {
        bail!(
            "{} exceeds the {} MiB input limit",
            path.display(),
            MAX_INPUT_SIZE / 1024 / 1024
        );
    }
    let data = fs::read(path)?;
    Ok(serde_json::from_slice(&data)?)
}

fn is_sbom(value: &Value) -> bool {
    value.get("bomFormat").and_then(Value::as_str) == Some("CycloneDX")
        || value.get("spdxVersion").is_some()
        || value.get("@graph").is_some()
        || value.get("type").and_then(Value::as_str) == Some("SpdxDocument")
}

fn extract_sbom_packages(value: &Value) -> Vec<Package> {
    fn visit(value: &Value, packages: &mut Vec<Package>) {
        match value {
            Value::Array(items) => items.iter().for_each(|item| visit(item, packages)),
            Value::Object(object) => {
                let name = object
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let version = object
                    .get("version")
                    .or_else(|| object.get("versionInfo"))
                    .or_else(|| object.get("software_packageVersion"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if let Some(purl) = object.get("purl").and_then(Value::as_str) {
                    if purl.starts_with("pkg:") {
                        packages.push(Package {
                            purl: purl.to_owned(),
                            name: name.to_owned(),
                            version: version.to_owned(),
                        });
                    }
                }
                for field in ["externalRefs", "externalIdentifier"] {
                    if let Some(references) = object.get(field).and_then(Value::as_array) {
                        for reference in references {
                            let purl_type = reference
                                .get("referenceType")
                                .or_else(|| reference.get("externalIdentifierType"))
                                .and_then(Value::as_str);
                            let purl = reference
                                .get("referenceLocator")
                                .or_else(|| reference.get("identifier"))
                                .and_then(Value::as_str);
                            if purl_type.is_some_and(|kind| kind.eq_ignore_ascii_case("purl"))
                                && purl.is_some_and(|purl| purl.starts_with("pkg:"))
                            {
                                packages.push(Package {
                                    purl: purl.unwrap().to_owned(),
                                    name: name.to_owned(),
                                    version: version.to_owned(),
                                });
                            }
                        }
                    }
                }
                object
                    .iter()
                    .filter(|(key, _)| {
                        !matches!(key.as_str(), "externalRefs" | "externalIdentifier")
                    })
                    .for_each(|(_, child)| visit(child, packages));
            }
            _ => {}
        }
    }

    let mut packages = Vec::new();
    visit(value, &mut packages);
    packages
}

fn catalog_cargo_lock(path: &Path) -> anyhow::Result<Vec<Package>> {
    let content = read_text(path)?;
    let lock: toml::Value = toml::from_str(&content)
        .with_context(|| format!("invalid Cargo lockfile '{}'", path.display()))?;
    let packages = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|package| {
            package
                .get("source")
                .and_then(toml::Value::as_str)
                .is_some_and(|source| source.starts_with("registry+"))
        })
        .filter_map(|package| {
            Some(Package {
                purl: format!(
                    "pkg:cargo/{}@{}",
                    package.get("name")?.as_str()?,
                    package.get("version")?.as_str()?
                ),
                name: package.get("name")?.as_str()?.to_owned(),
                version: package.get("version")?.as_str()?.to_owned(),
            })
        })
        .collect();
    Ok(packages)
}

fn catalog_npm_lock(path: &Path) -> anyhow::Result<Vec<Package>> {
    let value = read_json(path)?;
    let mut packages = Vec::new();
    if let Some(entries) = value.get("packages").and_then(Value::as_object) {
        for (key, entry) in entries {
            let Some(package_path) = key.rsplit("node_modules/").next() else {
                continue;
            };
            if package_path.is_empty() {
                continue;
            }
            let name = if package_path.starts_with('@') {
                package_path
                    .split('/')
                    .take(2)
                    .collect::<Vec<_>>()
                    .join("/")
            } else {
                package_path
                    .split('/')
                    .next()
                    .unwrap_or_default()
                    .to_owned()
            };
            if let (Some(version), Some(purl_name)) = (
                entry.get("version").and_then(Value::as_str),
                npm_purl_name(&name),
            ) {
                packages.push(Package {
                    purl: format!("pkg:npm/{purl_name}@{version}"),
                    name,
                    version: version.to_owned(),
                });
            }
        }
    } else if let Some(dependencies) = value.get("dependencies") {
        fn visit_dependencies(dependencies: &Value, packages: &mut Vec<Package>) {
            let Some(dependencies) = dependencies.as_object() else {
                return;
            };
            for (name, dependency) in dependencies {
                if let (Some(version), Some(purl_name)) = (
                    dependency.get("version").and_then(Value::as_str),
                    npm_purl_name(name),
                ) {
                    packages.push(Package {
                        purl: format!("pkg:npm/{purl_name}@{version}"),
                        name: name.clone(),
                        version: version.to_owned(),
                    });
                }
                visit_dependencies(&dependency["dependencies"], packages);
            }
        }
        visit_dependencies(dependencies, &mut packages);
    }
    Ok(packages)
}

fn npm_purl_name(name: &str) -> Option<String> {
    if let Some((scope, package)) = name.strip_prefix('@').and_then(|name| name.split_once('/')) {
        Some(format!("%40{scope}/{package}"))
    } else if !name.is_empty() {
        Some(name.to_owned())
    } else {
        None
    }
}

fn catalog_go_sum(path: &Path) -> anyhow::Result<Vec<Package>> {
    let content = read_text(path)?;
    let packages = content
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            let version = fields.next()?;
            let version = version.strip_suffix("/go.mod").unwrap_or(version);
            if version.is_empty() || version.starts_with("h1:") {
                return None;
            }
            let purl_name = go_purl_name(name);
            Some(Package {
                purl: format!("pkg:golang/{purl_name}@{version}"),
                name: name.to_owned(),
                version: version.to_owned(),
            })
        })
        .collect();
    Ok(packages)
}

fn go_purl_name(name: &str) -> String {
    let mut encoded = String::new();
    for character in name.chars() {
        if character.is_ascii_uppercase() {
            encoded.push('!');
            encoded.push(character.to_ascii_lowercase());
        } else {
            encoded.push(character);
        }
    }
    encoded
}

fn catalog_requirements(path: &Path) -> anyhow::Result<Vec<Package>> {
    let content = read_text(path)?;
    Ok(parse_requirements(&content))
}

fn parse_requirements(content: &str) -> Vec<Package> {
    let packages = content
        .lines()
        .filter_map(|line| {
            let line = line.split('#').next()?.trim();
            if line.is_empty() || line.starts_with('-') || line.contains(" @ ") {
                return None;
            }
            let (name, version) = line.split_once("===").or_else(|| line.split_once("=="))?;
            let name = name
                .split('[')
                .next()
                .unwrap_or(name)
                .trim()
                .to_ascii_lowercase()
                .replace('_', "-");
            let version = version.split(';').next()?.trim();
            if name.is_empty() || version.is_empty() || version.contains(',') {
                return None;
            }
            Some(Package {
                purl: format!("pkg:pypi/{name}@{version}"),
                name,
                version: version.to_owned(),
            })
        })
        .collect();
    packages
}

fn catalog_pyproject(path: &Path) -> anyhow::Result<Vec<Package>> {
    let content = read_text(path)?;
    let project: toml::Value = toml::from_str(&content)
        .with_context(|| format!("invalid Python project file '{}'", path.display()))?;
    let mut packages = Vec::new();
    if let Some(dependencies) = project
        .get("project")
        .and_then(|project| project.get("dependencies"))
        .and_then(toml::Value::as_array)
    {
        let lines = dependencies
            .iter()
            .filter_map(toml::Value::as_str)
            .collect::<Vec<_>>()
            .join("\n");
        packages.extend(parse_requirements(&lines));
    }
    if let Some(dependencies) = project
        .get("tool")
        .and_then(|tool| tool.get("poetry"))
        .and_then(|poetry| poetry.get("dependencies"))
        .and_then(toml::Value::as_table)
    {
        for (name, requirement) in dependencies {
            if name.eq_ignore_ascii_case("python") {
                continue;
            }
            let version = requirement
                .as_str()
                .or_else(|| requirement.get("version").and_then(toml::Value::as_str))
                .unwrap_or_default();
            if let Some(version) = pinned_python_version(version) {
                let name = normalize_python_name(name);
                packages.push(Package {
                    purl: format!("pkg:pypi/{name}@{version}"),
                    name,
                    version: version.to_owned(),
                });
            }
        }
    }
    Ok(packages)
}

fn catalog_python_lock(path: &Path) -> anyhow::Result<Vec<Package>> {
    let content = read_text(path)?;
    let lock: toml::Value = toml::from_str(&content)
        .with_context(|| format!("invalid Python lockfile '{}'", path.display()))?;
    Ok(lock
        .get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|package| {
            let name = normalize_python_name(package.get("name")?.as_str()?);
            let version = package.get("version")?.as_str()?;
            Some(Package {
                purl: format!("pkg:pypi/{name}@{version}"),
                name,
                version: version.to_owned(),
            })
        })
        .collect())
}

fn catalog_pipfile_lock(path: &Path) -> anyhow::Result<Vec<Package>> {
    let lock = read_json(path)?;
    let mut packages = Vec::new();
    for section in ["default", "develop"] {
        if let Some(dependencies) = lock.get(section).and_then(Value::as_object) {
            for (name, dependency) in dependencies {
                let version = dependency
                    .as_str()
                    .or_else(|| dependency.get("version").and_then(Value::as_str))
                    .and_then(|version| version.strip_prefix("=="));
                if let Some(version) = version {
                    let name = normalize_python_name(name);
                    packages.push(Package {
                        purl: format!("pkg:pypi/{name}@{version}"),
                        name,
                        version: version.to_owned(),
                    });
                }
            }
        }
    }
    Ok(packages)
}

fn pinned_python_version(requirement: &str) -> Option<&str> {
    requirement
        .strip_prefix("===")
        .or_else(|| requirement.strip_prefix("=="))
}

fn normalize_python_name(name: &str) -> String {
    name.to_ascii_lowercase().replace('_', "-")
}

fn catalog_gradle_lock(path: &Path) -> anyhow::Result<Vec<Package>> {
    let content = read_text(path)?;
    Ok(content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (coordinate, _) = line.split_once('=')?;
            let mut coordinate = coordinate.splitn(3, ':');
            let group = coordinate.next()?;
            let name = coordinate.next()?;
            let version = coordinate.next()?;
            if group.is_empty() || name.is_empty() || version.is_empty() {
                return None;
            }
            Some(Package {
                purl: format!("pkg:maven/{group}/{name}@{version}"),
                name: name.to_owned(),
                version: version.to_owned(),
            })
        })
        .collect())
}

fn catalog_dpkg_status(path: &Path) -> anyhow::Result<Vec<Package>> {
    let content = read_text(path)?;
    let mut packages = Vec::new();
    for block in content.split("\n\n") {
        let mut name = None;
        let mut version = None;
        let mut architecture = None;
        let mut installed = false;
        for line in block.lines() {
            if let Some(value) = line.strip_prefix("Package: ") {
                name = Some(value.trim());
            } else if let Some(value) = line.strip_prefix("Version: ") {
                version = Some(value.trim());
            } else if let Some(value) = line.strip_prefix("Architecture: ") {
                architecture = Some(value.trim());
            } else if line == "Status: install ok installed" {
                installed = true;
            }
        }
        if installed {
            if let (Some(name), Some(version)) = (name, version) {
                let qualifier = architecture
                    .filter(|architecture| !architecture.is_empty())
                    .map(|architecture| format!("?arch={architecture}"))
                    .unwrap_or_default();
                packages.push(Package {
                    purl: format!("pkg:deb/debian/{name}@{version}{qualifier}"),
                    name: name.to_owned(),
                    version: version.to_owned(),
                });
            }
        }
    }
    Ok(packages)
}

fn catalog_apk_installed(path: &Path) -> anyhow::Result<Vec<Package>> {
    let content = read_text(path)?;
    let mut packages = Vec::new();
    for block in content.split("\n\n") {
        let mut name = None;
        let mut version = None;
        let mut architecture = None;
        for line in block.lines() {
            if let Some(value) = line.strip_prefix("P:") {
                name = Some(value.trim());
            } else if let Some(value) = line.strip_prefix("V:") {
                version = Some(value.trim());
            } else if let Some(value) = line.strip_prefix("A:") {
                architecture = Some(value.trim());
            }
        }
        if let (Some(name), Some(version)) = (name, version) {
            let qualifier = architecture
                .filter(|architecture| !architecture.is_empty())
                .map(|architecture| format!("?arch={architecture}"))
                .unwrap_or_default();
            packages.push(Package {
                purl: format!("pkg:apk/alpine/{name}@{version}{qualifier}"),
                name: name.to_owned(),
                version: version.to_owned(),
            });
        }
    }
    Ok(packages)
}

fn catalog_rpm_filename(path: &Path) -> Vec<Package> {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Vec::new();
    };
    let Some(stem) = file_name.strip_suffix(".rpm") else {
        return Vec::new();
    };
    let Some((version_release, arch)) = stem.rsplit_once('.') else {
        return Vec::new();
    };
    let mut version_parts = version_release.rsplitn(3, '-');
    let Some(release) = version_parts.next() else {
        return Vec::new();
    };
    let Some(version) = version_parts.next() else {
        return Vec::new();
    };
    let Some(name) = version_parts.next() else {
        return Vec::new();
    };
    vec![Package {
        purl: format!("pkg:rpm/{name}@{version}-{release}?arch={arch}"),
        name: name.to_owned(),
        version: format!("{version}-{release}"),
    }]
}

fn read_text(path: &Path) -> anyhow::Result<String> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_INPUT_SIZE {
        bail!(
            "{} exceeds the {} MiB input limit",
            path.display(),
            MAX_INPUT_SIZE / 1024 / 1024
        );
    }
    fs::read_to_string(path).with_context(|| format!("could not read '{}'", path.display()))
}

async fn scan_registry(image: &str) -> anyhow::Result<Vec<Package>> {
    let reference: Reference = image
        .parse()
        .with_context(|| format!("invalid container image reference '{image}'"))?;
    let client = OciClient::new(ClientConfig {
        protocol: ClientProtocol::Https,
        ..Default::default()
    });
    let auth = RegistryAuth::Anonymous;
    let (manifest, digest) = client
        .pull_image_manifest(&reference, &auth)
        .await
        .context("failed to pull container image manifest")?;

    let attachment = format!("{}.sbom", digest.replace(':', "-"));
    let sbom_reference = Reference::with_tag(
        reference.registry().to_owned(),
        reference.repository().to_owned(),
        attachment,
    );
    if let Ok((sbom_manifest, _)) = client.pull_image_manifest(&sbom_reference, &auth).await {
        if let Some(layer) = sbom_manifest.layers.first() {
            let layer_size = u64::try_from(layer.size).context("invalid SBOM attachment size")?;
            if layer_size > MAX_INPUT_SIZE {
                tracing::warn!("container SBOM attachment exceeds the input-size limit");
            } else {
                let mut bytes = Vec::new();
                if client
                    .pull_blob(&sbom_reference, layer, &mut bytes)
                    .await
                    .is_ok()
                {
                    if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                        if is_sbom(&value) {
                            return Ok(deduplicate_packages(extract_sbom_packages(&value)));
                        }
                    }
                }
            }
        }
    }

    let temp = tempfile::tempdir().context("could not create temporary image directory")?;
    let mut extracted_size = 0;
    for (index, layer) in manifest.layers.iter().enumerate() {
        if !layer.media_type.contains("tar") {
            continue;
        }
        let layer_size = u64::try_from(layer.size)
            .with_context(|| format!("invalid size for container layer {index}"))?;
        if layer_size > MAX_LAYER_SIZE {
            bail!("container layer {index} exceeds the 2 GiB compressed-size limit");
        }
        let mut bytes = Vec::new();
        client
            .pull_blob(&reference, layer, &mut bytes)
            .await
            .with_context(|| format!("failed to download container layer {index}"))?;
        extract_layer(
            &bytes,
            layer.media_type.contains("gzip"),
            temp.path(),
            &mut extracted_size,
        )
        .with_context(|| format!("failed to extract container layer {index}"))?;
    }
    catalog_directory(temp.path())
}

fn scan_oci_archive(path: &Path) -> anyhow::Result<Vec<Package>> {
    let outer = tempfile::tempdir().context("could not create temporary OCI archive directory")?;
    let file = fs::File::open(path)?;
    let mut archive = Archive::new(file);
    let mut extracted_size = 0;
    unpack_archive(&mut archive, outer.path(), &mut extracted_size)
        .context("failed to extract OCI archive")?;

    let index: Value = serde_json::from_slice(
        &fs::read(outer.path().join("index.json")).context("OCI archive is missing index.json")?,
    )
    .context("OCI archive index.json is invalid")?;
    let digest = index
        .get("manifests")
        .and_then(Value::as_array)
        .and_then(|manifests| manifests.first())
        .and_then(|manifest| manifest.get("digest"))
        .and_then(Value::as_str)
        .context("OCI archive has no image manifest")?;
    let manifest_path = blob_path(outer.path(), digest)?;
    let manifest: Value = serde_json::from_slice(&fs::read(manifest_path)?)
        .context("OCI image manifest is invalid")?;
    let layers = manifest
        .get("layers")
        .and_then(Value::as_array)
        .context("OCI image manifest has no layers")?;

    for layer in layers {
        let media_type = layer
            .get("mediaType")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let digest = layer
            .get("digest")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if media_type.contains("sbom")
            || media_type.contains("spdx")
            || media_type.contains("cyclonedx")
        {
            let path = blob_path(outer.path(), digest)?;
            if let Ok(value) = read_json(&path) {
                if is_sbom(&value) {
                    return Ok(deduplicate_packages(extract_sbom_packages(&value)));
                }
            }
        }
    }

    let root = tempfile::tempdir().context("could not create temporary image filesystem")?;
    extracted_size = 0;
    for layer in layers {
        let media_type = layer
            .get("mediaType")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let digest = layer
            .get("digest")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !media_type.contains("tar") {
            continue;
        }
        let layer_path = blob_path(outer.path(), digest)?;
        if fs::metadata(&layer_path)?.len() > MAX_LAYER_SIZE {
            bail!("OCI archive layer exceeds the 2 GiB compressed-size limit");
        }
        let bytes = fs::read(layer_path)?;
        extract_layer(
            &bytes,
            media_type.contains("gzip"),
            root.path(),
            &mut extracted_size,
        )?;
    }
    catalog_directory(root.path())
}

fn extract_layer(
    bytes: &[u8],
    gzip: bool,
    destination: &Path,
    total_size: &mut u64,
) -> anyhow::Result<()> {
    if gzip {
        let decoder = GzDecoder::new(Cursor::new(bytes));
        let mut archive = Archive::new(decoder);
        unpack_archive(&mut archive, destination, total_size)
    } else {
        let mut archive = Archive::new(Cursor::new(bytes));
        unpack_archive(&mut archive, destination, total_size)
    }
}

fn unpack_archive<R: Read>(
    archive: &mut Archive<R>,
    destination: &Path,
    total_size: &mut u64,
) -> anyhow::Result<()> {
    for entry in archive.entries().context("invalid tar archive")? {
        let mut entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                tracing::debug!(%error, "skipping invalid archive entry");
                continue;
            }
        };
        let path = match entry.path() {
            Ok(path) => path.into_owned(),
            Err(_) => continue,
        };
        if path.is_absolute()
            || path
                .components()
                .any(|component| component == Component::ParentDir)
        {
            tracing::warn!(path = %path.display(), "skipping archive path traversal");
            continue;
        }
        if path_has_symlink_parent(destination, &path)? {
            tracing::debug!(path = %path.display(), "skipping archive entry below a symlink");
            continue;
        }
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if let Some(deleted_name) = file_name.strip_prefix(".wh.") {
            let deleted = destination.join(path.with_file_name(deleted_name));
            if deleted.is_dir() {
                let _ = fs::remove_dir_all(deleted);
            } else {
                let _ = fs::remove_file(deleted);
            }
            continue;
        }
        *total_size = total_size.saturating_add(entry.size());
        if *total_size > MAX_LAYER_SIZE {
            bail!("extracted image data exceeds the 2 GiB limit");
        }
        let output_path = destination.join(&path);
        let is_directory = entry.header().entry_type().is_dir();
        match fs::symlink_metadata(&output_path) {
            Ok(metadata) if is_directory && metadata.is_dir() => {}
            Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(&output_path)?,
            Ok(_) => fs::remove_file(&output_path)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        entry
            .unpack_in(destination)
            .context("could not safely unpack archive entry")?;
    }
    Ok(())
}

fn path_has_symlink_parent(root: &Path, relative_path: &Path) -> std::io::Result<bool> {
    let mut parent = root.to_path_buf();
    let Some(parent_path) = relative_path.parent() else {
        return Ok(false);
    };
    for component in parent_path.components() {
        match component {
            Component::Normal(name) => parent.push(name),
            Component::CurDir => continue,
            _ => return Ok(true),
        }
        match fs::symlink_metadata(&parent) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

fn blob_path(root: &Path, digest: &str) -> anyhow::Result<PathBuf> {
    let (algorithm, hash) = digest.split_once(':').context("invalid OCI digest")?;
    if !algorithm
        .chars()
        .all(|character| character.is_ascii_alphanumeric())
        || !hash.chars().all(|character| character.is_ascii_hexdigit())
    {
        bail!("invalid OCI blob digest '{digest}'");
    }
    Ok(root.join("blobs").join(algorithm).join(hash))
}

fn collect_purls(value: &Value, purls: &mut Vec<String>) {
    match value {
        Value::String(value)
            if value.starts_with("pkg:") && !package_from_purl(value).version.is_empty() =>
        {
            purls.push(value.clone());
        }
        Value::Array(values) => values.iter().for_each(|value| collect_purls(value, purls)),
        Value::Object(values) => values
            .values()
            .for_each(|value| collect_purls(value, purls)),
        _ => {}
    }
}

fn package_from_purl(purl: &str) -> Package {
    let without_scheme = purl.strip_prefix("pkg:").unwrap_or(purl);
    let without_subpath = without_scheme.split('#').next().unwrap_or(without_scheme);
    let without_qualifiers = without_subpath.split('?').next().unwrap_or(without_subpath);
    let (path, version) = without_qualifiers
        .rsplit_once('@')
        .unwrap_or((without_qualifiers, ""));
    Package {
        purl: purl.to_owned(),
        name: path.rsplit('/').next().unwrap_or(path).to_owned(),
        version: version.to_owned(),
    }
}

fn deduplicate_packages(packages: Vec<Package>) -> Vec<Package> {
    let mut packages: BTreeMap<String, Package> = packages
        .into_iter()
        .filter(|package| package.purl.starts_with("pkg:"))
        .map(|package| (package.purl.clone(), package))
        .collect();
    packages.values_mut().for_each(|package| {
        if package.name.is_empty() || package.version.is_empty() {
            let parsed = package_from_purl(&package.purl);
            if package.name.is_empty() {
                package.name = parsed.name;
            }
            if package.version.is_empty() {
                package.version = parsed.version;
            }
        }
    });
    packages.into_values().collect()
}

fn validate_purl(purl: &str) -> anyhow::Result<()> {
    let Some((package_type, name)) = purl
        .strip_prefix("pkg:")
        .and_then(|value| value.split_once('/'))
    else {
        bail!("invalid Package URL '{purl}'; expected pkg:type/name@version");
    };
    if package_type.is_empty() || name.is_empty() {
        bail!("invalid Package URL '{purl}'; expected pkg:type/name@version");
    }
    Ok(())
}

fn escape_query_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(character, '&' | '|' | '=' | '!' | '~' | '>' | '<' | '\\') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

fn print_text_result(result: &Value) {
    let count = result
        .get("package_count")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let analyzed_count = result
        .get("analyzed_package_count")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    println!(
        "Scanned {count} package(s), {analyzed_count} analyzed for {}",
        result["target"]
    );
    let mut matches = 0;
    if let Some(analysis) = result.get("analysis").and_then(Value::as_object) {
        for (purl, item) in analysis {
            let Some(details) = item.get("details").and_then(Value::as_array) else {
                continue;
            };
            for detail in details {
                let identifier = detail
                    .get("identifier")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let title = detail
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let severity = detail
                    .pointer("/base_score/severity")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let statuses = detail.get("purl_statuses").and_then(Value::as_array);
                if let Some(statuses) = statuses {
                    for status in statuses {
                        let status_name = status
                            .get("status")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown");
                        println!("{purl}  {identifier}  {severity}  {status_name}  {title}");
                        matches += 1;
                    }
                } else {
                    println!("{purl}  {identifier}  {severity}  {title}");
                    matches += 1;
                }
            }
        }
    }
    if matches == 0 {
        println!("No known vulnerabilities found.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_parser_recognizes_requested_inputs() {
        assert!(matches!(
            Target::parse("pkg:cargo/serde@1.0").unwrap(),
            Target::Purl(_)
        ));
        assert!(matches!(
            Target::parse("name:serde").unwrap(),
            Target::Component(_)
        ));
        assert!(matches!(
            Target::parse("registry:quay.io/org/image:latest").unwrap(),
            Target::Registry(_)
        ));
        assert!(matches!(Target::parse(".").unwrap(), Target::Directory(_)));
    }

    #[test]
    fn extracts_cyclonedx_and_spdx_purls() {
        let cdx = serde_json::json!({
            "bomFormat": "CycloneDX",
            "components": [{"name": "serde", "version": "1.0", "purl": "pkg:cargo/serde@1.0"}]
        });
        assert_eq!(extract_sbom_packages(&cdx)[0].purl, "pkg:cargo/serde@1.0");

        let spdx = serde_json::json!({
            "spdxVersion": "SPDX-2.3",
            "packages": [{
                "name": "openssl",
                "versionInfo": "3.0.7",
                "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:rpm/openssl@3.0.7"}]
            }]
        });
        assert_eq!(
            extract_sbom_packages(&spdx)[0].purl,
            "pkg:rpm/openssl@3.0.7"
        );
    }

    #[test]
    fn parses_purls_with_namespace_qualifiers_and_subpaths() {
        let package = package_from_purl("pkg:maven/org.example/library@2.1?type=jar#source");
        assert_eq!(package.name, "library");
        assert_eq!(package.version, "2.1");
    }

    #[test]
    fn component_query_escapes_trustify_filter_metacharacters() {
        assert_eq!(escape_query_value("foo&bar|baz"), "foo\\&bar\\|baz");
    }

    #[test]
    fn component_name_matching_is_exact_and_handles_namespaces() {
        assert!(purl_matches_component(
            "pkg:maven/org.example/library@2.1",
            "library"
        ));
        assert!(purl_matches_component(
            "pkg:npm/%40acme/library@2.1",
            "@acme/library"
        ));
        assert!(!purl_matches_component(
            "pkg:maven/org.example/library-tools@2.1",
            "library"
        ));
    }

    #[test]
    fn catalogs_cargo_go_and_python_dependencies() {
        let directory = tempfile::tempdir().unwrap();

        let cargo_lock = directory.path().join("Cargo.lock");
        fs::write(
            &cargo_lock,
            "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
        )
        .unwrap();
        assert_eq!(
            catalog_cargo_lock(&cargo_lock).unwrap()[0].purl,
            "pkg:cargo/serde@1.0.0"
        );

        let go_sum = directory.path().join("go.sum");
        fs::write(
            &go_sum,
            "github.com/acme/lib v1.2.3 h1:hash\ngithub.com/acme/lib v1.2.3/go.mod h1:hash\n",
        )
        .unwrap();
        assert_eq!(
            catalog_go_sum(&go_sum).unwrap()[0].purl,
            "pkg:golang/github.com/acme/lib@v1.2.3"
        );

        let requirements = directory.path().join("requirements.txt");
        fs::write(&requirements, "Some_Package==2.4.1\nother>=1.0\n").unwrap();
        assert_eq!(
            catalog_requirements(&requirements).unwrap()[0].purl,
            "pkg:pypi/some-package@2.4.1"
        );
    }

    #[test]
    fn catalogs_python_and_gradle_lock_formats() {
        let directory = tempfile::tempdir().unwrap();
        let pyproject = directory.path().join("pyproject.toml");
        fs::write(
            &pyproject,
            "[project]\ndependencies = [\"requests==2.31.0\"]\n\n[tool.poetry.dependencies]\npython = \"^3.11\"\nflask = \"==3.0.0\"\n",
        )
        .unwrap();
        let packages = catalog_pyproject(&pyproject).unwrap();
        assert!(packages
            .iter()
            .any(|package| package.purl == "pkg:pypi/requests@2.31.0"));
        assert!(packages
            .iter()
            .any(|package| package.purl == "pkg:pypi/flask@3.0.0"));

        let gradle_lock = directory.path().join("gradle.lockfile");
        fs::write(&gradle_lock, "org.example:library:2.1=runtimeClasspath\n").unwrap();
        assert_eq!(
            catalog_gradle_lock(&gradle_lock).unwrap()[0].purl,
            "pkg:maven/org.example/library@2.1"
        );
    }

    #[test]
    fn catalogs_installed_dpkg_and_apk_packages() {
        let directory = tempfile::tempdir().unwrap();
        let dpkg_status = directory.path().join("status");
        fs::write(
            &dpkg_status,
            "Package: openssl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 3.0.7-1\n",
        )
        .unwrap();
        assert_eq!(
            catalog_dpkg_status(&dpkg_status).unwrap()[0].purl,
            "pkg:deb/debian/openssl@3.0.7-1?arch=amd64"
        );

        let apk_installed = directory.path().join("installed");
        fs::write(&apk_installed, "P:libcrypto3\nV:3.1.4-r0\nA:x86_64\n").unwrap();
        assert_eq!(
            catalog_apk_installed(&apk_installed).unwrap()[0].purl,
            "pkg:apk/alpine/libcrypto3@3.1.4-r0?arch=x86_64"
        );
    }

    #[test]
    fn scans_oci_archive_sbom_layers() {
        let directory = tempfile::tempdir().unwrap();
        let layout = directory.path().join("layout");
        let blobs = layout.join("blobs/sha256");
        fs::create_dir_all(&blobs).unwrap();

        let manifest_digest = "1111111111111111111111111111111111111111111111111111111111111111";
        let sbom_digest = "2222222222222222222222222222222222222222222222222222222222222222";
        let index_path = layout.join("index.json");
        let manifest_path = blobs.join(manifest_digest);
        let sbom_path = blobs.join(sbom_digest);
        fs::write(
            &index_path,
            serde_json::to_vec(&serde_json::json!({
                "manifests": [{"digest": format!("sha256:{manifest_digest}")}]
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            &manifest_path,
            serde_json::to_vec(&serde_json::json!({
                "layers": [{
                    "digest": format!("sha256:{sbom_digest}"),
                    "mediaType": "application/vnd.cyclonedx+json"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            &sbom_path,
            serde_json::to_vec(&serde_json::json!({
                "bomFormat": "CycloneDX",
                "components": [{"name": "serde", "version": "1.0.0", "purl": "pkg:cargo/serde@1.0.0"}]
            }))
            .unwrap(),
        )
        .unwrap();

        let archive_path = directory.path().join("image.tar");
        let mut archive = tar::Builder::new(fs::File::create(&archive_path).unwrap());
        archive
            .append_path_with_name(&index_path, "index.json")
            .unwrap();
        archive
            .append_path_with_name(&manifest_path, format!("blobs/sha256/{manifest_digest}"))
            .unwrap();
        archive
            .append_path_with_name(&sbom_path, format!("blobs/sha256/{sbom_digest}"))
            .unwrap();
        archive.finish().unwrap();

        let packages = scan_oci_archive(&archive_path).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].purl, "pkg:cargo/serde@1.0.0");
    }

    #[test]
    fn later_container_layers_replace_files_before_creating_hard_links() {
        let directory = tempfile::tempdir().unwrap();
        let mut first_layer = tar::Builder::new(Vec::new());
        let perl = b"old perl binary";
        let mut perl_header = tar::Header::new_gnu();
        perl_header.set_size(perl.len() as u64);
        first_layer
            .append_data(&mut perl_header, "usr/bin/perl", &perl[..])
            .unwrap();
        let perl_version = b"new perl binary";
        let mut perl_version_header = tar::Header::new_gnu();
        perl_version_header.set_size(perl_version.len() as u64);
        first_layer
            .append_data(
                &mut perl_version_header,
                "usr/bin/perl5.40.1",
                &perl_version[..],
            )
            .unwrap();
        let first_layer = first_layer.into_inner().unwrap();

        let mut second_layer = tar::Builder::new(Vec::new());
        let mut hard_link_header = tar::Header::new_gnu();
        hard_link_header.set_entry_type(tar::EntryType::Link);
        hard_link_header.set_size(0);
        second_layer
            .append_link(&mut hard_link_header, "usr/bin/perl5.40.1", "usr/bin/perl")
            .unwrap();
        let second_layer = second_layer.into_inner().unwrap();
        let mut verification = Archive::new(Cursor::new(&second_layer));
        let link_entry = verification.entries().unwrap().next().unwrap().unwrap();
        assert!(link_entry.header().entry_type().is_hard_link());
        assert_eq!(
            link_entry.link_name().unwrap().unwrap(),
            Path::new("usr/bin/perl")
        );

        let mut extracted_size = 0;
        extract_layer(&first_layer, false, directory.path(), &mut extracted_size).unwrap();
        assert!(directory.path().join("usr/bin/perl5.40.1").exists());
        extract_layer(&second_layer, false, directory.path(), &mut extracted_size).unwrap();

        assert_eq!(
            fs::read(directory.path().join("usr/bin/perl5.40.1")).unwrap(),
            b"old perl binary"
        );
    }
}
