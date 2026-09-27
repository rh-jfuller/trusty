use std::{collections::BTreeMap, env, fs, io::ErrorKind, path::PathBuf};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};

use crate::{api::ListResource, output::tui::ThemeMode};

pub const DEFAULT_PAGE_SIZE: u32 = 20;
pub const MAX_PAGE_SIZE: u32 = 1000;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct AppSettings {
    pub theme: ThemeMode,
    pub page_size: u32,
    default_sorts: BTreeMap<String, String>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            theme: ThemeMode::default(),
            page_size: DEFAULT_PAGE_SIZE,
            default_sorts: [
                ("sbom", "published:desc"),
                ("vulnerability", "published:desc"),
                ("advisory", "published:desc"),
                ("exploit", "date_reported:desc"),
                ("license", "license:asc"),
                ("package", "name:asc"),
                ("product", "name:asc"),
                ("weakness", "id:asc"),
                ("organization", "name:asc"),
            ]
            .into_iter()
            .map(|(resource, sort)| (resource.to_owned(), sort.to_owned()))
            .collect(),
        }
    }
}

impl AppSettings {
    pub fn load() -> anyhow::Result<Self> {
        Self::load_from(&Self::config_path())
    }

    fn load_from(path: &std::path::Path) -> anyhow::Result<Self> {
        match fs::read_to_string(path) {
            Ok(contents) => {
                let settings: Self = serde_json::from_str(&contents)
                    .with_context(|| format!("reading Trusty settings from {}", path.display()))?;
                settings.validate()?;
                Ok(settings)
            }
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error)
                .with_context(|| format!("reading Trusty settings from {}", path.display())),
        }
    }

    pub fn save(&self) -> anyhow::Result<()> {
        self.save_to(&Self::config_path())
    }

    fn save_to(&self, path: &std::path::Path) -> anyhow::Result<()> {
        self.validate()?;
        let parent = path
            .parent()
            .context("Trusty settings path has no parent")?;
        fs::create_dir_all(parent)
            .with_context(|| format!("creating Trusty config directory {}", parent.display()))?;
        let contents = serde_json::to_vec_pretty(self).context("serializing Trusty settings")?;
        fs::write(path, contents)
            .with_context(|| format!("writing Trusty settings to {}", path.display()))
    }

    pub fn config_path() -> PathBuf {
        let base = env::var_os("XDG_CONFIG_HOME")
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                #[cfg(windows)]
                if let Some(path) = env::var_os("APPDATA").filter(|path| !path.is_empty()) {
                    return Some(PathBuf::from(path));
                }
                env::var_os("HOME")
                    .filter(|path| !path.is_empty())
                    .map(|path| PathBuf::from(path).join(".config"))
            })
            .unwrap_or_else(|| {
                env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .join("config")
            });
        base.join("trusty").join("config.json")
    }

    pub fn sort_value(&self, resource: ListResource) -> &str {
        self.default_sorts
            .get(resource_key(resource))
            .map(String::as_str)
            .unwrap_or_else(|| built_in_sort(resource))
    }

    pub fn default_sort(&self, resource: ListResource) -> Option<&str> {
        let sort = self.sort_value(resource);
        (!sort.trim().is_empty()).then_some(sort)
    }

    pub fn set_sort(&mut self, resource: ListResource, sort: String) {
        self.default_sorts
            .insert(resource_key(resource).to_owned(), sort);
    }

    pub fn reset_sort(&mut self, resource: ListResource) {
        self.default_sorts.remove(resource_key(resource));
    }

    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            (1..=MAX_PAGE_SIZE).contains(&self.page_size),
            "rows per page must be between 1 and {MAX_PAGE_SIZE}"
        );
        Ok(())
    }
}

fn resource_key(resource: ListResource) -> &'static str {
    match resource {
        ListResource::Sbom => "sbom",
        ListResource::Vulnerability => "vulnerability",
        ListResource::Advisory => "advisory",
        ListResource::Exploit => "exploit",
        ListResource::License => "license",
        ListResource::Package => "package",
        ListResource::Product => "product",
        ListResource::Weakness => "weakness",
        ListResource::Organization => "organization",
    }
}

fn built_in_sort(resource: ListResource) -> &'static str {
    match resource {
        ListResource::Sbom | ListResource::Vulnerability | ListResource::Advisory => {
            "published:desc"
        }
        ListResource::Exploit => "date_reported:desc",
        ListResource::License => "license:asc",
        ListResource::Package | ListResource::Product | ListResource::Organization => "name:asc",
        ListResource::Weakness => "id:asc",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_sorts_are_defined_for_every_resource() {
        for resource in [
            ListResource::Sbom,
            ListResource::Vulnerability,
            ListResource::Advisory,
            ListResource::Exploit,
            ListResource::License,
            ListResource::Package,
            ListResource::Product,
            ListResource::Weakness,
            ListResource::Organization,
        ] {
            assert!(
                AppSettings::default().default_sort(resource).is_some(),
                "missing default sort for {resource:?}"
            );
        }
        assert_eq!(
            AppSettings::default().default_sort(ListResource::Sbom),
            Some("published:desc")
        );
    }

    #[test]
    fn settings_json_round_trips_theme_and_custom_sorts() {
        let mut settings = AppSettings {
            theme: ThemeMode::Light,
            page_size: 50,
            ..AppSettings::default()
        };
        settings.set_sort(ListResource::Sbom, "ingested:desc".to_owned());
        settings.set_sort(ListResource::Product, String::new());

        let json = serde_json::to_string(&settings).expect("serialize settings");
        let restored: AppSettings = serde_json::from_str(&json).expect("parse settings");

        assert_eq!(restored.theme, ThemeMode::Light);
        assert_eq!(restored.page_size, 50);
        assert_eq!(
            restored.default_sort(ListResource::Sbom),
            Some("ingested:desc")
        );
        assert_eq!(restored.default_sort(ListResource::Product), None);
    }

    #[test]
    fn settings_save_and_load_from_the_config_file() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after UNIX epoch")
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "trusty-settings-{}-{nonce}.json",
            std::process::id()
        ));
        let mut settings = AppSettings::default();
        settings.set_sort(ListResource::Sbom, "ingested:desc".to_owned());

        settings.save_to(&path).expect("write settings file");
        let restored = AppSettings::load_from(&path).expect("read settings file");
        fs::remove_file(&path).expect("remove settings file");

        assert_eq!(
            restored.default_sort(ListResource::Sbom),
            Some("ingested:desc")
        );
        assert!(restored.default_sort(ListResource::Product).is_some());
    }
}
