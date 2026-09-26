use crossterm::event::KeyCode;
use serde_json::Value;

use crate::api::{sbom::ListParams, ListResource};

pub struct App {
    pub items: Vec<Value>,
    pub title: String,
    pub item_title: String,
    pub resource: Option<ListResource>,
    pub columns: Option<Vec<String>>,
    pub selected: usize,
    pub offset: u32,
    pub page_size: u32,
    pub total: Option<u64>,
    pub status: String,
    pub params: ListParams,
    pub search_input: Option<String>,
    pub screen: Screen,
}

pub enum Screen {
    List,
    Detail { item: Value, scroll: u16 },
}

#[derive(Debug, Eq, PartialEq)]
pub enum Action {
    None,
    Quit,
    NextPage,
    PreviousPage,
    OpenDetails,
    Search(Option<String>),
}

impl App {
    pub fn new(response: Value, params: ListParams, page_size: u32) -> anyhow::Result<Self> {
        Self::from_response(
            response,
            params,
            page_size,
            "SBOMs",
            "SBOM",
            Some(ListResource::Sbom),
            None,
        )
    }

    pub fn records(
        response: Value,
        params: ListParams,
        page_size: u32,
        title: &str,
        resource: ListResource,
    ) -> anyhow::Result<Self> {
        let items = response
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Trustify resource list response has no items array"))?;
        let columns = Some(record_columns(&items, resource));
        Self::from_response(
            response,
            params,
            page_size,
            title,
            title,
            Some(resource),
            columns,
        )
    }

    fn from_response(
        response: Value,
        mut params: ListParams,
        page_size: u32,
        title: &str,
        item_title: &str,
        resource: Option<ListResource>,
        columns: Option<Vec<String>>,
    ) -> anyhow::Result<Self> {
        let items = response
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Trustify list response has no items array"))?;
        let offset = params.offset.unwrap_or_default();
        params.limit = Some(page_size);

        Ok(Self {
            total: response.get("total").and_then(Value::as_u64),
            items,
            title: title.to_owned(),
            item_title: item_title.to_owned(),
            resource,
            columns,
            selected: 0,
            offset,
            page_size,
            status: String::new(),
            params,
            search_input: None,
            screen: Screen::List,
        })
    }

    pub fn detail_as(title: &str, item: Value) -> Self {
        let resource = match title.to_ascii_lowercase().as_str() {
            "sbom" | "sboms" => Some(ListResource::Sbom),
            "advisory" | "advisories" => Some(ListResource::Advisory),
            "license" | "licenses" => Some(ListResource::License),
            "package" | "packages" | "component" | "components" => Some(ListResource::Package),
            "vulnerability" | "vulnerabilities" => Some(ListResource::Vulnerability),
            _ => None,
        };
        Self {
            items: Vec::new(),
            title: title.to_owned(),
            item_title: title.to_owned(),
            resource,
            columns: None,
            selected: 0,
            offset: 0,
            page_size: 1,
            total: None,
            status: String::new(),
            params: ListParams::default(),
            search_input: None,
            screen: Screen::Detail { item, scroll: 0 },
        }
    }

    pub fn can_next_page(&self) -> bool {
        match self.total {
            Some(total) => u64::from(self.offset) + (self.items.len() as u64) < total,
            None => self.items.len() >= self.page_size as usize,
        }
    }

    pub fn set_page(&mut self, response: Value, offset: u32) -> anyhow::Result<bool> {
        let items = response
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Trustify list response has no items array"))?;
        if items.is_empty() && offset > self.offset {
            return Ok(false);
        }

        self.items = items;
        if self.columns.is_some() {
            if let Some(resource) = self.resource {
                self.columns = Some(record_columns(&self.items, resource));
            }
        }
        self.total = response.get("total").and_then(Value::as_u64);
        self.offset = offset;
        self.selected = 0;
        self.status.clear();
        Ok(true)
    }

    pub fn selected_id(&self) -> Option<&str> {
        let selected = self.items.get(self.selected)?;
        selected
            .get("id")
            .or_else(|| selected.get("uuid"))
            .and_then(Value::as_str)
    }

    pub fn open_details(&mut self, item: Value) {
        self.screen = Screen::Detail { item, scroll: 0 };
        self.status.clear();
    }

    pub fn handle_key(&mut self, key: KeyCode) -> Action {
        if let Some(input) = &mut self.search_input {
            match key {
                KeyCode::Esc => self.search_input = None,
                KeyCode::Enter => {
                    let query = self
                        .search_input
                        .take()
                        .unwrap_or_default()
                        .trim()
                        .to_owned();
                    return Action::Search((!query.is_empty()).then_some(query));
                }
                KeyCode::Backspace => {
                    input.pop();
                }
                KeyCode::Char(character) if !character.is_control() => input.push(character),
                _ => {}
            }
            return Action::None;
        }

        if let Screen::Detail { scroll, .. } = &mut self.screen {
            match key {
                KeyCode::Esc | KeyCode::Backspace => self.screen = Screen::List,
                KeyCode::Char('q') => return Action::Quit,
                KeyCode::Up | KeyCode::Char('k') => *scroll = scroll.saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') => *scroll = scroll.saturating_add(1),
                _ => {}
            }
            return Action::None;
        }

        match key {
            KeyCode::Char('q') | KeyCode::Esc => Action::Quit,
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected + 1 < self.items.len() {
                    self.selected += 1;
                }
                Action::None
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = self.selected.saturating_sub(1);
                Action::None
            }
            KeyCode::Right | KeyCode::PageDown | KeyCode::Char('n') if self.can_next_page() => {
                Action::NextPage
            }
            KeyCode::Left | KeyCode::PageUp | KeyCode::Char('p') if self.offset > 0 => {
                Action::PreviousPage
            }
            KeyCode::Enter if !self.items.is_empty() => Action::OpenDetails,
            KeyCode::Char('/') => {
                self.search_input = Some(self.params.query.clone().unwrap_or_default());
                Action::None
            }
            _ => Action::None,
        }
    }
}

fn record_columns(items: &[Value], resource: ListResource) -> Vec<String> {
    let Some(object) = items.iter().find_map(Value::as_object) else {
        if resource == ListResource::Vulnerability {
            return ["id", "title", "severity", "score"]
                .into_iter()
                .map(str::to_owned)
                .collect();
        }
        return vec!["value".to_owned()];
    };
    let contains_value = |field: &str| {
        items
            .iter()
            .any(|item| item.get(field).is_some_and(|value| !value.is_null()))
    };

    if resource == ListResource::Vulnerability {
        let identity = ["id", "uuid", "identifier", "document_id"]
            .iter()
            .find(|field| contains_value(field))
            .copied()
            .unwrap_or("id");
        let mut columns = vec![identity.to_owned(), "title".to_owned()];
        columns.extend(
            ["severity", "score"]
                .into_iter()
                .filter(|field| contains_value(field))
                .map(str::to_owned),
        );
        return columns;
    }

    let identity_fields = if resource == ListResource::Advisory {
        [
            "document_id",
            "uuid",
            "id",
            "identifier",
            "purl",
            "name",
            "license",
        ]
    } else {
        [
            "id",
            "uuid",
            "identifier",
            "document_id",
            "purl",
            "name",
            "license",
        ]
    };
    let identity = identity_fields.iter().find(|field| contains_value(field));
    let mut columns = identity
        .map(|field| vec![(*field).to_owned()])
        .unwrap_or_default();
    for field in [
        "title",
        "name",
        "version",
        "purl",
        "severity",
        "score",
        "published",
        "licenses",
        "license",
        "status",
        "type",
    ] {
        if columns.len() == 5 {
            break;
        }
        if !columns.iter().any(|column| column == field) && contains_value(field) {
            columns.push(field.to_owned());
        }
    }
    if columns.is_empty() {
        columns.extend(object.keys().take(5).cloned());
    }
    if columns.is_empty() {
        columns.push("value".to_owned());
    }
    columns
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        App::new(
            serde_json::json!({
                "items": [
                    {"id": "sbom-1"},
                    {"id": "sbom-2"}
                ],
                "total": 2
            }),
            ListParams::default(),
            2,
        )
        .expect("valid page")
    }

    #[test]
    fn navigation_selects_rows_and_opens_detail() {
        let mut app = app();
        assert_eq!(app.handle_key(KeyCode::Char('j')), Action::None);
        assert_eq!(app.selected, 1);
        assert_eq!(app.selected_id(), Some("sbom-2"));
        assert_eq!(app.handle_key(KeyCode::Enter), Action::OpenDetails);

        app.open_details(serde_json::json!({"id": "sbom-2"}));
        assert_eq!(app.handle_key(KeyCode::Esc), Action::None);
        assert!(matches!(app.screen, Screen::List));
    }

    #[test]
    fn search_input_emits_the_query_on_enter() {
        let mut app = app();
        app.handle_key(KeyCode::Char('/'));
        for character in "name~openssl".chars() {
            app.handle_key(KeyCode::Char(character));
        }
        assert_eq!(
            app.handle_key(KeyCode::Enter),
            Action::Search(Some("name~openssl".to_owned()))
        );
    }

    #[test]
    fn pagination_uses_total_or_full_page_length() {
        let mut app = app();
        assert!(!app.can_next_page());

        app.total = None;
        assert!(app.can_next_page());
        assert_eq!(app.handle_key(KeyCode::Char('n')), Action::NextPage);
    }

    #[test]
    fn an_empty_search_replaces_the_previous_results() {
        let mut app = app();
        assert!(app
            .set_page(serde_json::json!({"items": [], "total": 0}), 0)
            .expect("valid empty page"));
        assert!(app.items.is_empty());
        assert_eq!(app.total, Some(0));
    }

    #[test]
    fn sbom_pages_keep_their_summary_table_layout() {
        let mut app = app();

        app.set_page(
            serde_json::json!({"items": [{"id": "sbom-3", "name": "third"}], "total": 3}),
            2,
        )
        .expect("valid SBOM page");

        assert!(app.columns.is_none());
        assert_eq!(app.resource, Some(ListResource::Sbom));
    }

    #[test]
    fn resource_rows_choose_useful_summary_columns() {
        let app = App::records(
            serde_json::json!({
                "items": [{
                    "id": "CVE-2025-1234",
                    "title": "Example vulnerability",
                    "severity": "high",
                    "score": 8.1,
                    "description": "Long description"
                }],
                "total": 1
            }),
            ListParams::default(),
            20,
            "Vulnerabilities",
            ListResource::Vulnerability,
        )
        .expect("valid resource page");

        assert_eq!(app.title, "Vulnerabilities");
        assert_eq!(
            app.columns,
            Some(vec![
                "id".to_owned(),
                "title".to_owned(),
                "severity".to_owned(),
                "score".to_owned()
            ])
        );
    }

    #[test]
    fn vulnerability_rows_keep_the_title_column_when_the_first_cve_has_no_title() {
        let app = App::records(
            serde_json::json!({
                "items": [
                    {"id": "CVE-2025-0001", "title": null, "severity": "high"},
                    {"id": "CVE-2025-0002", "title": "Buffer overflow", "severity": "critical"}
                ],
                "total": 2
            }),
            ListParams::default(),
            20,
            "Vulnerabilities",
            ListResource::Vulnerability,
        )
        .expect("valid vulnerability page");

        assert_eq!(
            app.columns,
            Some(vec![
                "id".to_owned(),
                "title".to_owned(),
                "severity".to_owned()
            ])
        );
    }

    #[test]
    fn vulnerability_rows_always_reserve_a_title_column() {
        let app = App::records(
            serde_json::json!({"items": [{"id": "CVE-2025-0001", "severity": "high"}]}),
            ListParams::default(),
            20,
            "Vulnerabilities",
            ListResource::Vulnerability,
        )
        .expect("valid vulnerability page");

        assert!(app
            .columns
            .as_ref()
            .is_some_and(|columns| columns.iter().any(|column| column == "title")));
    }

    #[test]
    fn advisory_rows_prioritize_document_id_over_uuid() {
        let app = App::records(
            serde_json::json!({
                "items": [{
                    "uuid": "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
                    "document_id": "GHSA-abcd-1234",
                    "title": "Advisory title"
                }]
            }),
            ListParams::default(),
            20,
            "Advisories",
            ListResource::Advisory,
        )
        .expect("valid advisory page");

        assert_eq!(
            app.columns,
            Some(vec!["document_id".to_owned(), "title".to_owned()])
        );
    }

    #[test]
    fn scalar_resource_rows_have_a_value_column() {
        let app = App::records(
            serde_json::json!({"items": ["MIT", "Apache-2.0"]}),
            ListParams::default(),
            20,
            "Licenses",
            ListResource::License,
        )
        .expect("valid scalar resource page");

        assert_eq!(app.columns, Some(vec!["value".to_owned()]));
    }

    #[test]
    fn detail_pages_identify_the_entity_type() {
        let app = App::detail_as("Advisory", serde_json::json!({"title": "Example"}));

        assert_eq!(app.resource, Some(ListResource::Advisory));
    }
}
