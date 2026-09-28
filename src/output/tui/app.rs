use chrono::{Duration, NaiveDate, Utc};
use crossterm::event::KeyCode;
use serde_json::Value;

use crate::api::{sbom::ListParams, ListResource};

use super::theme::ThemeMode;

pub(super) const SEVERITY_FILTER_OPTIONS: [&str; 6] =
    ["critical", "high", "medium", "low", "none", "unknown"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DateRange {
    pub from: Option<String>,
    pub to: Option<String>,
}

impl DateRange {
    fn parse_input(input: &str) -> Result<Option<Self>, String> {
        Self::parse_input_at(input, Utc::now().date_naive())
    }

    fn parse_input_at(input: &str, today: NaiveDate) -> Result<Option<Self>, String> {
        let input = input.trim();
        if input.is_empty() {
            return Ok(None);
        }

        let normalized = input.split_whitespace().collect::<Vec<_>>().join(" ");
        let normalized = normalized.to_ascii_lowercase();
        let preset = match normalized.as_str() {
            "today" => Some((today, today)),
            "last 7 days" => Some((today - Duration::days(6), today)),
            "last 30 days" => Some((today - Duration::days(29), today)),
            _ => None,
        };
        if let Some((from, to)) = preset {
            return Ok(Some(Self {
                from: Some(from.format("%Y-%m-%d").to_string()),
                to: Some(to.format("%Y-%m-%d").to_string()),
            }));
        }

        let Some((from, to)) = input.split_once("..") else {
            return Err("Use today, last 7 days, last 30 days, or YYYY-MM-DD..YYYY-MM-DD; leave one side blank for an open range".into());
        };
        if to.contains("..") {
            return Err("Date range must contain one '..' separator".into());
        }

        let from = parse_date_bound(from)?;
        let to = parse_date_bound(to)?;
        if from.is_none() && to.is_none() {
            return Err("Enter a start date, end date, or leave the input blank to clear".into());
        }
        if from
            .as_ref()
            .zip(to.as_ref())
            .is_some_and(|(from, to)| from > to)
        {
            return Err("Start date must not be after end date".into());
        }

        Ok(Some(Self { from, to }))
    }

    pub fn input_value(&self) -> String {
        format!(
            "{}..{}",
            self.from.as_deref().unwrap_or_default(),
            self.to.as_deref().unwrap_or_default()
        )
    }

    fn query_constraints(&self, field: &str) -> Vec<String> {
        let mut constraints = Vec::with_capacity(2);
        if let Some(from) = &self.from {
            constraints.push(format!("{field}>={from}T00:00:00Z"));
        }
        if let Some(to) = &self.to {
            constraints.push(format!("{field}<={to}T23:59:59.999999999Z"));
        }
        constraints
    }
}

fn parse_date_bound(input: &str) -> Result<Option<String>, String> {
    let date = input.trim();
    if date.is_empty() {
        return Ok(None);
    }
    if !is_valid_date(date) {
        return Err(format!("Invalid date '{date}'; use YYYY-MM-DD"));
    }
    Ok(Some(date.to_owned()))
}

fn is_valid_date(date: &str) -> bool {
    let bytes = date.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes[..4].iter().all(u8::is_ascii_digit)
        || !bytes[5..7].iter().all(u8::is_ascii_digit)
        || !bytes[8..].iter().all(u8::is_ascii_digit)
    {
        return false;
    }

    let Ok(year) = date[..4].parse::<u32>() else {
        return false;
    };
    let Ok(month) = date[5..7].parse::<u32>() else {
        return false;
    };
    let Ok(day) = date[8..].parse::<u32>() else {
        return false;
    };
    if year == 0 || !(1..=12).contains(&month) {
        return false;
    }

    let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 if leap_year => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (1..=days_in_month).contains(&day)
}

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
    pub sort_input: Option<String>,
    pub date_range: Option<DateRange>,
    pub date_range_input: Option<String>,
    pub severity_filter: Option<Vec<String>>,
    pub severity_filter_open: bool,
    pub severity_filter_selected: usize,
    pub severity_filter_draft: Vec<String>,
    pub log_pane_open: bool,
    pub preview_pane_open: bool,
    pub help_open: bool,
    pub instance_label: String,
    pub theme: ThemeMode,
    pub screen: Screen,
}

pub enum Screen {
    List,
    Detail {
        item: Value,
        scroll: u16,
        title: String,
        resource: Option<ListResource>,
        previous: Option<Box<Screen>>,
    },
    CweList {
        cwes: Vec<String>,
        selected: usize,
        previous: Box<Screen>,
    },
    ExploitList {
        exploits: Vec<Value>,
        selected: usize,
        previous: Box<Screen>,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub enum Action {
    None,
    Quit,
    NextPage,
    PreviousPage,
    OpenDetails,
    Back,
    Search(Option<String>),
    Sort(Option<String>),
    SetDateRange(Option<DateRange>),
    SetSeverityFilter(Option<Vec<String>>),
    BrowseCwes(Vec<String>),
    BrowseExploits(String),
    OpenWeakness(String),
    OpenExploit(String),
    OpenVulnerability(String),
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
            sort_input: None,
            date_range: None,
            date_range_input: None,
            severity_filter: None,
            severity_filter_open: false,
            severity_filter_selected: 0,
            severity_filter_draft: Vec::new(),
            log_pane_open: crate::logging::debug_mode_enabled(),
            preview_pane_open: true,
            help_open: false,
            instance_label: String::new(),
            theme: ThemeMode::default(),
            screen: Screen::List,
        })
    }

    pub fn detail_as(title: &str, item: Value) -> Self {
        let resource = match title.to_ascii_lowercase().as_str() {
            "sbom" | "sboms" => Some(ListResource::Sbom),
            "advisory" | "advisories" => Some(ListResource::Advisory),
            "license" | "licenses" => Some(ListResource::License),
            "package" | "packages" | "component" | "components" => Some(ListResource::Package),
            "exploit" | "exploits" => Some(ListResource::Exploit),
            "organization" | "organizations" => Some(ListResource::Organization),
            "product" | "products" => Some(ListResource::Product),
            "vulnerability" | "vulnerabilities" => Some(ListResource::Vulnerability),
            "weakness" | "weaknesses" => Some(ListResource::Weakness),
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
            sort_input: None,
            date_range: None,
            date_range_input: None,
            severity_filter: None,
            severity_filter_open: false,
            severity_filter_selected: 0,
            severity_filter_draft: Vec::new(),
            log_pane_open: crate::logging::debug_mode_enabled(),
            preview_pane_open: false,
            help_open: false,
            instance_label: String::new(),
            theme: ThemeMode::default(),
            screen: Screen::Detail {
                item,
                scroll: 0,
                title: title.to_owned(),
                resource,
                previous: None,
            },
        }
    }

    pub fn with_instance_label(mut self, instance_label: impl Into<String>) -> Self {
        self.instance_label = instance_label.into();
        self
    }

    pub fn with_theme(mut self, theme: ThemeMode) -> Self {
        self.theme = theme;
        self
    }

    pub fn date_field(&self) -> Option<&'static str> {
        match self.resource {
            Some(ListResource::Sbom | ListResource::Advisory | ListResource::Vulnerability) => {
                Some("published")
            }
            Some(ListResource::Exploit) => Some("date_reported"),
            Some(
                ListResource::License
                | ListResource::Organization
                | ListResource::Package
                | ListResource::Product
                | ListResource::Weakness,
            )
            | None => None,
        }
    }

    pub fn list_query(&self) -> Option<String> {
        let mut constraints = self
            .params
            .query
            .as_deref()
            .filter(|query| !query.trim().is_empty())
            .map(str::to_owned)
            .into_iter()
            .collect::<Vec<_>>();
        if let (Some(date_range), Some(field)) = (&self.date_range, self.date_field()) {
            constraints.extend(date_range.query_constraints(field));
        }
        if let Some(severities) = &self.severity_filter {
            if !severities.is_empty() {
                constraints.push(format!("base_severity={}", severities.join("|")));
            }
        }
        (!constraints.is_empty()).then(|| constraints.join("&"))
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
        if let Some(total) = response.get("total").and_then(Value::as_u64) {
            self.total = Some(total);
        }
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
            .or_else(|| selected.get("identifier"))
            .or_else(|| selected.get("document_id"))
            .and_then(Value::as_str)
    }

    pub fn open_details(&mut self, item: Value) {
        self.screen = Screen::Detail {
            item,
            scroll: 0,
            title: self.item_title.clone(),
            resource: self.resource,
            previous: Some(Box::new(Screen::List)),
        };
        self.status.clear();
    }

    pub fn open_cwe_list(&mut self, cwes: Vec<String>) {
        let previous = std::mem::replace(&mut self.screen, Screen::List);
        self.screen = Screen::CweList {
            cwes,
            selected: 0,
            previous: Box::new(previous),
        };
        self.status.clear();
    }

    pub fn open_weakness_details(&mut self, item: Value) {
        let previous = std::mem::replace(&mut self.screen, Screen::List);
        self.screen = Screen::Detail {
            item,
            scroll: 0,
            title: "Weakness".to_owned(),
            resource: Some(ListResource::Weakness),
            previous: Some(Box::new(previous)),
        };
        self.status.clear();
    }

    pub fn open_exploit_list(&mut self, exploits: Vec<Value>) {
        if exploits.is_empty() {
            self.status = "No associated exploits".to_owned();
            return;
        }

        let previous = std::mem::replace(&mut self.screen, Screen::List);
        self.screen = Screen::ExploitList {
            exploits,
            selected: 0,
            previous: Box::new(previous),
        };
        self.status.clear();
    }

    pub fn open_linked_details(&mut self, title: &str, item: Value, resource: ListResource) {
        let previous = std::mem::replace(&mut self.screen, Screen::List);
        self.screen = Screen::Detail {
            item,
            scroll: 0,
            title: title.to_owned(),
            resource: Some(resource),
            previous: Some(Box::new(previous)),
        };
        self.status.clear();
    }

    pub fn go_back(&mut self) {
        let screen = std::mem::replace(&mut self.screen, Screen::List);
        self.screen = match screen {
            Screen::Detail {
                previous: Some(previous),
                ..
            }
            | Screen::CweList { previous, .. }
            | Screen::ExploitList { previous, .. } => *previous,
            Screen::Detail { .. } | Screen::List => Screen::List,
        };
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

        if let Some(input) = &mut self.sort_input {
            match key {
                KeyCode::Esc => self.sort_input = None,
                KeyCode::Enter => {
                    let sort = self.sort_input.take().unwrap_or_default().trim().to_owned();
                    return Action::Sort((!sort.is_empty()).then_some(sort));
                }
                KeyCode::Backspace => {
                    input.pop();
                }
                KeyCode::Char(character) if !character.is_control() => input.push(character),
                _ => {}
            }
            return Action::None;
        }

        if let Some(input) = &mut self.date_range_input {
            match key {
                KeyCode::Esc => {
                    self.date_range_input = None;
                    self.status.clear();
                }
                KeyCode::Enter => {
                    let input = self.date_range_input.take().unwrap_or_default();
                    match DateRange::parse_input(&input) {
                        Ok(date_range) => {
                            self.status.clear();
                            return Action::SetDateRange(date_range);
                        }
                        Err(message) => {
                            self.status = message;
                            self.date_range_input = Some(input);
                        }
                    }
                }
                KeyCode::Backspace => {
                    input.pop();
                    self.status.clear();
                }
                KeyCode::Char(character) if !character.is_control() => {
                    input.push(character);
                    self.status.clear();
                }
                _ => {}
            }
            return Action::None;
        }

        if self.severity_filter_open {
            match key {
                KeyCode::Esc => self.severity_filter_open = false,
                KeyCode::Up | KeyCode::Char('k') => {
                    self.severity_filter_selected = self.severity_filter_selected.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if self.severity_filter_selected + 1 < SEVERITY_FILTER_OPTIONS.len() {
                        self.severity_filter_selected += 1;
                    }
                }
                KeyCode::Char(' ') => {
                    let severity = SEVERITY_FILTER_OPTIONS[self.severity_filter_selected];
                    if let Some(index) = self
                        .severity_filter_draft
                        .iter()
                        .position(|selected| selected == severity)
                    {
                        self.severity_filter_draft.remove(index);
                    } else {
                        self.severity_filter_draft.push(severity.to_owned());
                    }
                }
                KeyCode::Char('a') => {
                    if self.severity_filter_draft.len() == SEVERITY_FILTER_OPTIONS.len() {
                        self.severity_filter_draft.clear();
                    } else {
                        self.severity_filter_draft = SEVERITY_FILTER_OPTIONS
                            .iter()
                            .map(|severity| (*severity).to_owned())
                            .collect();
                    }
                }
                KeyCode::Enter => {
                    self.severity_filter_open = false;
                    let severities = SEVERITY_FILTER_OPTIONS
                        .iter()
                        .filter(|severity| {
                            self.severity_filter_draft
                                .iter()
                                .any(|selected| selected == **severity)
                        })
                        .map(|severity| (*severity).to_owned())
                        .collect::<Vec<_>>();
                    let filter = (!severities.is_empty()
                        && severities.len() != SEVERITY_FILTER_OPTIONS.len())
                    .then_some(severities);
                    if filter != self.severity_filter {
                        self.severity_filter = filter.clone();
                        return Action::SetSeverityFilter(filter);
                    }
                }
                _ => {}
            }
            return Action::None;
        }

        if self.help_open {
            if matches!(
                key,
                KeyCode::Char('h' | 'q') | KeyCode::Esc | KeyCode::Backspace
            ) {
                self.help_open = false;
            }
            return Action::None;
        }

        if key == KeyCode::Char('h') {
            self.help_open = true;
            return Action::None;
        }

        if let Screen::CweList { cwes, selected, .. } = &mut self.screen {
            match key {
                KeyCode::Esc | KeyCode::Backspace => return Action::Back,
                KeyCode::Char('q') => return Action::Back,
                KeyCode::Char('l') => self.log_pane_open = !self.log_pane_open,
                KeyCode::Up | KeyCode::Char('k') => *selected = selected.saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') => {
                    if *selected + 1 < cwes.len() {
                        *selected += 1;
                    }
                }
                KeyCode::Enter => {
                    return cwes
                        .get(*selected)
                        .cloned()
                        .map(Action::OpenWeakness)
                        .unwrap_or(Action::None)
                }
                _ => {}
            }
            return Action::None;
        }

        if let Screen::ExploitList {
            exploits, selected, ..
        } = &mut self.screen
        {
            match key {
                KeyCode::Esc | KeyCode::Backspace | KeyCode::Char('q') => return Action::Back,
                KeyCode::Char('l') => self.log_pane_open = !self.log_pane_open,
                KeyCode::Up | KeyCode::Char('k') => *selected = selected.saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') => {
                    if *selected + 1 < exploits.len() {
                        *selected += 1;
                    }
                }
                KeyCode::Enter => {
                    if let Some(id) = exploits
                        .get(*selected)
                        .and_then(|exploit| exploit.get("id"))
                        .and_then(Value::as_str)
                    {
                        return Action::OpenExploit(id.to_owned());
                    }
                    self.status = "Related exploit has no identifier".to_owned();
                }
                _ => {}
            }
            return Action::None;
        }

        if let Screen::Detail {
            item,
            scroll,
            resource,
            previous,
            ..
        } = &mut self.screen
        {
            match key {
                KeyCode::Esc | KeyCode::Backspace => {
                    return if previous.is_some() {
                        Action::Back
                    } else {
                        Action::Quit
                    }
                }
                KeyCode::Char('q') => return Action::Quit,
                KeyCode::Char('l') => self.log_pane_open = !self.log_pane_open,
                KeyCode::Up | KeyCode::Char('k') => *scroll = scroll.saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') => *scroll = scroll.saturating_add(1),
                KeyCode::Char('c') if *resource == Some(ListResource::Vulnerability) => {
                    if let Some(id) = cwe_ids(item).into_iter().next() {
                        return Action::OpenWeakness(id);
                    }
                    self.status = "No associated CWEs".to_owned();
                }
                KeyCode::Enter if *resource == Some(ListResource::Vulnerability) => {
                    let cwes = cwe_ids(item);
                    if cwes.is_empty() {
                        self.status = "No associated CWEs".to_owned();
                    } else {
                        return Action::BrowseCwes(cwes);
                    }
                }
                KeyCode::Char('e') if *resource == Some(ListResource::Vulnerability) => {
                    if let Some(id) = item
                        .get("identifier")
                        .or_else(|| item.get("id"))
                        .or_else(|| item.get("uuid"))
                        .and_then(Value::as_str)
                    {
                        return Action::BrowseExploits(id.to_owned());
                    }
                    self.status = "Vulnerability has no identifier".to_owned();
                }
                KeyCode::Char('v') if *resource == Some(ListResource::Exploit) => {
                    if let Some(id) = item.get("cve_id").and_then(Value::as_str) {
                        return Action::OpenVulnerability(id.to_owned());
                    }
                    self.status = "Exploit has no associated vulnerability".to_owned();
                }
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
            KeyCode::Char('s') => {
                self.sort_input = Some(self.params.sort.clone().unwrap_or_default());
                Action::None
            }
            KeyCode::Char('d') if self.date_field().is_some() => {
                self.date_range_input = Some(
                    self.date_range
                        .as_ref()
                        .map(DateRange::input_value)
                        .unwrap_or_default(),
                );
                self.status.clear();
                Action::None
            }
            KeyCode::Char('f') if self.resource == Some(ListResource::Vulnerability) => {
                self.severity_filter_selected = 0;
                self.severity_filter_draft = self.severity_filter.clone().unwrap_or_else(|| {
                    SEVERITY_FILTER_OPTIONS
                        .iter()
                        .map(|severity| (*severity).to_owned())
                        .collect()
                });
                self.severity_filter_open = true;
                Action::None
            }
            KeyCode::Char('l') => {
                self.log_pane_open = !self.log_pane_open;
                Action::None
            }
            KeyCode::Char('v') => {
                self.preview_pane_open = !self.preview_pane_open;
                Action::None
            }
            _ => Action::None,
        }
    }
}

fn cwe_ids(item: &Value) -> Vec<String> {
    let Some(cwes) = item.get("cwes").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut ids = Vec::new();
    for id in cwes.iter().filter_map(Value::as_str) {
        if !ids.iter().any(|known| known == id) {
            ids.push(id.to_owned());
        }
    }
    ids
}

fn record_columns(items: &[Value], resource: ListResource) -> Vec<String> {
    let Some(object) = items.iter().find_map(Value::as_object) else {
        if resource == ListResource::Vulnerability {
            return ["id", "title", "severity", "score", "published", "modified"]
                .into_iter()
                .map(str::to_owned)
                .collect();
        }
        return vec!["value".to_owned()];
    };
    let contains_value = |field: &str| {
        items.iter().any(|item| {
            item.get(field).is_some_and(|value| !value.is_null())
                || (resource == ListResource::Advisory
                    && field == "type"
                    && item
                        .get("labels")
                        .and_then(|labels| labels.get(field))
                        .is_some_and(|value| !value.is_null()))
        })
    };

    if resource == ListResource::Vulnerability {
        let identity = ["id", "uuid", "identifier", "document_id"]
            .iter()
            .find(|field| contains_value(field))
            .copied()
            .unwrap_or("id");
        return [
            identity,
            "title",
            "severity",
            "score",
            "published",
            "modified",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
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
    if resource == ListResource::Advisory {
        for field in ["title", "type"] {
            if contains_value(field) && !columns.iter().any(|column| column == field) {
                columns.push(field.to_owned());
            }
        }
    }
    for field in [
        "title",
        "name",
        "cve_id",
        "source",
        "date_reported",
        "remediation_due_date",
        "version",
        "purl",
        "cpe_key",
        "website",
        "severity",
        "score",
        "published",
        "licenses",
        "license",
        "status",
        "type",
        "description",
        "vendor",
        "versions",
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
        assert_eq!(app.handle_key(KeyCode::Esc), Action::Back);
        app.go_back();
        assert!(matches!(app.screen, Screen::List));
    }

    #[test]
    fn help_opens_with_h_and_suspends_screen_keys_until_closed() {
        let mut app = app();

        assert_eq!(app.handle_key(KeyCode::Char('h')), Action::None);
        assert!(app.help_open);
        assert_eq!(app.handle_key(KeyCode::Char('j')), Action::None);
        assert_eq!(app.selected, 0);
        assert_eq!(app.handle_key(KeyCode::Esc), Action::None);
        assert!(!app.help_open);
    }

    #[test]
    fn vulnerability_cwes_open_weakness_details_and_return_to_the_vulnerability() {
        let mut app = App::detail_as(
            "Vulnerability",
            serde_json::json!({
                "identifier": "CVE-2025-1234",
                "cwes": ["CWE-79", "CWE-89", "CWE-79"]
            }),
        );

        assert_eq!(
            app.handle_key(KeyCode::Char('c')),
            Action::OpenWeakness("CWE-79".to_owned())
        );
        assert_eq!(
            app.handle_key(KeyCode::Enter),
            Action::BrowseCwes(vec!["CWE-79".to_owned(), "CWE-89".to_owned()])
        );
        app.open_cwe_list(vec!["CWE-79".to_owned(), "CWE-89".to_owned()]);
        assert_eq!(app.handle_key(KeyCode::Char('j')), Action::None);
        assert_eq!(
            app.handle_key(KeyCode::Enter),
            Action::OpenWeakness("CWE-89".to_owned())
        );

        app.open_weakness_details(serde_json::json!({
            "id": "CWE-89",
            "description": "SQL injection"
        }));
        assert_eq!(app.handle_key(KeyCode::Esc), Action::Back);
        app.go_back();
        assert!(matches!(app.screen, Screen::CweList { selected: 1, .. }));

        assert_eq!(app.handle_key(KeyCode::Esc), Action::Back);
        app.go_back();
        assert!(matches!(app.screen, Screen::Detail { .. }));
    }

    #[test]
    fn vulnerability_and_exploit_details_navigate_between_related_records() {
        let mut app = App::detail_as(
            "Vulnerability",
            serde_json::json!({
                "identifier": "CVE-2025-1234",
                "exploits": [
                    {"id": "exploit-1", "cve_id": "CVE-2025-1234", "source": "first"},
                    {"id": "exploit-2", "cve_id": "CVE-2025-1234", "source": "second"}
                ]
            }),
        );

        assert_eq!(
            app.handle_key(KeyCode::Char('e')),
            Action::BrowseExploits("CVE-2025-1234".to_owned())
        );
        app.open_exploit_list(vec![
            serde_json::json!({"id": "exploit-1", "cve_id": "CVE-2025-1234"}),
            serde_json::json!({"id": "exploit-2", "cve_id": "CVE-2025-1234"}),
        ]);
        assert_eq!(app.handle_key(KeyCode::Char('j')), Action::None);
        assert_eq!(
            app.handle_key(KeyCode::Enter),
            Action::OpenExploit("exploit-2".to_owned())
        );
        app.open_linked_details(
            "Exploit",
            serde_json::json!({"id": "exploit-2", "cve_id": "CVE-2025-1234"}),
            ListResource::Exploit,
        );

        assert_eq!(
            app.handle_key(KeyCode::Char('v')),
            Action::OpenVulnerability("CVE-2025-1234".to_owned())
        );
        app.open_linked_details(
            "Vulnerability",
            serde_json::json!({"identifier": "CVE-2025-1234"}),
            ListResource::Vulnerability,
        );

        assert_eq!(app.handle_key(KeyCode::Esc), Action::Back);
        app.go_back();
        assert!(matches!(app.screen, Screen::Detail { .. }));
        assert_eq!(app.handle_key(KeyCode::Esc), Action::Back);
        app.go_back();
        assert!(matches!(
            app.screen,
            Screen::ExploitList { selected: 1, .. }
        ));
        assert_eq!(app.handle_key(KeyCode::Esc), Action::Back);
        app.go_back();
        assert!(matches!(app.screen, Screen::Detail { .. }));
    }

    #[test]
    fn selected_vulnerability_id_falls_back_to_its_identifier() {
        let app = App::records(
            serde_json::json!({
                "items": [{"identifier": "CVE-2025-1234"}]
            }),
            ListParams::default(),
            20,
            "Vulnerabilities",
            ListResource::Vulnerability,
        )
        .expect("valid vulnerability page");

        assert_eq!(app.selected_id(), Some("CVE-2025-1234"));
    }

    #[test]
    fn log_pane_can_be_toggled_from_list_and_detail_screens() {
        let mut app = app();
        let initial_visibility = app.log_pane_open;

        assert_eq!(app.handle_key(KeyCode::Char('l')), Action::None);
        assert_eq!(app.log_pane_open, !initial_visibility);

        app.open_details(serde_json::json!({"id": "sbom-1"}));
        assert_eq!(app.handle_key(KeyCode::Char('l')), Action::None);
        assert_eq!(app.log_pane_open, initial_visibility);
    }

    #[test]
    fn preview_pane_is_open_by_default_and_can_be_toggled() {
        let mut app = app();
        assert!(app.preview_pane_open);

        assert_eq!(app.handle_key(KeyCode::Char('v')), Action::None);
        assert!(!app.preview_pane_open);
        assert_eq!(app.handle_key(KeyCode::Char('v')), Action::None);
        assert!(app.preview_pane_open);
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
    fn sort_input_emits_the_expression_on_enter() {
        let mut app = app();
        app.handle_key(KeyCode::Char('s'));
        for character in "name".chars() {
            app.handle_key(KeyCode::Char(character));
        }

        assert_eq!(
            app.handle_key(KeyCode::Enter),
            Action::Sort(Some("name".to_owned()))
        );
    }

    #[test]
    fn empty_sort_input_clears_the_current_sort() {
        let mut app = app();
        app.params.sort = Some("name".to_owned());
        app.handle_key(KeyCode::Char('s'));
        for _ in "name".chars() {
            app.handle_key(KeyCode::Backspace);
        }

        assert_eq!(app.handle_key(KeyCode::Enter), Action::Sort(None));
    }

    #[test]
    fn vulnerability_severity_filter_emits_selection_and_query() {
        let mut app = App::records(
            serde_json::json!({"items": [{"id": "CVE-2025-1234"}]}),
            ListParams::default(),
            20,
            "Vulnerabilities",
            ListResource::Vulnerability,
        )
        .expect("valid vulnerability page");
        let expected = SEVERITY_FILTER_OPTIONS[1..]
            .iter()
            .map(|severity| (*severity).to_owned())
            .collect::<Vec<_>>();

        assert_eq!(app.handle_key(KeyCode::Char('f')), Action::None);
        assert!(app.severity_filter_open);
        assert_eq!(app.handle_key(KeyCode::Char(' ')), Action::None);
        assert_eq!(
            app.handle_key(KeyCode::Enter),
            Action::SetSeverityFilter(Some(expected.clone()))
        );
        assert_eq!(
            app.list_query().as_deref(),
            Some(format!("base_severity={}", expected.join("|")).as_str())
        );
    }

    #[test]
    fn date_range_input_emits_an_inclusive_calendar_range() {
        let mut app = app();
        app.handle_key(KeyCode::Char('d'));
        for character in "2024-02-29..2024-03-01".chars() {
            app.handle_key(KeyCode::Char(character));
        }

        assert_eq!(
            app.handle_key(KeyCode::Enter),
            Action::SetDateRange(Some(DateRange {
                from: Some("2024-02-29".to_owned()),
                to: Some("2024-03-01".to_owned()),
            }))
        );
    }

    #[test]
    fn date_range_presets_include_today_and_the_previous_calendar_days() {
        let today = NaiveDate::from_ymd_opt(2024, 3, 1).expect("valid date");

        assert_eq!(
            DateRange::parse_input_at("today", today),
            Ok(Some(DateRange {
                from: Some("2024-03-01".to_owned()),
                to: Some("2024-03-01".to_owned()),
            }))
        );
        assert_eq!(
            DateRange::parse_input_at("Last 7 days", today),
            Ok(Some(DateRange {
                from: Some("2024-02-24".to_owned()),
                to: Some("2024-03-01".to_owned()),
            }))
        );
        assert_eq!(
            DateRange::parse_input_at(" last   30 days ", today),
            Ok(Some(DateRange {
                from: Some("2024-02-01".to_owned()),
                to: Some("2024-03-01".to_owned()),
            }))
        );
    }

    #[test]
    fn invalid_date_ranges_keep_the_editor_open() {
        let mut app = app();
        app.handle_key(KeyCode::Char('d'));
        for character in "2025-02-30..2025-03-01".chars() {
            app.handle_key(KeyCode::Char(character));
        }

        assert_eq!(app.handle_key(KeyCode::Enter), Action::None);
        assert_eq!(
            app.date_range_input.as_deref(),
            Some("2025-02-30..2025-03-01")
        );
        assert!(app.status.contains("Invalid date"));
    }

    #[test]
    fn date_range_is_preserved_when_search_and_sort_change() {
        let mut app = app();
        app.date_range = Some(DateRange {
            from: Some("2025-01-01".to_owned()),
            to: Some("2025-12-31".to_owned()),
        });

        app.handle_key(KeyCode::Char('/'));
        for character in "name~openssl".chars() {
            app.handle_key(KeyCode::Char(character));
        }
        if let Action::Search(query) = app.handle_key(KeyCode::Enter) {
            app.params.query = query;
        } else {
            panic!("search input should be applied");
        }

        app.handle_key(KeyCode::Char('s'));
        for character in "published".chars() {
            app.handle_key(KeyCode::Char(character));
        }
        if let Action::Sort(sort) = app.handle_key(KeyCode::Enter) {
            app.params.sort = sort;
        } else {
            panic!("sort input should be applied");
        }

        assert_eq!(
            app.list_query().as_deref(),
            Some(
                "name~openssl&published>=2025-01-01T00:00:00Z&published<=2025-12-31T23:59:59.999999999Z"
            )
        );
        assert_eq!(app.params.sort.as_deref(), Some("published"));
    }

    #[test]
    fn date_range_query_uses_only_fields_with_published_dates() {
        let mut app = App::records(
            serde_json::json!({"items": [{"name": "openssl"}]}),
            ListParams::default(),
            20,
            "Packages",
            ListResource::Package,
        )
        .expect("valid package page");
        app.date_range = Some(DateRange {
            from: Some("2025-01-01".to_owned()),
            to: None,
        });

        assert_eq!(app.date_field(), None);
        assert_eq!(app.list_query(), None);
    }

    #[test]
    fn exploit_date_range_filters_by_reported_date() {
        let mut app = App::records(
            serde_json::json!({
                "items": [{"id": "kev-1", "date_reported": "2025-01-01"}]
            }),
            ListParams::default(),
            20,
            "Exploits",
            ListResource::Exploit,
        )
        .expect("valid exploit page");
        app.date_range = Some(DateRange {
            from: Some("2025-01-01".to_owned()),
            to: None,
        });

        assert_eq!(app.date_field(), Some("date_reported"));
        assert_eq!(
            app.list_query().as_deref(),
            Some("date_reported>=2025-01-01T00:00:00Z")
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
    fn page_responses_without_a_total_keep_the_known_count() {
        let mut app = app();
        app.total = Some(8);

        app.set_page(
            serde_json::json!({"items": [{"id": "sbom-3"}]}),
            app.page_size,
        )
        .expect("valid page");

        assert_eq!(app.total, Some(8));
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
                "score".to_owned(),
                "published".to_owned(),
                "modified".to_owned()
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
                "severity".to_owned(),
                "score".to_owned(),
                "published".to_owned(),
                "modified".to_owned()
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
                "title": "Advisory title",
                "labels": {"type": "cve"}
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
            Some(vec![
                "document_id".to_owned(),
                "title".to_owned(),
                "type".to_owned()
            ])
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
