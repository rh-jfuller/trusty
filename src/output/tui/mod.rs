mod app;
mod render;
mod theme;

pub use theme::ThemeMode;

use std::{
    collections::HashMap,
    future::Future,
    io,
    sync::{Arc, Mutex},
};

use anyhow::Context as _;
use crossterm::{
    event::{Event, EventStream, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{
        disable_raw_mode, enable_raw_mode, Clear, ClearType, EnterAlternateScreen,
        LeaveAlternateScreen,
    },
};
use futures_util::StreamExt;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState},
    Frame, Terminal,
};
use serde_json::Value;
use tokio::sync::watch;

use crate::{
    api::{self, sbom, ApiClient, ListParams, ListResource},
    output::tui::app::{Action, App},
    settings::{AppSettings, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE},
};

#[derive(Clone, Copy)]
struct MenuEntry {
    resource: ListResource,
    title: &'static str,
    description: &'static str,
}

const MENU_ENTRIES: [MenuEntry; 9] = [
    MenuEntry {
        resource: ListResource::Sbom,
        title: "SBOMs",
        description: "Browse software bills of materials",
    },
    MenuEntry {
        resource: ListResource::Vulnerability,
        title: "Vulnerabilities",
        description: "Explore known vulnerabilities",
    },
    MenuEntry {
        resource: ListResource::Advisory,
        title: "Advisories",
        description: "Browse security advisories",
    },
    MenuEntry {
        resource: ListResource::License,
        title: "Licenses",
        description: "Browse licenses found in SBOMs",
    },
    MenuEntry {
        resource: ListResource::Package,
        title: "Packages / Components",
        description: "Search Package URLs",
    },
    MenuEntry {
        resource: ListResource::Product,
        title: "Products",
        description: "Browse products and versions",
    },
    MenuEntry {
        resource: ListResource::Exploit,
        title: "Exploits",
        description: "Explore known exploited vulnerabilities",
    },
    MenuEntry {
        resource: ListResource::Weakness,
        title: "Weaknesses",
        description: "Browse CWE weakness definitions",
    },
    MenuEntry {
        resource: ListResource::Organization,
        title: "Organizations",
        description: "Browse vendors and issuers",
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntityCount {
    Loading,
    Available(u64),
    Unavailable,
}

#[derive(Clone)]
pub struct EntityCountCache {
    values: Arc<Mutex<HashMap<ListResource, EntityCount>>>,
    updates: watch::Sender<()>,
}

impl Default for EntityCountCache {
    fn default() -> Self {
        let (updates, _) = watch::channel(());
        Self {
            values: Arc::new(Mutex::new(HashMap::new())),
            updates,
        }
    }
}

impl EntityCountCache {
    fn begin_fetch(&self, resource: ListResource) -> bool {
        let mut values = self.values.lock().expect("entity count cache poisoned");
        if values.contains_key(&resource) {
            return false;
        }
        values.insert(resource, EntityCount::Loading);
        drop(values);
        self.updates.send_replace(());
        true
    }

    fn begin_refresh(&self, resource: ListResource) -> bool {
        let mut values = self.values.lock().expect("entity count cache poisoned");
        if matches!(values.get(&resource), Some(EntityCount::Loading)) {
            return false;
        }
        values.insert(resource, EntityCount::Loading);
        drop(values);
        self.updates.send_replace(());
        true
    }

    pub fn total(&self, resource: ListResource) -> Option<u64> {
        match self
            .values
            .lock()
            .expect("entity count cache poisoned")
            .get(&resource)
        {
            Some(EntityCount::Available(total)) => Some(*total),
            Some(EntityCount::Loading | EntityCount::Unavailable) | None => None,
        }
    }

    pub fn set_total(&self, resource: ListResource, total: Option<u64>) {
        let count = total
            .map(EntityCount::Available)
            .unwrap_or(EntityCount::Unavailable);
        self.values
            .lock()
            .expect("entity count cache poisoned")
            .insert(resource, count);
        self.updates.send_replace(());
    }

    fn state(&self, resource: ListResource) -> Option<EntityCount> {
        self.values
            .lock()
            .expect("entity count cache poisoned")
            .get(&resource)
            .copied()
    }

    fn subscribe(&self) -> watch::Receiver<()> {
        self.updates.subscribe()
    }
}

fn start_entity_count_requests(client: &ApiClient, counts: &EntityCountCache, refresh: bool) {
    for entry in MENU_ENTRIES {
        let should_fetch = if refresh {
            counts.begin_refresh(entry.resource)
        } else {
            counts.begin_fetch(entry.resource)
        };
        if !should_fetch {
            continue;
        }

        let client = client.clone();
        let counts = counts.clone();
        tokio::spawn(async move {
            let params = ListParams {
                limit: Some(0),
                total: true,
                ..ListParams::default()
            };
            let total = match api::list_resource(&client, entry.resource, &params).await {
                Ok(response) => response.get("total").and_then(Value::as_u64),
                Err(error) => {
                    tracing::debug!(resource = ?entry.resource, %error, "failed to fetch entity count");
                    None
                }
            };
            counts.set_total(entry.resource, total);
        });
    }
}

#[derive(Debug, Eq, PartialEq)]
enum MenuAction {
    None,
    Exit,
    Select(ListResource),
    RefreshCounts,
    OpenSettings,
    SaveSettings,
}

#[derive(Default)]
struct MenuState {
    selected: usize,
    log_pane_open: bool,
    help_open: bool,
    settings_open: bool,
    settings_selected: usize,
    settings_input: Option<String>,
    settings_error: Option<String>,
}

impl MenuState {
    fn handle_key(&mut self, key: KeyCode, settings: &mut AppSettings) -> MenuAction {
        if self.help_open {
            if matches!(
                key,
                KeyCode::Char('h' | 'q') | KeyCode::Esc | KeyCode::Backspace
            ) {
                self.help_open = false;
            }
            return MenuAction::None;
        }

        if self.settings_open {
            if let Some(input) = &mut self.settings_input {
                match key {
                    KeyCode::Esc => {
                        self.settings_input = None;
                        self.settings_error = None;
                    }
                    KeyCode::Enter => {
                        let input = self.settings_input.take().unwrap_or_default();
                        if self.settings_selected == 1 {
                            match input.parse::<u32>() {
                                Ok(page_size) if (1..=MAX_PAGE_SIZE).contains(&page_size) => {
                                    settings.page_size = page_size;
                                    self.settings_error = None;
                                    return MenuAction::SaveSettings;
                                }
                                _ => {
                                    self.settings_input = Some(input);
                                    self.settings_error = Some(format!(
                                        "Enter a row count from 1 to {MAX_PAGE_SIZE}"
                                    ));
                                }
                            }
                        } else {
                            let resource = MENU_ENTRIES[self.settings_selected - 2].resource;
                            settings.set_sort(resource, input);
                            self.settings_error = None;
                            return MenuAction::SaveSettings;
                        }
                    }
                    KeyCode::Backspace => {
                        input.pop();
                        self.settings_error = None;
                    }
                    KeyCode::Char(character) if !character.is_control() => {
                        input.push(character);
                        self.settings_error = None;
                    }
                    _ => {}
                }
                return MenuAction::None;
            }

            match key {
                KeyCode::Esc | KeyCode::Backspace | KeyCode::Char('q') => {
                    self.settings_open = false;
                }
                KeyCode::Char('h') => self.help_open = true,
                KeyCode::Up | KeyCode::Char('k') => {
                    self.settings_selected = self.settings_selected.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if self.settings_selected < MENU_ENTRIES.len() + 1 {
                        self.settings_selected += 1;
                    }
                }
                KeyCode::Char('r') if self.settings_selected == 1 => {
                    settings.page_size = DEFAULT_PAGE_SIZE;
                    return MenuAction::SaveSettings;
                }
                KeyCode::Char('r') if self.settings_selected >= 2 => {
                    let resource = MENU_ENTRIES[self.settings_selected - 2].resource;
                    settings.reset_sort(resource);
                    return MenuAction::SaveSettings;
                }
                KeyCode::Char('d') if settings.theme != ThemeMode::Dark => {
                    settings.theme = ThemeMode::Dark;
                    return MenuAction::SaveSettings;
                }
                KeyCode::Char('l') if settings.theme != ThemeMode::Light => {
                    settings.theme = ThemeMode::Light;
                    return MenuAction::SaveSettings;
                }
                KeyCode::Enter | KeyCode::Char(' ') if self.settings_selected == 0 => {
                    settings.theme.toggle();
                    return MenuAction::SaveSettings;
                }
                KeyCode::Enter | KeyCode::Char(' ') if self.settings_selected == 1 => {
                    self.settings_input = Some(settings.page_size.to_string());
                    self.settings_error = None;
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    let resource = MENU_ENTRIES[self.settings_selected - 2].resource;
                    self.settings_input = Some(settings.sort_value(resource).to_owned());
                    self.settings_error = None;
                }
                _ => {}
            }
            return MenuAction::None;
        }

        match key {
            KeyCode::Char('q') | KeyCode::Esc => MenuAction::Exit,
            KeyCode::Char('h') => {
                self.help_open = true;
                MenuAction::None
            }
            KeyCode::Char('r') => MenuAction::RefreshCounts,
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = self.selected.saturating_sub(1);
                MenuAction::None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected < MENU_ENTRIES.len() {
                    self.selected += 1;
                }
                MenuAction::None
            }
            KeyCode::Char('l') => {
                self.log_pane_open = !self.log_pane_open;
                MenuAction::None
            }
            KeyCode::Enter if self.selected == MENU_ENTRIES.len() => MenuAction::OpenSettings,
            KeyCode::Enter => MenuAction::Select(MENU_ENTRIES[self.selected].resource),
            _ => MenuAction::None,
        }
    }
}

pub async fn main_menu(
    selected: usize,
    instance_label: &str,
    client_updates: &mut watch::Receiver<Option<Result<ApiClient, String>>>,
    counts: &EntityCountCache,
    settings: &mut AppSettings,
) -> anyhow::Result<Option<(ListResource, usize)>> {
    let mut count_updates = counts.subscribe();
    let mut client_ready = false;
    if let Some(client_result) = client_updates.borrow().clone() {
        update_entity_counts(client_result, counts);
        client_ready = true;
    }
    let mut menu = MenuState {
        selected: selected.min(MENU_ENTRIES.len()),
        log_pane_open: crate::logging::debug_mode_enabled(),
        ..MenuState::default()
    };
    let _guard = TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    execute!(io::stdout(), Clear(ClearType::All))?;
    let mut events = EventStream::new();

    loop {
        let connection_hint = match client_updates.borrow().as_ref() {
            None => " · connecting to Trustify",
            Some(Err(_)) => " · Trustify API unavailable",
            Some(Ok(_)) => "",
        };
        draw_frame(&mut terminal, |frame| {
            render_main_menu(
                frame,
                &menu,
                instance_label,
                counts,
                settings,
                connection_hint,
            )
        })?;
        let event = tokio::select! {
            event = events.next() => event,
            changed = count_updates.changed() => {
                if changed.is_err() {
                    return Ok(None);
                }
                continue;
            }
            changed = client_updates.changed(), if !client_ready => {
                if changed.is_ok() {
                    client_ready = true;
                    if let Some(client_result) = client_updates.borrow().clone() {
                        update_entity_counts(client_result, counts);
                    }
                }
                continue;
            }
        };
        let Some(event) = event else {
            return Ok(None);
        };
        if let Event::Key(key) = event.context("reading terminal event")? {
            if key.kind == KeyEventKind::Press {
                if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                    return Ok(None);
                }
                match menu.handle_key(key.code, settings) {
                    MenuAction::None => {}
                    MenuAction::Exit => return Ok(None),
                    MenuAction::Select(resource) => return Ok(Some((resource, menu.selected))),
                    MenuAction::RefreshCounts => {
                        if let Some(Ok(client)) = client_updates.borrow().clone() {
                            start_entity_count_requests(&client, counts, true);
                        }
                    }
                    MenuAction::OpenSettings => {
                        menu.settings_open = true;
                        menu.settings_selected = 0;
                    }
                    MenuAction::SaveSettings => settings.save()?,
                }
            }
        }
    }
}

fn update_entity_counts(client_result: Result<ApiClient, String>, counts: &EntityCountCache) {
    match client_result {
        Ok(client) => start_entity_count_requests(&client, counts, false),
        Err(_) => {
            for entry in MENU_ENTRIES {
                if counts.state(entry.resource).is_none() {
                    counts.set_total(entry.resource, None);
                }
            }
        }
    }
}

fn render_main_menu(
    frame: &mut Frame<'_>,
    menu: &MenuState,
    instance_label: &str,
    counts: &EntityCountCache,
    settings: &AppSettings,
    connection_hint: &str,
) {
    let theme = settings.theme;
    let log_pane_height = if menu.log_pane_open {
        Constraint::Length(5)
    } else {
        Constraint::Length(0)
    };
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(7),
            log_pane_height,
            Constraint::Length(1),
        ])
        .split(frame.area());

    let palette = theme.palette();
    frame.render_widget(
        Block::default().style(Style::default().bg(palette.background)),
        frame.area(),
    );
    render::render_banner_with_target(frame, areas[0], "Select an entity", instance_label, theme);

    if menu.help_open {
        render::render_help_panel(
            frame,
            areas[1],
            if menu.settings_open {
                "Settings help"
            } else {
                "Keyboard shortcuts"
            },
            if menu.settings_open {
                &[
                    "d           Select dark mode",
                    "l           Select light mode",
                    "↑/↓         Select appearance, rows, or entity sort",
                    "Enter       Toggle theme or edit selected value",
                    "Rows        Enter a number from 1 to 1000",
                    "Sort        Blank disables; r resets built-in default",
                    "Esc/q       Return to the entity menu",
                    "h           Show or close this help",
                ]
            } else {
                &[
                    "↑/↓ or j/k  Select an entity or settings",
                    "Enter       Open the selected page",
                    "r           Refresh entity counts",
                    "l           Toggle debug logs",
                    "q/Esc       Exit the entity menu",
                    "h           Show or close this help",
                ]
            },
            theme,
        );
    } else if menu.settings_open {
        let sort_rows = MENU_ENTRIES
            .iter()
            .map(|entry| (entry.resource, entry.title))
            .collect::<Vec<_>>();
        render::render_settings_panel(
            frame,
            areas[1],
            settings,
            &sort_rows,
            menu.settings_selected,
            menu.settings_input.as_deref(),
            menu.settings_error.as_deref(),
        );
    } else {
        let mut items = MENU_ENTRIES
            .iter()
            .map(|entry| {
                let count = match counts.state(entry.resource) {
                    Some(EntityCount::Loading) | None => "…".to_owned(),
                    Some(EntityCount::Available(total)) => total.to_string(),
                    Some(EntityCount::Unavailable) => "unavailable".to_owned(),
                };
                ListItem::new(Line::from(vec![
                    Span::styled(
                        entry.title,
                        Style::default()
                            .fg(palette.accent_bright)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("  ·  {}  ·  {count}", entry.description),
                        Style::default().fg(palette.muted),
                    ),
                ]))
            })
            .collect::<Vec<_>>();
        items.push(ListItem::new(
            "Settings  ·  Appearance and display preferences",
        ));
        let list = List::new(items)
            .block(
                Block::default()
                    .title("Main entities")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(palette.border))
                    .style(Style::default().fg(palette.foreground).bg(palette.surface)),
            )
            .highlight_style(
                Style::default()
                    .fg(palette.selection_foreground)
                    .bg(palette.selection)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("› ");
        let mut state = ListState::default();
        state.select(Some(menu.selected));
        frame.render_stateful_widget(list, areas[1], &mut state);
    }

    if menu.log_pane_open {
        render::render_log_pane(frame, areas[2], theme);
    }
    let status = if menu.help_open {
        format!("h/Esc/q close help{connection_hint}")
    } else if menu.settings_open {
        let settings_hint = if menu.settings_input.is_some() {
            if menu.settings_selected == 1 {
                "Type rows · Enter save · Esc cancel"
            } else {
                "Type sort · Enter save · Esc cancel"
            }
        } else {
            "↑/↓ select · Enter edit · d/l theme · r reset value · Esc back"
        };
        format!("{settings_hint} · h help{connection_hint}")
    } else {
        let log_hint = if menu.log_pane_open {
            " · l hide logs"
        } else {
            " · l logs"
        };
        format!("↑/↓ or j/k select · Enter open · r refresh counts · q/Esc exit{log_hint} · h help{connection_hint}")
    };
    render::render_status(frame, areas[3], &status, theme);
}

pub async fn browse_sboms(
    client: &ApiClient,
    mut params: sbom::ListParams,
    first_page: Value,
    theme: ThemeMode,
) -> anyhow::Result<()> {
    let page_size = params.limit.unwrap_or(20).max(1);
    params.limit = Some(page_size);
    let mut app = App::new(first_page, params, page_size)?
        .with_instance_label(client.instance_label())
        .with_theme(theme);
    let _guard = TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    execute!(io::stdout(), Clear(ClearType::All))?;
    let mut events = EventStream::new();

    loop {
        draw_frame(&mut terminal, |frame| render::render(frame, &app))?;
        let Some(event) = events.next().await else {
            break;
        };
        match event.context("reading terminal event")? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                    break;
                }
                let action = app.handle_key(key.code);
                match action {
                    Action::None => {}
                    Action::Quit => break,
                    Action::Back => app.go_back(),
                    Action::OpenDetails => {
                        if let Some(id) = app.selected_id().map(str::to_owned) {
                            app.status = "Loading details…".to_owned();
                            draw_frame(&mut terminal, |frame| render::render(frame, &app))?;
                            match sbom::get(client, &id).await {
                                Ok(item) => app.open_details(item),
                                Err(error) => app.status = error.to_string(),
                            }
                        }
                    }
                    Action::NextPage => {
                        let offset = app.offset.saturating_add(app.page_size);
                        load_page(client, &mut app, offset, false, &mut terminal).await?;
                    }
                    Action::PreviousPage => {
                        let offset = app.offset.saturating_sub(app.page_size);
                        load_page(client, &mut app, offset, false, &mut terminal).await?;
                    }
                    Action::Search(query) => {
                        app.params.query = query;
                        app.total = None;
                        load_page(client, &mut app, 0, true, &mut terminal).await?;
                    }
                    Action::Sort(sort) => {
                        app.params.sort = sort;
                        load_page(client, &mut app, 0, false, &mut terminal).await?;
                    }
                    Action::SetDateRange(date_range) => {
                        app.date_range = date_range;
                        app.total = None;
                        load_page(client, &mut app, 0, true, &mut terminal).await?;
                    }
                    Action::SetSeverityFilter(severities) => {
                        app.severity_filter = severities;
                        app.total = None;
                        load_page(client, &mut app, 0, true, &mut terminal).await?;
                    }
                    Action::BrowseCwes(cwes) => app.open_cwe_list(cwes),
                    Action::BrowseExploits(id) => {
                        if load_related_exploits(client, &mut app, &id, &mut terminal, &mut events)
                            .await?
                        {
                            break;
                        }
                    }
                    Action::OpenWeakness(id) => {
                        load_weakness_detail(client, &mut app, &id, &mut terminal).await?;
                    }
                    Action::OpenExploit(id) => {
                        if load_exploit_detail(client, &mut app, &id, &mut terminal, &mut events)
                            .await?
                        {
                            break;
                        }
                    }
                    Action::OpenVulnerability(id) => {
                        if load_vulnerability_detail(
                            client,
                            &mut app,
                            &id,
                            &mut terminal,
                            &mut events,
                        )
                        .await?
                        {
                            break;
                        }
                    }
                }
            }
            Event::Resize(_, _) => {}
            _ => {}
        }
    }

    Ok(())
}

pub async fn browse_records(
    client: &ApiClient,
    resource: ListResource,
    title: &str,
    mut params: ListParams,
    first_page: Value,
    theme: ThemeMode,
) -> anyhow::Result<()> {
    let page_size = params.limit.unwrap_or(20).max(1);
    params.limit = Some(page_size);
    let mut app = App::records(first_page, params, page_size, title, resource)?
        .with_instance_label(client.instance_label())
        .with_theme(theme);
    let _guard = TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    execute!(io::stdout(), Clear(ClearType::All))?;
    let mut events = EventStream::new();

    loop {
        draw_frame(&mut terminal, |frame| render::render(frame, &app))?;
        let Some(event) = events.next().await else {
            break;
        };
        match event.context("reading terminal event")? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                    break;
                }
                let action = app.handle_key(key.code);
                match action {
                    Action::None => {}
                    Action::Quit => break,
                    Action::Back => app.go_back(),
                    Action::OpenDetails => {
                        if let Some(item) = app.items.get(app.selected).cloned() {
                            app.open_details(item);
                        }
                    }
                    Action::NextPage => {
                        let offset = app.offset.saturating_add(app.page_size);
                        load_records_page(client, resource, &mut app, offset, false, &mut terminal)
                            .await?;
                    }
                    Action::PreviousPage => {
                        let offset = app.offset.saturating_sub(app.page_size);
                        load_records_page(client, resource, &mut app, offset, false, &mut terminal)
                            .await?;
                    }
                    Action::Search(query) => {
                        app.params.query = query;
                        app.total = None;
                        load_records_page(client, resource, &mut app, 0, true, &mut terminal)
                            .await?;
                    }
                    Action::Sort(sort) => {
                        app.params.sort = sort;
                        load_records_page(client, resource, &mut app, 0, false, &mut terminal)
                            .await?;
                    }
                    Action::SetDateRange(date_range) => {
                        app.date_range = date_range;
                        app.total = None;
                        load_records_page(client, resource, &mut app, 0, true, &mut terminal)
                            .await?;
                    }
                    Action::SetSeverityFilter(severities) => {
                        app.severity_filter = severities;
                        app.total = None;
                        load_records_page(client, resource, &mut app, 0, true, &mut terminal)
                            .await?;
                    }
                    Action::BrowseCwes(cwes) => app.open_cwe_list(cwes),
                    Action::BrowseExploits(id) => {
                        if load_related_exploits(client, &mut app, &id, &mut terminal, &mut events)
                            .await?
                        {
                            break;
                        }
                    }
                    Action::OpenWeakness(id) => {
                        load_weakness_detail(client, &mut app, &id, &mut terminal).await?;
                    }
                    Action::OpenExploit(id) => {
                        if load_exploit_detail(client, &mut app, &id, &mut terminal, &mut events)
                            .await?
                        {
                            break;
                        }
                    }
                    Action::OpenVulnerability(id) => {
                        if load_vulnerability_detail(
                            client,
                            &mut app,
                            &id,
                            &mut terminal,
                            &mut events,
                        )
                        .await?
                        {
                            break;
                        }
                    }
                }
            }
            Event::Resize(_, _) => {}
            _ => {}
        }
    }

    Ok(())
}

pub async fn show_detail(item: Value) -> anyhow::Result<()> {
    show_detail_as("SBOM", item).await
}

pub async fn show_detail_as(title: &str, item: Value) -> anyhow::Result<()> {
    run_detail_viewer(App::detail_as(title, item), None).await
}

pub async fn show_detail_as_on(
    title: &str,
    item: Value,
    instance_label: &str,
    client: &ApiClient,
    theme: ThemeMode,
) -> anyhow::Result<()> {
    run_detail_viewer(
        App::detail_as(title, item)
            .with_instance_label(instance_label)
            .with_theme(theme),
        Some(client),
    )
    .await
}

async fn run_detail_viewer(mut app: App, client: Option<&ApiClient>) -> anyhow::Result<()> {
    let _guard = TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    execute!(io::stdout(), Clear(ClearType::All))?;
    let mut events = EventStream::new();

    loop {
        draw_frame(&mut terminal, |frame| render::render(frame, &app))?;
        let Some(event) = events.next().await else {
            break;
        };
        if let Event::Key(key) = event.context("reading terminal event")? {
            if key.kind == KeyEventKind::Press {
                if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                    break;
                }
                match app.handle_key(key.code) {
                    Action::Quit => break,
                    Action::Back => app.go_back(),
                    Action::BrowseCwes(cwes) => app.open_cwe_list(cwes),
                    Action::BrowseExploits(id) => {
                        if let Some(client) = client {
                            if load_related_exploits(
                                client,
                                &mut app,
                                &id,
                                &mut terminal,
                                &mut events,
                            )
                            .await?
                            {
                                break;
                            }
                        } else {
                            app.status =
                                "No API client available to list related exploits".to_owned();
                        }
                    }
                    Action::OpenWeakness(id) => {
                        if let Some(client) = client {
                            load_weakness_detail(client, &mut app, &id, &mut terminal).await?;
                        } else {
                            app.status = "No API client available to open this CWE".to_owned();
                        }
                    }
                    Action::OpenExploit(id) => {
                        if let Some(client) = client {
                            if load_exploit_detail(
                                client,
                                &mut app,
                                &id,
                                &mut terminal,
                                &mut events,
                            )
                            .await?
                            {
                                break;
                            }
                        } else {
                            app.status = "No API client available to open this exploit".to_owned();
                        }
                    }
                    Action::OpenVulnerability(id) => {
                        if let Some(client) = client {
                            if load_vulnerability_detail(
                                client,
                                &mut app,
                                &id,
                                &mut terminal,
                                &mut events,
                            )
                            .await?
                            {
                                break;
                            }
                        } else {
                            app.status =
                                "No API client available to open this vulnerability".to_owned();
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

async fn load_weakness_detail(
    client: &ApiClient,
    app: &mut App,
    id: &str,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> anyhow::Result<()> {
    app.status = format!("Loading {id}…");
    draw_frame(terminal, |frame| render::render(frame, app))?;
    match api::weakness::get(client, id).await {
        Ok(item) => app.open_weakness_details(item),
        Err(error) => app.status = error.to_string(),
    }
    Ok(())
}

async fn load_vulnerability_detail(
    client: &ApiClient,
    app: &mut App,
    id: &str,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    events: &mut EventStream,
) -> anyhow::Result<bool> {
    app.status = format!("Loading vulnerability {id}…");
    draw_frame(terminal, |frame| render::render(frame, app))?;
    let params = ListParams {
        query: Some(format!("id={id}")),
        limit: Some(1),
        offset: Some(0),
        ..ListParams::default()
    };
    match await_with_terminal_interrupt(events, api::vulnerability::list(client, &params)).await? {
        Some(Ok(response)) => {
            if let Some(item) = response
                .get("items")
                .and_then(Value::as_array)
                .and_then(|items| items.first())
                .cloned()
            {
                app.open_linked_details("Vulnerability", item, ListResource::Vulnerability);
            } else {
                app.status = format!("No vulnerability found for {id}");
            }
        }
        Some(Err(error)) => app.status = error.to_string(),
        None => return Ok(true),
    }
    Ok(false)
}

async fn load_related_exploits(
    client: &ApiClient,
    app: &mut App,
    vulnerability_id: &str,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    events: &mut EventStream,
) -> anyhow::Result<bool> {
    app.status = format!("Loading exploits for {vulnerability_id}…");
    draw_frame(terminal, |frame| render::render(frame, app))?;
    let params = ListParams {
        query: Some(format!("cve_id={vulnerability_id}")),
        limit: Some(100),
        offset: Some(0),
        ..ListParams::default()
    };
    match await_with_terminal_interrupt(events, api::exploit::list(client, &params)).await? {
        Some(Ok(response)) => {
            let exploits = response
                .get("items")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            app.open_exploit_list(exploits);
        }
        Some(Err(error)) => app.status = error.to_string(),
        None => return Ok(true),
    }
    Ok(false)
}

async fn load_exploit_detail(
    client: &ApiClient,
    app: &mut App,
    id: &str,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    events: &mut EventStream,
) -> anyhow::Result<bool> {
    app.status = format!("Loading exploit {id}…");
    draw_frame(terminal, |frame| render::render(frame, app))?;
    match await_with_terminal_interrupt(events, api::exploit::get(client, id)).await? {
        Some(Ok(item)) => app.open_linked_details("Exploit", item, ListResource::Exploit),
        Some(Err(error)) => app.status = error.to_string(),
        None => return Ok(true),
    }
    Ok(false)
}

async fn await_with_terminal_interrupt<T, E, F>(
    events: &mut EventStream,
    future: F,
) -> anyhow::Result<Option<Result<T, E>>>
where
    F: Future<Output = Result<T, E>>,
{
    tokio::pin!(future);
    loop {
        tokio::select! {
            result = &mut future => return Ok(Some(result)),
            event = events.next() => match event {
                Some(Ok(Event::Key(key)))
                    if key.kind == KeyEventKind::Press
                        && key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL) => return Ok(None),
                Some(Ok(_)) => {}
                Some(Err(error)) => return Err(error).context("reading terminal event while waiting for Trustify"),
                None => return Ok(None),
            }
        }
    }
}

async fn load_records_page(
    client: &ApiClient,
    resource: ListResource,
    app: &mut App,
    offset: u32,
    include_total: bool,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> anyhow::Result<()> {
    app.status = "Loading page…".to_owned();
    draw_frame(terminal, |frame| render::render(frame, app))?;

    let params = ListParams {
        query: app.list_query(),
        limit: Some(app.page_size),
        offset: Some(offset),
        sort: app.params.sort.clone(),
        total: include_total,
    };
    let response = match api::list_resource(client, resource, &params).await {
        Ok(response) => response,
        Err(error) => {
            app.status = error.to_string();
            return Ok(());
        }
    };
    if !app.set_page(response, offset)? {
        app.status = "No more results".to_owned();
    }
    Ok(())
}

async fn load_page(
    client: &ApiClient,
    app: &mut App,
    offset: u32,
    include_total: bool,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> anyhow::Result<()> {
    app.status = "Loading page…".to_owned();
    draw_frame(terminal, |frame| render::render(frame, app))?;

    let params = sbom::ListParams {
        query: app.list_query(),
        limit: Some(app.page_size),
        offset: Some(offset),
        sort: app.params.sort.clone(),
        total: include_total,
    };
    let response = match sbom::list(client, &params).await {
        Ok(response) => response,
        Err(error) => {
            app.status = error.to_string();
            return Ok(());
        }
    };
    if !app.set_page(response, offset)? {
        app.status = "No more results".to_owned();
    }
    Ok(())
}

fn draw_frame(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    draw: impl FnOnce(&mut Frame<'_>),
) -> anyhow::Result<()> {
    terminal.draw(draw)?;
    Ok(())
}
struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> anyhow::Result<Self> {
        enable_raw_mode().context("enabling terminal raw mode")?;
        if let Err(error) = execute!(io::stdout(), EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(error).context("entering alternate screen");
        }
        crate::logging::set_tui_active(true);
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        crate::logging::set_tui_active(false);
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_navigation_selects_an_entity() {
        let mut menu = MenuState::default();
        let mut settings = AppSettings::default();

        assert_eq!(
            menu.handle_key(KeyCode::Down, &mut settings),
            MenuAction::None
        );
        assert_eq!(menu.selected, 1);
        assert_eq!(
            menu.handle_key(KeyCode::Enter, &mut settings),
            MenuAction::Select(ListResource::Vulnerability)
        );
    }

    #[test]
    fn main_menu_r_requests_entity_count_refresh() {
        let mut menu = MenuState::default();
        let mut settings = AppSettings::default();

        assert_eq!(
            menu.handle_key(KeyCode::Char('r'), &mut settings),
            MenuAction::RefreshCounts
        );
    }

    #[test]
    fn menu_exit_keys_close_the_picker() {
        let mut menu = MenuState::default();
        let mut settings = AppSettings::default();
        assert_eq!(
            menu.handle_key(KeyCode::Char('q'), &mut settings),
            MenuAction::Exit
        );
        assert_eq!(
            menu.handle_key(KeyCode::Esc, &mut settings),
            MenuAction::Exit
        );
    }

    #[test]
    fn menu_help_opens_with_h_and_closes_without_changing_selection() {
        let mut menu = MenuState::default();
        let mut settings = AppSettings::default();

        assert_eq!(
            menu.handle_key(KeyCode::Char('h'), &mut settings),
            MenuAction::None
        );
        assert!(menu.help_open);
        assert_eq!(
            menu.handle_key(KeyCode::Down, &mut settings),
            MenuAction::None
        );
        assert_eq!(menu.selected, 0);
        assert_eq!(
            menu.handle_key(KeyCode::Esc, &mut settings),
            MenuAction::None
        );
        assert!(!menu.help_open);
    }

    #[test]
    fn settings_menu_entry_opens_and_changes_theme() {
        let mut menu = MenuState::default();
        let mut settings = AppSettings::default();
        for _ in 0..=MENU_ENTRIES.len() {
            menu.handle_key(KeyCode::Down, &mut settings);
        }

        assert_eq!(menu.selected, MENU_ENTRIES.len());
        assert_eq!(
            menu.handle_key(KeyCode::Enter, &mut settings),
            MenuAction::OpenSettings
        );
        menu.settings_open = true;
        assert_eq!(
            menu.handle_key(KeyCode::Char('l'), &mut settings),
            MenuAction::SaveSettings
        );
        assert_eq!(settings.theme, ThemeMode::Light);
        assert_eq!(
            menu.handle_key(KeyCode::Char('d'), &mut settings),
            MenuAction::SaveSettings
        );
        assert_eq!(settings.theme, ThemeMode::Dark);
        assert_eq!(
            menu.handle_key(KeyCode::Esc, &mut settings),
            MenuAction::None
        );
        assert!(!menu.settings_open);
    }

    #[test]
    fn settings_can_edit_and_disable_an_entity_default_sort() {
        let mut menu = MenuState {
            settings_open: true,
            settings_selected: 2,
            settings_input: Some(String::new()),
            ..MenuState::default()
        };
        let mut settings = AppSettings::default();

        assert_eq!(
            menu.handle_key(KeyCode::Char('n'), &mut settings),
            MenuAction::None
        );
        assert_eq!(
            menu.handle_key(KeyCode::Char('a'), &mut settings),
            MenuAction::None
        );
        assert_eq!(
            menu.handle_key(KeyCode::Enter, &mut settings),
            MenuAction::SaveSettings
        );
        assert_eq!(settings.default_sort(ListResource::Sbom), Some("na"));
        assert_eq!(
            menu.handle_key(KeyCode::Char('r'), &mut settings),
            MenuAction::SaveSettings
        );
        assert_eq!(
            settings.default_sort(ListResource::Sbom),
            Some("published:desc")
        );

        menu.settings_selected = 3;
        menu.settings_input = Some(String::new());
        assert_eq!(
            menu.handle_key(KeyCode::Enter, &mut settings),
            MenuAction::SaveSettings
        );
        assert_eq!(settings.default_sort(ListResource::Vulnerability), None);
    }

    #[test]
    fn settings_can_edit_and_reset_page_size() {
        let mut menu = MenuState {
            settings_open: true,
            settings_selected: 1,
            ..MenuState::default()
        };
        let mut settings = AppSettings::default();

        assert_eq!(
            menu.handle_key(KeyCode::Enter, &mut settings),
            MenuAction::None
        );
        for _ in 0..2 {
            menu.handle_key(KeyCode::Backspace, &mut settings);
        }
        menu.handle_key(KeyCode::Char('4'), &mut settings);
        menu.handle_key(KeyCode::Char('2'), &mut settings);
        assert_eq!(
            menu.handle_key(KeyCode::Enter, &mut settings),
            MenuAction::SaveSettings
        );
        assert_eq!(settings.page_size, 42);

        assert_eq!(
            menu.handle_key(KeyCode::Char('r'), &mut settings),
            MenuAction::SaveSettings
        );
        assert_eq!(settings.page_size, DEFAULT_PAGE_SIZE);

        menu.handle_key(KeyCode::Enter, &mut settings);
        menu.handle_key(KeyCode::Backspace, &mut settings);
        menu.handle_key(KeyCode::Backspace, &mut settings);
        assert_eq!(
            menu.handle_key(KeyCode::Enter, &mut settings),
            MenuAction::None
        );
        assert_eq!(menu.settings_input.as_deref(), Some(""));
        assert!(menu.settings_error.is_some());
    }

    #[test]
    fn menu_can_toggle_the_debug_log_pane() {
        let mut menu = MenuState::default();
        let mut settings = AppSettings::default();

        assert_eq!(
            menu.handle_key(KeyCode::Char('l'), &mut settings),
            MenuAction::None
        );
        assert!(menu.log_pane_open);
        assert_eq!(
            menu.handle_key(KeyCode::Char('l'), &mut settings),
            MenuAction::None
        );
        assert!(!menu.log_pane_open);
    }

    #[test]
    fn menu_selection_stays_within_available_entities() {
        let mut menu = MenuState {
            selected: MENU_ENTRIES.len(),
            ..MenuState::default()
        };
        let mut settings = AppSettings::default();

        assert_eq!(
            menu.handle_key(KeyCode::Down, &mut settings),
            MenuAction::None
        );
        assert_eq!(menu.selected, MENU_ENTRIES.len());
        assert_eq!(
            menu.handle_key(KeyCode::Up, &mut settings),
            MenuAction::None
        );
        assert_eq!(menu.selected, MENU_ENTRIES.len() - 1);
    }

    #[test]
    fn menu_includes_products_exploits_weaknesses_and_organizations() {
        for resource in [
            ListResource::Product,
            ListResource::Exploit,
            ListResource::Weakness,
            ListResource::Organization,
        ] {
            assert!(
                MENU_ENTRIES.iter().any(|entry| entry.resource == resource),
                "missing TUI menu entry for {resource:?}"
            );
        }
    }

    #[test]
    fn entity_count_cache_retains_results_and_does_not_restart_fetches() {
        let counts = EntityCountCache::default();

        assert!(counts.begin_fetch(ListResource::Sbom));
        assert!(!counts.begin_fetch(ListResource::Sbom));
        assert!(!counts.begin_refresh(ListResource::Sbom));
        assert_eq!(counts.total(ListResource::Sbom), None);

        counts.set_total(ListResource::Sbom, Some(42));

        assert_eq!(counts.total(ListResource::Sbom), Some(42));
        assert!(!counts.begin_fetch(ListResource::Sbom));
        assert!(counts.begin_refresh(ListResource::Sbom));
        assert_eq!(counts.state(ListResource::Sbom), Some(EntityCount::Loading));
        assert!(!counts.begin_refresh(ListResource::Sbom));
    }

    #[tokio::test]
    async fn entity_count_cache_notifies_subscribers_when_counts_arrive() {
        let counts = EntityCountCache::default();
        let mut updates = counts.subscribe();
        assert!(counts.begin_fetch(ListResource::Product));
        updates.changed().await.expect("loading update");

        counts.set_total(ListResource::Product, Some(9));
        updates.changed().await.expect("result update");

        assert_eq!(counts.total(ListResource::Product), Some(9));
    }
}
