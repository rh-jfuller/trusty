mod app;
mod render;
mod theme;

pub use theme::ThemeMode;

use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex},
};

use anyhow::Context as _;
use crossterm::{
    event::{Event, EventStream, KeyCode, KeyEventKind},
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

fn start_entity_count_requests(client: &ApiClient, counts: &EntityCountCache) {
    for entry in MENU_ENTRIES {
        if !counts.begin_fetch(entry.resource) {
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
    OpenSettings,
}

#[derive(Default)]
struct MenuState {
    selected: usize,
    log_pane_open: bool,
    help_open: bool,
    settings_open: bool,
}

impl MenuState {
    fn handle_key(&mut self, key: KeyCode, theme: &mut ThemeMode) -> MenuAction {
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
            match key {
                KeyCode::Esc | KeyCode::Backspace | KeyCode::Char('q') => {
                    self.settings_open = false;
                }
                KeyCode::Char('h') => self.help_open = true,
                KeyCode::Char('d') => *theme = ThemeMode::Dark,
                KeyCode::Char('l') => *theme = ThemeMode::Light,
                KeyCode::Enter | KeyCode::Char(' ') => theme.toggle(),
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
    client: &ApiClient,
    counts: &EntityCountCache,
    theme: &mut ThemeMode,
) -> anyhow::Result<Option<(ListResource, usize)>> {
    start_entity_count_requests(client, counts);
    let mut count_updates = counts.subscribe();
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
        draw_frame(&mut terminal, |frame| {
            render_main_menu(frame, &menu, instance_label, counts, *theme)
        })?;
        let event = tokio::select! {
            event = events.next() => event,
            changed = count_updates.changed() => {
                if changed.is_err() {
                    return Ok(None);
                }
                continue;
            }
        };
        let Some(event) = event else {
            return Ok(None);
        };
        if let Event::Key(key) = event.context("reading terminal event")? {
            if key.kind == KeyEventKind::Press {
                match menu.handle_key(key.code, theme) {
                    MenuAction::None => {}
                    MenuAction::Exit => return Ok(None),
                    MenuAction::Select(resource) => return Ok(Some((resource, menu.selected))),
                    MenuAction::OpenSettings => menu.settings_open = true,
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
    theme: ThemeMode,
) {
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
                    "Enter/Space Toggle dark/light mode",
                    "Esc/q       Return to the entity menu",
                    "h           Show or close this help",
                ]
            } else {
                &[
                    "↑/↓ or j/k  Select an entity or settings",
                    "Enter       Open the selected page",
                    "l           Toggle debug logs",
                    "q/Esc       Exit the entity menu",
                    "h           Show or close this help",
                ]
            },
            theme,
        );
    } else if menu.settings_open {
        render::render_settings_panel(frame, areas[1], theme);
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
        "h/Esc/q close help".to_owned()
    } else if menu.settings_open {
        "d dark · l light · Enter toggle · Esc back · h help".to_owned()
    } else {
        let log_hint = if menu.log_pane_open {
            " · l hide logs"
        } else {
            " · l logs"
        };
        format!("↑/↓ or j/k select · Enter open · q/Esc exit{log_hint} · h help")
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
                    Action::BrowseCwes(cwes) => app.open_cwe_list(cwes),
                    Action::OpenWeakness(id) => {
                        load_weakness_detail(client, &mut app, &id, &mut terminal).await?;
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
                    Action::BrowseCwes(cwes) => app.open_cwe_list(cwes),
                    Action::OpenWeakness(id) => {
                        load_weakness_detail(client, &mut app, &id, &mut terminal).await?;
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
) -> anyhow::Result<()> {
    run_detail_viewer(
        App::detail_as(title, item).with_instance_label(instance_label),
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
                match app.handle_key(key.code) {
                    Action::Quit => break,
                    Action::Back => app.go_back(),
                    Action::BrowseCwes(cwes) => app.open_cwe_list(cwes),
                    Action::OpenWeakness(id) => {
                        if let Some(client) = client {
                            load_weakness_detail(client, &mut app, &id, &mut terminal).await?;
                        } else {
                            app.status = "No API client available to open this CWE".to_owned();
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
        let mut theme = ThemeMode::default();

        assert_eq!(menu.handle_key(KeyCode::Down, &mut theme), MenuAction::None);
        assert_eq!(menu.selected, 1);
        assert_eq!(
            menu.handle_key(KeyCode::Enter, &mut theme),
            MenuAction::Select(ListResource::Vulnerability)
        );
    }

    #[test]
    fn menu_exit_keys_close_the_picker() {
        let mut menu = MenuState::default();
        let mut theme = ThemeMode::default();
        assert_eq!(
            menu.handle_key(KeyCode::Char('q'), &mut theme),
            MenuAction::Exit
        );
        assert_eq!(menu.handle_key(KeyCode::Esc, &mut theme), MenuAction::Exit);
    }

    #[test]
    fn menu_help_opens_with_h_and_closes_without_changing_selection() {
        let mut menu = MenuState::default();
        let mut theme = ThemeMode::default();

        assert_eq!(
            menu.handle_key(KeyCode::Char('h'), &mut theme),
            MenuAction::None
        );
        assert!(menu.help_open);
        assert_eq!(menu.handle_key(KeyCode::Down, &mut theme), MenuAction::None);
        assert_eq!(menu.selected, 0);
        assert_eq!(menu.handle_key(KeyCode::Esc, &mut theme), MenuAction::None);
        assert!(!menu.help_open);
    }

    #[test]
    fn settings_menu_entry_opens_and_changes_theme() {
        let mut menu = MenuState::default();
        let mut theme = ThemeMode::Dark;
        for _ in 0..=MENU_ENTRIES.len() {
            menu.handle_key(KeyCode::Down, &mut theme);
        }

        assert_eq!(menu.selected, MENU_ENTRIES.len());
        assert_eq!(
            menu.handle_key(KeyCode::Enter, &mut theme),
            MenuAction::OpenSettings
        );
        menu.settings_open = true;
        assert_eq!(
            menu.handle_key(KeyCode::Char('l'), &mut theme),
            MenuAction::None
        );
        assert_eq!(theme, ThemeMode::Light);
        assert_eq!(
            menu.handle_key(KeyCode::Char('d'), &mut theme),
            MenuAction::None
        );
        assert_eq!(theme, ThemeMode::Dark);
        assert_eq!(menu.handle_key(KeyCode::Esc, &mut theme), MenuAction::None);
        assert!(!menu.settings_open);
    }

    #[test]
    fn menu_can_toggle_the_debug_log_pane() {
        let mut menu = MenuState::default();
        let mut theme = ThemeMode::default();

        assert_eq!(
            menu.handle_key(KeyCode::Char('l'), &mut theme),
            MenuAction::None
        );
        assert!(menu.log_pane_open);
        assert_eq!(
            menu.handle_key(KeyCode::Char('l'), &mut theme),
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
        let mut theme = ThemeMode::default();

        assert_eq!(menu.handle_key(KeyCode::Down, &mut theme), MenuAction::None);
        assert_eq!(menu.selected, MENU_ENTRIES.len());
        assert_eq!(menu.handle_key(KeyCode::Up, &mut theme), MenuAction::None);
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
        assert_eq!(counts.total(ListResource::Sbom), None);

        counts.set_total(ListResource::Sbom, Some(42));

        assert_eq!(counts.total(ListResource::Sbom), Some(42));
        assert!(!counts.begin_fetch(ListResource::Sbom));
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
