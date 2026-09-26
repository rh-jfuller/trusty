mod app;
mod render;

use std::io;

use anyhow::Context as _;
use crossterm::{
    cursor::{Hide, MoveTo},
    event::{Event, EventStream, KeyCode, KeyEventKind},
    execute,
    style::{
        Attribute, Color as CrosstermColor, Print, ResetColor, SetAttribute, SetForegroundColor,
    },
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
    widgets::{Block, Borders, List, ListItem, ListState},
    Frame, Terminal,
};
use serde_json::Value;

use crate::{
    api::{self, sbom, ApiClient, ListParams, ListResource},
    output::tui::app::{Action, App},
};

const OSC8_OPEN: &str = "\x1b]8;;";
const OSC8_CLOSE: &str = "\x1b]8;;\x1b\\";

#[derive(Clone, Copy)]
struct MenuEntry {
    resource: ListResource,
    title: &'static str,
    description: &'static str,
}

const MENU_ENTRIES: [MenuEntry; 5] = [
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
];

#[derive(Debug, Eq, PartialEq)]
enum MenuAction {
    None,
    Exit,
    Select(ListResource),
}

#[derive(Default)]
struct MenuState {
    selected: usize,
}

impl MenuState {
    fn handle_key(&mut self, key: KeyCode) -> MenuAction {
        match key {
            KeyCode::Char('q') | KeyCode::Esc => MenuAction::Exit,
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = self.selected.saturating_sub(1);
                MenuAction::None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected + 1 < MENU_ENTRIES.len() {
                    self.selected += 1;
                }
                MenuAction::None
            }
            KeyCode::Enter => MenuAction::Select(MENU_ENTRIES[self.selected].resource),
            _ => MenuAction::None,
        }
    }
}

pub async fn main_menu(selected: usize) -> anyhow::Result<Option<(ListResource, usize)>> {
    let mut menu = MenuState {
        selected: selected.min(MENU_ENTRIES.len() - 1),
    };
    let _guard = TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    execute!(io::stdout(), Clear(ClearType::All))?;
    let mut events = EventStream::new();

    loop {
        draw_frame(&mut terminal, |frame| render_main_menu(frame, &menu))?;
        let Some(event) = events.next().await else {
            return Ok(None);
        };
        if let Event::Key(key) = event.context("reading terminal event")? {
            if key.kind == KeyEventKind::Press {
                match menu.handle_key(key.code) {
                    MenuAction::None => {}
                    MenuAction::Exit => return Ok(None),
                    MenuAction::Select(resource) => return Ok(Some((resource, menu.selected))),
                }
            }
        }
    }
}

fn render_main_menu(frame: &mut Frame<'_>, menu: &MenuState) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(7),
            Constraint::Length(1),
        ])
        .split(frame.area());

    render::render_banner(frame, areas[0], "Select an entity");

    let items = MENU_ENTRIES
        .iter()
        .map(|entry| ListItem::new(format!("{}  ·  {}", entry.title, entry.description)))
        .collect::<Vec<_>>();
    let list = List::new(items)
        .block(
            Block::default()
                .title("Main entities")
                .borders(Borders::ALL),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("› ");
    let mut state = ListState::default();
    state.select(Some(menu.selected));
    frame.render_stateful_widget(list, areas[1], &mut state);

    render::render_status(
        frame,
        areas[2],
        "↑/↓ or j/k select · Enter open · q/Esc exit",
    );
}

pub async fn browse_sboms(
    client: &ApiClient,
    mut params: sbom::ListParams,
    first_page: Value,
) -> anyhow::Result<()> {
    let page_size = params.limit.unwrap_or(20).max(1);
    params.limit = Some(page_size);
    let mut app = App::new(first_page, params, page_size)?;
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
                        load_page(client, &mut app, offset, &mut terminal).await?;
                    }
                    Action::PreviousPage => {
                        let offset = app.offset.saturating_sub(app.page_size);
                        load_page(client, &mut app, offset, &mut terminal).await?;
                    }
                    Action::Search(query) => {
                        app.params.query = query;
                        load_page(client, &mut app, 0, &mut terminal).await?;
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
) -> anyhow::Result<()> {
    let page_size = params.limit.unwrap_or(20).max(1);
    params.limit = Some(page_size);
    let mut app = App::records(first_page, params, page_size, title, resource)?;
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
                    Action::OpenDetails => {
                        if let Some(item) = app.items.get(app.selected).cloned() {
                            app.open_details(item);
                        }
                    }
                    Action::NextPage => {
                        let offset = app.offset.saturating_add(app.page_size);
                        load_records_page(client, resource, &mut app, offset, &mut terminal)
                            .await?;
                    }
                    Action::PreviousPage => {
                        let offset = app.offset.saturating_sub(app.page_size);
                        load_records_page(client, resource, &mut app, offset, &mut terminal)
                            .await?;
                    }
                    Action::Search(query) => {
                        app.params.query = query;
                        load_records_page(client, resource, &mut app, 0, &mut terminal).await?;
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
    let mut app = App::detail_as(title, item);
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
                if matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) {
                    break;
                }
                app.handle_key(key.code);
            }
        }
    }

    Ok(())
}

async fn load_records_page(
    client: &ApiClient,
    resource: ListResource,
    app: &mut App,
    offset: u32,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> anyhow::Result<()> {
    app.status = "Loading page…".to_owned();
    draw_frame(terminal, |frame| render::render(frame, app))?;

    let params = ListParams {
        query: app.params.query.clone(),
        limit: Some(app.page_size),
        offset: Some(offset),
        sort: app.params.sort.clone(),
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
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> anyhow::Result<()> {
    app.status = "Loading page…".to_owned();
    draw_frame(terminal, |frame| render::render(frame, app))?;

    let params = sbom::ListParams {
        query: app.params.query.clone(),
        limit: Some(app.page_size),
        offset: Some(offset),
        sort: app.params.sort.clone(),
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

    let size = terminal.size()?;
    let label = render::repository_link_label();
    let version = format!("trusty v{}", env!("CARGO_PKG_VERSION"));
    let minimum_width = (label.len() + version.len() + 5) as u16;
    if size.width < minimum_width {
        return Ok(());
    }

    let x = size.width.saturating_sub(label.len() as u16 + 1);
    let open = format!("{OSC8_OPEN}{}\x1b\\", env!("CARGO_PKG_REPOSITORY"));
    execute!(
        io::stdout(),
        MoveTo(x, 0),
        SetForegroundColor(CrosstermColor::Cyan),
        SetAttribute(Attribute::Underlined),
        Print(open),
        Print(label),
        Print(OSC8_CLOSE),
        SetAttribute(Attribute::Reset),
        ResetColor,
        Hide
    )?;
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
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
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

        assert_eq!(menu.handle_key(KeyCode::Down), MenuAction::None);
        assert_eq!(menu.selected, 1);
        assert_eq!(
            menu.handle_key(KeyCode::Enter),
            MenuAction::Select(ListResource::Vulnerability)
        );
    }

    #[test]
    fn menu_exit_keys_close_the_picker() {
        let mut menu = MenuState::default();
        assert_eq!(menu.handle_key(KeyCode::Char('q')), MenuAction::Exit);
        assert_eq!(menu.handle_key(KeyCode::Esc), MenuAction::Exit);
    }

    #[test]
    fn menu_selection_stays_within_available_entities() {
        let mut menu = MenuState {
            selected: MENU_ENTRIES.len() - 1,
        };

        assert_eq!(menu.handle_key(KeyCode::Down), MenuAction::None);
        assert_eq!(menu.selected, MENU_ENTRIES.len() - 1);
        assert_eq!(menu.handle_key(KeyCode::Up), MenuAction::None);
        assert_eq!(menu.selected, MENU_ENTRIES.len() - 2);
    }
}
