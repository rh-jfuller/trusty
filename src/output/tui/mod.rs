mod app;
mod render;

use std::io;

use anyhow::Context as _;
use crossterm::{
    event::{Event, EventStream, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures_util::StreamExt;
use ratatui::{backend::CrosstermBackend, Terminal};
use serde_json::Value;

use crate::{
    api::{sbom, ApiClient},
    output::tui::app::{Action, App},
};

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
    terminal.clear()?;
    let mut events = EventStream::new();

    loop {
        terminal.draw(|frame| render::render(frame, &app))?;
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
                            terminal.draw(|frame| render::render(frame, &app))?;
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

pub async fn show_detail(item: Value) -> anyhow::Result<()> {
    let mut app = App::detail(item);
    let _guard = TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    terminal.clear()?;
    let mut events = EventStream::new();

    loop {
        terminal.draw(|frame| render::render(frame, &app))?;
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

async fn load_page(
    client: &ApiClient,
    app: &mut App,
    offset: u32,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> anyhow::Result<()> {
    app.status = "Loading page…".to_owned();
    terminal.draw(|frame| render::render(frame, app))?;

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
