use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Text},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap},
    Frame,
};
use serde_json::Value;

use super::app::{App, Screen};

pub fn render(frame: &mut Frame<'_>, app: &App) {
    match &app.screen {
        Screen::List => render_list(frame, app),
        Screen::Detail { item, scroll } => render_detail(frame, item, *scroll, app),
    }
}

fn render_list(frame: &mut Frame<'_>, app: &App) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(2),
        ])
        .split(frame.area());

    let title = if let Some(query) = &app.params.query {
        format!("SBOMs · {query}")
    } else {
        "SBOMs".to_owned()
    };
    frame.render_widget(
        Paragraph::new(title).block(Block::default().borders(Borders::ALL)),
        layout[0],
    );

    let header = Row::new(["ID", "NAME", "PUBLISHED", "PACKAGES", "SUPPLIERS"]).style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    let rows = app.items.iter().map(|item| {
        Row::new([
            Cell::from(short_id(sbom_id(item).unwrap_or("—"))),
            Cell::from(first_value(item, &["name", "document_id"])),
            Cell::from(value_text(item.get("published"))),
            Cell::from(value_text(item.get("number_of_packages"))),
            Cell::from(value_text(item.get("suppliers"))),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(13),
            Constraint::Min(18),
            Constraint::Length(21),
            Constraint::Length(10),
            Constraint::Min(16),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL))
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
    .highlight_symbol("› ");
    let mut state = TableState::default();
    state.select((!app.items.is_empty()).then_some(app.selected));
    frame.render_stateful_widget(table, layout[1], &mut state);

    let page = app.offset / app.page_size.max(1) + 1;
    let total = app
        .total
        .map(|total| format!(" · {total} total"))
        .unwrap_or_default();
    let footer = if let Some(query) = &app.search_input {
        format!("Search: {query}▏  Enter apply · Esc cancel")
    } else {
        format!(
            "Page {page}{total} · ↑/↓ or j/k select · Enter details · n/p page · / search · q quit{}",
            if app.status.is_empty() {
                String::new()
            } else {
                format!(" · {}", app.status)
            }
        )
    };
    frame.render_widget(Paragraph::new(footer), layout[2]);
}

fn render_detail(frame: &mut Frame<'_>, item: &Value, scroll: u16, app: &App) {
    let id = sbom_id(item).unwrap_or("SBOM detail");
    let title = format!("SBOM · {id}");
    let json = serde_json::to_string_pretty(item).unwrap_or_else(|_| item.to_string());
    let lines = json.lines().map(Line::from).collect::<Vec<_>>();
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(1)])
        .split(frame.area());

    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(Block::default().title(title).borders(Borders::ALL))
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        layout[0],
    );
    frame.render_widget(
        Paragraph::new(format!(
            "↑/↓ or j/k scroll · Esc back to list · q quit{}",
            app.status
        )),
        layout[1],
    );
}

fn sbom_id(item: &Value) -> Option<&str> {
    item.get("id")
        .or_else(|| item.get("uuid"))
        .and_then(Value::as_str)
}

fn first_value(item: &Value, fields: &[&str]) -> String {
    fields
        .iter()
        .find_map(|field| item.get(field))
        .map(|value| value_text(Some(value)))
        .unwrap_or_else(|| "—".to_owned())
}

fn value_text(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "—".to_owned(),
        Some(Value::String(value)) => value.clone(),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| value.to_string())
            })
            .collect::<Vec<_>>()
            .join(", "),
        Some(value) => value.to_string(),
    }
}

fn short_id(id: &str) -> String {
    let id = id.strip_prefix("urn:uuid:").unwrap_or(id);
    let mut characters = id.chars();
    let prefix = characters.by_ref().take(10).collect::<String>();
    if characters.next().is_some() {
        format!("{prefix}…")
    } else {
        id.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_read_sbom_summary_fields() {
        let item = serde_json::json!({
            "id": "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
            "name": "test-sbom",
            "published": "2025-01-01T00:00:00Z",
            "number_of_packages": 42,
            "suppliers": ["Acme"]
        });

        assert_eq!(short_id(sbom_id(&item).expect("SBOM id")), "123e4567-e…");
        assert_eq!(first_value(&item, &["name", "document_id"]), "test-sbom");
        assert_eq!(value_text(item.get("number_of_packages")), "42");
        assert_eq!(value_text(item.get("suppliers")), "Acme");
    }
}
