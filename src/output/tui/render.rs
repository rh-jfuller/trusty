use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap},
    Frame,
};
use serde_json::Value;

use crate::api::ListResource;

use super::app::{App, Screen};

pub fn render(frame: &mut Frame<'_>, app: &App) {
    match &app.screen {
        Screen::List => render_list(frame, app),
        Screen::Detail { item, scroll } => render_detail(frame, item, *scroll, app),
    }
}

pub(super) fn render_banner(frame: &mut Frame<'_>, area: Rect, context: &str) {
    let version = version_label();
    let repository = repository_link_label();
    let areas = Layout::horizontal([
        Constraint::Length((version.len() + 2) as u16),
        Constraint::Min(1),
        Constraint::Length((repository.len() + 2) as u16),
    ])
    .split(area);

    frame.render_widget(
        Paragraph::new(format!(" {version} ")).style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        areas[0],
    );
    frame.render_widget(
        Paragraph::new(format!(" {context}"))
            .style(Style::default().fg(Color::White).bg(Color::DarkGray)),
        areas[1],
    );
    frame.render_widget(
        Paragraph::new(format!(" {repository} ")).style(
            Style::default()
                .fg(Color::LightCyan)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::UNDERLINED),
        ),
        areas[2],
    );
}

pub(super) fn render_status(frame: &mut Frame<'_>, area: Rect, message: &str) {
    let line = Line::from(vec![
        Span::styled(
            " STATUS ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(" {message}")),
    ]);
    frame.render_widget(
        Paragraph::new(line).style(Style::default().fg(Color::White).bg(Color::DarkGray)),
        area,
    );
}

fn version_label() -> String {
    format!("trusty v{}", env!("CARGO_PKG_VERSION"))
}

pub(super) fn repository_link_label() -> String {
    env!("CARGO_PKG_REPOSITORY").to_owned()
}

fn render_list(frame: &mut Frame<'_>, app: &App) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(frame.area());

    let context = if let Some(query) = &app.params.query {
        format!("{} · {query}", app.title)
    } else {
        app.title.clone()
    };
    render_banner(frame, layout[0], &context);

    let (headers, rows, widths) = if let Some(columns) = &app.columns {
        let headers = columns
            .iter()
            .map(|column| column_label(column))
            .collect::<Vec<_>>();
        let rows = app
            .items
            .iter()
            .map(|item| {
                Row::new(
                    columns
                        .iter()
                        .map(|column| Cell::from(record_value(item, column)))
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        let widths = column_widths(columns, app.resource);
        (headers, rows, widths)
    } else {
        let rows = app
            .items
            .iter()
            .map(|item| {
                Row::new([
                    Cell::from(short_id(sbom_id(item).unwrap_or("—"))),
                    Cell::from(first_value(item, &["name", "document_id"])),
                    Cell::from(value_text(item.get("published"))),
                    Cell::from(value_text(item.get("number_of_packages"))),
                    Cell::from(value_text(item.get("suppliers"))),
                ])
            })
            .collect::<Vec<_>>();
        (
            ["ID", "NAME", "PUBLISHED", "PACKAGES", "SUPPLIERS"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            rows,
            vec![
                Constraint::Length(13),
                Constraint::Min(18),
                Constraint::Length(21),
                Constraint::Length(10),
                Constraint::Min(16),
            ],
        )
    };
    let header = Row::new(headers).style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("› ");
    let mut state = TableState::default();
    state.select((!app.items.is_empty()).then_some(app.selected));
    frame.render_stateful_widget(table, layout[1], &mut state);

    render_status(frame, layout[2], &list_status(app));
}

fn render_detail(frame: &mut Frame<'_>, item: &Value, scroll: u16, app: &App) {
    let id = record_id(item, app.resource).unwrap_or("details");
    let title = format!("{} · {id}", app.item_title);
    let fields = detail_fields(item, app.resource);
    let lines = if fields.is_empty() {
        vec![Line::from("No information available")]
    } else {
        fields
            .into_iter()
            .map(|(label, value)| {
                Line::from(vec![
                    Span::styled(
                        format!("{label}: "),
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(value),
                ])
            })
            .collect()
    };
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(frame.area());

    render_banner(frame, layout[0], &title);
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(
                Block::default()
                    .title(" Information ")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: true })
            .scroll((scroll, 0)),
        layout[1],
    );
    let status = if app.status.is_empty() {
        "↑/↓ or j/k scroll · Esc back · q back".to_owned()
    } else {
        format!("{} · ↑/↓ scroll · Esc back · q back", app.status)
    };
    render_status(frame, layout[2], &status);
}

fn list_status(app: &App) -> String {
    if let Some(query) = &app.search_input {
        return format!("Search: {query}▏ · Enter apply · Esc cancel");
    }

    let page = app.offset / app.page_size.max(1) + 1;
    let page_status = match app.total {
        Some(total) => format!("Page {page} · {}/{}", app.items.len(), total),
        None => format!("Page {page} · {} rows", app.items.len()),
    };
    let state = if app.status.is_empty() {
        page_status
    } else {
        format!("{} · {page_status}", app.status)
    };
    format!("{state} · j/k move · Enter open · n/p page · / search · q back")
}

fn sbom_id(item: &Value) -> Option<&str> {
    item.get("id")
        .or_else(|| item.get("uuid"))
        .and_then(Value::as_str)
}

fn record_id(item: &Value, resource: Option<ListResource>) -> Option<&str> {
    let preferred = match resource {
        Some(ListResource::Advisory) => [
            "document_id",
            "identifier",
            "id",
            "uuid",
            "purl",
            "name",
            "license",
        ],
        Some(ListResource::Package) => [
            "purl",
            "name",
            "id",
            "uuid",
            "identifier",
            "document_id",
            "license",
        ],
        Some(ListResource::License) => [
            "license",
            "name",
            "id",
            "uuid",
            "identifier",
            "document_id",
            "purl",
        ],
        _ => [
            "id",
            "uuid",
            "identifier",
            "document_id",
            "purl",
            "name",
            "license",
        ],
    };
    preferred
        .iter()
        .find_map(|field| item.get(*field).and_then(Value::as_str))
}

fn detail_fields(item: &Value, resource: Option<ListResource>) -> Vec<(String, String)> {
    let Some(object) = item.as_object() else {
        return vec![("VALUE".to_owned(), value_text(Some(item)))];
    };
    let preferred = match resource {
        Some(ListResource::Sbom) => &[
            "name",
            "document_id",
            "id",
            "uuid",
            "version",
            "spec_version",
            "published",
            "authors",
            "suppliers",
            "number_of_packages",
            "number_of_files",
            "number_of_dependencies",
            "source",
        ][..],
        Some(ListResource::Advisory) => &[
            "document_id",
            "id",
            "uuid",
            "title",
            "aliases",
            "published",
            "modified",
            "withdrawn",
            "severity",
            "average_severity",
            "average_score",
            "description",
            "vulnerabilities",
            "affected",
            "references",
        ][..],
        Some(ListResource::Vulnerability) => &[
            "id",
            "identifier",
            "title",
            "aliases",
            "summary",
            "published",
            "modified",
            "base_severity",
            "base_score",
            "severity",
            "score",
            "description",
            "weaknesses",
            "advisories",
            "affected",
            "references",
        ][..],
        Some(ListResource::Package) => &[
            "purl",
            "name",
            "version",
            "type",
            "namespace",
            "qualifiers",
            "subpath",
            "cpe",
            "licenses",
            "license",
            "supplier",
            "description",
            "source",
            "vulnerabilities",
        ][..],
        Some(ListResource::License) => &[
            "license",
            "name",
            "spdx_license_id",
            "status",
            "text",
            "url",
            "source",
            "see_also",
            "families",
        ][..],
        None => &[],
    };

    let mut fields = Vec::with_capacity(object.len());
    for field in preferred {
        if let Some(value) = object.get(*field).filter(|value| !value.is_null()) {
            fields.push((column_label(field), value_text(Some(value))));
        }
    }
    for (field, value) in object {
        if !value.is_null() && !preferred.contains(&field.as_str()) {
            fields.push((column_label(field), value_text(Some(value))));
        }
    }
    fields
}

fn column_label(column: &str) -> String {
    column.replace('_', " ").to_uppercase()
}

fn record_value(item: &Value, column: &str) -> String {
    if column == "value" && !item.is_object() {
        value_text(Some(item))
    } else {
        value_text(item.get(column))
    }
}

fn column_widths(columns: &[String], resource: Option<ListResource>) -> Vec<Constraint> {
    if matches!(
        resource,
        Some(ListResource::Advisory | ListResource::Vulnerability)
    ) {
        return columns
            .iter()
            .map(|column| match column.as_str() {
                "id" | "uuid" | "identifier" | "document_id" => Constraint::Length(18),
                "title" => Constraint::Fill(1),
                "severity" => Constraint::Length(12),
                "score" => Constraint::Length(8),
                _ => Constraint::Min(12),
            })
            .collect();
    }
    vec![Constraint::Min(12); columns.len()]
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

    #[test]
    fn banner_identifies_the_product_and_version() {
        assert_eq!(
            version_label(),
            format!("trusty v{}", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn banner_links_to_the_project_repository() {
        assert_eq!(
            repository_link_label(),
            "https://github.com/rh-jfuller/trusty"
        );
    }

    #[test]
    fn list_status_reports_page_counts_and_actions() {
        let app = App::new(
            serde_json::json!({
                "items": [{"id": "one"}, {"id": "two"}],
                "total": 8
            }),
            crate::api::ListParams::default(),
            5,
        )
        .expect("valid SBOM page");

        let status = list_status(&app);

        assert!(status.contains("Page 1 · 2/8"));
        assert!(status.contains("Enter open"));
        assert!(status.contains("/ search"));
    }

    #[test]
    fn vulnerability_columns_give_more_width_to_the_title() {
        let columns = ["id", "title", "severity", "score"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();

        assert_eq!(
            column_widths(&columns, Some(ListResource::Vulnerability)),
            vec![
                Constraint::Length(18),
                Constraint::Fill(1),
                Constraint::Length(12),
                Constraint::Length(8),
            ]
        );
    }

    #[test]
    fn advisory_columns_give_more_width_to_the_title() {
        let columns = ["document_id", "title"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();

        assert_eq!(
            column_widths(&columns, Some(ListResource::Advisory)),
            vec![Constraint::Length(18), Constraint::Fill(1)]
        );
    }

    #[test]
    fn advisory_details_prioritize_the_document_id_and_summary_fields() {
        let item = serde_json::json!({
            "id": "internal-id",
            "document_id": "GHSA-abcd-1234",
            "title": "Example advisory",
            "published": "2026-01-02",
            "description": null,
            "extra_field": "retained"
        });

        assert_eq!(
            record_id(&item, Some(ListResource::Advisory)),
            Some("GHSA-abcd-1234")
        );
        assert_eq!(
            detail_fields(&item, Some(ListResource::Advisory)),
            vec![
                ("DOCUMENT ID".to_owned(), "GHSA-abcd-1234".to_owned()),
                ("ID".to_owned(), "internal-id".to_owned()),
                ("TITLE".to_owned(), "Example advisory".to_owned()),
                ("PUBLISHED".to_owned(), "2026-01-02".to_owned()),
                ("EXTRA FIELD".to_owned(), "retained".to_owned()),
            ]
        );
    }
}
