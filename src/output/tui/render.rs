use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, Borders, Cell, List, ListItem, ListState, Paragraph, Row, Table, TableState, Wrap,
    },
    Frame,
};
use serde_json::Value;

use crate::api::ListResource;
use crate::settings::AppSettings;

use super::app::{App, Screen};
use super::theme::ThemeMode;

pub fn render(frame: &mut Frame<'_>, app: &App) {
    let palette = app.theme.palette();
    frame.render_widget(
        Block::default().style(Style::default().bg(palette.background)),
        frame.area(),
    );
    if app.help_open {
        render_app_help(frame, app, app.theme);
        return;
    }
    if app.severity_filter_open {
        render_severity_filter(frame, app, app.theme);
        return;
    }

    match &app.screen {
        Screen::List => render_list(frame, app, app.theme),
        Screen::Detail {
            item,
            scroll,
            title,
            resource,
            ..
        } => render_detail(frame, item, *scroll, title, *resource, app, app.theme),
        Screen::CweList { cwes, selected, .. } => {
            render_cwe_list(frame, cwes, *selected, app, app.theme)
        }
        Screen::ExploitList {
            exploits, selected, ..
        } => render_exploit_list(frame, exploits, *selected, app, app.theme),
    }
}

fn render_app_help(frame: &mut Frame<'_>, app: &App, theme: ThemeMode) {
    let (context, instructions): (&str, &[&str]) = match &app.screen {
        Screen::List => (
            "List",
            &[
                "↑/↓ or j/k  Move through rows",
                "Enter       Open the selected record",
                "n/p         Next/previous page",
                "/           Search; Enter applies, Esc cancels",
                "s           Edit the sort expression",
                "d           Filter by date when available",
                "f           Filter vulnerabilities by severity",
                "v           Toggle the preview pane",
                "l           Toggle debug logs",
                "q           Return to the entity menu",
                "h           Show or close this help",
            ],
        ),
        Screen::CweList { .. } => (
            "CWE selection",
            &[
                "↑/↓ or j/k  Select a CWE",
                "Enter       Open the selected weakness details",
                "Esc/q       Return to the vulnerability details",
                "h           Show or close this help",
            ],
        ),
        Screen::ExploitList { .. } => (
            "Related exploits",
            &[
                "↑/↓ or j/k  Select an exploit",
                "Enter       Open the selected exploit details",
                "Esc/q       Return to the vulnerability details",
                "h           Show or close this help",
            ],
        ),
        Screen::Detail {
            resource: Some(ListResource::Vulnerability),
            ..
        } => (
            "Vulnerability details",
            &[
                "↑/↓ or j/k  Scroll the details",
                "c           Open the first associated weakness",
                "Enter       Choose from associated CWE references",
                "e           Browse associated exploits",
                "Esc         Return to the list or CWE selection",
                "q           Exit the detail view",
                "l           Toggle debug logs",
                "h           Show or close this help",
            ],
        ),
        Screen::Detail {
            resource: Some(ListResource::Exploit),
            ..
        } => (
            "Exploit details",
            &[
                "↑/↓ or j/k  Scroll the details",
                "v           Open the associated vulnerability",
                "Esc         Return to the list or related exploits",
                "q           Exit the detail view",
                "l           Toggle debug logs",
                "h           Show or close this help",
            ],
        ),
        Screen::Detail { .. } => (
            "Record details",
            &[
                "↑/↓ or j/k  Scroll the details",
                "Esc         Return to the list",
                "q           Exit the detail view",
                "l           Toggle debug logs",
                "h           Show or close this help",
            ],
        ),
    };
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(frame.area());

    render_banner_with_target(
        frame,
        areas[0],
        &format!("Help · {context}"),
        &app.instance_label,
        theme,
    );
    render_help_panel(frame, areas[1], "Keyboard shortcuts", instructions, theme);
    render_status(frame, areas[2], "h/Esc/q close help", theme);
}

pub(super) fn render_help_panel(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    lines: &[&str],
    theme: ThemeMode,
) {
    let palette = theme.palette();
    let paragraph = Paragraph::new(help_body(lines))
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(palette.border))
                .style(Style::default().fg(palette.foreground).bg(palette.surface)),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

fn render_severity_filter(frame: &mut Frame<'_>, app: &App, theme: ThemeMode) {
    let palette = theme.palette();
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(6),
            Constraint::Length(1),
        ])
        .split(frame.area());
    render_banner_with_target(
        frame,
        areas[0],
        "Filter vulnerabilities by severity",
        &app.instance_label,
        theme,
    );

    let items = super::app::SEVERITY_FILTER_OPTIONS
        .iter()
        .map(|severity| {
            let checked = app
                .severity_filter_draft
                .iter()
                .any(|selected| selected == severity);
            let checkbox = if checked { "[✓]" } else { "[ ]" };
            ListItem::new(Line::from(vec![
                Span::styled(
                    checkbox,
                    Style::default()
                        .fg(palette.accent_bright)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(severity.to_ascii_uppercase(), severity_style(severity)),
            ]))
        })
        .collect::<Vec<_>>();
    let list = List::new(items)
        .block(
            Block::default()
                .title("Severity")
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
    state.select(Some(app.severity_filter_selected));
    frame.render_stateful_widget(list, areas[1], &mut state);
    render_status(
        frame,
        areas[2],
        "↑/↓ move · Space toggle · a all/none · Enter apply · Esc cancel",
        theme,
    );
}

pub(super) fn render_settings_panel(
    frame: &mut Frame<'_>,
    area: Rect,
    settings: &AppSettings,
    sort_rows: &[(ListResource, &str)],
    selected: usize,
    editing: Option<&str>,
    error: Option<&str>,
) {
    let theme = settings.theme;
    let palette = theme.palette();
    let block = Block::default()
        .title("Settings · display preferences")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(palette.border))
        .style(Style::default().fg(palette.foreground).bg(palette.surface));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(2)])
        .split(inner);
    let theme_name = match settings.theme {
        ThemeMode::Dark => "Dark",
        ThemeMode::Light => "Light",
    };
    let mut items = vec![ListItem::new(Line::from(vec![
        Span::styled(
            "Appearance",
            Style::default()
                .fg(palette.accent_bright)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("  {theme_name}")),
    ]))];
    let page_size = if selected == 1 {
        editing
            .map(|value| format!("{value}▏"))
            .unwrap_or_else(|| settings.page_size.to_string())
    } else {
        settings.page_size.to_string()
    };
    items.push(ListItem::new(Line::from(vec![
        Span::styled(
            "Rows per page",
            Style::default()
                .fg(palette.accent_bright)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("  {page_size}"), Style::default().fg(palette.muted)),
    ])));
    for (index, (resource, title)) in sort_rows.iter().enumerate() {
        let row_index = index + 2;
        let is_editing = editing.is_some() && row_index == selected;
        let sort = if is_editing {
            editing.unwrap_or_default()
        } else {
            settings.sort_value(*resource)
        };
        let sort = if !is_editing && sort.trim().is_empty() {
            "(disabled)".to_owned()
        } else {
            sort.to_owned()
        };
        let value = if is_editing {
            format!("{sort}▏")
        } else {
            sort
        };
        items.push(ListItem::new(Line::from(vec![
            Span::styled(
                *title,
                Style::default()
                    .fg(palette.accent_bright)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  Default sort: {value}"),
                Style::default().fg(palette.muted),
            ),
        ])));
    }
    let list = List::new(items)
        .highlight_style(
            Style::default()
                .fg(palette.selection_foreground)
                .bg(palette.selection)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("› ");
    let mut state = ListState::default();
    state.select(Some(selected));
    frame.render_stateful_widget(list, areas[0], &mut state);

    let instructions = match error {
        Some(error) => format!(
            "{error} · saved to {}",
            AppSettings::config_path().display()
        ),
        None => format!(
            "Enter toggles appearance or edits value · r resets · saved to {}",
            AppSettings::config_path().display()
        ),
    };
    frame.render_widget(
        Paragraph::new(instructions)
            .style(Style::default().fg(palette.muted).bg(palette.surface))
            .wrap(Wrap { trim: true }),
        areas[1],
    );
}

fn help_body(lines: &[&str]) -> String {
    format!(
        "{}\n\nProject repository: {}",
        lines.join("\n"),
        repository_link_label()
    )
}

pub(super) fn render_banner_with_target(
    frame: &mut Frame<'_>,
    area: Rect,
    context: &str,
    instance_label: &str,
    theme: ThemeMode,
) {
    let palette = theme.palette();
    let version = version_label();
    let target = (!instance_label.is_empty()).then(|| format!("Target: {instance_label}"));
    let target_width = target
        .as_ref()
        .map(|target| {
            target
                .chars()
                .count()
                .min(42)
                .min(area.width.saturating_sub((version.len() + 14) as u16) as usize)
                as u16
        })
        .filter(|width| *width >= "Target: x".chars().count() as u16)
        .unwrap_or_default();
    let areas = Layout::horizontal([
        Constraint::Length((version.len() + 2) as u16),
        Constraint::Min(1),
        Constraint::Length(target_width),
    ])
    .split(area);

    frame.render_widget(
        Paragraph::new(format!(" {version} ")).style(
            Style::default()
                .fg(palette.badge_foreground)
                .bg(palette.badge_background)
                .add_modifier(Modifier::BOLD),
        ),
        areas[0],
    );
    frame.render_widget(
        Paragraph::new(format!(" {context}")).style(
            Style::default()
                .fg(palette.foreground)
                .bg(palette.surface_alt),
        ),
        areas[1],
    );
    if let Some(target) = target.filter(|_| target_width > 0) {
        frame.render_widget(
            Paragraph::new(truncate_instance_label(&target, target_width as usize))
                .alignment(Alignment::Right)
                .style(
                    Style::default()
                        .fg(palette.accent_bright)
                        .bg(palette.surface_alt),
                ),
            areas[2],
        );
    }
}

pub(super) fn render_status(frame: &mut Frame<'_>, area: Rect, message: &str, theme: ThemeMode) {
    let palette = theme.palette();
    let line = Line::from(vec![
        Span::styled(
            " STATUS ",
            Style::default()
                .fg(palette.badge_foreground)
                .bg(palette.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(" {message}")),
    ]);
    frame.render_widget(
        Paragraph::new(line).style(
            Style::default()
                .fg(palette.status_foreground)
                .bg(palette.status_background),
        ),
        area,
    );
}

fn truncate_instance_label(label: &str, width: usize) -> String {
    let characters = label.chars().collect::<Vec<_>>();
    if characters.len() <= width {
        return label.to_owned();
    }
    if width == 0 {
        return String::new();
    }
    format!(
        "{}…",
        characters.into_iter().take(width - 1).collect::<String>()
    )
}

fn version_label() -> String {
    format!("trusty v{}", env!("CARGO_PKG_VERSION"))
}

pub(super) fn repository_link_label() -> String {
    env!("CARGO_PKG_REPOSITORY").to_owned()
}

fn render_list(frame: &mut Frame<'_>, app: &App, theme: ThemeMode) {
    let palette = theme.palette();
    let preview_height = if app.preview_pane_open {
        Constraint::Min(7)
    } else {
        Constraint::Length(0)
    };
    let log_pane_height = if app.log_pane_open {
        Constraint::Length(5)
    } else {
        Constraint::Length(0)
    };
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(5),
            preview_height,
            log_pane_height,
            Constraint::Length(1),
        ])
        .split(frame.area());

    let context = if let Some(query) = &app.params.query {
        format!("{} · {query}", app.title)
    } else {
        app.title.clone()
    };
    render_banner_with_target(frame, layout[0], &context, &app.instance_label, theme);

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
                        .map(|column| {
                            let value = record_value(item, column);
                            if app.resource == Some(ListResource::Vulnerability)
                                && column == "severity"
                                && value != "—"
                            {
                                Cell::from(Line::from(Span::styled(
                                    format!(" {value} "),
                                    severity_style(&value),
                                )))
                            } else {
                                Cell::from(value)
                            }
                        })
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
                    Cell::from(sbom_display_id(item)),
                    Cell::from(first_value(item, &["name"])),
                    Cell::from(value_text(item.get("published"))),
                    Cell::from(value_text(item.get("number_of_packages"))),
                    Cell::from(value_text(item.get("suppliers"))),
                ])
            })
            .collect::<Vec<_>>();
        (
            ["DOCUMENT ID", "NAME", "PUBLISHED", "PACKAGES", "SUPPLIERS"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            rows,
            vec![
                Constraint::Length(20),
                Constraint::Min(16),
                Constraint::Length(18),
                Constraint::Length(10),
                Constraint::Min(12),
            ],
        )
    };
    let header = Row::new(headers).style(
        Style::default()
            .fg(palette.accent_bright)
            .add_modifier(Modifier::BOLD),
    );
    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(palette.border))
                .style(Style::default().fg(palette.foreground).bg(palette.surface)),
        )
        .style(Style::default().fg(palette.foreground).bg(palette.surface))
        .row_highlight_style(
            Style::default()
                .fg(palette.selection_foreground)
                .bg(palette.selection)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("› ");
    let mut state = TableState::default();
    state.select((!app.items.is_empty()).then_some(app.selected));
    frame.render_stateful_widget(table, layout[1], &mut state);

    if app.preview_pane_open {
        render_preview_pane(frame, layout[2], app.items.get(app.selected), app, theme);
    }
    if app.log_pane_open {
        render_log_pane(frame, layout[3], theme);
    }
    render_status(frame, layout[4], &list_status(app), theme);
}

fn render_preview_pane(
    frame: &mut Frame<'_>,
    area: Rect,
    item: Option<&Value>,
    app: &App,
    theme: ThemeMode,
) {
    let palette = theme.palette();
    let (title, lines) = if let Some(item) = item {
        let fields = detail_fields(item, app.resource);
        let lines = if fields.is_empty() {
            vec![Line::from("No information available")]
        } else {
            fields
                .into_iter()
                .take(8)
                .map(|(label, value)| {
                    Line::from(vec![
                        Span::styled(
                            format!("{label}: "),
                            Style::default()
                                .fg(palette.accent_bright)
                                .add_modifier(Modifier::BOLD),
                        ),
                        if label.ends_with("SEVERITY") {
                            Span::styled(value.clone(), severity_style(&value))
                        } else {
                            Span::raw(value)
                        },
                    ])
                })
                .collect()
        };
        (
            record_id(item, app.resource).unwrap_or("Selected item"),
            lines,
        )
    } else {
        ("No selection", vec![Line::from("No item selected")])
    };
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(
                Block::default()
                    .title(format!(" Preview · {title} · v hide "))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(palette.border))
                    .style(Style::default().fg(palette.foreground).bg(palette.surface)),
            )
            .style(Style::default().fg(palette.foreground).bg(palette.surface))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_detail(
    frame: &mut Frame<'_>,
    item: &Value,
    scroll: u16,
    item_title: &str,
    resource: Option<ListResource>,
    app: &App,
    theme: ThemeMode,
) {
    let palette = theme.palette();
    let id = record_id(item, resource).unwrap_or("details");
    let title = format!("{item_title} · {id}");
    let fields = detail_fields(item, resource);
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
                            .fg(palette.accent_bright)
                            .add_modifier(Modifier::BOLD),
                    ),
                    if label.ends_with("SEVERITY") {
                        Span::styled(value.clone(), severity_style(&value))
                    } else {
                        Span::raw(value)
                    },
                ])
            })
            .collect()
    };
    let log_pane_height = if app.log_pane_open {
        Constraint::Length(5)
    } else {
        Constraint::Length(0)
    };
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(5),
            log_pane_height,
            Constraint::Length(1),
        ])
        .split(frame.area());

    render_banner_with_target(frame, layout[0], &title, &app.instance_label, theme);
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(
                Block::default()
                    .title(" Information ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(palette.border))
                    .style(Style::default().fg(palette.foreground).bg(palette.surface)),
            )
            .style(Style::default().fg(palette.foreground).bg(palette.surface))
            .wrap(Wrap { trim: true })
            .scroll((scroll, 0)),
        layout[1],
    );
    if app.log_pane_open {
        render_log_pane(frame, layout[2], theme);
    }
    let status = if app.status.is_empty() {
        "↑/↓ or j/k scroll · Esc back · q back".to_owned()
    } else {
        format!("{} · ↑/↓ scroll · Esc back · q back", app.status)
    };
    let log_hint = if app.log_pane_open {
        " · l hide logs"
    } else {
        " · l logs"
    };
    let cwe_hint = if resource == Some(ListResource::Vulnerability)
        && item
            .get("cwes")
            .and_then(Value::as_array)
            .is_some_and(|cwes| !cwes.is_empty())
    {
        " · c first CWE · Enter CWE list"
    } else {
        ""
    };
    let relationship_hint = match resource {
        Some(ListResource::Vulnerability) => " · e related exploits",
        Some(ListResource::Exploit) if item.get("cve_id").and_then(Value::as_str).is_some() => {
            " · v vulnerability"
        }
        _ => "",
    };
    render_status(
        frame,
        layout[3],
        &format!("{status}{cwe_hint}{relationship_hint}{log_hint} · h help"),
        theme,
    );
}

fn render_cwe_list(
    frame: &mut Frame<'_>,
    cwes: &[String],
    selected: usize,
    app: &App,
    theme: ThemeMode,
) {
    let palette = theme.palette();
    let log_pane_height = if app.log_pane_open {
        Constraint::Length(5)
    } else {
        Constraint::Length(0)
    };
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(5),
            log_pane_height,
            Constraint::Length(1),
        ])
        .split(frame.area());

    render_banner_with_target(
        frame,
        layout[0],
        "Associated CWE references",
        &app.instance_label,
        theme,
    );
    let items = cwes
        .iter()
        .map(|cwe| ListItem::new(cwe.clone()))
        .collect::<Vec<_>>();
    let list = List::new(items)
        .block(
            Block::default()
                .title("CWEs · Enter inspect")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(palette.border))
                .style(Style::default().fg(palette.foreground).bg(palette.surface)),
        )
        .style(Style::default().fg(palette.foreground).bg(palette.surface))
        .highlight_style(
            Style::default()
                .fg(palette.selection_foreground)
                .bg(palette.selection)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("› ");
    let mut state = ListState::default();
    state.select(Some(selected));
    frame.render_stateful_widget(list, layout[1], &mut state);
    if app.log_pane_open {
        render_log_pane(frame, layout[2], theme);
    }
    render_status(
        frame,
        layout[3],
        "↑/↓ or j/k choose · Enter inspect · Esc/q back · h help",
        theme,
    );
}

fn render_exploit_list(
    frame: &mut Frame<'_>,
    exploits: &[Value],
    selected: usize,
    app: &App,
    theme: ThemeMode,
) {
    let palette = theme.palette();
    let log_pane_height = if app.log_pane_open {
        Constraint::Length(5)
    } else {
        Constraint::Length(0)
    };
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(5),
            log_pane_height,
            Constraint::Length(1),
        ])
        .split(frame.area());

    render_banner_with_target(
        frame,
        layout[0],
        "Exploits linked to this vulnerability",
        &app.instance_label,
        theme,
    );
    let items = exploits
        .iter()
        .map(|exploit| {
            ListItem::new(format!(
                "{} · {} · reported {} · remediation due {}",
                value_text(exploit.get("cve_id")),
                value_text(exploit.get("source")),
                value_text(exploit.get("date_reported")),
                value_text(exploit.get("remediation_due_date")),
            ))
        })
        .collect::<Vec<_>>();
    let list = List::new(items)
        .block(
            Block::default()
                .title("Related exploits · Enter inspect")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(palette.border))
                .style(Style::default().fg(palette.foreground).bg(palette.surface)),
        )
        .style(Style::default().fg(palette.foreground).bg(palette.surface))
        .highlight_style(
            Style::default()
                .fg(palette.selection_foreground)
                .bg(palette.selection)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("› ");
    let mut state = ListState::default();
    state.select(Some(selected));
    frame.render_stateful_widget(list, layout[1], &mut state);
    if app.log_pane_open {
        render_log_pane(frame, layout[2], theme);
    }
    render_status(
        frame,
        layout[3],
        "↑/↓ or j/k choose · Enter inspect · Esc/q back · h help",
        theme,
    );
}

pub(super) fn render_log_pane(frame: &mut Frame<'_>, area: Rect, theme: ThemeMode) {
    let palette = theme.palette();
    let logs = crate::logging::recent_logs();
    let body = if logs.is_empty() {
        "No log events yet".to_owned()
    } else {
        logs[logs.len().saturating_sub(3)..].join("\n")
    };
    let paragraph = Paragraph::new(body)
        .block(
            Block::default()
                .title(" Debug logs · l hide ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(palette.border))
                .style(Style::default().fg(palette.log).bg(palette.surface)),
        )
        .style(Style::default().fg(palette.log).bg(palette.surface))
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

fn list_status(app: &App) -> String {
    if let Some(query) = &app.search_input {
        return format!("Search: {query}▏ · Enter apply · Esc cancel");
    }
    if let Some(sort) = &app.sort_input {
        return format!("Sort expression: {sort}▏ · Enter apply · Esc cancel");
    }
    if let Some(input) = &app.date_range_input {
        let field = app.date_field().unwrap_or("date");
        let validation = if app.status.is_empty() {
            String::new()
        } else {
            format!(" · {}", app.status)
        };
        return format!(
            "Date range ({field}): {input}▏ · YYYY-MM-DD..YYYY-MM-DD · blank clears · Enter apply · Esc cancel{validation}"
        );
    }

    let page = app.offset / app.page_size.max(1) + 1;
    let page_status = match app.total {
        Some(total) => format!("Page {page} · {} rows · Total: {total}", app.items.len()),
        None => format!("Page {page} · {} rows", app.items.len()),
    };
    let state = if app.status.is_empty() {
        page_status
    } else {
        format!("{} · {page_status}", app.status)
    };
    let sort = app
        .params
        .sort
        .as_ref()
        .map(|sort| format!(" · Sort: {sort}"))
        .unwrap_or_default();
    let date_range = match (&app.date_range, app.date_field()) {
        (Some(range), Some(field)) => {
            format!(" · {field}: {}", range.input_value())
        }
        _ => String::new(),
    };
    let date_hint = if app.date_field().is_some() {
        " · d date"
    } else {
        ""
    };
    let log_hint = if app.log_pane_open {
        " · l hide logs"
    } else {
        " · l logs"
    };
    let preview_hint = if app.preview_pane_open {
        " · v hide preview"
    } else {
        " · v preview"
    };
    let severity_filter = app
        .severity_filter
        .as_ref()
        .map(|severities| format!(" · Severity: {}", severities.join(", ")))
        .unwrap_or_default();
    let severity_hint = if app.resource == Some(ListResource::Vulnerability) {
        " · f severity"
    } else {
        ""
    };
    format!(
        "{state}{sort}{date_range}{severity_filter} · j/k move · Enter open · n/p page · / search · s sort{date_hint}{severity_hint}{preview_hint}{log_hint} · h help · q back"
    )
}

fn sbom_id(item: &Value) -> Option<&str> {
    ["document_id", "id", "uuid"]
        .iter()
        .find_map(|field| item.get(*field).and_then(Value::as_str))
}

fn sbom_display_id(item: &Value) -> String {
    if let Some(document_id) = item.get("document_id").and_then(Value::as_str) {
        return document_id.to_owned();
    }

    sbom_id(item)
        .map(short_id)
        .unwrap_or_else(|| "—".to_owned())
}

fn record_id(item: &Value, resource: Option<ListResource>) -> Option<&str> {
    let preferred = match resource {
        Some(ListResource::Sbom) => [
            "document_id",
            "id",
            "uuid",
            "identifier",
            "name",
            "purl",
            "license",
        ],
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
        Some(ListResource::Exploit) => [
            "cve_id",
            "id",
            "source",
            "name",
            "license",
            "purl",
            "document_id",
        ],
        Some(ListResource::Organization | ListResource::Product) => [
            "name",
            "id",
            "uuid",
            "identifier",
            "document_id",
            "purl",
            "license",
        ],
        Some(ListResource::Weakness) => [
            "id",
            "identifier",
            "document_id",
            "uuid",
            "purl",
            "name",
            "license",
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
            "document_id",
            "name",
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
            "cwes",
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
        Some(ListResource::Exploit) => &[
            "id",
            "cve_id",
            "source",
            "date_reported",
            "remediation_due_date",
            "metadata",
        ][..],
        Some(ListResource::Organization) => &["id", "name", "cpe_key", "website", "advisories"][..],
        Some(ListResource::Product) => &["id", "name", "vendor", "versions"][..],
        Some(ListResource::Weakness) => &[
            "id",
            "description",
            "extended_description",
            "child_of",
            "parent_of",
            "starts_with",
            "can_follow",
            "can_precede",
            "required_by",
            "requires",
            "can_also_be",
            "peer_of",
        ][..],
        None => &[],
    };

    let mut fields = Vec::with_capacity(object.len());
    for field in preferred {
        if let Some(value) = object.get(*field).filter(|value| !value.is_null()) {
            fields.push((column_label(field), value_text(Some(value))));
        }
    }
    if resource == Some(ListResource::Vulnerability) {
        if let Some(exploits) = item.get("exploits").and_then(Value::as_array) {
            if !exploits.is_empty() {
                fields.push((
                    "EXPLOITS".to_owned(),
                    format!("{} linked · press e to browse", exploits.len()),
                ));
            }
        }
    }
    for (field, value) in object {
        if resource == Some(ListResource::Vulnerability) && field == "exploits" {
            continue;
        }
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
        let value = match column {
            "severity" => item
                .get("base_score")
                .and_then(|base_score| base_score.get("severity"))
                .filter(|value| !value.is_null())
                .or_else(|| item.get("base_severity"))
                .filter(|value| !value.is_null())
                .or_else(|| item.get(column)),
            "score" => item
                .get("base_score")
                .and_then(|base_score| base_score.get("score"))
                .filter(|value| !value.is_null())
                .or_else(|| item.get(column)),
            "type" => item
                .get("labels")
                .and_then(|labels| labels.get("type"))
                .filter(|value| !value.is_null())
                .or_else(|| item.get(column)),
            _ => item.get(column),
        };
        let value = value_text(value);
        if matches!(column, "published" | "modified") {
            return value
                .split_once('T')
                .map_or(value.clone(), |(date, _)| date.to_owned());
        }
        value
    }
}

fn severity_style(severity: &str) -> Style {
    match severity.trim().to_ascii_lowercase().as_str() {
        "critical" => Style::default()
            .fg(Color::White)
            .bg(Color::Rgb(145, 24, 40))
            .add_modifier(Modifier::BOLD),
        "high" => Style::default()
            .fg(Color::White)
            .bg(Color::Rgb(196, 55, 49))
            .add_modifier(Modifier::BOLD),
        "medium" => Style::default()
            .fg(Color::Black)
            .bg(Color::Rgb(245, 190, 55))
            .add_modifier(Modifier::BOLD),
        "low" => Style::default()
            .fg(Color::White)
            .bg(Color::Rgb(45, 125, 82))
            .add_modifier(Modifier::BOLD),
        _ => Style::default()
            .fg(Color::White)
            .bg(Color::Rgb(89, 96, 108))
            .add_modifier(Modifier::BOLD),
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
                "published" | "modified" => Constraint::Length(12),
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
    fn sbom_views_prioritize_the_document_id_over_the_uuid() {
        let item = serde_json::json!({
            "id": "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
            "uuid": "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
            "document_id": "acme-product-2026-09",
            "name": "test-sbom"
        });

        assert_eq!(sbom_id(&item), Some("acme-product-2026-09"));
        assert_eq!(sbom_display_id(&item), "acme-product-2026-09");
        assert_eq!(
            record_id(&item, Some(ListResource::Sbom)),
            Some("acme-product-2026-09")
        );
        assert_eq!(
            detail_fields(&item, Some(ListResource::Sbom))[0],
            ("DOCUMENT ID".to_owned(), "acme-product-2026-09".to_owned())
        );

        let uuid_only = serde_json::json!({
            "uuid": "urn:uuid:123e4567-e89b-12d3-a456-426614174000"
        });
        assert_eq!(sbom_display_id(&uuid_only), "123e4567-e…");
    }

    #[test]
    fn banner_identifies_the_product_and_version() {
        assert_eq!(
            version_label(),
            format!("trusty v{}", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn help_includes_the_project_repository_url() {
        let body = help_body(&["Keyboard shortcuts"]);

        assert_eq!(
            body,
            "Keyboard shortcuts\n\nProject repository: https://github.com/rh-jfuller/trusty"
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

        assert!(status.contains("Page 1 · 2 rows · Total: 8"));
        assert!(status.contains("Enter open"));
        assert!(status.contains("/ search"));
        assert!(status.contains("s sort"));
        assert!(status.contains("v hide preview"));

        let mut sorted_app = app;
        sorted_app.params.sort = Some("name".to_owned());
        assert!(list_status(&sorted_app).contains("Sort: name"));

        sorted_app.sort_input = Some("published".to_owned());
        assert!(list_status(&sorted_app).contains("Sort expression: published"));

        sorted_app.sort_input = None;
        sorted_app.date_range = Some(crate::output::tui::app::DateRange {
            from: Some("2025-01-01".to_owned()),
            to: Some("2025-12-31".to_owned()),
        });
        assert!(list_status(&sorted_app).contains("published: 2025-01-01..2025-12-31"));
        assert!(list_status(&sorted_app).contains("d date"));

        sorted_app.date_range_input = Some("2025-01-01..2025-12-31".to_owned());
        assert!(list_status(&sorted_app).contains("Date range (published):"));
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
    fn vulnerability_rows_display_nested_base_score_fields() {
        let item = serde_json::json!({
            "base_score": {
                "score": 9.8,
                "severity": "CRITICAL"
            }
        });
        let app = App::records(
            serde_json::json!({"items": [item.clone()]}),
            crate::api::ListParams::default(),
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
        assert_eq!(record_value(&item, "severity"), "CRITICAL");
        assert_eq!(record_value(&item, "score"), "9.8");
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
    fn advisory_type_is_rendered_from_labels() {
        let item = serde_json::json!({
            "document_id": "GHSA-abcd-1234",
            "title": "Example advisory",
            "labels": {"type": "cve"}
        });
        let app = App::records(
            serde_json::json!({"items": [item.clone()]}),
            crate::api::ListParams::default(),
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
                "type".to_owned(),
            ])
        );
        assert_eq!(record_value(&item, "type"), "cve");
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

    #[test]
    fn vulnerability_details_summarize_linked_exploits() {
        let item = serde_json::json!({
            "identifier": "CVE-2025-1234",
            "exploits": [{
                "id": "exploit-1",
                "cve_id": "CVE-2025-1234",
                "source": "cisa-kev",
                "metadata": {"notes": "large nested exploit metadata"}
            }]
        });

        let fields = detail_fields(&item, Some(ListResource::Vulnerability));

        assert!(fields.contains(&(
            "EXPLOITS".to_owned(),
            "1 linked · press e to browse".to_owned()
        )));
        assert!(!fields
            .iter()
            .any(|(_, value)| value.contains("large nested exploit metadata")));
    }
}
