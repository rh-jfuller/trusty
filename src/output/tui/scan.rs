use std::{future::Future, io};

use crossterm::{
    event::{Event, EventStream, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{Clear, ClearType},
};
use futures_util::StreamExt;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap},
    Frame, Terminal,
};
use serde_json::Value;

use super::{render, theme::ThemeMode};

struct FindingRow {
    purl: String,
    identifier: String,
    severity: String,
    status: String,
    title: String,
}

pub async fn run_scan<F, Fut>(
    mut target: String,
    instance_label: String,
    theme: ThemeMode,
    scan: F,
) -> anyhow::Result<()>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = anyhow::Result<Value>>,
{
    let _guard = super::TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    execute!(io::stdout(), Clear(ClearType::All))?;
    let mut events = EventStream::new();
    let mut result = None;
    let mut rows = Vec::new();
    let mut selected = 0;
    let mut findings = 0;
    let mut error = None;

    loop {
        super::draw_frame(&mut terminal, |frame| {
            render_scan(
                frame,
                &target,
                &instance_label,
                result.as_ref(),
                &rows,
                selected,
                findings,
                error.as_deref(),
                theme,
            )
        })?;
        let Some(event) = events.next().await else {
            break;
        };
        match event? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                    break;
                }
                if result.is_some() {
                    match key.code {
                        KeyCode::Up | KeyCode::Char('k') => selected = selected.saturating_sub(1),
                        KeyCode::Down | KeyCode::Char('j') => {
                            selected = (selected + 1).min(rows.len().saturating_sub(1));
                        }
                        KeyCode::Esc => {
                            result = None;
                            rows.clear();
                            selected = 0;
                            error = None;
                        }
                        KeyCode::Char('q') => break,
                        _ => {}
                    }
                    continue;
                }

                match key.code {
                    KeyCode::Esc => break,
                    KeyCode::Enter => {
                        let target_value = target.trim().to_owned();
                        if target_value.is_empty() {
                            error = Some("Enter a scan target".to_owned());
                            continue;
                        }
                        error = None;
                        super::draw_frame(&mut terminal, |frame| {
                            render_scan(
                                frame,
                                &target,
                                &instance_label,
                                None,
                                &rows,
                                selected,
                                findings,
                                Some("Scanning… Ctrl-C to cancel"),
                                theme,
                            )
                        })?;
                        match super::await_with_terminal_interrupt(&mut events, scan(target_value))
                            .await?
                        {
                            None => break,
                            Some(Ok(scanned)) => {
                                (rows, findings) = finding_rows(&scanned);
                                selected = 0;
                                result = Some(scanned);
                            }
                            Some(Err(scan_error)) => error = Some(scan_error.to_string()),
                        }
                    }
                    KeyCode::Backspace => {
                        target.pop();
                        error = None;
                    }
                    KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        target.clear();
                        error = None;
                    }
                    KeyCode::Char(character) if !character.is_control() => {
                        target.push(character);
                        error = None;
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn finding_rows(result: &Value) -> (Vec<FindingRow>, usize) {
    let mut rows = Vec::new();
    let mut findings = 0;
    let Some(packages) = result.get("packages").and_then(Value::as_array) else {
        return (rows, findings);
    };
    let analysis = result.get("analysis").and_then(Value::as_object);

    for package in packages {
        let purl = package
            .get("purl")
            .and_then(Value::as_str)
            .unwrap_or("unknown package");
        let details = analysis
            .and_then(|analysis| analysis.get(purl))
            .and_then(|item| item.get("details"))
            .and_then(Value::as_array);
        let Some(details) = details.filter(|details| !details.is_empty()) else {
            rows.push(FindingRow {
                purl: purl.to_owned(),
                identifier: "—".to_owned(),
                severity: "—".to_owned(),
                status: "No known vulnerabilities".to_owned(),
                title: String::new(),
            });
            continue;
        };

        for detail in details {
            findings += 1;
            let identifier = detail
                .get("identifier")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned();
            let severity = detail
                .pointer("/base_score/severity")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned();
            let title = detail
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let statuses = detail.get("purl_statuses").and_then(Value::as_array);
            if let Some(statuses) = statuses.filter(|statuses| !statuses.is_empty()) {
                for status in statuses {
                    rows.push(FindingRow {
                        purl: purl.to_owned(),
                        identifier: identifier.clone(),
                        severity: severity.clone(),
                        status: status
                            .get("status")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown")
                            .to_owned(),
                        title: title.clone(),
                    });
                }
            } else {
                rows.push(FindingRow {
                    purl: purl.to_owned(),
                    identifier,
                    severity,
                    status: "—".to_owned(),
                    title,
                });
            }
        }
    }
    (rows, findings)
}

#[allow(clippy::too_many_arguments)]
fn render_scan(
    frame: &mut Frame<'_>,
    target: &str,
    instance_label: &str,
    result: Option<&Value>,
    rows: &[FindingRow],
    selected: usize,
    findings: usize,
    error: Option<&str>,
    theme: ThemeMode,
) {
    let palette = theme.palette();
    frame.render_widget(
        Block::default().style(Style::default().bg(palette.background)),
        frame.area(),
    );
    if let Some(result) = result {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(5),
                Constraint::Length(1),
            ])
            .split(frame.area());
        render::render_banner_with_target(
            frame,
            layout[0],
            &format!(
                "Scan results · {} package(s) · {findings} finding(s)",
                result
                    .get("package_count")
                    .and_then(Value::as_u64)
                    .unwrap_or_default()
            ),
            instance_label,
            theme,
        );
        let table_rows = rows
            .iter()
            .map(|row| {
                Row::new([
                    Cell::from(row.purl.clone()),
                    Cell::from(row.identifier.clone()),
                    Cell::from(row.severity.clone()),
                    Cell::from(row.status.clone()),
                    Cell::from(row.title.clone()),
                ])
            })
            .collect::<Vec<_>>();
        let table = Table::new(
            table_rows,
            [
                Constraint::Percentage(38),
                Constraint::Percentage(14),
                Constraint::Percentage(10),
                Constraint::Percentage(16),
                Constraint::Percentage(22),
            ],
        )
        .header(
            Row::new(["Package URL", "ID", "Severity", "Status", "Title"]).style(
                Style::default()
                    .fg(palette.accent_bright)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .block(
            Block::default()
                .title(format!(
                    " {} · {} analyzed ",
                    result
                        .get("target")
                        .and_then(Value::as_str)
                        .unwrap_or(target),
                    result
                        .get("analyzed_package_count")
                        .and_then(Value::as_u64)
                        .unwrap_or_default()
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(palette.border))
                .style(Style::default().fg(palette.foreground).bg(palette.surface)),
        )
        .row_highlight_style(
            Style::default()
                .fg(palette.selection_foreground)
                .bg(palette.selection)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("› ");
        let mut state = TableState::default();
        if !rows.is_empty() {
            state.select(Some(selected.min(rows.len() - 1)));
        }
        frame.render_stateful_widget(table, layout[1], &mut state);
        render::render_status(
            frame,
            layout[2],
            "↑/↓ or j/k browse · Esc edit target · q quit",
            theme,
        );
    } else {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(3),
                Constraint::Min(3),
                Constraint::Length(1),
            ])
            .split(frame.area());
        render::render_banner_with_target(
            frame,
            layout[0],
            "Vulnerability scan",
            instance_label,
            theme,
        );
        frame.render_widget(
            Paragraph::new(format!("{target}▏"))
                .block(
                    Block::default()
                        .title(" Scan target ")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(palette.accent))
                        .style(Style::default().fg(palette.foreground).bg(palette.surface)),
                )
                .style(Style::default().fg(palette.foreground).bg(palette.surface))
                .wrap(Wrap { trim: true }),
            layout[1],
        );
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::raw("Targets: "),
                Span::styled("dir:PATH", Style::default().fg(palette.accent_bright)),
                Span::raw(
                    " · sbom:PATH · pkg:PURL · name:COMPONENT · registry:IMAGE · oci-archive:PATH",
                ),
            ]))
            .style(Style::default().fg(palette.muted))
            .wrap(Wrap { trim: true }),
            layout[2],
        );
        render::render_status(
            frame,
            layout[3],
            error.unwrap_or(
                "Type a target · Enter scan · Backspace delete · Ctrl-U clear · Esc quit",
            ),
            theme,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::finding_rows;

    #[test]
    fn scan_results_show_vulnerabilities_and_clean_packages() {
        let result = serde_json::json!({
            "packages": [
                {"purl": "pkg:cargo/vulnerable@1.0.0"},
                {"purl": "pkg:cargo/clean@1.0.0"}
            ],
            "analysis": {
                "pkg:cargo/vulnerable@1.0.0": {
                    "details": [{
                        "identifier": "CVE-2025-0001",
                        "base_score": {"severity": "high"},
                        "purl_statuses": [{"status": "affected"}]
                    }]
                }
            }
        });

        let (rows, findings) = finding_rows(&result);
        assert_eq!(findings, 1);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].identifier, "CVE-2025-0001");
        assert_eq!(rows[0].status, "affected");
        assert_eq!(rows[1].status, "No known vulnerabilities");
    }
}
