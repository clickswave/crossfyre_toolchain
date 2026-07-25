use crate::scanner::StreamEvent;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, List, ListItem, ListState, Paragraph, Row, Table, TableState},
    Frame, Terminal,
};
use std::io;
use tokio::sync::mpsc;

#[derive(PartialEq, Clone, Copy)]
enum Screen {
    Home,
    Logs,
}

struct LogEntry {
    level: String,
    message: String,
}

struct FoundUrl {
    url: String,
    code: String,
    body: i64,
    headers: i64,
}

struct AppState {
    screen: Screen,
    operation_id: String,
    total: usize,
    scanned: usize,
    found: usize,
    not_found: usize,
    errors: usize,
    found_urls: Vec<FoundUrl>,
    table_state: TableState,
    logs: Vec<LogEntry>,
    log_state: ListState,
    done: bool,
}

impl AppState {
    fn new(operation_id: String, total: usize) -> Self {
        Self {
            screen: Screen::Home,
            operation_id,
            total,
            scanned: 0,
            found: 0,
            not_found: 0,
            errors: 0,
            found_urls: Vec::new(),
            table_state: TableState::default(),
            logs: Vec::new(),
            log_state: ListState::default(),
            done: false,
        }
    }

    fn apply_event(&mut self, event: StreamEvent) {
        match event.kind.as_str() {
            "result" => {
                self.scanned += 1;
                match event.status.as_deref().unwrap_or("error") {
                    "found" => {
                        self.found += 1;
                        if let Some(url) = event.url {
                            self.found_urls.push(FoundUrl {
                                url,
                                code: event.code.unwrap_or_default(),
                                body: event.body_length.unwrap_or(0),
                                headers: event.headers_length.unwrap_or(0),
                            });
                            self.table_state.select(Some(self.found_urls.len().saturating_sub(1)));
                        }
                    }
                    "not_found" => self.not_found += 1,
                    _ => self.errors += 1,
                }
            }
            "log" => {
                self.logs.push(LogEntry {
                    level: event.log_level.unwrap_or_else(|| "info".to_string()),
                    message: event.message.unwrap_or_default(),
                });
                self.log_state.select(Some(self.logs.len().saturating_sub(1)));
            }
            "done" => {
                self.done = true;
                if let Some(f) = event.found { self.found = f; }
                if let Some(n) = event.not_found { self.not_found = n; }
                if let Some(e) = event.error { self.errors = e; }
                if let Some(t) = event.total { self.scanned = t; }
                self.logs.push(LogEntry {
                    level: "info".to_string(),
                    message: format!(
                        "Scan complete - found: {}, not_found: {}, errors: {}",
                        self.found, self.not_found, self.errors
                    ),
                });
                self.log_state.select(Some(self.logs.len().saturating_sub(1)));
            }
            _ => {}
        }
    }
}

fn render_header<'a>(state: &'a AppState) -> Paragraph<'a> {
    let status_str = if state.done { "DONE" } else { "RUNNING" };
    let status_color = if state.done { Color::Green } else { Color::Yellow };
    let home_style = if state.screen == Screen::Home {
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let logs_style = if state.screen == Screen::Logs {
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    Paragraph::new(Line::from(vec![
        Span::styled("  MACH  ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(status_str, Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
        Span::raw("    "),
        Span::styled("[h] Home", home_style),
        Span::raw("  "),
        Span::styled("[l] Logs", logs_style),
        Span::raw("    "),
        Span::styled(&state.operation_id, Style::default().fg(Color::DarkGray)),
    ]))
    .block(Block::default().borders(Borders::ALL))
}

fn render_home(frame: &mut Frame, state: &mut AppState, area: ratatui::layout::Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(area);

    // Progress
    let ratio = if state.total > 0 {
        (state.scanned as f64 / state.total as f64).min(1.0)
    } else {
        0.0
    };
    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title("Progress"))
        .gauge_style(Style::default().fg(Color::Cyan))
        .ratio(ratio)
        .label(format!("{} / {}", state.scanned, state.total));
    frame.render_widget(gauge, chunks[0]);

    // Stats
    let counters = Paragraph::new(Line::from(vec![
        Span::raw("  "),
        Span::styled("Found: ", Style::default().fg(Color::DarkGray)),
        Span::styled(state.found.to_string(), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::raw("   "),
        Span::styled("Not Found: ", Style::default().fg(Color::DarkGray)),
        Span::styled(state.not_found.to_string(), Style::default().fg(Color::White)),
        Span::raw("   "),
        Span::styled("Errors: ", Style::default().fg(Color::DarkGray)),
        Span::styled(state.errors.to_string(), Style::default().fg(Color::Red)),
    ]))
    .block(Block::default().borders(Borders::ALL).title("Stats"));
    frame.render_widget(counters, chunks[1]);

    // Found URLs table
    let header_cells = ["Code", "Body", "Headers", "URL"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    let table_header = Row::new(header_cells).height(1);

    let rows: Vec<Row> = state.found_urls.iter().map(|fu| {
        let code_color = match fu.code.chars().next() {
            Some('2') => Color::Green,
            Some('3') => Color::Yellow,
            Some('4') | Some('5') => Color::Red,
            _ => Color::White,
        };
        Row::new(vec![
            Cell::from(fu.code.clone()).style(Style::default().fg(code_color)),
            Cell::from(fu.body.to_string()),
            Cell::from(fu.headers.to_string()),
            Cell::from(fu.url.clone()),
        ])
    }).collect();

    let table = Table::new(
        rows,
        [Constraint::Length(6), Constraint::Length(10), Constraint::Length(10), Constraint::Min(0)],
    )
    .header(table_header)
    .block(Block::default().borders(Borders::ALL).title("Found URLs"))
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    frame.render_stateful_widget(table, chunks[2], &mut state.table_state);
}

fn render_logs(frame: &mut Frame, state: &mut AppState, area: ratatui::layout::Rect) {
    let items: Vec<ListItem> = state.logs.iter().map(|entry| {
        let (level_color, prefix) = match entry.level.as_str() {
            "error" => (Color::Red, "ERR"),
            "warn"  => (Color::Yellow, "WRN"),
            "debug" => (Color::DarkGray, "DBG"),
            _       => (Color::Cyan, "INF"),
        };
        ListItem::new(Line::from(vec![
            Span::styled(format!("[{}] ", prefix), Style::default().fg(level_color)),
            Span::raw(entry.message.clone()),
        ]))
    }).collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Logs"))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    frame.render_stateful_widget(list, area, &mut state.log_state);
}

fn render(frame: &mut Frame, state: &mut AppState) {
    let area = frame.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    frame.render_widget(render_header(state), chunks[0]);

    match state.screen {
        Screen::Home => render_home(frame, state, chunks[1]),
        Screen::Logs => render_logs(frame, state, chunks[1]),
    }

    let footer_text = if state.done {
        "  Scan complete - press q to exit"
    } else {
        "  Press q to exit"
    };
    frame.render_widget(
        Paragraph::new(footer_text).style(Style::default().fg(Color::DarkGray)),
        chunks[2],
    );
}

pub async fn run(
    rx: mpsc::UnboundedReceiver<StreamEvent>,
    operation_id: String,
    total: usize,
    poll_timeout: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::task::spawn_blocking(move || {
        run_blocking(rx, operation_id, total, poll_timeout)
    })
    .await?
    .map_err(|e| -> Box<dyn std::error::Error> { format!("{}", e).into() })
}

fn run_blocking(
    mut rx: mpsc::UnboundedReceiver<StreamEvent>,
    operation_id: String,
    total: usize,
    poll_timeout: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = AppState::new(operation_id, total);
    let tick = std::time::Duration::from_millis(poll_timeout.min(100));

    let result = (|| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            loop {
                match rx.try_recv() {
                    Ok(ev) => state.apply_event(ev),
                    Err(_) => break,
                }
            }

            terminal.draw(|f| render(f, &mut state))?;

            if state.done {
                loop {
                    if event::poll(std::time::Duration::from_millis(200))? {
                        if let Event::Key(key) = event::read()? {
                            if key.kind == KeyEventKind::Press {
                                match key.code {
                                    KeyCode::Char('q') => return Ok(()),
                                    KeyCode::Char('h') => state.screen = Screen::Home,
                                    KeyCode::Char('l') => state.screen = Screen::Logs,
                                    _ => {}
                                }
                                terminal.draw(|f| render(f, &mut state))?;
                            }
                        }
                    }
                }
            }

            if event::poll(tick)? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        match key.code {
                            KeyCode::Char('q') => return Ok(()),
                            KeyCode::Char('h') => state.screen = Screen::Home,
                            KeyCode::Char('l') => state.screen = Screen::Logs,
                            _ => {}
                        }
                    }
                }
            }
        }
    })();

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    result
}
