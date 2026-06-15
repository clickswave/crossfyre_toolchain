use crate::scanner::StreamEvent;
use crossterm::{
    event::{self, Event, KeyCode},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    execute,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table},
    Terminal,
};
use std::io;
use tokio::sync::mpsc;

struct TuiState {
    operation_id: String,
    total: usize,
    received: usize,
    open: usize,
    closed: usize,
    filtered: usize,
    results: Vec<StreamEvent>,
    done: bool,
    scroll: usize,
}

pub async fn run(
    mut rx: mpsc::UnboundedReceiver<StreamEvent>,
    operation_id: String,
    total: usize,
    poll_timeout: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = TuiState {
        operation_id,
        total,
        received: 0,
        open: 0,
        closed: 0,
        filtered: 0,
        results: Vec::new(),
        done: false,
        scroll: 0,
    };

    loop {
        // Drain all pending events from the channel
        while let Ok(ev) = rx.try_recv() {
            match ev.kind.as_str() {
                "result" => {
                    state.received += 1;
                    match ev.status.as_deref() {
                        Some("open") => state.open += 1,
                        Some("filtered") => state.filtered += 1,
                        _ => state.closed += 1,
                    }
                    state.results.push(ev);
                }
                "done" => {
                    state.done = true;
                    if let Some(o) = ev.open { state.open = o; }
                    if let Some(c) = ev.closed { state.closed = c; }
                    if let Some(f) = ev.filtered { state.filtered = f; }
                    state.received = state.open + state.closed + state.filtered;
                }
                "log" => { state.received += 0; /* just refresh */ }
                _ => {}
            }
        }

        // Draw
        terminal.draw(|f| draw(f, &state))?;

        // Handle keyboard input
        if event::poll(std::time::Duration::from_millis(poll_timeout))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Up => { if state.scroll > 0 { state.scroll -= 1; } }
                    KeyCode::Down => { state.scroll += 1; }
                    _ => {}
                }
            }
        }

        if state.done {
            // Keep TUI open until user presses q
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

fn draw(f: &mut ratatui::Frame, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Length(3),  // Progress bar
            Constraint::Length(3),  // Stats
            Constraint::Min(5),    // Results table
            Constraint::Length(1), // Footer
        ])
        .split(f.area());

    // Header
    let status = if state.done { "COMPLETE" } else { "SCANNING" };
    let status_color = if state.done { Color::Green } else { Color::Cyan };
    let header = Paragraph::new(Line::from(vec![
        Span::styled(" PULSE ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        Span::styled(status, Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
        Span::raw("  "),
        Span::styled(&state.operation_id[..16.min(state.operation_id.len())], Style::default().fg(Color::DarkGray)),
    ]))
    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)));
    f.render_widget(header, chunks[0]);

    // Progress bar
    let progress = if state.total > 0 {
        (state.received as f64 / state.total as f64).min(1.0)
    } else { 0.0 };
    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title(" Progress ").border_style(Style::default().fg(Color::DarkGray)))
        .gauge_style(Style::default().fg(Color::Cyan))
        .ratio(progress)
        .label(format!("{}/{} ({:.0}%)", state.received, state.total, progress * 100.0));
    f.render_widget(gauge, chunks[1]);

    // Stats
    let stats = Paragraph::new(Line::from(vec![
        Span::styled(format!(" OPEN {} ", state.open), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        Span::styled(format!("CLOSED {} ", state.closed), Style::default().fg(Color::DarkGray)),
        Span::raw(" "),
        Span::styled(format!("FILTERED {} ", state.filtered), Style::default().fg(Color::Yellow)),
    ]))
    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)));
    f.render_widget(stats, chunks[2]);

    // Results table (only open/filtered)
    let header_cells = ["Host", "Port", "Status", "Service", "Latency", "Banner"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)));
    let header_row = Row::new(header_cells).height(1);

    let visible = &state.results[state.scroll.min(state.results.len())..];
    let rows = visible.iter().map(|ev| {
        let status_color = match ev.status.as_deref() {
            Some("open") => Color::Green,
            Some("filtered") => Color::Yellow,
            _ => Color::DarkGray,
        };
        Row::new(vec![
            Cell::from(ev.host.as_deref().unwrap_or("-")),
            Cell::from(ev.port.map(|p| p.to_string()).unwrap_or_default()),
            Cell::from(ev.status.as_deref().unwrap_or("-")).style(Style::default().fg(status_color)),
            Cell::from(ev.service.as_deref().unwrap_or("-")),
            Cell::from(ev.latency_ms.map(|l| format!("{}ms", l)).unwrap_or_default()),
            Cell::from(ev.banner.as_deref().unwrap_or("").chars().take(40).collect::<String>()),
        ])
    });

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(20),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(14),
            Constraint::Length(10),
            Constraint::Percentage(30),
        ],
    )
    .header(header_row)
    .block(Block::default().borders(Borders::ALL).title(" Results ").border_style(Style::default().fg(Color::DarkGray)));
    f.render_widget(table, chunks[3]);

    // Footer
    let footer = Paragraph::new(Span::styled(
        " q: quit  ↑↓: scroll",
        Style::default().fg(Color::DarkGray),
    ));
    f.render_widget(footer, chunks[4]);
}
