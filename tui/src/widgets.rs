//! The pieces every tool draws.
//!
//! Each one is a plain function taking data, not engine types, so this crate
//! stays a rendering layer and never becomes a route for internals to travel.

use crate::theme;
use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, ListState, Paragraph},
};

/// A counter on the stats row: "Found 142".
pub struct Stat {
    pub label: &'static str,
    pub value: String,
    pub style: Style,
}

impl Stat {
    pub fn new(label: &'static str, value: impl ToString) -> Self {
        Self {
            label,
            value: value.to_string(),
            style: theme::value(),
        }
    }

    pub fn good(label: &'static str, value: impl ToString) -> Self {
        Self {
            label,
            value: value.to_string(),
            style: theme::good(),
        }
    }

    pub fn bad(label: &'static str, value: impl ToString) -> Self {
        Self {
            label,
            value: value.to_string(),
            style: theme::bad(),
        }
    }
}

/// Height the stats row needs, so callers can size their layout without
/// hard-coding a number that drifts when the border style changes.
pub const STATS_HEIGHT: u16 = 3;
/// Height the progress gauge needs.
pub const GAUGE_HEIGHT: u16 = 3;

pub fn stats(frame: &mut Frame, area: Rect, items: &[Stat]) {
    let mut spans = vec![Span::raw("  ")];
    for (i, s) in items.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("   "));
        }
        spans.push(Span::styled(format!("{}: ", s.label), theme::label()));
        spans.push(Span::styled(s.value.clone(), s.style));
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans))
            .block(Block::default().borders(Borders::ALL).title("Stats")),
        area,
    );
}

/// Progress gauge. `total` of zero renders an empty bar rather than dividing
/// by it, which happens whenever a run starts before its work is counted.
pub fn progress(frame: &mut Frame, area: Rect, done: usize, total: usize, title: &str) {
    let ratio = if total > 0 {
        (done as f64 / total as f64).min(1.0)
    } else {
        0.0
    };
    frame.render_widget(
        Gauge::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(title.to_string()),
            )
            .gauge_style(Style::default().fg(theme::ACCENT))
            .ratio(ratio)
            .label(format!("{done} / {total}")),
        area,
    );
}

/// Progress for a run with no known total, where a gauge would be a lie.
pub fn progress_open(frame: &mut Frame, area: Rect, done: usize, title: &str, unit: &str) {
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw("  "),
            Span::styled(done.to_string(), theme::title()),
            Span::raw(" "),
            Span::styled(unit.to_string(), theme::label()),
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title.to_string()),
        ),
        area,
    );
}

pub fn table_constraints(widths: &[u16]) -> Vec<Constraint> {
    let mut c: Vec<Constraint> = widths.iter().map(|w| Constraint::Length(*w)).collect();
    c.push(Constraint::Min(0));
    c
}

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------

pub struct LogEntry {
    pub level: Level,
    pub message: String,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Level {
    Info,
    Warn,
    Error,
    Debug,
}

impl Level {
    /// Parse whatever the wire called it. Anything unrecognised is info, since
    /// dropping a line because its level was spelled oddly is worse than
    /// showing it under the wrong heading.
    pub fn parse(s: &str) -> Self {
        match s {
            "error" | "err" => Level::Error,
            "warn" | "warning" => Level::Warn,
            "debug" | "trace" => Level::Debug,
            _ => Level::Info,
        }
    }

    fn tag(self) -> (&'static str, ratatui::style::Color) {
        match self {
            Level::Error => ("ERR", theme::BAD),
            Level::Warn => ("WRN", theme::WARN),
            Level::Debug => ("DBG", theme::MUTED),
            Level::Info => ("INF", theme::ACCENT),
        }
    }
}

/// Scrollback shared by every tool, with the selection pinned to the newest
/// line so a long run reads like a tail rather than freezing at the top.
#[derive(Default)]
pub struct Logs {
    entries: Vec<LogEntry>,
    state: ListState,
    /// Keeps memory flat on runs that log heavily. Zero means unbounded.
    cap: usize,
}

impl Logs {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            state: ListState::default(),
            cap: 5_000,
        }
    }

    pub fn push(&mut self, level: Level, message: impl Into<String>) {
        self.entries.push(LogEntry {
            level,
            message: message.into(),
        });
        if self.cap > 0 && self.entries.len() > self.cap {
            let drop = self.entries.len() - self.cap;
            self.entries.drain(0..drop);
        }
        self.state
            .select(Some(self.entries.len().saturating_sub(1)));
    }

    pub fn info(&mut self, message: impl Into<String>) {
        self.push(Level::Info, message);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = self
            .entries
            .iter()
            .map(|e| {
                let (tag, colour) = e.level.tag();
                ListItem::new(Line::from(vec![
                    Span::styled(format!("[{tag}] "), Style::default().fg(colour)),
                    Span::raw(e.message.clone()),
                ]))
            })
            .collect();

        frame.render_stateful_widget(
            List::new(items)
                .block(Block::default().borders(Borders::ALL).title("Logs"))
                .highlight_style(theme::selected()),
            area,
            &mut self.state,
        );
    }
}
