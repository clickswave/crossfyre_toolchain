//! Shared terminal dashboard for the crossfyre tools.
//!
//! Every tool used to carry its own copy of the same three hundred lines, and
//! they had already drifted: different keys, different colours, different
//! wording for the same idea. This crate owns the chrome so a tool only
//! describes its own body.
//!
//! A tool implements [`Dashboard`] and hands it to [`run`]. It gets the header,
//! the tab bar, the logs view, the footer, key handling and terminal
//! lifecycle. It supplies a title and one render function per view.
//!
//! Nothing here depends on any engine crate. It takes numbers and strings, so
//! it cannot become a path for internals to reach the screen by accident.

pub mod theme;
pub mod widgets;

#[cfg(feature = "tuning")]
pub mod tuning;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};
use std::io::{self, IsTerminal};

pub use widgets::{Level, Logs, Stat};

/// A view the user can switch to. `key` is what they press, `label` is what
/// the tab bar shows.
pub struct View {
    pub key: char,
    pub label: &'static str,
}

impl View {
    pub const fn new(key: char, label: &'static str) -> Self {
        Self { key, label }
    }
}

/// The logs view every tool gets for free. Reserved so no tool binds it to
/// something else and breaks the muscle memory.
pub const LOGS_KEY: char = 'l';

/// What a tool must tell the driver.
pub trait Dashboard {
    /// Shown in the header, conventionally the tool name in capitals.
    fn name(&self) -> &str;

    /// Right of the tabs, dimmed. Usually the operation or target.
    fn subtitle(&self) -> &str {
        ""
    }

    /// True once the work is over. The footer changes and the driver stops
    /// pumping, but the view stays up so the results can be read.
    fn finished(&self) -> bool;

    /// Views beyond logs. Order is the tab order.
    fn views(&self) -> &'static [View];

    /// Draw one view into `area`. `key` is always one this tool declared.
    fn render(&mut self, key: char, frame: &mut Frame, area: Rect);

    /// Shared log scrollback.
    fn logs(&mut self) -> &mut Logs;

    /// Current pacing, if the tool tracks it.
    #[cfg(feature = "tuning")]
    fn tuning(&self) -> tuning::Snapshot {
        tuning::Snapshot::default()
    }
}

/// Whether a dashboard can be shown at all.
///
/// Worth checking before asking for one: these tools run under the node with
/// stdout piped, and taking over a terminal that is really a pipe produces
/// escape sequences in somebody's log file.
pub fn available() -> bool {
    io::stdout().is_terminal()
}

/// Drive a dashboard until the user quits.
///
/// `pump` is called every tick to drain whatever the tool is receiving into
/// its own state. The driver never sees the events, only the effect.
///
/// Blocking, and expects to own the terminal. Under tokio, wrap the call in
/// `spawn_blocking`.
pub fn run<D: Dashboard>(
    dashboard: &mut D,
    tick_ms: u64,
    mut pump: impl FnMut(&mut D),
) -> io::Result<()> {
    let mut terminal = enter()?;

    // Restore the terminal even if rendering panics. Without this a panic
    // leaves raw mode on and the alternate screen up, and the user is left
    // with a shell that no longer echoes what they type.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drive(&mut terminal, dashboard, tick_ms, &mut pump)
    }));

    leave(&mut terminal)?;

    match result {
        Ok(r) => r,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

type Term = Terminal<CrosstermBackend<io::Stdout>>;

fn enter() -> io::Result<Term> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    Terminal::new(CrosstermBackend::new(stdout))
}

fn leave(terminal: &mut Term) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()
}

fn drive<D: Dashboard>(
    terminal: &mut Term,
    dashboard: &mut D,
    tick_ms: u64,
    pump: &mut impl FnMut(&mut D),
) -> io::Result<()> {
    let mut active = first_view(dashboard);
    // Cap the tick so the UI stays responsive to keys even when a tool asks
    // for a slow poll.
    let tick = std::time::Duration::from_millis(tick_ms.clamp(16, 100));
    let mut announced = false;

    loop {
        if !dashboard.finished() {
            pump(dashboard);
        } else if !announced {
            // Say so once, in the logs, so the reason the numbers stopped
            // moving is on screen rather than inferred.
            dashboard.logs().info("Run complete. Press q to exit.");
            announced = true;
        }

        terminal.draw(|f| paint(f, dashboard, active))?;

        if event::poll(tick)?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                // Ctrl-C in raw mode is ours to handle: the terminal will not
                // deliver SIGINT, so without this the only way out is to kill
                // the process from another shell.
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Ok(());
                }
                KeyCode::Char(c) => {
                    if c == LOGS_KEY || dashboard.views().iter().any(|v| v.key == c) {
                        active = c;
                    }
                }
                _ => {}
            }
        }
    }
}

fn first_view<D: Dashboard>(dashboard: &D) -> char {
    dashboard.views().first().map(|v| v.key).unwrap_or(LOGS_KEY)
}

fn paint<D: Dashboard>(frame: &mut Frame, dashboard: &mut D, active: char) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(1)])
        .split(frame.area());

    header(frame, dashboard, active, rows[0]);

    if active == LOGS_KEY {
        dashboard.logs().render(frame, rows[1]);
    } else {
        dashboard.render(active, frame, rows[1]);
    }

    let hint = if dashboard.finished() {
        "  Run complete. q to exit."
    } else {
        "  q to exit."
    };
    frame.render_widget(
        Paragraph::new(hint).style(theme::label()),
        rows[2],
    );
}

fn header<D: Dashboard>(frame: &mut Frame, dashboard: &mut D, active: char, area: Rect) {
    let finished = dashboard.finished();
    let (state_text, state_style) = if finished {
        ("DONE", theme::good())
    } else {
        ("RUNNING", ratatui::style::Style::default().fg(theme::WARN))
    };

    let mut spans = vec![
        Span::styled(format!("  {}  ", dashboard.name()), theme::title()),
        Span::styled(state_text, state_style),
        Span::raw("    "),
    ];

    for view in dashboard.views() {
        spans.push(Span::styled(
            format!("[{}] {}", view.key, view.label),
            theme::tab(active == view.key),
        ));
        spans.push(Span::raw("  "));
    }
    spans.push(Span::styled(
        format!("[{LOGS_KEY}] Logs"),
        theme::tab(active == LOGS_KEY),
    ));

    let subtitle = dashboard.subtitle().to_string();
    if !subtitle.is_empty() {
        spans.push(Span::raw("    "));
        spans.push(Span::styled(subtitle, theme::label()));
    }

    frame.render_widget(
        Paragraph::new(Line::from(spans)).block(Block::default().borders(Borders::ALL)),
        area,
    );
}
