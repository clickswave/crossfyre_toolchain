//! One palette for every tool.
//!
//! Colours are named for what they mean rather than what they are, so a tool
//! asks for `GOOD` instead of `Green` and the whole toolchain shifts together
//! if the palette ever changes.

use ratatui::style::{Color, Modifier, Style};

/// Brand colour. Titles, gauges, the selected tab.
pub const ACCENT: Color = Color::Cyan;
/// Something worked: a hit, a 2xx, a finished run.
pub const GOOD: Color = Color::Green;
/// Worth a look but not a failure: a redirect, a retry, a slow host.
pub const WARN: Color = Color::Yellow;
/// Something failed.
pub const BAD: Color = Color::Red;
/// Ordinary values.
pub const TEXT: Color = Color::White;
/// Labels, chrome, anything the eye should skip.
pub const MUTED: Color = Color::DarkGray;

pub fn title() -> Style {
    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
}

pub fn label() -> Style {
    Style::default().fg(MUTED)
}

pub fn value() -> Style {
    Style::default().fg(TEXT)
}

pub fn good() -> Style {
    Style::default().fg(GOOD).add_modifier(Modifier::BOLD)
}

pub fn bad() -> Style {
    Style::default().fg(BAD)
}

pub fn selected() -> Style {
    Style::default().add_modifier(Modifier::REVERSED)
}

/// Tab in the header: bright and underlined when active, muted otherwise.
pub fn tab(active: bool) -> Style {
    if active {
        Style::default()
            .fg(ACCENT)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    } else {
        Style::default().fg(MUTED)
    }
}

/// Colour an HTTP status by its class.
pub fn status_code(code: &str) -> Color {
    match code.chars().next() {
        Some('2') => GOOD,
        Some('3') => WARN,
        Some('4') | Some('5') => BAD,
        _ => TEXT,
    }
}
