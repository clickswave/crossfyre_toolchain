//! Live view of how a run is pacing itself.
//!
//! Compiled only under the `tuning` feature. Published builds do not include
//! this module, so neither the panel nor its labels appear in the binary. The
//! pacing behaviour itself lives in the engines; this is a readout, and it is
//! kept out of default builds because the readout describes the behaviour.
//!
//! Tools report through [`Snapshot`], which holds numbers and short strings
//! only. Nothing in here reaches into engine types.

use crate::theme;
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

/// Height the panel needs, so callers can size a layout around it.
pub const HEIGHT: u16 = 3;

/// What a tool reports each tick. Every field is optional: a tool fills in
/// what it knows and leaves the rest, rather than inventing values to fit.
#[derive(Default, Clone)]
pub struct Snapshot {
    /// Requests in flight right now.
    pub in_flight: Option<usize>,
    /// Ceiling currently being honoured.
    pub limit: Option<usize>,
    /// Observed throughput per second.
    pub rate: Option<f64>,
    /// Short label for the current stance, chosen by the tool.
    pub posture: Option<String>,
    /// Responses that asked us to slow down.
    pub throttled: Option<u64>,
}

impl Snapshot {
    pub fn is_empty(&self) -> bool {
        self.in_flight.is_none()
            && self.limit.is_none()
            && self.rate.is_none()
            && self.posture.is_none()
            && self.throttled.is_none()
    }
}

pub fn render(frame: &mut Frame, area: Rect, snap: &Snapshot) {
    let mut spans = vec![Span::raw("  ")];

    let mut field = |label: &str, value: String, style: ratatui::style::Style| {
        if !spans.is_empty() && spans.len() > 1 {
            spans.push(Span::raw("   "));
        }
        spans.push(Span::styled(format!("{label}: "), theme::label()));
        spans.push(Span::styled(value, style));
    };

    if let (Some(n), Some(lim)) = (snap.in_flight, snap.limit) {
        field("Workers", format!("{n} / {lim}"), theme::value());
    } else if let Some(n) = snap.in_flight {
        field("Workers", n.to_string(), theme::value());
    }
    if let Some(r) = snap.rate {
        field("Rate", format!("{r:.0}/s"), theme::value());
    }
    if let Some(p) = &snap.posture {
        field("Posture", p.clone(), theme::title());
    }
    if let Some(t) = snap.throttled {
        let style = if t > 0 { theme::bad() } else { theme::value() };
        field("Throttled", t.to_string(), style);
    }

    frame.render_widget(
        Paragraph::new(Line::from(spans))
            .block(Block::default().borders(Borders::ALL).title("Pacing")),
        area,
    );
}
