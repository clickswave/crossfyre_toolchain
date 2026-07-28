//! Voyage's dashboard.
//!
//! Chrome, keys and logs come from `cfx_tui`. What stays here is the part that
//! is about subdomain enumeration: counting results and listing what turned
//! up, alongside the source that found it.

use crate::scanner::StreamEvent;
use cfx_tui::{Dashboard, Level, Logs, Stat, View, widgets};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
};
use tokio::sync::mpsc;

const FOUND: char = 'f';
const VIEWS: &[View] = &[View::new(FOUND, "Found")];

struct Subdomain {
    name: String,
    source: String,
}

struct Voyage {
    operation_id: String,
    total: usize,
    scanned: usize,
    found: usize,
    not_found: usize,
    subdomains: Vec<Subdomain>,
    table: TableState,
    logs: Logs,
    done: bool,
}

impl Voyage {
    fn new(operation_id: String, total: usize) -> Self {
        Self {
            operation_id,
            total,
            scanned: 0,
            found: 0,
            not_found: 0,
            subdomains: Vec::new(),
            table: TableState::default(),
            logs: Logs::new(),
            done: false,
        }
    }

    fn apply(&mut self, event: StreamEvent) {
        match event.kind.as_str() {
            "result" => {
                self.scanned += 1;
                match event.status.as_deref().unwrap_or("not_found") {
                    "found" => {
                        self.found += 1;
                        if let Some(name) = event.subdomain {
                            self.subdomains.push(Subdomain {
                                name,
                                source: event.source.unwrap_or_default(),
                            });
                            // Follow the newest result so a long enumeration
                            // reads as a feed rather than freezing at the top.
                            self.table
                                .select(Some(self.subdomains.len().saturating_sub(1)));
                        }
                    }
                    _ => self.not_found += 1,
                }
            }
            "log" => {
                let level = Level::parse(event.log_level.as_deref().unwrap_or("info"));
                self.logs.push(level, event.message.unwrap_or_default());
            }
            "done" => {
                self.done = true;
                // Prefer the server's totals: events can be dropped on a slow
                // client, and a summary that disagrees with the rows above it
                // is worse than no summary at all.
                if let Some(f) = event.found {
                    self.found = f;
                }
                if let Some(n) = event.not_found {
                    self.not_found = n;
                }
                if let Some(t) = event.total {
                    self.scanned = t;
                }
                self.logs
                    .info(format!("found {}, not found {}", self.found, self.not_found));
            }
            _ => {}
        }
    }

    fn render_found(&mut self, frame: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(widgets::GAUGE_HEIGHT),
                Constraint::Length(widgets::STATS_HEIGHT),
                Constraint::Min(0),
            ])
            .split(area);

        widgets::progress(frame, rows[0], self.scanned, self.total, "Progress");
        widgets::stats(
            frame,
            rows[1],
            &[
                Stat::good("Found", self.found),
                Stat::new("Not found", self.not_found),
            ],
        );

        let header = Row::new(
            ["Source", "Subdomain"]
                .iter()
                .map(|h| Cell::from(*h).style(cfx_tui::theme::title())),
        )
        .height(1);

        let body: Vec<Row> = self
            .subdomains
            .iter()
            .map(|s| {
                Row::new(vec![
                    Cell::from(s.source.clone()).style(cfx_tui::theme::label()),
                    Cell::from(s.name.clone()),
                ])
            })
            .collect();

        frame.render_stateful_widget(
            Table::new(body, widgets::table_constraints(&[14]))
                .header(header)
                .block(Block::default().borders(Borders::ALL).title("Subdomains"))
                .row_highlight_style(cfx_tui::theme::selected()),
            rows[2],
            &mut self.table,
        );
    }
}

impl Dashboard for Voyage {
    fn name(&self) -> &str {
        "VOYAGE"
    }

    fn subtitle(&self) -> &str {
        &self.operation_id
    }

    fn finished(&self) -> bool {
        self.done
    }

    fn views(&self) -> &'static [View] {
        VIEWS
    }

    fn render(&mut self, key: char, frame: &mut Frame, area: Rect) {
        if key == FOUND {
            self.render_found(frame, area);
        }
    }

    fn logs(&mut self) -> &mut Logs {
        &mut self.logs
    }
}

pub async fn run(
    rx: mpsc::UnboundedReceiver<StreamEvent>,
    operation_id: String,
    total: usize,
    poll_timeout: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::task::spawn_blocking(move || {
        let mut app = Voyage::new(operation_id, total);
        let mut rx = rx;
        cfx_tui::run(&mut app, poll_timeout, |app| {
            while let Ok(event) = rx.try_recv() {
                app.apply(event);
            }
        })
    })
    .await?
    .map_err(|e| -> Box<dyn std::error::Error> { format!("{e}").into() })
}
