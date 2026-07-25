//! Per-target coordination tuning.
//!
//! Open baseline. When many concurrent workers run against one target, a shared
//! pace lets them speed up and slow down together instead of each adapting in
//! isolation. This module holds the *tuning* of that arrangement, the re-eval
//! cadence, the window sizing, the envelope, and the posture seed, with round
//! placeholder values. The tuned numbers live in the private drop-in.

use crate::{Caps, HealthWindow};

/// How many outcomes a shared pace accumulates before it re-evaluates.
pub const TICK_EVERY: u64 = 20;

/// Rolling health-window sizing for one shared pace: samples retained, warm-up.
pub const WINDOW_CAP: usize = 256;
pub const WINDOW_WARMUP: usize = 32;

/// Starting aggressiveness for a shared pace, by posture. Baseline: conservative
/// placeholder seeds.
pub fn posture_cap(posture: &str) -> u64 {
    match posture {
        "throughput" => 2,
        _ => 1,
    }
}

impl Caps {
    /// Envelope for one shared per-target pace (open baseline placeholders).
    pub fn for_target(max: u32) -> Self {
        Caps {
            min_concurrency: 1,
            max_concurrency: max,
            max_delay_ms: 5_000,
            max_retries: 5,
        }
    }
}

impl HealthWindow {
    /// A health window sized for one shared per-target pace.
    pub fn for_target() -> Self {
        HealthWindow::new(WINDOW_CAP, WINDOW_WARMUP)
    }
}
