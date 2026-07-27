//! Rolling health window: probe outcomes in, a [`HealthStats`] snapshot out.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// What a single probe told us about the target. `Success` vs `NotFound` is the
/// caller's finding decision; for health they are identical ("the target
/// answered"), so [`ProbeClass::from_status`] maps any non-error status to
/// `Success` and the caller refines it separately if it cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeClass {
    Success,
    NotFound,
    RateLimited,
    ServerError,
    Timeout,
    ConnError,
}

impl ProbeClass {
    /// The target responded with a usable answer (any 1xx-4xx that isn't 429).
    pub fn answered(self) -> bool {
        matches!(self, ProbeClass::Success | ProbeClass::NotFound)
    }

    /// A signal that the target is under pressure or unreachable.
    pub fn is_stress(self) -> bool {
        matches!(
            self,
            ProbeClass::RateLimited
                | ProbeClass::ServerError
                | ProbeClass::Timeout
                | ProbeClass::ConnError
        )
    }

    /// Classify from an HTTP status code (health view; not the finding view).
    pub fn from_status(status: u16) -> Self {
        match status {
            429 => ProbeClass::RateLimited,
            500..=599 => ProbeClass::ServerError,
            _ => ProbeClass::Success,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Sample {
    class: ProbeClass,
    rtt_ms: u64,
}

/// A snapshot of the target's health over the current window. All `*_rate`
/// fields are fractions in `[0,1]`; `latency_inflation` is `p95 / baseline_p95`
/// (`1.0` when the baseline isn't established yet or the target is at/faster
/// than baseline for the excess calculation).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct HealthStats {
    pub total: usize,
    pub answered_rate: f64,
    pub rate_limited_rate: f64,
    pub server_err_rate: f64,
    pub timeout_drop_rate: f64,
    pub rtt_p50_ms: f64,
    pub rtt_p95_ms: f64,
    pub latency_inflation: f64,
}

impl HealthStats {
    /// The "nothing observed yet" snapshot: reads as healthy so a controller
    /// holds its seed rather than reacting to noise.
    pub fn empty() -> Self {
        HealthStats {
            total: 0,
            answered_rate: 1.0,
            rate_limited_rate: 0.0,
            server_err_rate: 0.0,
            timeout_drop_rate: 0.0,
            rtt_p50_ms: 0.0,
            rtt_p95_ms: 0.0,
            latency_inflation: 1.0,
        }
    }
}

impl Default for HealthStats {
    fn default() -> Self {
        HealthStats::empty()
    }
}

/// Bounded rolling record of the last `cap` probe outcomes for one target.
///
/// Count-bounded (not time-bounded) so it is deterministic and needs no clock:
/// old samples fall off as new ones arrive. A warm-up baseline latency is
/// captured from the first `warmup_k` answered probes, so [`HealthStats::latency_inflation`]
/// measures *slowdown relative to this target's own normal*, not absolute RTT.
pub struct HealthWindow {
    cap: usize,
    buf: VecDeque<Sample>,
    warmup_k: usize,
    warmup_rtts: Vec<u64>,
    baseline_p95_ms: Option<f64>,
}

impl HealthWindow {
    pub fn new(cap: usize, warmup_k: usize) -> Self {
        HealthWindow {
            cap: cap.max(1),
            buf: VecDeque::with_capacity(cap.max(1)),
            warmup_k: warmup_k.max(1),
            warmup_rtts: Vec::new(),
            baseline_p95_ms: None,
        }
    }

    /// Record one probe outcome. `rtt_ms` should be the round-trip time; pass a
    /// large sentinel (e.g. the timeout) for `Timeout`.
    pub fn record(&mut self, class: ProbeClass, rtt_ms: u64) {
        if self.baseline_p95_ms.is_none() && class.answered() {
            self.warmup_rtts.push(rtt_ms);
            if self.warmup_rtts.len() >= self.warmup_k {
                let mut w = self.warmup_rtts.clone();
                self.baseline_p95_ms = Some(percentile(&mut w, 0.95).max(1.0));
            }
        }
        if self.buf.len() >= self.cap {
            self.buf.pop_front();
        }
        self.buf.push_back(Sample { class, rtt_ms });
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// True once the warm-up baseline latency has been established.
    pub fn has_baseline(&self) -> bool {
        self.baseline_p95_ms.is_some()
    }

    /// Compute the current health snapshot from the window.
    pub fn stats(&self) -> HealthStats {
        let total = self.buf.len();
        if total == 0 {
            return HealthStats::empty();
        }
        let (mut rl, mut se, mut to, mut answered) = (0usize, 0usize, 0usize, 0usize);
        let mut rtts: Vec<u64> = Vec::with_capacity(total);
        for s in &self.buf {
            match s.class {
                ProbeClass::RateLimited => rl += 1,
                ProbeClass::ServerError => se += 1,
                ProbeClass::Timeout | ProbeClass::ConnError => to += 1,
                _ => {}
            }
            if s.class.answered() {
                answered += 1;
            }
            rtts.push(s.rtt_ms);
        }
        let t = total as f64;
        let p50 = percentile(&mut rtts.clone(), 0.50);
        let p95 = percentile(&mut rtts, 0.95);
        let latency_inflation = match self.baseline_p95_ms {
            Some(b) if b > 0.0 => p95 / b,
            _ => 1.0,
        };
        HealthStats {
            total,
            answered_rate: answered as f64 / t,
            rate_limited_rate: rl as f64 / t,
            server_err_rate: se as f64 / t,
            timeout_drop_rate: to as f64 / t,
            rtt_p50_ms: p50,
            rtt_p95_ms: p95,
            latency_inflation,
        }
    }
}

/// Nearest-rank percentile of a slice of latencies (sorts in place). `q` in `[0,1]`.
fn percentile(v: &mut [u64], q: f64) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_unstable();
    let idx = ((v.len() as f64 - 1.0) * q.clamp(0.0, 1.0)).round() as usize;
    v[idx.min(v.len() - 1)] as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_healthy_reads_answered_and_no_stress() {
        let mut w = HealthWindow::new(100, 5);
        for _ in 0..50 {
            w.record(ProbeClass::from_status(200), 40);
        }
        let s = w.stats();
        assert_eq!(s.total, 50);
        assert!((s.answered_rate - 1.0).abs() < 1e-9);
        assert_eq!(s.rate_limited_rate, 0.0);
        assert_eq!(s.server_err_rate, 0.0);
    }

    #[test]
    fn rate_limits_and_errors_are_counted() {
        let mut w = HealthWindow::new(100, 5);
        for _ in 0..80 {
            w.record(ProbeClass::from_status(200), 30);
        }
        for _ in 0..20 {
            w.record(ProbeClass::from_status(429), 30);
        }
        let s = w.stats();
        assert_eq!(s.total, 100);
        assert!((s.rate_limited_rate - 0.20).abs() < 1e-9);
        assert!((s.answered_rate - 0.80).abs() < 1e-9);
    }

    #[test]
    fn window_is_bounded_to_cap() {
        let mut w = HealthWindow::new(10, 3);
        for _ in 0..100 {
            w.record(ProbeClass::from_status(200), 10);
        }
        assert_eq!(w.len(), 10);
    }

    #[test]
    fn latency_inflation_tracks_slowdown_vs_baseline() {
        let mut w = HealthWindow::new(200, 10);
        // Warm-up: fast, establishes baseline ~50ms.
        for _ in 0..10 {
            w.record(ProbeClass::from_status(200), 50);
        }
        assert!(w.has_baseline());
        // Now the target slows to ~200ms.
        for _ in 0..50 {
            w.record(ProbeClass::from_status(200), 200);
        }
        let s = w.stats();
        assert!(
            s.latency_inflation > 3.0,
            "inflation was {}",
            s.latency_inflation
        );
    }

    #[test]
    fn unknown_baseline_yields_neutral_inflation() {
        let mut w = HealthWindow::new(200, 50); // warmup_k not reached
        for _ in 0..5 {
            w.record(ProbeClass::from_status(200), 999);
        }
        assert!(!w.has_baseline());
        assert_eq!(w.stats().latency_inflation, 1.0);
    }
}
