//! Resilience: retry decisions for failed probes.
//!
//! Open baseline. Keeps the public shape (which classes are retryable, a per-
//! probe ceiling, an exponential backoff) with simple, untuned defaults. The
//! tuned policy is in the private drop-in.

use crate::health::{HealthStats, ProbeClass};
use crate::rate::Posture;

/// The verdict for one failed probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryDecision {
    pub retry: bool,
    pub backoff_ms: u64,
}

impl RetryDecision {
    fn no() -> Self {
        RetryDecision {
            retry: false,
            backoff_ms: 0,
        }
    }
}

/// Decides whether a failed probe is worth retrying, capped by an absolute
/// per-probe ceiling.
pub struct ResilienceController {
    posture: Posture,
    ceiling: u32,
    base_backoff_ms: u64,
    max_backoff_ms: u64,
}

impl ResilienceController {
    pub fn new(posture: Posture, ceiling: u32) -> Self {
        ResilienceController {
            posture,
            ceiling,
            base_backoff_ms: 200,
            max_backoff_ms: 30_000,
        }
    }

    pub fn with_backoff(mut self, base_ms: u64, max_ms: u64) -> Self {
        self.base_backoff_ms = base_ms;
        self.max_backoff_ms = max_ms.max(base_ms);
        self
    }

    /// Only transient failures are retryable. A definitive answer (200/403/404)
    /// is the result, never retried.
    pub fn retryable(class: ProbeClass) -> bool {
        matches!(
            class,
            ProbeClass::RateLimited
                | ProbeClass::ServerError
                | ProbeClass::Timeout
                | ProbeClass::ConnError
        )
    }

    /// How many retries are allowed for a transient failure. Baseline: the
    /// posture max, capped by the hard ceiling.
    pub fn effective_max(&self, _health_score: f64) -> u32 {
        self.posture.params().max_retries.min(self.ceiling)
    }

    /// Decide for a probe that just failed with `class`, having already been
    /// retried `attempt` times (0 = first failure). `retry_after_ms` is a parsed
    /// `Retry-After` header, if the target sent one.
    pub fn decide(
        &self,
        class: ProbeClass,
        attempt: u32,
        stats: &HealthStats,
        health_score: f64,
        retry_after_ms: Option<u64>,
    ) -> RetryDecision {
        let _ = stats;
        if !Self::retryable(class) {
            return RetryDecision::no();
        }
        // Honour an explicit Retry-After with at least one retry.
        let floor = if retry_after_ms.is_some() { 1 } else { 0 };
        let allowed = self
            .effective_max(health_score)
            .max(floor)
            .min(self.ceiling);
        if attempt >= allowed {
            return RetryDecision::no();
        }
        let backoff = retry_after_ms
            .unwrap_or_else(|| self.exp_backoff(attempt, health_score))
            .min(self.max_backoff_ms);
        RetryDecision {
            retry: true,
            backoff_ms: backoff,
        }
    }

    fn exp_backoff(&self, attempt: u32, health_score: f64) -> u64 {
        let mult = 1u64 << attempt.min(5);
        let stress = if health_score < 0.5 { 2 } else { 1 };
        self.base_backoff_ms
            .saturating_mul(mult)
            .saturating_mul(stress)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats() -> HealthStats {
        HealthStats::empty()
    }

    #[test]
    fn definitive_answers_are_never_retried() {
        let rc = ResilienceController::new(Posture::Balanced, 5);
        assert!(
            !rc.decide(ProbeClass::NotFound, 0, &stats(), 1.0, None)
                .retry
        );
        assert!(!rc.decide(ProbeClass::Success, 0, &stats(), 1.0, None).retry);
    }

    #[test]
    fn transient_errors_are_retryable_up_to_ceiling() {
        let rc = ResilienceController::new(Posture::Throughput, 1); // hard ceiling 1
        assert!(
            rc.decide(ProbeClass::ServerError, 0, &stats(), 1.0, None)
                .retry
        );
        assert!(
            !rc.decide(ProbeClass::ServerError, 1, &stats(), 1.0, None)
                .retry
        );
    }

    #[test]
    fn retry_after_is_honoured() {
        let rc = ResilienceController::new(Posture::Balanced, 5);
        let d = rc.decide(ProbeClass::RateLimited, 0, &stats(), 0.10, Some(2000));
        assert!(d.retry);
        assert_eq!(d.backoff_ms, 2000);
    }
}
