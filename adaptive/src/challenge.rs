//! Challenge / anti-bot awareness.
//!
//! Recognises when a response came from a WAF or anti-bot layer (a hard block,
//! an interactive JS/CAPTCHA/Turnstile challenge, or velocity throttling) rather
//! than the origin application, and recommends a reaction: proceed, back off and
//! retry (optionally rotating the outbound identity), escalate to the challenge
//! broker, or abort.
//!
//! This is the PUBLIC baseline. It recognises only the obvious, well-documented
//! signatures and reacts conservatively (no broker escalation). The tuned
//! signature set, edge scoring, and thresholds live in the private drop-in:
//! challenge detection is adversarially sensitive, so a WAF vendor reading the
//! open toolchain must not be able to enumerate exactly what we key on.

/// Classification of an interfering response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Challenge {
    /// No anti-bot interference detected.
    None,
    /// An interactive JS / CAPTCHA / Turnstile challenge page.
    Interactive,
    /// A hard block or access-denied from the edge.
    Blocked,
    /// Rate limited (velocity throttle).
    RateLimited,
}

impl Challenge {
    /// True for anything other than [`Challenge::None`].
    pub fn is_challenge(self) -> bool {
        !matches!(self, Challenge::None)
    }

    /// A short stable label for logs / findings.
    pub fn label(self) -> &'static str {
        match self {
            Challenge::None => "none",
            Challenge::Interactive => "interactive_challenge",
            Challenge::Blocked => "blocked",
            Challenge::RateLimited => "rate_limited",
        }
    }
}

/// Recommended reaction to a detected challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reaction {
    /// Nothing to do; carry on.
    Proceed,
    /// Wait `delay_ms`, then retry. Rebuild the outbound identity first when
    /// `rotate_identity` is set (a fresh browser profile for the same target).
    Backoff {
        delay_ms: u64,
        rotate_identity: bool,
    },
    /// Escalate to the challenge broker (a headless browser mints clearance,
    /// whose cookie is handed back to the fast client). A paid, private-policy
    /// lever: the public baseline never returns this.
    Broker,
    /// Stop hitting this target for now.
    Abort,
}

/// Inspect a response for anti-bot interference.
///
/// `status` is the HTTP status; `header` looks a header value up by its
/// lowercased name; `body_prefix` is the first chunk of the body (a few KB is
/// plenty). The header lookup is a closure so callers need not build a map.
pub fn detect(
    status: u16,
    header: impl Fn(&str) -> Option<String>,
    body_prefix: &str,
) -> Challenge {
    // Velocity throttling is unambiguous from the status line.
    if status == 429 {
        return Challenge::RateLimited;
    }

    let body = body_prefix.to_ascii_lowercase();

    // Interactive challenge markers (the well-known public ones only).
    let interactive = body.contains("just a moment")
        || body.contains("/cdn-cgi/challenge-platform")
        || body.contains("challenge-platform")
        || body.contains("turnstile");
    if interactive && matches!(status, 200 | 403 | 429 | 503) {
        return Challenge::Interactive;
    }

    // Hard-block markers.
    let blocked = header("cf-mitigated").is_some()
        || body.contains("attention required")
        || body.contains("access denied")
        || body.contains("you have been blocked");
    if blocked && matches!(status, 403 | 406 | 503) {
        return Challenge::Blocked;
    }

    // A bare 403/503 from a known edge is suspicious but not conclusive; the
    // private drop-in scores those. The baseline stays conservative.
    Challenge::None
}

/// Decide what to do about a challenge, given how many times we have already hit
/// one on this target (`attempt`, 0-based).
///
/// Baseline policy: backoff with identity rotation for the first tries, then give
/// up. The broker is never invoked here (it is a private, paid escalation).
pub fn react(challenge: Challenge, attempt: u32) -> Reaction {
    match challenge {
        Challenge::None => Reaction::Proceed,
        Challenge::RateLimited => {
            if attempt >= 4 {
                Reaction::Abort
            } else {
                Reaction::Backoff {
                    delay_ms: 2000u64 << attempt.min(4),
                    rotate_identity: false,
                }
            }
        }
        Challenge::Interactive | Challenge::Blocked => {
            if attempt >= 2 {
                Reaction::Abort
            } else {
                Reaction::Backoff {
                    delay_ms: 1500u64 << attempt.min(3),
                    rotate_identity: true,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_headers(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn clean_response_is_none() {
        assert_eq!(
            detect(200, no_headers, "<html>hello</html>"),
            Challenge::None
        );
    }

    #[test]
    fn rate_limit_by_status() {
        assert_eq!(detect(429, no_headers, ""), Challenge::RateLimited);
    }

    #[test]
    fn interactive_challenge_body() {
        assert_eq!(
            detect(503, no_headers, "<title>Just a moment...</title>"),
            Challenge::Interactive
        );
    }

    #[test]
    fn blocked_by_header() {
        let h = |n: &str| (n == "cf-mitigated").then(|| "challenge".to_string());
        assert_eq!(detect(403, h, ""), Challenge::Blocked);
    }

    #[test]
    fn react_rotates_then_aborts() {
        assert!(matches!(
            react(Challenge::Blocked, 0),
            Reaction::Backoff {
                rotate_identity: true,
                ..
            }
        ));
        assert_eq!(react(Challenge::Blocked, 2), Reaction::Abort);
    }

    #[test]
    fn baseline_never_brokers() {
        for a in 0..8 {
            assert_ne!(react(Challenge::Interactive, a), Reaction::Broker);
            assert_ne!(react(Challenge::Blocked, a), Reaction::Broker);
        }
    }
}
