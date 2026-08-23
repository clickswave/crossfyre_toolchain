//! The Cortex vulnerability engine (minimal, real detection).
//!
//! Every candidate flows through the correctness pipeline
//! (GENERATE -> DETECT -> CONFIRM -> REPORT): template matches are re-issued to
//! confirm (see template.rs), and passive checks are deterministic on the
//! observed response. Findings are relayed verbatim by the node into the shared
//! asset graph. OAST-backed blind detection, the full DSL, and the generative
//! API mode are the documented next milestones (docs/tier1-engines-plan.md).

use crate::template;
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::sync::mpsc;
use transport::Client;

#[derive(Debug, Deserialize)]
pub struct ScanParams {
    pub target: String,
    /// Evasiveness posture (set by the node's Evasiveness switch): blend in as a
    /// browser (true, default) vs a neutral honest client (false).
    #[serde(default = "d_true")]
    pub evasive: bool,
    /// Attribution token: when set, advertise it so an authorized program can
    /// allow-list the traffic.
    #[serde(default)]
    pub identify: Option<String>,
    #[serde(default = "d_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "d_true")]
    pub follow_redirects: bool,
    /// Optional external nuclei-template directory (supported subset).
    #[serde(default)]
    pub templates_dir: Option<String>,
    /// nuclei-style severity filter (lowercased); empty = all severities.
    #[serde(default)]
    pub severity: Vec<String>,
    /// Only run passive header checks (no template requests).
    #[serde(default)]
    pub passive_only: bool,
    /// Optional request auth (headers + cookie) resolved from a credential by the
    /// node, so scanning (and later authorization testing) runs authenticated.
    #[serde(default)]
    pub auth: Option<AuthSpec>,
    /// Optional OAST endpoint (domains + poll API) the node resolved from the
    /// workspace's selected endpoint. When present it overrides the env fallback,
    /// enabling per-scan choice of the managed pool or a BYO self-hosted OAST.
    #[serde(default)]
    pub oast: Option<OastSpec>,
}
fn d_timeout() -> u64 {
    10_000
}
fn d_true() -> bool {
    true
}

/// An OAST endpoint resolved by the node for this scan.
#[derive(Debug, Deserialize)]
pub struct OastSpec {
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub api_url: String,
}

/// Request auth resolved from a credential. Now shared across all engines via
/// `transport`; re-exported so `crate::engine::AuthSpec` keeps resolving.
pub use transport::AuthSpec;

pub(crate) struct BaseResp {
    #[allow(dead_code)]
    pub(crate) is_https: bool,
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    /// First chunk of the body, for WAF/anti-bot challenge detection.
    pub(crate) body_prefix: String,
}

pub async fn run(params: ScanParams, tx: mpsc::UnboundedSender<Value>) {
    let base = match normalize_base(&params.target) {
        Some(b) => b,
        None => {
            let _ = tx.send(
                json!({"type":"error","message":format!("invalid target: {}", params.target)}),
            );
            return;
        }
    };

    // Outbound identity, presented via the transport layer. The reqwest backend
    // sends UA + hint headers; the impersonate (wreq) backend presents a real
    // browser TLS/HTTP2 fingerprint, with the emulation profile owning the
    // fingerprint headers. Fast posture skips emulation. Stable-per-target; the
    // profile choice is the private `adaptive` drop-in.
    let mode = adaptive::identity::Mode::from_flags(params.evasive, params.identify.clone());

    // Builds an outbound client for a resolved identity. Closed over so a
    // challenge retry can rebuild it with a rotated identity.
    let build_client = |ident: &adaptive::identity::Identity,
                        clearance: Option<&crate::solver::Solved>| {
        let mut browser_headers = transport::HeaderMap::new();
        for (k, v) in &ident.headers {
            if let (Ok(name), Ok(val)) = (
                transport::HeaderName::from_bytes(k.as_bytes()),
                transport::HeaderValue::from_str(v),
            ) {
                browser_headers.insert(name, val);
            }
        }
        let mut extra_headers = transport::HeaderMap::new();
        if let Some(auth) = params.auth.as_ref().filter(|a| a.is_meaningful()) {
            for (k, v) in auth.to_header_map().iter() {
                extra_headers.insert(k.clone(), v.clone());
            }
        }
        // The attribution token (Identify posture) is an app header: it must
        // survive emulation, so it goes in extra_headers, not the fingerprint set.
        if let adaptive::identity::Mode::Identify(token) = &mode {
            if let Ok(val) = transport::HeaderValue::from_str(token) {
                extra_headers.insert(transport::HeaderName::from_static("x-bug-bounty"), val);
            }
        }
        // Challenge clearance (from the solver): the cf_clearance cookie must ride
        // on every request, and the UA must match the solver's browser or the
        // cookie is rejected - so adopt the solver's UA for the fingerprint too.
        let mut ua = ident.user_agent.clone();
        if let Some(sol) = clearance {
            if let Ok(val) = transport::HeaderValue::from_str(&sol.cookie_header) {
                extra_headers.insert(transport::header::COOKIE, val);
            }
            if let Some(sua) = &sol.user_agent {
                ua = sua.clone();
            }
        }
        transport::build_client(transport::ClientConfig {
            timeout: Some(Duration::from_millis(
                params.timeout_ms.clamp(1000, 120_000),
            )),
            redirect: if params.follow_redirects {
                transport::Redirect::Limited(5)
            } else {
                transport::Redirect::None
            },
            accept_invalid_certs: true,
            cookie_store: true,
            user_agent: Some(ua),
            browser_headers,
            extra_headers,
            emulate: !matches!(mode, adaptive::identity::Mode::Fast),
            resolve: Vec::new(),
        })
    };

    let _ = tx.send(json!({"type":"ack","target": base}));

    // Fetch the base once and handle any WAF / anti-bot interference before
    // committing to the full scan: a challenge on the base means every
    // {{BaseURL}} template would just re-hit the WAF. Back off + rotate identity
    // per the challenge policy; if it persists, report it and skip the active
    // phase. (Broker escalation lands with the challenge-broker track; until then
    // an unclearable challenge ends the scan early.)
    let mut attempt: u32 = 0;
    let mut rotations: u32 = 0;
    let mut blocked = false;
    let mut block_label: &'static str = "blocked";
    // Set once the challenge solver returns a clearance cookie; every subsequent
    // client build then rides that cookie + the solver's UA.
    let mut clearance: Option<crate::solver::Solved> = None;
    let (client, base_resp) = loop {
        let seed = if rotations == 0 {
            params.target.clone()
        } else {
            format!("{}#{}", params.target, rotations)
        };
        let ident = adaptive::identity::resolve(&mode, Some(seed.as_str()));
        let client = match build_client(&ident, clearance.as_ref()) {
            Ok(c) => c,
            Err(e) => {
                let _ =
                    tx.send(json!({"type":"error","message":format!("client build failed: {e}")}));
                return;
            }
        };

        let base_resp = fetch_base(&client, &base).await;

        if let Some(ref br) = base_resp {
            let ch = adaptive::challenge::detect(
                br.status,
                |n| {
                    br.headers
                        .iter()
                        .find(|(k, _)| k == n)
                        .map(|(_, v)| v.clone())
                },
                &br.body_prefix,
            );
            if ch.is_challenge() {
                match adaptive::challenge::react(ch, attempt) {
                    adaptive::challenge::Reaction::Backoff {
                        delay_ms,
                        rotate_identity,
                    } => {
                        let _ = tx.send(json!({
                            "type":"log",
                            "message":format!(
                                "waf {} on base (HTTP {}), backing off {}ms{}",
                                ch.label(), br.status, delay_ms,
                                if rotate_identity { " + rotating identity" } else { "" }
                            )
                        }));
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                        attempt += 1;
                        if rotate_identity {
                            rotations += 1;
                        }
                        continue;
                    }
                    adaptive::challenge::Reaction::Broker => {
                        // Hand off to a node-side challenge solver (FlareSolverr-
                        // compatible), which mints a clearance cookie from the
                        // node's own egress. On success, retry the base carrying
                        // that cookie; if there is no solver, or it can't clear, or
                        // the challenge persists even with clearance, report + stop.
                        if clearance.is_none() && crate::solver::configured() {
                            let _ = tx.send(json!({
                                "type":"log",
                                "message":format!("waf {} on base; handing off to challenge solver", ch.label())
                            }));
                            match crate::solver::solve(
                                &base,
                                params.timeout_ms.clamp(1000, 120_000),
                            )
                            .await
                            {
                                Some(sol) => {
                                    let _ = tx.send(json!({
                                        "type":"log",
                                        "message":"challenge solver returned clearance; retrying with cf_clearance"
                                    }));
                                    clearance = Some(sol);
                                    attempt += 1;
                                    continue;
                                }
                                None => {
                                    let _ = tx.send(json!({
                                        "type":"log",
                                        "message":"challenge solver could not clear the target; ending scan"
                                    }));
                                }
                            }
                        } else if clearance.is_some() {
                            let _ = tx.send(json!({
                                "type":"log",
                                "message":format!("waf {} persists even after solver clearance; ending scan", ch.label())
                            }));
                        } else {
                            let _ = tx.send(json!({
                                "type":"log",
                                "message":format!("waf {} on base persists; no challenge solver configured (set CROSSFYRE_CHALLENGE_SOLVER), ending scan", ch.label())
                            }));
                        }
                        blocked = true;
                        block_label = ch.label();
                        break (client, base_resp);
                    }
                    adaptive::challenge::Reaction::Abort => {
                        blocked = true;
                        block_label = ch.label();
                        break (client, base_resp);
                    }
                    adaptive::challenge::Reaction::Proceed => {}
                }
            }
        }
        break (client, base_resp);
    };

    // A persistent WAF challenge on the base is itself reportable and a reason to
    // skip the active phase.
    if blocked {
        let _ = tx.send(json!({
            "type":"finding",
            "data":{
                "target": base,
                "type":"waf",
                "source":"cortex",
                "severity":"info",
                "name": format!("Target behind WAF/anti-bot ({block_label})"),
                "template":"cortex:waf-challenge",
                "matched_at": base,
                "description":"The base URL returned a WAF/anti-bot challenge that could not be cleared, so active vulnerability templates were skipped. Consider origin discovery, an attribution/allowlist header, or a challenge-solving session.",
                "confidence":"confirmed",
            }
        }));
    }

    let sev_filter: Vec<String> = params.severity.iter().map(|s| s.to_lowercase()).collect();
    let allow = |sev: &str| sev_filter.is_empty() || sev_filter.iter().any(|s| s == sev);

    let mut found: i64 = 0;

    // --- Passive header checks on the base response (deterministic) ---
    // fetch_base returns None only on a transport-level failure (connection
    // refused, timed out, TLS error): the target did not answer a simple GET.
    // Every {{BaseURL}} template dials the same host:port, so if the base is
    // unreachable the whole active phase would just re-dial a dead or tarpitting
    // target 100+ times, each attempt burning a full per-request timeout. Skip it.
    let base_reachable = if blocked {
        false
    } else if let Some(resp) = base_resp {
        for (name, template, severity, description) in header_checks(&resp) {
            if allow(severity) {
                found += 1;
                let _ = tx.send(json!({
                    "type": "finding",
                    "data": {
                        "target": base,
                        "type": "vulnerability",
                        "source": "cortex",
                        "severity": severity,
                        "name": name,
                        "template": template,
                        "matched_at": base,
                        "description": description,
                        "confidence": "confirmed",
                    }
                }));
            }
        }
        true
    } else {
        false
    };

    // --- Template mode (confirm-then-report) ---
    if !params.passive_only && base_reachable {
        let ext_dir = params
            .templates_dir
            .clone()
            .or_else(|| std::env::var("CORTEX_TEMPLATES_DIR").ok());
        let external = ext_dir
            .as_deref()
            .map(template::load_dir)
            .unwrap_or_default();
        let total = template::BUILTIN.len() + external.len();
        let mut done = 0usize;

        // OAST client for out-of-band (interactsh) templates; None disables OOB.
        // Per-scan endpoint (node-resolved) wins over the node env fallback.
        let oast = params
            .oast
            .as_ref()
            .and_then(|s| crate::oast::OastClient::from_spec(s.domains.clone(), &s.api_url))
            .or_else(crate::oast::OastClient::from_env);

        for tmpl in template::BUILTIN.iter().chain(external.iter()) {
            let sev = if tmpl.info.severity.is_empty() {
                "info".to_string()
            } else {
                tmpl.info.severity.to_lowercase()
            };
            if allow(&sev) {
                for m in
                    template::eval_template(&client, &base, tmpl, oast.as_ref(), params.evasive)
                        .await
                {
                    found += 1;
                    let _ = tx.send(json!({
                        "type": "finding",
                        "data": {
                            "target": m.matched_at,
                            "type": "vulnerability",
                            "source": "cortex",
                            "severity": m.severity,
                            "name": m.name,
                            "template": m.template_id,
                            "matched_at": m.matched_at,
                            "description": m.description,
                            "confidence": "confirmed",
                        }
                    }));
                }
            }
            done += 1;
            let _ = tx.send(json!({"type":"progress","processed": done, "total": total}));
        }
    }

    let _ = tx.send(json!({"type":"done","found": found}));
}

/// Passive security-header checks. Returns (name, template-id, severity, description).
fn header_checks(resp: &BaseResp) -> Vec<(&'static str, &'static str, &'static str, &'static str)> {
    let has = |n: &str| resp.headers.iter().any(|(k, _)| k == n);
    let mut out = Vec::new();
    if !has("x-frame-options") && !has("content-security-policy") {
        out.push((
            "Missing X-Frame-Options / frame-ancestors",
            "missing-x-frame-options",
            "info",
            "No X-Frame-Options or CSP frame-ancestors: the page may be framed for clickjacking.",
        ));
    }
    if !has("content-security-policy") {
        out.push((
            "Missing Content-Security-Policy header",
            "missing-csp",
            "low",
            "No Content-Security-Policy: reduced defense-in-depth against XSS and injection.",
        ));
    }
    if !has("x-content-type-options") {
        out.push((
            "Missing X-Content-Type-Options header",
            "missing-x-content-type-options",
            "info",
            "No X-Content-Type-Options: nosniff, so browsers may MIME-sniff responses.",
        ));
    }
    if resp.is_https && !has("strict-transport-security") {
        out.push((
            "Missing Strict-Transport-Security header",
            "missing-hsts",
            "low",
            "HTTPS site without HSTS: connections can be downgraded to plaintext.",
        ));
    }
    out
}

/// Cap on how much of a decoded response body we buffer. reqwest's gzip feature
/// auto-decompresses, so an unbounded read lets a scanned target serve a small
/// gzip "bomb" that inflates to gigabytes and OOMs the engine (a scanned target
/// is attacker-controlled). Reading in chunks with a ceiling keeps a hostile
/// response from exhausting memory; 8 MiB is far more than any real finding needs.
pub const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Read a response body but stop after `MAX_BODY_BYTES` of decoded output.
pub async fn read_body_capped(mut resp: transport::Response) -> String {
    let mut buf: Vec<u8> = Vec::new();
    while buf.len() < MAX_BODY_BYTES {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let room = MAX_BODY_BYTES - buf.len();
                let take = chunk.len().min(room);
                buf.extend_from_slice(&chunk[..take]);
                if take < chunk.len() {
                    break;
                }
            }
            _ => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

pub(crate) async fn fetch_base(client: &Client, base: &str) -> Option<BaseResp> {
    match client.get(base).send().await {
        Ok(r) => {
            let status = r.status().as_u16();
            let is_https = base.starts_with("https://");
            let mut headers = Vec::new();
            for (k, v) in r.headers().iter() {
                headers.push((
                    k.as_str().to_lowercase(),
                    v.to_str().unwrap_or("").to_string(),
                ));
            }
            // A few KB of body is plenty to spot a challenge/block page.
            let body = read_body_capped(r).await;
            let body_prefix: String = body.chars().take(16_384).collect();
            Some(BaseResp {
                is_https,
                status,
                headers,
                body_prefix,
            })
        }
        Err(_) => None,
    }
}

fn normalize_base(t: &str) -> Option<String> {
    transport::url::normalize_target(t).map(|tgt| tgt.base())
}
