//! The Cortex vulnerability engine (minimal, real detection).
//!
//! Every candidate flows through the correctness pipeline
//! (GENERATE -> DETECT -> CONFIRM -> REPORT): template matches are re-issued to
//! confirm (see template.rs), and passive checks are deterministic on the
//! observed response. Findings are relayed verbatim by the node into the shared
//! asset graph. OAST-backed blind detection, the full DSL, and the generative
//! API mode are the documented next milestones (docs/tier1-engines-plan.md).

use crate::template;
use reqwest::Client;
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Debug, Deserialize)]
pub struct ScanParams {
    pub target: String,
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

/// Request auth resolved from a credential (see core::creds `AuthContext`).
#[derive(Debug, serde::Deserialize, Clone, Default)]
pub struct AuthSpec {
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub cookies: String,
}
impl AuthSpec {
    pub fn to_header_map(&self) -> reqwest::header::HeaderMap {
        use reqwest::header::{COOKIE, HeaderMap, HeaderName, HeaderValue};
        let mut hm = HeaderMap::new();
        for (k, v) in &self.headers {
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(v),
            ) {
                hm.insert(name, val);
            }
        }
        if !self.cookies.is_empty()
            && let Ok(val) = HeaderValue::from_str(&self.cookies)
        {
            hm.insert(COOKIE, val);
        }
        hm
    }
    pub fn is_meaningful(&self) -> bool {
        !self.headers.is_empty() || !self.cookies.is_empty()
    }
}

struct BaseResp {
    is_https: bool,
    headers: Vec<(String, String)>,
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

    let mut builder = Client::builder()
        .timeout(Duration::from_millis(params.timeout_ms.max(1000)))
        .redirect(if params.follow_redirects {
            reqwest::redirect::Policy::limited(5)
        } else {
            reqwest::redirect::Policy::none()
        })
        .danger_accept_invalid_certs(true)
        .cookie_store(true)
        .user_agent("Mozilla/5.0 (compatible; cortex/0.1; +https://clickswave.org)");
    if let Some(auth) = params.auth.as_ref().filter(|a| a.is_meaningful()) {
        builder = builder.default_headers(auth.to_header_map());
    }
    let client = match builder.build() {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(json!({"type":"error","message":format!("client build failed: {e}")}));
            return;
        }
    };

    let _ = tx.send(json!({"type":"ack","target": base}));

    let sev_filter: Vec<String> = params.severity.iter().map(|s| s.to_lowercase()).collect();
    let allow = |sev: &str| sev_filter.is_empty() || sev_filter.iter().any(|s| s == sev);

    let mut found: i64 = 0;

    // --- Passive header checks on the base response (deterministic) ---
    if let Some(resp) = fetch_base(&client, &base).await {
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
    }

    // --- Template mode (confirm-then-report) ---
    if !params.passive_only {
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
                for m in template::eval_template(&client, &base, tmpl, oast.as_ref()).await {
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

async fn fetch_base(client: &Client, base: &str) -> Option<BaseResp> {
    match client.get(base).send().await {
        Ok(r) => {
            let mut headers = Vec::new();
            for (k, v) in r.headers().iter() {
                headers.push((
                    k.as_str().to_lowercase(),
                    v.to_str().unwrap_or("").to_string(),
                ));
            }
            Some(BaseResp {
                is_https: base.starts_with("https://"),
                headers,
            })
        }
        Err(_) => None,
    }
}

fn normalize_base(t: &str) -> Option<String> {
    let t = t.trim();
    if t.is_empty() {
        return None;
    }
    let with_scheme = if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else if let Some((_, p)) = t.rsplit_once(':') {
        if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            let scheme = if p == "443" || p == "8443" {
                "https"
            } else {
                "http"
            };
            format!("{scheme}://{t}")
        } else {
            format!("http://{t}")
        }
    } else {
        format!("http://{t}")
    };
    let url = reqwest::Url::parse(&with_scheme).ok()?;
    let scheme = url.scheme();
    let host = url.host_str()?;
    let base = match url.port() {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    };
    Some(base)
}
