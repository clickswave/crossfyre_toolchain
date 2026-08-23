//! Wordlist-free web crawler - the engine behind the `web_crawl` workflow.
//!
//! Unlike the fuzz path (which guesses hidden paths from a wordlist), the crawler
//! discovers endpoints by following what the app itself reveals: HTML hrefs / form
//! actions / script srcs, plus URL and path patterns inside JavaScript files. It
//! streams one `CrawlEvent` per discovered URL back over the daemon's stream
//! connection; the node (core::run_operation) republishes each as a finding into
//! the shared asset graph.
//!
//! Static regex extraction is the "Standard" depth tier. Headless runtime
//! extraction (executing JS and capturing XHR/fetch + the built DOM) is the later
//! "Deep" tier and is intentionally not implemented here yet.

use regex::Regex;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::sync::LazyLock;
use tokio::sync::mpsc;
use transport::Client;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Parameters for a crawl operation (flattened into the daemon request body).
#[derive(Debug, Deserialize, Clone)]
pub struct CrawlParams {
    /// Seed URL or host to start from.
    pub seed: String,
    /// Evasiveness posture (from the node switch): blend in as a browser (true,
    /// default) vs a neutral honest client (false).
    #[serde(default = "d_true")]
    pub evasive: bool,
    /// Attribution token: when set, advertise it so an authorized program can
    /// allow-list the traffic.
    #[serde(default)]
    pub identify: Option<String>,
    /// Restrict to the seed's exact host. Default true.
    #[serde(default = "d_true")]
    pub same_host: bool,
    /// Also allow subdomains of the seed host (e.g. api.example.com under example.com).
    #[serde(default)]
    pub include_subdomains: bool,
    /// Follow links to any external host. Overrides same_host/include_subdomains.
    #[serde(default)]
    pub follow_external: bool,
    /// Extra in-scope host suffixes.
    #[serde(default)]
    pub scope_hosts: Vec<String>,
    /// Max crawl depth (link hops from the seed).
    #[serde(default = "d_depth")]
    pub max_depth: u32,
    /// Max pages actually fetched.
    #[serde(default = "d_pages")]
    pub max_pages: u32,
    /// Concurrent fetches per wave.
    #[serde(default = "d_tasks")]
    pub tasks: usize,
    /// Per-fetch delay in ms (OPSEC pacing).
    #[serde(default)]
    pub delay: u64,
    /// Per-request timeout in ms.
    #[serde(default = "d_timeout")]
    pub timeout_ms: u64,
    /// Parse JavaScript files/inline scripts for endpoints. Default true.
    #[serde(default = "d_true")]
    pub parse_js: bool,
    /// Also surface static resources (css/json/map/wasm) as inventory so the asset graph can track
    /// them appearing/disappearing. JS is fetched regardless (for endpoint mining + body hashing).
    #[serde(default = "d_true")]
    pub capture_static: bool,
    /// Substring patterns; any discovered URL containing one is skipped.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Controller posture (reserved for adaptive pacing): stealth|balanced|throughput.
    #[serde(default = "d_posture")]
    // populated but not read yet; kept so the struct still mirrors its config
    #[allow(dead_code)]
    pub posture: String,
    /// Optional request auth (headers + cookie) resolved from a credential by the
    /// node. Applied as default headers so every fetched page is authenticated.
    #[serde(default)]
    pub auth: Option<AuthSpec>,
}

/// Request auth resolved from a credential. Shared across all engines via
/// `transport`; re-exported so existing `AuthSpec` references in this module keep
/// resolving.
pub use transport::AuthSpec;

fn d_true() -> bool {
    true
}
fn d_depth() -> u32 {
    3
}
fn d_pages() -> u32 {
    300
}
fn d_tasks() -> usize {
    8
}
fn d_timeout() -> u64 {
    8000
}
fn d_posture() -> String {
    "balanced".to_string()
}

/// A single streamed crawl event (newline JSON). The node maps `type:"url"` events
/// into findings and `type:"progress"` into operation_progress.
#[derive(Debug, Serialize)]
pub struct CrawlEvent {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub params: Vec<String>,
    /// Body field NAMES for a form/API endpoint that takes a request body (POST/PUT/PATCH). The asset
    /// graph turns these into `location=body` params so the injection engine fuzzes the body, not just
    /// the URL query - which is what reaches SQLi/cmdi/etc. behind HTML form submissions.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub body_params: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovered_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processed: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl CrawlEvent {
    fn ack(total: u32) -> Self {
        Self {
            kind: "ack".into(),
            total: Some(total),
            ..Self::blank()
        }
    }
    fn progress(processed: u32, total: u32) -> Self {
        Self {
            kind: "progress".into(),
            processed: Some(processed),
            total: Some(total),
            ..Self::blank()
        }
    }
    fn done(processed: u32) -> Self {
        Self {
            kind: "done".into(),
            processed: Some(processed),
            ..Self::blank()
        }
    }
    fn error(msg: String) -> Self {
        Self {
            kind: "error".into(),
            message: Some(msg),
            ..Self::blank()
        }
    }
    fn url_fetched(p: &Page) -> Self {
        Self {
            kind: "url".into(),
            url: Some(p.url.to_string()),
            status_code: Some(p.status),
            method: Some("GET".into()),
            content_type: if p.content_type.is_empty() {
                None
            } else {
                Some(p.content_type.clone())
            },
            content_hash: if p.content_hash.is_empty() {
                None
            } else {
                Some(p.content_hash.clone())
            },
            params: p.params.clone(),
            discovered_from: p.parent.clone(),
            depth: Some(p.depth),
            ..Self::blank()
        }
    }
    fn url_candidate(u: &Url, parent: Option<String>, depth: u32) -> Self {
        Self {
            kind: "url".into(),
            url: Some(u.to_string()),
            method: Some("GET".into()),
            discovered_from: parent,
            depth: Some(depth),
            ..Self::blank()
        }
    }
    /// An HTML `<form>` as a testable operation: its action URL, its method, and its fields as query
    /// params (GET form) or body params (write form) so the engine fuzzes the right location.
    fn form(u: &Url, method: &str, fields: &[String], parent: Option<String>, depth: u32) -> Self {
        let write = matches!(method, "POST" | "PUT" | "PATCH" | "DELETE");
        Self {
            kind: "url".into(),
            url: Some(u.to_string()),
            method: Some(method.to_string()),
            params: if write { Vec::new() } else { fields.to_vec() },
            body_params: if write { fields.to_vec() } else { Vec::new() },
            discovered_from: parent,
            depth: Some(depth),
            ..Self::blank()
        }
    }
    fn blank() -> Self {
        Self {
            kind: String::new(),
            url: None,
            status_code: None,
            method: None,
            content_type: None,
            content_hash: None,
            params: Vec::new(),
            body_params: Vec::new(),
            discovered_from: None,
            depth: None,
            processed: None,
            total: None,
            message: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Extraction regexes (compiled once)
// ---------------------------------------------------------------------------

/// href/src/action attribute values. Skips pure-fragment and inline handlers.
static RE_HTML_ATTR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(?:href|src|action)\s*=\s*["']([^"'][^"']*)["']"#).unwrap());
/// `<input name="...">` for parameter collection.
static RE_INPUT_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<(?:input|select|textarea)[^>]*\bname\s*=\s*["']([^"']+)["']"#).unwrap()
});
/// A whole `<form ...> ... </form>` block: attr string + inner HTML.
static RE_FORM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?is)<form\b([^>]*)>(.*?)</form>"#).unwrap());
static RE_ATTR_ACTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\baction\s*=\s*["']([^"']*)["']"#).unwrap());
static RE_ATTR_METHOD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bmethod\s*=\s*["']([^"']*)["']"#).unwrap());
/// Quoted absolute paths or full URLs inside JS/JSON/text.
static RE_JS_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"["'`](https?://[^"'`\s<>]+|/[A-Za-z0-9_./\-]{2,})["'`]"#).unwrap()
});
/// fetch()/axios()/.get()/.post()/.ajax() first string argument (URL only, method-agnostic).
static RE_JS_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:fetch|axios(?:\.\w+)?|\.(?:get|post|put|delete|patch|ajax))\s*\(\s*["'`]([^"'`]+)["'`]"#).unwrap()
});

/// Same call sites, but capturing the HTTP verb: `axios.post('/x')`, `http.put('/x')`, `.delete('/x')`.
/// Group 1 or 2 is the verb; group 3 is the URL. `fetch(...)` has no verb here (stays GET).
static RE_JS_CALL_METHOD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\w+\.(get|post|put|delete|patch)|\.(get|post|put|delete|patch))\s*\(\s*["'`]([^"'`]+)["'`]"#).unwrap()
});

/// Mine `(method, url)` from JS API calls that name a non-GET verb, so the SPA's write endpoints are
/// recorded with the right method (a param-less GET is untestable by the fuzz/discover engines).
fn extract_js_calls(body: &str, out: &mut Vec<(String, String)>) {
    for c in RE_JS_CALL_METHOD.captures_iter(body) {
        let verb = c
            .get(1)
            .or_else(|| c.get(2))
            .map(|m| m.as_str().to_uppercase());
        let url = c.get(3).map(|m| m.as_str().to_string());
        if let (Some(v), Some(u)) = (verb, url) {
            if v != "GET" {
                out.push((v, u));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Crawl state
// ---------------------------------------------------------------------------

struct Page {
    url: Url,
    depth: u32,
    parent: Option<String>,
    status: u16,
    content_type: String,
    links: Vec<String>,
    params: Vec<String>,
    /// (method, url) pairs mined from `fetch()/axios.post()/.put()...` calls in JS: the SPA's real
    /// API surface with its verb, so a mined `axios.post('/api/x')` becomes a POST operation the
    /// shape-discovery and injection engines can then work, not a param-less GET.
    api_calls: Vec<(String, String)>,
    /// (raw_action, METHOD, field_names) per `<form>` on the page: a form's action becomes a testable
    /// operation carrying its fields as body params (write forms) or query params (GET forms), so the
    /// injection engine reaches SQLi/cmdi/etc. behind form submissions.
    forms: Vec<(String, String, Vec<String>)>,
    /// sha256 of the response body for non-HTML text/code (js/json/xml). Empty otherwise. Lets the
    /// asset graph change-monitor JS/config bundles across scans without storing the body.
    content_hash: String,
}

const MAX_VISITED: usize = 20_000;

/// Run a crawl, streaming events into `tx`. Returns when the crawl finishes,
/// the page budget is hit, or the frontier drains.
pub async fn run_stream(params: CrawlParams, tx: mpsc::UnboundedSender<CrawlEvent>) {
    let seed = match normalize_seed(&params.seed) {
        Some(u) => u,
        None => {
            let _ = tx.send(CrawlEvent::error(format!("invalid seed: {}", params.seed)));
            return;
        }
    };
    let seed_host = seed.host_str().unwrap_or_default().to_lowercase();

    let mode = adaptive::identity::Mode::from_flags(params.evasive, params.identify.clone());
    let ident = adaptive::identity::resolve(&mode, Some(&seed_host));
    let token = if let adaptive::identity::Mode::Identify(t) = &mode {
        Some(t.as_str())
    } else {
        None
    };
    let client = match transport::build_scan_client(transport::ScanClient {
        identity_headers: &ident.headers,
        user_agent: &ident.user_agent,
        auth: params.auth.as_ref(),
        attribution_token: token,
        emulate: !matches!(mode, adaptive::identity::Mode::Fast),
        timeout: Some(std::time::Duration::from_millis(
            params.timeout_ms.max(1000),
        )),
        redirect: transport::Redirect::Limited(5),
        accept_invalid_certs: true,
        cookie_store: true,
        resolve: Vec::new(),
    }) {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(CrawlEvent::error(format!("client build failed: {e}")));
            return;
        }
    };

    let max_pages = params.max_pages.clamp(1, 5000);
    let max_depth = params.max_depth.min(20);
    let tasks = params.tasks.clamp(1, 50);

    let _ = tx.send(CrawlEvent::ack(max_pages));

    let mut visited: HashSet<String> = HashSet::new();
    let mut frontier: VecDeque<(Url, u32, Option<String>)> = VecDeque::new();
    visited.insert(norm_key(&seed));
    frontier.push_back((seed.clone(), 0, None));

    let mut pages_crawled: u32 = 0;

    while !frontier.is_empty() && pages_crawled < max_pages {
        // Take a wave of up to `tasks` URLs without exceeding the page budget.
        let mut wave: Vec<(Url, u32, Option<String>)> = Vec::new();
        while wave.len() < tasks && pages_crawled + (wave.len() as u32) < max_pages {
            match frontier.pop_front() {
                Some(x) => wave.push(x),
                None => break,
            }
        }
        if wave.is_empty() {
            break;
        }

        let mut set = tokio::task::JoinSet::new();
        for (u, d, parent) in wave {
            let client = client.clone();
            let delay = params.delay;
            let parse_js = params.parse_js;
            set.spawn(async move {
                if delay > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }
                fetch_page(&client, u, d, parent, parse_js).await
            });
        }

        while let Some(joined) = set.join_next().await {
            let page = match joined {
                Ok(p) => p,
                Err(_) => continue,
            };
            pages_crawled += 1;
            let _ = tx.send(CrawlEvent::url_fetched(&page));

            for raw in &page.links {
                if visited.len() >= MAX_VISITED {
                    break;
                }
                let child = match resolve_and_scope(raw, &page.url, &params, &seed_host) {
                    Some(c) => c,
                    None => continue,
                };
                let key = norm_key(&child);
                if !visited.insert(key) {
                    continue;
                }
                if is_static_asset(&child) {
                    // In-scope static asset: not crawled as a page, but (when capture_static) surfaced
                    // as inventory if it's a trackable code/config file (css/json/map/wasm). Media
                    // (images/fonts/av) stays dropped as noise. JS is not here - it isn't static-listed,
                    // so it's fetched above and its body hashed.
                    if params.capture_static && is_trackable_static(&child) {
                        let _ = tx.send(CrawlEvent::url_candidate(
                            &child,
                            Some(page.url.to_string()),
                            page.depth + 1,
                        ));
                    }
                    continue;
                }
                let child_depth = page.depth + 1;
                let parent = Some(page.url.to_string());
                if child_depth <= max_depth {
                    frontier.push_back((child, child_depth, parent));
                    // Emitted when fetched (or drained as a candidate below).
                } else {
                    let _ = tx.send(CrawlEvent::url_candidate(&child, parent, child_depth));
                }
            }

            // Mined write-verb API calls (axios.post/.put/...): surface each with its real method so
            // the asset graph records a POST/PUT/... operation the shape-discovery and injection
            // engines can then exercise, instead of a param-less GET they skip.
            for (method, raw) in &page.api_calls {
                let Some(child) = resolve_and_scope(raw, &page.url, &params, &seed_host) else {
                    continue;
                };
                let mut ev =
                    CrawlEvent::url_candidate(&child, Some(page.url.to_string()), page.depth + 1);
                ev.method = Some(method.clone());
                let _ = tx.send(ev);
            }

            // HTML forms -> testable operations. Resolve the action against the page (empty action =
            // the page's own URL), scope it, and emit with the form's method + fields so the injection
            // engine fuzzes the BODY of a POST form (SQLi/cmdi/XPath behind form submissions).
            for (action, method, fields) in &page.forms {
                let raw = if action.is_empty() {
                    page.url.as_str()
                } else {
                    action.as_str()
                };
                let Some(child) = resolve_and_scope(raw, &page.url, &params, &seed_host) else {
                    continue;
                };
                let _ = tx.send(CrawlEvent::form(
                    &child,
                    method,
                    fields,
                    Some(page.url.to_string()),
                    page.depth + 1,
                ));
            }

            let _ = tx.send(CrawlEvent::progress(pages_crawled, max_pages));
        }
    }

    // Budget exhausted: surface the remaining known-but-unfetched URLs as candidates.
    while let Some((u, d, parent)) = frontier.pop_front() {
        let _ = tx.send(CrawlEvent::url_candidate(&u, parent, d));
    }

    // Probe API-spec locations AFTER the link crawl so the burst of probe requests
    // (some apps rate-limit / serve their SPA for unknown paths) can't perturb the
    // main crawl. A bare REST API exposes no HTML/JS to crawl, but its
    // OpenAPI/Swagger doc lists every route; we harvest the spec's quoted path keys
    // as candidates so spec-defined endpoints still enter the asset graph.
    if params.parse_js {
        probe_specs(&client, &seed, &seed_host, &params, &tx).await;
    }

    let _ = tx.send(CrawlEvent::done(pages_crawled));
}

// ---------------------------------------------------------------------------
// Fetch + extract
// ---------------------------------------------------------------------------

async fn fetch_page(
    client: &Client,
    url: Url,
    depth: u32,
    parent: Option<String>,
    parse_js: bool,
) -> Page {
    let mut page = Page {
        params: query_keys(&url),
        url: url.clone(),
        depth,
        parent,
        status: 0,
        content_type: String::new(),
        links: Vec::new(),
        api_calls: Vec::new(),
        forms: Vec::new(),
        content_hash: String::new(),
    };

    match client.get(url.clone()).send().await {
        Ok(resp) => {
            page.status = resp.status().as_u16();
            let ct = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            page.content_type = ct.split(';').next().unwrap_or("").trim().to_lowercase();

            let path = url.path().to_lowercase();
            let is_html = page.content_type.contains("html");
            let is_js = page.content_type.contains("javascript")
                || path.ends_with(".js")
                || path.ends_with(".mjs");
            let is_texty = is_html
                || is_js
                || page.content_type.contains("json")
                || page.content_type.contains("xml")
                || page.content_type.contains("text");

            if is_texty && let Ok(body) = resp.text().await {
                if is_html {
                    extract_html(&body, &mut page.links);
                    extract_input_names(&body, &mut page.params);
                    page.forms = extract_forms(&body);
                    if parse_js {
                        extract_js(&body, &mut page.links);
                        extract_js_calls(&body, &mut page.api_calls);
                    }
                } else {
                    // js / json / xml / text: hash the body so the asset graph can change-monitor it,
                    // and harvest URL-like strings (JS recon).
                    page.content_hash = sha256_hex(body.as_bytes());
                    if parse_js {
                        extract_js(&body, &mut page.links);
                        extract_js_calls(&body, &mut page.api_calls);
                    }
                }
            }
        }
        Err(_) => {
            page.status = 0;
        }
    }

    dedup(&mut page.links);
    dedup(&mut page.params);
    page.api_calls.sort();
    page.api_calls.dedup();
    page
}

/// Fetch well-known OpenAPI/Swagger locations and harvest their route keys, so a
/// bare API (no crawlable HTML/JS) still yields its endpoints. Runs before the
/// main crawl and emits candidates directly; it never touches the crawl frontier.
async fn probe_specs(
    client: &Client,
    seed: &Url,
    seed_host: &str,
    params: &CrawlParams,
    tx: &mpsc::UnboundedSender<CrawlEvent>,
) {
    const SPEC_PATHS: &[&str] = &[
        "/openapi.json",
        "/swagger.json",
        "/api-docs",
        "/v2/api-docs",
        "/v3/api-docs",
        "/swagger/v1/swagger.json",
        "/api/openapi.json",
        "/api-docs/swagger.json",
        "/swagger/doc.json",
        "/api/swagger.json",
    ];
    // Probe all locations concurrently with a short timeout: on an app that serves
    // its SPA for unknown paths, sequential probing with the full crawl timeout
    // would starve the actual crawl. Capped so the whole pass is a few seconds.
    let mut set = tokio::task::JoinSet::new();
    for p in SPEC_PATHS {
        let url = match seed.join(p) {
            Ok(u) => u,
            Err(_) => continue,
        };
        let client = client.clone();
        set.spawn(async move {
            let resp = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                client.get(url.clone()).send(),
            )
            .await
            .ok()?
            .ok()?;
            if !resp.status().is_success() {
                return None;
            }
            let ct = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_lowercase();
            if !ct.contains("json") {
                return None;
            }
            let body = tokio::time::timeout(std::time::Duration::from_secs(6), resp.text())
                .await
                .ok()?
                .ok()?;
            // Only harvest something that actually looks like an API spec.
            if !(body.contains("\"paths\"")
                || body.contains("\"swagger\"")
                || body.contains("\"openapi\""))
            {
                return None;
            }
            Some((url, body))
        });
    }
    while let Some(joined) = set.join_next().await {
        if let Ok(Some((url, body))) = joined {
            let mut links = Vec::new();
            extract_js(&body, &mut links);
            dedup(&mut links);
            for raw in &links {
                if let Some(child) = resolve_and_scope(raw, &url, params, seed_host) {
                    let _ = tx.send(CrawlEvent::url_candidate(&child, Some(url.to_string()), 1));
                }
            }
        }
    }
}

fn extract_html(body: &str, out: &mut Vec<String>) {
    for c in RE_HTML_ATTR.captures_iter(body) {
        if let Some(m) = c.get(1) {
            out.push(m.as_str().to_string());
        }
    }
}

/// Each `<form>` on the page as (raw_action, METHOD, field_names). Field names come from the inputs
/// INSIDE that form, so a POST form's fields are attributed to the form's action + POST method rather
/// than smeared across the page as query params. Empty action = submits to the page's own URL.
fn extract_forms(body: &str) -> Vec<(String, String, Vec<String>)> {
    let mut out = Vec::new();
    for f in RE_FORM.captures_iter(body) {
        let attrs = f.get(1).map(|m| m.as_str()).unwrap_or("");
        let inner = f.get(2).map(|m| m.as_str()).unwrap_or("");
        let action = RE_ATTR_ACTION
            .captures(attrs)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();
        let method = RE_ATTR_METHOD
            .captures(attrs)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_uppercase())
            .filter(|m| !m.is_empty())
            .unwrap_or_else(|| "GET".into());
        let mut fields = Vec::new();
        for c in RE_INPUT_NAME.captures_iter(inner) {
            if let Some(m) = c.get(1) {
                let n = m.as_str().to_string();
                if !n.is_empty() && !fields.contains(&n) {
                    fields.push(n);
                }
            }
        }
        if !fields.is_empty() {
            out.push((action, method, fields));
        }
    }
    out
}

fn extract_input_names(body: &str, out: &mut Vec<String>) {
    for c in RE_INPUT_NAME.captures_iter(body) {
        if let Some(m) = c.get(1) {
            out.push(m.as_str().to_string());
        }
    }
}

fn extract_js(body: &str, out: &mut Vec<String>) {
    for c in RE_JS_PATH.captures_iter(body) {
        if let Some(m) = c.get(1) {
            out.push(m.as_str().to_string());
        }
    }
    for c in RE_JS_CALL.captures_iter(body) {
        if let Some(m) = c.get(1) {
            out.push(m.as_str().to_string());
        }
    }
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

fn normalize_seed(seed: &str) -> Option<Url> {
    let s = seed.trim();
    if s.is_empty() {
        return None;
    }
    let with_scheme = if s.starts_with("http://") || s.starts_with("https://") {
        s.to_string()
    } else {
        format!("http://{s}")
    };
    Url::parse(&with_scheme).ok()
}

/// Resolve a raw link against the page URL and apply scope rules. Returns the
/// canonical (fragment-stripped) URL if it should be part of the map.
fn resolve_and_scope(raw: &str, base: &Url, params: &CrawlParams, seed_host: &str) -> Option<Url> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("mailto:")
        || lower.starts_with("javascript:")
        || lower.starts_with("tel:")
        || lower.starts_with("data:")
        || lower.starts_with("blob:")
        || raw.starts_with('#')
    {
        return None;
    }

    let mut url = base.join(raw).ok()?;
    match url.scheme() {
        "http" | "https" => {}
        _ => return None,
    }
    url.set_fragment(None);

    let host = url.host_str()?.to_lowercase();
    // `||` short-circuits left to right, so this evaluates exactly as the
    // previous if/else-if chain did: the scope_hosts scan only runs when every
    // cheaper check has already failed.
    let in_scope = params.follow_external
        || host == seed_host
        || (params.include_subdomains && host.ends_with(&format!(".{seed_host}")))
        || params.scope_hosts.iter().any(|s| {
            let s = s.to_lowercase();
            host == s || host.ends_with(&format!(".{s}"))
        });
    if !in_scope {
        return None;
    }
    if !params.same_host
        && !params.include_subdomains
        && !params.follow_external
        && host != seed_host
    {
        return None;
    }

    let full = url.as_str();
    if params
        .exclude
        .iter()
        .any(|p| !p.is_empty() && full.contains(p.as_str()))
    {
        return None;
    }

    Some(url)
}

/// A canonical dedup key: scheme, host, path, and sorted query keys (values
/// dropped so /x?id=1 and /x?id=2 collapse to the same endpoint).
fn norm_key(url: &Url) -> String {
    let scheme = url.scheme();
    let host = url.host_str().unwrap_or("");
    let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
    let path = url.path().trim_end_matches('/');
    let mut keys: Vec<String> = url.query_pairs().map(|(k, _)| k.into_owned()).collect();
    keys.sort();
    keys.dedup();
    let q = if keys.is_empty() {
        String::new()
    } else {
        format!("?{}", keys.join("&"))
    };
    format!("{scheme}://{host}{port}{path}{q}")
}

fn query_keys(url: &Url) -> Vec<String> {
    let mut v: Vec<String> = url.query_pairs().map(|(k, _)| k.into_owned()).collect();
    dedup(&mut v);
    v
}

fn is_static_asset(url: &Url) -> bool {
    let path = url.path().to_lowercase();
    const EXT: &[&str] = &[
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".css", ".woff",
        ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm", ".mp3", ".wav", ".avi", ".mov", ".pdf",
        ".zip", ".gz", ".tar", ".rar", ".7z",
    ];
    EXT.iter().any(|e| path.ends_with(e))
}

/// A static asset worth inventorying (code/config), as opposed to media noise. These carry attack
/// surface / change signal; images/fonts/audio/video/archives don't.
fn is_trackable_static(url: &Url) -> bool {
    let path = url.path().to_lowercase();
    const EXT: &[&str] = &[".css", ".json", ".map", ".wasm", ".xml"];
    EXT.iter().any(|e| path.ends_with(e))
}

/// Lowercase hex sha256 (no `hex` crate dependency).
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn dedup(v: &mut Vec<String>) {
    let mut seen = HashSet::new();
    v.retain(|s| !s.is_empty() && seen.insert(s.clone()));
}

#[cfg(test)]
mod normalize_seed_tests {
    use super::normalize_seed;

    #[test]
    fn adds_scheme_and_keeps_existing() {
        assert_eq!(
            normalize_seed("example.com").unwrap().as_str(),
            "http://example.com/"
        );
        assert_eq!(normalize_seed("https://x.com/a").unwrap().scheme(), "https");
    }

    #[test]
    fn empty_is_none() {
        assert!(normalize_seed("").is_none());
        assert!(normalize_seed("   ").is_none());
    }
}
