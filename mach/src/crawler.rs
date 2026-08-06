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
use transport::Client;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::sync::LazyLock;
use tokio::sync::mpsc;

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

/// Request auth resolved from a credential (see core::creds `AuthContext`).
#[derive(Debug, Deserialize, Clone, Default)]
pub struct AuthSpec {
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub cookies: String,
}

impl AuthSpec {
    /// Build a HeaderMap from the resolved auth (custom headers + Cookie).
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
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub params: Vec<String>,
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
    fn blank() -> Self {
        Self {
            kind: String::new(),
            url: None,
            status_code: None,
            method: None,
            content_type: None,
            params: Vec::new(),
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
/// Quoted absolute paths or full URLs inside JS/JSON/text.
static RE_JS_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"["'`](https?://[^"'`\s<>]+|/[A-Za-z0-9_./\-]{2,})["'`]"#).unwrap()
});
/// fetch()/axios()/.get()/.post()/.ajax() first string argument.
static RE_JS_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:fetch|axios(?:\.\w+)?|\.(?:get|post|put|delete|patch|ajax))\s*\(\s*["'`]([^"'`]+)["'`]"#).unwrap()
});

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
    let mut extra_headers = transport::HeaderMap::new();
    if let Some(auth) = params.auth.as_ref().filter(|a| a.is_meaningful()) {
        for (k, v) in auth.to_header_map().iter() {
            extra_headers.insert(k.clone(), v.clone());
        }
    }
    if let adaptive::identity::Mode::Identify(token) = &mode {
        if let Ok(val) = transport::HeaderValue::from_str(token) {
            extra_headers.insert(transport::HeaderName::from_static("x-bug-bounty"), val);
        }
    }
    let client = match transport::build_client(transport::ClientConfig {
        timeout: Some(std::time::Duration::from_millis(params.timeout_ms.max(1000))),
        redirect: transport::Redirect::Limited(5),
        accept_invalid_certs: true,
        cookie_store: true,
        user_agent: Some(ident.user_agent.clone()),
        browser_headers: transport::headers_from_pairs(&ident.headers),
        extra_headers,
        emulate: !matches!(mode, adaptive::identity::Mode::Fast),
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
                    // In-scope but a static asset: recorded (deduped) but not mapped or fetched.
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

            let _ = tx.send(CrawlEvent::progress(pages_crawled, max_pages));
        }
    }

    // Budget exhausted: surface the remaining known-but-unfetched URLs as candidates.
    while let Some((u, d, parent)) = frontier.pop_front() {
        let _ = tx.send(CrawlEvent::url_candidate(&u, parent, d));
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
                    if parse_js {
                        extract_js(&body, &mut page.links);
                    }
                } else if parse_js {
                    // js / json / xml / text: harvest URL-like strings
                    extract_js(&body, &mut page.links);
                }
            }
        }
        Err(_) => {
            page.status = 0;
        }
    }

    dedup(&mut page.links);
    dedup(&mut page.params);
    page
}

fn extract_html(body: &str, out: &mut Vec<String>) {
    for c in RE_HTML_ATTR.captures_iter(body) {
        if let Some(m) = c.get(1) {
            out.push(m.as_str().to_string());
        }
    }
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
