//! Authorization testing (BOLA / BFLA / broken authentication).
//!
//! Given a set of endpoints and a set of identities (each a role + resolved auth
//! context), this replays every endpoint as every identity and compares the
//! responses to detect authorization flaws:
//!
//! - **Broken authentication**: an anonymous request reaches a protected endpoint.
//! - **BFLA** (function-level): a non-privileged identity reaches a privileged
//!   endpoint that a privileged identity also reaches (so it is a real function).
//! - **BOLA / IDOR** (object-level): two *different* authenticated identities get
//!   byte-identical successful responses for an object-scoped endpoint, meaning
//!   the object is not scoped to its owner.
//!
//! Correctness is the product: every candidate is re-requested (confirm step)
//! before it is reported, obvious public endpoints are excluded, and login/redirect
//! pages are never counted as success.

use crate::engine::AuthSpec;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;
use tokio::sync::mpsc;
use transport::Client;

#[derive(Debug, Deserialize)]
pub struct AuthzParams {
    #[serde(default)]
    pub endpoints: Vec<Endpoint>,
    #[serde(default)]
    pub identities: Vec<Identity>,
    #[serde(default = "d_timeout")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub target: String,
    /// Opt-in to the state-changing mass-assignment probe (POST/PUT/PATCH with an
    /// injected privileged body). Off by default: read-only is the safe default,
    /// per the plan's safety rails.
    #[serde(default)]
    pub test_writes: bool,
    /// Evasiveness posture (from the node switch): blend in as a browser (true,
    /// default) vs a neutral honest client (false).
    #[serde(default = "d_true")]
    pub evasive: bool,
    /// Attribution token: when set, advertise it so an authorized program can
    /// allow-list the traffic.
    #[serde(default)]
    pub identify: Option<String>,
}
fn d_true() -> bool {
    true
}
fn d_timeout() -> u64 {
    10_000
}

#[derive(Debug, Deserialize, Clone)]
pub struct Endpoint {
    #[serde(default = "d_get")]
    pub method: String,
    pub url: String,
}
fn d_get() -> String {
    "GET".into()
}

#[derive(Debug, Deserialize, Clone)]
pub struct Identity {
    pub role: String,
    #[serde(default)]
    pub auth: AuthSpec,
}

#[derive(Clone)]
struct Probe {
    role: String,
    is_anon: bool,
    status: u16,
    body_len: usize,
    body_hash: u64,
    login_ish: bool,
    ok: bool,
    /// Hard-sensitive field names found in the response body (password/token/...),
    /// for the BOPLA excessive-data-exposure oracle.
    sensitive: Vec<String>,
}

/// A finding that still needs its confirm re-request before it is emitted.
struct Candidate {
    finding: Value,
    /// Which identity to re-probe to confirm.
    confirm_role: String,
    /// For BOLA, the body hash that must reappear on re-probe.
    expect_hash: Option<u64>,
    /// For excessive-data-exposure, the sensitive field must reappear on re-probe.
    expect_sensitive: bool,
}

pub async fn run(params: AuthzParams, tx: mpsc::UnboundedSender<Value>) {
    let _ = tx.send(json!({ "type": "ack", "target": params.target }));

    if params.identities.is_empty() {
        let _ = tx.send(
            json!({"type":"error","message":"authorization testing needs at least one identity"}),
        );
        let _ = tx.send(json!({"type":"done","found":0}));
        return;
    }
    if params.endpoints.is_empty() {
        let _ = tx.send(json!({"type":"error","message":"authorization testing needs at least one endpoint (run a crawl first, or provide endpoints)"}));
        let _ = tx.send(json!({"type":"done","found":0}));
        return;
    }

    // One client per identity, carrying that identity's auth as default headers.
    // Redirects are NOT followed so a 302 to a login page reads as "denied".
    // One coherent browser identity for the whole authz run; each per-auth
    // client carries it plus that auth identity's headers.
    let mode = adaptive::identity::Mode::from_flags(params.evasive, params.identify.clone());
    let seed = (!params.target.is_empty()).then_some(params.target.as_str());
    let browser = adaptive::identity::resolve(&mode, seed);
    let emulate = !matches!(mode, adaptive::identity::Mode::Fast);
    // Attribution token (Identify posture) is an app header that must survive
    // emulation, so it is added to each client's extra headers below.
    let identify_token = if let adaptive::identity::Mode::Identify(t) = &mode {
        transport::HeaderValue::from_str(t).ok()
    } else {
        None
    };
    let mut clients: Vec<(Identity, Client)> = Vec::new();
    for id in &params.identities {
        let mut browser_headers = transport::HeaderMap::new();
        for (k, v) in &browser.headers {
            if let (Ok(name), Ok(val)) = (
                transport::HeaderName::from_bytes(k.as_bytes()),
                transport::HeaderValue::from_str(v),
            ) {
                browser_headers.insert(name, val);
            }
        }
        let mut extra_headers = transport::HeaderMap::new();
        if id.auth.is_meaningful() {
            for (k, v) in id.auth.to_header_map().iter() {
                extra_headers.insert(k.clone(), v.clone());
            }
        }
        if let Some(tok) = &identify_token {
            extra_headers.insert(
                transport::HeaderName::from_static("x-bug-bounty"),
                tok.clone(),
            );
        }
        let built = transport::build_client(transport::ClientConfig {
            timeout: Some(Duration::from_millis(
                params.timeout_ms.clamp(1000, 120_000),
            )),
            redirect: transport::Redirect::None,
            accept_invalid_certs: true,
            cookie_store: false,
            user_agent: Some(browser.user_agent.clone()),
            browser_headers,
            extra_headers,
            emulate,
            resolve: Vec::new(),
        });
        match built {
            Ok(c) => clients.push((id.clone(), c)),
            Err(e) => {
                let _ =
                    tx.send(json!({"type":"error","message":format!("client build failed: {e}")}));
                return;
            }
        }
    }

    let total = params.endpoints.len() as i64;
    let mut done = 0i64;
    let mut found = 0i64;

    for ep in &params.endpoints {
        let mut probes: Vec<Probe> = Vec::with_capacity(clients.len());
        for (id, client) in &clients {
            probes.push(probe(client, ep, id).await);
        }

        for cand in analyze(ep, &probes) {
            // Confirm step: re-request as the accused identity before reporting.
            if let Some((_, client)) = clients.iter().find(|(id, _)| id.role == cand.confirm_role) {
                let p2 = probe(
                    client,
                    ep,
                    &Identity {
                        role: cand.confirm_role.clone(),
                        auth: AuthSpec::default(),
                    },
                )
                .await;
                let confirmed = if let Some(h) = cand.expect_hash {
                    p2.ok && p2.body_hash == h
                } else if cand.expect_sensitive {
                    p2.ok && !p2.sensitive.is_empty()
                } else {
                    p2.ok && !p2.login_ish
                };
                if confirmed {
                    found += 1;
                    let _ = tx.send(json!({ "type": "finding", "data": cand.finding }));
                }
            }
        }

        // BOPLA mass-assignment (state-changing) - opt-in only, write verbs only.
        if params.test_writes && is_write_method(&ep.method) {
            found += mass_assign_probe(ep, &clients, &tx).await;
        }

        done += 1;
        if done % 5 == 0 || done == total {
            let _ = tx.send(json!({"type":"progress","processed": done, "total": total}));
        }
    }

    let _ = tx.send(json!({"type":"done","found": found}));
}

fn is_write_method(m: &str) -> bool {
    matches!(m.to_uppercase().as_str(), "POST" | "PUT" | "PATCH")
}

const INJECT_BODY: &str =
    r#"{"role":"admin","is_admin":true,"isAdmin":true,"admin":true,"is_superuser":true}"#;

/// A 2xx write response that echoes an injected privileged property back as
/// accepted - the reflection signal for mass assignment.
fn injected_reflected(status: u16, body: &str) -> bool {
    if !(200..300).contains(&status) {
        return false;
    }
    // Strip whitespace so `"role": "admin"` and `"role":"admin"` both match.
    let low: String = body
        .to_ascii_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    low.contains("\"role\":\"admin\"")
        || low.contains("\"is_admin\":true")
        || low.contains("\"isadmin\":true")
        || low.contains("\"admin\":true")
        || low.contains("\"is_superuser\":true")
}

async fn send_injected(client: &Client, ep: &Endpoint) -> (u16, String) {
    let rb = match ep.method.to_uppercase().as_str() {
        "PUT" => client.put(&ep.url),
        "PATCH" => client.patch(&ep.url),
        _ => client.post(&ep.url),
    }
    .header("Content-Type", "application/json")
    .body(INJECT_BODY);
    match rb.send().await {
        Ok(r) => {
            let s = r.status().as_u16();
            let b = crate::engine::read_body_capped(r).await;
            (s, b)
        }
        Err(_) => (0, String::new()),
    }
}

/// Send an injected privileged body as each non-privileged authed identity and
/// report mass assignment when the property is reflected as accepted (re-sent
/// once to confirm). Anonymous and privileged identities are skipped: setting your
/// own admin flag only matters for a lower-privileged identity.
async fn mass_assign_probe(
    ep: &Endpoint,
    clients: &[(Identity, Client)],
    tx: &mpsc::UnboundedSender<Value>,
) -> i64 {
    let mut found = 0;
    for (id, client) in clients {
        if !id.auth.is_meaningful() || role_is_privileged(&id.role) {
            continue;
        }
        let (s1, b1) = send_injected(client, ep).await;
        if !injected_reflected(s1, &b1) {
            continue;
        }
        let (s2, b2) = send_injected(client, ep).await; // confirm
        if !injected_reflected(s2, &b2) {
            continue;
        }
        let matrix = json!([{ "role": id.role, "status": s1, "reflected": true }]);
        let finding = finding_value(
            "Mass assignment / BOPLA (privileged property accepted)",
            "high",
            "mass_assignment",
            ep,
            &matrix,
            &id.role,
            format!(
                "Identity '{}' set a privileged property (role/is_admin) via {} {} and it was reflected as accepted, indicating mass assignment.",
                id.role,
                ep.method.to_uppercase(),
                ep.url
            ),
        );
        let _ = tx.send(json!({ "type": "finding", "data": finding }));
        found += 1;
    }
    found
}

async fn probe(client: &Client, ep: &Endpoint, id: &Identity) -> Probe {
    let method = ep.method.to_uppercase();
    let mut attempt: u32 = 0;
    loop {
        let rb = match method.as_str() {
            "POST" => client.post(&ep.url),
            "PUT" => client.put(&ep.url),
            "DELETE" => client.delete(&ep.url),
            "PATCH" => client.patch(&ep.url),
            "HEAD" => client.head(&ep.url),
            _ => client.get(&ep.url),
        };
        match rb.send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                // Rate-limit resilience: back off and retry so a 429/503 is not
                // misread as "denied" (which would hide a real BOLA/BFLA).
                if (status == 429 || status == 503) && attempt < 5 {
                    let wait = (400u64 << attempt.min(4)).min(4000);
                    tokio::time::sleep(Duration::from_millis(wait)).await;
                    attempt += 1;
                    continue;
                }
                let is_redirect = (300..400).contains(&status);
                let body = crate::engine::read_body_capped(r).await;
                let ok = (200..300).contains(&status);
                return Probe {
                    role: id.role.clone(),
                    is_anon: !id.auth.is_meaningful(),
                    status,
                    body_len: body.len(),
                    body_hash: hash_body(&body),
                    login_ish: is_redirect || looks_like_login(&body),
                    ok,
                    sensitive: if ok {
                        scan_sensitive(&body)
                    } else {
                        Vec::new()
                    },
                };
            }
            Err(_) => {
                if attempt < 2 {
                    tokio::time::sleep(Duration::from_millis(300 * (attempt as u64 + 1))).await;
                    attempt += 1;
                    continue;
                }
                return Probe {
                    role: id.role.clone(),
                    is_anon: !id.auth.is_meaningful(),
                    status: 0,
                    body_len: 0,
                    body_hash: 0,
                    login_ish: false,
                    ok: false,
                    sensitive: Vec::new(),
                };
            }
        }
    }
}

fn analyze(ep: &Endpoint, probes: &[Probe]) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    let matrix = build_matrix(probes);
    let anon = probes.iter().find(|p| p.is_anon);
    let authed: Vec<&Probe> = probes.iter().filter(|p| !p.is_anon).collect();

    let is_priv_path = privileged_path(&ep.url);
    let has_object_id = object_id_in_path(&ep.url);
    // Fully public: every identity gets a 2xx and they all share one body.
    let all_ok = probes.iter().all(|p| p.ok);
    let all_same_body = all_ok
        && probes
            .windows(2)
            .all(|w| w[0].body_hash == w[1].body_hash && w[0].body_hash != 0);

    // 1) Broken authentication: anon reaches a protected endpoint.
    if let Some(a) = anon
        && a.ok
        && !a.login_ish
        && (is_priv_path || looks_protected(&ep.url))
        && !all_same_body
    {
        out.push(Candidate {
            confirm_role: a.role.clone(),
            expect_hash: None,
            expect_sensitive: false,
            finding: finding_value(
                "Unauthenticated access to a protected endpoint",
                "high",
                "broken_authentication",
                ep,
                &matrix,
                &a.role,
                format!(
                    "An unauthenticated request to {} returned {} (expected 401/403).",
                    ep.url, a.status
                ),
            ),
        });
    }

    // 2) BFLA: a non-privileged identity reaches a privileged endpoint that a
    //    privileged identity also reaches (proving it is a real function).
    if is_priv_path {
        let priv_baseline = authed
            .iter()
            .any(|p| role_is_privileged(&p.role) && p.ok && !p.login_ish);
        if priv_baseline {
            for p in &authed {
                if p.ok && !p.login_ish && !role_is_privileged(&p.role) {
                    out.push(Candidate {
                        confirm_role: p.role.clone(),
                        expect_hash: None,
                        expect_sensitive: false,
                        finding: finding_value(
                            "Function-level authorization broken (BFLA)",
                            "high",
                            "bfla",
                            ep,
                            &matrix,
                            &p.role,
                            format!(
                                "Non-privileged identity '{}' reached the privileged endpoint {} with {} (a privileged identity also succeeds, so it is a real function).",
                                p.role, ep.url, p.status
                            ),
                        ),
                    });
                }
            }
        }
    }

    // 3) BOLA / IDOR: two different authenticated identities get byte-identical
    //    successful bodies for an object-scoped endpoint, and anon cannot.
    //    BOLA is a *horizontal* break (a peer reads a peer's object), so both
    //    identities in the pair must be NON-privileged: a privileged role (admin/
    //    owner/...) is expected to read other users' objects, and pairing it here
    //    only produces false positives on legitimate god-mode access.
    if has_object_id && authed.len() >= 2 && !all_same_body {
        let anon_ok = anon.map(|a| a.ok).unwrap_or(false);
        'pairs: for i in 0..authed.len() {
            for j in (i + 1)..authed.len() {
                let a = authed[i];
                let b = authed[j];
                if a.ok
                    && b.ok
                    && a.body_hash != 0
                    && a.body_hash == b.body_hash
                    && a.body_len > 0
                    && !anon_ok
                    && !role_is_privileged(&a.role)
                    && !role_is_privileged(&b.role)
                {
                    out.push(Candidate {
                        confirm_role: b.role.clone(),
                        expect_hash: Some(b.body_hash),
                        expect_sensitive: false,
                        finding: finding_value(
                            "Object-level authorization broken (BOLA / IDOR)",
                            "critical",
                            "bola",
                            ep,
                            &matrix,
                            &b.role,
                            format!(
                                "Identities '{}' and '{}' received an identical response body for the object endpoint {}, indicating the object is not scoped to its owner.",
                                a.role, b.role, ep.url
                            ),
                        ),
                    });
                    break 'pairs;
                }
            }
        }
    }

    // 4) BOPLA - excessive data exposure (API3): a 2xx response body exposes a
    //    hard-sensitive field (password/token/secret/...). Reported once per
    //    endpoint, attributed to the lowest-trust identity that received it
    //    (anon > peer > privileged), which also sets the severity.
    {
        let mut exposed: Option<&Probe> = None;
        for p in probes {
            if p.ok && !p.sensitive.is_empty() {
                let better = exposed
                    .map(|e| trust_rank(p) < trust_rank(e))
                    .unwrap_or(true);
                if better {
                    exposed = Some(p);
                }
            }
        }
        if let Some(p) = exposed {
            let sev = if p.is_anon || !role_is_privileged(&p.role) {
                "high"
            } else {
                "medium"
            };
            out.push(Candidate {
                confirm_role: p.role.clone(),
                expect_hash: None,
                expect_sensitive: true,
                finding: finding_value(
                    "Excessive data exposure (sensitive fields in response)",
                    sev,
                    "excessive_data_exposure",
                    ep,
                    &matrix,
                    &p.role,
                    format!(
                        "The response to identity '{}' for {} exposes sensitive field(s): {}.",
                        p.role,
                        ep.url,
                        p.sensitive.join(", ")
                    ),
                ),
            });
        }
    }

    out
}

/// Trust rank for exposure attribution: lower = less trusted = worse exposure.
fn trust_rank(p: &Probe) -> u8 {
    if p.is_anon {
        0
    } else if !role_is_privileged(&p.role) {
        1
    } else {
        2
    }
}

/// Hard-sensitive JSON field names that should never appear in an API response
/// body. Deliberately tight (key form `"name":`) to keep false positives near zero.
fn scan_sensitive(body: &str) -> Vec<String> {
    if body.len() > 500_000 {
        return Vec::new();
    }
    let low = body.to_ascii_lowercase();
    const KEYS: &[&str] = &[
        "password",
        "passwd",
        "pwd",
        "password_hash",
        "secret",
        "client_secret",
        "api_key",
        "apikey",
        "private_key",
        "access_token",
        "refresh_token",
        "ssn",
        "social_security",
        "credit_card",
        "card_number",
        "cvv",
    ];
    let mut hits = Vec::new();
    for k in KEYS {
        if low.contains(&format!("\"{k}\":")) {
            hits.push((*k).to_string());
        }
    }
    hits
}

fn finding_value(
    name: &str,
    severity: &str,
    class: &str,
    ep: &Endpoint,
    matrix: &Value,
    role: &str,
    detail: String,
) -> Value {
    json!({
        "type": "vulnerability",
        "vuln_class": class,
        "name": name,
        "severity": severity,
        "confidence": "confirmed",
        "target": ep.url,
        "url": ep.url,
        "method": ep.method.to_uppercase(),
        "role": role,
        "matrix": matrix,
        "description": detail,
        "source": "cortex-authz",
    })
}

fn build_matrix(probes: &[Probe]) -> Value {
    Value::Array(
        probes
            .iter()
            .map(|p| {
                json!({
                    "role": p.role,
                    "anon": p.is_anon,
                    "status": p.status,
                    "ok": p.ok,
                    "body_len": p.body_len,
                })
            })
            .collect(),
    )
}

fn hash_body(body: &str) -> u64 {
    if body.is_empty() {
        return 0;
    }
    let mut h = DefaultHasher::new();
    body.hash(&mut h);
    h.finish()
}

/// A response body that looks like a login / auth-challenge page (so a 200 that
/// is really "please sign in" is not counted as authorized access).
fn looks_like_login(body: &str) -> bool {
    let b = body.to_ascii_lowercase();
    if b.len() > 200_000 {
        return false;
    }
    (b.contains("type=\"password\"") || b.contains("name=\"password\""))
        || b.contains("please log in")
        || b.contains("please sign in")
        || b.contains("sign in to continue")
        || b.contains("authentication required")
        || b.contains("login required")
}

fn path_of(url: &str) -> String {
    // Strip scheme+host, keep the path (lowercased) for pattern checks.
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let path = after_scheme
        .find('/')
        .map(|i| &after_scheme[i..])
        .unwrap_or("/");
    path.to_ascii_lowercase()
}

fn privileged_path(url: &str) -> bool {
    let p = path_of(url);
    const MARKERS: &[&str] = &[
        "/admin",
        "/administrator",
        "/internal",
        "/manage",
        "/management",
        "/backoffice",
        "/console",
        "/superuser",
        "/sudo",
        "/root",
        "/staff",
        "/_admin",
        "/system/",
    ];
    MARKERS.iter().any(|m| p.contains(m))
}

fn looks_protected(url: &str) -> bool {
    let p = path_of(url);
    const MARKERS: &[&str] = &[
        "/api/",
        "/account",
        "/user",
        "/users",
        "/me",
        "/orders",
        "/order",
        "/profile",
        "/dashboard",
        "/settings",
        "/billing",
        "/invoice",
        "/wallet",
        "/private",
    ];
    MARKERS.iter().any(|m| p.contains(m))
}

fn role_is_privileged(role: &str) -> bool {
    let r = role.to_ascii_lowercase();
    [
        "admin",
        "owner",
        "root",
        "super",
        "manager",
        "staff",
        "privileged",
    ]
    .iter()
    .any(|m| r.contains(m))
}

/// Does the URL reference an object id, either in a path segment
/// (`/invoices/3`, `/orders/{uuid}`) or in a query parameter whose name denotes
/// an object reference (`?account_id=2`, `?user_id=...`, `?id=...`)? Query-param
/// object ids are the common REST/JSON-API BOLA shape and must be covered, not
/// just path ids.
fn object_id_in_path(url: &str) -> bool {
    let p = path_of(url);
    let (path, query) = match p.split_once('?') {
        Some((a, b)) => (a, b.split('#').next().unwrap_or(b)),
        None => (p.as_str(), ""),
    };
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        if looks_like_id_value(seg) {
            return true;
        }
    }
    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if key_is_id_ref(k) && looks_like_id_value(v) {
            return true;
        }
    }
    false
}

/// A single token that looks like an object id: all-digits, a UUID, or a long
/// opaque alphanumeric handle containing a digit.
fn looks_like_id_value(seg: &str) -> bool {
    if seg.is_empty() {
        return false;
    }
    if seg.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    if is_uuid(seg) {
        return true;
    }
    seg.len() >= 12
        && seg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && seg.chars().any(|c| c.is_ascii_digit())
}

/// A query-parameter name that denotes an object reference (so a differing value
/// selects a different object): `id`, `*_id`, `*-id`, `uid`, `uuid`.
fn key_is_id_ref(k: &str) -> bool {
    let k = k.trim();
    k.eq_ignore_ascii_case("id")
        || k.eq_ignore_ascii_case("uid")
        || k.eq_ignore_ascii_case("uuid")
        || {
            let lk = k.to_ascii_lowercase();
            lk.ends_with("_id") || lk.ends_with("-id")
        }
}

fn is_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && parts[0].len() == 8
        && parts[1].len() == 4
        && parts[2].len() == 4
        && parts[3].len() == 4
        && parts[4].len() == 12
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_id_detected_in_path_and_query() {
        // Path ids (numeric / uuid).
        assert!(object_id_in_path("http://h/api/v1/invoices/3"));
        assert!(object_id_in_path(
            "http://h/api/orders/550e8400-e29b-41d4-a716-446655440000"
        ));
        // Query-param object references (the REST/JSON-API BOLA shape).
        assert!(object_id_in_path(
            "http://h/api/v1/payment-methods?account_id=2"
        ));
        assert!(object_id_in_path("http://h/api/v1/devices?account_id=2"));
        assert!(object_id_in_path("http://h/x?id=42"));
        assert!(object_id_in_path("http://h/x?user-id=42"));
    }

    #[test]
    fn non_object_urls_not_flagged() {
        // No id anywhere.
        assert!(!object_id_in_path("http://h/api/v1/plans"));
        assert!(!object_id_in_path("http://h/api/v1/account"));
        // A non-id query param, even numeric, is not an object reference.
        assert!(!object_id_in_path("http://h/search?page=2"));
        assert!(!object_id_in_path("http://h/list?limit=50"));
        // A key that merely ends in the letters "id" is not an "_id" reference.
        assert!(!object_id_in_path("http://h/x?grid=2"));
    }

    #[test]
    fn key_is_id_ref_precision() {
        assert!(key_is_id_ref("id"));
        assert!(key_is_id_ref("account_id"));
        assert!(key_is_id_ref("user-id"));
        assert!(key_is_id_ref("UUID"));
        assert!(!key_is_id_ref("grid"));
        assert!(!key_is_id_ref("page"));
        assert!(!key_is_id_ref("valid"));
    }

    fn probe_of(role: &str, ok: bool, hash: u64, len: usize) -> Probe {
        Probe {
            role: role.into(),
            is_anon: role == "anon",
            status: if ok { 200 } else { 403 },
            body_len: len,
            body_hash: hash,
            login_ish: false,
            ok,
            sensitive: Vec::new(),
        }
    }

    #[test]
    fn bola_requires_nonprivileged_peers() {
        let ep = Endpoint {
            method: "GET".into(),
            url: "http://h/api/orders/1001".into(),
        };
        let has_bola = |probes: &[Probe]| {
            analyze(&ep, probes)
                .iter()
                .any(|c| c.finding["vuln_class"].as_str() == Some("bola"))
        };
        // Two non-privileged peers get an identical object body, anon denied -> BOLA.
        assert!(has_bola(&[
            probe_of("user-a", true, 42, 100),
            probe_of("user-b", true, 42, 100),
            probe_of("anon", false, 0, 0),
        ]));
        // Admin (privileged) god-mode reading a user's object is NOT BOLA.
        assert!(!has_bola(&[
            probe_of("admin", true, 99, 100),
            probe_of("user-a", true, 99, 100),
            probe_of("anon", false, 0, 0),
        ]));
    }
}
