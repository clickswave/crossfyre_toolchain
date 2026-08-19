//! Web Tracer capture agent - Method 2 (local intercepting proxy, Burp-style).
//!
//! Instead of sniffing packets (Method 1 needs Wireshark + capture privileges), this runs an
//! in-process MITM proxy on `127.0.0.1`: the browser is pointed at it, HTTPS is terminated with a
//! per-host leaf cert minted on the fly from a session CA, and every request/response is reduced to
//! the same redacted [`TraceEvent`] shape and streamed to the control plane. The only prerequisite
//! is a browser - no external tools.
//!
//! The reduction + streaming pipeline (`redact_url` / `shape` / `Batcher` / `post_batch`) is shared
//! verbatim with Method 1; only the capture front-end differs. Forwarding to the origin uses the
//! crate's existing `reqwest` (redirects disabled so the browser still sees them; no body rewriting).

use std::collections::HashMap;
use std::convert::Infallible;
use std::error::Error;
use std::sync::{Arc, Mutex};

use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

use super::trace::{post_batch, shape, Batcher, RawCapture, TraceConfig, TraceEvent};

type BoxErr = Box<dyn Error + Send + Sync>;
type Body = BoxBody<Bytes, Infallible>;

fn full(b: Bytes) -> Body {
    Full::new(b).boxed()
}
fn empty() -> Body {
    Empty::<Bytes>::new().boxed()
}

/// Chromium flags that suppress Google/Chrome background traffic so the capture is the operator's
/// browsing, not the browser phoning home (safebrowsing, optimization hints, account sync, component
/// + spellcheck-dictionary downloads, metrics, GCM, hyperlink auditing). Mirrors the quiet profile
/// Burp's embedded browser launches with.
const CHROMIUM_QUIET_FLAGS: &[&str] = &[
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-sync",
    "--disable-domain-reliability",
    "--disable-client-side-phishing-detection",
    "--safebrowsing-disable-auto-update",
    "--disable-default-apps",
    "--disable-breakpad",
    "--metrics-recording-only",
    "--no-pings",
    "--no-service-autorun",
    "--password-store=basic",
    "--use-mock-keychain",
    "--disable-component-extensions-with-background-pages",
    "--disable-search-engine-choice-screen",
    "--disable-features=OptimizationHints,OptimizationGuideModelDownloading,Translate,MediaRouter,\
DialMediaRouteProvider,InterestFeedContentSuggestions,CalculateNativeWinOcclusion,\
AutofillServerCommunication,CertificateTransparencyComponentUpdater",
];

// ---------------------------------------------------------------------------
// Session CA + on-the-fly per-host leaf certs
// ---------------------------------------------------------------------------

/// A short-lived CA minted for this capture session. The user installs `pem` in their browser (or,
/// for the browser we launch, we pass `--ignore-certificate-errors` so it isn't even needed).
struct Ca {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
    pem: String,
}

fn generate_ca() -> Result<Ca, BoxErr> {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    params.distinguished_name.push(DnType::CommonName, "Crossfyre Web Tracer CA");
    params.distinguished_name.push(DnType::OrganizationName, "Crossfyre");
    let cert = params.self_signed(&key)?;
    let pem = cert.pem();
    Ok(Ca { cert, key, pem })
}

/// Resolves (and caches) a leaf cert per SNI hostname, signed by the session CA.
struct MitmResolver {
    ca: Arc<Ca>,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl std::fmt::Debug for MitmResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MitmResolver")
    }
}

impl MitmResolver {
    fn leaf_for(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        if let Some(k) = self.cache.lock().unwrap().get(host) {
            return Some(k.clone());
        }
        let ck = make_leaf(&self.ca, host).ok()?;
        self.cache.lock().unwrap().insert(host.to_string(), ck.clone());
        Some(ck)
    }
}

impl ResolvesServerCert for MitmResolver {
    fn resolve(&self, hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        // Prefer SNI; fall back to a wildcard-ish default so a no-SNI client still gets a cert.
        let host = hello.server_name().map(|s| s.to_string()).unwrap_or_else(|| "localhost".into());
        self.leaf_for(&host)
    }
}

fn make_leaf(ca: &Ca, host: &str) -> Result<Arc<CertifiedKey>, BoxErr> {
    use rcgen::{CertificateParams, DnType, KeyPair};
    let leaf_key = KeyPair::generate()?;
    let mut params = CertificateParams::new(vec![host.to_string()])?;
    params.distinguished_name.push(DnType::CommonName, host);
    let leaf = params.signed_by(&leaf_key, &ca.cert, &ca.key)?;

    let leaf_der: CertificateDer<'static> = leaf.der().clone();
    let ca_der: CertificateDer<'static> = ca.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key_der)?;
    Ok(Arc::new(CertifiedKey::new(vec![leaf_der, ca_der], signing_key)))
}

// ---------------------------------------------------------------------------
// proxy
// ---------------------------------------------------------------------------

/// Headers that must not be forwarded across a proxy hop.
fn is_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection" | "keep-alive" | "proxy-authenticate" | "proxy-authorization" | "te"
            | "trailer" | "transfer-encoding" | "upgrade" | "content-length" | "host"
    )
}

/// Shared bits every connection/request handler needs.
#[derive(Clone)]
struct Ctx {
    client: reqwest::Client,
    acceptor: TlsAcceptor,
    tx: mpsc::Sender<TraceEvent>,
    scope: Option<String>,
}

/// Forward one request to its origin, relay the response back, and emit a shape. `base` is empty for
/// a plain-HTTP request (the URI is already absolute) or `https://host` for a request read off a
/// MITM-terminated CONNECT tunnel (the URI is origin-form).
async fn forward(req: Request<Incoming>, base: &str, ctx: &Ctx) -> Response<Body> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let url = if base.is_empty() { uri.to_string() } else { format!("{base}{uri}") };
    let authed = req.headers().contains_key(hyper::header::AUTHORIZATION)
        || req.headers().contains_key(hyper::header::COOKIE);

    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await.map(|c| c.to_bytes()).unwrap_or_default();

    let mut rb = ctx.client.request(method.clone(), url.as_str());
    for (name, value) in parts.headers.iter() {
        if !is_hop_header(name.as_str()) {
            rb = rb.header(name.clone(), value.clone());
        }
    }
    rb = rb.body(body_bytes);

    match rb.send().await {
        Ok(resp) => {
            let status = resp.status();
            let server = resp
                .headers()
                .get(reqwest::header::SERVER)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            // Emit the shape (scope-filtered). Response status + tech are known here, so unlike the
            // packet path this is one correlated event per request.
            let raw = RawCapture {
                method: Some(method.as_str().to_string()),
                uri: Some(url.clone()),
                status: Some(status.as_u16() as i64),
                server,
                authed,
            };
            if let Some(ev) = shape(&raw, ctx.scope.as_deref()) {
                let _ = ctx.tx.send(ev).await;
            }

            let mut builder = Response::builder().status(status);
            for (name, value) in resp.headers().iter() {
                if !is_hop_header(name.as_str()) {
                    builder = builder.header(name, value);
                }
            }
            let bytes = resp.bytes().await.unwrap_or_default();
            builder.body(full(bytes)).unwrap_or_else(|_| Response::new(empty()))
        }
        Err(e) => {
            let msg = format!("crossfyre trace proxy: upstream error: {e}");
            Response::builder().status(502).body(full(Bytes::from(msg))).unwrap()
        }
    }
}

/// The service for one browser connection: CONNECT is MITM'd (TLS-terminated, then re-served), any
/// other method is a plain-HTTP proxy request.
async fn handle(req: Request<Incoming>, ctx: Ctx) -> Result<Response<Body>, Infallible> {
    if req.method() == Method::CONNECT {
        let Some(authority) = req.uri().authority().cloned() else {
            return Ok(Response::builder().status(400).body(empty()).unwrap());
        };
        let host = authority.host().to_string();
        let ctx2 = ctx.clone();
        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    let tls = match ctx2.acceptor.accept(TokioIo::new(upgraded)).await {
                        Ok(t) => t,
                        Err(_) => return, // browser rejected the cert (CA not trusted) or handshake failed
                    };
                    let base = format!("https://{host}");
                    let inner = ctx2.clone();
                    let svc = service_fn(move |r| {
                        let inner = inner.clone();
                        let base = base.clone();
                        async move { Ok::<_, Infallible>(forward(r, &base, &inner).await) }
                    });
                    let _ = http1::Builder::new().serve_connection(TokioIo::new(tls), svc).await;
                }
                Err(_) => {}
            }
        });
        // 200 lets the browser proceed to the TLS handshake we then intercept.
        Ok(Response::new(empty()))
    } else {
        Ok(forward(req, "", &ctx).await)
    }
}

/// Accept loop: one task per browser connection.
async fn serve(listener: TcpListener, ctx: Ctx) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => continue,
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| handle(req, ctx.clone()));
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), svc)
                .with_upgrades()
                .await;
        });
    }
}

/// Run a capture session using the local proxy. Mirrors `trace::run`'s batching/flush loop but the
/// events come from the proxy (via a channel) instead of tshark lines.
pub async fn run_proxy(cfg: TraceConfig) -> Result<(), BoxErr> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let ca = Arc::new(generate_ca()?);
    let resolver = Arc::new(MitmResolver { ca: ca.clone(), cache: Mutex::new(HashMap::new()) });

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()]; // force h1 on the browser side (we don't MITM h2)
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(false)
        .build()?;

    let addr = format!("127.0.0.1:{}", cfg.proxy_port);
    let listener = TcpListener::bind(&addr).await.map_err(|e| format!("cannot bind proxy on {addr}: {e}"))?;
    let bound = listener.local_addr().map(|a| a.to_string()).unwrap_or(addr.clone());

    // Write the CA so a bring-your-own browser can trust it.
    let ca_path = std::env::temp_dir().join(format!("cfx-trace-ca-{}.pem", std::process::id()));
    std::fs::write(&ca_path, ca.pem.as_bytes()).ok();

    println!("Web Tracer: local proxy on {bound} (session {})", cfg.workflow_id);
    println!("  CA cert: {} (install it to trace with your own browser)", ca_path.display());

    let (tx, mut rx) = mpsc::channel::<TraceEvent>(1024);
    let ctx = Ctx { client, acceptor, tx, scope: cfg.host_filter.clone() };
    tokio::spawn(serve(listener, ctx));

    // Launch a browser pointed at the proxy, isolated so it can't clobber the user's real profile.
    // --ignore-certificate-errors means the launched browser trusts our MITM cert without installing
    // the CA (it's an ephemeral, operator-controlled profile).
    let mut browser_child = None;
    if let Some(browser) = &cfg.browser {
        let bin = super::trace::browser_binary(browser);
        let profile = std::env::temp_dir().join(format!("cfx-trace-profile-{}", std::process::id()));
        let mut cmd = tokio::process::Command::new(&bin);
        // Bare host:port -> Chromium uses it for both HTTP and HTTPS (via CONNECT). --ignore-certificate
        // -errors makes the ephemeral profile trust our MITM cert without installing the CA.
        cmd.arg(format!("--proxy-server={bound}"))
            .arg(format!("--user-data-dir={}", profile.display()))
            .arg("--ignore-certificate-errors");
        // Chromium-family only: silence the background/telemetry traffic (safebrowsing, optimization
        // hints, account sync, component/dictionary downloads, the New Tab Page's promos/doodles, GCM,
        // metrics) so the capture is the operator's browsing, not Google phoning home - the same reason
        // Burp's embedded browser is quiet. Firefox is left to its defaults (different flags/prefs).
        if bin != "firefox" {
            for flag in CHROMIUM_QUIET_FLAGS {
                cmd.arg(flag);
            }
            // Start on a blank page, not Google's NTP (which itself fetches promos/one-google-bar/doodles).
            cmd.arg("about:blank");
        }
        cmd.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
        match cmd.spawn() {
            Ok(c) => {
                println!("  launched {bin} through the proxy (isolated profile)");
                browser_child = Some(c);
            }
            Err(e) => eprintln!("  could not launch {bin} ({e}); point your browser at http://{bound} and trust the CA above"),
        }
    } else {
        println!("  point your browser's HTTP/HTTPS proxy at {bound}, trust the CA, then browse your target");
    }
    println!("  browsing captures into the session; Ctrl-C (or close the browser) to end.");

    // Batch + flush loop.
    let post_client = reqwest::Client::new();
    let mut batcher = Batcher::new(cfg.batch_size);
    let mut total = 0usize;
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(cfg.flush_secs.max(1)));

    loop {
        tokio::select! {
            ev = rx.recv() => {
                match ev {
                    Some(ev) => {
                        if let Some(batch) = batcher.push(ev) {
                            match post_batch(&post_client, &cfg, &batch, false).await {
                                Ok(n) => { total += n; print!("\r  captured {total} endpoints"); let _ = std::io::Write::flush(&mut std::io::stdout()); }
                                Err(e) => eprintln!("\n  ingest error: {e}"),
                            }
                        }
                    }
                    None => break,
                }
            }
            _ = ticker.tick() => {
                if !batcher.is_empty() {
                    let batch = batcher.drain();
                    if let Ok(n) = post_batch(&post_client, &cfg, &batch, false).await { total += n; }
                }
            }
            _ = tokio::signal::ctrl_c() => { println!("\n  stopping…"); break; }
        }
    }

    let tail = batcher.drain();
    if let Err(e) = post_batch(&post_client, &cfg, &tail, true).await {
        eprintln!("  final flush error: {e}");
    }
    if let Some(mut b) = browser_child {
        let _ = b.start_kill();
    }
    let _ = std::fs::remove_file(&ca_path);
    println!("\nWeb Tracer: session ended, {total} endpoints captured.");
    Ok(())
}
