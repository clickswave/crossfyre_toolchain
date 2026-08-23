//! Per-flow MITM inspect + forward: the shared heart of the tracer. Given one client TCP flow whose
//! intended destination is known (`target_host:target_port`), terminate its TLS as that host (session
//! CA leaf), read each HTTP/1 request, reduce it to a privacy-safe [`TraceEvent`], forward it to the
//! origin through the chosen [`Egress`], stream the response back, and emit the event.
//!
//! The desktop proxy hands this an accepted CONNECT socket; the mobile netstack hands it a TCP flow
//! reassembled off the TUN fd. Same code either way.

use std::error::Error;
use std::sync::{Arc, LazyLock};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE, HOST, SERVER};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc::UnboundedSender;
use tokio_rustls::TlsConnector;

use crate::reduce::{TraceEvent, body_field_names, redact_url};
use crate::{Egress, SessionCa, mitm_acceptor};

type BoxErr = Box<dyn Error + Send + Sync>;

/// A rustls client config trusting the Mozilla webpki roots, for the UPSTREAM (origin) leg. Built
/// once. Cross-compiles to Android (pure-Rust roots), unlike a native-tls upstream.
static UPSTREAM_TLS: LazyLock<TlsConnector> = LazyLock::new(|| {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
});

/// Serve one captured client flow: MITM-terminate it as `target_host`, then inspect + forward every
/// request on it. Returns when the client closes the connection.
pub async fn serve_mitm_flow(
    client: TcpStream,
    target_host: String,
    target_port: u16,
    ca: Arc<SessionCa>,
    egress: Egress,
    tx: UnboundedSender<TraceEvent>,
) -> Result<(), BoxErr> {
    let tls = mitm_acceptor(ca).accept(client).await?;
    let host = Arc::new(target_host);
    let svc = service_fn(move |req: Request<Incoming>| {
        let egress = egress.clone();
        let tx = tx.clone();
        let host = host.clone();
        async move { handle_request(req, host, target_port, egress, tx).await }
    });
    hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(tls), svc)
        .await?;
    Ok(())
}

async fn handle_request(
    req: Request<Incoming>,
    target_host: Arc<String>,
    target_port: u16,
    egress: Egress,
    tx: UnboundedSender<TraceEvent>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    match forward(req, &target_host, target_port, egress, tx).await {
        Ok(resp) => Ok(resp),
        // A dead/unreachable origin must not kill the client connection: answer 502 like a proxy.
        Err(_) => Ok(Response::builder()
            .status(502)
            .body(Full::new(Bytes::from_static(b"upstream error")))
            .unwrap()),
    }
}

async fn forward(
    req: Request<Incoming>,
    target_host: &str,
    target_port: u16,
    egress: Egress,
    tx: UnboundedSender<TraceEvent>,
) -> Result<Response<Full<Bytes>>, BoxErr> {
    let scheme = if target_port == 443 { "https" } else { "http" };
    let method = req.method().to_string();
    let pq = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();
    let headers = req.headers().clone();
    let authed = headers.contains_key(AUTHORIZATION) || headers.contains_key(COOKIE);
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let host_hdr = headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or(target_host)
        .to_string();

    // Buffer the request body so we can read its field names AND replay it upstream.
    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await?.to_bytes();
    let body_params = body_field_names(content_type.as_deref(), &body_bytes);
    let url = redact_url(&format!("{scheme}://{host_hdr}{pq}"));

    // Rebuild the request for the origin (same method/uri/headers, buffered body).
    let mut up_req = Request::builder().method(parts.method).uri(pq.clone());
    for (k, v) in parts.headers.iter() {
        up_req = up_req.header(k, v);
    }
    let up_req = up_req.body(Full::new(body_bytes))?;

    // Dial the origin through the routing egress, TLS-wrapping the upstream for https.
    let tcp = egress.connect(target_host, target_port).await?;
    let (status, tech, resp_bytes) = if scheme == "https" {
        let server_name = rustls::pki_types::ServerName::try_from(target_host.to_string())?;
        let stream = UPSTREAM_TLS.connect(server_name, tcp).await?;
        send_upstream(stream, up_req).await?
    } else {
        send_upstream(tcp, up_req).await?
    };

    let _ = tx.send(TraceEvent {
        method,
        url,
        status: Some(status),
        tech,
        authed,
        content_type,
        body_params,
    });

    Ok(Response::builder()
        .status(status as u16)
        .body(Full::new(resp_bytes))?)
}

/// HTTP/1 client handshake over an already-connected (optionally TLS) stream: send `req`, return
/// (status, Server banner, response body bytes).
async fn send_upstream<S>(
    stream: S,
    req: Request<Full<Bytes>>,
) -> Result<(i64, Option<String>, Bytes), BoxErr>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let resp = sender.send_request(req).await?;
    let status = resp.status().as_u16() as i64;
    let tech = resp
        .headers()
        .get(SERVER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = resp.into_body().collect().await?.to_bytes();
    Ok((status, tech, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // Bring up a bare HTTP origin that echoes a fixed body, drive a TLS client THROUGH serve_mitm_flow
    // at it, and assert (a) the client gets the origin's response and (b) a correctly-reduced
    // TraceEvent is emitted. This exercises TLS termination + reduction + forward + event end to end
    // on loopback, with no device or TUN.
    #[tokio::test]
    async fn mitm_flow_reduces_and_forwards() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // 1. HTTP origin.
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = origin.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf).await.unwrap();
            let body = "hello-origin";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nServer: test-origin\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(resp.as_bytes()).await;
            let _ = s.flush().await;
        });

        // 2. The MITM flow in front of it.
        let ca = Arc::new(crate::generate_ca().unwrap());
        let ca_pem = ca.pem.clone();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<TraceEvent>();
        let mitm = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mitm_port = mitm.local_addr().unwrap().port();
        let ca2 = ca.clone();
        tokio::spawn(async move {
            let (client, _) = mitm.accept().await.unwrap();
            // Routing target is the loopback origin; the logical host ("origin.test") is carried by
            // the client's SNI + Host header and is what shows up (redacted) in the event URL.
            let _ = serve_mitm_flow(
                client,
                "127.0.0.1".into(),
                origin_port,
                ca2,
                Egress::Direct,
                tx,
            )
            .await;
        });

        // 3. A TLS client that trusts the session CA, pointed at the MITM.
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_pemfile::certs(&mut ca_pem.as_bytes()).flatten() {
            roots.add(c).unwrap();
        }
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(cfg));
        let tcp = TcpStream::connect(("127.0.0.1", mitm_port)).await.unwrap();
        let sni = rustls::pki_types::ServerName::try_from("origin.test").unwrap();
        let tls = connector.connect(sni, tcp).await.unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/login?token=secret&next=2")
            .header(HOST, "origin.test")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, "Bearer xyz")
            .body(Full::new(Bytes::from_static(
                br#"{"email":"a@b","pw":"p"}"#,
            )))
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        let got = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&got[..], b"hello-origin");

        // 4. The emitted event is correctly reduced: keys kept, values + secrets gone.
        let ev = rx.recv().await.expect("a trace event");
        assert_eq!(ev.method, "POST");
        assert_eq!(ev.url, "http://origin.test/api/login?token=&next=");
        assert_eq!(ev.status, Some(200));
        assert_eq!(ev.tech.as_deref(), Some("test-origin"));
        assert!(ev.authed);
        assert_eq!(ev.content_type.as_deref(), Some("application/json"));
        assert!(ev.body_params.contains(&"email".to_string()));
        assert!(ev.body_params.contains(&"pw".to_string()));
        // The secret VALUES never appear anywhere in the event.
        let blob = format!("{ev:?}");
        assert!(!blob.contains("secret") && !blob.contains("Bearer") && !blob.contains("a@b"));
    }
}
