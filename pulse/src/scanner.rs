use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Events streamed to the client during a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamEvent {
    #[serde(rename = "type")]
    pub kind: String, // "ack", "result", "log", "done"

    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,

    // Result fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>, // "open", "closed", "filtered"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,

    // Counters (sent with "done")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filtered: Option<usize>,

    // Logging
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl StreamEvent {
    pub fn ack(operation_id: &str, total: usize) -> Self {
        Self {
            kind: "ack".to_string(),
            operation_id: Some(operation_id.to_string()),
            total: Some(total),
            host: None, port: None, status: None, service: None, banner: None,
            latency_ms: None, open: None, closed: None, filtered: None,
            log_level: None, message: None,
        }
    }

    pub fn result(host: &str, port: u16, status: &str, latency_ms: u64) -> Self {
        Self {
            kind: "result".to_string(),
            operation_id: None, total: None,
            host: Some(host.to_string()),
            port: Some(port),
            status: Some(status.to_string()),
            service: None, banner: None,
            latency_ms: Some(latency_ms),
            open: None, closed: None, filtered: None,
            log_level: None, message: None,
        }
    }

    pub fn result_with_service(host: &str, port: u16, status: &str, latency_ms: u64, service: &str, banner: Option<String>) -> Self {
        let mut ev = Self::result(host, port, status, latency_ms);
        ev.service = Some(service.to_string());
        ev.banner = banner;
        ev
    }

    pub fn done(open: usize, closed: usize, filtered: usize) -> Self {
        Self {
            kind: "done".to_string(),
            operation_id: None, total: None,
            host: None, port: None, status: None, service: None, banner: None,
            latency_ms: None,
            open: Some(open), closed: Some(closed), filtered: Some(filtered),
            log_level: None, message: None,
        }
    }

    pub fn log(level: &str, message: &str) -> Self {
        Self {
            kind: "log".to_string(),
            operation_id: None, total: None,
            host: None, port: None, status: None, service: None, banner: None,
            latency_ms: None, open: None, closed: None, filtered: None,
            log_level: Some(level.to_string()),
            message: Some(message.to_string()),
        }
    }

    pub fn error(message: &str) -> Self {
        Self {
            kind: "error".to_string(),
            operation_id: None, total: None,
            host: None, port: None, status: None, service: None, banner: None,
            latency_ms: None, open: None, closed: None, filtered: None,
            log_level: None,
            message: Some(message.to_string()),
        }
    }
}

/// Scan parameters parsed from a daemon request.
#[derive(Debug, Clone, Deserialize)]
pub struct ScanParams {
    pub targets: Vec<String>,
    /// Ports can be an array of numbers [80, 443] or a string spec "top-1000", "22,80,443"
    #[serde(deserialize_with = "deserialize_ports")]
    pub ports: Vec<u16>,
    #[serde(default = "default_technique")]
    pub technique: String,
    #[serde(default = "default_tasks")]
    pub tasks: u32,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    /// Per-slot delay in milliseconds. Each concurrent slot waits this long
    /// after acquiring the semaphore before issuing its probe, so the
    /// effective rate is roughly `tasks / (delay + probe_time)`.
    #[serde(default)]
    pub delay: u64,
    #[serde(default)]
    pub service_detection: bool,
}

fn default_technique() -> String { "connect".to_string() }
fn default_tasks() -> u32 { 100 }
fn default_timeout() -> u64 { 2000 }

fn deserialize_ports<'de, D>(deserializer: D) -> Result<Vec<u16>, D::Error>
where D: serde::Deserializer<'de> {
    use serde::de;

    struct PortsVisitor;
    impl<'de> de::Visitor<'de> for PortsVisitor {
        type Value = Vec<u16>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a port array or a port spec string")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<u16>, E> {
            Ok(crate::libs::cli_args::resolve_ports(v))
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u16>, A::Error> {
            let mut ports = Vec::new();
            while let Some(val) = seq.next_element::<u16>()? {
                ports.push(val);
            }
            Ok(ports)
        }
    }

    deserializer.deserialize_any(PortsVisitor)
}

/// Resolves target strings (hostnames, IPs, CIDRs) into a list of IPs.
/// For now, supports single IPs and hostnames. CIDR expansion can be added later.
pub fn resolve_targets(targets: &[String]) -> Vec<String> {
    let mut hosts = Vec::new();
    for target in targets {
        let t = target.trim();
        if t.contains('/') {
            // Basic CIDR: e.g. 192.168.1.0/24
            if let Some(expanded) = expand_cidr(t) {
                hosts.extend(expanded);
            } else {
                hosts.push(t.to_string());
            }
        } else {
            hosts.push(t.to_string());
        }
    }
    hosts
}

fn expand_cidr(cidr: &str) -> Option<Vec<String>> {
    let (ip_str, prefix_str) = cidr.split_once('/')?;
    let prefix: u32 = prefix_str.parse().ok()?;
    if prefix > 32 { return None; }

    let octets: Vec<u32> = ip_str.split('.').filter_map(|o| o.parse().ok()).collect();
    if octets.len() != 4 { return None; }

    let ip_num = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    let mask = if prefix == 0 { 0 } else { !((1u32 << (32 - prefix)) - 1) };
    let network = ip_num & mask;
    let broadcast = network | !mask;

    // Skip network and broadcast addresses for /24 and larger
    let (start, end) = if prefix <= 30 {
        (network + 1, broadcast - 1)
    } else {
        (network, broadcast)
    };

    let mut ips = Vec::new();
    for i in start..=end {
        ips.push(format!("{}.{}.{}.{}", (i >> 24) & 0xFF, (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF));
    }
    Some(ips)
}

/// Run a TCP connect scan, streaming results to the channel.
pub async fn run_connect_scan(
    params: &ScanParams,
    tx: mpsc::UnboundedSender<StreamEvent>,
) {
    let hosts = resolve_targets(&params.targets);
    let timeout_dur = Duration::from_millis(params.timeout);
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(params.tasks as usize));

    let mut open = 0usize;
    let mut closed = 0usize;
    let mut filtered = 0usize;

    let (result_tx, mut result_rx) = mpsc::unbounded_channel::<StreamEvent>();

    // Spawn all probe tasks
    let delay = params.delay;
    let mut total_spawned = 0usize;
    for host in &hosts {
        for &port in &params.ports {
            let sem = semaphore.clone();
            let host = host.clone();
            let rtx = result_tx.clone();
            let detect_service = params.service_detection;
            tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                // Per-slot pacing - sleeps while holding the semaphore so it
                // actually throttles the rate (otherwise probes complete in
                // <1ms on local targets and the cap becomes meaningless).
                if delay > 0 {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                let ev = probe_port(&host, port, timeout_dur, detect_service).await;
                let _ = rtx.send(ev);
            });
            total_spawned += 1;
        }
    }
    drop(result_tx); // Close sender so result_rx ends when all tasks finish

    // Collect results
    let mut received = 0usize;
    while let Some(ev) = result_rx.recv().await {
        match ev.status.as_deref() {
            Some("open") => open += 1,
            Some("filtered") => filtered += 1,
            _ => closed += 1,
        }
        received += 1;

        // Only stream open and filtered ports (skip closed to reduce noise)
        if ev.status.as_deref() != Some("closed") {
            let _ = tx.send(ev);
        }

        // Periodic progress log
        if received % 500 == 0 {
            let _ = tx.send(StreamEvent::log(
                "info",
                &format!("Progress: {}/{} probes completed ({} open, {} filtered)", received, total_spawned, open, filtered),
            ));
        }
    }

    let _ = tx.send(StreamEvent::done(open, closed, filtered));
}

/// Probe a single host:port via TCP connect.
///
/// For hostnames that resolve to multiple addresses (e.g. "localhost" →
/// 127.0.0.1 *and* ::1) we try every one before declaring the port closed.
/// Most local services bind to only IPv4 OR only IPv6, so picking just the
/// first address from the resolver was making the same port look open or
/// closed depending on which family came back first - that's why DS and
/// SB scans of the same `localhost:5432` could disagree.
async fn probe_port(host: &str, port: u16, timeout_dur: Duration, detect_service: bool) -> StreamEvent {
    let addr_str = format!("{}:{}", host, port);

    // Build the list of addresses to try.
    let addrs: Vec<SocketAddr> = if let Ok(parsed) = addr_str.parse::<SocketAddr>() {
        vec![parsed]
    } else {
        match tokio::net::lookup_host(&addr_str).await {
            Ok(iter) => iter.collect(),
            Err(_) => return StreamEvent::result(host, port, "filtered", 0),
        }
    };
    if addrs.is_empty() {
        return StreamEvent::result(host, port, "filtered", 0);
    }

    let start = Instant::now();
    let mut saw_refused = false;
    for addr in &addrs {
        match timeout(timeout_dur, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let latency = start.elapsed().as_millis() as u64;
                // RST-close instead of a graceful FIN so the socket doesn't sit
                // in TIME_WAIT. A full-range scan opens tens of thousands of
                // connections; without this the local ephemeral-port pool is
                // exhausted partway through and connect() stalls (slow tail).
                let _ = stream.set_linger(Some(std::time::Duration::ZERO));
                if detect_service {
                    let service = identify_service(port);
                    let banner = grab_banner(&stream, timeout_dur).await;
                    return StreamEvent::result_with_service(host, port, "open", latency, service, banner);
                } else {
                    return StreamEvent::result(host, port, "open", latency);
                }
            }
            Ok(Err(_)) => { saw_refused = true; }    // RST -> closed (this address)
            Err(_)     => {}                          // timeout -> filtered (this address)
        }
    }

    // No address opened. Distinguish "closed" (we got RST somewhere) from
    // "filtered" (everything timed out).
    if saw_refused {
        StreamEvent::result(host, port, "closed", start.elapsed().as_millis() as u64)
    } else {
        StreamEvent::result(host, port, "filtered", timeout_dur.as_millis() as u64)
    }
}

/// Basic service identification by well-known port.
fn identify_service(port: u16) -> &'static str {
    match port {
        21 => "ftp", 22 => "ssh", 23 => "telnet", 25 => "smtp",
        53 => "dns", 80 => "http", 110 => "pop3", 111 => "rpcbind",
        135 => "msrpc", 139 => "netbios", 143 => "imap", 443 => "https",
        445 => "smb", 465 => "smtps", 587 => "submission", 993 => "imaps",
        995 => "pop3s", 1433 => "mssql", 1521 => "oracle", 3306 => "mysql",
        3389 => "rdp", 5432 => "postgresql", 5900 => "vnc", 6379 => "redis",
        6443 => "k8s-api", 8080 => "http-proxy", 8443 => "https-alt",
        9200 => "elasticsearch", 27017 => "mongodb",
        _ => "unknown",
    }
}

/// Attempt to grab a service banner (first bytes sent by the server).
async fn grab_banner(stream: &TcpStream, timeout_dur: Duration) -> Option<String> {
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 512];
    match timeout(Duration::from_millis(timeout_dur.as_millis() as u64 / 2), stream.readable()).await {
        Ok(Ok(())) => {
            match stream.try_read(&mut buf) {
                Ok(n) if n > 0 => {
                    let banner = String::from_utf8_lossy(&buf[..n])
                        .trim()
                        .chars()
                        .take(200)
                        .collect::<String>();
                    if banner.is_empty() { None } else { Some(banner) }
                }
                _ => None,
            }
        }
        _ => None,
    }
}
