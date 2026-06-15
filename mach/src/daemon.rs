use crate::libs::cli_args::{Args, HttpMethod, LogLevel, OutputFormat};
use crate::libs::mach_db::MachDb;
use crate::scanner::{Scanner, StreamEvent};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{
    tcp::OwnedWriteHalf,
    TcpListener, TcpStream,
};
use tokio::sync::mpsc;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Top-level request sent over the TCP connection (newline-delimited JSON).
#[derive(Debug, Deserialize)]
struct DaemonRequest {
    operation: String,
    /// "instant" - wait for completion and return results
    /// "queue"   - ack immediately with operation_id, run in background
    /// "stream"  - stream events as they occur (used by `mach fuzz`)
    #[serde(default = "default_response_mode")]
    response: String,
    #[serde(default)]
    save: bool,
    #[serde(flatten)]
    params: Value,
}

fn default_response_mode() -> String {
    "queue".to_string()
}

#[derive(Debug, Serialize)]
struct DaemonResponse {
    operation_id: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    results: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

/// Scan-specific parameters.
#[derive(Debug, Deserialize, Clone)]
struct ScanParams {
    endpoint: String,
    wordlist: String,
    #[serde(default = "default_method")]
    method: String,
    #[serde(default = "default_tasks")]
    tasks: usize,
    /// Per-task wait between requests, in ms. Same semantic as pulse's
    /// `delay` and as mach's CLI `--interval`. cfx_node passes this from
    /// the wizard's "Delay between probes" setting.
    #[serde(default)]
    delay: u64,
    #[serde(default)]
    follow_redirects: bool,
    #[serde(default = "default_follow_redirects_depth")]
    follow_redirects_depth: u64,
    #[serde(default)]
    fresh_start: bool,
    #[serde(default = "default_fuzz_marker")]
    fuzz_marker: String,
    #[serde(default = "default_success_codes")]
    success_status_codes: Vec<u16>,
}

fn default_method() -> String { "get".to_string() }
fn default_tasks() -> usize { 4 }
fn default_follow_redirects_depth() -> u64 { 5 }
fn default_fuzz_marker() -> String { "::FUZZ::".to_string() }
fn default_success_codes() -> Vec<u16> {
    vec![200, 201, 202, 203, 204, 205, 206, 207, 208, 226,
         300, 301, 302, 303, 304, 305, 306, 307, 308]
}

/// Params for the lightweight single-URL probe operation.
#[derive(Debug, Deserialize)]
struct ProbeParams {
    operation_id: String,
    url: String,
    #[serde(default = "default_method")]
    method: String,
    #[serde(default = "default_success_codes")]
    success_codes: Vec<u16>,
    /// 0 = don't store; 1-8766 = store and delete after this many hours
    #[serde(default)]
    volatility: u32,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run(port: u16, db: MachDb) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    println!("Mach daemon listening on port {}", port);

    let db = Arc::new(db);
    let probe_client = Arc::new(
        Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::limited(10))
            .user_agent(format!("mach/{}", env!("CARGO_PKG_VERSION")))
            .build()?,
    );

    // Background task: delete expired probe_results every 5 minutes
    {
        let db_cleanup = Arc::clone(&db);
        tokio::spawn(async move {
            let interval = std::time::Duration::from_secs(300);
            loop {
                tokio::time::sleep(interval).await;
                if let Ok(n) = db_cleanup.delete_expired_probe_results().await {
                    if n > 0 {
                        println!("Cleaned up {} expired probe result(s)", n);
                    }
                }
            }
        });
    }

    loop {
        let (stream, addr) = listener.accept().await?;
        let _ = stream.set_nodelay(true);
        let db_clone = Arc::clone(&db);
        let client_clone = Arc::clone(&probe_client);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, db_clone, client_clone).await {
                eprintln!("Connection error from {}: {}", addr, e);
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

async fn handle_connection(
    stream: TcpStream,
    db: Arc<MachDb>,
    probe_client: Arc<Client>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let req = match serde_json::from_str::<DaemonRequest>(&line) {
            Err(e) => {
                write_json(&mut writer, &serde_json::json!({
                    "operation_id": Uuid::new_v4().to_string(),
                    "status": "error",
                    "message": format!("Invalid JSON: {}", e),
                }))
                .await?;
                continue;
            }
            Ok(r) => r,
        };

        // Stream mode takes over the connection for the duration of the scan
        if req.response == "stream" {
            handle_stream_scan(req, writer, Arc::clone(&db)).await?;
            return Ok(());
        }

        let response = dispatch(req, Arc::clone(&db), Arc::clone(&probe_client)).await;
        write_json(&mut writer, &response).await?;
    }

    Ok(())
}

async fn write_json<W, T>(writer: &mut W, value: &T) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    W: AsyncWriteExt + Unpin,
    T: Serialize,
{
    let mut s = serde_json::to_string(value)?;
    s.push('\n');
    writer.write_all(s.as_bytes()).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Stream mode: owned writer, forward events as JSON lines
// ---------------------------------------------------------------------------

async fn handle_stream_scan(
    req: DaemonRequest,
    mut writer: OwnedWriteHalf,
    db: Arc<MachDb>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let operation_id = Uuid::new_v4().to_string();

    let scan_params: ScanParams = match serde_json::from_value(req.params.clone()) {
        Ok(p) => p,
        Err(e) => {
            write_json(&mut writer, &serde_json::json!({
                "type": "error",
                "operation_id": operation_id,
                "message": format!("Invalid scan params: {}", e),
            }))
            .await?;
            return Ok(());
        }
    };

    if req.save {
        let params_str = serde_json::to_string(&req.params).unwrap_or_default();
        let _ = db.create_operation(&operation_id, "scan", &params_str).await;
    }

    // Set up the scan (wordlist, DB entries, etc.)
    let (scanner, total) = match prepare_scan(&scan_params, &db).await {
        Ok(v) => v,
        Err(e) => {
            write_json(&mut writer, &serde_json::json!({
                "type": "error",
                "operation_id": operation_id,
                "message": e.to_string(),
            }))
            .await?;
            return Ok(());
        }
    };

    // Send "ack" with operation_id and total entry count
    write_json(&mut writer, &StreamEvent {
        kind: "ack".to_string(),
        operation_id: Some(operation_id.clone()),
        total: Some(total),
        url: None, status: None, code: None,
        body_length: None, headers_length: None,
        found: None, not_found: None, error: None,
        log_level: None, message: None,
    })
    .await?;

    // Create event channel and run the scan
    let (tx, mut rx) = mpsc::unbounded_channel::<StreamEvent>();

    let oid = operation_id.clone();
    let save = req.save;
    let db_clone = Arc::clone(&db);

    tokio::spawn(async move {
        match scanner.run_headless_stream(tx).await {
            Ok(_) => {
                if save {
                    let _ = db_clone.update_operation_status(&oid, "completed", None).await;
                }
            }
            Err(e) => {
                if save {
                    let _ = db_clone.update_operation_status(&oid, "error", Some(&e.to_string())).await;
                }
            }
        }
    });

    // Forward all events to the TCP stream
    while let Some(event) = rx.recv().await {
        write_json(&mut writer, &event).await?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Regular (non-stream) dispatch
// ---------------------------------------------------------------------------

async fn dispatch(req: DaemonRequest, db: Arc<MachDb>, probe_client: Arc<Client>) -> DaemonResponse {
    let operation_id = Uuid::new_v4().to_string();

    match req.operation.as_str() {
        "scan" => {
            let scan_params: ScanParams = match serde_json::from_value(req.params.clone()) {
                Ok(p) => p,
                Err(e) => {
                    return DaemonResponse {
                        operation_id,
                        status: "error".to_string(),
                        results: None,
                        message: Some(format!("Invalid scan params: {}", e)),
                    };
                }
            };

            if req.save {
                let params_str = serde_json::to_string(&req.params).unwrap_or_default();
                if let Err(e) = db.create_operation(&operation_id, "scan", &params_str).await {
                    eprintln!("Failed to save operation: {}", e);
                }
            }

            match req.response.as_str() {
                "instant" => run_scan_instant(operation_id, scan_params, db, req.save).await,
                _ => {
                    let oid = operation_id.clone();
                    tokio::spawn(async move {
                        run_scan_background(oid, scan_params, db).await;
                    });
                    DaemonResponse {
                        operation_id,
                        status: "queued".to_string(),
                        results: None,
                        message: None,
                    }
                }
            }
        }
        "probe" => {
            let probe_params: ProbeParams = match serde_json::from_value(req.params.clone()) {
                Ok(p) => p,
                Err(e) => return DaemonResponse {
                    operation_id,
                    status: "error".to_string(),
                    results: None,
                    message: Some(format!("Invalid probe params: {}", e)),
                },
            };
            run_probe(probe_params, probe_client, db).await
        }
        "db_reset" => {
            match db.truncate_tables().await {
                Ok(_) => DaemonResponse {
                    operation_id,
                    status: "completed".to_string(),
                    results: None,
                    message: Some("All tables truncated.".to_string()),
                },
                Err(e) => DaemonResponse {
                    operation_id,
                    status: "error".to_string(),
                    results: None,
                    message: Some(format!("DB reset failed: {}", e)),
                },
            }
        }
        unknown => DaemonResponse {
            operation_id,
            status: "error".to_string(),
            results: None,
            message: Some(format!("Unknown operation: {}", unknown)),
        },
    }
}

async fn run_scan_instant(operation_id: String, params: ScanParams, db: Arc<MachDb>, save: bool) -> DaemonResponse {
    match run_scan(&params, &db).await {
        Ok(results) => {
            let result_json = serde_json::to_value(&results.found).unwrap_or(Value::Null);
            if save {
                let s = serde_json::to_string(&result_json).unwrap_or_default();
                let _ = db.update_operation_status(&operation_id, "completed", Some(&s)).await;
            }
            DaemonResponse { operation_id, status: "completed".to_string(), results: Some(result_json), message: None }
        }
        Err(e) => {
            if save { let _ = db.update_operation_status(&operation_id, "error", Some(&e.to_string())).await; }
            DaemonResponse { operation_id, status: "error".to_string(), results: None, message: Some(e.to_string()) }
        }
    }
}

async fn run_scan_background(operation_id: String, params: ScanParams, db: Arc<MachDb>) {
    match run_scan(&params, &db).await {
        Ok(results) => {
            let s = serde_json::to_string(&results.found).unwrap_or_default();
            let _ = db.update_operation_status(&operation_id, "completed", Some(&s)).await;
        }
        Err(e) => {
            let _ = db.update_operation_status(&operation_id, "error", Some(&e.to_string())).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Shared scan setup → returns (Scanner, total_entries)
// ---------------------------------------------------------------------------

async fn prepare_scan(
    params: &ScanParams,
    db: &Arc<MachDb>,
) -> Result<(Scanner, usize), Box<dyn std::error::Error + Send + Sync>> {
    let http_method = parse_method(&params.method);

    let mut endpoint = params.endpoint.clone();
    if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
        endpoint = format!("http://{}", endpoint);
    }
    if !endpoint.contains(&params.fuzz_marker) {
        if endpoint.ends_with('/') {
            endpoint.push_str(&params.fuzz_marker);
        } else {
            endpoint.push_str(&format!("/{}", params.fuzz_marker));
        }
    }

    let config = build_args(&params, endpoint, http_method);

    let wordlist_config = crate::libs::wordlist_config::WordlistConfig::new(&params.wordlist)
        .await
        .map_err(|e| format!("Wordlist error: {}", e))?;

    let wordlist = match db.find_wordlist(&wordlist_config.hash).await {
        Ok(w) => w,
        Err(sqlx::Error::RowNotFound) => db.create_wordlist(&wordlist_config).await.map_err(|e| format!("DB: {}", e))?,
        Err(e) => return Err(format!("DB: {}", e).into()),
    };

    let words = db.fetch_words(&wordlist.id).await.map_err(|e| format!("DB: {}", e))?;

    let scan_config_json = serde_json::to_string(&serde_json::json!({
        "urls": &config.url,
        "wordlist_hash": &wordlist_config.hash,
        "method": &config.http_method.to_string(),
    }))?;
    let scan_config_hash = crate::libs::sha::sha512_from_string(scan_config_json)
        .await
        .map_err(|e| format!("Hash: {}", e))?;

    let mut scan = match db.find_scan(&scan_config_hash).await {
        Ok(s) if params.fresh_start => db.fresh_start_scan(&s.id).await.map_err(|e| format!("DB: {}", e))?,
        Ok(s) => s,
        Err(sqlx::Error::RowNotFound) => db.create_scan(&scan_config_hash, &wordlist.id, &config.http_method.to_string()).await.map_err(|e| format!("DB: {}", e))?,
        Err(e) => return Err(format!("DB: {}", e).into()),
    };

    let logger = db.spawn_logger(&scan.id, &config.log_level.to_string()).await.map_err(|e| format!("DB: {}", e))?;

    let urls = match db.find_urls(&scan.id).await {
        Ok(u) => u,
        Err(sqlx::Error::RowNotFound) => db.create_urls(&scan.id, &config.url).await.map_err(|e| format!("DB: {}", e))?,
        Err(e) => return Err(format!("DB: {}", e).into()),
    };

    if scan.status == "created" {
        db.create_scan_entries(&urls, &scan, &words).await.map_err(|e| format!("DB: {}", e))?;
        scan.status = db.set_scan_status(&scan.id, "populated").await.map_err(|e| format!("DB: {}", e))?;
    }

    db.reset_halted_scan_entries(&scan.id).await.map_err(|e| format!("DB: {}", e))?;

    let (_, _, _, total) = db.fetch_total_scan_entries(scan.id).await.map_err(|e| format!("DB: {}", e))?;

    let scan_db = db.clone_with_config(config.clone());
    let scanner = Scanner::new(config, scan_db, logger, scan.id);

    Ok((scanner, total))
}

async fn run_scan(
    params: &ScanParams,
    db: &Arc<MachDb>,
) -> Result<crate::scanner::ScanResults, Box<dyn std::error::Error + Send + Sync>> {
    let (scanner, _) = prepare_scan(params, db).await?;
    scanner.run_headless().await.map_err(|e| format!("Scan: {}", e).into())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_method(method: &str) -> HttpMethod {
    match method.to_lowercase().as_str() {
        "post" => HttpMethod::Post,
        "put" => HttpMethod::Put,
        "delete" => HttpMethod::Delete,
        "head" => HttpMethod::Head,
        _ => HttpMethod::Get,
    }
}

fn build_args(params: &ScanParams, endpoint: String, http_method: HttpMethod) -> Args {
    Args {
        url: vec![endpoint],
        wordlist_path: params.wordlist.clone(),
        fuzz_marker: params.fuzz_marker.clone(),
        cookies: vec![],
        headers: vec![],
        basic_auth: String::new(),
        store_cookies: false,
        success_status_codes: params.success_status_codes.clone(),
        follow_redirects: params.follow_redirects,
        follow_redirects_depth: params.follow_redirects_depth,
        http_method,
        interval: params.delay,
        tasks: params.tasks,
        fresh_start: params.fresh_start,
        random_user_agent_scan: false,
        random_user_agent_request: false,
        append_slash: false,
        save_response_body: false,
        save_response_headers: true,
        user_agent: format!("mach/{}", env!("CARGO_PKG_VERSION")),
        no_exit_banner: true,
        recreate_db: false,
        launch_delay: 0,
        log_level: LogLevel::Info,
        output_format: OutputFormat::Text,
        output_path: String::new(),
        event_poll_timeout: 1000,
        enable_offset_pagination: false,
        interactive: false,
    }
}

async fn run_probe(params: ProbeParams, client: Arc<Client>, db: Arc<MachDb>) -> DaemonResponse {
    let builder = match params.method.to_lowercase().as_str() {
        "post"   => client.post(&params.url),
        "put"    => client.put(&params.url),
        "delete" => client.delete(&params.url),
        "head"   => client.head(&params.url),
        _        => client.get(&params.url),
    };

    match builder.send().await {
        Ok(resp) => {
            let code = resp.status().as_u16();
            let status = if params.success_codes.is_empty() || params.success_codes.contains(&code) {
                "found"
            } else {
                "not_found"
            };
            let headers_length = resp.headers().len() as i64;
            let body_length = resp.content_length().unwrap_or(0) as i64;

            let volatility = params.volatility.min(8766);
            if volatility > 0 {
                let _ = db.save_probe_result(
                    &params.operation_id,
                    &params.url,
                    status,
                    code as i32,
                    body_length,
                    headers_length,
                    volatility as i32,
                ).await;
            }

            DaemonResponse {
                operation_id: params.operation_id,
                status: status.to_string(),
                results: Some(serde_json::json!({
                    "code": code,
                    "body_length": body_length,
                    "headers_length": headers_length,
                })),
                message: None,
            }
        }
        Err(e) => DaemonResponse {
            operation_id: params.operation_id,
            status: "error".to_string(),
            results: None,
            message: Some(e.to_string()),
        },
    }
}
