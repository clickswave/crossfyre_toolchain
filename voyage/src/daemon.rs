use crate::libs::voyage_db::VoyageDb;
use crate::scanner::{EnumConfig, Scanner, StreamEvent};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{tcp::OwnedWriteHalf, TcpListener, TcpStream};
use tokio::sync::mpsc;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct DaemonRequest {
    operation: String,
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

#[derive(Debug, Deserialize, Clone)]
struct EnumParams {
    domain: String,
    #[serde(default)]
    wordlist: String,
    #[serde(default = "default_tasks")]
    tasks: usize,
    /// Per-task wait between requests in ms. Same semantic as pulse's
    /// `delay` and as voyage's CLI `--interval`. cfx_node passes this from
    /// the wizard's "Delay between probes" setting.
    #[serde(default)]
    delay: u64,
    #[serde(default)]
    fresh_start: bool,
    #[serde(default)]
    disable_passive: bool,
    #[serde(default)]
    disable_active: bool,
    #[serde(default)]
    exclude_passive_sources: Vec<String>,
    #[serde(default)]
    exclude_active_techniques: Vec<String>,
    #[serde(default = "default_http_ports")]
    http_probing_ports: Vec<u16>,
    #[serde(default = "default_https_ports")]
    https_probing_ports: Vec<u16>,
    #[serde(default = "default_active_ua")]
    active_user_agent: String,
    #[serde(default = "default_passive_ua")]
    passive_user_agent: String,
}

fn default_tasks() -> usize {
    4
}
fn default_http_ports() -> Vec<u16> {
    vec![80]
}
fn default_https_ports() -> Vec<u16> {
    vec![443]
}
fn default_active_ua() -> String {
    format!("voyage/{}", env!("CARGO_PKG_VERSION"))
}
fn default_passive_ua() -> String {
    format!("voyage/{}", env!("CARGO_PKG_VERSION"))
}

#[derive(Debug, Deserialize)]
struct ProbeParams {
    operation_id: String,
    domain: String,
    /// 0 = don't store; 1-8766 = store and delete after this many hours
    #[serde(default)]
    volatility: u32,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run(port: u16, db: VoyageDb) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    println!("Voyage daemon listening on port {}", port);

    let db = Arc::new(db);

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
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, db_clone).await {
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
    db: Arc<VoyageDb>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let req = match serde_json::from_str::<DaemonRequest>(&line) {
            Err(e) => {
                write_json(
                    &mut writer,
                    &serde_json::json!({
                        "operation_id": Uuid::new_v4().to_string(),
                        "status": "error",
                        "message": format!("Invalid JSON: {}", e),
                    }),
                )
                .await?;
                continue;
            }
            Ok(r) => r,
        };

        // Stream mode takes over the connection for the duration of the scan
        if req.response == "stream" {
            handle_stream_enum(req, writer, Arc::clone(&db)).await?;
            return Ok(());
        }

        let response = dispatch(req, Arc::clone(&db)).await;
        write_json(&mut writer, &response).await?;
    }

    Ok(())
}

async fn write_json<W, T>(
    writer: &mut W,
    value: &T,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
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
// Stream mode: forward events as JSON lines
// ---------------------------------------------------------------------------

async fn handle_stream_enum(
    req: DaemonRequest,
    mut writer: OwnedWriteHalf,
    db: Arc<VoyageDb>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let operation_id = Uuid::new_v4().to_string();

    let params: EnumParams = match serde_json::from_value(req.params.clone()) {
        Ok(p) => p,
        Err(e) => {
            write_json(
                &mut writer,
                &serde_json::json!({
                    "type": "error",
                    "operation_id": operation_id,
                    "message": format!("Invalid enum params: {}", e),
                }),
            )
            .await?;
            return Ok(());
        }
    };

    if req.save {
        let params_str = serde_json::to_string(&req.params).unwrap_or_default();
        let _ = db.create_operation(&operation_id, "enum", &params_str).await;
    }

    let (scanner, total) = match prepare_enum(&params, &db).await {
        Ok(v) => v,
        Err(e) => {
            write_json(
                &mut writer,
                &serde_json::json!({
                    "type": "error",
                    "operation_id": operation_id,
                    "message": e.to_string(),
                }),
            )
            .await?;
            return Ok(());
        }
    };

    // Send "ack" with operation_id and total entry count
    write_json(
        &mut writer,
        &StreamEvent {
            kind: "ack".to_string(),
            operation_id: Some(operation_id.clone()),
            total: Some(total),
            subdomain: None,
            status: None,
            source: None,
            found: None,
            not_found: None,
            log_level: None,
            message: None,
            error: None,
        },
    )
    .await?;

    let (tx, mut rx) = mpsc::unbounded_channel::<StreamEvent>();

    let oid = operation_id.clone();
    let save = req.save;
    let db_clone = Arc::clone(&db);

    tokio::spawn(async move {
        match scanner.run_headless_stream(tx).await {
            Ok(_) => {
                if save {
                    let _ = db_clone
                        .update_operation_status(&oid, "completed", None)
                        .await;
                }
            }
            Err(e) => {
                if save {
                    let _ = db_clone
                        .update_operation_status(&oid, "error", Some(&e.to_string()))
                        .await;
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

async fn dispatch(req: DaemonRequest, db: Arc<VoyageDb>) -> DaemonResponse {
    let operation_id = Uuid::new_v4().to_string();

    match req.operation.as_str() {
        "enum" => {
            let params: EnumParams = match serde_json::from_value(req.params.clone()) {
                Ok(p) => p,
                Err(e) => {
                    return DaemonResponse {
                        operation_id,
                        status: "error".to_string(),
                        results: None,
                        message: Some(format!("Invalid enum params: {}", e)),
                    }
                }
            };

            if req.save {
                let params_str = serde_json::to_string(&req.params).unwrap_or_default();
                let _ = db.create_operation(&operation_id, "enum", &params_str).await;
            }

            match req.response.as_str() {
                "instant" => match run_enum_instant(&params, &db).await {
                    Ok(found) => {
                        let result_json = serde_json::to_value(&found).unwrap_or(Value::Null);
                        if req.save {
                            let s = serde_json::to_string(&result_json).unwrap_or_default();
                            let _ = db
                                .update_operation_status(&operation_id, "completed", Some(&s))
                                .await;
                        }
                        DaemonResponse {
                            operation_id,
                            status: "completed".to_string(),
                            results: Some(result_json),
                            message: None,
                        }
                    }
                    Err(e) => {
                        if req.save {
                            let _ = db
                                .update_operation_status(
                                    &operation_id,
                                    "error",
                                    Some(&e.to_string()),
                                )
                                .await;
                        }
                        DaemonResponse {
                            operation_id,
                            status: "error".to_string(),
                            results: None,
                            message: Some(e.to_string()),
                        }
                    }
                },
                _ => {
                    let oid = operation_id.clone();
                    let db2 = Arc::clone(&db);
                    tokio::spawn(async move {
                        let _ = run_enum_instant(&params, &db2).await;
                        let _ = db2.update_operation_status(&oid, "completed", None).await;
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
                Err(e) => {
                    return DaemonResponse {
                        operation_id,
                        status: "error".to_string(),
                        results: None,
                        message: Some(format!("Invalid probe params: {}", e)),
                    }
                }
            };
            run_probe(probe_params, db).await
        }
        "db_reset" => match db.truncate_tables().await {
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
        },
        unknown => DaemonResponse {
            operation_id,
            status: "error".to_string(),
            results: None,
            message: Some(format!("Unknown operation: {}", unknown)),
        },
    }
}

// ---------------------------------------------------------------------------
// Shared enum setup → returns (Scanner, total_entries)
// ---------------------------------------------------------------------------

async fn prepare_enum(
    params: &EnumParams,
    db: &Arc<VoyageDb>,
) -> Result<(Scanner, usize), Box<dyn std::error::Error + Send + Sync>> {
    // Compute config hash from domain + wordlist path
    let config_str = serde_json::json!({
        "domain": &params.domain,
        "wordlist": &params.wordlist,
    })
    .to_string();
    let config_hash = crate::libs::sha::sha512(config_str)
        .await
        .map_err(|e| format!("Hash error: {}", e))?;

    let scan_id = db
        .get_or_create_scan(&config_hash, &params.domain, &params.wordlist)
        .await
        .map_err(|e| format!("DB error: {}", e))?;

    if params.fresh_start {
        db.fresh_start_scan(&scan_id)
            .await
            .map_err(|e| format!("DB error: {}", e))?;
    }

    // Passive scan - insert results with status="found"
    if !params.disable_passive {
        match crate::scanners::passive_scan::execute(
            &params.domain,
            &params.passive_user_agent,
            &params.exclude_passive_sources,
        )
        .await
        {
            Ok(results) => {
                let entries: Vec<(String, String, String, String)> = results
                    .iter()
                    .map(|(subdomain, source)| {
                        (
                            subdomain.clone(),
                            "passive".to_string(),
                            source.clone(),
                            "found".to_string(),
                        )
                    })
                    .collect();
                let _ = db.insert_entries_batch(&scan_id, &entries).await;
            }
            Err(e) => eprintln!("[WARN] Passive scan error: {}", e),
        }
    }

    // Active wordlist - insert entries with status="queued"
    if !params.disable_active && !params.wordlist.is_empty() {
        let words = crate::libs::wordlist::read_lines(&params.wordlist)
            .await
            .map_err(|e| format!("Wordlist error: {}", e))?;

        let entries: Vec<(String, String, String, String)> = words
            .iter()
            .filter(|w| !w.trim().is_empty())
            .map(|word| {
                (
                    format!("{}.{}", word.trim(), params.domain),
                    "active".to_string(),
                    String::new(),
                    "queued".to_string(),
                )
            })
            .collect();

        db.insert_entries_batch(&scan_id, &entries)
            .await
            .map_err(|e| format!("DB error: {}", e))?;
    }

    db.set_scan_status(&scan_id, "populated")
        .await
        .map_err(|e| format!("DB error: {}", e))?;
    db.reset_halted_entries(&scan_id)
        .await
        .map_err(|e| format!("DB error: {}", e))?;

    let total = db
        .get_scan_entry_total(&scan_id)
        .await
        .map_err(|e| format!("DB error: {}", e))? as usize;

    let config = EnumConfig {
        scan_id,
        domain: params.domain.clone(),
        tasks: params.tasks,
        interval_ms: params.delay,
        exclude_passive_sources: params.exclude_passive_sources.clone(),
        exclude_active_techniques: params.exclude_active_techniques.clone(),
        http_probing_ports: params.http_probing_ports.clone(),
        https_probing_ports: params.https_probing_ports.clone(),
        active_user_agent: params.active_user_agent.clone(),
        passive_user_agent: params.passive_user_agent.clone(),
        active_random_user_agent: false,
    };

    let scanner = Scanner::new(config, Arc::clone(db));
    Ok((scanner, total))
}

async fn run_enum_instant(
    params: &EnumParams,
    db: &Arc<VoyageDb>,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let (scanner, _) = prepare_enum(params, db).await?;
    let scan_id = scanner.config.scan_id.clone();
    let db2 = Arc::clone(&scanner.db);

    let (tx, mut rx) = mpsc::unbounded_channel::<StreamEvent>();

    tokio::spawn(async move {
        let _ = scanner.run_headless_stream(tx).await;
    });

    // Drain until channel closes (after "done" is sent)
    while let Some(_) = rx.recv().await {}

    db2.get_found_subdomains(&scan_id)
        .await
        .map_err(|e| format!("{}", e).into())
}

// ---------------------------------------------------------------------------
// Probe: single subdomain DNS lookup
// ---------------------------------------------------------------------------

async fn run_probe(params: ProbeParams, db: Arc<VoyageDb>) -> DaemonResponse {
    let resolver = match crate::libs::dns::create_resolver() {
        Ok(r) => r,
        Err(e) => {
            return DaemonResponse {
                operation_id: params.operation_id,
                status: "error".to_string(),
                results: None,
                message: Some(format!("DNS resolver error: {}", e)),
            }
        }
    };

    // ipv4 lookup is the fastest check for subdomain existence
    let found = resolver.ipv4_lookup(&params.domain).await.is_ok();

    let volatility = params.volatility.min(8766);
    if volatility > 0 {
        let _ = db
            .save_probe_result(
                &params.operation_id,
                &params.domain,
                found,
                "ipv4_lookup",
                volatility as i32,
            )
            .await;
    }

    DaemonResponse {
        operation_id: params.operation_id,
        status: if found { "found" } else { "not_found" }.to_string(),
        results: Some(serde_json::json!({ "found": found })),
        message: None,
    }
}
