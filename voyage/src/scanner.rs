use crate::libs::voyage_db::{VoyageDb, Work};
use crate::scanners::active_scan;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;

/// Configuration for a single enumeration run.
#[derive(Clone)]
pub struct EnumConfig {
    pub scan_id: String,
    pub domain: String,
    pub tasks: usize,
    pub interval_ms: u64,
    pub exclude_passive_sources: Vec<String>,
    pub exclude_active_techniques: Vec<String>,
    pub http_probing_ports: Vec<u16>,
    pub https_probing_ports: Vec<u16>,
    pub active_user_agent: String,
    pub passive_user_agent: String,
    pub active_random_user_agent: bool,
}

/// Events streamed from the daemon to the enum client over TCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamEvent {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subdomain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub found: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_found: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub struct Scanner {
    pub config: Arc<EnumConfig>,
    pub db: Arc<VoyageDb>,
}

impl Scanner {
    pub fn new(config: EnumConfig, db: Arc<VoyageDb>) -> Self {
        Scanner {
            config: Arc::new(config),
            db,
        }
    }

    /// Emit passive results already in DB, then run active workers and stream all events.
    pub async fn run_headless_stream(
        &self,
        tx: mpsc::UnboundedSender<StreamEvent>,
    ) -> Result<(), sqlx::Error> {
        let arc_tx = Arc::new(tx);

        // Emit passive results first (already inserted by prepare_enum)
        let passive_results = self.db.get_passive_results(&self.config.scan_id).await?;
        for r in &passive_results {
            let _ = arc_tx.send(StreamEvent {
                kind: "result".to_string(),
                subdomain: Some(r.full_subdomain.clone()),
                status: Some("found".to_string()),
                source: Some(r.source.clone()),
                operation_id: None,
                total: None,
                found: None,
                not_found: None,
                log_level: None,
                message: None,
                error: None,
            });
        }

        // Spawn active worker tasks
        let mut join_set = tokio::task::JoinSet::new();
        for _ in 0..self.config.tasks {
            join_set.spawn(task_handle(
                Arc::clone(&self.config),
                Arc::clone(&self.db),
                Arc::clone(&arc_tx),
            ));
        }

        while let Some(res) = join_set.join_next().await {
            if let Err(e) = res {
                emit_log(
                    &Some(Arc::clone(&arc_tx)),
                    "error",
                    &format!("Task panicked: {:?}", e),
                );
            }
        }

        // Get final totals and send "done"
        let (found, not_found) = self
            .db
            .get_scan_totals(&self.config.scan_id)
            .await
            .unwrap_or((0, 0));

        let _ = arc_tx.send(StreamEvent {
            kind: "done".to_string(),
            found: Some(found as usize),
            not_found: Some(not_found as usize),
            total: Some((found + not_found) as usize),
            operation_id: None,
            subdomain: None,
            status: None,
            source: None,
            log_level: None,
            message: None,
            error: None,
        });

        Ok(())
    }
}

async fn task_handle(
    config: Arc<EnumConfig>,
    db: Arc<VoyageDb>,
    event_tx: Arc<mpsc::UnboundedSender<StreamEvent>>,
) -> Result<(), sqlx::Error> {
    let resolver = match crate::libs::dns::create_resolver() {
        Ok(r) => r,
        Err(e) => {
            emit_log(
                &Some(event_tx.clone()),
                "error",
                &format!("DNS resolver error: {}", e),
            );
            return Ok(());
        }
    };

    let user_agent = if config.active_random_user_agent {
        crate::libs::rng::user_agent()
    } else {
        config.active_user_agent.clone()
    };

    let client = match reqwest::Client::builder()
        .user_agent(&user_agent)
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            emit_log(
                &Some(event_tx.clone()),
                "error",
                &format!("HTTP client build error: {}", e),
            );
            return Ok(());
        }
    };

    loop {
        if config.interval_ms > 0 {
            sleep(Duration::from_millis(config.interval_ms)).await;
        }

        let work: Work = match db.get_work_one(&config.scan_id).await {
            Ok(w) => w,
            Err(sqlx::Error::RowNotFound) => {
                // No queued work - check if any tasks are still actively scanning
                match db.is_scanning_active(&config.scan_id).await {
                    Ok(true) => {
                        sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                    _ => return Ok(()),
                }
            }
            Err(e) => {
                emit_log(
                    &Some(event_tx.clone()),
                    "error",
                    &format!("get_work_one error: {}", e),
                );
                sleep(Duration::from_millis(200)).await;
                continue;
            }
        };

        let scan_result = active_scan::execute(
            &resolver,
            &client,
            &config.exclude_active_techniques,
            &config.http_probing_ports,
            &config.https_probing_ports,
            &work.full_subdomain,
        )
        .await;

        // Log negative results (debug/info level only)
        for neg in &scan_result.negatives {
            emit_log(&Some(event_tx.clone()), &neg.level, &neg.description);
        }

        let status = if scan_result.found { "found" } else { "not_found" };
        let source = &scan_result.source;

        if let Err(e) = db.update_work_status(work.entry_id, status, source).await {
            emit_log(
                &Some(event_tx.clone()),
                "error",
                &format!("update_work_status failed: {}", e),
            );
            let _ = db.reset_entry_to_queued(work.entry_id).await;
            continue;
        }

        if scan_result.found {
            emit_log(
                &Some(event_tx.clone()),
                "info",
                &format!("FOUND: {} ({})", work.full_subdomain, source),
            );
        }

        let _ = event_tx.send(StreamEvent {
            kind: "result".to_string(),
            subdomain: Some(work.full_subdomain),
            status: Some(status.to_string()),
            source: Some(source.clone()),
            operation_id: None,
            total: None,
            found: None,
            not_found: None,
            log_level: None,
            message: None,
            error: None,
        });
    }
}

fn emit_log(
    event_tx: &Option<Arc<mpsc::UnboundedSender<StreamEvent>>>,
    level: &str,
    msg: &str,
) {
    if let Some(tx) = event_tx {
        let _ = tx.send(StreamEvent {
            kind: "log".to_string(),
            log_level: Some(level.to_string()),
            message: Some(msg.to_string()),
            operation_id: None,
            total: None,
            subdomain: None,
            status: None,
            source: None,
            found: None,
            not_found: None,
            error: None,
        });
    }
}
