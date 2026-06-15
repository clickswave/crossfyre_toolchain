use crate::libs::cli_args;
use crate::libs::mach_db::{Logger, MachDb};
use crate::tui::Tui;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub url: String,
    pub scan_status: String,
    pub request_status: String,
    pub body_length: i64,
    pub headers_length: i64,
}

#[derive(Debug, Clone)]
pub struct ScanResultTotals {
    pub found: usize,
    pub not_found: usize,
    pub error: usize,
    pub entries: usize,
}

#[derive(Debug)]
pub struct ScanResults {
    pub found: Vec<ScanResult>,
    pub not_found: Vec<ScanResult>,
    pub error: Vec<ScanResult>,
    pub totals: ScanResultTotals,
}

#[derive(Debug, Clone, FromRow)]
pub struct Log {
    pub level: String,
    pub description: String,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct LogTotals {
    pub debug: usize,
    pub info: usize,
    pub warn: usize,
    pub error: usize,
    pub entries: usize,
}

#[derive(Debug, Clone)]
pub struct Logs {
    pub logs: Vec<Log>,
    pub totals: LogTotals,
}

/// Events streamed from the daemon to the fuzz client over TCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamEvent {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_length: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers_length: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub found: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_found: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

pub struct Scanner {
    config: cli_args::Args,
    db: MachDb,
    logger: Logger,
    scan_id: i64,
}
pub struct ObservableValue {
    pub(crate) value: usize,
    on_change:
        Vec<Box<dyn Fn(usize) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>>,
}

// A reactive value that can notify subscribers when it changes;
impl ObservableValue {
    pub fn new(initial: usize) -> Self {
        Self {
            value: initial,
            on_change: Vec::new(),
        }
    }

    pub fn set(&mut self, new_value: usize) {
        if self.value != new_value {
            self.value = new_value;
            for cb in &self.on_change {
                let fut = cb(new_value);
                tokio::spawn(fut);
            }
        }
    }

    pub fn subscribe<F, Fut>(&mut self, f: F)
    where
        F: Fn(usize) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.on_change.push(Box::new(move |val| Box::pin(f(val))));
    }
}

// Type aliases for clarity
pub type Limit = ObservableValue;
pub type Offset = ObservableValue;

impl Scanner {
    pub fn new(config: cli_args::Args, db: MachDb, logger: Logger, scan_id: i64) -> Self {
        Scanner {
            config,
            db,
            logger,
            scan_id,
        }
    }

    /// Run scan headlessly (no TUI) - used by daemon mode.
    /// Blocks until all work is exhausted, then returns the final results.
    pub async fn run_headless(&self) -> Result<ScanResults, sqlx::Error> {
        let mut join_set = tokio::task::JoinSet::new();

        let arc_config = Arc::new(self.config.clone());
        let arc_db = Arc::new(self.db.clone());
        let arc_logger = Arc::new(self.logger.clone());
        let arc_scan_id = Arc::new(self.scan_id);
        let pause_notifier = Arc::new(AtomicBool::new(false));

        let arc_prober = match crate::prober::Prober::new(&self.config).await {
            Ok(prober) => Arc::new(prober),
            Err(e) => {
                eprintln!("Failed to create prober: {:?}", e);
                self.logger
                    .error(&format!("Failed to create prober: {:?}", e))
                    .await?;
                return Err(sqlx::Error::BeginFailed);
            }
        };

        for _ in 0..self.config.tasks {
            join_set.spawn(task_handle(
                Arc::clone(&arc_config),
                Arc::clone(&arc_db),
                Arc::clone(&arc_logger),
                Arc::clone(&arc_scan_id),
                Arc::clone(&arc_prober),
                Arc::clone(&pause_notifier),
                None,
            ));
        }

        while let Some(result) = join_set.join_next().await {
            if let Err(e) = result {
                eprintln!("Task failed: {:?}", e);
                self.logger.error(&format!("Task failed: {:?}", e)).await?;
            }
        }

        self.db.get_scan_results(self.scan_id, 0, 0).await
    }

    /// Run scan headlessly, streaming per-result events through `tx`.
    /// Sends a final "done" event when all work is exhausted.
    pub async fn run_headless_stream(
        &self,
        tx: mpsc::UnboundedSender<StreamEvent>,
    ) -> Result<ScanResults, sqlx::Error> {
        let mut join_set = tokio::task::JoinSet::new();

        let arc_config = Arc::new(self.config.clone());
        let arc_db = Arc::new(self.db.clone());
        let arc_logger = Arc::new(self.logger.clone());
        let arc_scan_id = Arc::new(self.scan_id);
        let pause_notifier = Arc::new(AtomicBool::new(false));
        let arc_tx = Arc::new(tx);

        let arc_prober = match crate::prober::Prober::new(&self.config).await {
            Ok(prober) => Arc::new(prober),
            Err(e) => {
                self.logger.error(&format!("Failed to create prober: {:?}", e)).await?;
                return Err(sqlx::Error::BeginFailed);
            }
        };

        for _ in 0..self.config.tasks {
            join_set.spawn(task_handle(
                Arc::clone(&arc_config),
                Arc::clone(&arc_db),
                Arc::clone(&arc_logger),
                Arc::clone(&arc_scan_id),
                Arc::clone(&arc_prober),
                Arc::clone(&pause_notifier),
                Some(Arc::clone(&arc_tx)),
            ));
        }

        while let Some(result) = join_set.join_next().await {
            if let Err(e) = result {
                self.logger.error(&format!("Task failed: {:?}", e)).await?;
            }
        }

        let results = self.db.get_scan_results(self.scan_id, 0, 0).await?;

        let _ = arc_tx.send(StreamEvent {
            kind: "done".to_string(),
            found: Some(results.totals.found),
            not_found: Some(results.totals.not_found),
            error: Some(results.totals.error),
            total: Some(results.totals.entries),
            operation_id: None, url: None, status: None, code: None,
            body_length: None, headers_length: None, log_level: None, message: None,
        });

        Ok(results)
    }

    #[allow(dead_code)]
    pub async fn spawn_tasks(&self) -> Result<(), sqlx::Error> {
        let mut join_set = tokio::task::JoinSet::new();

        let arc_config = Arc::new(self.config.clone());
        let arc_db = Arc::new(self.db.clone());
        let arc_logger = Arc::new(self.logger.clone());
        let arc_scan_id = Arc::new(self.scan_id);

        let arc_prober = match crate::prober::Prober::new(&self.config).await {
            Ok(prober) => Arc::new(prober),
            Err(e) => {
                eprintln!("Failed to create prober: {:?}", e);
                self.logger
                    .error(&format!("Failed to create prober: {:?}", e))
                    .await?;
                return Err(sqlx::Error::BeginFailed);
            }
        };

        let terminal = ratatui::init();
        let rows_limit = match self.config.enable_offset_pagination {
            true => terminal.size()?.height as usize,
            false => 0,
        };

        let scan_results_arc = Arc::new(Mutex::new(
            self.db
                .get_scan_results(self.scan_id, rows_limit, 0)
                .await?,
        ));

        let scan_results_offset = Arc::new(Mutex::new(Offset::new(0)));
        let scan_results_limit = Arc::new(Mutex::new(Limit::new(rows_limit)));


        let logs_arc = Arc::new(Mutex::new(
            self.db.get_logs(&self.scan_id, rows_limit, 0).await?,
        ));

        let logs_offset = Arc::new(Mutex::new(Offset::new(0)));
        let logs_limit = Arc::new(Mutex::new(Limit::new(rows_limit)));

        let pause_notifier = Arc::new(AtomicBool::new(false));

        // ADD SUBSCRIBERS IF PAGINATION IS ENABLED
        if self.config.enable_offset_pagination {
            // ATOMIC SUBSCRIBERS
            {
                let db = Arc::clone(&arc_db);
                let scan_id = Arc::clone(&arc_scan_id);
                let limit = Arc::clone(&scan_results_limit);
                let offset = Arc::clone(&scan_results_offset);
                let results = Arc::clone(&scan_results_arc);

                let update_results = move |_| {
                    let db = Arc::clone(&db);
                    let scan_id = Arc::clone(&scan_id);
                    let limit = Arc::clone(&limit);
                    let offset = Arc::clone(&offset);
                    let results = Arc::clone(&results);

                    async move {
                        let limit_val = limit.lock().unwrap().value;
                        let offset_val = offset.lock().unwrap().value;
                        match db.get_scan_results(*scan_id, limit_val, offset_val).await {
                            Ok(new_results) => *results.lock().unwrap() = new_results,
                            Err(e) => eprintln!("{}", e),
                        }
                    }
                };

                scan_results_offset
                    .lock()
                    .unwrap()
                    .subscribe(update_results.clone());
                scan_results_limit.lock().unwrap().subscribe(update_results);
            }
            {
                let db = Arc::clone(&arc_db);
                let scan_id = Arc::clone(&arc_scan_id);
                let limit = Arc::clone(&logs_limit);
                let offset = Arc::clone(&logs_offset);
                let logs_data = Arc::clone(&logs_arc);

                let update_logs = move |_| {
                    let db = Arc::clone(&db);
                    let scan_id = Arc::clone(&scan_id);
                    let limit = Arc::clone(&limit);
                    let offset = Arc::clone(&offset);
                    let logs_data = Arc::clone(&logs_data);

                    async move {
                        let (limit_val, offset_val) =
                            { (limit.lock().unwrap().value, offset.lock().unwrap().value) };
                        match db.get_logs(&scan_id, limit_val, offset_val).await {
                            Ok(new_logs) => *logs_data.lock().unwrap() = new_logs,
                            Err(e) => eprintln!("Error fetching logs: {:?}", e),
                        }
                    }
                };

                logs_offset.lock().unwrap().subscribe(update_logs.clone());
                logs_limit.lock().unwrap().subscribe(update_logs);
            }
        }

        let mut tui = Tui::new(
            Arc::clone(&arc_config),
            Arc::clone(&scan_results_arc),
            Arc::clone(&pause_notifier),
            Arc::clone(&scan_results_limit),
            Arc::clone(&scan_results_offset),
            Arc::clone(&logs_arc),
            Arc::clone(&logs_limit),
            Arc::clone(&logs_offset),
            self.scan_id,
            self.db.clone()
        );

        for _ in 0..self.config.tasks {
            join_set.spawn(task_handle(
                Arc::clone(&arc_config),
                Arc::clone(&arc_db),
                Arc::clone(&arc_logger),
                Arc::clone(&arc_scan_id),
                Arc::clone(&arc_prober),
                Arc::clone(&pause_notifier),
                None,
            ));
        }

        join_set.spawn(update_results_handle(
            Arc::clone(&arc_db),
            Arc::clone(&arc_scan_id),
            Arc::clone(&scan_results_arc),
            Arc::clone(&scan_results_limit),
            Arc::clone(&scan_results_offset),
        ));

        join_set.spawn(update_logs_handle(
            Arc::clone(&arc_db),
            Arc::clone(&arc_scan_id),
            Arc::clone(&logs_arc),
            Arc::clone(&logs_limit),
            Arc::clone(&logs_offset),
        ));

        if let Err(e) = tui.run(terminal).await {
            eprintln!("Failed to run TUI: {:?}", e);
            self.logger
                .error(&format!("Failed to run TUI: {:?}", e))
                .await?;
            return Err(sqlx::Error::BeginFailed);
        }

        while let Some(result) = join_set.join_next().await {
            if let Err(e) = result {
                eprintln!("Task failed: {:?}", e);
                self.logger.error(&format!("Task failed: {:?}", e)).await?;
            }
        }

        Ok(())
    }
}

#[allow(dead_code)]
async fn update_logs_handle(
    db: Arc<MachDb>,
    scan_id: Arc<i64>,
    logs: Arc<Mutex<Logs>>,
    limit: Arc<Mutex<Limit>>,
    offset: Arc<Mutex<Offset>>,
) -> Result<(), sqlx::Error> {
    loop {
        // Wait for the specified interval before updating logs
        sleep(Duration::from_secs(1)).await;
        let (limit_val, offset_val) =
            { (limit.lock().unwrap().value, offset.lock().unwrap().value) };

        let new_logs = match db.get_logs(&scan_id, limit_val, offset_val).await {
            Ok(logs) => logs,
            Err(e) => {
                eprintln!("Error fetching logs: {:?}", e);
                continue; // Retry on error
            }
        };
        let mut logs_lock = logs.lock().unwrap();
        *logs_lock = new_logs;
    }
}

#[allow(dead_code)]
async fn update_results_handle(
    db: Arc<MachDb>,
    scan_id: Arc<i64>,
    results: Arc<Mutex<ScanResults>>,
    limit: Arc<Mutex<Limit>>,
    offset: Arc<Mutex<Offset>>,
) -> Result<(), sqlx::Error> {
    loop {
        // Wait for the specified interval before updating results
        sleep(Duration::from_secs(1)).await;
        let (limit_val, offset_val) =
            { (limit.lock().unwrap().value, offset.lock().unwrap().value) };

        let new_results = match db.get_scan_results(*scan_id, limit_val, offset_val).await {
            Ok(results) => results,
            Err(e) => {
                eprintln!("Error fetching scan results: {:?}", e);
                continue; // Retry on error
            }
        };
        let mut results_lock = results.lock().unwrap();
        *results_lock = new_results;
    }
}

async fn task_handle(
    config: Arc<cli_args::Args>,
    db: Arc<MachDb>,
    logger: Arc<Logger>,
    scan_id: Arc<i64>,
    prober: Arc<crate::prober::Prober>,
    pause_notifier: Arc<AtomicBool>,
    event_tx: Option<Arc<mpsc::UnboundedSender<StreamEvent>>>,
) -> Result<(), sqlx::Error> {
    loop {
        if config.interval > 0 {
            sleep(Duration::from_millis(config.interval)).await;
        }

        if pause_notifier.load(core::sync::atomic::Ordering::Relaxed) {
            let _ = logger.debug("Scanner paused, waiting...").await;
            sleep(Duration::from_secs(1)).await;
            continue;
        }

        let work = match db.get_work_one(&scan_id).await {
            Ok(work) => work,
            Err(sqlx::Error::RowNotFound) => {
                let _ = logger.info("No work available, exiting thread").await;
                return Ok(());
            }
            Err(e) => {
                let msg = format!("Error fetching work: {:?}", e);
                let _ = logger.error(&msg).await;
                emit_log(&event_tx, "error", &msg);
                sleep(Duration::from_millis(200)).await;
                continue;
            }
        };

        let probe = prober.probe_url(&work, config.random_user_agent_request).await;
        match probe {
            Ok(result) => {
                if let Err(e) = db.update_work_status(
                    work.entry_id,
                    &result.status,
                    result.response.status.to_string().as_str(),
                    result.response.body,
                    result.response.headers,
                    result.response.headers_length,
                    result.response.body_length,
                )
                .await
                {
                    let msg = format!("Failed to update work status: {:?}", e);
                    let _ = logger.error(&msg).await;
                    emit_log(&event_tx, "error", &msg);
                    let _ = db.reset_entry_to_queued(work.entry_id).await;
                    continue;
                }

                emit_log(
                    &event_tx,
                    if result.status == "found" { "info" } else { "debug" },
                    &format!("[{}] {} {}", result.response.status, result.status.to_uppercase(), work.url),
                );

                if let Some(ref tx) = event_tx {
                    let _ = tx.send(StreamEvent {
                        kind: "result".to_string(),
                        url: Some(work.url.clone()),
                        status: Some(result.status.clone()),
                        code: Some(result.response.status.to_string()),
                        body_length: Some(result.response.body_length),
                        headers_length: Some(result.response.headers_length),
                        operation_id: None, total: None, found: None,
                        not_found: None, error: None, log_level: None, message: None,
                    });
                }
            }
            Err(e) => {
                let err_msg = e.to_string();
                let _ = logger.error(&err_msg).await;
                let (entry_status, code) = match &e {
                    crate::prober::ProbeError::UnsupportedMethod(_) => ("error", "EXCEPT"),
                    crate::prober::ProbeError::RequestFailed(_) => ("error", "0"),
                };
                emit_log(&event_tx, "error", &format!("[{}] {} {}", code, work.url, err_msg));
                if let Err(db_err) = db.update_work_status(work.entry_id, entry_status, code, None, None, 0, 0).await {
                    let msg = format!("Failed to update error status: {:?}", db_err);
                    let _ = logger.error(&msg).await;
                    emit_log(&event_tx, "error", &msg);
                    let _ = db.reset_entry_to_queued(work.entry_id).await;
                }
                if let Some(ref tx) = event_tx {
                    let _ = tx.send(StreamEvent {
                        kind: "result".to_string(),
                        url: Some(work.url.clone()),
                        status: Some("error".to_string()),
                        code: Some(code.to_string()),
                        body_length: Some(0),
                        headers_length: Some(0),
                        operation_id: None, total: None, found: None,
                        not_found: None, error: None, log_level: None, message: None,
                    });
                }
            }
        }
    }
}

fn emit_log(event_tx: &Option<Arc<mpsc::UnboundedSender<StreamEvent>>>, level: &str, msg: &str) {
    if let Some(tx) = event_tx {
        let _ = tx.send(StreamEvent {
            kind: "log".to_string(),
            log_level: Some(level.to_string()),
            message: Some(msg.to_string()),
            operation_id: None, total: None, url: None, status: None,
            code: None, body_length: None, headers_length: None,
            found: None, not_found: None, error: None,
        });
    }
}
