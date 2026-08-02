//! Per-engine operation handlers, extracted from the run_operation()
//! dispatcher. Each handler owns an [`OpEnv`] for the lifetime of one
//! dispatched operation: it runs the engine, streams results/progress onto
//! NATS, and publishes the terminal `operation_completed`.
pub mod content_discovery;
pub mod network_scan;
pub mod service_enum;
pub mod subdomain_enum;
pub mod vuln_scan;
pub mod web_crawl;

/// Shared context handed to each engine handler. Carries the operation
/// identifiers, the NATS publish handle + subjects the node reports on, and
/// the control-plane HTTP client used for claims and credential resolution.
pub struct OpEnv {
    pub op_id: String,
    pub workflow_id: String,
    pub data: serde_json::Value,
    pub node_id: String,
    pub pub_clone: async_nats::Client,
    pub status_subj: String,
    pub result_subj: String,
    pub http: reqwest::Client,
    pub api_url: String,
    pub api_key: String,
}
