use crate::cfx_runtime;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::ffi::CString;

/// Everything needed to run a .cfx script.
pub struct JobContext {
    pub node_id: String,
    pub job_id: String,
    /// The raw .cfx script source code.
    pub script: String,
    /// (type, value) pairs injected as targets.
    pub targets: Vec<(String, String)>,
}

#[derive(Debug)]
pub enum ExecutionResult {
    Completed { code: i32 },
    Error { message: String },
}

/// Run Python with injected context, execute the script, call run() if defined.
fn run_python(ctx: &JobContext) -> PyResult<()> {
    Python::attach(|py| {
        cfx_runtime::register_modules(py)?;

        let globals = PyDict::new(py);
        globals.set_item("__name__", "__main__")?;

        let code = CString::new(ctx.script.as_str())
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid script: {}", e)))?;
        py.run(&code, Some(&globals), None)?;

        // Call run() if it exists
        if let Ok(Some(run_fn)) = globals.get_item("run") {
            run_fn.call0()?;
        }

        Ok(())
    })
}

/// Execute a .cfx script inside an embedded Python interpreter.
///
/// Results stream back through the returned receiver.  The function
/// blocks on `spawn_blocking` so the caller can `.await` it from the
/// async runtime without holding the GIL.
pub async fn execute_job(
    ctx: JobContext,
    publisher: async_nats::Client,
    result_subject: String,
) -> ExecutionResult {
    let (tx, rx) = std::sync::mpsc::channel::<cfx_runtime::cfxs::CfxMessage>();

    // ── Drain channel → NATS in a background tokio task ──────────────
    let drain = tokio::spawn(async move {
        while let Ok(msg) = rx.recv() {
            let payload = match &msg {
                cfx_runtime::cfxs::CfxMessage::Result { job_id, data } => {
                    serde_json::json!({
                        "type": "result",
                        "job_id": job_id,
                        "data": data,
                    })
                }
                cfx_runtime::cfxs::CfxMessage::Log { job_id, message } => {
                    serde_json::json!({
                        "type": "log",
                        "job_id": job_id,
                        "message": message,
                    })
                }
                cfx_runtime::cfxs::CfxMessage::Completed { job_id, code } => {
                    let p = serde_json::json!({
                        "type": "completed",
                        "job_id": job_id,
                        "code": code,
                    });
                    let _ = publisher
                        .publish(result_subject.clone(), p.to_string().into())
                        .await;
                    return;
                }
            };
            let _ = publisher
                .publish(result_subject.clone(), payload.to_string().into())
                .await;
        }
    });

    // ── Run Python in a blocking thread ──────────────────────────────
    let handle = tokio::task::spawn_blocking(move || -> ExecutionResult {
        cfx_runtime::targets::inject(ctx.targets.clone());
        cfx_runtime::cfxs::inject(ctx.node_id.clone(), ctx.job_id.clone(), tx);
        cfx_runtime::extensions::inject_defaults();
        cfx_runtime::nodes::inject(vec![(ctx.node_id.clone(), "self".to_string())]);

        let result = run_python(&ctx);

        // Cleanup statics regardless of outcome
        cfx_runtime::targets::clear();
        cfx_runtime::cfxs::clear();
        cfx_runtime::extensions::clear();
        cfx_runtime::nodes::clear();

        match result {
            Ok(()) => ExecutionResult::Completed { code: 0 },
            Err(e) => ExecutionResult::Error {
                message: format!("Script error: {}", e),
            },
        }
    });

    let exec_result = match handle.await {
        Ok(r) => r,
        Err(e) => ExecutionResult::Error {
            message: format!("Task panicked: {}", e),
        },
    };

    // The drain task will exit once the tx side is dropped (script done).
    let _ = drain.await;
    exec_result
}

/// Convenience: execute a .cfx script locally without NATS.
/// Prints results to stdout.  Used for `cfx_controller node --run <file>`.
pub async fn execute_local(script_path: &str, targets: Vec<(String, String)>) -> ExecutionResult {
    let script = match std::fs::read_to_string(script_path) {
        Ok(s) => s,
        Err(e) => {
            return ExecutionResult::Error {
                message: format!("Cannot read '{}': {}", script_path, e),
            }
        }
    };

    let (tx, rx) = std::sync::mpsc::channel::<cfx_runtime::cfxs::CfxMessage>();

    // Print messages to stdout instead of publishing to NATS.
    let printer = tokio::spawn(async move {
        while let Ok(msg) = rx.recv() {
            match msg {
                cfx_runtime::cfxs::CfxMessage::Result { job_id, data } => {
                    println!("[result] job={} data={}", job_id, data);
                }
                cfx_runtime::cfxs::CfxMessage::Log { job_id, message } => {
                    println!("[log]    job={} {}", job_id, message);
                }
                cfx_runtime::cfxs::CfxMessage::Completed { job_id, code } => {
                    println!("[done]   job={} code={}", job_id, code);
                    return;
                }
            }
        }
    });

    let ctx = JobContext {
        node_id: "local".to_string(),
        job_id: "local-test".to_string(),
        script,
        targets,
    };

    let handle = tokio::task::spawn_blocking(move || -> ExecutionResult {
        cfx_runtime::targets::inject(ctx.targets.clone());
        cfx_runtime::cfxs::inject(ctx.node_id.clone(), ctx.job_id.clone(), tx);
        cfx_runtime::extensions::inject_defaults();
        cfx_runtime::nodes::inject(vec![(ctx.node_id.clone(), "self".to_string())]);

        let result = run_python(&ctx);

        cfx_runtime::targets::clear();
        cfx_runtime::cfxs::clear();
        cfx_runtime::extensions::clear();
        cfx_runtime::nodes::clear();

        match result {
            Ok(()) => ExecutionResult::Completed { code: 0 },
            Err(e) => ExecutionResult::Error {
                message: format!("Script error: {}", e),
            },
        }
    });

    let exec_result = match handle.await {
        Ok(r) => r,
        Err(e) => ExecutionResult::Error {
            message: format!("Task panicked: {}", e),
        },
    };

    let _ = printer.await;
    exec_result
}
