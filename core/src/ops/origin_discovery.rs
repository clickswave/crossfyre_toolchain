//! Origin-discovery op: find a target's real origin IP behind a CDN/WAF.
//!
//! A single request/response against the voyage daemon (port 4442): voyage
//! gathers cert-transparency SANs, resolves them, drops CDN ranges, and validates
//! the survivors directly. Each confirmed/likely origin is published as a result.
use super::OpEnv;
use crate::*;

pub async fn handle(env: OpEnv) {
    let OpEnv {
        op_id,
        workflow_id,
        data,
        node_id,
        pub_clone,
        status_subj,
        result_subj,
        ..
    } = env;

    let domain = data["domain"].as_str().unwrap_or("").to_string();
    // Origin probes present as a real browser unless the operation opts out.
    let evasive = data["evasive"].as_bool().unwrap_or(true);
    let timeout_ms = data["timeout_ms"].as_i64().unwrap_or(12000).max(1000);

    println!("[op] voyage origin discovery: {domain} evasive={evasive}");

    let voyage_req = serde_json::json!({
        "operation": "origin",
        "response": "instant",
        "domain": domain,
        "evasive": evasive,
        "timeout_ms": timeout_ms,
    });

    let mut found_count = 0;
    match tokio::net::TcpStream::connect("127.0.0.1:4442").await {
        Ok(stream) => {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            let (reader, mut writer) = stream.into_split();
            let mut req_str = serde_json::to_string(&voyage_req).unwrap();
            req_str.push('\n');
            let _ = writer.write_all(req_str.as_bytes()).await;

            let mut lines = BufReader::new(reader).lines();
            if let Ok(Some(line)) = lines.next_line().await
                && let Ok(resp) = serde_json::from_str::<serde_json::Value>(&line)
            {
                match resp["status"].as_str() {
                    Some("completed") => {
                        if let Some(arr) = resp["results"].as_array() {
                            for f in arr {
                                found_count += 1;
                                let result_msg = serde_json::json!({
                                    "type": "result",
                                    "job_id": format!("{}-{}", workflow_id, op_id),
                                    "workflow_id": workflow_id,
                                    "data": {
                                        "target": f["ip"].as_str().unwrap_or(""),
                                        "type": "origin",
                                        "confidence": f["confidence"].as_str().unwrap_or(""),
                                        "via_host": f["host"].as_str().unwrap_or(""),
                                        "note": f["note"].as_str().unwrap_or(""),
                                        "domain": domain.clone(),
                                        "operation_id": op_id,
                                    }
                                });
                                let _ = pub_clone
                                    .publish(result_subj.clone(), result_msg.to_string().into())
                                    .await;
                            }
                        }
                        println!("[op] OK origin discovery: {found_count} candidate(s)");
                    }
                    Some("error") => {
                        eprintln!(
                            "[op] FAIL voyage origin error: {}",
                            resp["message"].as_str().unwrap_or("unknown")
                        );
                    }
                    _ => {}
                }
            }
        }
        Err(e) => {
            eprintln!("[op] FAIL Cannot connect to voyage daemon: {e}");
            let msg = serde_json::json!({
                "type": "completed",
                "job_id": format!("{}-{}", workflow_id, op_id),
                "workflow_id": workflow_id,
                "code": 1
            });
            let _ = pub_clone
                .publish(result_subj.clone(), msg.to_string().into())
                .await;
            return;
        }
    }

    let done_msg = serde_json::json!({
        "type": "completed",
        "job_id": format!("{}-{}", workflow_id, op_id),
        "workflow_id": workflow_id,
        "code": 0
    });
    let _ = pub_clone
        .publish(result_subj.clone(), done_msg.to_string().into())
        .await;

    mark_op_done(&op_id);
    let status_msg = serde_json::json!({
        "type": "operation_completed",
        "operation_id": op_id,
        "workflow_id": workflow_id,
        "found_count": found_count,
        "node_id": node_id,
    });
    let _ = pub_clone
        .publish(status_subj.clone(), status_msg.to_string().into())
        .await;
}
