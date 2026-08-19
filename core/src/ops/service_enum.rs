//! Service-enum op: scout-driven service/tech identification.
//!
//! Extracted verbatim from the run_operation() dispatcher in lib.rs.
use super::{OpEnv, Relay};
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
        http,
        api_url,
        api_key,
    } = env;

    // Web/service fingerprinting via the scout daemon (port 4444).
    // Scout streams `finding` events whose `data` is the finding
    // verbatim; the node just stamps operation_id and relays them.
    let target = data["target"]
        .as_str()
        .or_else(|| data["seed"].as_str())
        .or_else(|| data["url"].as_str())
        .unwrap_or("")
        .to_string();

    let mut scout_req = serde_json::json!({
        "operation": "fingerprint",
        "response": "stream",
        "target": target,
        "timeout_ms": data["timeout_ms"].as_i64().unwrap_or(8000),
        "follow_redirects": data["follow_redirects"].as_bool().unwrap_or(true),
        "favicon": data["favicon"].as_bool().unwrap_or(true),
        "depth_tier": data["depth_tier"].as_i64().unwrap_or(2),
    });

    // Authenticated fingerprinting: resolve an attached credential
    // into request auth and hand it to scout.
    if let Some(cid) = data["credential_id"].as_str().filter(|s| !s.is_empty()) {
        let host = target_host(&target);
        match creds::resolve_auth(&http, &api_url, &api_key, cid, &host).await {
            Ok(auth) => {
                if let Some(cr) = scout_req.as_object_mut() {
                    cr.insert("auth".into(), auth);
                }
            }
            Err(e) => eprintln!("[op] service-enum credential resolve failed ({cid}): {e}"),
        }
    }

    let relay = Relay {
        pubc: &pub_clone,
        status_subj: &status_subj,
        result_subj: &result_subj,
        op_id: &op_id,
        workflow_id: &workflow_id,
        node_id: &node_id,
    };

    let mut found_count: i64 = 0;
    let conn = tokio::net::TcpStream::connect(crate::toolchain::config::engine_addr("scout")).await;
    match conn {
        Ok(stream) => {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            let (reader, mut writer) = stream.into_split();
            let mut req_str = serde_json::to_string(&scout_req).unwrap();
            req_str.push('\n');
            let _ = writer.write_all(req_str.as_bytes()).await;

            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if !workflow_id.is_empty() && is_workflow_cancelled(&workflow_id) {
                    drop(lines);
                    drop(writer);
                    return;
                }
                if line.trim().is_empty() {
                    continue;
                }
                let event = match serde_json::from_str::<serde_json::Value>(&line) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                match event["type"].as_str().unwrap_or("") {
                    "finding" => {
                        found_count += 1;
                        let mut fdata = event["data"].clone();
                        if let Some(obj) = fdata.as_object_mut() {
                            obj.insert("operation_id".to_string(), serde_json::json!(op_id));
                        }
                        let result_msg = serde_json::json!({
                            "type": "result",
                            "job_id": format!("{}-{}", workflow_id, op_id),
                            "workflow_id": workflow_id,
                            "data": fdata,
                        });
                        let _ = pub_clone
                            .publish(result_subj.clone(), result_msg.to_string().into())
                            .await;
                    }
                    "done" => break,
                    "error" => {
                        eprintln!(
                            "[op] FAIL scout error: {}",
                            event["message"].as_str().unwrap_or("unknown")
                        );
                        break;
                    }
                    _ => {}
                }
            }
        }
        Err(e) => {
            eprintln!(
                "[op] FAIL scout daemon unreachable on {} ({e}). Is `scout --daemon` running?",
                crate::toolchain::config::engine_addr("scout")
            );
            relay.publish_failed().await;
            return;
        }
    }

    relay.finish(found_count, Some((1, 1))).await;
}
