use crate::engine::{self, ScanParams};
use serde::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{tcp::OwnedWriteHalf, TcpListener, TcpStream};
use tokio::sync::mpsc;

#[derive(Debug, Deserialize)]
struct DaemonRequest {
    operation: String,
    #[serde(default = "default_response")]
    #[allow(dead_code)]
    response: String,
    #[serde(flatten)]
    params: Value,
}
fn default_response() -> String {
    "stream".to_string()
}

pub async fn run(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    println!("Cortex daemon listening on port {}", port);

    loop {
        let (stream, addr) = listener.accept().await?;
        let _ = stream.set_nodelay(true);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream).await {
                eprintln!("Connection error from {}: {}", addr, e);
            }
        });
    }
}

async fn handle_connection(stream: TcpStream) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        let req: DaemonRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                write_line(&mut writer, &serde_json::json!({
                    "type": "error",
                    "message": format!("Invalid JSON: {}", e),
                }))
                .await?;
                continue;
            }
        };

        match req.operation.as_str() {
            "scan" => {
                handle_scan(req.params, &mut writer).await?;
                return Ok(());
            }
            "authz" => {
                handle_authz(req.params, &mut writer).await?;
                return Ok(());
            }
            other => {
                write_line(&mut writer, &serde_json::json!({
                    "type": "error",
                    "message": format!("Unknown operation: {}", other),
                }))
                .await?;
            }
        }
    }

    Ok(())
}

async fn handle_scan(
    params: Value,
    writer: &mut OwnedWriteHalf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sp: ScanParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => {
            write_line(writer, &serde_json::json!({
                "type": "error",
                "message": format!("Invalid scan params: {}", e),
            }))
            .await?;
            return Ok(());
        }
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
    tokio::spawn(async move {
        engine::run(sp, tx).await;
    });

    while let Some(ev) = rx.recv().await {
        write_line(writer, &ev).await?;
    }
    Ok(())
}

async fn handle_authz(
    params: Value,
    writer: &mut OwnedWriteHalf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ap: crate::authz::AuthzParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => {
            write_line(writer, &serde_json::json!({
                "type": "error",
                "message": format!("Invalid authz params: {}", e),
            }))
            .await?;
            return Ok(());
        }
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
    tokio::spawn(async move {
        crate::authz::run(ap, tx).await;
    });

    while let Some(ev) = rx.recv().await {
        write_line(writer, &ev).await?;
    }
    Ok(())
}

async fn write_line(
    writer: &mut OwnedWriteHalf,
    v: &Value,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut s = serde_json::to_string(v)?;
    s.push('\n');
    writer.write_all(s.as_bytes()).await?;
    Ok(())
}
