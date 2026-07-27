use crate::libs::cli_args::{Cli, Commands};
use clap::Parser;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

mod authz;
mod daemon;
mod dsl;
mod engine;
mod libs;
mod oast;
mod template;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Cortex is stateless: no DB, a vulnerability-detection TCP service.
    if cli.daemon {
        return daemon::run(cli.port).await;
    }

    match cli.command {
        Some(Commands::Scan(args)) => {
            let req = serde_json::json!({
                "operation": "scan",
                "response": "stream",
                "target": args.target,
            });
            send_stream(cli.port, req).await
        }
        Some(Commands::Exec(args)) => {
            let mut payload: serde_json::Value =
                serde_json::from_str(&args.json).map_err(|e| format!("Invalid JSON: {e}"))?;
            if payload.get("response").is_none() {
                payload["response"] = serde_json::json!("stream");
            }
            send_stream(cli.port, payload).await
        }
        None => {
            eprintln!(
                "No command given. Use `cortex scan <target>`, `cortex exec <json>`, or `cortex --daemon`."
            );
            std::process::exit(1);
        }
    }
}

async fn send_stream(port: u16, req: serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
    let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .map_err(|_| {
            format!(
                "Cortex daemon is not running on port {port}. Start it first with: cortex --daemon"
            )
        })?;
    let (reader, mut writer) = tokio::io::split(stream);
    let mut s = serde_json::to_string(&req)?;
    s.push('\n');
    writer.write_all(s.as_bytes()).await?;

    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        println!("{line}");
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
            let t = v["type"].as_str().unwrap_or("");
            if t == "done" || t == "error" {
                break;
            }
        }
    }
    Ok(())
}
