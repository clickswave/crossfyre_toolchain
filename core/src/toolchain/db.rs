// Toolchain Postgres container management. The extension daemons persist
// scan state to a shared Postgres instance; by default that's a local Docker
// container named `crossfyre-postgres` published on port 4440.

use super::config::{load_config, load_or_create_config, save_config, ToolchainConfig};
use std::process::Command;

const CONTAINER_NAME: &str = "crossfyre-postgres";

pub fn run(command: &crate::DbCommands) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_or_create_config()?;

    match command {
        crate::DbCommands::Up => up(&config),
        crate::DbCommands::Down => down(&config),
        crate::DbCommands::Start => start(&config),
        crate::DbCommands::Stop => stop(&config),
        crate::DbCommands::Restart => {
            stop(&config)?;
            start(&config)
        }
    }
}

/// Bring the database up for init / the dashboard's start-postgres action:
/// `start` an existing container, or `up` a fresh one when none exists.
pub fn ensure_up() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_or_create_config()?;
    if running(&config) {
        println!("Postgres container already running.");
        return Ok(());
    }
    if start(&config).is_ok() && running(&config) {
        return Ok(());
    }
    up(&config)
}

/// True if the configured Postgres port accepts TCP connections.
pub fn running(config: &ToolchainConfig) -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], config.postgres.port)),
        std::time::Duration::from_millis(300),
    ).is_ok()
}

pub fn up(config: &ToolchainConfig) -> Result<(), Box<dyn std::error::Error>> {
    // Stop and remove any existing container by saved ID first
    if let Some(ref id) = config.container.id {
        println!("Removing existing container ({})...", &id[..id.len().min(12)]);
        let _ = Command::new("docker").args(["rm", "-f", id]).output();
    } else {
        // Fallback: clean up by name in case of leftover
        let _ = Command::new("docker").args(["rm", "-f", CONTAINER_NAME]).output();
    }

    let mut docker_args = vec![
        "run".to_string(),
        "-d".to_string(),
        "--name".to_string(),
        CONTAINER_NAME.to_string(),
        "-p".to_string(),
        format!("{}:5432", config.postgres.port),
        "-e".to_string(),
        format!("POSTGRES_USER={}", config.postgres.user),
        "-e".to_string(),
        format!("POSTGRES_DB={}", config.postgres.db_name),
    ];

    if let Some(ref pwd) = config.postgres.password {
        docker_args.push("-e".to_string());
        docker_args.push(format!("POSTGRES_PASSWORD={}", pwd));
    } else {
        docker_args.push("-e".to_string());
        docker_args.push("POSTGRES_HOST_AUTH_METHOD=trust".to_string());
    }

    docker_args.push("postgres".to_string());

    let output = Command::new("docker").args(&docker_args).output()?;

    if output.status.success() {
        let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        println!("Postgres container is up. ID: {}", &container_id[..container_id.len().min(12)]);

        let mut updated = load_config()?;
        updated.container.id = Some(container_id);
        save_config(&updated)?;
    } else {
        eprintln!("Failed to bring up Postgres container.");
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    }

    Ok(())
}

fn resolve_container(config: &ToolchainConfig) -> String {
    config.container.id.clone().unwrap_or_else(|| CONTAINER_NAME.to_string())
}

fn down(config: &ToolchainConfig) -> Result<(), Box<dyn std::error::Error>> {
    let target = resolve_container(config);
    let status = Command::new("docker").args(["rm", "-f", &target]).status()?;
    if status.success() {
        println!("Postgres container removed.");
        let mut updated = load_config()?;
        updated.container.id = None;
        save_config(&updated)?;
    } else {
        eprintln!("Failed to remove Postgres container. It may not exist.");
    }
    Ok(())
}

fn start(config: &ToolchainConfig) -> Result<(), Box<dyn std::error::Error>> {
    let target = resolve_container(config);
    let status = Command::new("docker").args(["start", &target]).status()?;
    if status.success() {
        println!("Postgres container started.");
    } else {
        eprintln!("Failed to start Postgres container. Try running 'crossfyre db up' first.");
    }
    Ok(())
}

fn stop(config: &ToolchainConfig) -> Result<(), Box<dyn std::error::Error>> {
    let target = resolve_container(config);
    let status = Command::new("docker").args(["stop", &target]).status()?;
    if status.success() {
        println!("Postgres container stopped.");
    } else {
        eprintln!("Failed to stop Postgres container.");
    }
    Ok(())
}
