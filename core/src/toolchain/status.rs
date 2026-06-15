// `crossfyre status [nodes|extensions|db]` - the one place to look when
// something is off. Read-only: probes ports, pid files, and the container,
// never mutates state.

use super::config::{ext_bin_path, is_extension_installed, load_config};
use super::{service, EXTENSION_PORTS};
use std::path::Path;

fn port_open(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        std::time::Duration::from_millis(300),
    ).is_ok()
}

/// `crossfyre status` - everything at a glance.
pub fn overview(base: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("Crossfyre Status");
    println!("================");
    println!();
    nodes(base)?;
    extensions()?;
    db()?;
    Ok(())
}

/// `crossfyre node status` - registered nodes on this machine.
pub fn nodes(base: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("  {:<38} {:<10} {:<8}", "NODE", "DAEMON", "PID");
    println!("  {:<38} {:<10} {:<8}", "----", "------", "---");

    let ids = match crate::discover_nodes(base) {
        Ok(ids) => ids,
        Err(e) => {
            println!("  (no nodes registered: {})", e);
            println!();
            return Ok(());
        }
    };
    if ids.is_empty() {
        println!("  (none - run `crossfyre node init` to register this host)");
    }
    for id in ids {
        let paths = crate::NodePaths::new(base, &id);
        let (state, pid) = match std::fs::read_to_string(&paths.pid)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
        {
            Some(pid) if Path::new(&format!("/proc/{}", pid)).exists() => ("running", pid.to_string()),
            Some(_) => ("stale pid", "-".to_string()),
            None => ("stopped", "-".to_string()),
        };
        println!("  {:<38} {:<10} {:<8}", id, state, pid);
    }
    if service::node_service_exists() {
        println!();
        println!("  node service: installed (crossfyre-node.service)");
    } else {
        println!();
        println!("  node service: not installed - nodes only run while `crossfyre node up` is open");
    }
    println!();
    Ok(())
}

/// `crossfyre status extensions` - per-extension install + daemon health.
pub fn extensions() -> Result<(), Box<dyn std::error::Error>> {
    println!("  {:<12} {:<12} {:<10} {:<8} {:<8}", "EXTENSION", "INSTALLED", "DAEMON", "PORT", "LISTENING");
    println!("  {:<12} {:<12} {:<10} {:<8} {:<8}", "---------", "---------", "------", "----", "---------");

    for (ext, port) in EXTENSION_PORTS {
        let installed = is_extension_installed(ext);
        let daemon = if installed { service::daemon_status(ext) } else { "-".to_string() };
        let listening = if installed {
            if port_open(*port) { "yes" } else { "no" }
        } else { "-" };
        println!(
            "  {:<12} {:<12} {:<10} {:<8} {:<8}",
            ext,
            if installed { "yes" } else { "no" },
            daemon,
            port,
            listening,
        );
    }
    println!();
    Ok(())
}

/// `crossfyre status db` - Postgres container state.
pub fn db() -> Result<(), Box<dyn std::error::Error>> {
    match load_config() {
        Ok(config) => {
            let listening = port_open(config.postgres.port);
            println!("  postgres: port {} {}", config.postgres.port,
                if listening { "(accepting connections)" } else { "(not reachable)" });
            if let Some(ref id) = config.container.id {
                println!("  container: {}", &id[..id.len().min(12)]);
            } else {
                println!("  container: none recorded - `crossfyre db up` to create one");
            }
            // Extension binaries are useless without the db; nudge if it's down.
            if !listening && super::EXTENSIONS.iter().any(|e| ext_bin_path(e).exists()) {
                println!("  hint: extensions are installed but the database is down - `crossfyre db start`");
            }
        }
        Err(_) => {
            println!("  postgres: no toolchain config yet - created on first `crossfyre node init` or `crossfyre db up`");
        }
    }
    println!();
    Ok(())
}
