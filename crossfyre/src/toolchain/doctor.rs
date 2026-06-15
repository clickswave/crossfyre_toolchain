// `crossfyre doctor` - environment checks for the things that actually break
// in the field: missing docker/unzip, dead daemons, unreachable control
// plane, leftover OrionChain installs.

use super::{config, EXTENSION_PORTS};
use std::path::Path;

fn check(label: &str, ok: bool, fix: &str) {
    if ok {
        println!("  OK   {}", label);
    } else {
        println!("  FAIL {}", label);
        if !fix.is_empty() {
            println!("       -> {}", fix);
        }
    }
}

fn has_binary(name: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else { return false };
    std::env::split_paths(&path).any(|dir| dir.join(name).is_file())
}

fn port_open(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        std::time::Duration::from_millis(300),
    ).is_ok()
}

pub async fn run(base: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("Crossfyre Doctor");
    println!("================");
    println!();

    // -- Host tooling -----------------------------------------------------
    check("docker available", has_binary("docker"), "install Docker (the toolchain database runs in a container)");
    check("unzip available", has_binary("unzip"), "install unzip (used to unpack extension downloads)");
    #[cfg(target_os = "linux")]
    check("iproute2 (`ip`) available", has_binary("ip"), "install iproute2 (needed for VPN network namespaces)");

    // -- Toolchain config ---------------------------------------------------
    let config_path = config::get_config_path();
    if config_path.exists() {
        check(
            &format!("toolchain config parses ({})", config_path.display()),
            config::load_config().is_ok(),
            "fix or delete the file; a fresh default is written on next init/db command",
        );
    } else {
        println!("  --   no toolchain config yet ({}) - created on first init", config_path.display());
    }

    // -- Daemons ------------------------------------------------------------
    for (ext, port) in EXTENSION_PORTS {
        if config::is_extension_installed(ext) {
            check(
                &format!("{} daemon listening on {}", ext, port),
                port_open(*port),
                &format!("crossfyre extension start {}", ext),
            );
        } else {
            println!("  --   {} not installed", ext);
        }
    }
    match config::load_config() {
        Ok(c) => check(
            &format!("postgres listening on {}", c.postgres.port),
            port_open(c.postgres.port),
            "crossfyre db start",
        ),
        Err(_) => {}
    }

    // -- Connectivity ---------------------------------------------------------
    let cdn = super::install::BASE_URL;
    let cdn_ok = reqwest::get(format!("{}/manifest.json", cdn)).await
        .map(|r| r.status().is_success())
        .unwrap_or(false);
    check(&format!("release CDN reachable ({})", cdn), cdn_ok, "check network/DNS; installs and updates need this");

    // Control plane, per registered node config.
    if let Ok(ids) = crate::discover_nodes(base) {
        for id in ids {
            let paths = crate::NodePaths::new(base, &id);
            let Ok(text) = std::fs::read_to_string(&paths.config) else { continue };
            let Ok(cfg) = toml::from_str::<crate::Config>(&text) else { continue };
            let reachable = reqwest::Client::new()
                .get(format!("{}/api/v1", cfg.api_url))
                .timeout(std::time::Duration::from_secs(5))
                .send().await.is_ok();
            check(
                &format!("control plane reachable for node {} ({})", &id[..id.len().min(8)], cfg.api_url),
                reachable,
                "check the api_url in this node's config and your network",
            );
        }
    } else {
        println!("  --   no nodes registered yet (run `crossfyre node init`)");
    }

    // -- Legacy OrionChain leftovers ------------------------------------------
    let legacy_opt = Path::new("/opt/orionchain").exists();
    let legacy_cfg = super::sudo_user::invoking_user_config_dir().join("orionchain").exists();
    if legacy_opt || legacy_cfg {
        println!("  WARN legacy OrionChain install detected");
        println!("       -> re-run `sudo crossfyre node init` to migrate, or remove /opt/orionchain and ~/.config/orionchain manually");
    } else {
        println!("  OK   no legacy OrionChain leftovers");
    }

    println!();
    Ok(())
}
