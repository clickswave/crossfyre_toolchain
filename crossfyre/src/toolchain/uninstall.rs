// `crossfyre uninstall` - remove everything the toolchain put on this host:
// extension daemons + binaries, the node service, the Postgres container,
// and (with --purge) the config root including registered node configs.
//
// Also home of the legacy OrionChain cleanup used by `init` to migrate hosts
// that were set up before the orion -> crossfyre merge.

use super::config::get_toolchain_dir;
use super::sudo_user::cmd_as_invoking_user;
use super::{install, service, EXTENSIONS};
use std::path::Path;

pub fn run(purge: bool) -> Result<(), Box<dyn std::error::Error>> {
    let confirmed = dialoguer::Confirm::new()
        .with_prompt(if purge {
            "Remove all Crossfyre services, binaries, the database container AND all config/node registrations?"
        } else {
            "Remove all Crossfyre services, binaries and the database container? (config root is kept)"
        })
        .default(false)
        .interact()?;
    if !confirmed {
        println!("Aborted.");
        return Ok(());
    }

    // Extensions: stop, disable, deregister, delete binaries.
    for ext in EXTENSIONS {
        let _ = install::remove(ext);
    }

    // Node service (system scope).
    let _ = service::remove_node_service();

    // Database container.
    let _ = std::process::Command::new("docker")
        .args(["rm", "-f", "crossfyre-postgres"])
        .output();
    println!("[*] Removed database container (if it existed).");

    // The install dir (binaries are already gone; this removes the tree,
    // including the crossfyre binary itself - fine, we're already loaded).
    #[cfg(not(windows))]
    {
        let _ = std::fs::remove_dir_all("/opt/crossfyre");
        println!("[*] Removed /opt/crossfyre.");
    }

    if purge {
        let dir = get_toolchain_dir();
        let _ = std::fs::remove_dir_all(&dir);
        println!("[*] Purged config root {} (node registrations included).", dir.display());
    } else {
        println!("[*] Config root {} kept. Re-run with --purge to remove it.", get_toolchain_dir().display());
    }

    println!("Done.");
    Ok(())
}

/// Best-effort migration cleanup for hosts initialized before the
/// orion -> crossfyre merge. Stops and removes the old orion services,
/// the old install dir, config dir, and the old database container.
/// Called from `init` when leftovers are detected; every step is optional.
pub fn cleanup_legacy_orionchain() {
    let legacy_bin = Path::new("/opt/orionchain");
    let legacy_cfg = super::sudo_user::invoking_user_config_dir().join("orionchain");
    if !legacy_bin.exists() && !legacy_cfg.exists() {
        return;
    }

    println!("[migrate] Legacy OrionChain install detected - cleaning up...");

    #[cfg(target_os = "linux")]
    for tool in EXTENSIONS {
        let svc = format!("orion-{}.service", tool);
        let _ = cmd_as_invoking_user("systemctl").args(["--user", "stop", &svc]).output();
        let _ = cmd_as_invoking_user("systemctl").args(["--user", "disable", &svc]).output();
        let unit = super::sudo_user::invoking_user_home()
            .join(".config/systemd/user").join(&svc);
        if unit.exists() {
            let _ = std::fs::remove_file(&unit);
            println!("[migrate] Removed old service {}", svc);
        }
    }
    #[cfg(target_os = "linux")]
    {
        let _ = cmd_as_invoking_user("systemctl").args(["--user", "daemon-reload"]).output();
    }

    #[cfg(target_os = "macos")]
    for tool in EXTENSIONS {
        let plist = super::sudo_user::invoking_user_home()
            .join("Library/LaunchAgents")
            .join(format!("com.orionchain.{}.plist", tool));
        if plist.exists() {
            let _ = cmd_as_invoking_user("launchctl")
                .args(["unload", "-w", &plist.to_string_lossy()])
                .output();
            let _ = std::fs::remove_file(&plist);
            println!("[migrate] Removed old launchd agent for {}", tool);
        }
    }

    // Old database container. Scan state is per-host and disposable; the new
    // container is provisioned fresh by init.
    let _ = std::process::Command::new("docker")
        .args(["rm", "-f", "orion-postgres"])
        .output();

    if legacy_bin.exists() {
        match std::fs::remove_dir_all(legacy_bin) {
            Ok(_) => println!("[migrate] Removed /opt/orionchain"),
            Err(e) => eprintln!("[migrate] Could not remove /opt/orionchain: {} (remove it manually)", e),
        }
    }
    if legacy_cfg.exists() {
        match std::fs::remove_dir_all(&legacy_cfg) {
            Ok(_) => println!("[migrate] Removed {}", legacy_cfg.display()),
            Err(e) => eprintln!("[migrate] Could not remove {}: {}", legacy_cfg.display(), e),
        }
    }
    println!("[migrate] Legacy cleanup complete.");
}
