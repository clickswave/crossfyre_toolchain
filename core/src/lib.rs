#![allow(dead_code, unused_imports, unused_variables, unused_mut)]
use clap::Subcommand;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::{Arc, OnceLock};
use sysinfo::System;
use tokio::sync::Semaphore;

pub mod auth;
pub mod cfx_runtime;
pub mod executor;
pub mod toolchain;

use toolchain::sudo_user::chown_to_invoking_user;

/// Per-workflow metrics so we can log a real-time snapshot ("2 in flight,
/// 1500 done") instead of the misleading cumulative "Processed N" line that
/// makes it look like all ops ran simultaneously.
pub struct WorkflowMetrics {
    in_flight: std::sync::atomic::AtomicUsize,
    completed: std::sync::atomic::AtomicUsize,
    errored: std::sync::atomic::AtomicUsize,
}

static WORKFLOW_METRICS: OnceLock<std::sync::Mutex<std::collections::HashMap<String, Arc<WorkflowMetrics>>>> = OnceLock::new();

pub fn workflow_metrics(workflow_id: &str) -> Arc<WorkflowMetrics> {
    let map = WORKFLOW_METRICS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut m = map.lock().unwrap();
    m.entry(workflow_id.to_string())
        .or_insert_with(|| Arc::new(WorkflowMetrics {
            in_flight: 0.into(), completed: 0.into(), errored: 0.into(),
        }))
        .clone()
}

/// RAII guard that bumps `in_flight` while alive and finalises completed/
/// errored on drop. Lets us track concurrency through the actual permit
/// lifetime without manual decrement at every return path.
pub struct InFlightGuard {
    metrics: Arc<WorkflowMetrics>,
    errored: bool,
}
impl InFlightGuard {
    fn start(metrics: Arc<WorkflowMetrics>) -> Self {
        metrics.in_flight.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self { metrics, errored: false }
    }
    fn fail(&mut self) { self.errored = true; }
}
impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.metrics.in_flight.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        if self.errored {
            self.metrics.errored.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            self.metrics.completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// Workflows the operator has halted from the dashboard. Daemon spawn-tasks
/// check this set after waking from the semaphore but before doing the work,
/// so semaphore-queued probes don't fire after a halt.
static CANCELLED_WORKFLOWS: OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> = OnceLock::new();
pub fn cancelled_workflows() -> &'static std::sync::Mutex<std::collections::HashSet<String>> {
    CANCELLED_WORKFLOWS.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}
pub fn is_workflow_cancelled(id: &str) -> bool {
    cancelled_workflows().lock().map(|s| s.contains(id)).unwrap_or(false)
}
pub fn cancel_workflow(id: &str) {
    if let Ok(mut s) = cancelled_workflows().lock() { s.insert(id.to_string()); }
}
pub fn resume_workflow(id: &str) {
    if let Ok(mut s) = cancelled_workflows().lock() { s.remove(id); }
}

/// Operations this node has already COMPLETED, so a re-dispatch of the same op
/// (e.g. after pause/resume, which re-sprays still-pending ops and can overlap
/// with tasks still draining from the first dispatch) is skipped instead of
/// probing the target a second time. Only completed ops are recorded, so an op
/// that was dropped mid-flight by a pause is still free to re-run on resume.
static DONE_OPS: OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> = OnceLock::new();
fn done_ops() -> &'static std::sync::Mutex<std::collections::HashSet<String>> {
    DONE_OPS.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}
pub fn op_is_done(op_id: &str) -> bool {
    done_ops().lock().map(|s| s.contains(op_id)).unwrap_or(false)
}
pub fn mark_op_done(op_id: &str) {
    if let Ok(mut s) = done_ops().lock() { s.insert(op_id.to_string()); }
}

/// Per-workflow semaphore registry. Each workflow is sized at the user's
/// configured `tasks` value (from step 5 of the wizard) - so a DS port scan
/// with tasks=2 keeps exactly 2 probes in flight at any moment, picking up
/// the next op only after one finishes or fails. The semaphore is fair-FIFO
/// so messages drain in order.
///
/// Hard ceiling: pulse can't handle more than ~100 concurrent probes anyway,
/// so we clamp on the upper end regardless of what the user typed.
static WORKFLOW_SEMAPHORES: OnceLock<std::sync::Mutex<std::collections::HashMap<String, Arc<Semaphore>>>> = OnceLock::new();

pub fn workflow_semaphore(workflow_id: &str, tasks: usize) -> Arc<Semaphore> {
    let map = WORKFLOW_SEMAPHORES.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut m = map.lock().unwrap();
    m.entry(workflow_id.to_string())
        .or_insert_with(|| {
            let n = tasks.clamp(1, 200);
            Arc::new(Semaphore::new(n))
        })
        .clone()
}

/// Counts claim outcomes so we can log progress summaries instead of per-op spam.
static CLAIM_OK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static CLAIM_MISS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);



#[derive(Subcommand, Debug)]
pub enum DbCommands {
    /// Start and recreate the database container
    Up,
    /// Stop and remove the database container
    Down,
    /// Start the database container
    Start,
    /// Stop the database container
    Stop,
    /// Restart the database container
    Restart,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    api_key: String,
    node_id: String,
    /// Control plane API URL (set during init)
    pub api_url: String,
    /// NATS server URL (returned by authorize-node)
    #[serde(default = "default_nats_url")]
    nats_url: String,
    nats_nkey_seed: Option<String>,
    nats_user_jwt: Option<String>,
    /// Extensions installed on this node (e.g. ["mach", "voyage"])
    #[serde(default)]
    extensions: Vec<String>,
    /// Deploy-time network identity (tunnel selection + OPSEC toggles).
    /// Stored verbatim from the dashboard so we can re-read it across runs.
    #[serde(default)]
    network: Option<NetworkConfig>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct NetworkConfig {
    /// 'direct' | 'htb' | 'thm' | 'openvpn' | 'wireguard'
    #[serde(default)]
    kind: String,
    /// Local path the .ovpn / .conf was written to (set during --init).
    #[serde(default)]
    config_path: Option<String>,
    /// Original filename uploaded by the operator.
    #[serde(default)]
    config_filename: Option<String>,
    /// True if the operator marked the config as needing username/password.
    #[serde(default)]
    needs_creds: bool,
    /// OPSEC flags (best-effort hints for the daemon).
    #[serde(default)]
    kill_switch: bool,
    #[serde(default)]
    dns_over_tunnel: bool,
    #[serde(default)]
    lab_only_routing: bool,
    #[serde(default)]
    wg_endpoint: Option<String>,
    #[serde(default)]
    wg_public_key: Option<String>,
}

pub fn default_nats_url() -> String { "nats://localhost:4222".to_string() }

/// Resolve the data directory for this invocation. Order of preference:
///   1. `--data-dir <PATH>` (if provided)
///   2. `$SUDO_USER`'s home + `.config/crossfyre`  - keeps the user's data
///      visible when they `sudo crossfyre node up`
///   3. `dirs::config_dir()/crossfyre`
pub fn resolve_data_dir(cli_arg: Option<&std::path::Path>) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    if let Some(p) = cli_arg {
        return Ok(p.to_path_buf());
    }
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if !sudo_user.is_empty() && sudo_user != "root" {
            // Best effort - fall back to dirs::config_dir() if the home directory
            // can't be resolved (e.g. unusual NSS setup).
            if let Some(home) = home_for_user(&sudo_user) {
                let mut p = home;
                p.push(".config");
                p.push("crossfyre");
                return Ok(p);
            }
        }
    }
    let mut p = dirs::config_dir().ok_or("Could not resolve config directory")?;
    p.push("crossfyre");
    Ok(p)
}

#[cfg(unix)]
pub fn home_for_user(name: &str) -> Option<std::path::PathBuf> {
    use std::ffi::CString;
    let c = CString::new(name).ok()?;
    unsafe {
        let pwd = libc::getpwnam(c.as_ptr());
        if pwd.is_null() {
            return None;
        }
        let dir_ptr = (*pwd).pw_dir;
        if dir_ptr.is_null() {
            return None;
        }
        let cstr = std::ffi::CStr::from_ptr(dir_ptr);
        Some(std::path::PathBuf::from(cstr.to_string_lossy().into_owned()))
    }
}
#[cfg(not(unix))]
pub fn home_for_user(_name: &str) -> Option<std::path::PathBuf> { None }

/// When running under `sudo`, `chown` files we just wrote back to the
/// invoking user so they aren't suddenly owned by root. Best effort - log
/// and continue on failure so writes themselves don't appear to fail.
/// (Thin wrappers around the toolchain helper, kept for readability at the
/// call sites: one name for a single path, one for a tree.)
pub fn chown_to_sudo_user(path: &std::path::Path) {
    chown_to_invoking_user(path);
}

/// Recursively chown every file under `dir` back to the invoking user.
pub fn chown_tree_to_sudo_user(dir: &std::path::Path) {
    chown_to_invoking_user(dir);
}

/// Print a security-posture banner so the operator understands the privilege
/// model: crossfyre *itself* is meant to run as a regular user, but bringing
/// up an isolated network namespace + VPN tunnel needs the kernel's
/// CAP_NET_ADMIN. We solve that by accepting `sudo` invocations and
/// dropping back to $SUDO_USER for anything user-state (configs, the
/// toolchain database, extensions). Plain-root invocations get a soft
/// warning - things still work, but on-disk artifacts end up owned by root.
pub fn print_privilege_banner(needs_root: bool) {
    let euid = unsafe { libc::geteuid() };
    let sudo_user = std::env::var("SUDO_USER").ok().filter(|s| !s.is_empty() && s != "root");
    if euid == 0 && sudo_user.is_none() {
        eprintln!("[security] WARNING: launched as plain root. Re-run with `sudo crossfyre ...` from your user shell.");
    } else if euid != 0 && needs_root {
        eprintln!("Please re-run with sudo:");
        eprintln!("  sudo crossfyre node up");
        std::process::exit(1);
    }
}

/// Per-node namespace name. Multiple daemons can coexist - each gets a
/// netns derived from a stable hash of its node-id, so the same node picks
/// the same netns across restarts (and two nodes in the same home never
/// collide on a shared namespace).
pub fn netns_for(seed: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    seed.hash(&mut h);
    format!("cfx-{:x}", h.finish() & 0xffff_ffff)
}

/// On-disk locations for a single registered node. Several nodes can share
/// one crossfyre config root (`base`) - they're disambiguated by node-id:
///
///   <base>/nodes.d/<node-id>.toml       <- config (what `--init` writes)
///   <base>/nodes.d/<node-id>.pid        <- daemon PID lock
///   <base>/nodes.d/<node-id>.network/   <- VPN config / auth.txt / openvpn.log
///
/// `base` itself is the value resolved from `--data-dir` / `$SUDO_USER`.
pub struct NodePaths {
    base: std::path::PathBuf,
    node_id: String,
    pub config: std::path::PathBuf,
    pub pid: std::path::PathBuf,
    network_dir: std::path::PathBuf,
}

impl NodePaths {
    pub fn new(base: &std::path::Path, node_id: &str) -> Self {
        let nodes_dir = nodes_dir(base);
        Self {
            base: base.to_path_buf(),
            node_id: node_id.to_string(),
            config: nodes_dir.join(format!("{}.toml", node_id)),
            pid: nodes_dir.join(format!("{}.pid", node_id)),
            network_dir: nodes_dir.join(format!("{}.network", node_id)),
        }
    }
}

/// The directory that holds one `.toml` per registered node.
pub fn nodes_dir(base: &std::path::Path) -> std::path::PathBuf {
    base.join("nodes.d")
}

/// Validate the `~/.config/crossfyre` layout before booting: the config root
/// must exist and contain a `nodes.d` directory. Returns the list of
/// registered node-ids (one per `nodes.d/<id>.toml`), sorted for stable
/// ordering. Files that don't parse as a node config are skipped with a
/// warning so one corrupt node doesn't block the rest from booting.
pub fn discover_nodes(base: &std::path::Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    if !base.exists() {
        return Err(format!(
            "config root {:?} does not exist - run `crossfyre node init` first",
            base
        ).into());
    }
    let nd = nodes_dir(base);
    if !nd.is_dir() {
        return Err(format!(
            "{:?} is missing - run `crossfyre node init` to register a node",
            nd
        ).into());
    }

    let mut ids = Vec::new();
    for entry in fs::read_dir(&nd)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else { continue };
        // Validate it parses as a node config so `--boot` doesn't spawn a
        // daemon that's just going to die on a malformed file.
        match fs::read_to_string(&path).map_err(|e| e.to_string())
            .and_then(|s| toml::from_str::<Config>(&s).map_err(|e| e.to_string()))
        {
            Ok(_) => ids.push(stem.to_string()),
            Err(e) => eprintln!("[boot] WARNING: skipping {:?} - not a valid node config: {}", path, e),
        }
    }
    ids.sort();
    Ok(ids)
}

/// One-time migration for hosts initialized before the `nodes.d` layout:
/// move a legacy `<base>/config.toml` to `<base>/nodes.d/<node-id>.toml`
/// (and its `network/` dir to `<node-id>.network/`). Best-effort and silent
/// when there's nothing to migrate.
pub fn migrate_legacy_config(base: &std::path::Path) {
    let legacy = base.join("config.toml");
    if !legacy.is_file() {
        return;
    }
    let Ok(text) = fs::read_to_string(&legacy) else { return };
    let Ok(cfg) = toml::from_str::<Config>(&text) else { return };
    let paths = NodePaths::new(base, &cfg.node_id);
    if paths.config.exists() {
        return; // already migrated
    }
    if let Err(e) = fs::create_dir_all(nodes_dir(base)) {
        eprintln!("[migrate] Could not create nodes.d: {}", e);
        return;
    }
    if fs::rename(&legacy, &paths.config).is_ok() {
        println!("[migrate] Moved legacy config.toml -> {:?}", paths.config);
        let legacy_net = base.join("network");
        if legacy_net.is_dir() && !paths.network_dir.exists() {
            let _ = fs::rename(&legacy_net, &paths.network_dir);
        }
        chown_to_sudo_user(&paths.config);
        chown_tree_to_sudo_user(&nodes_dir(base));
    }
}



/// How often `up` re-scans `nodes.d` to pick up nodes registered (or
/// removed) after it started. 2s keeps a freshly `--init`'d node coming
/// online almost immediately without busy-spinning on the filesystem.
const BOOT_RESCAN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// Spawn one `crossfyre node daemon <node-id>` child pinned to `base`.
pub fn spawn_node_daemon(
    exe: &std::path::Path,
    base: &std::path::Path,
    id: &str,
    force: bool,
) -> Option<std::process::Child> {
    // `exe` is the `node` worker binary; its daemon subcommand is top-level.
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("daemon").arg(id);
    if force {
        cmd.arg("--force");
    }
    // Pin children to the same config root so a custom --data-dir propagates
    // (resolve_data_dir would otherwise re-derive it).
    cmd.arg("--data-dir").arg(base);
    match cmd.spawn() {
        Ok(child) => {
            println!("[boot] Started node {} (pid {})", id, child.id());
            Some(child)
        }
        Err(e) => {
            eprintln!("[boot] FAIL Could not start node {}: {}", id, e);
            None
        }
    }
}

/// Validate the crossfyre config layout, then keep every registered node
/// online. `up` re-scans `nodes.d` every couple of seconds, so a node
/// registered in another terminal (`crossfyre node init`) is picked up
/// and started without restarting the supervisor - and a node whose `.toml`
/// is removed is stopped. A SIGINT/SIGTERM to the supervisor is forwarded to
/// every child so the whole fleet tears down (tunnels, netns) together.
pub async fn run_boot(force: bool, base: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("Booting Crossfyre nodes from {:?}...", base);

    // Pull a pre-nodes.d single-node install into the new layout if present.
    migrate_legacy_config(base);

    let node_ids = discover_nodes(base)?;
    if node_ids.is_empty() {
        eprintln!(
            "No nodes registered under {:?}.\nRegister one with: crossfyre node init",
            nodes_dir(base)
        );
        std::process::exit(1);
    }

    println!("Found {} node(s): {}", node_ids.len(), node_ids.join(", "));

    let exe = std::env::current_exe()?;
    // node-id -> running daemon child.
    let mut children: std::collections::HashMap<String, std::process::Child> =
        std::collections::HashMap::new();
    // Nodes whose daemon exited on its own (crashed / evicted / duplicate
    // already running). We hold these back from an immediate respawn so a
    // node that fails to start doesn't hot-loop. The hold is cleared once the
    // node's `.toml` disappears, so removing+re-adding it (or restarting boot)
    // gives it a fresh attempt.
    let mut dead: std::collections::HashSet<String> = std::collections::HashSet::new();

    for id in &node_ids {
        if let Some(child) = spawn_node_daemon(&exe, base, id, force) {
            children.insert(id.clone(), child);
        }
    }

    if children.is_empty() {
        return Err("no node daemons could be started".into());
    }

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM handler");
    let mut rescan = tokio::time::interval(BOOT_RESCAN_INTERVAL);
    rescan.tick().await; // consume the immediate first tick

    println!(
        "[boot] Supervising {} daemon(s); watching {:?} for changes. Press Ctrl+C to stop all.",
        children.len(),
        nodes_dir(base)
    );

    // Supervise loop: reconcile running children against nodes.d on every
    // tick until a shutdown signal arrives.
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => { println!("\n[boot] Ctrl+C received - stopping all nodes..."); break; }
            _ = sigterm.recv() => { println!("\n[boot] SIGTERM received - stopping all nodes..."); break; }
            _ = rescan.tick() => {
                // 1. Reap children that exited on their own; park them in
                //    `dead` so we don't respawn a flapping node every tick.
                let exited: Vec<String> = children.iter_mut()
                    .filter_map(|(id, child)| match child.try_wait() {
                        Ok(Some(status)) => {
                            println!("[boot] Node {} exited ({}). Holding until its config changes.", id, status);
                            Some(id.clone())
                        }
                        _ => None,
                    })
                    .collect();
                for id in exited {
                    children.remove(&id);
                    dead.insert(id);
                }

                // 2. Re-scan nodes.d. A read error (e.g. nodes.d briefly gone)
                //    is transient - skip this tick rather than tearing down.
                let current = match discover_nodes(base) {
                    Ok(ids) => ids,
                    Err(e) => { eprintln!("[boot] re-scan skipped: {}", e); continue; }
                };
                let current_set: std::collections::HashSet<&String> = current.iter().collect();

                // 3. Start nodes that appeared and aren't already running/held.
                for id in &current {
                    if !children.contains_key(id) && !dead.contains(id) {
                        println!("[boot] New node detected: {}", id);
                        if let Some(child) = spawn_node_daemon(&exe, base, id, force) {
                            children.insert(id.clone(), child);
                        }
                    }
                }

                // 4. Stop nodes whose `.toml` was removed, and clear any hold
                //    so a later re-add gets a fresh start.
                let removed: Vec<String> = children.keys()
                    .filter(|id| !current_set.contains(*id))
                    .cloned()
                    .collect();
                for id in removed {
                    if let Some(mut child) = children.remove(&id) {
                        println!("[boot] Node {} de-registered (config removed) - stopping (pid {}).", id, child.id());
                        #[cfg(unix)]
                        unsafe { libc::kill(child.id() as i32, libc::SIGTERM); }
                        // Reap without blocking the loop; the kernel will
                        // deliver SIGTERM and the daemon tears its tunnel down.
                        let _ = child.try_wait();
                    }
                }
                dead.retain(|id| current_set.contains(id));
            }
        }
    }

    // Shutdown: forward SIGTERM to every child so their tunnel/netns teardown
    // (Drop guards) runs, give the fleet a moment, then hard-reap.
    for (id, child) in &children {
        #[cfg(unix)]
        unsafe { libc::kill(child.id() as i32, libc::SIGTERM); }
        println!("[boot] Sent SIGTERM to node {} (pid {})", id, child.id());
    }
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    for (id, mut child) in children {
        let _ = child.kill();
        let _ = child.wait();
        println!("[boot] Node {} stopped.", id);
    }

    Ok(())
}

/// Prompt the operator to paste their node API key (created in the dashboard).
/// With --no-prompt we refuse to block on stdin and require --node-key instead.
pub fn prompt_node_key(no_prompt: bool) -> Result<String, Box<dyn std::error::Error>> {
    if no_prompt {
        return Err("no node key provided: pass --node-key <KEY> (--no-prompt is set)".into());
    }
    use std::io::Write;
    println!("\n  Create a node in the dashboard (Nodes -> create a node) to get its API key.");
    print!("  Paste the node API key: ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let key = line.trim().to_string();
    if key.is_empty() {
        return Err("no node key entered".into());
    }
    Ok(key)
}

/// Marker error: the control plane doesn't recognise this node's API key
/// (deleted in the dashboard, or the key was revoked). The daemon treats this
/// as terminal - it stops instead of retrying a key that will never work.
#[derive(Debug)]
pub struct NodeDeleted;
impl std::fmt::Display for NodeDeleted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "node not found on the server (deleted or key revoked)")
    }
}
impl std::error::Error for NodeDeleted {}

/// Delete a node's on-disk registration: config + pid lock + network dir.
pub fn remove_node_files(base: &std::path::Path, node_id: &str) -> std::io::Result<()> {
    let paths = NodePaths::new(base, node_id);
    if paths.config.exists() {
        fs::remove_file(&paths.config)?;
    }
    if paths.pid.exists() {
        let _ = fs::remove_file(&paths.pid);
    }
    if paths.network_dir.exists() {
        let _ = fs::remove_dir_all(&paths.network_dir);
    }
    Ok(())
}

/// `crossfyre node remove <id> | --inactive`. Removes a node's local
/// registration; `--inactive` removes every node the server reports as unknown
/// (401 from authorize-node = deleted/revoked).
/// `crossfyre node list`: show the account's node fleet from the control plane,
/// with live online/offline status. Distinct from `node status`, which only
/// reports the node daemons running locally on this host.
pub async fn run_node_list(
    base: &std::path::Path,
    as_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(account) = auth::load_account(base) else {
        eprintln!("  You are not logged in.");
        eprintln!("  Run `crossfyre login` first to see your node fleet.");
        std::process::exit(1);
    };

    let client = reqwest::Client::new();
    let nodes = auth::list_nodes(&client, &account).await?;

    if as_json {
        println!("{}", serde_json::to_string_pretty(&nodes)?);
        return Ok(());
    }

    if nodes.is_empty() {
        println!("  No nodes on your account yet.");
        println!("  Register this host with `crossfyre node init`.");
        return Ok(());
    }

    // Plain-text table. STATUS is colorized: green=online, dim=offline.
    const GREEN: &str = "\x1b[32m";
    const DIM: &str = "\x1b[2m";
    const RESET: &str = "\x1b[0m";

    println!("  {:<38} {:<20} {:<9} {:<16}", "ID", "NAME", "STATUS", "IP");
    println!("  {:<38} {:<20} {:<9} {:<16}", "--", "----", "------", "--");
    for n in &nodes {
        let id = n["id"].as_str().unwrap_or("-");
        let name = n["name"].as_str().unwrap_or("-");
        let ip = n["ip"].as_str().unwrap_or("-");
        let status = n["status"].as_str().unwrap_or("unknown");
        let status_cell = match status {
            "online" => format!("{GREEN}online{RESET}"),
            "offline" => format!("{DIM}offline{RESET}"),
            other => other.to_string(),
        };
        // Pad the visible width manually (ANSI codes don't count toward width).
        let pad = 9usize.saturating_sub(status.len());
        println!(
            "  {:<38} {:<20} {}{} {:<16}",
            id, name, status_cell, " ".repeat(pad), ip
        );
    }
    println!();
    println!("  {} node(s). Online = sending heartbeats now.", nodes.len());
    Ok(())
}

pub async fn run_node_remove(
    base: &std::path::Path,
    node_id: Option<String>,
    inactive: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let ids = discover_nodes(base).unwrap_or_default();
    if ids.is_empty() {
        println!("No nodes registered on this host.");
        return Ok(());
    }

    if let Some(want) = node_id {
        // Accept a full id or a unique prefix.
        let matches: Vec<&String> = ids
            .iter()
            .filter(|x| x.as_str() == want || x.starts_with(&want))
            .collect();
        match matches.as_slice() {
            [id] => {
                remove_node_files(base, id)?;
                println!("Removed node {}.", id);
                println!("Restart the supervisor (crossfyre node up) to drop it from the running fleet.");
            }
            [] => {
                eprintln!("No registered node matches '{}'.", want);
                eprintln!("Registered: {}", ids.join(", "));
                std::process::exit(1);
            }
            _ => {
                eprintln!("'{}' matches multiple nodes; be more specific:", want);
                for m in matches {
                    eprintln!("  {}", m);
                }
                std::process::exit(1);
            }
        }
        return Ok(());
    }

    if inactive {
        let client = reqwest::Client::new();
        let mut removed = 0usize;
        for id in &ids {
            let paths = NodePaths::new(base, id);
            let cfg: Config = match fs::read_to_string(&paths.config)
                .ok()
                .and_then(|s| toml::from_str(&s).ok())
            {
                Some(c) => c,
                None => {
                    eprintln!("Skipped {} (unreadable config).", id);
                    continue;
                }
            };
            let res = client
                .post(format!("{}/api/v1/authorize-node", cfg.api_url))
                .json(&serde_json::json!({ "api_key": cfg.api_key, "force": false }))
                .send()
                .await;
            match res {
                Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED => {
                    remove_node_files(base, id)?;
                    println!("Removed {} (not found on the server).", id);
                    removed += 1;
                }
                Ok(_) => println!("Kept {} (still registered on the server).", id),
                Err(e) => eprintln!("Skipped {} (could not reach the server: {}).", id, e),
            }
        }
        println!("Done. Removed {} inactive node(s).", removed);
        if removed > 0 {
            println!("Restart the supervisor (crossfyre node up) to drop them from the running fleet.");
        }
        return Ok(());
    }

    eprintln!("Specify a node to remove, or use --inactive.");
    eprintln!("  crossfyre node remove <node-id>");
    eprintln!("  crossfyre node remove --inactive");
    eprintln!("\nRegistered nodes:");
    for id in &ids {
        eprintln!("  {}", id);
    }
    std::process::exit(1);
}

pub async fn run_init(
    force: bool,
    api_url: &str,
    data_dir: &std::path::Path,
    no_service: bool,
    node_key: Option<String>,
    no_prompt: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Initializing Crossfyre Node Client...");
    println!("Control plane: {}", api_url);
    println!("Data directory: {}", data_dir.display());
    print_privilege_banner(false);

    let client = reqwest::Client::new();

    // Enrol this host against an existing dashboard-created node, identified by
    // its node API key. The operator creates the node in the dashboard (which
    // mints the key), then pastes it here. `json_resp` is the authorize-node
    // body; `node_api_key` is persisted so the daemon can re-authorize on start.
    let node_key = match node_key {
        Some(k) => k,
        None => prompt_node_key(no_prompt)?,
    };
    println!("Verifying node key...");
    let json_resp = auth::authorize_existing_node(&client, api_url, &node_key, force).await?;
    let node_api_key = node_key;

    // Server may reject if the node is already online elsewhere
    if json_resp["valid"].as_bool() == Some(false) {
        let node_name = json_resp["node_name"].as_str().unwrap_or("unknown");
        let last_seen = json_resp["last_seen"].as_str().unwrap_or("unknown");
        eprintln!("\n  Node '{}' is already running elsewhere.", node_name);
        eprintln!("  Last heartbeat : {}", last_seen);
        eprintln!("\n  Run with --force to disconnect it and take over:");
        eprintln!("  crossfyre node init --force");
        std::process::exit(1);
    }

    let node_id = json_resp["node_id"]
        .as_str()
        .ok_or("Failed to extract node_id from server response")?
        .to_string();

    let nats_nkey_seed = json_resp["nats_nkey_seed"]
        .as_str()
        .map(|s| s.to_string());

    let nats_user_jwt = json_resp["nats_user_jwt"]
        .as_str()
        .map(|s| s.to_string());

    // Resolve per-node on-disk paths (honors --data-dir / $SUDO_USER so the
    // config root stays the invoking user's home). Each node gets its own
    // `nodes.d/<node-id>.toml` so several can share one crossfyre config root.
    let config_dir = data_dir.to_path_buf();
    let paths = NodePaths::new(data_dir, &node_id);

    // Create config root + nodes.d if they don't exist yet.
    let nd = nodes_dir(data_dir);
    if !nd.exists() {
        fs::create_dir_all(&nd)?;
        println!("Created directory: {:?}", nd);
    }

    // -- Fetch extensions from server -------------------------------------
    let selected_extensions: Vec<String> = json_resp["extensions"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    if selected_extensions.is_empty() {
        println!("\n  No extensions assigned to this node.");
    } else {
        println!("\n  Extensions to install: {}", selected_extensions.join(", "));
    }

    // Extract NATS URL from server response (falls back to localhost for dev)
    let nats_url = json_resp["nats_url"]
        .as_str()
        .unwrap_or("nats://localhost:4222")
        .to_string();

    // -- Network identity (VPN tunnel set on the dashboard) -------------
    let network = process_network_config(&json_resp["network_config"], &paths.network_dir);

    // Write nodes.d/<node-id>.toml (with extensions list + network section)
    let config = Config {
        api_key: node_api_key.clone(),
        node_id,
        api_url: api_url.to_string(),
        nats_url,
        nats_nkey_seed,
        nats_user_jwt,
        extensions: selected_extensions.clone(),
        network: network.clone(),
    };
    let config_path = &paths.config;
    let config_toml = toml::to_string(&config)?;
    fs::write(config_path, config_toml)?;
    println!("Configuration saved to: {:?}", config_path);

    // Write session file (placeholder empty file for now)
    let session_path = config_dir.join("session");
    if !session_path.exists() {
        fs::write(&session_path, "")?;
        println!("Session file created at: {:?}", session_path);
    } else {
        println!("Session file already exists at: {:?}", session_path);
    }

    // -- Set up the toolchain + selected extensions ------------------------
    println!("\n[install] Setting up the Crossfyre toolchain...");

    // One-time migration: clean up a pre-merge OrionChain install so the old
    // orion services and binaries don't fight the new ones.
    toolchain::uninstall::cleanup_legacy_orionchain();

    // Put the crossfyre binary at its stable path so OS services have a
    // fixed ExecStart (no-op when already running from /opt/crossfyre/bin).
    let stable_exe = match toolchain::install::ensure_self_installed() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[install] WARN could not install binary to {}: {} (continuing from current path)",
                toolchain::config::get_bin_dir().display(), e);
            std::env::current_exe()?
        }
    };

    // Ensure the `node` worker binary is installed next to crossfyre, so the
    // node service's ExecStart (/opt/crossfyre/bin/node) resolves.
    if let Err(e) = toolchain::install::ensure_node_installed().await {
        eprintln!("[install] WARN could not install the node worker binary: {e}");
    }

    // Write the default toolchain config (postgres connection for the
    // extension daemons) if this host doesn't have one yet.
    if let Err(e) = toolchain::config::load_or_create_config() {
        eprintln!("[install] WARN could not create toolchain config: {}", e);
    }

    // Install each extension assigned to this node: download, verify against
    // the release manifest, enable and start its daemon. The package manager
    // is built in - no external installer involved.
    for ext in &selected_extensions {
        if toolchain::config::is_extension_installed(ext) {
            println!("[install] OK {} already installed", ext);
            let _ = toolchain::service::enable(ext);
            let _ = toolchain::service::start(ext);
            continue;
        }
        println!("[install] Installing {}...", ext);
        match toolchain::install::install_and_start(ext).await {
            Ok(()) => println!("[install] OK {} installed and started", ext),
            Err(e) => eprintln!("[install] FAIL {} install failed: {}. Run manually: crossfyre extension install {}", ext, e, ext),
        }
    }

    // Bring up the toolchain database the extensions persist scan state to.
    if !selected_extensions.is_empty() {
        println!("[install] Starting the toolchain database...");
        match toolchain::db::ensure_up() {
            Ok(()) => println!("[install] OK Database ready"),
            Err(e) => eprintln!("[install] FAIL Database start failed: {}. Run manually: crossfyre db up", e),
        }
    }

    // Register the node supervisor as an OS service so the node survives
    // reboots and closed terminals (Linux; needs root).
    if no_service {
        println!("[service] Skipped node service install (--no-service). Run the node with: crossfyre node up");
    } else {
        match toolchain::service::install_node_service(&stable_exe, data_dir) {
            Ok(()) => println!("[service] OK Node service installed and started (crossfyre-node)"),
            Err(e) => {
                eprintln!("[service] WARN could not install the node service: {}", e);
                eprintln!("[service]      run the node manually with: sudo crossfyre node up");
            }
        }
    }

    // Update node status on the server
    let status_res = client.post(format!("{}/api/v1/node-status", api_url))
        .json(&serde_json::json!({
            "api_key": &node_api_key,
            "status": "initialized",
            "event": "initialization",
            "message": "Node successfully initialized on CLI"
        }))
        .send()
        .await;

    if let Err(e) = status_res {
        eprintln!("Warning: Failed to update initialization status on server: {}", e);
    } else if let Ok(res) = status_res {
        if !res.status().is_success() {
            eprintln!("Warning: Server returned error when updating initialization status: {}", res.status());
        }
    }

    // If we ran under sudo, hand ownership of the data dir back to the
    // invoking user so the next non-sudo `--init` (or a plain `cat config.toml`)
    // can still read & write it.
    chown_tree_to_sudo_user(&config_dir);

    println!("Initialization complete.");
    Ok(())
}

/// Persist the operator-uploaded VPN config to disk and surface bring-up
/// instructions so the user can wire the tunnel into their host. We don't
/// auto-start the tunnel because that needs root and is OS-specific - we
/// tell the user exactly what to run.
pub fn process_network_config(
    raw: &serde_json::Value,
    net_dir: &std::path::Path,
) -> Option<NetworkConfig> {
    if !raw.is_object() {
        return None;
    }
    let kind = raw.get("kind").and_then(|v| v.as_str()).unwrap_or("direct").to_string();
    if kind == "direct" || kind.is_empty() {
        println!("\n[network] Direct egress - no tunnel configured.");
        return Some(NetworkConfig { kind, ..Default::default() });
    }

    let mut net = NetworkConfig {
        kind: kind.clone(),
        config_filename: raw.get("config_filename").and_then(|v| v.as_str()).map(|s| s.to_string()),
        needs_creds: raw.get("needs_creds").and_then(|v| v.as_bool()).unwrap_or(false),
        kill_switch: raw.get("kill_switch").and_then(|v| v.as_bool()).unwrap_or(false),
        dns_over_tunnel: raw.get("dns_over_tunnel").and_then(|v| v.as_bool()).unwrap_or(false),
        lab_only_routing: raw.get("lab_only_routing").and_then(|v| v.as_bool()).unwrap_or(false),
        wg_endpoint: raw.get("wg_endpoint").and_then(|v| v.as_str()).map(|s| s.to_string()),
        wg_public_key: raw.get("wg_public_key").and_then(|v| v.as_str()).map(|s| s.to_string()),
        ..Default::default()
    };

    // Write the .ovpn / .conf into this node's network dir so the user has
    // it locally and the daemon can find it on boot.
    if let Some(text) = raw.get("config_text").and_then(|v| v.as_str()) {
        if !net_dir.exists() {
            if let Err(e) = fs::create_dir_all(net_dir) {
                eprintln!("[network] Could not create {:?}: {}", net_dir, e);
                return Some(net);
            }
        }
        let suffix = if kind == "wireguard" { "conf" } else { "ovpn" };
        let fname = net.config_filename
            .clone()
            .unwrap_or_else(|| format!("crossfyre-{}.{}", kind, suffix));
        let path = net_dir.join(&fname);
        match fs::write(&path, text) {
            Ok(_) => {
                // Restrict perms - VPN configs contain secrets.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
                }
                println!("[network] Wrote tunnel config: {:?}", path);
                net.config_path = Some(path.to_string_lossy().to_string());
            }
            Err(e) => eprintln!("[network] Failed to write tunnel config: {}", e),
        }
    }

    print_tunnel_instructions(&net, net_dir);
    Some(net)
}

/// State recorded so the TunnelGuard can tear down everything we set up.
/// The veth pair, iptables MASQUERADE rule, and `/etc/netns/<n>/resolv.conf`
/// all need explicit cleanup or they'd leak across daemon restarts.
pub struct NetnsEgress {
    veth_host: String,
    subnet_cidr: String,    // "10.200.X.0/24"
    out_iface: String,
    resolv_conf: std::path::PathBuf,
}

/// Find the host's default-route interface so MASQUERADE knows where to NAT.
pub fn default_egress_iface() -> Option<String> {
    let out = std::process::Command::new("ip")
        .args(["-4", "route", "get", "1.1.1.1"])
        .output().ok()?;
    if !out.status.success() { return None; }
    let s = String::from_utf8_lossy(&out.stdout);
    let mut tokens = s.split_whitespace();
    while let Some(t) = tokens.next() {
        if t == "dev" { return tokens.next().map(|x| x.to_string()); }
    }
    None
}

/// Wire up netns <-> host connectivity: veth pair + default route + IPv4
/// forwarding + MASQUERADE + a private resolv.conf. Without this, an
/// otherwise-empty netns can't even resolve the VPN server's hostname,
/// so openvpn dies on RESOLVE: failure.
pub fn setup_netns_egress(netns: &str) -> Option<NetnsEgress> {
    // Pick a /24 that's stable for this netns (two daemons get distinct
    // subnets so their NAT rules don't clash).
    let octet: u8 = {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        netns.hash(&mut h);
        let v = ((h.finish() >> 8) & 0xff) as u8;
        // Avoid 0/255; collisions with system subnets like 10.200.0.0 are unlikely
        // but we steer away from them.
        if v == 0 || v == 255 { 100 } else { v }
    };
    let subnet_prefix = format!("10.200.{}", octet);
    let subnet_cidr = format!("{}.0/24", subnet_prefix);
    let host_ip = format!("{}.1", subnet_prefix);
    let ns_ip = format!("{}.2", subnet_prefix);

    // Interface names: kernel limit is 15 chars. cfx-XXXXXXXX -> 11 chars
    // for the suffix, prefix with "vh-"/"vn-" -> 14 chars total. Safe.
    let suffix = netns.strip_prefix("cfx-").unwrap_or(netns);
    let suffix = &suffix[..suffix.len().min(11)];
    let veth_host = format!("vh-{}", suffix);
    let veth_ns = format!("vn-{}", suffix);

    let out_iface = match default_egress_iface() {
        Some(s) => s,
        None => {
            eprintln!("[network] FAIL Couldn't detect default egress interface; netns will have no internet.");
            return None;
        }
    };

    println!("[netns] Wiring netns egress: {} <-> host {} (NAT via {}).", subnet_cidr, host_ip, out_iface);

    // Clean up any leftover veth from a previous crash before adding.
    let _ = std::process::Command::new("ip")
        .args(["link", "del", &veth_host])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    // Run an `ip` command, log success/failure with the exact argv.
    let run_ip = |label: &str, args: &[&str]| -> bool {
        let out = std::process::Command::new("ip").args(args).output();
        match out {
            Ok(o) if o.status.success() => {
                println!("[netns]   OK {}", label);
                true
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                eprintln!("[netns]   FAIL {} -- exit {:?}: {}", label, o.status.code(), stderr.trim());
                false
            }
            Err(e) => {
                eprintln!("[netns]   FAIL {} -- could not run: {}", label, e);
                false
            }
        }
    };

    if !run_ip(&format!("create veth pair {} <-> {}", veth_host, veth_ns),
               &["link", "add", &veth_host, "type", "veth", "peer", "name", &veth_ns]) {
        return None;
    }
    if !run_ip(&format!("move {} into netns {}", veth_ns, netns),
               &["link", "set", &veth_ns, "netns", netns]) {
        let _ = std::process::Command::new("ip").args(["link", "del", &veth_host]).status();
        return None;
    }
    run_ip(&format!("assign {}/24 to host-side {}", host_ip, veth_host),
           &["addr", "add", &format!("{}/24", host_ip), "dev", &veth_host]);
    run_ip(&format!("bring up host-side {}", veth_host),
           &["link", "set", &veth_host, "up"]);
    run_ip(&format!("assign {}/24 to ns-side {}", ns_ip, veth_ns),
           &["netns", "exec", netns, "ip", "addr", "add", &format!("{}/24", ns_ip), "dev", &veth_ns]);
    run_ip(&format!("bring up ns-side {}", veth_ns),
           &["netns", "exec", netns, "ip", "link", "set", &veth_ns, "up"]);
    run_ip(&format!("default route in netns via {}", host_ip),
           &["netns", "exec", netns, "ip", "route", "add", "default", "via", &host_ip]);

    // IPv4 forwarding so the host actually routes packets from the netns.
    match std::fs::write("/proc/sys/net/ipv4/ip_forward", "1\n") {
        Ok(_) => println!("[netns]   OK enabled IPv4 forwarding"),
        Err(e) => eprintln!("[netns]   FAIL enable IPv4 forwarding: {}", e),
    }

    // MASQUERADE so the netns's source IP gets translated to the host's
    // public IP on egress (otherwise return packets have nowhere to go).
    let run_ipt = |label: &str, args: &[&str]| -> bool {
        let out = std::process::Command::new("iptables").args(args).output();
        match out {
            Ok(o) if o.status.success() => {
                println!("[netns]   OK iptables {}", label);
                true
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                eprintln!("[netns]   FAIL iptables {} -- exit {:?}: {}", label, o.status.code(), stderr.trim());
                false
            }
            Err(e) => {
                eprintln!("[netns]   FAIL iptables not found ({}): install iptables and retry.", e);
                false
            }
        }
    };
    run_ipt(
        &format!("nat MASQUERADE {} -o {}", subnet_cidr, out_iface),
        &["-t", "nat", "-A", "POSTROUTING", "-s", &subnet_cidr, "-o", &out_iface, "-j", "MASQUERADE"],
    );
    // FORWARD chain may default to DROP on systems with firewalld/ufw or
    // restrictive iptables-nft setups. Without these rules, packets from
    // the netns get dropped before NAT ever sees them - and openvpn's
    // DNS lookup fails with "Temporary failure in name resolution".
    run_ipt(
        &format!("FORWARD allow {} -> {}", subnet_cidr, out_iface),
        &["-A", "FORWARD", "-s", &subnet_cidr, "-o", &out_iface, "-j", "ACCEPT"],
    );
    run_ipt(
        &format!("FORWARD allow {} <- {} (return traffic)", subnet_cidr, out_iface),
        &["-A", "FORWARD", "-d", &subnet_cidr, "-i", &out_iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
    );

    // /etc/netns/<n>/resolv.conf is bind-mounted onto /etc/resolv.conf
    // inside the netns by `ip netns exec`. Without this, the netns has
    // no resolver and openvpn fails with "Cannot resolve host address".
    let resolv_dir = std::path::PathBuf::from(format!("/etc/netns/{}", netns));
    let resolv_conf = resolv_dir.join("resolv.conf");
    match std::fs::create_dir_all(&resolv_dir).and_then(|_|
        std::fs::write(&resolv_conf, "nameserver 1.1.1.1\nnameserver 8.8.8.8\n")
    ) {
        Ok(_) => println!("[netns]   OK wrote {} (1.1.1.1, 8.8.8.8)", resolv_conf.display()),
        Err(e) => eprintln!("[netns]   FAIL write {}: {}", resolv_conf.display(), e),
    }

    // Sanity check: ICMP-ping the host-side veth from inside the netns.
    // If this fails, none of the above plumbing actually works and openvpn
    // will fail to even resolve its server address.
    print_netns_diagnostics(netns, &host_ip);

    Some(NetnsEgress { veth_host, subnet_cidr, out_iface, resolv_conf })
}

/// Dump the netns's view of the world right after egress setup, so the
/// operator can see exactly why the tunnel might fail to come up.
pub fn print_netns_diagnostics(netns: &str, host_ip: &str) {
    println!("[netns] Diagnostics inside '{}':", netns);

    let dump = |label: &str, args: &[&str]| {
        let out = std::process::Command::new("ip")
            .args(args)
            .output();
        match out {
            Ok(o) => {
                let s = String::from_utf8_lossy(&o.stdout);
                for line in s.lines() {
                    println!("[netns]   {}: {}", label, line);
                }
            }
            Err(e) => eprintln!("[netns]   {} failed: {}", label, e),
        }
    };
    dump("links", &["netns", "exec", netns, "ip", "-o", "link", "show"]);
    dump("addrs", &["netns", "exec", netns, "ip", "-o", "-4", "addr", "show"]);
    dump("routes", &["netns", "exec", netns, "ip", "-4", "route", "show"]);

    // Ping the host side - if this fails, the veth/route setup is broken.
    let ping = std::process::Command::new("ip")
        .args(["netns", "exec", netns, "ping", "-c", "1", "-W", "2", host_ip])
        .output();
    match ping {
        Ok(o) if o.status.success() => println!("[netns]   OK ping {} (host) OK", host_ip),
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stderr);
            eprintln!("[netns]   FAIL ping {} (host) failed: {}", host_ip, s.trim());
        }
        Err(e) => eprintln!("[netns]   FAIL ping not available: {}", e),
    }

    // Ping out to the wider internet - if this fails, MASQUERADE/forwarding is broken.
    let ping_out = std::process::Command::new("ip")
        .args(["netns", "exec", netns, "ping", "-c", "1", "-W", "3", "1.1.1.1"])
        .output();
    match ping_out {
        Ok(o) if o.status.success() => println!("[netns]   OK ping 1.1.1.1 (egress) OK"),
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stderr);
            eprintln!("[netns]   FAIL ping 1.1.1.1 (egress) FAILED: {}", s.trim());
            eprintln!("[netns]     Check: net.ipv4.ip_forward, iptables MASQUERADE, host firewall.");
        }
        Err(_) => {}
    }

    // DNS resolve - if this fails, openvpn can't find its VPN server.
    let dig = std::process::Command::new("ip")
        .args(["netns", "exec", netns, "getent", "hosts", "hackthebox.eu"])
        .output();
    match dig {
        Ok(o) if o.status.success() => {
            let s = String::from_utf8_lossy(&o.stdout);
            println!("[netns]   OK DNS resolve OK: {}", s.trim());
        }
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stderr);
            eprintln!("[netns]   FAIL DNS resolve FAILED: {} (resolv.conf override may not be applied)", s.trim());
        }
        Err(_) => {}
    }
}

pub fn teardown_netns_egress(eg: &NetnsEgress) {
    // Remove iptables rules we added (best-effort - if any rule isn't
    // there, the -D fails harmlessly).
    let ipt_del = |args: &[&str]| {
        let _ = std::process::Command::new("iptables")
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    };
    ipt_del(&["-t", "nat", "-D", "POSTROUTING", "-s", &eg.subnet_cidr, "-o", &eg.out_iface, "-j", "MASQUERADE"]);
    ipt_del(&["-D", "FORWARD", "-s", &eg.subnet_cidr, "-o", &eg.out_iface, "-j", "ACCEPT"]);
    ipt_del(&["-D", "FORWARD", "-d", &eg.subnet_cidr, "-i", &eg.out_iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]);
    // Remove veth (peer is auto-removed by the kernel).
    let _ = std::process::Command::new("ip")
        .args(["link", "del", &eg.veth_host])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    // Remove resolv.conf override (and the parent dir if empty).
    let _ = std::fs::remove_file(&eg.resolv_conf);
    if let Some(parent) = eg.resolv_conf.parent() {
        let _ = std::fs::remove_dir(parent);
    }
}

/// Bring the operator-configured VPN up *inside an isolated network namespace*
/// rather than on the host. The daemon itself keeps using the host's regular
/// network (so it can still reach the controller and NATS). Only commands the
/// operator runs via `ip netns exec cfx-tun ...` see the tunnel - which is what
/// scan extensions should do.
pub fn ensure_tunnel_up(net: &NetworkConfig, net_dir: &std::path::Path, netns: &str) -> (Option<std::process::Child>, Option<NetnsEgress>) {
    if net.kind.is_empty() || net.kind == "direct" {
        return (None, None);
    }
    let Some(cfg_path) = net.config_path.as_deref() else {
        eprintln!("[network] No tunnel config file on disk; skipping auto-start.");
        return (None, None);
    };
    if !std::path::Path::new(cfg_path).exists() {
        eprintln!("[network] Tunnel config not found at {}; skipping auto-start.", cfg_path);
        return (None, None);
    }
    if !is_root() {
        eprintln!("\n[network] Not running as root - cannot create the network namespace.");
        eprintln!("[network] Re-run the daemon with sudo (we honor $SUDO_USER so your config stays user-owned):");
        eprintln!("[network]   sudo crossfyre node up");
        return (None, None);
    }
    if which_binary("ip").is_none() {
        eprintln!("[network] `ip` (iproute2) not found. Install iproute2 and retry.");
        return (None, None);
    }

    // -- 1. Create the netns (idempotent) --------------------------------
    if !netns_exists(netns) {
        println!("[network] Creating network namespace '{}'...", netns);
        let s = std::process::Command::new("ip").args(["netns", "add", netns]).status();
        match s {
            Ok(s) if s.success() => {}
            Ok(s) => {
                eprintln!("[network] FAIL `ip netns add` exited with {}.", s);
                return (None, None);
            }
            Err(e) => {
                eprintln!("[network] FAIL Could not run `ip netns add`: {}.", e);
                return (None, None);
            }
        }
        let _ = std::process::Command::new("ip")
            .args(["netns", "exec", netns, "ip", "link", "set", "lo", "up"])
            .status();
    } else {
        println!("[network] Reusing existing network namespace '{}'.", netns);
    }

    // -- 2. Wire up netns egress (veth/NAT/DNS) --------------------------
    // Without this the netns can't resolve hostnames or reach the VPN
    // server's IP, so openvpn dies on `RESOLVE: Cannot resolve host`.
    let egress = setup_netns_egress(netns);

    // -- 3. Skip if the tunnel interface is already up *inside the netns* --
    if tunnel_in_netns(netns, &net.kind) {
        println!("[network] Tunnel already up inside '{}'.", netns);
        print_netns_usage(netns);
        return (None, egress);
    }

    // -- 4. Start the tunnel inside the netns -----------------------------
    // We deliberately do NOT use openvpn's `--daemon` mode: we want openvpn
    // to stay a direct child of crossfyre so PR_SET_PDEATHSIG can guarantee
    // it dies the moment crossfyre dies -- even via SIGKILL or a hard crash.
    println!("[network] Starting {} tunnel inside '{}'...", net.kind, netns);
    let log_path = net_dir.join("openvpn.log");
    let openvpn_child = match net.kind.as_str() {
        "wireguard" => {
            if which_binary("wg-quick").is_none() {
                eprintln!("[network] wg-quick not found in PATH. Install wireguard-tools and retry.");
                return (None, egress);
            }
            let s = std::process::Command::new("ip")
                .args(["netns", "exec", netns, "wg-quick", "up", cfg_path])
                .status();
            wait_for_tunnel(netns, &net.kind, &log_path);
            match s {
                Ok(s) if s.success() => None,
                Ok(s) => { eprintln!("[network] FAIL wg-quick exited with {}.", s); None }
                Err(e) => { eprintln!("[network] FAIL Could not run wg-quick: {}.", e); None }
            }
        }
        _ => {
            if which_binary("openvpn").is_none() {
                eprintln!("[network] openvpn not found in PATH. Install openvpn and retry.");
                return (None, egress);
            }
            let mut cmd = std::process::Command::new("ip");
            cmd.args([
                "netns", "exec", netns,
                "openvpn",
                "--config", cfg_path,
                "--log", log_path.to_string_lossy().as_ref(),
            ]);
            if net.needs_creds {
                let auth = net_dir.join("auth.txt");
                if !auth.exists() {
                    eprintln!(
                        "[network] Tunnel needs credentials but {} is missing.",
                        auth.display()
                    );
                    return (None, egress);
                }
                cmd.args(["--auth-user-pass", auth.to_string_lossy().as_ref()]);
            }
            cmd.stdin(std::process::Stdio::null())
               .stdout(std::process::Stdio::null())
               .stderr(std::process::Stdio::null());
            #[cfg(target_os = "linux")]
            unsafe {
                use std::os::unix::process::CommandExt;
                cmd.pre_exec(|| {
                    let r = libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM as libc::c_ulong, 0, 0, 0);
                    if r != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            match cmd.spawn() {
                Ok(child) => {
                    wait_for_tunnel(netns, &net.kind, &log_path);
                    Some(child)
                }
                Err(e) => {
                    eprintln!("[network] FAIL Could not spawn openvpn: {}.", e);
                    None
                }
            }
        }
    };

    (openvpn_child, egress)
}

/// Poll the netns until a tunnel interface appears (HTB's auth/handshake
/// can take 10-15s). Always prints the openvpn log tail at the end so
/// the operator sees the auth/route-push lines whether or not the
/// interface actually came up.
pub fn wait_for_tunnel(netns: &str, kind: &str, log_path: &std::path::Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut up = false;
    while std::time::Instant::now() < deadline {
        if tunnel_in_netns(netns, kind) {
            up = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    if up {
        println!("[network] OK Tunnel up inside '{}'. Host network is untouched.", netns);
        print_netns_usage(netns);
        // Verify connectivity *over the tunnel* - HTB only marks us
        // online once it sees traffic on the assigned tun IP.
        let ip_check = std::process::Command::new("ip")
            .args(["netns", "exec", netns, "ip", "-4", "addr", "show"])
            .output();
        if let Ok(o) = ip_check {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines().filter(|l| l.contains(" inet ")) {
                println!("[network]   {}", line.trim());
            }
        }
        // Check whether HTB routes are pushed.
        let route_check = std::process::Command::new("ip")
            .args(["netns", "exec", netns, "ip", "-4", "route", "show"])
            .output();
        if let Ok(o) = route_check {
            let s = String::from_utf8_lossy(&o.stdout);
            let tunnel_routes: Vec<_> = s.lines()
                .filter(|l| l.contains(" dev tun") || l.contains(" dev tap"))
                .collect();
            if tunnel_routes.is_empty() {
                eprintln!("[network] WARNING: Tunnel iface up but no routes pushed - HTB lab subnets may be unreachable.");
            } else {
                println!("[network]   Tunnel routes:");
                for r in tunnel_routes {
                    println!("[network]     {}", r.trim());
                }
            }
        }
    } else {
        eprintln!("[network] WARNING: Tunnel didn't come up inside '{}' within 30s.", netns);
    }

    // Always print openvpn's log tail (the most useful diagnostic).
    if kind != "wireguard" && log_path.exists() {
        let label = if up { "log" } else { "Last lines" };
        println!("[network] {} of {}:", label, log_path.display());
        if let Ok(contents) = std::fs::read_to_string(log_path) {
            let lines: Vec<&str> = contents.lines().collect();
            let n = lines.len();
            let start = n.saturating_sub(if up { 8 } else { 25 });
            for line in &lines[start..] {
                println!("[network]   | {}", line);
            }
        }
        println!("[network]   Tail with: sudo tail -f {}", log_path.display());
    } else if !up {
        eprintln!("[network]   Check logs with: sudo ip netns exec {} journalctl -u openvpn", netns);
    }
}

/// Tears the tunnel + netns down when the daemon exits. The Child handle
/// (when present) is openvpn running as our direct child with
/// PR_SET_PDEATHSIG set -- so it dies even if we get SIGKILL'd. This
/// Drop adds the graceful path: SIGTERM -> wait -> SIGKILL -> remove netns.
pub struct TunnelGuard {
    netns: String,
    openvpn: Option<std::process::Child>,
    egress: Option<NetnsEgress>,
}

impl Drop for TunnelGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.openvpn.take() {
            let pid = child.id() as i32;
            println!("[network] Stopping OpenVPN (pid {})...", pid);
            #[cfg(unix)]
            unsafe { libc::kill(pid, libc::SIGTERM); }
            // Give openvpn ~1s to send a hangup to the upstream so the
            // remote (HTB / etc) marks us offline immediately.
            for _ in 0..10 {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    _ => std::thread::sleep(std::time::Duration::from_millis(100)),
                }
            }
            let _ = child.kill();
            let _ = child.wait();
        }

        // Best-effort: tear down WireGuard interfaces left in the netns.
        let _ = std::process::Command::new("ip")
            .args(["netns", "exec", &self.netns, "sh", "-c", "for i in $(ip -o link show | awk -F': ' '/wg/ {print $2}'); do ip link del $i 2>/dev/null; done"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        // Tear down egress (iptables MASQUERADE + veth + resolv.conf override).
        if let Some(eg) = self.egress.take() {
            teardown_netns_egress(&eg);
        }

        if netns_exists(&self.netns) {
            println!("[network] Removing network namespace '{}'...", self.netns);
            let _ = std::process::Command::new("ip")
                .args(["netns", "del", &self.netns])
                .status();
        }
    }
}

pub fn netns_exists(name: &str) -> bool {
    std::path::Path::new(&format!("/var/run/netns/{}", name)).exists()
}

pub fn tunnel_in_netns(netns: &str, kind: &str) -> bool {
    // List every interface in the netns and look for tun*/wg* prefixes.
    // We don't know which device name OpenVPN/wg-quick will pick (`dev tun`
    // is dynamic, HTB sometimes uses tun0/tun1/...) so a substring check is
    // more robust than a hardcoded candidate list.
    let prefixes: &[&str] = if kind == "wireguard" {
        &["wg"]
    } else {
        &["tun", "tap"]
    };
    let out = std::process::Command::new("ip")
        .args(["netns", "exec", netns, "ip", "-o", "link", "show"])
        .output();
    let Ok(out) = out else { return false };
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        // Format: "N: <ifname>: ..." -- pull the second whitespace-separated token
        let mut parts = line.split_whitespace();
        let _ = parts.next();
        let Some(name) = parts.next() else { continue };
        let name = name.trim_end_matches(':').split('@').next().unwrap_or(name);
        if name == "lo" { continue }
        if prefixes.iter().any(|p| name.starts_with(p)) {
            return true;
        }
    }
    false
}

pub fn print_netns_usage(netns: &str) {
    println!(
        "[network]     -> Run scan tooling through the tunnel with:  sudo ip netns exec {} <cmd>",
        netns
    );
    println!(
        "[network]     -> The crossfyre daemon stays on the host network so it can reach the controller."
    );
}

#[cfg(unix)]
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
#[cfg(not(unix))]
pub fn is_root() -> bool { false }

pub fn which_binary(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

pub fn print_tunnel_instructions(net: &NetworkConfig, net_dir: &std::path::Path) {
    let auth_path = net_dir.join("auth.txt");
    let auth = auth_path.display();
    let label = match net.kind.as_str() {
        "htb" => "HackTheBox",
        "thm" => "TryHackMe",
        "openvpn" => "OpenVPN",
        "wireguard" => "WireGuard",
        _ => "Tunnel",
    };
    println!("\n  --- {} tunnel ---------------------------------------", label);
    let path = net.config_path.as_deref().unwrap_or("<config not written>");
    match net.kind.as_str() {
        "wireguard" => {
            println!("  1. Install WireGuard if needed:");
            println!("     Debian/Ubuntu : sudo apt install -y wireguard");
            println!("     Arch          : sudo pacman -S wireguard-tools");
            println!("     macOS         : brew install wireguard-tools");
            println!("  2. Bring the tunnel up (root or capabilities required):");
            println!("     sudo wg-quick up {}", path);
            println!("  3. Verify with: ip addr show wg0   (Linux) / ifconfig (macOS)");
        }
        _ => {
            println!("  1. Install OpenVPN if needed:");
            println!("     Debian/Ubuntu : sudo apt install -y openvpn");
            println!("     Arch          : sudo pacman -S openvpn");
            println!("     macOS         : brew install openvpn");
            if net.needs_creds {
                println!("  2. Create an auth file with your credentials (one per line):");
                println!("     printf 'YOUR_USERNAME\\nYOUR_PASSWORD\\n' > {}", auth);
                println!("     chmod 600 {}", auth);
                println!("  3. Bring the tunnel up:");
                println!("     sudo openvpn --config {} --auth-user-pass {} --daemon", path, auth);
            } else {
                println!("  2. Bring the tunnel up (root required for /dev/net/tun):");
                println!("     sudo openvpn --config {} --daemon", path);
            }
            println!("  3. Verify with: ip addr show tun0");
        }
    }
    if net.kill_switch {
        println!("  WARNING:  Kill-switch enabled in dashboard - we recommend an iptables rule blocking egress");
        println!("     on the default interface so requests fail closed if the tunnel drops.");
    }
    if net.lab_only_routing {
        println!("  OK  Lab-only routing flag set - only push lab subnets through the tunnel");
        println!("     (e.g. 10.10.0.0/16 for HackTheBox). Configure via your VPN client's pull-filter.");
    }
    println!("  --------------------------------------------------------");
}

/// Call /api/v1/authorize-node to get a fresh JWT+NKey, then persist them
/// to config.toml so the next NATS connect uses valid credentials.
/// Re-authorize the node on every daemon start. The server response is the
/// authoritative source for everything operator-configurable: NATS creds,
/// installed extensions, network identity (VPN), and the proxy chain. Every
/// piece is refreshed in-place so dashboard edits take effect on the next
/// daemon restart without needing the operator to re-run --init.
pub async fn refresh_node_state(
    config: &mut Config,
    config_path: &std::path::Path,
    net_dir: &std::path::Path,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Refreshing node state from controller...");
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{}/api/v1/authorize-node", config.api_url))
        .json(&serde_json::json!({ "api_key": &config.api_key, "force": force }))
        .send()
        .await?;

    // 401 = the server doesn't know this api_key (node deleted / key revoked).
    // Surface it as a terminal NodeDeleted error so the daemon stops cleanly
    // instead of retrying a key that will never authorize.
    if res.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err(Box::new(NodeDeleted));
    }
    if !res.status().is_success() {
        return Err(format!("authorize-node returned {}", res.status()).into());
    }

    let json_resp: serde_json::Value = res.json().await?;

    if json_resp["valid"].as_bool() != Some(true) {
        // Server says this api_key already has a live node elsewhere - the
        // daemon caller must surface this so the operator knows another
        // instance is still holding the slot.
        let node_name = json_resp["node_name"].as_str().unwrap_or("unknown");
        let last_seen = json_resp["last_seen"].as_str().unwrap_or("unknown");
        return Err(format!(
            "node '{}' is already running elsewhere (last heartbeat {}). Use --force to take over.",
            node_name, last_seen
        ).into());
    }

    if let Some(jwt) = json_resp["nats_user_jwt"].as_str() {
        config.nats_user_jwt = Some(jwt.to_string());
    }
    if let Some(seed) = json_resp["nats_nkey_seed"].as_str() {
        config.nats_nkey_seed = Some(seed.to_string());
    }

    // Refresh the network/VPN config from the server. This rewrites the
    // .ovpn / .conf on disk if the operator uploaded a new one - so an edit
    // in the dashboard plus a daemon restart is enough to switch tunnels.
    let new_network = process_network_config(&json_resp["network_config"], net_dir);
    if new_network != config.network {
        if let Some(ref n) = new_network {
            println!("[network] Tunnel selection: {} (updated from controller).", n.kind);
        } else {
            println!("[network] No tunnel configured (cleared by controller).");
        }
        config.network = new_network;
    }

    // Persist so next restart also has fresh creds if refresh fails.
    let config_toml = toml::to_string(&config)?;
    fs::write(config_path, config_toml)?;
    // Daemon often runs as root via sudo - the file we just wrote is now
    // root-owned. Hand it back to the invoking user so non-sudo tools can
    // still read it.
    chown_to_sudo_user(config_path);
    if let Some(parent) = config_path.parent() {
        chown_tree_to_sudo_user(parent);
    }
    println!("Node state refreshed and saved.");
    Ok(())
}

pub async fn run_daemon(force: bool, paths: &NodePaths) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting Crossfyre Node Client Daemon...");
    println!("Node id       : {}", paths.node_id);
    println!("Config root   : {}", paths.base.display());
    print_privilege_banner(true);

    // --- PID lock: scoped to this node-id, so multiple nodes can coexist in
    // the same config root - each holds its own `nodes.d/<node-id>.pid`. ---
    fs::create_dir_all(nodes_dir(&paths.base))?;
    let pid_path = paths.pid.clone();

    if pid_path.exists() {
        let existing_pid_str = fs::read_to_string(&pid_path).unwrap_or_default();
        let existing_pid: u32 = existing_pid_str.trim().parse().unwrap_or(0);
        if existing_pid > 0 {
            let proc_path = format!("/proc/{}", existing_pid);
            if std::path::Path::new(&proc_path).exists() {
                if force {
                    println!("  --force: Terminating existing daemon (PID {})...", existing_pid);
                    // SIGTERM the old process
                    unsafe { libc::kill(existing_pid as i32, libc::SIGTERM); }
                    // Give it a moment to exit
                    tokio::time::sleep(tokio::time::Duration::from_millis(800)).await;
                } else {
                    eprintln!("\n  A daemon is already running for node {}.", paths.node_id);
                    eprintln!("  PID            : {}", existing_pid);
                    eprintln!("\n  Take it over with:");
                    eprintln!("  crossfyre node daemon {} --force\n", paths.node_id);
                    std::process::exit(1);
                }
            }
        }
    }
    // Write our own PID
    let my_pid = std::process::id();
    fs::write(&pid_path, my_pid.to_string())?;
    chown_to_sudo_user(&pid_path);
    // Remove PID file on exit (best-effort via a drop guard)
    struct PidGuard(std::path::PathBuf);
    impl Drop for PidGuard {
        fn drop(&mut self) { let _ = fs::remove_file(&self.0); }
    }
    let _pid_guard = PidGuard(pid_path);
    // ------------------------------------------------------------------


    // Check if this node's configuration exists
    let config_path = paths.config.clone();

    if !config_path.exists() {
        eprintln!(
            "Configuration for node '{}' not found. Run `crossfyre node init` first. Expected at: {:?}",
            paths.node_id, config_path
        );
        std::process::exit(1);
    }

    // Load config
    let config_str = fs::read_to_string(&config_path)?;
    let mut config: Config = toml::from_str(&config_str)?;

    println!("Configuration loaded successfully.");

    // Pull the latest state (creds + network config + extensions) from the
    // controller on every daemon start. The server enforces "one running
    // node per api_key" - so if it returns valid=false we abort instead of
    // falling through to a cached config (which would let two daemons race
    // for the same NATS subjects).
    if let Err(e) = refresh_node_state(&mut config, &config_path, &paths.network_dir, force).await {
        if e.downcast_ref::<NodeDeleted>().is_some() {
            eprintln!("\n  Node {} not found on the server (deleted in the dashboard, or its key was revoked).", paths.node_id);
            eprintln!("  Stopping - this node will not be retried.");
            eprintln!("  Clean it up locally with:");
            eprintln!("    crossfyre node remove {}", paths.node_id);
            eprintln!("    crossfyre node remove --inactive   # remove all server-deleted nodes");
            std::process::exit(1);
        }
        eprintln!("\n  Cannot start daemon: {}", e);
        eprintln!("  crossfyre node daemon {} --force   # take over this node", paths.node_id);
        std::process::exit(1);
    }

    // -- Bring up the VPN tunnel (if any) before scanning starts ---------
    // We do this after credential refresh (which needs the regular internet
    // to reach the controller) and before NATS connect, so any subscriber
    // traffic that should route through the tunnel does.
    //
    // The guard tears the tunnel + netns down on every exit path (Ctrl+C,
    // SIGTERM, panic, normal return) -- without it, OpenVPN's `--daemon`
    // process would outlive crossfyre and HackTheBox would still see us
    // connected. Bound to a `_tunnel_guard` so it lives the full daemon
    // lifetime. The netns is keyed off the node-id so two nodes never share
    // a namespace.
    let _tunnel_guard = if let Some(net) = config.network.as_ref() {
        let net_dir = paths.network_dir.clone();
        let netns = netns_for(&paths.node_id);
        let (openvpn, egress) = ensure_tunnel_up(net, &net_dir, &netns);
        Some(TunnelGuard { netns, openvpn, egress })
    } else {
        None
    };

    println!("Connecting to Jetstream at {}...", config.nats_url);

    // Connect to NATS
    let nats_url = config.nats_url.as_str();
    
    // Require JWT credentials - NATS is in operator mode, anonymous connections are rejected
    let (jwt_str, seed_str) = match (&config.nats_user_jwt, &config.nats_nkey_seed) {
        (Some(j), Some(s)) if !j.is_empty() && !s.is_empty() => (j.clone(), s.clone()),
        _ => {
            eprintln!("ERROR: nats_user_jwt or nats_nkey_seed is missing from this node's config.");
            eprintln!("       Run `crossfyre node init` to register this node and get fresh credentials.");
            std::process::exit(1);
        }
    };
    
    println!("Authenticating to Jetstream with dynamically issued User JWT & Seed...");
    let key_pair = std::sync::Arc::new(
        nkeys::KeyPair::from_seed(seed_str.as_str())
            .expect("Invalid nats_nkey_seed in config.toml")
    );
    let opts = async_nats::ConnectOptions::with_jwt(
        jwt_str,
        move |nonce: Vec<u8>| {
            let kp = key_pair.clone();
            async move {
                kp.sign(&nonce).map_err(|e| async_nats::AuthError::new(e))
            }
        }
    )
    // Increase the subscriber buffer so large bursts (e.g. a 65k-op DS scan)
    // don't overflow and drop messages as "slow consumer".
    .subscription_capacity(1_000_000);

    let nats_client = opts.connect(nats_url).await
        .map_err(|e| { eprintln!("ERROR: Failed to connect to NATS: {}", e); e })?;

    // Subscribe to the job/control channel for this node
    let job_subject = format!("cfx.jobs.{}", config.node_id);
    let mut job_sub = nats_client.subscribe(job_subject.clone()).await
        .map_err(|e| { eprintln!("ERROR: Failed to subscribe to {}: {}", job_subject, e); e })?;

    // Keep a clone for publishing status updates (nats_client is cheap to clone)
    let publisher = nats_client.clone();
    let status_subject = format!("cfx.node.{}.status", config.node_id);
    let _jetstream = async_nats::jetstream::new(nats_client);

    // -- Build full host info on first connect -------------------------------
    let mut sys = System::new_all();
    sys.refresh_all();
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    sys.refresh_all();

    let hostname = sysinfo::System::host_name().unwrap_or_else(|| "unknown".into());
    let os_name  = sysinfo::System::long_os_version().unwrap_or_else(|| "unknown".into());
    let arch     = std::env::consts::ARCH.to_string();

    // Detect primary local IP
    let ip = {
        use std::net::UdpSocket;
        UdpSocket::bind("0.0.0.0:0")
            .and_then(|s| { s.connect("8.8.8.8:80")?; s.local_addr() })
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|_| "unknown".into())
    };

    let ram_total = sys.total_memory() as i64;
    let ram_used  = sys.used_memory() as i64;
    let ram_avail = (sys.total_memory().saturating_sub(sys.used_memory())) as i64;
    let cpu_usage = sys.global_cpu_usage() as i64;

    // Network baseline
    use sysinfo::Networks;
    let mut nets = Networks::new_with_refreshed_list();
    let (mut last_rx, mut last_tx) = nets.iter().fold((0i64, 0i64), |(rx, tx), (_, n)| {
        (rx + n.total_received() as i64, tx + n.total_transmitted() as i64)
    });

    // -- Send full host_status on first connect ------------------------------
    println!("Connected to Jetstream successfully.");
    println!("Listening for commands on : {}", job_subject);
    println!("Publishing status to      : {}", status_subject);
    println!("Daemon running. Press Ctrl+C to stop.");

    // -- Validate API key before going online -------------------------------
    // This blocks the node from ever appearing online with a revoked key.
    let http_client = reqwest::Client::new();
    let validate_res = http_client
        .post(&format!("{}/api/v1/node-status", config.api_url))
        .json(&serde_json::json!({
            "api_key": &config.api_key,
            "status": "online",
            "event": "initialization",
            "message": serde_json::Value::Null,
            "host_status": serde_json::json!({
                "cpu": cpu_usage,
                "ram_used": ram_used,
                "ram_available": ram_avail,
                "ram_total": ram_total,
                "net_rx": 0,
                "net_tx": 0,
                "hostname": hostname,
                "ip": ip,
                "os": os_name,
                "arch": arch
            })
        }))
        .send()
        .await;

    match validate_res {
        Ok(res) if res.status() == 401 => {
            eprintln!("\n[EVICTION] API key has been revoked. This node is no longer authorized.");
            eprintln!("           Run `crossfyre node init` again to re-register with a valid key.");
            std::process::exit(1);
        }
        Ok(res) if !res.status().is_success() => {
            eprintln!("Warning: Server returned {} on startup. Continuing...", res.status());
        }
        Err(e) => {
            eprintln!("Warning: Could not reach backend on startup: {}. Continuing offline...", e);
        }
        _ => {}
    }

    let api_url = config.api_url.clone();
    let api_key = config.api_key.clone();
    let node_id = config.node_id.clone();

    // Ask the controller to re-publish any operations that were assigned
    // to this node and never finished (because we crashed, were killed, or
    // exited mid-scan). The controller filters out halted/finished
    // workflows, so this only revives in-progress runs. Republished
    // messages flow through the normal cfx.jobs.<node_id> subscription.
    {
        let resume_res = http_client
            .post(&format!("{}/api/v1/resume-pending", api_url))
            .json(&serde_json::json!({ "api_key": api_key }))
            .send()
            .await;
        match resume_res {
            Ok(r) if r.status().is_success() => {
                if let Ok(body) = r.json::<serde_json::Value>().await {
                    let n = body["data"]["republished"].as_u64().unwrap_or(0);
                    if n > 0 {
                        println!("[resume] Picking up {} pending operation(s) from prior run", n);
                    }
                }
            }
            Ok(r) => eprintln!("[resume] Controller returned {} - skipping resume", r.status()),
            Err(e) => eprintln!("[resume] Could not reach controller: {} - skipping resume", e),
        }
    }

    let mut heartbeat_interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
    // Skip the first tick since we already sent the initial status above
    heartbeat_interval.tick().await;
    let mut first_tick = false; // already sent full host_status above, don't duplicate it

    // Proactive credential refresh - fire every 6 days (JWT has a 7-day TTL).
    // If the daemon runs long enough, this prevents silent NATS disconnects.
    let mut refresh_interval = tokio::time::interval(tokio::time::Duration::from_secs(6 * 24 * 3600));
    refresh_interval.tick().await; // skip immediate first tick

    // Catch SIGTERM (the default `kill` signal) so the tunnel teardown
    // path runs - without this, `kill <pid>` would bypass the Drop guard
    // and leave OpenVPN orphaned.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM handler");

    loop {
        tokio::select! {
            // Credential refresh (every 6 days)
            _ = refresh_interval.tick() => {
                println!("[refresh] Proactively refreshing NATS credentials...");
                match refresh_node_state(&mut config, &config_path, &paths.network_dir, false).await {
                    Ok(()) => println!("[refresh] Done. New JWT will take effect on next daemon restart."),
                    Err(e) => eprintln!("[refresh] Warning: credential refresh failed: {}. JWT still valid for ~1 day.", e),
                }
                // Note: we don't reconnect NATS in-flight - the current connection uses the
                // old JWT which is still valid for ~1 more day. The refresh just ensures the
                // *saved* config is fresh so a restart works cleanly. A full reconnect would
                // require rebuilding subscriptions and is deferred for a future release.
            }
            // Heartbeat tick
            _ = heartbeat_interval.tick() => {
                sys.refresh_cpu_all();
                sys.refresh_memory();
                nets.refresh(true);

                let cpu   = sys.global_cpu_usage() as i64;
                let r_used  = sys.used_memory() as i64;
                let r_avail = (sys.total_memory().saturating_sub(sys.used_memory())) as i64;
                let (rx_now, tx_now) = nets.iter().fold((0i64, 0i64), |(rx, tx), (_, n)| {
                    (rx + n.total_received() as i64, tx + n.total_transmitted() as i64)
                });
                let net_rx = rx_now - last_rx;
                let net_tx = tx_now - last_tx;
                last_rx = rx_now;
                last_tx = tx_now;

                // Probe only installed extension daemon ports
                let ext_status: serde_json::Value = {
                    let mut map = serde_json::Map::new();
                    let known_ports: &[(&str, u16)] = &[("mach", 4441), ("voyage", 4442), ("pulse", 4443)];
                    for (ext, port) in known_ports {
                        if !config.extensions.iter().any(|e| e == ext) { continue; }
                        let running = std::net::TcpStream::connect_timeout(
                            &std::net::SocketAddr::from(([127, 0, 0, 1], *port)),
                            std::time::Duration::from_millis(200),
                        ).is_ok();
                        map.insert(ext.to_string(), serde_json::json!({
                            "port": port,
                            "running": running
                        }));
                    }
                    serde_json::Value::Object(map)
                };

                // Toolchain health. The package manager is built into this
                // binary, so "installed" is always true and the version is
                // our own; Postgres is probed on its TCP port.
                let toolchain_status: serde_json::Value = {
                    let pg_running = std::net::TcpStream::connect_timeout(
                        &std::net::SocketAddr::from(([127, 0, 0, 1], 4440)),
                        std::time::Duration::from_millis(200),
                    ).is_ok();

                    serde_json::json!({
                        "installed": true,
                        "version": format!("crossfyre {}", env!("CARGO_PKG_VERSION")),
                        "postgres": { "port": 4440, "running": pg_running }
                    })
                };

                let host_status = if first_tick {
                    first_tick = false;
                    serde_json::json!({
                        "cpu": cpu_usage,
                        "ram_used": ram_used,
                        "ram_available": ram_avail,
                        "ram_total": ram_total,
                        "net_rx": 0,
                        "net_tx": 0,
                        "hostname": hostname,
                        "ip": ip,
                        "os": os_name,
                        "arch": arch,
                        "extension_status": ext_status,
                        "toolchain_status": toolchain_status
                    })
                } else {
                    serde_json::json!({
                        "cpu": cpu,
                        "ram_used": r_used,
                        "ram_available": r_avail,
                        "ram_total": ram_total,
                        "net_rx": net_rx,
                        "net_tx": net_tx,
                        "extension_status": ext_status,
                        "toolchain_status": toolchain_status
                    })
                };

                let status_res = http_client.post(&format!("{}/api/v1/node-status", api_url))
                    .json(&serde_json::json!({
                        "api_key": &api_key,
                        "status": "online",
                        "event": "heartbeat",
                        "message": serde_json::Value::Null,
                        "host_status": host_status
                    }))
                    .send()
                    .await;

                match status_res {
                    Ok(res) if res.status().is_success() => print!("."),
                    Ok(res) if res.status() == 401 => {
                        eprintln!("\n[EVICTION] Heartbeat returned 401 - API key has been revoked. Shutting down...");
                        let msg = serde_json::json!({
                            "type": "terminated",
                            "reason": "api_key_revoked",
                            "node_id": &node_id
                        });
                        let _ = publisher.publish(status_subject.clone(), msg.to_string().into()).await;
                        break;
                    }
                    Ok(res) => eprintln!("Warning: Heartbeat returned {}", res.status()),
                    Err(e) => eprintln!("Warning: Failed to send heartbeat: {}", e),
                }
            }

            // Ctrl+C - graceful shutdown
            _ = tokio::signal::ctrl_c() => {
                let reason = "user_initiated_shutdown";
                println!("\nCtrl+C received. Reason: {}. Shutting down...", reason);
                let msg = serde_json::json!({
                    "type": "terminated",
                    "reason": reason,
                    "node_id": &node_id
                });
                let _ = publisher.publish(status_subject.clone(), msg.to_string().into()).await;
                break;
            }

            // SIGTERM (e.g. `kill <pid>`, systemd stop) - same shutdown path
            _ = sigterm.recv() => {
                let reason = "sigterm_received";
                println!("\nSIGTERM received. Shutting down...");
                let msg = serde_json::json!({
                    "type": "terminated",
                    "reason": reason,
                    "node_id": &node_id
                });
                let _ = publisher.publish(status_subject.clone(), msg.to_string().into()).await;
                break;
            }

            // Command message from JetStream
            msg = job_sub.next() => {
                if let Some(msg) = msg {
                    let body = std::str::from_utf8(&msg.payload).unwrap_or("");
                    if let Ok(cmd) = serde_json::from_str::<serde_json::Value>(body) {
                        match cmd["type"].as_str() {
                            Some("terminate") => {
                                let reason = cmd["reason"].as_str().unwrap_or("unknown");
                                println!("\nReceived terminate command. Reason: {}. Shutting down...", reason);
                                let msg = serde_json::json!({
                                    "type": "terminated",
                                    "reason": reason,
                                    "node_id": &node_id
                                });
                                let _ = publisher.publish(status_subject.clone(), msg.to_string().into()).await;
                                break;
                            }
                            Some("cancel_workflow") => {
                                if let Some(wid) = cmd["workflow_id"].as_str() {
                                    println!("[op] Cancelling all in-flight ops for workflow {}", wid);
                                    cancel_workflow(wid);
                                }
                            }
                            Some("resume_workflow") => {
                                if let Some(wid) = cmd["workflow_id"].as_str() {
                                    println!("[op] Clearing cancel flag for workflow {} (restart)", wid);
                                    resume_workflow(wid);
                                }
                            }
                            Some("operation") => {
                                let op_id = cmd["operation_id"].as_str().unwrap_or("unknown").to_string();
                                let workflow_id = cmd["workflow_id"].as_str().unwrap_or("").to_string();
                                let op_type = cmd["op_type"].as_str().unwrap_or("").to_string();
                                let consumption = cmd["consumption"].as_str().unwrap_or("single").to_string();
                                let pre_claimed = cmd["pre_claimed"].as_bool().unwrap_or(false);
                                let data = cmd["data"].clone();

                                // Don't print one line per received message - in a DS scan a
                                // node sees thousands of ops in a flash. The "Claimed N" /
                                // "Skipped N" running counters below give us the same picture
                                // without the spam. Print only the first few + at log-worthy
                                // checkpoints (claim site already does that).

                                let pub_clone = publisher.clone();
                                let status_subj = status_subject.clone();
                                let result_subj = format!("cfx.results.{}", node_id);
                                let node_id = node_id.clone();
                                let http = http_client.clone();
                                let api_url = api_url.clone();

                                tokio::spawn(async move {
                                    // For DS port-scan ops, gate on the workflow's
                                    // per-workflow concurrency permit BEFORE claiming.
                                    // This keeps unclaimed ops available to other
                                    // nodes if this one is at capacity, and ensures
                                    // we genuinely run only `tasks` probes at a time
                                    // - the next op claims as soon as one finishes.
                                    let _ws_permit = if op_type == "network-scan-ds" || op_type == "content-discovery-ds" {
                                        // Port-scan DS uses `tasks`; content-discovery DS uses
                                        // `threads`. Either way it's the workflow-level
                                        // concurrency the user picked in the wizard.
                                        let n = data["tasks"].as_i64()
                                            .or_else(|| data["threads"].as_i64())
                                            .unwrap_or(10)
                                            .max(1) as usize;
                                        let sem = workflow_semaphore(&workflow_id, n);
                                        Some(sem.acquire_owned().await.ok())
                                    } else {
                                        None
                                    };

                                    // The operator may have halted this workflow
                                    // while we were waiting on the semaphore. Drop
                                    // the permit and exit without doing work.
                                    if !workflow_id.is_empty() && is_workflow_cancelled(&workflow_id) {
                                        return;
                                    }

                                    // Already completed this op (a pause/resume or the
                                    // server's stuck-op watchdog can re-dispatch an op
                                    // whose first copy already ran). Don't probe twice -
                                    // but DO re-publish the completion ack, because a
                                    // re-dispatch usually means the original ack was
                                    // dropped by NATS Core. Silently returning is what
                                    // leaves a scan parked at 9x% on lost acks.
                                    if op_is_done(&op_id) {
                                        let reack = serde_json::json!({
                                            "type": "operation_completed",
                                            "operation_id": op_id,
                                            "workflow_id": workflow_id,
                                            "found_count": 0,
                                            "node_id": node_id,
                                        });
                                        let _ = pub_clone
                                            .publish(status_subj.clone(), reack.to_string().into())
                                            .await;
                                        return;
                                    }

                                    // Track in-flight count through the rest of the
                                    // closure. Print a stat line on every claim so
                                    // the operator can see the throttle in action -
                                    // each line tells them which op just started
                                    // and how many are now active vs done.
                                    let _flight = if !workflow_id.is_empty() {
                                        let m = workflow_metrics(&workflow_id);
                                        let g = InFlightGuard::start(m.clone());
                                        use std::sync::atomic::Ordering;
                                        let ifl = m.in_flight.load(Ordering::Relaxed);
                                        let done = m.completed.load(Ordering::Relaxed);
                                        let fail = m.errored.load(Ordering::Relaxed);
                                        let short = workflow_id.get(..8).unwrap_or(&workflow_id);
                                        println!("[scan {}] claim in_flight={} done={} failed={}",
                                                 short, ifl, done, fail);
                                        Some(g)
                                    } else { None };

                                    // For single-consumption ops, try to claim
                                    // it first - unless the controller marked it
                                    // pre_claimed (1-node-assigned ops have no
                                    // race to win, so we skip the HTTP round-trip).
                                    if consumption == "single" && !pre_claimed {
                                        let claim_res = http
                                            .post(&format!("{}/api/v1/claim-operation", api_url))
                                            .json(&serde_json::json!({
                                                "operation_id": op_id,
                                                "node_id": node_id,
                                            }))
                                            .send()
                                            .await;

                                        let claimed = match claim_res {
                                            Ok(res) if res.status().is_success() => {
                                                let body: serde_json::Value = res.json().await.unwrap_or_default();
                                                body["data"]["claimed"].as_bool().unwrap_or(false)
                                            }
                                            _ => false,
                                        };

                                        use std::sync::atomic::Ordering;
                                        if !claimed {
                                            // Counter still tracked for the periodic
                                            // snapshot below; per-event log dropped.
                                            CLAIM_MISS.fetch_add(1, Ordering::Relaxed);
                                            return;
                                        }
                                        CLAIM_OK.fetch_add(1, Ordering::Relaxed);
                                    } else if pre_claimed {
                                        use std::sync::atomic::Ordering;
                                        CLAIM_OK.fetch_add(1, Ordering::Relaxed);
                                    }
                                    // For content-discovery-*, talk directly to mach daemon
                                    if op_type.starts_with("content-discovery-") {
                                        let mode = data["mode"].as_str().unwrap_or("batch");

                                        // DS probe mode: single URL probe via mach
                                        if mode == "probe" {
                                            let probe_url = data["probe_url"].as_str().unwrap_or("");
                                            let method = data["method"].as_str().unwrap_or("GET").to_lowercase();
                                            let success_codes_str = data["success_codes"].as_str().unwrap_or("200,201,301,302,403");
                                            let codes: Vec<u16> = success_codes_str.split(',')
                                                .filter_map(|s| s.trim().parse().ok()).collect();

                                            // Per-slot pacing: sleep WHILE holding the semaphore
                                            // permit so the wizard's "delay" actually throttles
                                            // the rate. tasks=10 + delay=20ms => floor of ~500/sec.
                                            let delay_ms = data["delay"].as_i64().unwrap_or(0).max(0) as u64;
                                            if delay_ms > 0 {
                                                tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                                            }

                                            let mach_req = serde_json::json!({
                                                "operation": "probe",
                                                "response": "instant",
                                                "url": probe_url,
                                                "method": method,
                                                "success_codes": codes,
                                                "volatility": 0,
                                                "operation_id": op_id,
                                                // Wizard "Follow Redirects" toggle (default off).
                                                "follow_redirects": data["follow_redirects"].as_bool().unwrap_or(false),
                                            });

                                            let conn = tokio::net::TcpStream::connect("127.0.0.1:4441").await;
                                            match conn {
                                                Ok(stream) => {
                                                    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                                                    let (reader, mut writer) = stream.into_split();
                                                    let mut req_str = serde_json::to_string(&mach_req).unwrap();
                                                    req_str.push('\n');
                                                    let _ = writer.write_all(req_str.as_bytes()).await;

                                                    let mut lines = BufReader::new(reader).lines();
                                                    // Bound the wait. If mach connects but never
                                                    // answers (target stopped responding, or mach
                                                    // wedged on this URL), don't deadlock the op
                                                    // forever - time out and fall through to the
                                                    // completion ack below so the scan advances.
                                                    let read = tokio::time::timeout(
                                                        std::time::Duration::from_secs(30),
                                                        lines.next_line(),
                                                    )
                                                    .await;
                                                    if let Ok(Ok(Some(line))) = read {
                                                        if let Ok(resp) = serde_json::from_str::<serde_json::Value>(&line) {
                                                            let status = resp["status"].as_str().unwrap_or("");
                                                            let code = resp["code"].as_i64().unwrap_or(0);
                                                            let body_len = resp["body_length"].as_i64().unwrap_or(0);

                                                            if status == "found" {
                                                                let result_msg = serde_json::json!({
                                                                    "type": "result",
                                                                    "job_id": format!("{}-{}", workflow_id, op_id),
                                                                    "workflow_id": workflow_id,
                                                                    "data": {
                                                                        "target": probe_url,
                                                                        "type": "endpoint",
                                                                        "status_code": code,
                                                                        "body_length": body_len,
                                                                        "source": "mach",
                                                                        "operation_id": op_id,
                                                                        "word": data["word"].as_str().unwrap_or(""),
                                                                    }
                                                                });
                                                                let _ = pub_clone.publish(
                                                                    result_subj.clone(),
                                                                    result_msg.to_string().into()
                                                                ).await;
                                                                println!("[op] OK FOUND {} [{}]", probe_url, code);
                                                            } else {
                                                                // Not found - no result published
                                                            }
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    eprintln!("[op] FAIL Cannot connect to mach daemon: {}", e);
                                                }
                                            }

                                            // Signal completion for this single probe
                                            let done_msg = serde_json::json!({
                                                "type": "completed",
                                                "job_id": format!("{}-{}", workflow_id, op_id),
                                                "workflow_id": workflow_id,
                                                "code": 0
                                            });
                                            let _ = pub_clone.publish(result_subj, done_msg.to_string().into()).await;

                                            mark_op_done(&op_id);
                                            let status_msg = serde_json::json!({
                                                "type": "operation_completed",
                                                "operation_id": op_id,
                                                "workflow_id": workflow_id,
                                                "found_count": if data["probe_url"].is_string() { 1 } else { 0 },
                                                "node_id": node_id,
                                            });
                                            let _ = pub_clone.publish(status_subj, status_msg.to_string().into()).await;
                                            return;
                                        }

                                        // Batch/stream mode: full scan via mach
                                        let url = data["url"].as_str().unwrap_or("");
                                        let method = data["method"].as_str().unwrap_or("GET");
                                        let threads = data["threads"].as_i64().unwrap_or(10);
                                        let success_codes_str = data["success_codes"].as_str().unwrap_or("200,201,301,302,403");

                                        // Download wordlist - supports both formats:
                                        // DB mode: "wordlist_url" (single presigned chunk URL)
                                        // SB mode: "wordlists" array with [{ id, url }]
                                        let mut wordlist_path = String::new();

                                        if let Some(wl_url) = data["wordlist_url"].as_str() {
                                            // DB mode: single chunk URL
                                            if !wl_url.is_empty() {
                                                let tmp = format!("/tmp/cfx-wl-chunk-{}.txt", op_id);
                                                println!("[op] Downloading wordlist chunk...");
                                                if let Ok(resp) = reqwest::get(wl_url).await {
                                                    if let Ok(body) = resp.text().await {
                                                        let _ = std::fs::write(&tmp, &body);
                                                        wordlist_path = tmp;
                                                        let lines = body.lines().count();
                                                        println!("[op] OK Chunk downloaded ({} lines, {} bytes)", lines, body.len());
                                                    }
                                                }
                                            }
                                        } else if let Some(wls) = data["wordlists"].as_array() {
                                            // SB mode: array of wordlists
                                            if let Some(first) = wls.first() {
                                                let dl_url = first["url"].as_str().unwrap_or("");
                                                if !dl_url.is_empty() {
                                                    let wl_id = first["id"].as_str().unwrap_or("wordlist");
                                                    let tmp = format!("/tmp/cfx-wl-{}.txt", wl_id);
                                                    println!("[op] Downloading wordlist: {}", wl_id);
                                                    if let Ok(resp) = reqwest::get(dl_url).await {
                                                        if let Ok(body) = resp.text().await {
                                                            let _ = std::fs::write(&tmp, &body);
                                                            wordlist_path = tmp;
                                                            println!("[op] OK Wordlist downloaded ({} bytes)", body.len());
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        if wordlist_path.is_empty() {
                                            // Fallback to local common.txt
                                            wordlist_path = "/opt/crossfyre/wordlists/common.txt".to_string();
                                            if !std::path::Path::new(&wordlist_path).exists() {
                                                eprintln!("[op] FAIL No wordlist available");
                                                let msg = serde_json::json!({
                                                    "type": "completed", "job_id": op_id,
                                                    "code": 1
                                                });
                                                let _ = pub_clone.publish(result_subj, msg.to_string().into()).await;
                                                return;
                                            }
                                        }

                                        // Build mach endpoint
                                        let endpoint = if url.contains("::FUZZ::") {
                                            url.to_string()
                                        } else {
                                            format!("{}/::FUZZ::", url.trim_end_matches('/'))
                                        };

                                        // Parse success codes
                                        let codes: Vec<u16> = success_codes_str.split(',')
                                            .filter_map(|s| s.trim().parse().ok())
                                            .collect();

                                        let delay = data["delay"].as_i64().unwrap_or(0).max(0);

                                        println!("[op] mach scan: {} method={} threads={} delay={}ms wordlist={} mode={}",
                                            endpoint, method, threads, delay, wordlist_path, mode);

                                        // Connect to mach daemon on port 4441. Pass `delay` so
                                        // mach's internal pacing matches the wizard's setting -
                                        // mach honors it the same way pulse does.
                                        let mach_req = serde_json::json!({
                                            "operation": "scan",
                                            "response": "stream",
                                            "endpoint": endpoint,
                                            "wordlist": wordlist_path,
                                            "method": method.to_lowercase(),
                                            "tasks": threads,
                                            "delay": delay,
                                            "success_status_codes": codes,
                                            "fresh_start": true,
                                        });

                                        let conn = tokio::net::TcpStream::connect("127.0.0.1:4441").await;
                                        match conn {
                                            Ok(stream) => {
                                                use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                                                let (reader, mut writer) = stream.into_split();
                                                let mut req_str = serde_json::to_string(&mach_req).unwrap();
                                                req_str.push('\n');
                                                let _ = writer.write_all(req_str.as_bytes()).await;

                                                let mut lines = BufReader::new(reader).lines();
                                                let mut found_count = 0;
                                                let mut total_events = 0;

                                                while let Ok(Some(line)) = lines.next_line().await {
                                                    if line.trim().is_empty() { continue; }
                                                    total_events += 1;
                                                    if let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) {
                                                        let evt_type = event["type"].as_str().unwrap_or("");

                                                        // Log first few events and all non-result events for debugging
                                                        if total_events <= 3 || (evt_type != "result") {
                                                            println!("[op] mach event #{}: type={} status={}",
                                                                total_events, evt_type,
                                                                event["status"].as_str().unwrap_or("-"));
                                                        }

                                                        match evt_type {
                                                            "result" if event["status"].as_str() == Some("found") => {
                                                                found_count += 1;
                                                                let result_msg = serde_json::json!({
                                                                    "type": "result",
                                                                    "job_id": format!("{}-{}", workflow_id, op_id),
                                                                    "workflow_id": workflow_id,
                                                                    "data": {
                                                                        "target": event["url"].as_str().unwrap_or(url),
                                                                        "type": "endpoint",
                                                                        "status_code": event["code"],
                                                                        "body_length": event["body_length"],
                                                                        "source": "mach",
                                                                        "operation_id": op_id,
                                                                    }
                                                                });
                                                                let _ = pub_clone.publish(
                                                                    result_subj.clone(),
                                                                    result_msg.to_string().into()
                                                                ).await;
                                                            }
                                                            "done" => {
                                                                println!("[op] OK Scan complete: {} found out of {} events", found_count, total_events);
                                                                break;
                                                            }
                                                            "error" => {
                                                                let msg = event["message"].as_str().unwrap_or("unknown error");
                                                                eprintln!("[op] FAIL mach error: {}", msg);
                                                                break;
                                                            }
                                                            _ => {} // ack, progress, not_found - skip
                                                        }
                                                    }
                                                }

                                                // Signal completion
                                                let done_msg = serde_json::json!({
                                                    "type": "completed",
                                                    "job_id": format!("{}-{}", workflow_id, op_id),
                                                    "workflow_id": workflow_id,
                                                    "code": 0
                                                });
                                                let _ = pub_clone.publish(result_subj, done_msg.to_string().into()).await;

                                                // Report on status channel
                                                mark_op_done(&op_id);
                                                let status_msg = serde_json::json!({
                                                    "type": "operation_completed",
                                                    "operation_id": op_id,
                                                    "workflow_id": workflow_id,
                                                    "found_count": found_count,
                                                    "node_id": node_id,
                                                });
                                                let _ = pub_clone.publish(status_subj, status_msg.to_string().into()).await;
                                            }
                                            Err(e) => {
                                                eprintln!("[op] FAIL Cannot connect to mach daemon: {}", e);
                                                let msg = serde_json::json!({
                                                    "type": "completed",
                                                    "job_id": format!("{}-{}", workflow_id, op_id),
                                                    "code": 1
                                                });
                                                let _ = pub_clone.publish(result_subj, msg.to_string().into()).await;
                                            }
                                        }
                                    } else if op_type.starts_with("subdomain-enum-") {
                                        // Subdomain enumeration via voyage daemon (port 4442)
                                        let domain = data["domain"].as_str().unwrap_or("").to_string();
                                        let threads = data["threads"].as_i64().unwrap_or(10);
                                        let delay = data["delay"].as_i64().unwrap_or(0).max(0);
                                        let disable_passive = data["disable_passive"].as_bool().unwrap_or(false);
                                        let disable_active = data["disable_active"].as_bool().unwrap_or(false);

                                        // Download wordlist for active enum if available
                                        let mut wordlist_path = String::new();
                                        if !disable_active {
                                            if let Some(wl_url) = data["wordlist_url"].as_str() {
                                                if !wl_url.is_empty() {
                                                    let tmp = format!("/tmp/cfx-wl-sub-{}.txt", op_id);
                                                    if let Ok(resp) = reqwest::get(wl_url).await {
                                                        if let Ok(body) = resp.text().await {
                                                            let _ = std::fs::write(&tmp, &body);
                                                            wordlist_path = tmp;
                                                        }
                                                    }
                                                }
                                            } else if let Some(wls) = data["wordlists"].as_array() {
                                                if let Some(first) = wls.first() {
                                                    let dl_url = first["url"].as_str().unwrap_or("");
                                                    if !dl_url.is_empty() {
                                                        let tmp = format!("/tmp/cfx-wl-sub-{}.txt", first["id"].as_str().unwrap_or("wl"));
                                                        if let Ok(resp) = reqwest::get(dl_url).await {
                                                            if let Ok(body) = resp.text().await {
                                                                let _ = std::fs::write(&tmp, &body);
                                                                wordlist_path = tmp;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        println!("[op] voyage enum: {} passive={} active={} threads={} delay={}ms",
                                            domain, !disable_passive, !disable_active, threads, delay);

                                        let voyage_req = serde_json::json!({
                                            "operation": "enum",
                                            "response": "stream",
                                            "domain": domain,
                                            "wordlist": wordlist_path,
                                            "tasks": threads,
                                            "delay": delay,
                                            "fresh_start": true,
                                            "disable_passive": disable_passive,
                                            "disable_active": disable_active,
                                            "dns_server": data["dns_server"].as_str().unwrap_or(""),
                                        });

                                        let conn = tokio::net::TcpStream::connect("127.0.0.1:4442").await;
                                        match conn {
                                            Ok(stream) => {
                                                use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                                                let (reader, mut writer) = stream.into_split();
                                                let mut req_str = serde_json::to_string(&voyage_req).unwrap();
                                                req_str.push('\n');
                                                let _ = writer.write_all(req_str.as_bytes()).await;

                                                let mut lines = BufReader::new(reader).lines();
                                                let mut found_count = 0;
                                                let mut total_events = 0;
                                                // Phase + progress: voyage's "ack" carries the total candidate count
                                                // (active = wordlist size); each "result" is one processed candidate.
                                                // Forward a throttled progress signal for "Active: 1,234 / 5,000".
                                                let phase = data["phase"].as_str().or_else(|| data["mode"].as_str()).unwrap_or("active").to_string();
                                                let mut total: i64 = 0;
                                                let mut processed: i64 = 0;
                                                let mut last_prog = std::time::Instant::now();
                                                let emit_progress = |processed: i64, total: i64, found: i64| {
                                                    let p = pub_clone.clone();
                                                    let subj = status_subj.clone();
                                                    let oid = op_id.clone();
                                                    let wid = workflow_id.to_string();
                                                    let ph = phase.clone();
                                                    let nid = node_id.clone();
                                                    async move {
                                                        let msg = serde_json::json!({
                                                            "type": "operation_progress", "operation_id": oid, "workflow_id": wid,
                                                            "phase": ph, "processed": processed, "total": total,
                                                            "found_count": found, "node_id": nid,
                                                        });
                                                        let _ = p.publish(subj, msg.to_string().into()).await;
                                                    }
                                                };

                                                while let Ok(Some(line)) = lines.next_line().await {
                                                    if line.trim().is_empty() { continue; }
                                                    // Operator paused/stopped the workflow: quit forwarding so
                                                    // results stop appearing. The op stays 'running' (not marked
                                                    // done), so resume re-dispatches and re-runs it.
                                                    if !workflow_id.is_empty() && is_workflow_cancelled(&workflow_id) {
                                                        println!("[op] subdomain enum cancelled (workflow paused) - stopping stream");
                                                        return;
                                                    }
                                                    total_events += 1;
                                                    if let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) {
                                                        let evt_type = event["type"].as_str().unwrap_or("");

                                                        if total_events <= 3 || evt_type != "result" {
                                                            println!("[op] voyage event #{}: type={} status={}",
                                                                total_events, evt_type,
                                                                event["status"].as_str().unwrap_or("-"));
                                                        }

                                                        match evt_type {
                                                            "ack" => {
                                                                total = event["total"].as_i64().unwrap_or(0);
                                                                println!("[progress] phase={} total={} (voyage ack) - emitting operation_progress", phase, total);
                                                                emit_progress(0, total, 0).await;
                                                            }
                                                            "result" => {
                                                                processed += 1;
                                                                if event["status"].as_str() == Some("found") {
                                                                    found_count += 1;
                                                                    let subdomain = event["subdomain"].as_str().unwrap_or("");
                                                                    let source = event["source"].as_str().unwrap_or("unknown");
                                                                    let result_msg = serde_json::json!({
                                                                        "type": "result",
                                                                        "job_id": format!("{}-{}", workflow_id, op_id),
                                                                        "workflow_id": workflow_id,
                                                                        "data": {
                                                                            "target": subdomain,
                                                                            "type": "subdomain",
                                                                            "source": source,
                                                                            "domain": domain,
                                                                            "operation_id": op_id,
                                                                        }
                                                                    });
                                                                    let _ = pub_clone.publish(result_subj.clone(), result_msg.to_string().into()).await;
                                                                }
                                                                if last_prog.elapsed() >= std::time::Duration::from_millis(1500) {
                                                                    println!("[progress] phase={} {}/{} processed", phase, processed, total);
                                                                    emit_progress(processed, total, found_count).await;
                                                                    last_prog = std::time::Instant::now();
                                                                }
                                                            }
                                                            "done" => {
                                                                println!("[op] OK Enum complete: {} subdomains found ({} events)", found_count, total_events);
                                                                emit_progress(if total > 0 { total } else { processed }, total, found_count).await;
                                                                break;
                                                            }
                                                            "error" => {
                                                                let msg = event["message"].as_str().unwrap_or("unknown");
                                                                eprintln!("[op] FAIL voyage error: {}", msg);
                                                                break;
                                                            }
                                                            _ => {}
                                                        }
                                                    }
                                                }

                                                let done_msg = serde_json::json!({
                                                    "type": "completed",
                                                    "job_id": format!("{}-{}", workflow_id, op_id),
                                                    "workflow_id": workflow_id,
                                                    "code": 0
                                                });
                                                let _ = pub_clone.publish(result_subj, done_msg.to_string().into()).await;

                                                mark_op_done(&op_id);
                                                let status_msg = serde_json::json!({
                                                    "type": "operation_completed",
                                                    "operation_id": op_id,
                                                    "workflow_id": workflow_id,
                                                    "found_count": found_count,
                                                    "node_id": node_id,
                                                });
                                                let _ = pub_clone.publish(status_subj, status_msg.to_string().into()).await;
                                            }
                                            Err(e) => {
                                                eprintln!("[op] FAIL Cannot connect to voyage daemon: {}", e);
                                                let msg = serde_json::json!({
                                                    "type": "completed",
                                                    "job_id": format!("{}-{}", workflow_id, op_id),
                                                    "workflow_id": workflow_id,
                                                    "code": 1
                                                });
                                                let _ = pub_clone.publish(result_subj, msg.to_string().into()).await;
                                            }
                                        }
                                    } else if op_type.starts_with("network-scan-") {
                                        // Single-port probe mode (DS strategy): data has host+port
                                        if let Some(host) = data["host"].as_str().map(|s| s.to_string()) {
                                            let port = data["port"].as_u64().unwrap_or(0) as u16;
                                            let timeout_ms = data["timeout"].as_i64().unwrap_or(2000);
                                            let delay_ms = data["delay"].as_i64().unwrap_or(0).max(0) as u64;
                                            let service_detection = data["service_detection"].as_bool().unwrap_or(true);

                                            // Per-probe delay - sleeps WHILE holding the
                                            // semaphore permit, so it actually paces the
                                            // workflow's effective rate. e.g. tasks=10 +
                                            // delay=20ms => floor of ~500 probes/sec
                                            // (10 / 20ms = 500/s).
                                            if delay_ms > 0 {
                                                tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                                            }

                                            // Use the same `scan` engine path SB/DB use, just
                                            // with a single-port array. This way DS shares the
                                            // exact same code in pulse that's been validated to
                                            // find every open port - the older `probe` mode had
                                            // a subtle reliability gap where some opens were
                                            // returned as the default-closed when run_connect_scan's
                                            // result event raced with the channel close.
                                            // Concurrency is already gated by `_ws_permit`.
                                            let pulse_req = serde_json::json!({
                                                "operation": "scan",
                                                "response": "instant",
                                                "save": false,
                                                "targets": [host],
                                                "ports": [port],
                                                "tasks": 1,
                                                "timeout": timeout_ms,
                                                "service_detection": service_detection,
                                            });

                                            let short_op = op_id.get(..8).unwrap_or(&op_id).to_string();
                                            // Log every probe response while we're debugging the
                                            // DS-vs-SB discrepancy. Noisy but definitive: we'll
                                            // see exactly what pulse says about every port and
                                            // can grep for known-open ones (53, 80, 5432, etc).
                                            let log_sample = true;
                                            let mut found_count = 0;
                                            let conn = tokio::net::TcpStream::connect("127.0.0.1:4443").await;
                                            match conn {
                                                Ok(stream) => {
                                                    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                                                    // RST-close so this per-op connection to pulse doesn't pile
                                                    // up TIME_WAIT sockets and exhaust ephemeral ports on a big scan.
                                                    let _ = stream.set_linger(Some(std::time::Duration::ZERO));
                                                    let (reader, mut writer) = stream.into_split();
                                                    let mut req_str = serde_json::to_string(&pulse_req).unwrap();
                                                    req_str.push('\n');
                                                    if log_sample {
                                                        println!("[ds {} {}:{}] -> probe sent ({} bytes)", short_op, host, port, req_str.len());
                                                    }
                                                    if let Err(e) = writer.write_all(req_str.as_bytes()).await {
                                                        eprintln!("[ds {} {}:{}] write failed: {}", short_op, host, port, e);
                                                    }

                                                    let mut lines = BufReader::new(reader).lines();
                                                    match lines.next_line().await {
                                                        Ok(Some(line)) => {
                                                            // Always log a snippet of the raw response on the
                                                            // sampled probes so we can see the actual shape.
                                                            if log_sample {
                                                                let snippet = &line[..line.len().min(250)];
                                                                println!("[ds {} {}:{}] <- pulse: {}", short_op, host, port, snippet);
                                                            }
                                                            if let Ok(resp) = serde_json::from_str::<serde_json::Value>(&line) {
                                                                let results_arr = resp["results"].as_array().cloned().unwrap_or_default();
                                                                if log_sample {
                                                                    println!("[ds {} {}:{}] parsed: results.len={}, top.status={:?}",
                                                                        short_op, host, port,
                                                                        results_arr.len(),
                                                                        resp["status"].as_str().unwrap_or("?"));
                                                                }
                                                                if let Some(result) = results_arr.first() {
                                                                    let status = result["status"].as_str().unwrap_or("");
                                                                    if status == "open" || status == "filtered" {
                                                                        found_count = 1;
                                                                        let msg = serde_json::json!({
                                                                            "type": "result",
                                                                            "job_id": format!("{}-{}", workflow_id, op_id),
                                                                            "workflow_id": workflow_id,
                                                                            "operation_id": op_id,
                                                                            "data": {
                                                                                "host": host,
                                                                                "port": port,
                                                                                "status": status,
                                                                                "service": result["service"],
                                                                                "banner": result["banner"],
                                                                                "latency_ms": result["latency_ms"],
                                                                            }
                                                                        });
                                                                        match pub_clone.publish(result_subj.clone(), msg.to_string().into()).await {
                                                                            Err(e) => eprintln!("[ds {} {}:{}] result publish failed: {}", short_op, host, port, e),
                                                                            Ok(_)  => println!("[ds {} {}:{}] OPEN service={} latency={}",
                                                                                short_op, host, port,
                                                                                result["service"].as_str().unwrap_or("?"),
                                                                                result["latency_ms"].as_u64().unwrap_or(0)),
                                                                        }
                                                                    }
                                                                }
                                                                if resp.get("results").is_none() && resp.get("status").and_then(|s| s.as_str()) != Some("error") {
                                                                    eprintln!("[ds {} {}:{}] WEIRD response (no results field): {}", short_op, host, port, &line[..line.len().min(300)]);
                                                                }
                                                            } else {
                                                                eprintln!("[ds {} {}:{}] non-JSON response: {}", short_op, host, port, &line[..line.len().min(300)]);
                                                            }
                                                        }
                                                        Ok(None) => {
                                                            eprintln!("[ds {} {}:{}] pulse closed connection without response", short_op, host, port);
                                                        }
                                                        Err(e) => {
                                                            eprintln!("[ds {} {}:{}] read error: {}", short_op, host, port, e);
                                                        }
                                                    }

                                                    let done_msg = serde_json::json!({
                                                        "type": "completed",
                                                        "job_id": format!("{}-{}", workflow_id, op_id),
                                                        "workflow_id": workflow_id,
                                                        "code": 0
                                                    });
                                                    if let Err(e) = pub_clone.publish(result_subj, done_msg.to_string().into()).await {
                                                        eprintln!("[ds {} {}:{}] completed publish failed: {}", short_op, host, port, e);
                                                    } else if log_sample {
                                                        println!("[ds {} {}:{}] -> completed published (found={})", short_op, host, port, found_count);
                                                    }

                                                    mark_op_done(&op_id);
                                                    let status_msg = serde_json::json!({
                                                        "type": "operation_completed",
                                                        "operation_id": op_id,
                                                        "workflow_id": workflow_id,
                                                        "found_count": found_count,
                                                        "node_id": node_id,
                                                    });
                                                    if let Err(e) = pub_clone.publish(status_subj, status_msg.to_string().into()).await {
                                                        eprintln!("[ds {} {}:{}] operation_completed publish failed: {}", short_op, host, port, e);
                                                    }
                                                }
                                                Err(e) => {
                                                    // The workflow view already shows a "Fix" button
                                                    // based on the heartbeat-reported extension_status,
                                                    // so we don't spam node_logs here. Just rate-limited
                                                    // local stderr for operator-side debugging.
                                                    use std::sync::atomic::{AtomicU64, Ordering};
                                                    static LAST_LOG: AtomicU64 = AtomicU64::new(0);
                                                    let now_secs = std::time::SystemTime::now()
                                                        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                                                    if now_secs.saturating_sub(LAST_LOG.load(Ordering::Relaxed)) >= 60 {
                                                        LAST_LOG.store(now_secs, Ordering::Relaxed);
                                                        eprintln!("[op] FAIL pulse daemon unreachable on 127.0.0.1:4443 ({}). Is `pulse --daemon` running? (suppressing further messages for 60s)", e);
                                                    }
                                                    let msg = serde_json::json!({
                                                        "type": "completed",
                                                        "job_id": format!("{}-{}", workflow_id, op_id),
                                                        "workflow_id": workflow_id,
                                                        "code": 1
                                                    });
                                                    let _ = pub_clone.publish(result_subj, msg.to_string().into()).await;
                                                }
                                            }
                                            return;
                                        }

                                        // Batch scan mode (SB / DB strategies): data has targets+ports arrays
                                        let targets: Vec<String> = data["targets"]
                                            .as_array()
                                            .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                                            .unwrap_or_default();
                                        let ports_value = data["ports"].clone();
                                        let tasks = data["tasks"].as_i64().unwrap_or(100);
                                        let timeout = data["timeout"].as_i64().unwrap_or(2000);
                                        let delay = data["delay"].as_i64().unwrap_or(0).max(0);
                                        let service_detection = data["service_detection"].as_bool().unwrap_or(true);

                                        println!("[op] pulse scan: {} targets, ports={}, {} tasks, delay={}ms",
                                            targets.len(), ports_value, tasks, delay);

                                        let pulse_req = serde_json::json!({
                                            "operation": "scan",
                                            "response": "stream",
                                            "save": false,
                                            "targets": targets,
                                            "ports": ports_value,
                                            "tasks": tasks,
                                            "timeout": timeout,
                                            "delay": delay,
                                            "service_detection": service_detection,
                                        });

                                        let conn = tokio::net::TcpStream::connect("127.0.0.1:4443").await;
                                        match conn {
                                            Ok(stream) => {
                                                use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                                                // RST-close so this per-op connection to pulse doesn't pile
                                                // up TIME_WAIT sockets and exhaust ephemeral ports on a big scan.
                                                let _ = stream.set_linger(Some(std::time::Duration::ZERO));
                                                let (reader, mut writer) = stream.into_split();
                                                let mut req_str = serde_json::to_string(&pulse_req).unwrap();
                                                req_str.push('\n');
                                                let _ = writer.write_all(req_str.as_bytes()).await;

                                                let mut lines = BufReader::new(reader).lines();
                                                let mut found_count = 0;
                                                let mut total_events = 0;

                                                while let Ok(Some(line)) = lines.next_line().await {
                                                    if let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) {
                                                        total_events += 1;
                                                        let event_type = event["type"].as_str().unwrap_or("");

                                                        match event_type {
                                                            "result" => {
                                                                // Only report open/filtered ports as findings (skip closed to reduce noise)
                                                                if event["status"].as_str() == Some("closed") { continue; }
                                                                found_count += 1;
                                                                let result_msg = serde_json::json!({
                                                                    "type": "result",
                                                                    "job_id": format!("{}-{}", workflow_id, op_id),
                                                                    "workflow_id": workflow_id,
                                                                    "operation_id": op_id,
                                                                    "data": {
                                                                        "host": event["host"],
                                                                        "port": event["port"],
                                                                        "status": event["status"],
                                                                        "service": event["service"],
                                                                        "banner": event["banner"],
                                                                        "latency_ms": event["latency_ms"],
                                                                    }
                                                                });
                                                                let _ = pub_clone.publish(
                                                                    result_subj.clone(),
                                                                    result_msg.to_string().into()
                                                                ).await;
                                                            }
                                                            "done" => {
                                                                println!("[op] OK Scan complete: {} open ports found ({} events)", found_count, total_events);
                                                                break;
                                                            }
                                                            "error" => {
                                                                let msg = event["message"].as_str().unwrap_or("unknown");
                                                                eprintln!("[op] FAIL pulse error: {}", msg);
                                                                break;
                                                            }
                                                            _ => {}
                                                        }
                                                    }
                                                }

                                                let done_msg = serde_json::json!({
                                                    "type": "completed",
                                                    "job_id": format!("{}-{}", workflow_id, op_id),
                                                    "workflow_id": workflow_id,
                                                    "code": 0
                                                });
                                                let _ = pub_clone.publish(result_subj, done_msg.to_string().into()).await;

                                                mark_op_done(&op_id);
                                                let status_msg = serde_json::json!({
                                                    "type": "operation_completed",
                                                    "operation_id": op_id,
                                                    "workflow_id": workflow_id,
                                                    "found_count": found_count,
                                                    "node_id": node_id,
                                                });
                                                let _ = pub_clone.publish(status_subj, status_msg.to_string().into()).await;
                                            }
                                            Err(e) => {
                                                use std::sync::atomic::{AtomicU64, Ordering};
                                                static LAST_LOG: AtomicU64 = AtomicU64::new(0);
                                                let now_secs = std::time::SystemTime::now()
                                                    .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                                                if now_secs.saturating_sub(LAST_LOG.load(Ordering::Relaxed)) >= 60 {
                                                    LAST_LOG.store(now_secs, Ordering::Relaxed);
                                                    eprintln!("[op] FAIL Cannot connect to pulse daemon: {} (suppressing further messages for 60s)", e);
                                                }
                                                let msg = serde_json::json!({
                                                    "type": "completed",
                                                    "job_id": format!("{}-{}", workflow_id, op_id),
                                                    "workflow_id": workflow_id,
                                                    "code": 1
                                                });
                                                let _ = pub_clone.publish(result_subj, msg.to_string().into()).await;
                                            }
                                        }
                                    } else {
                                        println!("[op] Unknown op_type: {}", op_type);
                                    }
                                });
                            }
                            Some("execute") => {
                                let job_id = cmd["job_id"].as_str().unwrap_or("unknown").to_string();
                                let script = cmd["script"].as_str().unwrap_or("").to_string();
                                let raw_targets = cmd["targets"].as_array();

                                let targets: Vec<(String, String)> = raw_targets
                                    .map(|arr| {
                                        arr.iter()
                                            .filter_map(|t| {
                                                let typ = t["type"].as_str()?;
                                                let val = t["value"].as_str()?;
                                                Some((typ.to_string(), val.to_string()))
                                            })
                                            .collect()
                                    })
                                    .unwrap_or_default();

                                println!("\n[execute] job_id={} targets={} script_len={}",
                                    job_id, targets.len(), script.len());

                                let ctx = executor::JobContext {
                                    node_id: node_id.clone(),
                                    job_id: job_id.clone(),
                                    script,
                                    targets,
                                };
                                let pub_clone = publisher.clone();
                                let subj = format!("cfx.results.{}", node_id);
                                tokio::spawn(async move {
                                    let result = executor::execute_job(ctx, pub_clone, subj).await;
                                    match result {
                                        executor::ExecutionResult::Completed { code } =>
                                            println!("[execute] job={} completed code={}", job_id, code),
                                        executor::ExecutionResult::Error { message } =>
                                            eprintln!("[execute] job={} error: {}", job_id, message),
                                    }
                                });
                            }
                            Some("install_extension") => {
                                let ext = cmd["extension"].as_str().unwrap_or("").to_string();
                                println!("\n[install] Installing extension: {}", ext);

                                // Built-in package manager: download + verify +
                                // enable + start in one call.
                                let msg = match toolchain::install::install_and_start(&ext).await {
                                    Ok(()) => {
                                        println!("[install] OK {} installed and started", ext);
                                        serde_json::json!({
                                            "type": "extension_installed",
                                            "extension": ext,
                                            "started": true,
                                            "node_id": &node_id
                                        })
                                    }
                                    Err(e) => {
                                        eprintln!("[install] FAIL Failed to install {}: {}", ext, e);
                                        serde_json::json!({
                                            "type": "extension_install_failed",
                                            "extension": ext,
                                            "step": "install",
                                            "node_id": &node_id
                                        })
                                    }
                                };
                                let _ = publisher.publish(status_subject.clone(), msg.to_string().into()).await;
                            }
                            Some("start_postgres") => {
                                println!("\n[toolchain] Starting PostgreSQL...");
                                let success = match toolchain::db::ensure_up() {
                                    Ok(()) => { println!("[toolchain] OK PostgreSQL started"); true }
                                    Err(e) => { eprintln!("[toolchain] FAIL PostgreSQL failed to start: {}", e); false }
                                };

                                let msg = serde_json::json!({
                                    "type": "postgres_started",
                                    "success": success,
                                    "node_id": &node_id
                                });
                                let _ = publisher.publish(status_subject.clone(), msg.to_string().into()).await;
                            }
                            Some("update_node") => {
                                // Dashboard-triggered self-update from the release
                                // manifest. On success the new binary is on disk;
                                // exit non-zero so the node service's
                                // Restart=on-failure brings us back up as the new
                                // version (a clean exit would stay down).
                                println!("\n[update] Updating crossfyre from the release manifest...");
                                let updated = match toolchain::install::fetch_manifest().await {
                                    Ok(manifest) => toolchain::install::self_update(&manifest).await,
                                    Err(e) => Err(e),
                                };

                                let (success, restarting) = match &updated {
                                    Ok(true) => (true, true),
                                    Ok(false) => (true, false), // already current
                                    Err(e) => {
                                        eprintln!("[update] FAIL {}", e);
                                        (false, false)
                                    }
                                };

                                let msg = serde_json::json!({
                                    "type": "node_updated",
                                    "success": success,
                                    "restarting": restarting,
                                    "node_id": &node_id
                                });
                                let _ = publisher.publish(status_subject.clone(), msg.to_string().into()).await;

                                if restarting {
                                    println!("[update] Restarting to run the new version...");
                                    // Give the publish a moment to flush.
                                    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
                                    std::process::exit(7);
                                }
                            }
                            Some("remove_extension") => {
                                let ext = cmd["extension"].as_str().unwrap_or("").to_string();
                                println!("\n[remove] Removing extension: {}", ext);

                                let remove_ok = match toolchain::install::remove(&ext) {
                                    Ok(()) => { println!("[remove] OK {} removed", ext); true }
                                    Err(e) => { eprintln!("[remove] FAIL Failed to remove {}: {}", ext, e); false }
                                };

                                let msg = serde_json::json!({
                                    "type": "extension_removed",
                                    "extension": ext,
                                    "success": remove_ok,
                                    "node_id": &node_id
                                });
                                let _ = publisher.publish(status_subject.clone(), msg.to_string().into()).await;
                            }
                            Some("restart_extension") => {
                                let ext = cmd["extension"].as_str().unwrap_or("").to_string();
                                println!("\n[restart] Restarting extension: {}", ext);

                                let msg = match toolchain::service::restart(&ext) {
                                    Ok(()) => {
                                        println!("[restart] OK {} restarted", ext);
                                        serde_json::json!({
                                            "type": "extension_restarted",
                                            "extension": ext,
                                            "success": true,
                                            "node_id": &node_id
                                        })
                                    }
                                    Err(e) => {
                                        eprintln!("[restart] FAIL Failed to restart {}: {}", ext, e);
                                        serde_json::json!({
                                            "type": "extension_restart_failed",
                                            "extension": ext,
                                            "success": false,
                                            "node_id": &node_id
                                        })
                                    }
                                };
                                let _ = publisher.publish(status_subject.clone(), msg.to_string().into()).await;
                            }
                            Some("reinstall_extension") => {
                                let ext = cmd["extension"].as_str().unwrap_or("").to_string();
                                println!("\n[reinstall] Reinstalling extension: {}", ext);

                                let success = match toolchain::install::install(&ext, true).await {
                                    Ok(()) => {
                                        println!("[reinstall] OK {} reinstalled, starting service...", ext);
                                        let _ = toolchain::service::start(&ext);
                                        true
                                    }
                                    Err(e) => {
                                        eprintln!("[reinstall] FAIL Failed to reinstall {}: {}", ext, e);
                                        false
                                    }
                                };

                                let msg = serde_json::json!({
                                    "type": if success { "extension_reinstalled" } else { "extension_reinstall_failed" },
                                    "extension": ext,
                                    "success": success,
                                    "node_id": &node_id
                                });
                                let _ = publisher.publish(status_subject.clone(), msg.to_string().into()).await;
                            }
                            Some("stop_extension") => {
                                let ext = cmd["extension"].as_str().unwrap_or("").to_string();
                                println!("\n[stop] Stopping extension: {}", ext);

                                let success = match toolchain::service::stop(&ext) {
                                    Ok(()) => { println!("[stop] OK {} stopped", ext); true }
                                    Err(e) => { eprintln!("[stop] FAIL Failed to stop {}: {}", ext, e); false }
                                };

                                let msg = serde_json::json!({
                                    "type": if success { "extension_stopped" } else { "extension_stop_failed" },
                                    "extension": ext,
                                    "success": success,
                                    "node_id": &node_id
                                });
                                let _ = publisher.publish(status_subject.clone(), msg.to_string().into()).await;
                            }
                            _ => {
                                println!("Received unknown job command: {}", body);
                            }
                        }
                    }
                }
            }
        }
    }

    println!("Node daemon stopped.");
    Ok(())
}

/// Run a .cfx script locally without NATS.  For development / testing.
///
/// Usage: crossfyre run tests/test.cfx domain:example.com domain:test.org
pub async fn run_script(
    script_path: &str,
    raw_targets: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let targets: Vec<(String, String)> = raw_targets
        .iter()
        .map(|s| {
            if let Some((t, v)) = s.split_once(':') {
                (t.to_string(), v.to_string())
            } else {
                // Default to "domain" if no type prefix
                ("domain".to_string(), s.to_string())
            }
        })
        .collect();

    println!("Running {} with {} target(s)...\n", script_path, targets.len());

    let result = executor::execute_local(script_path, targets).await;

    match result {
        executor::ExecutionResult::Completed { code } => {
            println!("\nScript finished with code {}", code);
        }
        executor::ExecutionResult::Error { message } => {
            eprintln!("\nScript failed: {}", message);
            std::process::exit(1);
        }
    }

    Ok(())
}
