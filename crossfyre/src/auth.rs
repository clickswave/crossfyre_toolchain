//! Account authentication for the `crossfyre` CLI (`crossfyre login`).
//!
//! Three methods all converge on the CLI holding a revocable *account API key*
//! (the `account_api_keys` table server-side), persisted to `<data_dir>/auth.toml`:
//!   - `--api-key <key>`              -> verify the pasted key
//!   - `--username <u> --password <p>`-> exchange credentials for a fresh key
//!   - no flags                       -> browser device-authorization flow
//!
//! With a session, `crossfyre node init` provisions a node server-side (no manual
//! node-key paste). Flags `--agree-tos` and `--no-prompt` make the flow
//! scriptable; mismatched/missing flags error rather than silently prompting.

use serde::{Deserialize, Serialize};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

/// The default control-plane origin. The CLI talks to web_server's public
/// `/api/v1/*` proxy (which injects the backend auth header), so this is the
/// public site origin, not api_switch directly. Override with `--api-url`.
///
/// Baked at build time per env (crossfyre_build sets CROSSFYRE_API_URL): a dev
/// build points at the local web (http://localhost:12004), staging at
/// staging.crossfyre.io, prod at crossfyre.io. Defaults to prod when unset.
pub const DEFAULT_API_URL: &str = match option_env!("CROSSFYRE_API_URL") {
    Some(u) => u,
    None => "https://crossfyre.io",
};

/// A short legal notice shown before the first login unless `--agree-tos`.
const TOS_NOTICE: &str = "\
  Crossfyre is an offensive security platform for AUTHORIZED penetration
  testing and security research only. By logging in you agree to the Terms of
  Service (https://crossfyre.io/terms) and Acceptable Use Policy, and confirm
  you are authorized to test the targets you operate against. Unauthorized use
  is illegal and strictly prohibited.";

/// Persisted account session. Stored at `<data_dir>/auth.toml`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Account {
    /// Control-plane origin this session authenticates against.
    pub api_url: String,
    /// Account API key (`cfk_...`) the CLI presents for account-scoped calls.
    pub api_key: String,
    pub user_id: String,
    pub username: String,
    pub email: String,
}

pub fn account_path(data_dir: &Path) -> PathBuf {
    data_dir.join("auth.toml")
}

pub fn load_account(data_dir: &Path) -> Option<Account> {
    let raw = std::fs::read_to_string(account_path(data_dir)).ok()?;
    toml::from_str(&raw).ok()
}

pub fn save_account(data_dir: &Path, account: &Account) -> Result<(), Box<dyn std::error::Error>> {
    if !data_dir.exists() {
        std::fs::create_dir_all(data_dir)?;
    }
    let path = account_path(data_dir);
    std::fs::write(&path, toml::to_string(account)?)?;
    // Keep it owner-readable only; it holds a credential.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    // Hand ownership back to the invoking user if we ran under sudo.
    crate::toolchain::sudo_user::chown_to_invoking_user(&path);
    Ok(())
}

pub fn clear_account(data_dir: &Path) -> bool {
    std::fs::remove_file(account_path(data_dir)).is_ok()
}

// ---- small environment helpers ----------------------------------------

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn os_label() -> String {
    format!("{} ({})", std::env::consts::OS, std::env::consts::ARCH)
}

fn cli_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn spawn_quiet(cmd: &str, args: &[&str]) -> bool {
    std::process::Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
}

/// Best-effort: open `url` in the operator's browser. Never fatal.
///
/// On Linux under `sudo`, root has no GUI session, so `xdg-open` as root does
/// nothing. Re-launch it as the invoking user ($SUDO_USER), preserving the
/// display/session env vars so it lands in their actual desktop session.
fn open_browser(url: &str) -> bool {
    if cfg!(target_os = "macos") {
        return spawn_quiet("open", &[url]);
    }
    if cfg!(target_os = "windows") {
        return spawn_quiet("cmd", &["/C", "start", "", url]);
    }
    #[cfg(unix)]
    {
        let euid = unsafe { libc::geteuid() };
        if euid == 0 {
            if let Ok(user) = std::env::var("SUDO_USER") {
                if !user.is_empty() && user != "root" {
                    if spawn_quiet(
                        "sudo",
                        &[
                            "-u",
                            &user,
                            "--preserve-env=DISPLAY,XDG_RUNTIME_DIR,DBUS_SESSION_BUS_ADDRESS,WAYLAND_DISPLAY,XAUTHORITY",
                            "xdg-open",
                            url,
                        ],
                    ) {
                        return true;
                    }
                }
            }
        }
    }
    spawn_quiet("xdg-open", &[url])
}

// ---- login orchestration -----------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Method {
    ApiKey,
    Password,
    Browser,
}

/// Inputs gathered from the CLI flags (shared by `login` and `init`).
pub struct LoginFlags {
    pub api_key: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub api_url: String,
    pub agree_tos: bool,
    pub no_prompt: bool,
}

/// Resolve which method to use from the flags, erroring on mismatched or
/// missing combinations (especially under `--no-prompt`). May prompt for a
/// missing half of a username/password pair when interactive.
fn resolve_method(flags: &mut LoginFlags) -> Result<Method, String> {
    let has_key = flags.api_key.as_deref().map(|s| !s.is_empty()).unwrap_or(false);
    let has_user = flags.username.as_deref().map(|s| !s.is_empty()).unwrap_or(false);
    let has_pass = flags.password.as_deref().map(|s| !s.is_empty()).unwrap_or(false);

    if has_key && (has_user || has_pass) {
        return Err("Choose one login method: either --api-key, or --username/--password (not both).".into());
    }

    if has_key {
        return Ok(Method::ApiKey);
    }

    if has_user || has_pass {
        // A credential pair: fill the missing half interactively, else error.
        if !has_user {
            if flags.no_prompt {
                return Err("--password was given without --username (and --no-prompt is set).".into());
            }
            let u: String = dialoguer::Input::new().with_prompt("Username or email").interact_text()
                .map_err(|e| e.to_string())?;
            flags.username = Some(u);
        }
        if !has_pass {
            if flags.no_prompt {
                return Err("--username was given without --password (and --no-prompt is set).".into());
            }
            let p = dialoguer::Password::new().with_prompt("Password").interact()
                .map_err(|e| e.to_string())?;
            flags.password = Some(p);
        }
        return Ok(Method::Password);
    }

    // No method flags at all.
    if flags.no_prompt {
        return Err("No login method specified. Pass --api-key, or --username/--password, in non-interactive mode.".into());
    }
    if !std::io::stdin().is_terminal() {
        // Can't run an interactive picker or browser flow without a TTY.
        return Err("No login method specified and no terminal available. Pass --api-key or --username/--password.".into());
    }

    // Interactive: let the operator choose.
    let choices = ["Browser (open crossfyre.io to approve)", "API key", "Username & password"];
    let pick = dialoguer::Select::new()
        .with_prompt("How would you like to log in?")
        .items(&choices)
        .default(0)
        .interact()
        .map_err(|e| e.to_string())?;
    match pick {
        1 => {
            let k: String = dialoguer::Input::new().with_prompt("Account API key").interact_text()
                .map_err(|e| e.to_string())?;
            flags.api_key = Some(k);
            Ok(Method::ApiKey)
        }
        2 => {
            let u: String = dialoguer::Input::new().with_prompt("Username or email").interact_text()
                .map_err(|e| e.to_string())?;
            let p = dialoguer::Password::new().with_prompt("Password").interact()
                .map_err(|e| e.to_string())?;
            flags.username = Some(u);
            flags.password = Some(p);
            Ok(Method::Password)
        }
        _ => Ok(Method::Browser),
    }
}

/// Enforce ToS acceptance. Returns Err with a message if it can't be obtained.
fn require_tos(flags: &LoginFlags) -> Result<(), String> {
    if flags.agree_tos {
        return Ok(());
    }
    if flags.no_prompt {
        return Err("You must pass --agree-tos to accept the Terms of Service in non-interactive mode.".into());
    }
    println!("\n{}\n", TOS_NOTICE);
    let ok = dialoguer::Confirm::new()
        .with_prompt("Do you accept the Terms of Service?")
        .default(false)
        .interact()
        .map_err(|e| e.to_string())?;
    if ok {
        Ok(())
    } else {
        Err("Terms of Service not accepted.".into())
    }
}

/// Run the full login flow and persist the resulting session. Returns the
/// authenticated Account. Shared by the `login` command and `init`.
pub async fn perform_login(
    data_dir: &Path,
    mut flags: LoginFlags,
) -> Result<Account, Box<dyn std::error::Error>> {
    let method = resolve_method(&mut flags).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    require_tos(&flags).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    let client = reqwest::Client::new();
    let api_url = flags.api_url.trim_end_matches('/').to_string();

    let (api_key, user) = match method {
        Method::ApiKey => {
            let key = flags.api_key.clone().unwrap();
            let user = verify_key(&client, &api_url, &key).await?;
            (key, user)
        }
        Method::Password => {
            let username = flags.username.clone().unwrap();
            let password = flags.password.clone().unwrap();
            password_login(&client, &api_url, &username, &password).await?
        }
        Method::Browser => browser_login(&client, &api_url).await?,
    };

    let account = Account {
        api_url,
        api_key,
        user_id: user.0,
        username: user.1,
        email: user.2,
    };
    save_account(data_dir, &account)?;
    Ok(account)
}

/// (user_id, username, email) extracted from a `{ data: { user: {...} } }` body.
type UserTriple = (String, String, String);

fn user_from_data(body: &serde_json::Value) -> Result<UserTriple, Box<dyn std::error::Error>> {
    let u = &body["data"]["user"];
    let id = u["id"].as_str().ok_or("login response missing user id")?.to_string();
    let username = u["username"].as_str().unwrap_or("").to_string();
    let email = u["email"].as_str().unwrap_or("").to_string();
    Ok((id, username, email))
}

fn body_message(body: &serde_json::Value) -> String {
    body["message"].as_str().unwrap_or("Login failed").to_string()
}

async fn verify_key(
    client: &reqwest::Client,
    api_url: &str,
    key: &str,
) -> Result<UserTriple, Box<dyn std::error::Error>> {
    let res = client
        .post(format!("{}/api/v1/cli/verify-key", api_url))
        .json(&serde_json::json!({ "api_key": key }))
        .send()
        .await?;
    let ok = res.status().is_success();
    let body: serde_json::Value = res.json().await.unwrap_or(serde_json::json!({}));
    if !ok {
        return Err(body_message(&body).into());
    }
    user_from_data(&body)
}

async fn password_login(
    client: &reqwest::Client,
    api_url: &str,
    identifier: &str,
    password: &str,
) -> Result<(String, UserTriple), Box<dyn std::error::Error>> {
    let res = client
        .post(format!("{}/api/v1/cli/login", api_url))
        .json(&serde_json::json!({
            "identifier": identifier,
            "password": password,
            "key_name": hostname(),
        }))
        .send()
        .await?;
    let ok = res.status().is_success();
    let body: serde_json::Value = res.json().await.unwrap_or(serde_json::json!({}));
    if !ok {
        return Err(body_message(&body).into());
    }
    let api_key = body["data"]["api_key"].as_str().ok_or("login response missing api_key")?.to_string();
    let user = user_from_data(&body)?;
    Ok((api_key, user))
}

async fn browser_login(
    client: &reqwest::Client,
    api_url: &str,
) -> Result<(String, UserTriple), Box<dyn std::error::Error>> {
    // 1. Start the device flow.
    let res = client
        .post(format!("{}/api/v1/cli/device/start", api_url))
        .json(&serde_json::json!({
            "client_info": { "hostname": hostname(), "os": os_label(), "version": cli_version() }
        }))
        .send()
        .await?;
    if !res.status().is_success() {
        let body: serde_json::Value = res.json().await.unwrap_or(serde_json::json!({}));
        return Err(body_message(&body).into());
    }
    let body: serde_json::Value = res.json().await?;
    let d = &body["data"];
    let device_code = d["device_code"].as_str().ok_or("device start: missing device_code")?.to_string();
    let verify_uri = d["verification_uri_complete"]
        .as_str()
        .or_else(|| d["verification_uri"].as_str())
        .unwrap_or("https://crossfyre.io/device")
        .to_string();
    let interval = d["interval"].as_u64().unwrap_or(3).max(1);
    let expires_in = d["expires_in"].as_u64().unwrap_or(600);

    println!("\n  To finish signing in, approve this device in your browser:");
    println!("    {}\n", verify_uri);
    if open_browser(&verify_uri) {
        println!("  (opened your browser; if nothing happened, paste the URL above)");
    }
    println!("  Waiting for approval...");

    // 2. Poll until approved / denied / expired / timeout.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(expires_in);
    loop {
        if std::time::Instant::now() > deadline {
            return Err("Login timed out before it was approved.".into());
        }
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;

        let res = client
            .post(format!("{}/api/v1/cli/device/poll", api_url))
            .json(&serde_json::json!({ "device_code": device_code }))
            .send()
            .await?;
        let body: serde_json::Value = res.json().await.unwrap_or(serde_json::json!({}));
        let status = body["data"]["status"].as_str().unwrap_or("");
        match status {
            "approved" => {
                let api_key = body["data"]["api_key"].as_str().ok_or("approval missing api_key")?.to_string();
                let user = user_from_data(&body)?;
                return Ok((api_key, user));
            }
            "denied" => return Err("Login was denied in the browser.".into()),
            "expired" => return Err("Login request expired. Run `crossfyre login` again.".into()),
            "unknown" => return Err("Login request was not found.".into()),
            _ => { /* pending: keep polling */ }
        }
    }
}

// ---- node provisioning (used by `init`) --------------------------------

/// Authenticate an existing dashboard-created node by its `cfx_...` key
/// (legacy `crossfyre node init --node-key` path). Returns the authorize-node body.
pub async fn authorize_existing_node(
    client: &reqwest::Client,
    api_url: &str,
    node_key: &str,
    force: bool,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let res = client
        .post(format!("{}/api/v1/authorize-node", api_url.trim_end_matches('/')))
        .json(&serde_json::json!({ "api_key": node_key, "force": force }))
        .send()
        .await?;
    if !res.status().is_success() {
        return Err("Invalid node API key or server error.".into());
    }
    Ok(res.json().await?)
}

/// Provision a brand-new node for the logged-in account. Returns a body shaped
/// like authorize-node (node_id, nats_*, extensions, ...) plus `api_key` (the
/// node's enrolment key, which the caller persists for daemon refresh).
// Retained for the account-provisioning flow; `node init` currently enrols via
// a dashboard-issued node key instead of auto-provisioning.
#[allow(dead_code)]
pub async fn provision_node(
    client: &reqwest::Client,
    account: &Account,
    name: Option<&str>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let res = client
        .post(format!("{}/api/v1/cli/node/provision", account.api_url.trim_end_matches('/')))
        .json(&serde_json::json!({
            "api_key": account.api_key,
            "hostname": hostname(),
            "name": name,
        }))
        .send()
        .await?;
    let ok = res.status().is_success();
    let body: serde_json::Value = res.json().await.unwrap_or(serde_json::json!({}));
    if !ok {
        return Err(body_message(&body).into());
    }
    Ok(body["data"].clone())
}

/// `crossfyre node list`: fetch the account's node fleet (scoped to its team)
/// with live online/offline status. Returns the `nodes` array.
pub async fn list_nodes(
    client: &reqwest::Client,
    account: &Account,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let res = client
        .post(format!("{}/api/v1/cli/node/list", account.api_url.trim_end_matches('/')))
        .json(&serde_json::json!({ "api_key": account.api_key }))
        .send()
        .await?;
    let ok = res.status().is_success();
    let body: serde_json::Value = res.json().await.unwrap_or(serde_json::json!({}));
    if !ok {
        return Err(body_message(&body).into());
    }
    Ok(body["data"]["nodes"].as_array().cloned().unwrap_or_default())
}

// ---- command entrypoints -----------------------------------------------

/// `crossfyre login`
pub async fn run_login(data_dir: &Path, flags: LoginFlags) -> Result<(), Box<dyn std::error::Error>> {
    let account = perform_login(data_dir, flags).await?;
    println!(
        "\n  Logged in as {} <{}>.",
        if account.username.is_empty() { &account.user_id } else { &account.username },
        account.email
    );
    println!("  Session saved to {}", account_path(data_dir).display());
    println!("\n  Next: register this host as a node with `crossfyre node init`.");
    Ok(())
}

/// `crossfyre logout`
///
/// Extensions must not run without an account session, so logging out stops and
/// disables every installed extension daemon (so none keep running or restart on
/// boot). Logging back in lets you start them again. Best-effort; failures to
/// stop a unit are ignored.
pub fn run_logout(data_dir: &Path) {
    let mut touched = Vec::new();
    for ext in crate::toolchain::EXTENSIONS {
        if crate::toolchain::config::is_extension_installed(ext) {
            let _ = crate::toolchain::service::stop(ext);
            let _ = crate::toolchain::service::disable(ext);
            touched.push(*ext);
        }
    }
    if !touched.is_empty() {
        println!("Stopped and disabled extensions (no session): {}", touched.join(", "));
    }

    if clear_account(data_dir) {
        println!("Logged out (removed {}).", account_path(data_dir).display());
    } else {
        println!("Not logged in.");
    }
}

/// Ensure there is an account session, logging in inline if needed. Honors the
/// same flags as `login`. Retained for the account-provisioning flow (see
/// `provision_node`); not used by the current key-based `node init`.
#[allow(dead_code)]
pub async fn ensure_logged_in(
    data_dir: &Path,
    flags: LoginFlags,
) -> Result<Account, Box<dyn std::error::Error>> {
    if let Some(existing) = load_account(data_dir) {
        println!("  Using saved login for {}.", if existing.username.is_empty() { &existing.user_id } else { &existing.username });
        return Ok(existing);
    }
    println!("  Not logged in yet - signing in first.");
    perform_login(data_dir, flags).await
}
