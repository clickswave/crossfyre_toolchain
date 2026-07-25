//! `crossfyre oast` self-host helpers.
//!
//! Stands up the operator's OWN OAST server on their OWN box + domain: writes an
//! `/etc/oast/oast.env` config, a `cf-oast.service` systemd unit that runs
//! `crossfyre oast serve`, obtains a wildcard TLS cert via ACME DNS-01 (the box is
//! authoritative for the delegated zone, so cf_oast answers its own challenge), and
//! prints the DNS-delegation records the operator must add at their DNS provider.
//!
//! The server itself is the `oast` crate, run in-process by `crossfyre oast serve`.
//! Self-hosting is Linux/systemd only (like the node service).

use crate::toolchain::ui::{hint, ok, step, warn};
use std::path::Path;
use std::process::Command;

const OAST_DIR: &str = "/etc/oast";
const ENV_PATH: &str = "/etc/oast/oast.env";
const ACME_TXT: &str = "/etc/oast/acme_txt";
const ACME_HOOK: &str = "/usr/local/bin/oast-acme-hook.sh";
const LEGO_PATH: &str = "/etc/oast/lego";
const UNIT_PATH: &str = "/etc/systemd/system/cf-oast.service";
const RENEW_SVC: &str = "/etc/systemd/system/cf-oast-renew.service";
const RENEW_TIMER: &str = "/etc/systemd/system/cf-oast-renew.timer";

pub struct SetupOpts {
    /// The delegated zone callbacks arrive on (e.g. "oob.acme.com").
    pub domain: String,
    /// This box's public IP (auto-detected when None).
    pub public_ip: Option<String>,
    /// ACME account email (required to obtain TLS).
    pub email: Option<String>,
    /// Skip the wildcard-cert step (HTTP/DNS only).
    pub no_tls: bool,
}

fn require_root() -> Result<(), Box<dyn std::error::Error>> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("setting up an OAST server needs root - re-run with sudo".into());
    }
    Ok(())
}

fn cert_paths(domain: &str) -> (String, String) {
    // lego sanitises the wildcard "*" to "_".
    let base = format!("{LEGO_PATH}/certificates/_.{domain}");
    (format!("{base}.crt"), format!("{base}.key"))
}

/// Best-effort public IP detection via a couple of plain-text echo services.
async fn detect_public_ip() -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .ok()?;
    for url in ["https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"] {
        if let Ok(resp) = client.get(url).send().await {
            if let Ok(text) = resp.text().await {
                let ip = text.trim().to_string();
                if ip.split('.').count() == 4 && ip.split('.').all(|o| o.parse::<u8>().is_ok()) {
                    return Some(ip);
                }
            }
        }
    }
    None
}

/// Is the delegated zone live and pointing at this box? Resolve a random label and
/// check it comes back as `ip` (our DNS answers A for any name with our public IP).
async fn delegation_live(domain: &str, ip: &str) -> bool {
    let probe = format!("cfxprobe{}.{}:80", rand_label(), domain);
    match tokio::net::lookup_host(&probe).await {
        Ok(addrs) => addrs.filter_map(|a| match a.ip() {
            std::net::IpAddr::V4(v4) => Some(v4.to_string()),
            _ => None,
        }).any(|got| got == ip),
        Err(_) => false,
    }
}

fn rand_label() -> String {
    // A unique-enough probe label (no crypto needed): low bits of the clock.
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}", (n as u64) & 0xffff_ffff)
}

/// Write /etc/oast/oast.env. Includes TLS vars only when the cert already exists.
fn write_env(domain: &str, ip: &str) -> std::io::Result<()> {
    let (crt, key) = cert_paths(domain);
    let mut body = format!(
        "# Crossfyre OAST server config (managed by `crossfyre oast setup`).\n\
         OAST_DOMAIN={domain}\n\
         OAST_PUBLIC_IP={ip}\n\
         OAST_ACME_TXT_FILE={ACME_TXT}\n"
    );
    if Path::new(&crt).exists() && Path::new(&key).exists() {
        body.push_str(&format!("OAST_HTTPS_ADDR=0.0.0.0:443\nOAST_TLS_CERT={crt}\nOAST_TLS_KEY={key}\n"));
    }
    std::fs::write(ENV_PATH, body)
}

fn write_unit(exe: &Path) -> std::io::Result<()> {
    let body = format!(
        "[Unit]\n\
         Description=Crossfyre OAST server\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         EnvironmentFile={ENV_PATH}\n\
         ExecStart={exe} oast serve\n\
         AmbientCapabilities=CAP_NET_BIND_SERVICE\n\
         Restart=on-failure\n\
         RestartSec=3\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        exe = exe.display(),
    );
    std::fs::write(UNIT_PATH, body)
}

fn systemctl(args: &[&str]) -> bool {
    Command::new("systemctl").args(args).status().map(|s| s.success()).unwrap_or(false)
}

/// Print the DNS records the operator must add at their DNS provider to delegate
/// the zone to this box.
fn print_delegation(domain: &str, ip: &str) {
    let parent = domain.splitn(2, '.').nth(1).unwrap_or(domain);
    let sub = domain.strip_suffix(&format!(".{parent}")).unwrap_or(domain);
    println!();
    step(&format!("Delegate {domain} to this box. In your DNS provider for {parent}, add:"));
    println!("      ns1.{domain}   A    {ip}          (glue: the box's authoritative NS)");
    println!("      {sub}          NS   ns1.{domain}   (delegate the zone to it)");
    println!();
    hint("Delegation can take a few minutes to propagate.");
}

pub async fn setup(exe: &Path, opts: SetupOpts) -> Result<(), Box<dyn std::error::Error>> {
    require_root()?;
    let domain = opts.domain.trim().trim_matches('.').to_ascii_lowercase();
    if domain.split('.').count() < 2 {
        return Err("--domain must be a delegated zone like oob.example.com".into());
    }

    step("Resolving this box's public IP...");
    let ip = match opts.public_ip {
        Some(x) => x.trim().to_string(),
        None => detect_public_ip().await.ok_or("could not auto-detect public IP; pass --public-ip")?,
    };
    ok(&format!("Public IP: {ip}"));

    std::fs::create_dir_all(format!("{LEGO_PATH}/certificates"))?;
    let _ = std::fs::write(ACME_TXT, "");
    write_env(&domain, &ip)?;
    write_unit(exe)?;
    systemctl(&["daemon-reload"]);
    systemctl(&["enable", "cf-oast"]);
    systemctl(&["restart", "cf-oast"]);
    ok("cf-oast service installed and started (DNS :53, HTTP :80).");

    // TLS needs the delegation live so Let's Encrypt can read our challenge.
    let (crt, _key) = cert_paths(&domain);
    if Path::new(&crt).exists() {
        ok("Wildcard certificate already present; HTTPS is enabled.");
    } else if opts.no_tls {
        print_delegation(&domain, &ip);
        hint("Skipping TLS (--no-tls). Re-run without it once delegation is live to get HTTPS.");
    } else {
        step("Checking DNS delegation to this box...");
        if delegation_live(&domain, &ip).await {
            ok("Delegation is live.");
            match opts.email.as_deref() {
                Some(email) if !email.is_empty() => {
                    obtain_cert(&domain, email)?;
                    write_env(&domain, &ip)?; // now includes TLS paths
                    systemctl(&["restart", "cf-oast"]);
                    install_renewal(email, &domain)?;
                    ok("Wildcard TLS obtained; HTTPS (443) is live; auto-renewal installed.");
                }
                _ => {
                    warn("Delegation is live but no --email given; cannot obtain TLS.");
                    hint("Re-run: crossfyre oast setup --domain <d> --email you@example.com");
                }
            }
        } else {
            warn("Delegation not visible yet.");
            print_delegation(&domain, &ip);
            hint("After adding the records, re-run this command to obtain wildcard TLS.");
        }
    }

    print_endpoint(&domain, Path::new(&crt).exists());
    Ok(())
}

/// Obtain a `*.<domain>` cert via lego DNS-01, serving the challenge from cf_oast.
fn obtain_cert(domain: &str, email: &str) -> Result<(), Box<dyn std::error::Error>> {
    ensure_lego()?;
    // The exec hook writes the DNS-01 TXT value to the file cf_oast serves.
    std::fs::write(
        ACME_HOOK,
        "#!/usr/bin/env bash\n\
         action=\"${1:-}\"; value=\"${3:-}\"\n\
         case \"$action\" in\n\
         \x20 present) printf '%s' \"$value\" > /etc/oast/acme_txt ;;\n\
         \x20 cleanup) : > /etc/oast/acme_txt ;;\n\
         esac\n",
    )?;
    let _ = Command::new("chmod").args(["755", ACME_HOOK]).status();

    step("Obtaining wildcard certificate (Let's Encrypt, DNS-01)...");
    let status = Command::new("lego")
        .env("EXEC_PATH", ACME_HOOK)
        .args([
            "--accept-tos", "--email", email,
            "--dns", "exec", "--dns.disable-cp",
            "--domains", &format!("*.{domain}"),
            "--path", LEGO_PATH,
            "run",
        ])
        .status()?;
    if !status.success() {
        return Err("lego failed to obtain the certificate (check delegation + that port 53 is reachable)".into());
    }
    Ok(())
}

/// Ensure the `lego` ACME client is installed (download the static release if not).
fn ensure_lego() -> Result<(), Box<dyn std::error::Error>> {
    if Command::new("lego").arg("--version").status().map(|s| s.success()).unwrap_or(false) {
        return Ok(());
    }
    step("Installing lego (ACME client)...");
    let ver = "4.17.4";
    let url = format!("https://github.com/go-acme/lego/releases/download/v{ver}/lego_v{ver}_linux_amd64.tar.gz");
    // curl + tar are ubiquitous on Linux servers; shelling out keeps deps light.
    let sh = format!(
        "set -e; cd /tmp; curl -fsSL -o lego.tgz '{url}'; tar xzf lego.tgz lego; install -m0755 lego /usr/local/bin/lego; rm -f lego.tgz lego"
    );
    let status = Command::new("sh").arg("-c").arg(sh).status()?;
    if !status.success() {
        return Err("failed to install lego; install it manually and re-run".into());
    }
    Ok(())
}

/// A daily renewal timer that renews < 30 days out and restarts cf-oast on a roll.
fn install_renewal(email: &str, domain: &str) -> Result<(), Box<dyn std::error::Error>> {
    let renew_sh = "/usr/local/bin/oast-renew.sh";
    std::fs::write(
        renew_sh,
        format!(
            "#!/usr/bin/env bash\nset -e\nEXEC_PATH={ACME_HOOK} \\\n\
             lego --accept-tos --email {email} --dns exec --dns.disable-cp \\\n\
             \x20 --domains '*.{domain}' --path {LEGO_PATH} \\\n\
             \x20 renew --days 30 --renew-hook 'systemctl restart cf-oast'\n"
        ),
    )?;
    let _ = Command::new("chmod").args(["755", renew_sh]).status();
    std::fs::write(
        RENEW_SVC,
        "[Unit]\nDescription=Renew Crossfyre OAST wildcard TLS certificate\nAfter=network-online.target\n\
         [Service]\nType=oneshot\nExecStart=/usr/local/bin/oast-renew.sh\n",
    )?;
    std::fs::write(
        RENEW_TIMER,
        "[Unit]\nDescription=Daily Crossfyre OAST cert renewal check\n\
         [Timer]\nOnCalendar=*-*-* 03:30:00\nRandomizedDelaySec=1h\nPersistent=true\n\
         [Install]\nWantedBy=timers.target\n",
    )?;
    systemctl(&["daemon-reload"]);
    systemctl(&["enable", "--now", "cf-oast-renew.timer"]);
    Ok(())
}

/// Print the values the operator pastes into the dashboard (Arsenal -> OAST endpoints).
fn print_endpoint(domain: &str, tls: bool) {
    println!();
    if tls {
        ok("Your OAST endpoint is ready. Add it in the dashboard (OAST Endpoints -> Add endpoint):");
        println!("      Callback domain :  {domain}");
        println!("      Poll API URL    :  https://api.{domain}");
    } else {
        warn("HTTPS is not enabled yet, so the endpoint is not usable by scans until TLS is obtained.");
        hint("Complete DNS delegation, then re-run `crossfyre oast setup` to finish TLS.");
    }
}

/// Show local OAST server status.
pub fn status() -> Result<(), Box<dyn std::error::Error>> {
    if !Path::new(UNIT_PATH).exists() {
        warn("No OAST server configured on this host.");
        hint("Run `crossfyre oast setup --domain oob.example.com` to stand one up.");
        return Ok(());
    }
    let active = Command::new("systemctl").args(["is-active", "cf-oast"]).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    if active == "active" { ok("cf-oast: active"); } else { warn(&format!("cf-oast: {active}")); }
    if let Ok(env) = std::fs::read_to_string(ENV_PATH) {
        for line in env.lines() {
            if let Some(d) = line.strip_prefix("OAST_DOMAIN=") { step(&format!("domain: {d}")); }
            if line.starts_with("OAST_TLS_CERT=") { ok("TLS: enabled (HTTPS on 443)"); }
        }
    }
    Ok(())
}
