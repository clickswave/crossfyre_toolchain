// Download, verify, and install extension binaries (and the crossfyre binary
// itself) from the release CDN. Every artifact is resolved through a signed-
// by-checksum manifest: manifest.json maps component -> version -> per-
// platform artifact file + SHA256. Nothing is installed without a checksum
// match.

use super::config::{ext_bin_path, ext_file_name, get_bin_dir};
use super::service;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

// The bins origin this binary fetches releases from. Baked at build time so a
// dev/staging build pulls from its own bucket: crossfyre_build sets
// CROSSFYRE_BINS_ORIGIN per --env. Defaults to prod when built without it.
pub const BASE_URL: &str = match option_env!("CROSSFYRE_BINS_ORIGIN") {
    Some(o) => o,
    None => "https://bins.crossfyre.io",
};

#[derive(serde::Deserialize, Debug)]
pub struct Manifest {
    pub components: HashMap<String, Component>,
}

#[derive(serde::Deserialize, Debug)]
pub struct Component {
    pub version: String,
    /// Keyed by platform: "linux-x86_64", "darwin-aarch64", "windows-x86_64", ...
    pub artifacts: HashMap<String, Artifact>,
}

#[derive(serde::Deserialize, Debug)]
pub struct Artifact {
    pub file: String,
    pub sha256: String,
}

/// "linux-x86_64" style key for the running host.
pub fn platform_key() -> String {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    format!("{}-{}", os, std::env::consts::ARCH)
}

pub async fn fetch_manifest() -> Result<Manifest, Box<dyn std::error::Error>> {
    let url = format!("{}/manifest.json", BASE_URL);
    let resp = reqwest::get(&url).await
        .map_err(|e| format!("could not fetch release manifest ({}): {}", url, e))?;
    if !resp.status().is_success() {
        return Err(format!("release manifest fetch failed: {} returned {}", url, resp.status()).into());
    }
    let manifest: Manifest = resp.json().await
        .map_err(|e| format!("release manifest is malformed: {}", e))?;
    Ok(manifest)
}

fn resolve_artifact<'m>(
    manifest: &'m Manifest,
    component: &str,
) -> Result<(&'m Component, &'m Artifact), Box<dyn std::error::Error>> {
    let comp = manifest.components.get(component)
        .ok_or_else(|| format!("component '{}' not in release manifest", component))?;
    let key = platform_key();
    let artifact = comp.artifacts.get(&key)
        .ok_or_else(|| format!("no '{}' artifact for platform {} in release manifest", component, key))?;
    Ok((comp, artifact))
}

/// Download an artifact to `dest` and verify its SHA256 against the manifest.
async fn download_verified(artifact: &Artifact, dest: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/{}", BASE_URL, artifact.file);
    let resp = reqwest::get(&url).await
        .map_err(|e| format!("download failed ({}): {}", url, e))?;
    if !resp.status().is_success() {
        return Err(format!("download failed: {} returned {}", url, resp.status()).into());
    }
    let bytes = resp.bytes().await?;

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let got = format!("{:x}", hasher.finalize());
    if !got.eq_ignore_ascii_case(&artifact.sha256) {
        return Err(format!(
            "checksum mismatch for {} (expected {}, got {}) - refusing to install",
            artifact.file, artifact.sha256, got
        ).into());
    }

    fs::write(dest, &bytes)?;
    Ok(())
}

/// Unzip `zip_path` into `extract_dir` (shells out to `unzip`, which the
/// installer checks for).
fn extract_zip(zip_path: &Path, extract_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(extract_dir)?;
    let status = Command::new("unzip")
        .args(["-q", &zip_path.to_string_lossy(), "-d", &extract_dir.to_string_lossy()])
        .status()
        .map_err(|e| format!("unzip not found or failed to execute: {}", e))?;
    if !status.success() {
        return Err(format!("Failed to extract {}", zip_path.display()).into());
    }
    Ok(())
}

/// Atomically place `src` at `dest` (write-next-to + rename), 0755 on unix.
fn place_binary(src: &Path, dest: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = dest.with_extension("new");
    fs::copy(src, &tmp_path)?;
    fs::rename(&tmp_path, dest)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dest, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

/// Install one or more extensions ("mach" | "all"). Download + verify +
/// register the daemon service. The service is created but only started by
/// `install_and_start` (or an explicit `crossfyre service start`).
pub async fn install(extension: &str, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = fetch_manifest().await?;
    for ext in super::resolve_extensions(extension)? {
        install_one(&manifest, ext, force).await?;
    }
    Ok(())
}

async fn install_one(manifest: &Manifest, ext: &str, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    let bin_path = ext_bin_path(ext);

    if bin_path.exists() && !force {
        println!("{} is already installed (use --force to reinstall)", ext);
        return Ok(());
    }

    let (comp, artifact) = resolve_artifact(manifest, ext)?;
    println!("[*] Downloading {} {} ...", ext, comp.version);

    let tmp_dir = tempfile::tempdir().map_err(|e| format!("Failed to create temp dir: {}", e))?;
    let zip_path = tmp_dir.path().join(&artifact.file);
    download_verified(artifact, &zip_path).await?;

    println!("[*] Installing {} ...", ext);
    let extract_dir = tmp_dir.path().join("extracted");
    extract_zip(&zip_path, &extract_dir)?;

    let extracted_binary = extract_dir.join(ext_file_name(ext));
    if !extracted_binary.exists() {
        return Err(format!("Binary '{}' not found inside zip", ext_file_name(ext)).into());
    }

    // Stop the running daemon (if any) before replacing the binary - on
    // Windows the file is locked while the task runs. Best-effort, OS-aware.
    if bin_path.exists() {
        service::try_stop(ext);
    }

    place_binary(&extracted_binary, &bin_path)?;
    println!("[+] {} {} installed to {}", ext, comp.version, bin_path.display());

    if let Err(e) = service::create_service_file(ext) {
        eprintln!("[!] Failed to create service: {}", e);
    }

    Ok(())
}

/// One-step install used by `crossfyre install`, `init`, and the dashboard's
/// install-extension path: download + verify + enable + start.
pub async fn install_and_start(ext: &str) -> Result<(), Box<dyn std::error::Error>> {
    install(ext, false).await?;
    for e in super::resolve_extensions(ext)? {
        service::enable(e)?;
        service::start(e)?;
    }
    Ok(())
}

/// Remove one or more extensions: stop + disable + deregister + delete binary.
pub fn remove(extension: &str) -> Result<(), Box<dyn std::error::Error>> {
    for ext in super::resolve_extensions(extension)? {
        remove_one(ext)?;
    }
    Ok(())
}

fn remove_one(ext: &str) -> Result<(), Box<dyn std::error::Error>> {
    let bin_path = ext_bin_path(ext);

    if !bin_path.exists() {
        println!("{} is not installed, nothing to remove.", ext);
        return Ok(());
    }

    println!("[*] Stopping {} service...", ext);
    let _ = service::stop(ext);
    println!("[*] Disabling {} service...", ext);
    let _ = service::disable(ext);
    service::remove_service_file(ext)?;

    fs::remove_file(&bin_path)?;
    println!("[+] {} removed from {}", ext, bin_path.display());
    Ok(())
}

/// `crossfyre update [self|<ext>|all]`. With no target: update self plus
/// every installed extension. Returns true if the crossfyre binary itself
/// was replaced (caller should restart).
pub async fn update(target: Option<&str>) -> Result<bool, Box<dyn std::error::Error>> {
    let manifest = fetch_manifest().await?;
    let mut self_updated = false;

    let (do_self, exts): (bool, Vec<&str>) = match target {
        Some("self") => (true, vec![]),
        Some("all") | None => (true, installed_extensions()),
        Some(ext) => (false, super::resolve_extensions(ext)?),
    };

    for ext in exts {
        // Reinstall at the manifest version; service is restarted to pick
        // up the new binary.
        install_one(&manifest, ext, true).await?;
        let _ = service::start(ext);
    }

    if do_self {
        self_updated = self_update(&manifest).await?;
        // The node worker is part of "self": keep it in lockstep with the CLI.
        if let Err(e) = download_node(&manifest).await {
            eprintln!("[update] WARN could not update the node worker binary: {e}");
        }
    }

    Ok(self_updated)
}

fn installed_extensions() -> Vec<&'static str> {
    super::EXTENSIONS.iter().copied()
        .filter(|e| super::config::is_extension_installed(e))
        .collect()
}

/// Replace the running crossfyre binary with the manifest version. Linux
/// keeps the old inode mapped, so the running process is unaffected until
/// restart. Returns true if a new version was written.
pub async fn self_update(manifest: &Manifest) -> Result<bool, Box<dyn std::error::Error>> {
    let (comp, artifact) = resolve_artifact(manifest, "crossfyre")?;

    let current_version = env!("CARGO_PKG_VERSION");
    if comp.version == current_version {
        println!("crossfyre is already at {} - nothing to update.", current_version);
        return Ok(false);
    }

    println!("[*] Updating crossfyre {} -> {} ...", current_version, comp.version);
    let tmp_dir = tempfile::tempdir()?;
    let zip_path = tmp_dir.path().join(&artifact.file);
    download_verified(artifact, &zip_path).await?;

    let extract_dir = tmp_dir.path().join("extracted");
    extract_zip(&zip_path, &extract_dir)?;
    let extracted = extract_dir.join(ext_file_name("crossfyre"));
    if !extracted.exists() {
        return Err("crossfyre binary not found inside update zip".into());
    }

    let exe = std::env::current_exe()?;
    place_binary(&extracted, &exe)?;

    // Keep the stable /opt path in sync too, in case the process was started
    // from somewhere else (e.g. a dev checkout).
    let stable = get_bin_dir().join(ext_file_name("crossfyre"));
    if stable != exe {
        let _ = place_binary(&extracted, &stable);
    }

    println!("[+] crossfyre updated to {} - restart the node to run it.", comp.version);
    Ok(true)
}

/// Copy the running binary to the stable install path
/// (`/opt/crossfyre/bin/crossfyre`) so OS services have a fixed ExecStart.
/// No-op when already running from there.
pub fn ensure_self_installed() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let exe = std::env::current_exe()?;
    let stable = get_bin_dir().join(ext_file_name("crossfyre"));
    if exe == stable {
        return Ok(stable);
    }
    place_binary(&exe, &stable)?;
    println!("[+] Installed crossfyre binary to {}", stable.display());
    Ok(stable)
}

/// Download + install the `node` worker binary to the stable bin dir. The
/// crossfyre CLI and the OS service exec it (ExecStart=/opt/crossfyre/bin/node),
/// so it must sit next to crossfyre.
pub async fn download_node(manifest: &Manifest) -> Result<(), Box<dyn std::error::Error>> {
    let (comp, artifact) = resolve_artifact(manifest, "node")?;
    let tmp_dir = tempfile::tempdir()?;
    let zip_path = tmp_dir.path().join(&artifact.file);
    download_verified(artifact, &zip_path).await?;
    let extract_dir = tmp_dir.path().join("extracted");
    extract_zip(&zip_path, &extract_dir)?;
    let extracted = extract_dir.join(ext_file_name("node"));
    if !extracted.exists() {
        return Err("node binary not found inside the node zip".into());
    }
    let stable = get_bin_dir().join(ext_file_name("node"));
    place_binary(&extracted, &stable)?;
    println!("[+] node worker installed at {} ({})", stable.display(), comp.version);
    Ok(())
}

/// Ensure the `node` worker binary is present next to crossfyre. Prefers a
/// sibling of the running binary (fresh install / dev checkout) and falls back
/// to downloading it from the release manifest. Called during `node init` so
/// the service's ExecStart resolves.
pub async fn ensure_node_installed() -> Result<(), Box<dyn std::error::Error>> {
    let stable = get_bin_dir().join(ext_file_name("node"));
    if stable.exists() {
        return Ok(());
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(sib) = exe.parent().map(|d| d.join(ext_file_name("node"))) {
            if sib.exists() && sib != stable {
                place_binary(&sib, &stable)?;
                println!("[+] Installed node binary to {}", stable.display());
                return Ok(());
            }
        }
    }
    let manifest = fetch_manifest().await?;
    download_node(&manifest).await
}
