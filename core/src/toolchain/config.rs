// Toolchain configuration: where extension binaries live, and how the
// extensions reach the shared Postgres instance. Lives in the same
// `~/.config/crossfyre` root as the node configs (`nodes.d/`), in a
// `config.toml` the extension daemons also read.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct ToolchainConfig {
    pub postgres: PostgresSection,
    pub container: ContainerSection,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PostgresSection {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: Option<String>,
    pub db_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContainerSection {
    pub id: Option<String>,
}

impl Default for ToolchainConfig {
    fn default() -> Self {
        Self {
            postgres: PostgresSection {
                host: "localhost".to_string(),
                port: 4440,
                user: "postgres".to_string(),
                password: None,
                db_name: "crossfyre".to_string(),
            },
            container: ContainerSection {
                id: None,
            },
        }
    }
}

/// `~/.config/crossfyre` of the *invoking* user (honors SUDO_USER), the same
/// root that holds `nodes.d/`.
pub fn get_toolchain_dir() -> PathBuf {
    super::sudo_user::invoking_user_config_dir().join("crossfyre")
}

pub fn get_config_path() -> PathBuf {
    get_toolchain_dir().join("config.toml")
}

pub fn get_bin_dir() -> PathBuf {
    // Where extension binaries (and the crossfyre binary itself) are
    // installed. Linux/macOS keep the conventional /opt prefix; Windows has
    // no /opt so we use %ProgramData%\Crossfyre\bin.
    #[cfg(windows)]
    {
        let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
        PathBuf::from(base).join("Crossfyre").join("bin")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/opt/crossfyre/bin")
    }
}

/// On-disk file name of an extension binary (adds `.exe` on Windows).
pub fn ext_file_name(ext: &str) -> String {
    if cfg!(windows) {
        format!("{}.exe", ext)
    } else {
        ext.to_string()
    }
}

/// Full path to an installed extension binary, OS-correct extension included.
pub fn ext_bin_path(ext: &str) -> PathBuf {
    get_bin_dir().join(ext_file_name(ext))
}

pub fn is_extension_installed(ext: &str) -> bool {
    ext_bin_path(ext).exists()
}

pub fn load_config() -> Result<ToolchainConfig, Box<dyn std::error::Error>> {
    let path = get_config_path();
    let contents = fs::read_to_string(path)?;
    let config: ToolchainConfig = toml::from_str(&contents)?;
    Ok(config)
}

pub fn save_config(config: &ToolchainConfig) -> Result<(), Box<dyn std::error::Error>> {
    let dir = get_toolchain_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
    }

    let path = get_config_path();
    let toml_string = toml::to_string(config)?;
    fs::write(&path, toml_string)?;
    super::sudo_user::chown_to_invoking_user(&path);
    Ok(())
}

/// Load the toolchain config, writing the defaults first if none exists.
/// Defaults are sane for a single-host install; operators can edit
/// `config.toml` afterwards to point at an external Postgres.
pub fn load_or_create_config() -> Result<ToolchainConfig, Box<dyn std::error::Error>> {
    if !get_config_path().exists() {
        let config = ToolchainConfig::default();
        save_config(&config)?;
        println!("[config] Wrote default toolchain config: {}", get_config_path().display());
    }
    load_config()
}
