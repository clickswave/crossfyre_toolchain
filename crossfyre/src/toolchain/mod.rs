// Built-in package manager and service lifecycle for the Crossfyre toolchain.
//
// Formerly the standalone `orion` CLI (OrionChain). Merged into the node
// binary so `crossfyre node init` can install extensions, provision the Postgres
// container, and register OS services without piping a remote install script
// into a shell. Extensions (mach, voyage, pulse) remain separate closed-source
// daemon binaries downloaded from bins.crossfyre.io.

pub mod config;
pub mod db;
pub mod doctor;
pub mod install;
pub mod service;
pub mod status;
pub mod sudo_user;
pub mod uninstall;

/// Scan engines installable as node extensions.
pub const EXTENSIONS: &[&str] = &["mach", "voyage", "pulse"];

/// Default daemon port per extension. These are fixed protocol constants -
/// the daemons listen on localhost and the node talks to them over TCP JSON.
pub const EXTENSION_PORTS: &[(&str, u16)] = &[("mach", 4441), ("voyage", 4442), ("pulse", 4443)];

/// Expand an extension argument ("mach" | "all") into concrete extension names.
pub fn resolve_extensions(name: &str) -> Result<Vec<&'static str>, Box<dyn std::error::Error>> {
    if name == "all" {
        Ok(EXTENSIONS.to_vec())
    } else {
        match EXTENSIONS.iter().find(|&&e| e == name) {
            Some(e) => Ok(vec![e]),
            None => Err(format!("Unknown extension: '{}'. Use: mach, voyage, pulse, or all", name).into()),
        }
    }
}

pub fn print_extension_usage(verb: &str) {
    println!("Usage: crossfyre extension {} <extension>", verb);
    println!();
    println!("Available extensions:");
    println!("  mach     - HTTP fuzzer and content-discovery engine");
    println!("  voyage   - Subdomain enumeration engine");
    println!("  pulse    - Network host and port-scanning engine");
    println!("  all      - {} every extension", if verb == "remove" { "Remove" } else { "Install" });
    println!();
    println!("Examples:");
    println!("  crossfyre extension {} mach", verb);
    println!("  crossfyre extension {} all", verb);
}
