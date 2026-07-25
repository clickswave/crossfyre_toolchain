use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "scout",
    about = "Service enumeration and web fingerprinting daemon",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Run as a background daemon (TCP server on the given port)
    #[arg(long, default_value_t = false)]
    pub daemon: bool,

    /// TCP port to bind (daemon) or connect to (client)
    #[arg(long, default_value_t = 4444)]
    pub port: u16,
}

#[derive(Subcommand, Clone)]
pub enum Commands {
    /// Fingerprint a single target through the running daemon
    Fingerprint(FpArgs),
    /// Send a raw JSON op to the daemon and print the streamed events
    Exec(ExecArgs),
}

#[derive(Parser, Clone)]
pub struct FpArgs {
    /// Target URL or host[:port] (e.g. https://example.com, example.com:8443)
    pub target: String,
}

#[derive(Parser, Clone)]
pub struct ExecArgs {
    /// Raw JSON payload to send to the daemon
    pub json: String,
}
