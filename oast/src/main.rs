//! Standalone `oast` server binary: reads config from the environment and runs.
//! (Self-hosters usually go through `crossfyre oast serve`, which runs the same
//! server in-process; this binary is for systemd units and container images.)

#[tokio::main]
async fn main() {
    oast::run(oast::Config::from_env()).await;
}
