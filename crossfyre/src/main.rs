//! The Crossfyre command-line interface. Management + lifecycle commands.
//! Node lifecycle is delegated to the separate `node` worker binary (the OS
//! service execs `node supervise`; `crossfyre node up/down` manage that service).
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "crossfyre", about = "Crossfyre node and toolchain CLI", version)]
struct Cli {
    /// Override the crossfyre config root (the directory that holds
    /// `nodes.d` and `config.toml`). Defaults to `$XDG_CONFIG_HOME/crossfyre`
    /// of the *invoking* user (so `sudo` keeps using your home, not `/root`).
    /// Pass an explicit path to run an isolated set of nodes:
    /// `--data-dir ~/.config/cfx-htb`.
    #[arg(long, global = true, value_name = "PATH")]
    data_dir: Option<std::path::PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Log in to your Crossfyre account so the CLI can act on your behalf
    /// (e.g. provision nodes during `node init`). Three methods:
    ///   crossfyre login --api-key <key>
    ///   crossfyre login --username <u> --password <p>
    ///   crossfyre login                 (opens the browser to approve)
    /// The session is saved to <data-dir>/auth.toml.
    Login {
        /// Log in with an account API key (from Settings -> CLI Access)
        #[arg(long)]
        api_key: Option<String>,

        /// Username or email (use with --password)
        #[arg(long)]
        username: Option<String>,

        /// Password (use with --username)
        #[arg(long)]
        password: Option<String>,

        /// Control-plane origin
        #[arg(long, default_value = cfx_core::auth::DEFAULT_API_URL)]
        api_url: String,

        /// Accept the Terms of Service without an interactive prompt
        #[arg(long)]
        agree_tos: bool,

        /// Never prompt; require everything via flags (fails on missing/mismatched flags)
        #[arg(long)]
        no_prompt: bool,
    },

    /// Log out: remove the saved account session (auth.toml).
    Logout,

    /// Manage Crossfyre nodes: register this host (`node init`), see your fleet
    /// (`node list`), bring nodes online (`node up` / `node down`), or check the
    /// local daemons (`node status`). All node commands live under here.
    Node {
        #[command(subcommand)]
        action: NodeAction,
    },

    /// Manage toolchain extensions (mach, voyage, pulse): list, install, remove,
    /// update, and control their daemons. All extension commands live under here.
    #[command(alias = "ext")]
    Extension {
        #[command(subcommand)]
        action: ExtensionAction,
    },

    /// Run a .cfx script locally, no control plane required.
    /// Targets are type:value pairs, e.g. `crossfyre run test.cfx domain:example.com`.
    Run {
        script: String,

        #[arg(trailing_var_arg = true)]
        targets: Vec<String>,
    },

    /// Update from the release manifest: `self`, an extension name, or `all`
    /// (default: self + every installed extension). For a single extension you
    /// can also use `crossfyre extension update <name>`.
    Update {
        target: Option<String>,
    },

    /// Show a full overview of the local node daemons, extensions and database.
    /// (Use `crossfyre node status`, `crossfyre extension list` or
    /// `crossfyre db status` for a single area.)
    Status,

    /// Manage the toolchain Postgres container.
    Db {
        #[command(subcommand)]
        command: cfx_core::DbCommands,
    },

    /// Check the environment for common problems.
    Doctor,

    /// Remove Crossfyre services, extensions, binaries and the database
    /// container from this host.
    Uninstall {
        /// Also remove the config root (node registrations included)
        #[arg(long)]
        purge: bool,
    },
}

#[derive(Subcommand, Debug)]
enum NodeAction {
    /// Register this host as a Crossfyre node using a node API key created in
    /// the dashboard (Nodes -> create a node). Pass it with `--node-key`, or
    /// run interactively and you'll be prompted to paste it. Enrolment writes
    /// `nodes.d/<node-id>.toml`, installs the node's selected extensions,
    /// provisions the database, and installs the node OS service.
    Init {
        /// Force-disconnect an already-running instance and take over
        #[arg(long)]
        force: bool,

        /// API base URL for the Crossfyre control plane
        #[arg(long, default_value = cfx_core::auth::DEFAULT_API_URL)]
        api_url: String,

        /// Skip installing the node OS service (run `crossfyre node up` manually)
        #[arg(long)]
        no_service: bool,

        /// The node API key (from the dashboard). If omitted, you're prompted
        /// to paste it (unless --no-prompt).
        #[arg(long)]
        node_key: Option<String>,

        /// Never prompt; require the node key via --node-key (fails if missing).
        #[arg(long)]
        no_prompt: bool,
    },

    /// Remove a registered node from this host: deletes its `nodes.d/<id>.toml`
    /// (and pid/network files). `--inactive` removes every locally-registered
    /// node the server no longer knows about (deleted in the dashboard).
    Remove {
        /// Node id (or unique prefix) to remove. Omit with --inactive.
        node_id: Option<String>,

        /// Remove all nodes the server reports as unknown/deleted.
        #[arg(long)]
        inactive: bool,
    },

    /// List your node fleet from the control plane, with live online/offline
    /// status. (This is the server view; for the local daemons on this host use
    /// `crossfyre node status`.)
    List {
        /// Print raw JSON instead of a table.
        #[arg(long)]
        json: bool,
    },

    /// Show the node daemons registered on THIS host and whether each is running.
    Status,

    /// Bring all nodes online: start the node supervisor service (background).
    /// Falls back to a foreground supervisor when no OS service is installed.
    Up {
        /// Force-disconnect already-running instances and take over
        #[arg(long)]
        force: bool,
    },

    /// Take all nodes offline: stop the node supervisor service.
    Down,

    /// Restart the node supervisor service.
    Restart,

    /// Enable the node supervisor service (start on boot).
    Enable,

    /// Disable the node supervisor service (don't start on boot).
    Disable,

}

#[derive(Subcommand, Debug)]
enum ExtensionAction {
    /// List extensions with install state and daemon health.
    List,
    /// Install an extension (mach, voyage, pulse, all): download, verify against
    /// the release manifest, enable and start its daemon.
    Install {
        name: Option<String>,
        /// Force reinstall even if already installed
        #[arg(short, long)]
        force: bool,
    },
    /// Remove an extension (stop service, delete binary).
    Remove { name: Option<String> },
    /// Update an extension from the release manifest.
    Update { name: Option<String> },
    /// Start an extension daemon.
    Start { name: String },
    /// Stop an extension daemon.
    Stop { name: String },
    /// Restart an extension daemon.
    Restart { name: String },
    /// Enable an extension daemon (start on boot).
    Enable { name: String },
    /// Disable an extension daemon (don't start on boot).
    Disable { name: String },
}



/// Run the `node` worker's supervisor in the foreground (fallback for hosts
/// with no OS service). Finds the `node` binary next to this one, else on PATH.
fn exec_node_supervise(base: &std::path::Path, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    let node = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("node")))
        .filter(|p| p.exists())
        .unwrap_or_else(|| std::path::PathBuf::from("node"));
    let mut cmd = std::process::Command::new(node);
    cmd.arg("supervise").arg("--data-dir").arg(base);
    if force { cmd.arg("--force"); }
    if !cmd.status()?.success() {
        return Err("node supervise exited with an error".into());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let base = cfx_core::resolve_data_dir(cli.data_dir.as_deref())?;

    // Account gate: the operational/management commands require an account
    // session. `login`/`logout` are the way in/out; `init` performs login
    // inline; `doctor`/`uninstall` stay usable for diagnostics + cleanup; and
    // `up`/`daemon` are run by the OS service and are already implicitly gated
    // (they need a node config that only `init` can create).
    // `node list` needs an account too, but it self-handles the missing-session
    // case with a tailored message (see run_node_list), so it's not gated here.
    let requires_login = matches!(
        &cli.command,
        Commands::Extension { .. }
            | Commands::Update { .. }
            | Commands::Status
            | Commands::Db { .. }
            | Commands::Run { .. }
    );
    if requires_login && cfx_core::auth::load_account(&base).is_none() {
        eprintln!("  You are not logged in.");
        eprintln!("  Run `crossfyre login` first (then `crossfyre node init` to register this host).");
        std::process::exit(1);
    }

    match cli.command {
        Commands::Login { api_key, username, password, api_url, agree_tos, no_prompt } => {
            cfx_core::auth::run_login(&base, cfx_core::auth::LoginFlags {
                api_key, username, password, api_url, agree_tos, no_prompt,
            }).await?;
        }
        Commands::Logout => {
            cfx_core::auth::run_logout(&base);
        }
        Commands::Node { action } => match action {
            NodeAction::Init { force, api_url, no_service, node_key, no_prompt } => {
                cfx_core::run_init(force, &api_url, &base, no_service, node_key, no_prompt).await?;
            }
            NodeAction::Remove { node_id, inactive } => {
                cfx_core::run_node_remove(&base, node_id, inactive).await?;
            }
            NodeAction::List { json } => {
                cfx_core::run_node_list(&base, json).await?;
            }
            NodeAction::Status => {
                cfx_core::toolchain::status::nodes(&base)?;
            }
            NodeAction::Up { force } => {
                if cfx_core::toolchain::service::node_service_exists() {
                    cfx_core::toolchain::service::start(cfx_core::toolchain::service::NODE_TARGET)?;
                    println!("Node supervisor started. Run `crossfyre node status` to see the daemons.");
                } else {
                    // No OS service (e.g. `node init --no-service`, or non-Linux):
                    // run the supervisor in the foreground instead.
                    println!("No node service installed; running the supervisor in the foreground (Ctrl-C to stop).");
                    exec_node_supervise(&base, force)?;
                }
            }
            NodeAction::Down => {
                if cfx_core::toolchain::service::node_service_exists() {
                    cfx_core::toolchain::service::stop(cfx_core::toolchain::service::NODE_TARGET)?;
                    println!("Node supervisor stopped.");
                } else {
                    println!("No node service installed; nothing to stop. (If a foreground `node up` is running, press Ctrl-C there.)");
                }
            }
            NodeAction::Restart => {
                cfx_core::toolchain::service::restart(cfx_core::toolchain::service::NODE_TARGET)?;
            }
            NodeAction::Enable => {
                cfx_core::toolchain::service::enable(cfx_core::toolchain::service::NODE_TARGET)?;
            }
            NodeAction::Disable => {
                cfx_core::toolchain::service::disable(cfx_core::toolchain::service::NODE_TARGET)?;
            }
        },
        Commands::Extension { action } => match action {
            ExtensionAction::List => cfx_core::toolchain::status::extensions()?,
            ExtensionAction::Install { name, force } => {
                match name.as_deref() {
                    Some(ext) => {
                        if force {
                            cfx_core::toolchain::install::install(ext, true).await?;
                            for e in cfx_core::toolchain::resolve_extensions(ext)? {
                                cfx_core::toolchain::service::enable(e)?;
                                cfx_core::toolchain::service::start(e)?;
                            }
                        } else {
                            cfx_core::toolchain::install::install_and_start(ext).await?;
                        }
                    }
                    None => cfx_core::toolchain::print_extension_usage("install"),
                }
            }
            ExtensionAction::Remove { name } => {
                match name.as_deref() {
                    Some(ext) => cfx_core::toolchain::install::remove(ext)?,
                    None => cfx_core::toolchain::print_extension_usage("remove"),
                }
            }
            ExtensionAction::Update { name } => {
                cfx_core::toolchain::install::update(name.as_deref()).await?;
            }
            ExtensionAction::Start { name } => cfx_core::toolchain::service::start(&name)?,
            ExtensionAction::Stop { name } => cfx_core::toolchain::service::stop(&name)?,
            ExtensionAction::Restart { name } => cfx_core::toolchain::service::restart(&name)?,
            ExtensionAction::Enable { name } => cfx_core::toolchain::service::enable(&name)?,
            ExtensionAction::Disable { name } => cfx_core::toolchain::service::disable(&name)?,
        },
        Commands::Run { script, targets } => {
            cfx_core::run_script(&script, &targets).await?;
        }
        Commands::Update { target } => {
            let self_updated = cfx_core::toolchain::install::update(target.as_deref()).await?;
            if self_updated && cfx_core::toolchain::service::node_service_exists() {
                println!("Restarting the node service to pick up the new binary...");
                let _ = cfx_core::toolchain::service::restart(cfx_core::toolchain::service::NODE_TARGET);
            }
        }
        Commands::Status => {
            cfx_core::toolchain::status::overview(&base)?;
        }
        Commands::Db { command } => {
            cfx_core::toolchain::db::run(&command)?;
        }
        Commands::Doctor => {
            cfx_core::toolchain::doctor::run(&base).await?;
        }
        Commands::Uninstall { purge } => {
            cfx_core::toolchain::uninstall::run(purge)?;
        }
    }

    Ok(())
}

