//! Isolated-egress orchestration.
//!
//! Open-core boundary. The real per-node egress mechanism (network isolation,
//! tunnels, transparent routing) is a private drop-in (`private.rs`, git-ignored)
//! that `build.rs` selects when it is present. A public checkout has only
//! `baseline.rs` (direct egress, no isolation), so the open build compiles and
//! runs but does not apply isolated egress. Isolated egress is a platform
//! feature.
//!
//! Both implementations expose the same small surface, so `lib.rs` is identical
//! regardless of which is compiled:
//!   - [`process_network_config`] ingests a node's network config,
//!   - [`bring_up`] applies egress and returns a [`TunnelGuard`],
//!   - [`TunnelGuard`] tears everything down on `Drop`.

// One `mod`, with the path chosen by cfg, rather than two cfg-gated `mod imp;`
// declarations. Both forms compile identically, but tools that resolve modules
// without evaluating cfg (rustfmt, rustdoc, rust-analyzer) tried to read BOTH
// arms of the old form and hard-errored on a public checkout, where private.rs
// does not exist:
//
//     error: couldn't read core/src/egress/private.rs: No such file or directory
//
// That made `cargo fmt` and `cargo doc` unusable for outside contributors.
#[cfg_attr(egress_private, path = "private.rs")]
#[cfg_attr(not(egress_private), path = "baseline.rs")]
mod imp;

pub use imp::{TunnelGuard, bring_up, process_network_config};
