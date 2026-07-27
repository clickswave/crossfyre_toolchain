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

#[cfg(egress_private)]
#[path = "private.rs"]
mod imp;

#[cfg(not(egress_private))]
#[path = "baseline.rs"]
mod imp;

pub use imp::{TunnelGuard, bring_up, process_network_config};
