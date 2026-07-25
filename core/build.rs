//! Selects the isolated-egress implementation at build time.
//!
//! If the private drop-in `src/egress/private.rs` is present (first-party
//! builds), compile it and set `cfg(egress_private)`. A public checkout has only
//! `src/egress/baseline.rs`, so the open build compiles the direct-egress
//! baseline. See `src/egress/mod.rs`.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(egress_private)");
    if std::path::Path::new("src/egress/private.rs").exists() {
        println!("cargo::rustc-cfg=egress_private");
    }
    println!("cargo::rerun-if-changed=src/egress/private.rs");
}
