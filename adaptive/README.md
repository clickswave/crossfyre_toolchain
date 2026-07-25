# adaptive

Adaptive rate-limiting and resilience control for Crossfyre engines: given a
stream of probe outcomes, decide how many probes to run concurrently, how long
to wait between them, and whether a failed probe is worth retrying.

## Open baseline vs. private tuning

This crate is the **open reference implementation**. It defines the interface the
engines (`pulse`, `mach`, `voyage`, `cfx_core`) call and provides a conservative,
**untuned** baseline behaviour using round placeholder constants. It builds
standalone and ships publicly. Nothing here is the production tuning.

The production build swaps in a private drop-in with the same public API (the
tuned per-posture tables and control law) via a Cargo `paths` override. That
override and its config are git-ignored and never published:

```
crossfyre_toolchain/
  adaptive/            # this crate, committed, open baseline
  adaptive-private/    # git-ignored, the tuned drop-in (same name + version)
  .cargo/config.toml   # git-ignored, paths = ["adaptive-private"]
```

With the override present (first-party builds), Cargo transparently replaces this
crate with `adaptive-private`. In a public checkout neither exists, so this
baseline is what builds, the open crates compile and run without the secret.

**When you change the public API here, mirror the signatures in `adaptive-private`
so it stays a clean drop-in.**
