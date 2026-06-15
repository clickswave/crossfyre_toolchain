# Contributing to the Crossfyre Toolchain

Thanks for taking the time to contribute. This repo holds the open-source engines (`mach`, `voyage`, `pulse`), the node agent (`node`), and the `crossfyre` CLI.

## Ground rules

- Be respectful. We follow the standard expectation of professional, harassment-free conduct.
- Only contribute code you have the right to contribute. By opening a pull request, you agree your contribution is licensed under the same [Apache-2.0](LICENSE) terms as the project.

## Reporting bugs

Open an issue and include:

- The tool and version (`mach --version`).
- The exact command you ran.
- What you expected, and what happened instead.
- Your OS and architecture.

For anything security-sensitive, do **not** open a public issue. See [SECURITY.md](SECURITY.md).

## Proposing changes

- For small fixes (typos, obvious bugs), a pull request is fine.
- For anything larger (new flags, new behavior, new sources), open an issue first so we can agree on the approach before you invest the work. It saves everyone time.

## Development

You need a recent stable [Rust toolchain](https://rustup.rs).

```sh
cargo build            # build the whole workspace
cargo test             # run the tests
cargo fmt              # format before you commit
cargo clippy           # lint; please keep it warning-clean
```

Keep pull requests focused: one logical change per PR, with a clear description of what and why. Match the style of the surrounding code.

## What belongs here

This repo is the open toolchain: scanning and recon engines, plus the agent that runs them. Platform and orchestration features (scheduling, fleet management, the hosted dashboard) live in the Crossfyre platform, not here. If you are unsure whether something fits, open an issue and ask.
