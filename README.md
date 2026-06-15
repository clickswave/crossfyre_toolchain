<div align="center">

# Crossfyre Toolchain

**Fast, composable offensive-security engines for your terminal.**

Run them standalone, or connect them to the Crossfyre platform for distributed, scheduled scanning.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)](#)
[![Discord](https://img.shields.io/badge/discord-join-5865F2.svg)](https://discord.gg/cPccst2Vr6)

</div>

---

The Crossfyre toolchain is a set of standalone reconnaissance and scanning engines plus a lightweight node agent. Every tool here works on its own: no account, no server, no telemetry. When you outgrow a single box, the same tools plug into the hosted [Crossfyre platform](https://crossfyre.io) for fleet-wide, scheduled, resumable scans.

## What's inside

| Tool | What it does |
| --- | --- |
| **`mach`** | HTTP fuzzer and content-discovery engine with a live TUI. Stateful and resumable. |
| **`voyage`** | Subdomain enumeration engine: passive sources plus active wordlist brute-forcing. |
| **`pulse`** | Network host and port-scanning engine (SYN and connect techniques, service detection). |
| **`node`** | The Crossfyre node agent. Runs the engines on your machine and, optionally, connects to the platform. |
| **`crossfyre`** | The command-line interface that ties it together: install engines, run scans, manage nodes. |

## Quick start

### Install

Linux and macOS:

```sh
curl -fsSL https://get.crossfyre.io/install.sh | sudo bash
```

Windows (PowerShell):

```powershell
irm https://get.crossfyre.io/install.ps1 | iex
```

Prefer to build it yourself? See [Building from source](#building-from-source). Prebuilt binaries for each release are on the [Releases](../../releases) page.

### Run something

```sh
# Content discovery: fuzz a path with a wordlist
mach scan --url https://example.com/::FUZZ:: --wordlist-path ./wordlist.txt

# Subdomain enumeration: passive sources + active brute-force
voyage scan --domain example.com --wordlist-path ./subdomains.txt

# Port scan a network range, with service detection
pulse scan --targets 10.0.0.0/24 --ports top-1000 --service-detection
```

Each tool runs a live TUI by default and writes its findings to a local database, so a scan you stop can be picked up again where it left off.

## Standalone, or part of the platform

These engines are useful on their own, and that is the point: use `mach`, `voyage`, and `pulse` like any other CLI tool, on systems you are authorized to test.

When you need more than one machine can give you (a fleet of nodes, scheduled recurring scans, a shared findings dashboard, your team in one place), enrol the host as a node and the same engines run under the [Crossfyre platform](https://crossfyre.io):

```sh
crossfyre login
crossfyre node init
crossfyre node list
```

The platform is optional. Nothing here phones home unless you ask it to.

## Building from source

You need a recent stable [Rust toolchain](https://rustup.rs).

```sh
git clone https://github.com/clickswave/crossfyre_toolchain.git
cd crossfyre_toolchain
cargo build --release
# binaries land in ./target/release/{crossfyre,node,mach,voyage,pulse}
```

To install a single tool straight from the repo:

```sh
cargo install --git https://github.com/clickswave/crossfyre_toolchain.git mach
```

## Responsible use

These are offensive-security tools. Only scan systems you own or have explicit, written permission to test. Unauthorized scanning is illegal in most jurisdictions and can disrupt the systems you point it at. You are responsible for how you use them.

## Contributing

Issues and pull requests are welcome. If you are reporting a bug, include the tool, the command you ran, and what you expected. For larger changes, open an issue first so we can agree on the approach before you invest the work.

Found a security issue? Please do not open a public issue. Email **security@clickswave.org** instead.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). You may use, modify, and distribute these tools freely, including commercially, subject to the terms of the license.

---

<div align="center">
Built by <a href="https://clickswave.org">Clickswave</a>. The platform lives at <a href="https://crossfyre.io">crossfyre.io</a>.
</div>
