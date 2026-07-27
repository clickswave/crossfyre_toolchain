//! Shared terminal styling for the whole crossfyre CLI. One vocabulary so every
//! command (update, node remove/init/list/status, login, extensions, doctor,
//! uninstall, ...) looks the same:
//!
//!   * a **bold title** with a dim subtitle, wrapped in blank lines
//!   * dim **section** labels
//!   * aligned **rows** with ✓ / • / ! / ✗ symbols and a colored status
//!   * dim **hints** and a bold-green **done** summary
//!
//! Prefer these helpers over raw `println!` + ANSI in command output, so the look
//! stays consistent. ANSI is emitted unconditionally; the toolchain targets
//! interactive terminals (matching the existing status table in lib.rs).
#![allow(dead_code)]

pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const GREEN: &str = "\x1b[32m";
pub const CYAN: &str = "\x1b[36m";
pub const YELLOW: &str = "\x1b[33m";
pub const RED: &str = "\x1b[31m";

// ── inline colorizers (for a fragment inside a larger line) ─────────────
pub fn dim(s: &str) -> String {
    format!("{DIM}{s}{RESET}")
}
pub fn bold(s: &str) -> String {
    format!("{BOLD}{s}{RESET}")
}
pub fn green(s: &str) -> String {
    format!("{GREEN}{s}{RESET}")
}
pub fn yellow(s: &str) -> String {
    format!("{YELLOW}{s}{RESET}")
}
pub fn red(s: &str) -> String {
    format!("{RED}{s}{RESET}")
}
pub fn cyan(s: &str) -> String {
    format!("{CYAN}{s}{RESET}")
}

/// A version string in the aligned middle column (dim, padded to a stable width).
pub fn ver(v: &str) -> String {
    format!("{DIM}{v:<7}{RESET}")
}

// ── status symbols ──────────────────────────────────────────────────────
pub fn check() -> String {
    format!("{GREEN}\u{2713}{RESET}")
} // ✓ done / ok
pub fn dot() -> String {
    format!("{CYAN}\u{2022}{RESET}")
} // • neutral / in progress
pub fn bang() -> String {
    format!("{YELLOW}!{RESET}")
} // ! warning / skipped
pub fn cross() -> String {
    format!("{RED}\u{2717}{RESET}")
} // ✗ failed
pub fn arrow() -> String {
    format!("{CYAN}\u{203a}{RESET}")
} // › working

// ── block structure ─────────────────────────────────────────────────────

/// Header block: a blank line, `  <bold name>   <dim subtitle>`, a blank line.
/// Pass an empty `subtitle` to print just the title.
pub fn title(name: &str, subtitle: &str) {
    println!();
    if subtitle.is_empty() {
        println!("  {BOLD}{name}{RESET}");
    } else {
        println!("  {BOLD}{name}{RESET}   {}", dim(subtitle));
    }
    println!();
}

/// A dim section label, e.g. `  Nodes`.
pub fn section(label: &str) {
    println!("  {}", dim(label));
}

/// One aligned component line: `    <sym> <name>      <mid>   <status>`.
/// `sym`/`mid`/`status` may carry their own color; `name` is plain so the column
/// padding stays correct (ANSI codes do not count toward width).
pub fn row(sym: &str, name: &str, mid: &str, status: &str) -> String {
    format!("    {sym} {name:<10} {mid}   {status}")
}

/// A key/value line under a block: `    <dim label>   <value>` (label padded).
pub fn field(label: &str, value: &str) {
    println!("    {}  {value}", dim(&format!("{label:<16}")));
}

// ── single status lines (indented under a section) ──────────────────────
pub fn ok(msg: &str) {
    println!("    {} {msg}", check());
}
pub fn warn(msg: &str) {
    println!("    {} {msg}", bang());
}
pub fn fail(msg: &str) {
    println!("    {} {msg}", cross());
}
pub fn step(msg: &str) {
    println!("    {} {msg}", dot());
}
pub fn working(msg: &str) {
    println!("    {} {msg}", arrow());
}

/// A dim helper/hint line at the block (2-space) indent.
pub fn hint(msg: &str) {
    println!("  {}", dim(msg));
}

/// A bold-green summary/footer line, e.g. `Removed 3 nodes`.
pub fn done(msg: &str) {
    println!("  {BOLD}{GREEN}{msg}{RESET}");
}

/// A bold-red failure headline at the block indent, e.g. `Could not reach the server`.
pub fn error(msg: &str) {
    println!("  {} {BOLD}{msg}{RESET}", cross());
}

/// A trailing blank line to close a block.
pub fn end() {
    println!();
}
