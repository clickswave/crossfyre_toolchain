#!/usr/bin/env python3
"""Guard the open-core `adaptive` swap.

`adaptive/` (committed, open baseline) and `adaptive-private/` (git-ignored tuned
drop-in) share a package name and are swapped at build time by the `.cargo/config.toml`
`[paths]` override. For that swap to stay sound, the two crates MUST expose the
*same public API surface* - dependents (core, mach, pulse, voyage) compile against
whichever is present, so a `pub` item that drifts in one but not the other breaks
either the first-party build or the public build, and the break shows up far from
the edit.

This checks that the public API surfaces match. It does NOT look at bodies - the
private crate's whole point is that its implementations differ. Run it locally
(the private drop-in never ships, so no CI ever has both): it is wired into the
committed `.githooks/pre-push`.

Exit codes: 0 = in parity (or private drop-in absent -> skipped), 1 = drift.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBLIC = os.path.join(ROOT, "adaptive", "src")
PRIVATE = os.path.join(ROOT, "adaptive-private", "src")

# A "public surface" line: a top-level or impl/trait item, or a struct field /
# enum variant, that is visible to dependents. `pub(crate)`/`pub(super)` are
# internal, so they are deliberately excluded - they can differ freely.
PUB_ITEM = re.compile(r"^\s*pub\s+(?:unsafe\s+)?(?:async\s+)?"
                      r"(?:fn|struct|enum|trait|type|const|static|mod|union)\b")
PUB_FIELD = re.compile(r"^\s*pub\s+[A-Za-z_][A-Za-z0-9_]*\s*:")  # pub name: Type
PUBCRATE = re.compile(r"^\s*pub\s*\(")  # pub(crate) / pub(super) / pub(in ..)


def strip_line_comment(s: str) -> str:
    # Good enough for signature lines; we never need string-literal fidelity here.
    i = s.find("//")
    return s[:i] if i != -1 else s


def signatures(src_dir: str) -> set:
    """Extract the normalized set of public-API declarations from a crate's src.

    For fns/types/consts the full signature is captured (joining continuation
    lines) up to the `{`, `;`, or `where`. For struct/enum/trait the header plus
    each public member (pub fields, all enum variants, trait item signatures) is
    captured, tracking nesting so member scanning stops at the item's close.
    """
    out = set()
    files = []
    for base, _dirs, names in os.walk(src_dir):
        for n in names:
            if n.endswith(".rs"):
                files.append(os.path.join(base, n))
    for path in sorted(files):
        rel = os.path.relpath(path, src_dir)
        with open(path, "r") as f:
            raw = f.readlines()
        lines = [strip_line_comment(l).rstrip("\n") for l in raw]
        i = 0
        while i < len(lines):
            line = lines[i]
            t = line.strip()
            if PUBCRATE.match(line):
                i += 1
                continue
            is_item = bool(PUB_ITEM.match(line))
            is_field = bool(PUB_FIELD.match(line))
            if not (is_item or is_field):
                i += 1
                continue
            # `pub const`/`pub static` carry a VALUE after `=` - and for the tuned
            # drop-in that value IS the secret (WINDOW_MS = 400 vs 500). The API
            # surface is `NAME: Type`, never the value, so terminate those at `=`.
            # Everything else (incl. `pub type X = Y`, where the alias target is
            # part of the API) keeps its full signature.
            is_valued = bool(re.match(r"^\s*pub\s+(?:const|static)\b", line))
            terms = r"[{;=]" if is_valued else r"[{;]"
            # Accumulate the declaration until a signature terminator.
            buf = t
            j = i
            while not re.search(terms, buf) and " where" not in buf and j + 1 < len(lines):
                j += 1
                buf += " " + lines[j].strip()
            # Header = everything up to the first terminator (the signature), normalized.
            header = re.split(terms, buf, maxsplit=1)[0].strip()
            header = re.sub(r"\s+", " ", header)
            kind = header.split()[1] if len(header.split()) > 1 else header
            out.add(f"{rel}:: {header}")
            # For struct/enum/trait, also record the public members inside the block.
            if is_item and re.match(r"^\s*pub\s+(?:struct|enum|trait|union)\b", line) and "{" in buf:
                depth = buf.count("{") - buf.count("}")
                container = kind  # struct|enum|trait
                k = j
                while depth > 0 and k + 1 < len(lines):
                    k += 1
                    ml = lines[k]
                    mt = ml.strip()
                    depth += ml.count("{") - ml.count("}")
                    if not mt or mt.startswith("#"):
                        continue
                    if container == "enum":
                        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)", mt)
                        if m:
                            out.add(f"{rel}::{header}::variant {m.group(1)}")
                    elif container == "struct":
                        if mt.startswith("pub ") and not PUBCRATE.match(ml):
                            fld = re.sub(r"\s+", " ", re.split(r"[,]", mt, maxsplit=1)[0]).strip()
                            out.add(f"{rel}::{header}::field {fld}")
                    elif container == "trait":
                        if re.match(r"^(?:unsafe\s+)?(?:async\s+)?(?:fn|type|const)\b", mt):
                            sig = re.split(r"[{;]", mt, maxsplit=1)[0].strip()
                            out.add(f"{rel}::{header}::item {re.sub(r'\\s+', ' ', sig)}")
                i = k + 1
                continue
            i = j + 1
    return out


def main() -> int:
    if not os.path.isdir(PRIVATE):
        print("adaptive parity: adaptive-private/ absent (public checkout) - skipped")
        return 0
    if not os.path.isdir(PUBLIC):
        print("adaptive parity: adaptive/src missing - cannot check", file=sys.stderr)
        return 1
    pub = signatures(PUBLIC)
    prv = signatures(PRIVATE)
    only_pub = sorted(pub - prv)
    only_prv = sorted(prv - pub)
    if not only_pub and not only_prv:
        print(f"adaptive parity: OK ({len(pub)} public API items match)")
        return 0
    print("adaptive parity: DRIFT - the open `adaptive` and private `adaptive-private`")
    print("public API surfaces differ. The `[paths]` swap requires them identical.\n")
    if only_pub:
        print("  Only in adaptive/ (public baseline):")
        for s in only_pub:
            print(f"    + {s}")
    if only_prv:
        print("  Only in adaptive-private/ (tuned drop-in):")
        for s in only_prv:
            print(f"    - {s}")
    print("\nBring both crates' public signatures back in line before pushing.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
