#!/usr/bin/env bash
# Point this repo's git hooks at the committed .githooks/ directory. Run once
# per clone. First-party developers should run it so the adaptive API-parity
# guard fires on push; a public checkout can run it too (the guard no-ops when
# the private drop-in is absent).
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"
git config core.hooksPath .githooks
chmod +x .githooks/* 2>/dev/null || true
echo "hooks installed: core.hooksPath -> .githooks"
echo "  pre-push: adaptive open/private API parity (scripts/check_adaptive_parity.py)"
