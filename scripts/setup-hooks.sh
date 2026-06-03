#!/usr/bin/env bash
# Enable the repository's git hooks (one-time, per clone).
#
#   ./scripts/setup-hooks.sh
#
# Points git at the version-controlled hooks in .githooks/ so formatting,
# build, and unit-test checks run automatically on commit and push. No extra
# tooling required beyond git and cargo.

set -euo pipefail
cd "$(dirname "$0")/.."

git config core.hooksPath .githooks
chmod +x .githooks/* 2>/dev/null || true

echo "Git hooks enabled (core.hooksPath -> .githooks)."
echo "  pre-commit: cargo fmt --check"
echo "  pre-push:   cargo check + cargo test --workspace --lib"
echo
echo "Bypass once with --no-verify if ever needed. Disable with:"
echo "  git config --unset core.hooksPath"
