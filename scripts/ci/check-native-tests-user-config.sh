#!/usr/bin/env bash
#
# CI gate for issue #5940: scripts/native-tests/test-npm.sh ran a bare
# `npm config set`, so every local run left the test registry and its
# credentials in the developer's ~/.npmrc. test-cargo.sh and test-maven.sh
# overwrote ~/.cargo/config.toml and ~/.m2/settings.xml the same way.
#
# A native test keeps client config in its own work dir. This fails on:
#   - `npm|yarn|pnpm config set` in a script that does not export
#     NPM_CONFIG_USERCONFIG (or pass --userconfig / --location=project)
#   - `helm repo add` in a script that does not export HELM_REPOSITORY_CONFIG
#   - a redirect, tee or mkdir into ~/ or $HOME/
#
# Env:
#   NATIVE_TESTS_DIR  directory to scan (default: scripts/native-tests), for
#                     the self-test
#
# Exit codes: 0 clean, 1 a script writes user-level config, 2 infra.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIR="${NATIVE_TESTS_DIR:-$ROOT/scripts/native-tests}"

if [ ! -d "$DIR" ]; then
  echo "INFRA: $DIR is not a directory" >&2
  exit 2
fi

HOME_RE='(~|\$HOME|\$\{HOME\})/'
found=0

report() { # <file> <line> <why>
  echo "$1:$2: $3"
  found=1
}

code_lines() { # <file>: line-numbered, comment lines dropped
  grep -nv '^[[:space:]]*#' "$1" || true
}

while IFS= read -r -d '' f; do
  rel="${f#"$ROOT"/}"

  if ! grep -Eq '^[[:space:]]*export NPM_CONFIG_USERCONFIG=' "$f"; then
    while IFS=: read -r ln text; do
      case "$text" in *--userconfig* | *--location=project*) continue ;; esac
      report "$rel" "$ln" "npm config set without NPM_CONFIG_USERCONFIG writes ~/.npmrc"
    done < <(code_lines "$f" | grep -E '^[0-9]+:.*\b(npm|yarn|pnpm) config set\b' || true)
  fi

  if ! grep -Eq '^[[:space:]]*export HELM_REPOSITORY_CONFIG=' "$f"; then
    while IFS=: read -r ln _; do
      report "$rel" "$ln" "helm repo add without HELM_REPOSITORY_CONFIG writes the user's helm config"
    done < <(code_lines "$f" | grep -E '^[0-9]+:.*\bhelm repo add\b' || true)
  fi

  while IFS=: read -r ln _; do
    report "$rel" "$ln" "writes under the user's home directory, use the work dir"
  done < <(code_lines "$f" | grep -E "^[0-9]+:.*((>>?|tee( -a)?)[[:space:]]*\"?$HOME_RE|mkdir( -p)?[[:space:]]+\"?$HOME_RE)" || true)
done < <(find "$DIR" -name '*.sh' -type f -print0 | sort -z)

if [ "$found" -ne 0 ]; then
  echo "native tests must keep client config in their work dir (#5940)" >&2
  exit 1
fi
echo "native tests keep client config in their work dir"
