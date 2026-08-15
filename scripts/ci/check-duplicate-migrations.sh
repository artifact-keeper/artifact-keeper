#!/usr/bin/env bash
#
# CI gate for issue #3313: duplicate sqlx migration version numbers.
#
# Two migration PRs that pick the same version number produce NO textual merge
# conflict (different filenames), both report mergeable CLEAN, and both pass CI
# independently — then the backend ABORTS at startup after the second one
# merges, because sqlx sorts migrations by version without deduplicating
# (`duplicate key value violates unique constraint "_sqlx_migrations_pkey"`,
# #1128; near-miss renumber 193 -> 195 recorded in
# backend/migrations/195_curation_attestation_verification.sql).
#
# This check is only meaningful against the MERGE RESULT, not a PR branch in
# isolation: each branch has exactly one file at the colliding number, so the
# duplicate is invisible on either side alone. GitHub's default `pull_request`
# checkout is already the PR's merge commit, which is the property the CI step
# depends on — do not move this to a `pull_request.head` checkout.
#
# What it does:
#   1. FAILS on two files in backend/migrations/ whose version prefixes are
#      the same NUMBER. Comparison is numeric, not textual: sqlx parses the
#      prefix as an integer, so `007_a.sql` and `7_b.sql` are the same
#      version even though a string-prefix dedup would pass them.
#   2. FAILS on a file with no numeric version prefix at all (sqlx would
#      refuse the whole directory).
#   3. WARNS (exit 0) on gaps in the version sequence. A gap usually means a
#      migration was renumbered on one side of a merge and the ledger is
#      drifting — the same underlying condition as a duplicate, one step
#      earlier. Warning rather than failing because legitimate gaps exist in
#      history and retro-renumbering shipped migrations is exactly the
#      mistake this file warns against.
#
# Env:
#   MIGRATIONS_DIR  directory to scan (default backend/migrations at the repo
#                   root); exists so the self-test can point at fixtures.
#
# Exit codes: 0 clean (possibly with gap warnings), 1 duplicate/unparseable
# version, 2 infra (directory missing/empty).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MIGRATIONS_DIR="${MIGRATIONS_DIR:-$ROOT/backend/migrations}"

if [[ ! -d "$MIGRATIONS_DIR" ]]; then
  echo "INFRA: migrations directory not found: $MIGRATIONS_DIR" >&2
  exit 2
fi

shopt -s nullglob
files=("$MIGRATIONS_DIR"/*.sql)
shopt -u nullglob
if [[ ${#files[@]} -eq 0 ]]; then
  echo "INFRA: no .sql migrations in $MIGRATIONS_DIR" >&2
  exit 2
fi

status=0
declare -A seen # numeric version -> first filename claiming it

for f in "${files[@]}"; do
  name="$(basename "$f")"
  prefix="${name%%_*}"
  if [[ ! "$prefix" =~ ^[0-9]+$ ]]; then
    echo "::error::migration has no numeric version prefix: $name (sqlx cannot order it)"
    status=1
    continue
  fi
  ver=$((10#$prefix)) # numeric: 007 and 7 are the SAME sqlx version
  if [[ -n "${seen[$ver]:-}" ]]; then
    echo "::error::duplicate migration version $ver: '${seen[$ver]}' vs '$name'." \
         "sqlx does not deduplicate versions; the backend aborts at startup" \
         "after this merges (#3313, #1128). Renumber one of them to the next" \
         "free slot."
    status=1
  else
    seen[$ver]="$name"
  fi
done

# Gap warning (never blocks): report missing versions between the observed
# min and max, so a renumber-in-flight is visible on the PR that creates it.
if [[ $status -eq 0 && ${#seen[@]} -gt 0 ]]; then
  mapfile -t versions < <(printf '%s\n' "${!seen[@]}" | sort -n)
  min="${versions[0]}"
  max="${versions[${#versions[@]} - 1]}"
  gaps=()
  for ((v = min; v <= max; v++)); do
    [[ -z "${seen[$v]:-}" ]] && gaps+=("$v")
  done
  if [[ ${#gaps[@]} -gt 0 ]]; then
    echo "::warning::gap(s) in migration version sequence (${gaps[*]}):" \
         "usually a renumber on one side of a merge. Not blocking, but check" \
         "that no in-flight PR still claims the gap number(s) (#3313)."
  fi
fi

if [[ $status -eq 0 ]]; then
  echo "migration versions: ${#seen[@]} unique, no duplicates"
fi
exit "$status"
