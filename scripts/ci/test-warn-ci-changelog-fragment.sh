#!/usr/bin/env bash
#
# Self-test for scripts/ci/warn-ci-changelog-fragment.sh (#6476).
#
# The cases build scratch git repos so the check reads a real diff against a
# real base, then vary the three conditions independently: title type, a path
# outside release-commit-exemptions.sh, and an added fragment. Advisory means
# every case must exit 0, including the ones that warn.
#
# Usage: bash scripts/ci/test-warn-ci-changelog-fragment.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/scripts/ci/warn-ci-changelog-fragment.sh"
[ -f "$SCRIPT" ] || {
  echo "cannot find warn-ci-changelog-fragment.sh next to this test" >&2
  exit 2
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
n=0

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() {
  printf '  \033[31mFAIL\033[0m  %s\n' "$*"
  fails=$((fails + 1))
}

make_repo() { # -> path on stdout
  local repo="$WORK/repo.$n"
  mkdir -p "$repo/changes/unreleased" "$repo/scripts/ci"
  git -C "$repo" init -q -b main
  git -C "$repo" config user.email test@example.invalid
  git -C "$repo" config user.name Test
  printf 'seed\n' > "$repo/seed.txt"
  printf '#!/usr/bin/env bash\n' > "$repo/scripts/ci/gate.sh"
  printf '%s\n' '---' 'section: Fixed' 'issues: [#1000]' '---' '- **Old entry** (#1000). Already on the base.' \
    > "$repo/changes/unreleased/1000-existing.md"
  git -C "$repo" add -A
  git -C "$repo" commit -qm base
  git -C "$repo" branch base
  printf '%s' "$repo"
}

add_file() { # <repo> <path> [body]
  local repo="$1" path="$2" body="${3:-changed}"
  mkdir -p "$repo/$(dirname "$path")"
  printf '%s\n' "$body" > "$repo/$path"
  git -C "$repo" add -A
  git -C "$repo" commit -qm "change $path"
}

expect() { # <label> <want-warning 0|1> <needle> <title> <event> <repo> [base-ref]
  local label="$1" want="$2" needle="$3" title="$4" event="$5" repo="$6" base="${7:-base}"
  local out got has
  n=$((n + 1))
  out="$(cd "$repo" && PR_TITLE="$title" GITHUB_EVENT_NAME="$event" bash "$SCRIPT" "$base" 2>&1)"
  got=$?
  if grep -qF '::warning' <<< "$out"; then has=1; else has=0; fi
  if [ "$got" != 0 ]; then
    fail "$label: expected exit 0, got $got"
    printf '%s\n' "$out" | sed 's/^/        /' >&2
  elif [ "$has" != "$want" ]; then
    fail "$label: expected warning=$want, got $has"
    printf '%s\n' "$out" | sed 's/^/        /' >&2
  elif [ "$want" = 1 ] && [ -n "$needle" ] && ! grep -qF "$needle" <<< "$out"; then
    fail "$label: warning lacks '$needle'"
    printf '%s\n' "$out" | sed 's/^/        /' >&2
  else
    pass "$label"
  fi
}

echo "warn-ci-changelog-fragment (#6476)"

n=$((n + 1)); repo="$(make_repo)"
add_file "$repo" backend/src/x.rs
push_case="$repo"
expect "non-PR event is a no-op even with a non-CI path" 0 "" \
  "ci: touch backend" push "$push_case"

expect "non-ci title ignores a non-CI path" 0 "" \
  "feat(backend): touch x" pull_request "$push_case"

expect "plain ci title warns" 1 "backend/src/x.rs" \
  "ci: touch x" pull_request "$push_case"

expect "breaking-change ci title warns" 1 "backend/src/x.rs" \
  "ci(backend)!: touch x" pull_request "$push_case"

n=$((n + 1)); repo="$(make_repo)"
add_file "$repo" .github/workflows/check.yml
expect "workflow-only ci PR stays quiet" 0 "" \
  "ci: add a check" pull_request "$repo"

n=$((n + 1)); repo="$(make_repo)"
add_file "$repo" scripts/ci/new-gate.sh
expect "scripts/ci-only ci PR stays quiet" 0 "" \
  "ci: add a gate" pull_request "$repo"

n=$((n + 1)); repo="$(make_repo)"
add_file "$repo" backend/src/x.rs
add_file "$repo" changes/unreleased/6476-fragment.md \
  $'---\nsection: Changed\nissues: [#6476]\n---\n- **New entry** (#6476). Something shipped.\n'
expect "ci PR with a non-CI path and a new fragment stays quiet" 0 "" \
  "ci: touch backend and document it" pull_request "$repo"

n=$((n + 1)); repo="$(make_repo)"
add_file "$repo" changes/unreleased/1000-existing.md \
  $'---\nsection: Fixed\nissues: [#1000]\n---\n- **Edited entry** (#1000). Still not new.\n'
expect "editing an existing fragment is not adding one" 1 "no fragment under changes/unreleased" \
  "ci: edit only a fragment" pull_request "$repo"

n=$((n + 1)); repo="$(make_repo)"
mkdir -p "$repo/backend/src"
git -C "$repo" mv scripts/ci/gate.sh backend/src/gate.sh
git -C "$repo" commit -qm "move gate out of scripts/ci"
expect "rename out of the CI path set warns on the new path" 1 "backend/src/gate.sh" \
  "ci: move a gate" pull_request "$repo"

expect "missing base ref warns and still exits zero" 1 "base ref" \
  "ci: touch backend" pull_request "$push_case" origin/missing

echo
if [ "$fails" -gt 0 ]; then
  echo "$fails case(s) failed"
  exit 1
fi
echo "all cases passed"
