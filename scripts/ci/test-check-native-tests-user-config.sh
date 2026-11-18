#!/usr/bin/env bash
#
# Self-test for scripts/ci/check-native-tests-user-config.sh (#5940): it must
# fail on each way a native test can write user-level client config and pass
# on the scoped forms.
#
# Usage: bash scripts/ci/test-check-native-tests-user-config.sh
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check-native-tests-user-config.sh"
[ -f "$SCRIPT" ] || {
  echo "cannot find check-native-tests-user-config.sh next to this test" >&2
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

check() { # <want rc> <name> <script line>...
  local want="$1" name="$2"
  shift 2
  n=$((n + 1))
  local dir="$WORK/case.$n"
  mkdir -p "$dir"
  printf '%s\n' "$@" > "$dir/test-case.sh"
  NATIVE_TESTS_DIR="$dir" bash "$SCRIPT" > "$dir/out" 2>&1
  local rc=$?
  if [ "$rc" -eq "$want" ]; then
    pass "$name"
  else
    fail "$name (exit $rc, want $want)"
    sed 's/^/        /' "$dir/out"
  fi
}

echo "check-native-tests-user-config.sh"

check 1 "bare npm config set" \
  'WORK_DIR="$(mktemp -d)"' \
  'npm config set registry "$NPM_REGISTRY"'
check 1 "bare yarn config set" \
  'yarn config set registry "$NPM_REGISTRY"'
check 0 "npm config set after exporting NPM_CONFIG_USERCONFIG" \
  'WORK_DIR="$(mktemp -d)"' \
  'export NPM_CONFIG_USERCONFIG="$WORK_DIR/.npmrc"' \
  'npm config set registry "$NPM_REGISTRY"'
check 0 "npm config set with --userconfig or --location=project" \
  'npm config set registry "$NPM_REGISTRY" --userconfig "$WORK_DIR/.npmrc"' \
  'npm config set registry "$NPM_REGISTRY" --location=project'
check 0 "npm config set only in a comment" \
  '  # npm config set registry would write ~/.npmrc'
check 1 "helm repo add without HELM_REPOSITORY_CONFIG" \
  'helm repo add test-registry "$REGISTRY_URL"'
check 0 "helm repo add after exporting HELM_REPOSITORY_CONFIG" \
  'export HELM_REPOSITORY_CONFIG="$WORK_DIR/helm/repositories.yaml"' \
  'helm repo add test-registry "$REGISTRY_URL"'
check 1 "heredoc into ~/.cargo" \
  'cat > ~/.cargo/config.toml << EOF' \
  'EOF'
check 1 'mkdir under $HOME' \
  'mkdir -p "$HOME/.m2"'
check 1 'append to ${HOME}' \
  'echo x >> ${HOME}/.condarc'
check 1 "tee -a into ~/" \
  'echo x | tee -a ~/.pypirc'
check 0 "writes inside the work dir" \
  'mkdir -p "$WORK_DIR/.cargo"' \
  'cat > "$WORK_DIR/.cargo/config.toml" << EOF' \
  'EOF' \
  'echo "see ~/.npmrc" > "$WORK_DIR/notes"'

n=$((n + 1))
NATIVE_TESTS_DIR="$WORK/missing" bash "$SCRIPT" > /dev/null 2>&1
rc=$?
if [ "$rc" -eq 2 ]; then
  pass "missing directory is infra"
else
  fail "missing directory is infra (exit $rc, want 2)"
fi

echo
if [ "$fails" -ne 0 ]; then
  echo "$fails of $n cases failed"
  exit 1
fi
echo "all $n cases passed"
