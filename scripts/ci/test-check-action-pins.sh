#!/usr/bin/env bash
# Self-test for scripts/ci/check-action-pins.sh (#6178): each unpinned shape
# fails, each allowed shape passes.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$HERE/check-action-pins.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
SHA=3d3c42e5aac5ba805825da76410c181273ba90b1

case_() { # <label> <want exit> <yaml>
  printf '%s\n' "$3" >"$WORK/wf.yml"
  local rc=0
  bash "$CHECK" "$WORK/wf.yml" >"$WORK/out" 2>&1 || rc=$?
  if [[ "$rc" == "$2" ]]; then
    echo "  PASS  $1"
  else
    echo "  FAIL  $1: expected exit $2, got $rc"; sed 's/^/        /' "$WORK/out"
    fails=$((fails + 1))
  fi
}

case_ "sha pin with a version comment" 0 "    steps:
      - uses: actions/checkout@$SHA # v7.0.1"
case_ "quoted sha pin" 0 "      - uses: 'actions/checkout@$SHA'"
case_ "local action" 0 "      - uses: ./.github/actions/setup"
case_ "docker digest" 0 "      - uses: docker://alpine@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
case_ "tag ref" 1 "      - uses: actions/checkout@v7.0.1"
case_ "major tag ref" 1 "      - uses: actions/upload-artifact@v7"
case_ "branch ref" 1 "      - uses: dtolnay/rust-toolchain@master"
case_ "short sha" 1 "      - uses: actions/checkout@3d3c42e"
case_ "sha only in the comment" 1 "      - uses: actions/checkout@v7 # $SHA"
case_ "reusable workflow by branch" 1 "    uses: artifact-keeper/artifact-keeper-test/.github/workflows/release-gate.yml@main"
case_ "flow-style tag ref" 1 "      - {uses: actions/checkout@v7, with: {fetch-depth: 0}}"
case_ "flow-style sha pin" 0 "      - {name: co, uses: actions/checkout@$SHA}"
case_ "docker tag" 1 "      - uses: docker://alpine:3.20"
case_ "versioned install-action tools" 0 "      - uses: taiki-e/install-action@$SHA # v2.90.6
        with:
          tool: cargo-nextest@0.9.152,sqlx-cli@0.9.1"
case_ "unversioned install-action tool" 1 "      - uses: taiki-e/install-action@$SHA # v2.90.6
        with:
          tool: cargo-nextest@0.9.152,sqlx-cli"
case_ "tool: of another action is not checked" 0 "      - uses: some/action@$SHA
        with:
          tool: anything
      - run: echo hi"
case_ "install-action scope ends at the next step" 0 "      - uses: taiki-e/install-action@$SHA
        with:
          tool: cargo-nextest@0.9.152
      - name: other
        uses: other/action@$SHA
        with:
          tool: free-text"

if [[ "$fails" -gt 0 ]]; then
  echo "$fails case(s) failed"; exit 1
fi
echo "all check-action-pins cases passed"
