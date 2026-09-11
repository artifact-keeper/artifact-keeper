#!/usr/bin/env bash
# Self-test for check-supply-chain-soft-fail.sh (#3496).
#
# The guard exists because a control that cannot report its own failure is not
# a control, so the guard itself has to be able to fail. Each case below builds
# a throwaway `.github/workflows` directory and asserts the exit status: the
# six shapes that actually shipped (attestation and VEX soft-failed in
# docker-publish.yml) must be rejected, and so must the near-misses — a cosign
# step soft-failed in some other workflow, an unrelated soft step in the
# publish workflow, a `continue-on-error` written as an expression instead of a
# literal, and a workflow set with no supply-chain step at all (which would
# otherwise pass vacuously).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="$HERE/check-supply-chain-soft-fail.sh"

pass=0
fail=0

check() { # <label> <expected-status> <workflow-dir> [expected-substring]
  local label="$1" expected="$2" dir="$3" needle="${4:-}" status=0 out
  out="$("$GUARD" "$dir" 2>&1)" || status=$?
  if [ "$status" -ne "$expected" ]; then
    echo "  FAIL $label: expected exit $expected, got $status"
    echo "$out" | sed 's/^/       | /'
    fail=$((fail + 1))
    return
  fi
  if [ -n "$needle" ] && ! grep -qF -- "$needle" <<<"$out"; then
    echo "  FAIL $label: exit $status was right but output did not mention '$needle'"
    echo "$out" | sed 's/^/       | /'
    fail=$((fail + 1))
    return
  fi
  echo "  ok   $label (exit $status)"
  pass=$((pass + 1))
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# <dir> <workflow-filename> <soft-attest> <soft-vex> <soft-unrelated>
# Each `soft-*` argument is either empty (hard-fail) or a YAML scalar to put
# after `continue-on-error:`.
make_publish() {
  local dir="$1" name="$2" soft_attest="$3" soft_vex="$4" soft_unrelated="$5"
  mkdir -p "$dir/.github/workflows"
  {
    echo "name: publish"
    echo "on: push"
    echo "jobs:"
    echo "  merge-backend:"
    echo "    runs-on: ubuntu-latest"
    echo "    steps:"
    echo "      - name: Apply ghcr tags"
    echo "        run: docker buildx imagetools create -t ghcr.io/o/i:1 ghcr.io/o/i@sha256:abc"
    if [ -n "$soft_unrelated" ]; then echo "        continue-on-error: $soft_unrelated"; fi
    echo "      - name: Sign image with cosign (keyless)"
    echo "        run: cosign sign --yes ghcr.io/o/i@sha256:abc"
    echo "      - name: Generate artifact attestation"
    echo "        uses: actions/attest-build-provenance@a2bbfa25 # v4"
    echo "        with:"
    echo "          subject-name: ghcr.io/o/i"
    if [ -n "$soft_attest" ]; then echo "        continue-on-error: $soft_attest"; fi
    echo "      - name: Attach VEX attestations"
    echo "        run: docker scout attestation add --file .vex/a.json ghcr.io/o/i@sha256:abc"
    if [ -n "$soft_vex" ]; then echo "        continue-on-error: $soft_vex"; fi
  } >"$dir/.github/workflows/$name"
}

echo "check-supply-chain-soft-fail self-test"

# The corrected shape: nothing soft anywhere.
make_publish "$tmp/good" docker-publish.yml "" "" ""
check "hard-fail publish workflow is accepted" 0 "$tmp/good/.github/workflows"

# The shipped defect, half 1: provenance attestation soft-failed.
make_publish "$tmp/soft-attest" docker-publish.yml true "" ""
check "soft attestation step is rejected" 1 "$tmp/soft-attest/.github/workflows" \
  "supply-chain control"

# The shipped defect, half 2: VEX attachment soft-failed.
make_publish "$tmp/soft-vex" docker-publish.yml "" true ""
check "soft VEX step is rejected" 1 "$tmp/soft-vex/.github/workflows" \
  "publish workflow"

# Any other soft step in the publish workflow is rejected too: the next one
# added would otherwise re-open the same hole under a different name.
make_publish "$tmp/soft-other" docker-publish.yml "" "" true
check "unrelated soft step in the publish workflow is rejected" 1 \
  "$tmp/soft-other/.github/workflows" "Apply ghcr tags"

# An expression that could evaluate to true is soft, and must not slip past a
# literal comparison against `true`.
make_publish "$tmp/soft-expr" docker-publish.yml "\${{ github.event_name == 'schedule' }}" "" ""
check "expression-valued continue-on-error is rejected" 1 \
  "$tmp/soft-expr/.github/workflows" "supply-chain control"

# `continue-on-error: false` is explicit hard-fail and must be accepted.
make_publish "$tmp/explicit-false" docker-publish.yml false false false
check "explicit continue-on-error: false is accepted" 0 \
  "$tmp/explicit-false/.github/workflows"

# Invariant 1 is repo-wide, not publish-workflow-only: copying an attestation
# step into another workflow does not buy it an exemption. (The publish
# workflow is present too, so the non-vacuity check is not what fires.)
make_publish "$tmp/other-wf" docker-publish.yml "" "" ""
mkdir -p "$tmp/other-wf/.github/workflows"
cat >"$tmp/other-wf/.github/workflows/nightly-publish.yml" <<'EOF'
name: nightly
on: schedule
jobs:
  nightly:
    runs-on: ubuntu-latest
    steps:
      - name: Sign image with cosign (keyless)
        run: cosign sign --yes ghcr.io/o/i@sha256:abc
        continue-on-error: true
EOF
check "soft cosign step in another workflow is rejected" 1 \
  "$tmp/other-wf/.github/workflows" "nightly-publish.yml"

# Job-level continue-on-error in the publish workflow is rejected as well: it
# is less bad than step-level (the job result is not `success`) but it still
# publishes an image whose controls did not run.
mkdir -p "$tmp/soft-job/.github/workflows"
cat >"$tmp/soft-job/.github/workflows/docker-publish.yml" <<'EOF'
name: publish
on: push
jobs:
  merge-backend:
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - name: Generate artifact attestation
        uses: actions/attest-build-provenance@a2bbfa25 # v4
EOF
check "job-level continue-on-error in the publish workflow is rejected" 1 \
  "$tmp/soft-job/.github/workflows" "job-level"

# Non-vacuity: if signing and attestation vanish entirely the guard must fail
# rather than report a clean tree.
mkdir -p "$tmp/no-controls/.github/workflows"
cat >"$tmp/no-controls/.github/workflows/docker-publish.yml" <<'EOF'
name: publish
on: push
jobs:
  merge-backend:
    runs-on: ubuntu-latest
    steps:
      - name: Apply ghcr tags
        run: docker buildx imagetools create -t ghcr.io/o/i:1 ghcr.io/o/i@sha256:abc
EOF
check "a workflow set with no supply-chain step is rejected" 1 \
  "$tmp/no-controls/.github/workflows" "vacuously"

# A missing directory is an error, not a pass.
check "a missing workflow directory is rejected" 1 "$tmp/does-not-exist" "not found"

echo
echo "passed: $pass   failed: $fail"
[ "$fail" -eq 0 ]
