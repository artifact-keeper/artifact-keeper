#!/usr/bin/env bash
#
# Self-test for scripts/ci/check-registry-publish-parity.sh (issue #3562).
#
# WHY THIS EXISTS
#   The gate under test is green on a healthy workflow no matter what it does,
#   so the only way to know it works is to hand it the broken shapes on
#   purpose. The most important one is case 2: it is `docker-publish.yml`
#   EXACTLY as it stood before #3562 -- every image mirrored to Docker Hub,
#   `cosign sign` pointed at ghcr alone. That configuration was green under
#   every other check this repository has, including the two that exist
#   specifically to protect image signing (`check-supply-chain-soft-fail.sh`
#   and, for ghcr, `check-published-image-signature.sh`), for the project's
#   whole history. If this gate does not go red on case 2, it is decoration.
#
#   Case 6 is the other one worth reading. The gate's scope is defined by the
#   presence of a cosign signing step, so without a non-vacuity floor you
#   could satisfy it by DELETING a signing step -- the very defect it guards.
#
#   Case 11 replays the repository's real workflow rather than a fixture, so
#   the gate stays anchored to the thing it is meant to be about.
#
# HOW
#   The gate reads a YAML file and nothing else. Each case writes a small
#   workflow to a temp dir and asserts the exit code and a phrase. No network,
#   no registry, no `gh`; ~1s.
#
# Usage: bash scripts/ci/test-check-registry-publish-parity.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="$HERE/check-registry-publish-parity.sh"
[ -f "$GATE" ] || { echo "cannot find check-registry-publish-parity.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

# job <name> <sign-targets> <verify-targets> [if-false]
#   sign-targets / verify-targets: "both" | "ghcr" | "hub" | "none"
# Every emitted job mirrors to Docker Hub, which is what puts it in scope.
job() {
  local name="$1" sign="$2" verify="$3" iffalse="${4-}"
  printf '  %s:\n' "$name"
  printf '    runs-on: ubuntu-latest\n'
  [ -n "$iffalse" ] && printf '    if: false\n'
  printf '    steps:\n'
  printf '      - name: Copy to Docker Hub\n'
  printf '        run: |\n'
  printf '          docker buildx imagetools create -t docker.io/artifactkeeper/%s:1.0.0 ghcr.io/x/%s@sha256:aa\n' "$name" "$name"
  case "$sign" in
    none) : ;;
    *)
      printf '      - name: Sign image with cosign (keyless)\n'
      printf '        run: |\n'
      case "$sign" in
        both|ghcr) printf '          cosign sign --yes ghcr.io/x/%s@sha256:aa\n' "$name" ;;
      esac
      case "$sign" in
        both|hub) printf '          cosign sign --yes docker.io/artifactkeeper/%s@sha256:aa\n' "$name" ;;
      esac
      ;;
  esac
  case "$verify" in
    none) : ;;
    *)
      printf '      - name: Verify the published tags resolve to signed bytes\n'
      printf '        run: |\n'
      case "$verify" in
        both) printf '          scripts/ci/check-published-image-signature.sh ghcr.io/x/%s:1.0.0 docker.io/artifactkeeper/%s:1.0.0\n' "$name" "$name" ;;
        ghcr) printf '          scripts/ci/check-published-image-signature.sh ghcr.io/x/%s:1.0.0\n' "$name" ;;
        hub)  printf '          scripts/ci/check-published-image-signature.sh docker.io/artifactkeeper/%s:1.0.0\n' "$name" ;;
      esac
      ;;
  esac
}

# expect <label> <expected-exit> <expected-substring> -- then the workflow body
# arrives on stdin.
expect() {
  local label="$1" want="$2" needle="$3" got=0
  local wf="$WORK/docker-publish.yml"
  { printf 'name: t\non: push\njobs:\n'; cat; } > "$wf"
  bash "$GATE" "$wf" >"$WORK/out.txt" 2>&1 || got=$?
  if [ "$got" != "$want" ]; then
    fail "$label: expected exit $want, got $got"
    sed 's/^/        /' "$WORK/out.txt" | head -20
    return
  fi
  if [ -n "$needle" ] && ! grep -qF -- "$needle" "$WORK/out.txt"; then
    fail "$label: exit $got correct but output lacks '$needle'"
    sed 's/^/        /' "$WORK/out.txt" | head -20
    return
  fi
  pass "$label"
}

echo "check-registry-publish-parity.sh"

# 1. Parity holds on all three jobs.
expect "full parity passes" 0 "sign and verify every registry" <<EOF
$(job merge-backend both both)
$(job merge-openscap both both)
$(job merge-scanner-adapter both both)
EOF

# 2. THE #3562 FIXTURE. The workflow exactly as it was: mirrored to Docker Hub
#    everywhere, signed on ghcr only. Green under every other check in this
#    repository; must be red here.
expect "signing ghcr only BLOCKS (the shipped defect)" 1 "mirrors an image to Docker Hub" <<EOF
$(job merge-backend ghcr ghcr)
$(job merge-openscap ghcr ghcr)
$(job merge-scanner-adapter ghcr ghcr)
EOF

# 3. Signed on both, but the gate still only looks at ghcr. This is how the
#    fix silently rots back: the signature is there today and nothing notices
#    when a later change stops producing it.
expect "verifying ghcr only BLOCKS" 1 "verifies published tags on ghcr only" <<EOF
$(job merge-backend both ghcr)
$(job merge-openscap both both)
$(job merge-scanner-adapter both both)
EOF

# 4. Parity runs both ways: dropping the ghcr signature is equally a defect.
expect "signing Docker Hub only BLOCKS" 1 "no ghcr one" <<EOF
$(job merge-backend hub both)
$(job merge-openscap both both)
$(job merge-scanner-adapter both both)
EOF

expect "verifying Docker Hub only BLOCKS" 1 "not on ghcr" <<EOF
$(job merge-backend both hub)
$(job merge-openscap both both)
$(job merge-scanner-adapter both both)
EOF

# 5. Signs, publishes, and asserts nothing. `cosign sign` prints nothing on the
#    happy path, so this is the #3559 shape one registry over.
expect "publishing with no verification step BLOCKS" 1 "never runs check-published-image-signature.sh" <<EOF
$(job merge-backend both none)
$(job merge-openscap both both)
$(job merge-scanner-adapter both both)
EOF

# 6. NON-VACUITY. Scope is defined by the presence of a signing step, so
#    deleting one would otherwise remove a job from its own guard and leave the
#    gate cheerfully green on two-thirds of a publish.
expect "too few in-scope jobs BLOCKS rather than passing vacuously" 1 "expected at least 3" <<EOF
$(job merge-backend both both)
$(job merge-openscap both both)
$(job merge-scanner-adapter none none)
EOF

# 7. A job disabled with a literal \`if: false\` publishes nothing, so its
#    defect is not a finding -- but it must be named in the output rather than
#    silently dropped, and re-enabling it must bring it back into scope.
expect "an if:false job is skipped and SAID to be skipped" 0 "Skipped" <<EOF
$(job merge-backend both both)
$(job merge-openscap both both)
$(job merge-scanner-adapter both both)
$(job merge-backend-alpine ghcr none true)
EOF

expect "the same job re-enabled is back in scope and BLOCKS" 1 "merge-backend-alpine" <<EOF
$(job merge-backend both both)
$(job merge-openscap both both)
$(job merge-scanner-adapter both both)
$(job merge-backend-alpine ghcr none)
EOF

# 8. A job that writes Docker Hub tags but signs nothing is out of scope by
#    design -- \`apply-floating-tags\` re-points tags at an already-signed
#    digest and uploads no bytes. It must not be dragged in.
expect "a tag-only job (apply-floating-tags shape) is out of scope" 0 "OK: 3 publish job(s)" <<EOF
$(job merge-backend both both)
$(job merge-openscap both both)
$(job merge-scanner-adapter both both)
  apply-floating-tags:
    runs-on: ubuntu-latest
    steps:
      - name: Apply floating tags
        run: |
          docker buildx imagetools create -t docker.io/artifactkeeper/backend:latest docker.io/artifactkeeper/backend@sha256:aa
EOF

# 9..10. INFRASTRUCTURE. Not being able to ask the question is exit 2, never a
#        pass and never a finding about the workflow.
got=0; bash "$GATE" "$WORK/does-not-exist.yml" >"$WORK/out.txt" 2>&1 || got=$?
if [ "$got" = 2 ]; then pass "missing workflow file is INFRA, not a pass"
else fail "missing workflow file: expected exit 2, got $got"; fi

printf 'jobs:\n  a:\n   - [unbalanced\n' > "$WORK/bad.yml"
got=0; bash "$GATE" "$WORK/bad.yml" >"$WORK/out.txt" 2>&1 || got=$?
if [ "$got" = 2 ]; then pass "unparsable workflow is INFRA, not a pass"
else fail "unparsable workflow: expected exit 2, got $got"; sed 's/^/        /' "$WORK/out.txt" | head -5; fi

# 11. The real thing. Fixtures prove the logic; this proves the logic is
#     pointed at this repository's actual publish workflow.
REAL="$(cd "$HERE/../.." && pwd)/.github/workflows/docker-publish.yml"
if [ -f "$REAL" ]; then
  got=0; bash "$GATE" "$REAL" >"$WORK/out.txt" 2>&1 || got=$?
  if [ "$got" = 0 ]; then pass "the repository's real docker-publish.yml has registry parity"
  else fail "real docker-publish.yml: expected exit 0, got $got"; sed 's/^/        /' "$WORK/out.txt" | head -30; fi
else
  fail "real docker-publish.yml not found at $REAL"
fi

echo ""
if [ "$fails" -gt 0 ]; then
  echo "FAILED: $fails case(s)"
  exit 1
fi
echo "OK: every case behaved (including all ${0##*/} BLOCK and INFRA legs)."
