#!/usr/bin/env bash
# Self-test for check-floating-tag-promotion.sh.
#
# The gate encodes an ORDERING, and an ordering is exactly the kind of property
# that looks fine in a green run: every release where nothing goes wrong
# publishes the same tags whether or not `:latest` moved 78 minutes early. So
# the drift shapes are asserted here directly -- each one is a real edit
# someone could plausibly make while "just adding a tag" or "making the job
# more robust", and each must be refused:
#
#   * a `type=raw,value=latest` line put back into a merge job;
#   * the writer job losing one of its three merge-job `needs:` (the
#     partial-publish shape that made v1.7.2 publicly pullable);
#   * an `if: !cancelled()` added to the writer, which quietly converts
#     `success()` fan-in into "run even though a sibling failed";
#   * a promotion job in release.yml that does not depend on the gate, so
#     "post-gate" is only a comment;
#   * the promotion disappearing entirely, which would leave floating tags
#     never applied at all;
#   * the writer no longer writing anything, which would let the gate pass
#     vacuously.
#
# Throwaway YAML in a temp dir; no network, ~1s.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
GUARD="$HERE/check-floating-tag-promotion.sh"

pass=0
fail=0

check() { # <label> <expected-status> <workflow-dir> [expected-substring]
  local label="$1" expected="$2" dir="$3" needle="${4:-}" status=0 out
  out="$("$GUARD" "$dir" 2>&1)" || status=$?
  if [ "$status" -ne "$expected" ]; then
    echo "  FAIL $label: expected exit $expected, got $status"
    # shellcheck disable=SC2001  # sed is the clearest way to indent a block
    echo "$out" | sed 's/^/       | /'
    fail=$((fail + 1))
    return
  fi
  if [ -n "$needle" ] && ! grep -qF -- "$needle" <<<"$out"; then
    echo "  FAIL $label: exit $status was right but output did not mention '$needle'"
    # shellcheck disable=SC2001  # sed is the clearest way to indent a block
    echo "$out" | sed 's/^/       | /'
    fail=$((fail + 1))
    return
  fi
  echo "  ok   $label (exit $status)"
  pass=$((pass + 1))
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# make_publish <dir> <merge-tag-extra> <writer-needs> <writer-if> <writer-body>
make_publish() {
  local dir="$1" merge_extra="$2" writer_needs="$3" writer_if="$4" writer_body="$5"
  mkdir -p "$dir/.github/workflows"
  {
    echo "name: publish"
    echo "on: push"
    echo "jobs:"
    for img in backend openscap scanner-adapter; do
      echo "  merge-${img}:"
      echo "    runs-on: ubuntu-latest"
      echo "    steps:"
      echo "      - name: Extract metadata (ghcr.io)"
      echo "        uses: docker/metadata-action@dc80 # v6"
      echo "        with:"
      echo "          images: ghcr.io/o/${img}"
      echo "          tags: |"
      echo "            type=semver,pattern={{version}}"
      echo "            type=sha"
      if [ -n "$merge_extra" ] && [ "$img" = "backend" ]; then
        echo "            ${merge_extra}"
      fi
      echo "      - name: Apply ghcr tags"
      echo "        run: docker buildx imagetools create -t ghcr.io/o/${img}:1.2.3 ghcr.io/o/${img}@sha256:abc"
    done
    echo "  apply-floating-tags:"
    echo "    runs-on: ubuntu-latest"
    if [ -n "$writer_if" ]; then
      echo "    if: ${writer_if}"
    fi
    echo "    needs: [${writer_needs}]"
    echo "    steps:"
    echo "      - name: Apply floating tags"
    echo "        run: |"
    echo "          ${writer_body}"
  } > "$dir/.github/workflows/docker-publish.yml"
}

# make_release <dir> <promoter-needs|"">   ("" = no promotion job at all)
make_release() {
  local dir="$1" needs="${2:-}"
  mkdir -p "$dir/.github/workflows"
  {
    echo "name: release"
    echo "on:"
    echo "  push:"
    echo "    tags: ['v*']"
    echo "jobs:"
    echo "  release-gate:"
    echo "    uses: o/t/.github/workflows/gate.yml@main"
    echo "  release:"
    echo "    runs-on: ubuntu-latest"
    echo "    needs: [release-gate]"
    echo "    steps:"
    echo "      - run: echo publish"
    if [ -n "$needs" ]; then
      echo "  promote-floating-tags:"
      echo "    runs-on: ubuntu-latest"
      echo "    needs: [${needs}]"
      echo "    steps:"
      echo "      - run: gh workflow run docker-publish.yml -f promote_version=1.2.3 -f promote_floating=true"
    fi
  } > "$dir/.github/workflows/release.yml"
}

ALL_MERGES="merge-backend, merge-openscap, merge-scanner-adapter"
GOOD_BODY='docker buildx imagetools create -t ghcr.io/o/backend:latest ghcr.io/o/backend@sha256:abc'

echo "check-floating-tag-promotion.sh"

# The repository's own workflows are the primary case: if the shipped
# arrangement does not satisfy the gate, nothing else here matters.
check "the repo's real workflows pass" 0 "$ROOT/.github/workflows" "OK:"

ok="$tmp/ok"
make_publish "$ok" "" "$ALL_MERGES" "" "$GOOD_BODY"
make_release "$ok" "release-gate, release"
check "minimal correct arrangement" 0 "$ok/.github/workflows" "OK:"

# THE REGRESSION. Someone re-adds `latest` to a merge job -- which is exactly
# what the code looked like before this change, and what it will look like
# again the first time a metadata block is copy-pasted.
bad="$tmp/latest-in-merge"
make_publish "$bad" "type=raw,value=latest,enable=\${{ startsWith(github.ref, 'refs/tags/v') }}" "$ALL_MERGES" "" "$GOOD_BODY"
make_release "$bad" "release-gate, release"
check "latest re-added to a merge job is refused" 1 "$bad/.github/workflows" "emits a floating tag"

bad="$tmp/major-minor-in-merge"
make_publish "$bad" "type=semver,pattern={{major}}.{{minor}}" "$ALL_MERGES" "" "$GOOD_BODY"
make_release "$bad" "release-gate, release"
check "X.Y re-added to a merge job is refused" 1 "$bad/.github/workflows" "emits a floating tag"

# THE PARTIAL-PUBLISH SHAPE: the writer stops depending on one of the images,
# so backend's floating tags move whatever happened to the other two.
bad="$tmp/missing-need"
make_publish "$bad" "" "merge-backend, merge-openscap" "" "$GOOD_BODY"
make_release "$bad" "release-gate, release"
check "writer missing a merge-job need is refused" 1 "$bad/.github/workflows" "merge-scanner-adapter"

# The subtle one. `!cancelled()` reads like robustness and silently replaces
# `success()` fan-in with "run even if a sibling failed".
# shellcheck disable=SC2016  # these are literal GitHub expressions, not shell
for cond in '${{ !cancelled() }}' '${{ always() }}'; do
  bad="$tmp/writer-if-$RANDOM"
  make_publish "$bad" "" "$ALL_MERGES" "$cond" "$GOOD_BODY"
  make_release "$bad" "release-gate, release"
  check "writer with a job-level if ($cond) is refused" 1 "$bad/.github/workflows" "job-level"
done

# "Post-gate" has to be an edge in the job graph.
bad="$tmp/promote-before-gate"
make_publish "$bad" "" "$ALL_MERGES" "" "$GOOD_BODY"
make_release "$bad" "release-preflight"
check "promotion not gated on release-gate is refused" 1 "$bad/.github/workflows" "release-gate"

bad="$tmp/promote-before-release"
make_publish "$bad" "" "$ALL_MERGES" "" "$GOOD_BODY"
make_release "$bad" "release-gate"
check "promotion not gated on release is refused" 1 "$bad/.github/workflows" "needs: release"

# With the merge jobs no longer writing floating tags, losing the promotion
# means they are never written at all -- a silent, permanent stale `:latest`.
bad="$tmp/no-promotion"
make_publish "$bad" "" "$ALL_MERGES" "" "$GOOD_BODY"
make_release "$bad" ""
check "release.yml with no promotion job is refused" 1 "$bad/.github/workflows" "promote_floating"

# Non-vacuity: a writer that writes nothing must not make the gate green.
bad="$tmp/writer-writes-nothing"
make_publish "$bad" "" "$ALL_MERGES" "" "echo 'nothing to do'"
make_release "$bad" "release-gate, release"
check "writer that never re-points a tag is refused" 1 "$bad/.github/workflows" "imagetools create"

bad="$tmp/writer-no-latest"
make_publish "$bad" "" "$ALL_MERGES" "" 'docker buildx imagetools create -t ghcr.io/o/backend:1.2 ghcr.io/o/backend@sha256:abc'
make_release "$bad" "release-gate, release"
check "writer that never mentions latest is refused" 1 "$bad/.github/workflows" "does not mention"

bad="$tmp/no-writer"
make_publish "$bad" "" "$ALL_MERGES" "" "$GOOD_BODY"
sed -i 's/^  apply-floating-tags:/  some-other-job:/' "$bad/.github/workflows/docker-publish.yml"
make_release "$bad" "release-gate, release"
check "missing writer job is refused" 1 "$bad/.github/workflows" "has no \`apply-floating-tags\` job"

# A job that is switched off publishes nothing, so its stale metadata block is
# reported rather than treated as a violation (this is the suspended alpine
# job in the real workflow).
okd="$tmp/disabled-producer"
make_publish "$okd" "" "$ALL_MERGES" "" "$GOOD_BODY"
{
  echo "  merge-backend-alpine:"
  echo "    if: false"
  echo "    runs-on: ubuntu-latest"
  echo "    steps:"
  echo "      - uses: docker/metadata-action@dc80 # v6"
  echo "        with:"
  echo "          images: ghcr.io/o/backend"
  echo "          tags: |"
  echo "            type=raw,value=latest"
} >> "$okd/.github/workflows/docker-publish.yml"
make_release "$okd" "release-gate, release"
check "a disabled job's floating tags are exempt" 0 "$okd/.github/workflows" "exempt"

echo ""
echo "  ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
