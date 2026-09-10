#!/usr/bin/env bash
#
# Self-test for scripts/ci/assert-adopted-image-sources.sh (issue #3640).
#
# WHY THIS EXISTS
#   The gate under test decides whether ALREADY-PUBLISHED bytes may stand in
#   for the commit being released. Its dangerous direction is fail-open: an
#   adoption that should have been refused certifies stale bytes for a tag
#   they were not built from. So the legs that must REFUSE are the point --
#   an image-input change (down to the Dockerfile and .dockerignore, which a
#   path set written from memory would forget), missing provenance, and an
#   unverifiable commit. The one leg that must PASS is the v1.8.2 shape: the
#   published revision and the tag differ only outside the image inputs.
#
# HOW
#   A scratch git repo provides real commits; the published revision is
#   injected through ADOPT_PUBLISHED_REV exactly as release.yml passes the
#   output of registry-tag-revision.sh. No network, ~1s.
#
# Usage: bash scripts/ci/test-assert-adopted-image-sources.sh
set -uo pipefail

GATE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assert-adopted-image-sources.sh"
[ -f "$GATE" ] || { echo "cannot find assert-adopted-image-sources.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

# --- scratch repo with the real input-set layout ---------------------------
REPO="$WORK/repo"
git init -q "$REPO"
git -C "$REPO" config user.email t@t; git -C "$REPO" config user.name t
mkdir -p "$REPO/backend/src" "$REPO/.sqlx" "$REPO/docker" "$REPO/scripts/ci"
echo 'fn main() {}'        > "$REPO/backend/src/main.rs"
echo '[package]'           > "$REPO/Cargo.toml"
echo 'lock v1'             > "$REPO/Cargo.lock"
echo '{"q":1}'             > "$REPO/.sqlx/query-1.json"
echo 'FROM scratch'        > "$REPO/docker/Dockerfile.backend"
echo 'target/'             > "$REPO/.dockerignore"
echo '# changelog'         > "$REPO/CHANGELOG.md"
echo 'echo ci'             > "$REPO/scripts/ci/x.sh"
git -C "$REPO" add -A; git -C "$REPO" commit -qm base
REV_BASE="$(git -C "$REPO" rev-parse HEAD)"

commit_after() { # $1 msg; stdout: new sha (working tree already edited)
  git -C "$REPO" add -A; git -C "$REPO" commit -qm "$1"; git -C "$REPO" rev-parse HEAD
}

# <label> <expected-exit> <expected-substring>; env: CASE_SHA CASE_REV
expect() {
  local label="$1" want="$2" needle="$3" got=0
  ( cd "$REPO" && \
      ADOPT_TAG_SHA="$CASE_SHA" \
      ADOPT_PUBLISHED_REV="$CASE_REV" \
      ADOPT_LABEL="backend:9.9.9" \
      bash "$GATE" >"$WORK/out.txt" 2>&1 ) || got=$?
  if [ "$got" != "$want" ]; then
    fail "$label: expected exit $want, got $got"
    sed 's/^/        /' "$WORK/out.txt" >&2
  elif ! grep -qF -- "$needle" "$WORK/out.txt"; then
    fail "$label: exit $got correct but output lacks '$needle'"
    sed 's/^/        /' "$WORK/out.txt" >&2
  else
    pass "$label (exit $got)"
  fi
}

echo "adopted-image source gate: the legs"

# 1. The normal release: the image was built from the tagged commit itself.
CASE_SHA="$REV_BASE"; CASE_REV="$REV_BASE"
expect "published revision == tag -> ok, no adoption" 0 \
  "built from the tagged commit"

# 2. THE v1.8.2 SHAPE: the re-tag differs from the published revision only in
#    CHANGELOG.md and scripts/ci -- nothing the image is built from.
echo '# changelog v2' >  "$REPO/CHANGELOG.md"
echo 'echo ci v2'     >  "$REPO/scripts/ci/x.sh"
SHA_DOCSONLY="$(commit_after 'docs+ci only')"
CASE_SHA="$SHA_DOCSONLY"; CASE_REV="$REV_BASE"
expect "tag differs only outside image inputs -> VERIFIED adoption" 0 \
  "VERIFIED ADOPTION"

# 3. Backend source changed: the published bytes are stale for this tag.
echo 'fn main() { new(); }' > "$REPO/backend/src/main.rs"
SHA_SRC="$(commit_after 'backend change')"
CASE_SHA="$SHA_SRC"; CASE_REV="$REV_BASE"
expect "backend source changed -> REFUSED, names the file" 1 \
  "backend/src/main.rs"

# 4. Only the Dockerfile changed (base image bump, tool pin): still an image
#    input, still a different image. A path set written from the COPY lines
#    alone would miss this.
git -C "$REPO" checkout -q "$SHA_DOCSONLY" -- backend 2>/dev/null || true
git -C "$REPO" reset -q --hard "$SHA_DOCSONLY"
echo 'FROM scratch AS v2' > "$REPO/docker/Dockerfile.backend"
SHA_DF="$(commit_after 'dockerfile change')"
CASE_SHA="$SHA_DF"; CASE_REV="$REV_BASE"
expect "Dockerfile changed -> REFUSED" 1 \
  "docker/Dockerfile.backend"

# 5. Only .dockerignore changed: it shapes what COPY backend sees.
git -C "$REPO" reset -q --hard "$SHA_DOCSONLY"
echo 'target/ extra/' > "$REPO/.dockerignore"
SHA_DI="$(commit_after 'dockerignore change')"
CASE_SHA="$SHA_DI"; CASE_REV="$REV_BASE"
expect ".dockerignore changed -> REFUSED" 1 \
  ".dockerignore"

# 6. The published image has no provenance annotation. Unverifiable is not
#    adoptable -- and it is a real verdict, not an infra retry.
CASE_SHA="$SHA_DOCSONLY"; CASE_REV="none"
expect "no revision annotation -> REFUSED as unverifiable" 1 \
  "no org.opencontainers.image.revision"

# 7. The registry could not be read at all: indeterminate, distinct from both
#    pass and refuse, so the caller can retry instead of mis-verdicting.
CASE_SHA="$SHA_DOCSONLY"; CASE_REV="indeterminate"
expect "indeterminate revision -> INFRA" 2 \
  "indeterminate"

# 8. The published revision names a commit this repo cannot produce: no
#    comparison, no verdict, no adoption.
CASE_SHA="$SHA_DOCSONLY"; CASE_REV="1111111111111111111111111111111111111111"
expect "unfetchable published commit -> INFRA" 2 \
  "not fetchable"

# 9. Malformed tag sha -> infra, not a quiet pass.
CASE_SHA="deadbeef"; CASE_REV="$REV_BASE"
expect "short tag sha -> INFRA" 2 \
  "ADOPT_TAG_SHA"

echo
if [ "$fails" -gt 0 ]; then
  echo "${fails} case(s) FAILED"
  exit 1
fi
echo "all cases passed"
