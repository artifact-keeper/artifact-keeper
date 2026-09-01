#!/usr/bin/env bash
#
# Self-test for scripts/ci/assert-binary-sbom.sh (issue #3558).
#
# WHY THIS EXISTS
#   The gate under test asserts that a release binary really carries the
#   dependency graph we claim it carries. The reason it needs an assertion at
#   all -- and the reason case 2 below is the important one -- is that the tool
#   doing the looking FAILS OPEN. Measured with cargo-audit 0.22.2 against a
#   binary built WITHOUT `cargo auditable`:
#
#       warning: <path> was not built with 'cargo auditable', the report will
#                be incomplete (1 dependencies recovered)
#       $ echo $?
#       0
#
#   It falls back to scraping a partial dependency list out of panic messages,
#   says so in a warning, and exits 0. So a job that merely "runs cargo audit
#   bin" cannot fail for the reason it was added: drop `cargo auditable` from
#   the build command and CI stays green while every shipped binary silently
#   loses its embedded SBOM. Case 2 is the revert-proof for that.
#
#   The strings the stub replays are the real tool's real output, transcribed
#   from those runs, so the parser is tested against what it will actually see.
#
# HOW
#   `cargo` is stubbed first on PATH; the SBOM fixtures are real files. No
#   network, no compiler, ~1s.
#
# Usage: bash scripts/ci/test-assert-binary-sbom.sh
set -uo pipefail

GATE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assert-binary-sbom.sh"
[ -f "$GATE" ] || { echo "cannot find assert-binary-sbom.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

STUB="$WORK/bin"; mkdir -p "$STUB"

# `cargo audit bin`, replayed. FAKE_AUDIT selects which real-world answer.
cat > "$STUB/cargo" <<'STUBCARGO'
#!/usr/bin/env bash
[ "${1:-}" = "audit" ] || { echo "stub cargo: unexpected '${1:-}'" >&2; exit 64; }
shift
# swallow `--color never bin` and pick up the path
bin_path=""
while [ $# -gt 0 ]; do
  case "$1" in
    --color) shift 2 ;;
    bin)     shift ;;
    *)       bin_path="$1"; shift ;;
  esac
done
preamble() {
  echo "    Fetching advisory database from \`https://github.com/RustSec/advisory-db.git\`"
  echo "      Loaded 1226 security advisories (from /home/runner/.cargo/advisory-db)"
  echo "    Updating crates.io index"
}
case "${FAKE_AUDIT:-auditable}" in
  auditable)
    preamble
    echo "       Found 'cargo auditable' data in ${bin_path} (744 dependencies)"
    exit 0 ;;
  plain)
    # VERBATIM shape of the real fail-open answer.
    preamble
    echo "warning: ${bin_path} was not built with 'cargo auditable', the report will be incomplete (1 dependencies recovered)"
    exit 0 ;;
  low)
    preamble
    echo "       Found 'cargo auditable' data in ${bin_path} (3 dependencies)"
    exit 0 ;;
  vulns)
    preamble
    echo "       Found 'cargo auditable' data in ${bin_path} (744 dependencies)"
    echo "Crate:     some-crate"
    echo "Version:   0.1.0"
    echo "Title:     A vulnerability"
    echo "ID:        RUSTSEC-2099-0001"
    echo "error: 1 vulnerability found!"
    exit 1 ;;
  dbfail)
    echo "error: couldn't fetch advisory database: git operation failed: failed to resolve address for github.com: Temporary failure in name resolution"
    exit 1 ;;
  nodata)
    # The third real state: `load_deps_from_binary` found nothing at all, not
    # even the panic-message fallback. Verbatim wording from cargo-audit.
    preamble
    echo "error: No dependency information found in ${bin_path}! Is it a Rust program built with cargo?"
    exit 1 ;;
  garbage)
    echo "something entirely unexpected happened"
    exit 0 ;;
  notinstalled)
    echo "error: no such subcommand: \`audit\`" >&2
    exit 101 ;;
esac
STUBCARGO
chmod +x "$STUB/cargo"

sbom_with() {  # <path> <n-components> [bomFormat] [subject-name]
  local path="$1" n="$2" fmt="${3-CycloneDX}" subject="${4-artifact-keeper-backend}"
  {
    printf '{"bomFormat":"%s","specVersion":"1.5",' "$fmt"
    printf '"metadata":{"component":{"type":"application","name":"%s","version":"9.9.9"}},' "$subject"
    printf '"components":['
    local i
    for i in $(seq 1 "$n"); do
      printf '{"type":"library","name":"c%s","version":"1.0.0"}' "$i"
      [ "$i" -lt "$n" ] && printf ','
    done
    printf ']}'
  } > "$path"
}

BIN="$WORK/artifact-keeper-linux-amd64"
SBOM="$WORK/artifact-keeper-linux-amd64.cdx.json"

reset_case() {
  printf 'pretend ELF with a .dep-v0 section\n' > "$BIN"
  sbom_with "$SBOM" 60
  FAKE_AUDIT=auditable
  CASE_BIN="$BIN"; CASE_SBOM="$SBOM"
}

# <label> <expected-exit> <expected-substring>
expect() {
  local label="$1" want="$2" needle="$3" got=0
  ( PATH="$STUB:$PATH" \
      BINARY="${CASE_BIN-$BIN}" \
      SBOM="${CASE_SBOM-$SBOM}" \
      FAKE_AUDIT="${FAKE_AUDIT:-auditable}" \
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

echo "embedded-SBOM gate: every leg"

# 1. HAPPY PATH first, so a later red is about the change and not the fixture.
reset_case
expect "auditable binary + valid CycloneDX SBOM -> PASS" 0 \
  "744 embedded dependencies"

# 2. ★ THE FAIL-OPEN ARM. This is exactly what `cargo audit bin` prints, and
#    exactly the exit code it returns, for a binary built with a plain
#    `cargo build`. Revert the build command to `cargo build` and this is the
#    case that goes red -- nothing else would.
reset_case
FAKE_AUDIT=plain
expect "binary NOT built with cargo auditable (tool exits 0!) -> BLOCKED" 1 \
  "carries NO embedded dependency data"

# 3. Embedded data present but nearly empty: the wrong binary, or an embedding
#    that covered one crate. Well-formed and worthless.
reset_case
FAKE_AUDIT=low
expect "embedded graph below the dependency floor -> BLOCKED" 1 \
  "below the floor"

# 3b. Not a cargo-built Rust binary at all -- a truncated upload, a wrapper
#     script, the wrong file packaged under the binary's name.
reset_case
FAKE_AUDIT=nodata
expect "no dependency information of any kind -> BLOCKED" 1 \
  "found no dependency information of any kind"

# 4. An answer the gate does not recognise is not a pass.
reset_case
FAKE_AUDIT=garbage
expect "unparseable cargo-audit output -> BLOCKED" 1 \
  "not what this gate knows how to read"

# 5/6. INFRA: nothing was measured. Distinct from "the artifact is wrong",
#      because a name-resolution failure on a cold runner says nothing about
#      the bytes.
reset_case
FAKE_AUDIT=dbfail
expect "advisory database unreachable -> INFRA (exit 2)" 2 \
  "could not load its advisory database"

reset_case
FAKE_AUDIT=notinstalled
expect "cargo-audit not installed -> INFRA (exit 2)" 2 \
  "is unavailable"

# 7. Advisories found. Deliberately NOT fatal here -- vulnerability policy is
#    owned by ci.yml's security-audit gate and .cargo/audit.toml -- but the
#    embedded-SBOM verdict still has to be reached and reported.
reset_case
FAKE_AUDIT=vulns
expect "advisories reported, embedded data present -> PASS with a warning" 0 \
  "::warning title=Advisories reported against the release binary"

# 8. The SBOM asset half.
reset_case
rm -f "$SBOM"
expect "missing .cdx.json -> BLOCKED" 1 \
  "does not exist"

reset_case
sbom_with "$SBOM" 60 "SPDX"
expect "SBOM asset is not CycloneDX -> BLOCKED" 1 \
  "expected 'CycloneDX'"

reset_case
sbom_with "$SBOM" 4
expect "SBOM asset has almost no components -> BLOCKED" 1 \
  "below the floor of"

reset_case
sbom_with "$SBOM" 60 "CycloneDX" ""
expect "SBOM asset does not say what it describes -> BLOCKED" 1 \
  "metadata.component.name is empty"

reset_case
printf 'not json at all' > "$SBOM"
expect "SBOM asset is not JSON -> BLOCKED" 1 \
  "not parseable as JSON"

# 9. No binary at all: nothing was packaged for this target.
reset_case
rm -f "$BIN"
expect "binary absent -> BLOCKED" 1 \
  "does not exist"

# 10. The SBOM validator's interpreter missing is INFRA, not a bad artifact.
reset_case
mkdir -p "$WORK/shim"
for t in bash cargo grep sed basename printf head tr cat; do
  real="$(command -v "$t" || true)"
  [ -n "$real" ] && ln -sf "$real" "$WORK/shim/$t"
done
ln -sf "$STUB/cargo" "$WORK/shim/cargo"
got=0
( PATH="$WORK/shim" BINARY="$BIN" SBOM="$SBOM" FAKE_AUDIT=auditable \
    bash "$GATE" >"$WORK/out.txt" 2>&1 ) || got=$?
if [ "$got" = "2" ] && grep -qF "python3 is not on PATH" "$WORK/out.txt"; then
  pass "python3 unavailable -> INFRA (exit 2) (exit $got)"
else
  fail "python3 unavailable: expected exit 2 mentioning python3, got $got"
  sed 's/^/        /' "$WORK/out.txt" >&2
fi

echo
if [ "$fails" -eq 0 ]; then
  printf '\033[32mall embedded-SBOM gate cases behaved as required\033[0m\n'
  exit 0
fi
printf '\033[31m%s case(s) failed\033[0m\n' "$fails"
exit 1
