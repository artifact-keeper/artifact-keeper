#!/usr/bin/env bash
#
# Build gate: refuse to ship a release binary that does not actually carry its
# own dependency graph, and refuse a CycloneDX SBOM asset that is not one
# (issue #3558).
#
# WHY THIS EXISTS, AND WHY IT IS NOT A FORMALITY
# ---------------------------------------------
# `build-binaries` now builds with `cargo auditable`, which embeds the resolved
# dependency list in the shipped binary (`.dep-v0` on ELF, the equivalent
# section on Mach-O and PE), so an operator holding only the artifact can ask
# `cargo audit bin artifact-keeper-linux-amd64` what is in it. That is the whole
# value: an SBOM that travels separately from the artifact is an SBOM you have
# to trust someone to have paired correctly.
#
# The trap this script closes, measured rather than assumed:
#
#     $ cargo audit bin plain-build/striptest
#     warning: plain-build/striptest was not built with 'cargo auditable',
#              the report will be incomplete (1 dependencies recovered)
#     $ echo $?
#     0
#
# `cargo audit bin` EXITS 0 on a binary with no embedded data. It falls back to
# recovering a partial dependency list from panic messages and says so in a
# warning. So "we run cargo audit bin in CI" is, on its own, a check that
# cannot fail for the reason it was added -- which is the same species as every
# other soft control this repository has had to remove (#2824, #3496, the
# step-level `continue-on-error` that made `resilience-tests` unfalsifiable).
# Drop the `cargo auditable` wrapper from the build command and CI stays green
# unless something asserts on the OUTPUT. This is that assertion.
#
# The dependency-count floor is the second half of the same idea. A binary can
# carry a well-formed, correctly-parsed, *nearly empty* dependency list -- if
# the wrapper covered only the final crate, or if the wrong binary was
# packaged. artifact-keeper resolves ~700 crates, so a floor of a few dozen
# separates "the embedding worked" from "something answered the question
# without doing the work".
#
# WHAT THIS DELIBERATELY DOES NOT DO: BLOCK ON VULNERABILITIES
#   `cargo audit bin` exits non-zero when it finds an advisory, and this script
#   does not treat that as a failure. That is a scoping decision, not an
#   oversight:
#     * Vulnerability policy already has an owner -- `cargo audit` is a hard
#       merge gate in ci.yml's `security-audit` job, and `.cargo/audit.toml`
#       carries a reachability justification for every suppression. A release
#       cut from a green `main` has already passed it.
#     * The only NEW thing blocking here would catch is an advisory published
#       between the merge and the tag. The remedy for that -- add a justified
#       suppression, land it, re-cut -- costs a burned immutable version number
#       (`refs/tags/v*` is covered by ruleset 19144026 and v1.7.2 is the
#       cautionary tale), at 2am, for a finding nobody has triaged yet.
#     * Turning a routine advisory publication into a release-stopping event is
#       how a gate gets a reputation for crying wolf, and that reputation is
#       what makes the next person add `continue-on-error`.
#   Findings are printed in full and raised as a workflow warning, so the
#   information is not lost -- it is just not the thing that stops the tag.
#
# THE SIZE CEILING (issue #3636)
#   `cargo audit bin` refuses, before opening the file, any binary larger than
#   a default 100 MiB:
#
#       error: bad parameter: binary dist/artifact-keeper-linux-amd64 exceeds
#              max size limit of 104857600 bytes
#       $ echo $?
#       2
#
#   That is what happened on the v1.8.2 tag. Measured on the real published
#   v1.8.1 assets and the real v1.8.2 build artifact:
#
#       linux-amd64    119,661,680  +14.1 MiB over  -> gate could not run
#       linux-arm64    102,317,720    2.4 MiB under -> gate ran, 721 deps
#       windows-amd64  139,272,192  +32.8 MiB over  -> gate could not run
#
#   The x86_64/aarch64 split is not a build-configuration difference. Both
#   linux binaries are reported `stripped` by file(1) and `[profile.release]
#   strip = true` is already set in Cargo.toml, so STRIPPING IS NOT AN
#   AVAILABLE REMEDY HERE -- it is already applied. The architectures simply
#   straddle the limit, and aarch64 clears it by 2.4 MiB, which is one
#   dependency bump from failing too.
#
#   So the ceiling is raised explicitly, rather than passed `0` (unlimited).
#   The point of a ceiling is that a multi-GB file packaged under the binary's
#   name should be refused rather than read into the runner's memory; the point
#   of raising it is that ~114 MiB is the size our binaries legitimately are.
#   A binary over the RAISED ceiling still BLOCKS, at the named arm below --
#   the gate does not stop failing closed just because the number moved.
#
# Env:
#   BINARY                (required) path to the built binary to inspect
#   SBOM                  (optional) path to the CycloneDX .cdx.json for the
#                         same target; validated when set
#   MIN_DEPS              default 50  -- floor on embedded dependency count
#   MIN_SBOM_COMPONENTS   default 50  -- floor on CycloneDX component count
#   MAX_BINARY_SIZE       default 512MiB -- ceiling handed to `cargo audit bin`
#                         (see THE SIZE CEILING below)
#   GITHUB_STEP_SUMMARY   appended to when set
#
# Exit codes:
#   0  the binary carries a plausible embedded dependency graph (and the SBOM,
#      if given, is a well-formed CycloneDX document)
#   1  BLOCKED -- the artifact is not what it claims to be
#   2  INFRA   -- could not measure (tool missing, advisory DB unreachable).
#                 NOT a pass.
#
set -uo pipefail

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; RST=$'\033[0m'
[[ -t 1 ]] || { RED=""; GRN=""; YEL=""; RST=""; }

BINARY="${BINARY:-}"
SBOM="${SBOM:-}"
MIN_DEPS="${MIN_DEPS:-50}"
MIN_SBOM_COMPONENTS="${MIN_SBOM_COMPONENTS:-50}"
MAX_BINARY_SIZE="${MAX_BINARY_SIZE:-536870912}"   # 512 MiB; see THE SIZE CEILING

declare -a detail=()
say() { detail+=("$1"); printf '  %s\n' "$1"; }

summarise() {
  local status="$1" line="$2"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo "### Embedded SBOM check (\`$(basename "${BINARY:-?}")\`): ${status}"
      echo
      echo "| | |"
      echo "|---|---|"
      echo "| binary | \`${BINARY}\` |"
      echo "| sbom | \`${SBOM:-<none>}\` |"
      echo "| verdict | ${line} |"
      echo
      # `"${arr[@]}"` on an EMPTY array is an unbound-variable error under
      # `set -u` in bash before 4.4 -- and /bin/bash on the macOS runners this
      # repository builds on is 3.2. `${arr[@]+...}` is the portable guard.
      # `detail` is empty on exactly the early-failure paths that matter, so
      # without this the summary write would itself fail there.
      for d in ${detail[@]+"${detail[@]}"}; do echo "- ${d}"; done
    } >> "$GITHUB_STEP_SUMMARY"
  fi
}

block() {
  echo
  printf '%sBLOCKED%s: %s\n' "$RED" "$RST" "$1"
  echo "::error title=Release binary has no embedded dependency graph::$1"
  summarise "BLOCKED" "$1"
  exit 1
}

infra() {
  echo
  printf '%sINFRA%s: %s\n' "$YEL" "$RST" "$1"
  echo "::error title=Embedded SBOM could not be measured::$1 This is not a pass -- retry."
  summarise "INFRA" "$1"
  exit 2
}

echo "== embedded dependency-graph check (#3558) =="
echo "binary: ${BINARY}"
echo "sbom:   ${SBOM:-<none>}"

[[ -n "$BINARY" ]] || infra "BINARY is not set."
[[ -f "$BINARY" ]] || block "${BINARY} does not exist. Nothing was packaged for this target."
[[ -s "$BINARY" ]] || block "${BINARY} is empty."

command -v cargo   >/dev/null 2>&1 || infra "cargo is not on PATH."
# Only needed for the SBOM half, but checked here so a missing interpreter is
# reported as INFRA rather than arriving as an unrecognised parse failure.
[[ -z "$SBOM" ]] || command -v python3 >/dev/null 2>&1 || \
  infra "python3 is not on PATH, so the CycloneDX SBOM asset cannot be validated."

# ---------------------------------------------------------------------------
# 1. the embedded dependency graph
# ---------------------------------------------------------------------------
printf '\n1. cargo audit bin\n'

# Reported unconditionally: the v1.8.2 failure was invisible until someone
# measured the artifact, and the aarch64 headroom is small enough that the
# number is worth having in every release log.
bin_bytes="$(wc -c < "$BINARY" | tr -d '[:space:]')"
echo "      size: ${bin_bytes} bytes (ceiling ${MAX_BINARY_SIZE})"

# `--max-binary-size` is load-bearing (issue #3636), and cargo-audit is
# installed as `@latest`, so the flag is not guaranteed to be there. Detect it
# rather than discover its absence as an unparseable answer: a tool that cannot
# be driven is a measurement that did not happen, which is INFRA, not a pass.
help_out="$(cargo audit bin --help 2>&1)" || true
if ! printf '%s' "$help_out" | grep -qF -- "--max-binary-size"; then
  # Distinguish "no cargo-audit" from "a cargo-audit that lost the flag".
  # Both are INFRA, but they are different things to go and fix, and the
  # not-installed case would otherwise be reported as a flag problem.
  if printf '%s' "$help_out" | grep -qiE "no such (file or directory|subcommand)|is not installed|Unrecognized|command not found"; then
    infra "\`cargo audit bin\` is unavailable (is cargo-audit installed in this job?). The embedded data was not inspected."
  fi
  infra "this cargo-audit's \`bin\` subcommand has no --max-binary-size flag, so the ${bin_bytes}-byte binary cannot be submitted to it. Pin a cargo-audit that has it, or update this gate to the flag's new name. Nothing was measured."
fi

audit_out=""
audit_rc=0
audit_out="$(cargo audit --color never bin --max-binary-size "$MAX_BINARY_SIZE" "$BINARY" 2>&1)" || audit_rc=$?
printf '%s\n' "$audit_out" | sed 's/^/      /'

# `cargo audit` is installed via taiki-e/install-action in the same job; a
# missing subcommand means the install step did not run, not a bad artifact.
if printf '%s' "$audit_out" | grep -qiE "no such (file or directory|subcommand)|is not installed|Unrecognized|command not found"; then
  infra "\`cargo audit bin\` is unavailable (is cargo-audit installed in this job?). The embedded data was not inspected."
fi

# The advisory database is fetched over the network on a cold runner. An
# outage there says nothing about the artifact.
if printf '%s' "$audit_out" | grep -qiE "couldn't fetch|error fetching|unable to fetch|failed to fetch|connection refused|no such host|i/o timeout|TLS handshake|context deadline exceeded" \
   && ! printf '%s' "$audit_out" | grep -q "cargo auditable"; then
  infra "cargo-audit could not load its advisory database, so it never got as far as reading ${BINARY}."
fi

# Over even the RAISED ceiling. cargo-audit exits 2 here having never opened
# the file, so nothing about the artifact was established. It is nonetheless
# BLOCKED rather than INFRA: at 512 MiB this is not a transient condition a
# retry clears, it is a binary that is either wrong or has grown far past what
# this release ships, and either way a human has to look. The distinct message
# exists so that person is told which knob moved, instead of being handed the
# generic "unrecognised answer" verdict that made the v1.8.2 failure take a
# log dive to understand.
if printf '%s' "$audit_out" | grep -qE "exceeds max size limit"; then
  block "${BINARY} is ${bin_bytes} bytes, over the ${MAX_BINARY_SIZE}-byte ceiling this gate hands \`cargo audit bin\`, so its embedded dependency graph was never read. Raise MAX_BINARY_SIZE if the release binary has legitimately grown; otherwise find out what got packaged under this name."
fi

# THE ARM THAT MATTERS. cargo-audit prints this and exits 0.
if printf '%s' "$audit_out" | grep -qF "was not built with 'cargo auditable'"; then
  block "${BINARY} carries NO embedded dependency data: cargo-audit fell back to recovering a partial list from panic messages. The build did not go through \`cargo auditable build\`, so \`cargo audit bin\` gives a consumer of this release an incomplete answer while looking like it gave a complete one. Do not ship it."
fi

# The third state cargo-audit can report. `load_deps_from_binary` returning
# `None` means it could not find dependency data of ANY kind -- not even the
# panic-message fallback -- which is what a non-Rust file, a truncated upload
# or a wrapper script packaged under the binary's name looks like.
if printf '%s' "$audit_out" | grep -qF "No dependency information found in"; then
  block "cargo-audit found no dependency information of any kind in ${BINARY}. That is not a Rust executable built by cargo, so whatever got packaged under this name is not the artifact this release is supposed to ship."
fi

# "Found 'cargo auditable' data in <path> (N dependencies)"
found_line="$(printf '%s\n' "$audit_out" | grep -F "Found 'cargo auditable' data" | head -1)"
if [[ -z "$found_line" ]]; then
  block "cargo-audit reported neither embedded data nor the 'not built with cargo auditable' warning for ${BINARY}. Its output is not what this gate knows how to read, and an unrecognised answer is not a pass."
fi

n_deps="$(printf '%s' "$found_line" | sed -nE 's/.*\(([0-9]+) dependenc.*/\1/p')"
if [[ -z "$n_deps" ]]; then
  block "Could not read a dependency count out of cargo-audit's output line: ${found_line}"
fi

if [[ "$n_deps" -lt "$MIN_DEPS" ]]; then
  block "${BINARY} reports only ${n_deps} embedded dependencies, below the floor of ${MIN_DEPS}. artifact-keeper resolves several hundred crates, so this is either the wrong binary or an embedding that covered almost nothing."
fi
say "embedded dependency graph present: ${n_deps} dependencies (floor ${MIN_DEPS})"

if [[ "$audit_rc" -ne 0 ]]; then
  # Deliberately not fatal -- see the header. Loud, though.
  say "cargo-audit exited ${audit_rc}: it found advisories against this dependency set."
  echo "::warning title=Advisories reported against the release binary::cargo audit bin exited ${audit_rc} for ${BINARY}. The embedded SBOM is present and this gate passes on that basis; vulnerability policy is owned by ci.yml's security-audit job and .cargo/audit.toml. Triage before promoting the release."
fi

# ---------------------------------------------------------------------------
# 2. the CycloneDX SBOM asset
# ---------------------------------------------------------------------------
if [[ -n "$SBOM" ]]; then
  printf '\n2. CycloneDX SBOM asset\n'
  [[ -f "$SBOM" ]] || block "${SBOM} does not exist. cargo-cyclonedx did not produce the SBOM asset for this target, and a release asset that is sometimes there is one nobody can build a process on."
  [[ -s "$SBOM" ]] || block "${SBOM} is empty."

  sbom_report=""
  sbom_rc=0
  sbom_report="$(MIN_SBOM_COMPONENTS="$MIN_SBOM_COMPONENTS" python3 - "$SBOM" 2>&1 <<'PY'
import json
import os
import sys

path = sys.argv[1]
floor = int(os.environ.get("MIN_SBOM_COMPONENTS", "50"))

try:
    with open(path, encoding="utf-8") as handle:
        doc = json.load(handle)
except Exception as exc:  # noqa: BLE001 - any parse failure is the same verdict
    print(f"not parseable as JSON: {exc}")
    raise SystemExit(1)

if not isinstance(doc, dict):
    print("top level is not a JSON object")
    raise SystemExit(1)

fmt = doc.get("bomFormat")
if fmt != "CycloneDX":
    print(f"bomFormat is {fmt!r}, expected 'CycloneDX'")
    raise SystemExit(1)

components = doc.get("components")
if not isinstance(components, list):
    print("no 'components' array")
    raise SystemExit(1)

if len(components) < floor:
    print(f"only {len(components)} components, below the floor of {floor}")
    raise SystemExit(1)

subject = ((doc.get("metadata") or {}).get("component") or {}).get("name")
if not subject:
    print("metadata.component.name is empty: the SBOM does not say what it describes")
    raise SystemExit(1)

print(f"CycloneDX {doc.get('specVersion')}, subject {subject}, {len(components)} components")
PY
)" || sbom_rc=$?

  if [[ "$sbom_rc" -ne 0 ]]; then
    printf '      %s\n' "$sbom_report"
    if printf '%s' "$sbom_report" | grep -qiE "command not found|No such file or directory: 'python3'"; then
      infra "python3 is unavailable, so the SBOM asset was not validated."
    fi
    block "${SBOM} is not a usable CycloneDX SBOM: ${sbom_report}"
  fi
  say "SBOM asset OK: ${sbom_report}"
fi

line="$(basename "$BINARY") carries ${n_deps} embedded dependencies$( [[ -n "$SBOM" ]] && echo " and ships a valid CycloneDX SBOM" )."
echo
printf '%sOK%s: %s\n' "$GRN" "$RST" "$line"
summarise "PASS" "$line"
exit 0
