#!/usr/bin/env bash
#
# The artifact-keeper-test gate pin (issue #6170, slice 1).
#
# WHY THIS EXISTS
#   The release gate is a reusable workflow in artifact-keeper-test. Called
#   `@main`, it changed 12 times in the 19 hours around the 2026-11-17
#   candidates, so two candidates on the same bytes ran different gates, and a
#   rerun was refused because "the gate gained jobs since the original". Every
#   caller now names ONE artifact-keeper-test commit, and a gate change reaches
#   a candidate only through a reviewed bump PR in this repository.
#   GitHub needs a literal ref in `uses:`, so nothing can enforce that at run
#   time; this script does, at PR time.
#
# MODES
#   check [<workflows dir>]   offline guard, every PR (Shell Tests):
#       * every job that calls an artifact-keeper-test reusable workflow
#         names a 40-hex commit, not a branch or tag;
#       * all of them name the SAME commit (the nightly measures the gate a
#         candidate would run today, so a bump moves every caller together);
#       * every `uses:` line naming one is a job the YAML parse found (no
#         caller hidden from the parse);
#       * a caller that passes the literal `iac_ref: main` or `web_tag: latest`
#         is reported as KNOWN, not failed. TODO(#6170 slice 2): pin the chart
#         and the web image by version and digest, then make these fail.
#   reachable [<base ref>]    online, PRs only (Shell Tests): when this branch
#       pins a commit the base did not, that commit must be on
#       artifact-keeper-test main: GET compare/<sha>...main must say `ahead`
#       (main has moved on from it) or `identical`. `behind` or `diverged` is
#       a branch-only or force-pushed-away commit; a 404/422 is no such commit.
#       A PR that changes no pin makes no API call.
#
# BUMPING THE PIN
#   Replace the sha in every caller (`grep -rn artifact-keeper-test/.github/
#   workflows/ .github/workflows`) with artifact-keeper-test main's head,
#   `gh api repos/artifact-keeper/artifact-keeper-test/commits/main --jq .sha`,
#   and date the trailing comment (Dependabot, if it ever opens the bump,
#   does not update that `# ... as of DATE` comment: fix it by hand). It is an
#   ordinary pipeline change, and Mergify does not auto-merge it. CODEOWNERS
#   lists the callers to mark ownership only: a code-owner review is enforced
#   once branch protection on main and release/* requires it (#6216).
#
#   The pin covers only the workflow YAML. The gate's jobs still check out
#   artifact-keeper-test's default branch and run its scripts, and tests_sha
#   resolves from the branch tip. So:
#     * bump promptly after any artifact-keeper-test change to
#       release-gate.yml: until then the old YAML runs against new scripts;
#     * before merging a bump, dispatch the release-gate rehearsal
#       (release-gate-rehearsal.yml, mode release-gate) on the bump branch.
#
# Env:
#   GATE_PIN_TEST_REPO  default artifact-keeper/artifact-keeper-test
#   GH_TOKEN            reachable mode only; any token reads a public repo
#
# Exit: 0 ok, 1 BLOCKED, 2 INFRA (could not measure; not a pass).
set -uo pipefail

TEST_REPO="${GATE_PIN_TEST_REPO:-artifact-keeper/artifact-keeper-test}"
MODE="${1:-check}"

blocked() { echo "::error title=Gate pin::$1" >&2; printf 'BLOCKED: %s\n' "$1" >&2; exit 1; }
infra()   { echo "::error title=Gate pin could not be checked::$1 Retry; do not interpret as a pass." >&2; printf 'INFRA: %s\n' "$1" >&2; exit 2; }

command -v python3 >/dev/null 2>&1 || infra "python3 is not on PATH."
python3 -c 'import yaml' 2>/dev/null || infra "python3 has no yaml module (python3-yaml)."

# callers <workflows dir | git:<ref>>
#   One TSV line per caller: file, job, called workflow, ref, iac_ref, web_tag
#   (the last two only when passed as a literal), then a final
#   `#uses-lines <n>` line: how many raw `uses:` lines name the test repo.
callers() {
  python3 - "$1" "$TEST_REPO" <<'PY'
import os, re, subprocess, sys, yaml
src, repo = sys.argv[1], sys.argv[2]
prefix = repo + "/.github/workflows/"
if src.startswith("git:"):
    ref = src[4:]
    names = subprocess.run(["git", "ls-tree", "--name-only", ref + ":.github/workflows"],
                           check=True, capture_output=True, text=True).stdout.split()
    files = {n: subprocess.run(["git", "show", f"{ref}:.github/workflows/{n}"], check=True,
                               capture_output=True, text=True).stdout for n in names}
else:
    files = {n: open(os.path.join(src, n), encoding="utf-8").read() for n in os.listdir(src)}
# GitHub resolves owner/repo case-insensitively, so the match does too.
raw = re.compile(r"^\s*-?\s*uses:\s*['\"]?" + re.escape(prefix), re.M | re.I)
lines = 0
for name in sorted(files):
    if not name.endswith((".yml", ".yaml")):
        continue
    text = files[name]
    lines += len(raw.findall(text))
    doc = yaml.safe_load(text) or {}
    for job_id, job in (doc.get("jobs") or {}).items():
        uses = job.get("uses") if isinstance(job, dict) else None
        if not isinstance(uses, str) or not uses.lower().startswith(prefix.lower()):
            continue
        wf, _, ref = uses[len(prefix):].partition("@")
        w = job.get("with") or {}
        lit = lambda k: str(w[k]) if k in w and "${{" not in str(w[k]) else ""
        print("\t".join([name, str(job_id), wf, ref, lit("iac_ref"), lit("web_tag")]))
print(f"#uses-lines {lines}")
PY
}

case "$MODE" in
  check)
    dir="${2:-.github/workflows}"
    [[ -d "$dir" ]] || infra "no workflows directory at ${dir}."
    out="$(callers "$dir")" || infra "could not parse the workflows under ${dir}."
    raw_lines="$(sed -n 's/^#uses-lines //p' <<<"$out")"
    rows="$(grep -v '^#' <<<"$out" || true)"
    n=0; bad=0; known=0; shas=""
    while IFS=$'\t' read -r file job wf ref iac web; do
      [[ -n "$file" ]] || continue
      n=$((n + 1))
      where="${file} job ${job} (${wf})"
      if [[ ! "$ref" =~ ^[0-9a-f]{40}$ ]]; then
        echo "FAIL  ${where}: calls ${TEST_REPO} at '@${ref}', not a 40-hex commit."; bad=$((bad + 1))
      else
        echo "ok    ${where}: @${ref}"
        shas+="${ref}"$'\n'
      fi
      # TODO(#6170 slice 2): pin the chart and the web image, then fail these.
      if [[ "$iac" == main ]]; then
        echo "KNOWN ${where}: passes iac_ref: main (allow-listed until #6170 slice 2)"; known=$((known + 1))
      fi
      if [[ "$web" == latest ]]; then
        echo "KNOWN ${where}: passes web_tag: latest (allow-listed until #6170 slice 2)"; known=$((known + 1))
      fi
    done <<<"$rows"
    [[ "$n" -gt 0 ]] || blocked "found no caller of a ${TEST_REPO} workflow under ${dir}; the guard would pass vacuously."
    if [[ "$raw_lines" != "$n" ]]; then
      echo "FAIL  ${raw_lines} 'uses:' line(s) name ${TEST_REPO} workflows but the YAML parse found ${n} caller job(s)."; bad=$((bad + 1))
    fi
    distinct="$(sort -u <<<"$shas" | grep -c . || true)"
    if [[ "$distinct" -gt 1 ]]; then
      echo "FAIL  the callers pin ${distinct} different ${TEST_REPO} commits; a bump moves all of them together:"
      sort -u <<<"$shas" | grep . | sed 's/^/        /'
      bad=$((bad + 1))
    fi
    [[ "$bad" -eq 0 ]] || blocked "${bad} gate pin problem(s) above."
    echo "gate pin: ${n} caller(s), one ${TEST_REPO} commit; ${known} known slice-2 finding(s)."
    ;;

  reachable)
    command -v gh >/dev/null 2>&1 || infra "gh is not on PATH."
    command -v git >/dev/null 2>&1 || infra "git is not on PATH."
    base="${2:-${GITHUB_BASE_REF:-main}}"
    if ! git rev-parse --verify -q "${base}^{commit}" >/dev/null; then
      git rev-parse --verify -q "origin/${base}^{commit}" >/dev/null || infra "base ref '${base}' is not available (fetch it first)."
      base="origin/${base}"
    fi
    pins_of() { grep -v '^#' <<<"$1" | cut -f4 | sort -u | grep . || true; }
    head_out="$(callers .github/workflows)" || infra "could not parse this branch's workflows."
    base_out="$(callers "git:${base}")" || infra "could not read the workflows at ${base}."
    head_pins="$(pins_of "$head_out")"
    base_pins="$(pins_of "$base_out")"
    new="$(comm -23 <(printf '%s\n' "$head_pins" | grep .) <(printf '%s\n' "$base_pins" | grep .) || true)"
    if [[ -z "$new" ]]; then
      echo "gate pin: this branch pins no ${TEST_REPO} commit that ${base} does not; nothing to check."
      exit 0
    fi
    err="$(mktemp)"; trap 'rm -f "$err"' EXIT
    bad=0
    while read -r sha; do
      [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "FAIL  '@${sha}' is not a 40-hex commit (see check mode)."; bad=$((bad + 1)); continue; }
      if status="$(gh api "repos/${TEST_REPO}/compare/${sha}...main" --jq .status 2>"$err")"; then
        case "$status" in
          ahead|identical) echo "ok    ${sha}: on ${TEST_REPO} main (${status})." ;;
          behind|diverged) echo "FAIL  ${sha}: not on ${TEST_REPO} main (compare says ${status}): a branch-only or force-pushed-away commit."; bad=$((bad + 1)) ;;
          *) infra "compare ${sha}...main answered status '${status}'." ;;
        esac
      elif grep -qE 'HTTP (404|422)' "$err"; then
        echo "FAIL  ${sha}: ${TEST_REPO} has no such commit ($(head -c 200 "$err"))."; bad=$((bad + 1))
      else
        infra "GET compare/${sha}...main failed: $(head -c 300 "$err")"
      fi
    done <<<"$new"
    [[ "$bad" -eq 0 ]] || blocked "${bad} pinned commit(s) are not on ${TEST_REPO} main. Pin main's head: gh api repos/${TEST_REPO}/commits/main --jq .sha"
    echo "gate pin: every newly pinned commit is on ${TEST_REPO} main."
    ;;

  *) infra "unknown mode '${MODE}' (check | reachable)." ;;
esac
