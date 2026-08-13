#!/usr/bin/env bash
#
# Pre-tag release readiness check (issue #3042).
#
# Run this BEFORE cutting a release/RC tag (see RELEASING.md). It asserts that
# `main` is actually releasable, so a stale main does not cost a full re-cut
# cycle. The motivating incident (#3039): v1.7.0-rc.1 stalled ~90 minutes at
# docker-publish's Security Scan because `main` was missing two trivy-CLI CVE
# suppressions that lived only on `release/1.6.x` (#2997/#3040). Security Scan
# HARD-gates the multi-arch manifest, which gates resolve-candidate-digest,
# which gates the ENTIRE release-gate chain -- so a missing suppression turns
# into a silent 90-minute stall with a draft release at the end. The signal was
# already visible (`Docker Publish [push/main]` had been red for 5 commits);
# nothing checked it before tagging. This gate is that check.
#
# What it verifies:
#   1. TRIVYIGNORE DRIFT (hard): main's CVE/GHSA suppression set must be a
#      SUPERSET of every active `release/*` branch's. A CVE suppressed on a
#      hotfix branch but not forward-ported to main means main's images fail
#      Security Scan -> no release can be cut from main. This is the exact
#      #3039 gap. Enumeration mirrors check-migration-ledger.sh.
#   2. VERSION-SET CONSISTENCY (hard): the workspace version in Cargo.toml,
#      the OpenAPI info version in backend/src/api/openapi.rs, and the
#      artifact-keeper-backend entry in Cargo.lock must all agree. A partial
#      bump ships a stale version string (see RELEASING.md step 2).
#   3. MAIN DOCKER-PUBLISH HEALTH (hard, when it can be measured): whether the
#      most recent `Docker Publish` run on main published its multi-arch
#      manifest (i.e. Security Scan passed). A red/skipped manifest here does
#      not merely "predict" the same stall on the tag -- it is the same job,
#      on the same images, with the same gate. If it is red, the cut stalls.
#
#      This check used to `warn` and let the script exit 0, so the tool printed
#      "a tag cut will likely stall" and "READY: ... Safe to cut the tag." in
#      the same breath (#3308). That is worse than having no preflight, because
#      it launders a measured red into an explicit go-ahead -- exactly the
#      "gate failure is cosmetic, promote anyway" reasoning the release freeze
#      was written to remove after the v1.5.8 integrity failure.
#
#      Note the asymmetry this fixes. Check 1 (trivyignore drift) is a PROXY
#      for "will Security Scan pass" and catches exactly one cause: a
#      suppression stranded on release/*. Check 3 is the DIRECT measurement.
#      Having the proxy hard and the measurement soft was backwards, and the
#      gap was reachable: on 2026-08-13 a newly-published advisory (#3307)
#      failed Security Scan on main while every hard check passed clean,
#      because the CVE affected main and the release branches equally so there
#      was no drift to find.
#
#      Three outcomes, deliberately kept distinct -- "I did not look",
#      "I could not look" and "I looked and it is red" are different claims:
#        * not measured (skipped, or `gh` absent)      -> note, not blocking
#        * could not measure (the gh query failed)     -> INFRA, exit 2
#        * measured red                                -> blocking, exit 1
#
# Exit-code contract (mirrors scripts/ci/check-migration-ledger.sh):
#   0  ready       -- no blocking problem found.
#   1  NOT READY   -- a real, blocking problem (drift, version mismatch, or a
#                     measured-red Docker Publish on main).
#                     Fix it on main before tagging; NEVER retry it away.
#   2  INFRA       -- tooling/network failure (git ls-remote / gh / file reads
#                     failed); retryable, NOT a readiness verdict.
#
# Env overrides:
#   PREFLIGHT_REPO   owner/name for the `gh api` calls (default: derived from
#                    the origin remote, else artifact-keeper/artifact-keeper).
#   PREFLIGHT_SKIP_DOCKER_HEALTH=1  do not run check 3 at all.
#   PREFLIGHT_ALLOW_RED_PUBLISH=1   run check 3, report a red result, but do
#                    not block on it. Deliberately SEPARATE from
#                    PREFLIGHT_SKIP_DOCKER_HEALTH: "do not look" and "I looked,
#                    it is red, proceeding anyway" are different decisions and
#                    should read differently in the transcript. Using this is a
#                    judgement call a human makes and owns; it is never a
#                    default, and it is not a way to make a red main green.
#
set -euo pipefail

# --- locate repo root -------------------------------------------------------
if ! ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"; then
  echo "INFRA: not inside a git work tree" >&2
  exit 2
fi
cd "$ROOT"

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; RST=$'\033[0m'
[[ -t 1 ]] || { RED=""; GRN=""; YEL=""; RST=""; }
problems=0

note() { printf '  %s\n' "$*"; }
ok()   { printf '%s[ok]%s   %s\n' "$GRN" "$RST" "$*"; }
bad()  { printf '%s[FAIL]%s %s\n' "$RED" "$RST" "$*"; problems=$((problems + 1)); }
warn() { printf '%s[warn]%s %s\n' "$YEL" "$RST" "$*"; }

# repo slug for gh
REPO="${PREFLIGHT_REPO:-}"
if [[ -z "$REPO" ]]; then
  origin="$(git config --get remote.origin.url 2>/dev/null || true)"
  REPO="$(printf '%s' "$origin" | sed -E 's#(git@[^:]+:|https?://[^/]+/)##; s#\.git$##')"
  [[ -z "$REPO" ]] && REPO="artifact-keeper/artifact-keeper"
fi

# extract sorted, unique CVE-/GHSA- tokens from stdin
suppression_tokens() {
  grep -oE '^(CVE-[0-9]{4}-[0-9]+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})' | sort -u
}

echo "== release preflight =="
echo "repo: $REPO   ref: $(git rev-parse --short HEAD 2>/dev/null || echo '?')"
echo

# --- check 1: .trivyignore forward-port drift -------------------------------
echo "1) .trivyignore forward-port drift (main must be a superset of release/*)"
if [[ ! -f .trivyignore ]]; then
  warn "no .trivyignore at repo root -- skipping drift check"
else
  main_tokens="$(suppression_tokens < .trivyignore)"
  # enumerate active release branches (works on a shallow checkout)
  if ! remote_refs="$(git ls-remote --heads origin 'release/*' 2>/dev/null)"; then
    echo "INFRA: git ls-remote for release/* failed" >&2
    exit 2
  fi
  rel_branches="$(printf '%s\n' "$remote_refs" | sed -E 's#^[0-9a-f]+\trefs/heads/##' | sort -u)"
  if [[ -z "$rel_branches" ]]; then
    note "no active release/* branches -- nothing to compare"
    ok "trivyignore drift: n/a"
  else
    drift=0
    while IFS= read -r br; do
      [[ -z "$br" ]] && continue
      # read that branch's .trivyignore without a full fetch
      if ! rel_content="$(gh api "repos/$REPO/contents/.trivyignore?ref=$br" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null)"; then
        warn "could not read .trivyignore from $br (no file or gh error) -- skipping"
        continue
      fi
      rel_tokens="$(printf '%s\n' "$rel_content" | suppression_tokens)"
      # tokens present on the release branch but MISSING from main
      missing="$(comm -23 <(printf '%s\n' "$rel_tokens") <(printf '%s\n' "$main_tokens") | grep -v '^$' || true)"
      if [[ -n "$missing" ]]; then
        bad "main is MISSING suppressions that $br has:"
        while IFS= read -r m; do [[ -n "$m" ]] && note "  - $m"; done <<< "$missing"
        note "  -> forward-port these to main's .trivyignore before tagging (see #3039)"
        drift=$((drift + 1))
      else
        note "$br: main covers all of its suppressions"
      fi
    done <<< "$rel_branches"
    [[ "$drift" -eq 0 ]] && ok "trivyignore drift: main is a superset of every release/*"
  fi
fi
echo

# --- check 2: version-set consistency ---------------------------------------
echo "2) version-set consistency (Cargo.toml == openapi.rs == Cargo.lock)"
cargo_ver="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
openapi_ver="$(sed -n 's/.*version = "\([0-9][^"]*\)".*/\1/p' backend/src/api/openapi.rs | head -1)"
lock_ver="$(awk '/^name = "artifact-keeper-backend"$/{getline; if ($0 ~ /^version = /){gsub(/version = "|"/,""); print; exit}}' Cargo.lock)"
note "Cargo.toml   = ${cargo_ver:-<none>}"
note "openapi.rs   = ${openapi_ver:-<none>}"
note "Cargo.lock   = ${lock_ver:-<none>}"
if [[ -z "$cargo_ver" || -z "$openapi_ver" || -z "$lock_ver" ]]; then
  bad "could not extract one or more version strings"
elif [[ "$cargo_ver" == "$openapi_ver" && "$cargo_ver" == "$lock_ver" ]]; then
  ok "version set is consistent at $cargo_ver"
else
  bad "version strings disagree -- a partial bump ships a stale version (RELEASING.md step 2)"
fi
echo

# --- check 3: main docker-publish health (hard when measurable) -------------
echo "3) latest main Docker Publish health"
if [[ "${PREFLIGHT_SKIP_DOCKER_HEALTH:-0}" == "1" ]]; then
  note "NOT MEASURED (PREFLIGHT_SKIP_DOCKER_HEALTH=1) -- this check did not run,"
  note "which is not the same as it passing."
elif ! command -v gh >/dev/null 2>&1; then
  note "NOT MEASURED (gh not on PATH) -- this check did not run, which is not"
  note "the same as it passing."
else
  run_id="$(gh run list --repo "$REPO" --workflow "Docker Publish" --branch main --limit 1 \
              --json databaseId --jq '.[0].databaseId' 2>/dev/null || true)"
  if [[ -z "$run_id" ]]; then
    # gh is present but the query failed (auth, network, API). We could not
    # measure, so we must not render a readiness verdict either way.
    echo "INFRA: could not query the latest main Docker Publish run" >&2
    exit 2
  fi
  sec="$(gh run view "$run_id" --repo "$REPO" --json jobs \
          --jq '[.jobs[]|select(.name=="Security Scan")|(.conclusion//"?")]|first//"?"' 2>/dev/null || echo '?')"
  man="$(gh run view "$run_id" --repo "$REPO" --json jobs \
          --jq '[.jobs[]|select(.name|test("Backend Multi-Arch Manifest"))|(.conclusion//"skipped")]|first//"?"' 2>/dev/null || echo '?')"
  note "run $run_id: Security Scan=$sec, Backend Multi-Arch Manifest=$man"
  if [[ "$sec" == "?" || "$man" == "?" ]]; then
    echo "INFRA: could not read job conclusions from run $run_id" >&2
    exit 2
  elif [[ "$sec" == "success" && "$man" == "success" ]]; then
    ok "main images are publishing cleanly"
  elif [[ "${PREFLIGHT_ALLOW_RED_PUBLISH:-0}" == "1" ]]; then
    warn "main's last Docker Publish did NOT cleanly publish the manifest, but"
    warn "PREFLIGHT_ALLOW_RED_PUBLISH=1 was set, so this is not blocking."
    note "  -> whoever set that owns the stall if the cut hits the same gate."
    note "  -> run: $(printf '%s/actions/runs/%s' "https://github.com/$REPO" "$run_id")"
  else
    bad "main's last Docker Publish did NOT cleanly publish the manifest -- a tag cut WILL stall on the same gate."
    note "  -> Security Scan hard-gates every multi-arch manifest, which gates"
    note "     resolve-candidate-digest, which gates the whole release chain."
    note "  -> run: $(printf '%s/actions/runs/%s' "https://github.com/$REPO" "$run_id")"
    note "  -> fix it on main and let Docker Publish go green before tagging (#3039, #3307)."
    note "  -> PREFLIGHT_ALLOW_RED_PUBLISH=1 overrides this deliberately; do not use it to retry a red away."
  fi
fi
echo

# --- verdict ----------------------------------------------------------------
if [[ "$problems" -gt 0 ]]; then
  echo "${RED}NOT READY${RST}: $problems blocking problem(s). Fix on main before tagging."
  exit 1
fi
echo "${GRN}READY${RST}: no blocking problems. Safe to cut the tag."
exit 0
