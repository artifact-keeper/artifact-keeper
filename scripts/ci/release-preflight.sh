#!/usr/bin/env bash
#
# Pre-tag release readiness check (issue #3042).
#
# Run this BEFORE cutting a release/RC tag (see RELEASING.md). It asserts that
# THE REF BEING CUT is actually releasable, so a stale tree does not cost a
# full re-cut cycle. The motivating incident (#3039): v1.7.0-rc.1 stalled ~90 minutes at
# docker-publish's Security Scan because `main` was missing two trivy-CLI CVE
# suppressions that lived only on `release/1.6.x` (#2997/#3040). Security Scan
# HARD-gates the multi-arch manifest, which gates resolve-candidate-digest,
# which gates the ENTIRE release-gate chain -- so a missing suppression turns
# into a silent 90-minute stall with a draft release at the end. The signal was
# already visible (`Docker Publish [push/main]` had been red for 5 commits);
# nothing checked it before tagging. This gate is that check.
#
# What it verifies:
#   1. TRIVYIGNORE DRIFT (hard): every suppression on every active `release/*`
#      branch must be ACCOUNTED FOR on main -- either as a live suppression
#      token, or as an explicit `# RETIRED: <token>` tombstone line. A CVE
#      suppressed on a hotfix branch and neither carried nor tombstoned on
#      main means main's images fail Security Scan -> no release can be cut
#      from main. This is the exact #3039 gap. Enumeration mirrors
#      check-migration-ledger.sh.
#
#      This one check is MAIN-CENTRIC and is skipped (loudly) when the audited
#      ref is a `release/*` branch. Its subject is "can a cut from main clear
#      Security Scan given what the maintenance branches suppress"; a
#      maintenance branch's own images are scanned against its OWN
#      .trivyignore, so another branch's suppressions say nothing about it and
#      the branch comparing against itself is vacuous. Running it anyway would
#      manufacture drift findings that no cut from that branch can act on.
#
#      The tombstone form exists because a plain superset rule makes the set
#      monotonic (#3309): a suppression provably dead for main's images could
#      never be DELETED while any release branch still listed it, so the file
#      drifted from "the residual set" toward "everything ever worked
#      around". A `# RETIRED: <token>` line is the machine-read record that
#      main removed the token DELIBERATELY (the finding is absent from main's
#      images), as opposed to never having received it (the #3039 forward-port
#      miss, which still hard-fails). Retiring is a reviewable diff, and a
#      token listed BOTH live and retired is a contradiction and fails.
#   2. VERSION-SET CONSISTENCY (hard): the workspace version in Cargo.toml,
#      the OpenAPI info version in backend/src/api/openapi.rs, and the
#      artifact-keeper-backend entry in Cargo.lock must all agree. A partial
#      bump ships a stale version string (see RELEASING.md step 2).
#   3. DOCKER-PUBLISH HEALTH FOR THIS COMMIT (hard, when it can be measured):
#      whether the `Docker Publish` run for the EXACT commit being tagged
#      (HEAD) published its multi-arch manifest (i.e. Security Scan passed).
#      A red/skipped manifest here does not merely "predict" the same stall
#      on the tag -- it is the same job, on the same images, with the same
#      gate. If it is red, the cut stalls.
#
#      Selection is by `head_sha`, NOT by recency (#3338). "Latest run on
#      main" is a proxy that diverges from the question that matters whenever
#      main has moved since the last publish, a publish is still in flight,
#      or the list API answers stalely -- the v1.7.2 cut lost time to a
#      blocking false red when the "latest run" query returned a ten-day-old
#      run while the actual latest (and green) run existed. A tag is cut on a
#      commit; the commit's own run is the measurement.
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
#      Outcomes, deliberately kept distinct -- "I did not look", "I could not
#      look", "there is nothing to look at yet" and "I looked and it is red"
#      are different claims:
#        * not measured (skipped, or `gh` absent)      -> note, not blocking
#        * could not measure (the gh query failed)     -> INFRA, exit 2
#        * no run for this commit (not built yet)      -> blocking, exit 1
#          NOT a pass and NOT "ran and failed": the images for this commit do
#          not exist, so a tag cut has nothing to resolve a digest from.
#        * run still queued/in progress                -> blocking, exit 1
#          (wait for it to finish and re-run; treating in-flight as absent
#          or as green would launder an unfinished measurement)
#        * measured red                                -> blocking, exit 1
#      PREFLIGHT_ALLOW_RED_PUBLISH only overrides the MEASURED-RED outcome:
#      "I looked, it is red, proceeding anyway" is a coherent human call.
#      There is no override for not-built/in-flight, because there is no
#      result to accept the risk of -- the digest resolution would simply
#      fail.
#
#   4. VERSION-PINNED IMAGE COLLISION (hard, when it can be measured): for each
#      component whose image tag comes from a checked-in VERSION file, whether
#      that exact tag is ALREADY published from different sources. Exact
#      version tags are never republished (#2457 / the v1.5.8 integrity
#      failure), so a changed component with an unbumped VERSION cannot
#      publish -- and the failure skips every remaining manifest, so
#      resolve-candidate-digest has nothing to pin and the whole release chain
#      stops.
#
#      The motivating incident: v1.7.2 was tagged on a commit where #3315
#      re-pinned the trivy base image inside docker/Dockerfile.scanner-adapter
#      but left docker/scanner-adapter/VERSION at 1.2.2. The tag's Docker
#      Publish failed with "1.2.2 already exists ... but scanner-adapter
#      sources changed", the chain stopped, and because the tag was immutable
#      it had to be deleted by hand.
#
#      Why nothing caught it earlier is the whole point of putting the check
#      HERE. The publish job derives `stable_requested` from the ref, and only
#      a clean `refs/tags/v*` (no hyphen) sets it. On main the job publishes
#      dev/sha tags and returns before the collision check; on a `-rc.N` tag it
#      does the same. So Docker Publish passed on main for the SAME commit, and
#      an RC would have passed too. The defect was reachable by exactly one
#      kind of run -- the real tag -- which is the most expensive place to
#      discover it and the one place it cannot be amended.
#
#      Same three-way outcome as check 3, for the same reason: a registry we
#      cannot read is not a registry that said yes.
#        * tag absent                                  -> ok, it will be created
#        * published, sources identical                -> ok (a rebuild may
#          still move the floating tags; the exact tag stays put)
#        * published, sources differ                   -> blocking, exit 1
#        * published, no provenance annotation         -> blocking, exit 1
#          (measured: the publish job hard-fails on this too)
#        * registry unreadable / commit unfetchable    -> INFRA, exit 2
#
#   5. CHANGELOG <-> COMMIT RECONCILIATION (hard, when it can be measured):
#      whether the pending `## [Unreleased]` section and the commit range
#      `<previous stable tag>..HEAD` describe the same set of work, in BOTH
#      directions. Checks 1-4 ask whether the release will build; this one
#      asks whether it will be described correctly -- which is the failure
#      mode that actually shipped, four times in eight releases (#3537). Full
#      rationale at the check itself.
#
# Exit-code contract (mirrors scripts/ci/check-migration-ledger.sh):
#   0  ready       -- no blocking problem found.
#   1  NOT READY   -- a real, blocking problem (drift, version mismatch, or a
#                     measured-red Docker Publish for the audited commit).
#                     Fix it on the ref being cut before tagging; NEVER retry
#                     it away.
#   2  INFRA       -- tooling/network failure (git ls-remote / gh / file reads
#                     failed); retryable, NOT a readiness verdict.
#
# Exit 1 OUTRANKS exit 2 (#3538). If a check has already counted a blocking
# problem and a LATER check cannot be measured, the run exits 1, not 2: the
# blocking problem is definite, retrying will not remove it, and "retryable"
# is the wrong instruction to hand an operator who is already not ready. This
# does not weaken exit 2 in the direction that matters -- an indeterminate
# result still never reads as a pass, and nothing that used to block stops
# blocking. It only converts some exit-2s into exit-1s.
#
# Env overrides:
#   PREFLIGHT_REF    the ref this run is a statement about. Names the verdict
#                    line and decides whether check 1 applies. Defaults to the
#                    checked-out branch name; a detached HEAD reports as
#                    `HEAD`, which is not a `release/*` ref, so check 1 keeps
#                    its historical behaviour when nothing says otherwise.
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
#   PREFLIGHT_SKIP_VERSION_PIN=1    do not run check 4 at all.
#   PREFLIGHT_SKIP_CHANGELOG_RECON=1  do not run check 5 at all.
#   PREFLIGHT_PREV_TAG              override the previous-stable-tag end of
#                    check 5's commit range (default: `git describe`). Exists
#                    for the self-test and for replaying a historical cut.
#   PREFLIGHT_TAG_STATE_CMD         path to the tag-presence probe
#                    (default .github/scripts/registry-tag-state.sh).
#   PREFLIGHT_TAG_REVISION_CMD      path to the tag-revision probe
#                    (default .github/scripts/registry-tag-revision.sh).
#                    Both exist so the self-test can replay canned registry
#                    answers without a network or a docker daemon.
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

# The single exit point for "this check could not be measured" (#3538).
#
# An indeterminate result must never read as a pass -- that part is #3308's
# lesson and it is unchanged. It must not mask a verdict that is ALREADY
# definite either, and that part was reachable: every INFRA site below exits
# immediately, discarding whatever `problems` the earlier checks had already
# counted. A run where check 1 found real forward-port drift AND ghcr was
# briefly unreadable reported exit 2 -- "retryable" -- when the true answer
# was "you are not ready, and retrying will not help". Telling an operator to
# retry a definite red is how a red gets laundered into a rerun.
#
# So the exit code is the STRONGEST claim the run has actually earned:
#   * nothing blocking counted yet -> exit 2, INFRA, exactly as before.
#   * something blocking counted   -> exit 1, NOT READY.
# Checks only ever ADD problems (`bad` increments, nothing decrements), so a
# NOT READY reached here cannot be withdrawn by a check that did not run. The
# audit IS incomplete, though, so the verdict line says so instead of implying
# a clean sweep.
infra_exit() {
  if [[ "$problems" -gt 0 ]]; then
    echo "${RED}NOT READY${RST} to cut from ${AUDIT_REF:-?}@${AUDIT_SHA:-?}: $problems blocking problem(s) found before a later check could not be measured (see the INFRA line above)."
    echo "  The blocking problems are real and are not retryable. The remaining"
    echo "  checks did not run, so this audit is incomplete -- fix these, then"
    echo "  re-run the preflight for a full verdict."
    exit 1
  fi
  exit 2
}

# repo slug for gh
REPO="${PREFLIGHT_REPO:-}"
if [[ -z "$REPO" ]]; then
  origin="$(git config --get remote.origin.url 2>/dev/null || true)"
  REPO="$(printf '%s' "$origin" | sed -E 's#(git@[^:]+:|https?://[^/]+/)##; s#\.git$##')"
  [[ -z "$REPO" ]] && REPO="artifact-keeper/artifact-keeper"
fi

# extract sorted, unique CVE-/GHSA- tokens from stdin. `|| true` because a
# file with zero tokens is an answer, not an error (grep exits 1 on no match,
# which would abort the script under `set -euo pipefail`).
suppression_tokens() {
  { grep -oE '^(CVE-[0-9]{4}-[0-9]+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})' || true; } | sort -u
}

# extract sorted, unique tombstoned tokens (`# RETIRED: <token>` lines, #3309)
# from stdin. Anything after the token (a date, an issue ref) is free text.
retired_tokens() {
  { grep -oE '^# RETIRED: (CVE-[0-9]{4}-[0-9]+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})' || true; } \
    | sed 's/^# RETIRED: //' | sort -u
}

# --- which ref is this run a statement about? -------------------------------
#
# The workflow used to hardcode `ref: main` in its checkout, so a preflight
# dispatched from release/1.7.x audited main and said READY about it. Naming
# the ref in the verdict is what makes that mistake unrepeatable: a transcript
# that says which ref it evaluated cannot be read as one about another.
#
# refs/heads/ is stripped so `refs/heads/release/1.7.x` and `release/1.7.x`
# print (and match) identically no matter which of the two the caller passes.
AUDIT_REF="${PREFLIGHT_REF:-}"
if [[ -z "$AUDIT_REF" ]]; then
  AUDIT_REF="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
fi
AUDIT_REF="${AUDIT_REF#refs/heads/}"
AUDIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo '?')"

# True for a maintenance branch, false for main / a tag / a detached HEAD.
is_release_branch_ref() { [[ "$AUDIT_REF" == release/* ]]; }

echo "== release preflight =="
echo "repo: $REPO   ref: ${AUDIT_REF}@${AUDIT_SHA}"
echo

# --- check 1: .trivyignore forward-port drift -------------------------------
echo "1) .trivyignore forward-port drift (main must account for release/* suppressions)"
if is_release_branch_ref; then
  note "NOT APPLICABLE: this check asks whether MAIN accounts for the"
  note "suppressions on every release/* branch, and the audited ref is"
  note "${AUDIT_REF}. A maintenance branch's images are scanned against its own"
  note ".trivyignore, so another branch's suppressions are not a claim about"
  note "this cut -- and comparing the branch against itself is vacuous."
  note "Run this check against main (its forward-port drift is main's problem)."
elif [[ ! -f .trivyignore ]]; then
  warn "no .trivyignore at repo root -- skipping drift check"
else
  main_tokens="$(suppression_tokens < .trivyignore)"
  main_retired="$(retired_tokens < .trivyignore)"
  # A token both live and tombstoned is a contradiction: the file claims
  # "this is an active exception" and "this was deliberately removed" at
  # once. Fail rather than pick a winner (#3309).
  contradiction="$(comm -12 <(printf '%s\n' "$main_tokens") <(printf '%s\n' "$main_retired") | grep -v '^$' || true)"
  if [[ -n "$contradiction" ]]; then
    bad ".trivyignore lists token(s) BOTH as live suppressions and as '# RETIRED:' tombstones:"
    while IFS= read -r c; do [[ -n "$c" ]] && note "  - $c"; done <<< "$contradiction"
    note "  -> delete one of the two lines per token; a token is live or retired, never both."
  fi
  # What main accounts for: live suppressions plus deliberate retirements.
  covered="$(printf '%s\n%s\n' "$main_tokens" "$main_retired" | grep -v '^$' | sort -u)"
  # enumerate active release branches (works on a shallow checkout)
  if ! remote_refs="$(git ls-remote --heads origin 'release/*' 2>/dev/null)"; then
    echo "INFRA: git ls-remote for release/* failed" >&2
    infra_exit
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
      # tokens present on the release branch but neither live nor tombstoned
      # on main: the #3039 forward-port miss, still a hard failure.
      missing="$(comm -23 <(printf '%s\n' "$rel_tokens") <(printf '%s\n' "$covered") | grep -v '^$' || true)"
      # tokens the release branch still suppresses that main has RETIRED:
      # accounted for, but say so -- a retirement is a claim about main's
      # images, and it should be visible in the transcript, not silent.
      retired_hits="$(comm -12 <(printf '%s\n' "$rel_tokens") <(printf '%s\n' "$main_retired") | grep -v '^$' || true)"
      if [[ -n "$missing" ]]; then
        bad "main is MISSING suppressions that $br has:"
        while IFS= read -r m; do [[ -n "$m" ]] && note "  - $m"; done <<< "$missing"
        note "  -> forward-port these to main's .trivyignore before tagging (see #3039),"
        note "     or -- ONLY if the finding is measured absent from main's images --"
        note "     record the removal as a '# RETIRED: <token>' tombstone (see #3309)."
        drift=$((drift + 1))
      elif [[ -n "$retired_hits" ]]; then
        note "$br: main covers all of its suppressions ($(printf '%s' "$retired_hits" | grep -c . ) via RETIRED tombstones)"
      else
        note "$br: main covers all of its suppressions"
      fi
    done <<< "$rel_branches"
    [[ "$drift" -eq 0 ]] && ok "trivyignore drift: main accounts for every release/* suppression"
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

# --- check 3: docker-publish health for HEAD (hard when measurable) ---------
echo "3) Docker Publish health for the commit being tagged (HEAD)"
if [[ "${PREFLIGHT_SKIP_DOCKER_HEALTH:-0}" == "1" ]]; then
  note "NOT MEASURED (PREFLIGHT_SKIP_DOCKER_HEALTH=1) -- this check did not run,"
  note "which is not the same as it passing."
elif ! command -v gh >/dev/null 2>&1; then
  note "NOT MEASURED (gh not on PATH) -- this check did not run, which is not"
  note "the same as it passing."
else
  head_sha="$(git rev-parse HEAD 2>/dev/null || true)"
  if [[ -z "$head_sha" ]]; then
    echo "INFRA: could not resolve HEAD" >&2
    infra_exit
  fi
  # Select the run for THIS commit, never "the latest run" (#3338): recency
  # is a proxy that diverges when main has moved, a publish is in flight, or
  # the list API answers stalely -- and the divergence produced a blocking
  # false red on the v1.7.2 cut. head_sha resolves to at most one run and
  # needs no new machinery.
  if ! run_info="$(gh api "repos/$REPO/actions/workflows/docker-publish.yml/runs?head_sha=$head_sha&per_page=1" \
                    --jq '.workflow_runs[0] // empty | "\(.id) \(.status)"' 2>/dev/null)"; then
    # gh is present but the query failed (auth, network, API). We could not
    # measure, so we must not render a readiness verdict either way.
    echo "INFRA: could not query Docker Publish runs for $head_sha" >&2
    infra_exit
  fi
  if [[ -z "$run_info" ]]; then
    # A fourth outcome, distinct from "ran and failed" (#3338): the query
    # succeeded and there is NO run for this commit. The images a tag cut
    # would pin do not exist, so resolve-candidate-digest has nothing to
    # resolve. Not a pass; also not an infra retry.
    bad "no Docker Publish run exists for HEAD ($(git rev-parse --short HEAD)) -- the images for this commit have NOT been built."
    note "  -> a tag cut from this commit has no manifest to resolve a digest from."
    note "  -> wait for (or trigger) Docker Publish on this exact commit, then re-run preflight."
  else
    read -r run_id run_status <<< "$run_info"
    if [[ -z "$run_id" || -z "$run_status" ]]; then
      echo "INFRA: unparseable Docker Publish run answer for $head_sha ('$run_info')" >&2
      infra_exit
    fi
    if [[ "$run_status" != "completed" ]]; then
      # In flight is not absent and not green: block and say to wait rather
      # than silently mis-classifying an unfinished measurement (#3338).
      bad "Docker Publish for HEAD is still '$run_status' (run $run_id) -- its verdict does not exist yet."
      note "  -> run: $(printf '%s/actions/runs/%s' "https://github.com/$REPO" "$run_id")"
      note "  -> wait for it to complete, then re-run preflight. Do not tag ahead of the gate."
    else
      sec="$(gh run view "$run_id" --repo "$REPO" --json jobs \
              --jq '[.jobs[]|select(.name=="Security Scan")|(.conclusion//"?")]|first//"?"' 2>/dev/null || echo '?')"
      man="$(gh run view "$run_id" --repo "$REPO" --json jobs \
              --jq '[.jobs[]|select(.name|test("Backend Multi-Arch Manifest"))|(.conclusion//"skipped")]|first//"?"' 2>/dev/null || echo '?')"
      note "run $run_id: Security Scan=$sec, Backend Multi-Arch Manifest=$man"
      if [[ "$sec" == "?" || "$man" == "?" ]]; then
        echo "INFRA: could not read job conclusions from run $run_id" >&2
        infra_exit
      elif [[ "$sec" == "success" && "$man" == "success" ]]; then
        ok "this commit's images published cleanly"
      elif [[ "${PREFLIGHT_ALLOW_RED_PUBLISH:-0}" == "1" ]]; then
        warn "Docker Publish for HEAD did NOT cleanly publish the manifest, but"
        warn "PREFLIGHT_ALLOW_RED_PUBLISH=1 was set, so this is not blocking."
        note "  -> whoever set that owns the stall if the cut hits the same gate."
        note "  -> run: $(printf '%s/actions/runs/%s' "https://github.com/$REPO" "$run_id")"
      else
        bad "Docker Publish for HEAD did NOT cleanly publish the manifest -- a tag cut WILL stall on the same gate."
        note "  -> Security Scan hard-gates every multi-arch manifest, which gates"
        note "     resolve-candidate-digest, which gates the whole release chain."
        note "  -> run: $(printf '%s/actions/runs/%s' "https://github.com/$REPO" "$run_id")"
        note "  -> fix it on main and let Docker Publish go green before tagging (#3039, #3307)."
        note "  -> PREFLIGHT_ALLOW_RED_PUBLISH=1 overrides this deliberately; do not use it to retry a red away."
      fi
    fi
  fi
fi
echo

# --- check 4: version-pinned image collision --------------------------------
#
# One row per component whose published image tag is named by a checked-in
# VERSION file, as `<version file>|<image name suffix>|<source paths>`. The
# source paths MUST mirror the paths the publish job diffs, or this check and
# the gate it predicts disagree.
#
# scanner-adapter is currently the ONLY such component: `docker/scanner-adapter/
# VERSION` is the only VERSION file in the repo. backend, web and openscap are
# tagged with the AK release semver taken from the git tag itself, so their
# exact tags cannot collide the same way -- a re-cut of an existing version is
# caught earlier, by assert-release-absent.sh / assert-stable-tag-free.sh. This
# is a list rather than a hardcoded component so that adding the second one is
# a one-line change instead of a rewrite.
echo "4) version-pinned image tags (VERSION file vs published image)"
VERSION_PINNED_COMPONENTS=(
  "docker/scanner-adapter/VERSION|-scanner-adapter|docker/scanner-adapter docker/Dockerfile.scanner-adapter"
)
TAG_STATE_CMD="${PREFLIGHT_TAG_STATE_CMD:-.github/scripts/registry-tag-state.sh}"
TAG_REVISION_CMD="${PREFLIGHT_TAG_REVISION_CMD:-.github/scripts/registry-tag-revision.sh}"

if [[ "${PREFLIGHT_SKIP_VERSION_PIN:-0}" == "1" ]]; then
  note "NOT MEASURED (PREFLIGHT_SKIP_VERSION_PIN=1) -- this check did not run,"
  note "which is not the same as it passing."
elif [[ ! -x "$TAG_STATE_CMD" || ! -x "$TAG_REVISION_CMD" ]]; then
  echo "INFRA: registry probe scripts not found/executable ($TAG_STATE_CMD, $TAG_REVISION_CMD)" >&2
  infra_exit
else
  for component in "${VERSION_PINNED_COMPONENTS[@]}"; do
    IFS='|' read -r vfile suffix srcpaths <<< "$component"
    read -r -a srcarr <<< "$srcpaths"
    if [[ ! -f "$vfile" ]]; then
      warn "no $vfile -- skipping this component"
      continue
    fi
    pinned="$(tr -d '[:space:]' < "$vfile")"
    image="${REPO}${suffix}"
    if [[ -z "$pinned" ]]; then
      bad "$vfile is empty -- the publish job cannot derive a tag from it"
      continue
    fi

    state="$("$TAG_STATE_CMD" ghcr.io "$image" "$pinned" 2>/dev/null || true)"
    note "$image:$pinned -> $state"
    case "$state" in
      absent)
        ok "$vfile pins $pinned, which is unpublished -- the cut will create it"
        continue
        ;;
      present) ;;
      *)
        # Includes `indeterminate` and an empty/absent probe answer. We could
        # not read the registry, so we must not render a verdict either way.
        echo "INFRA: could not determine whether $image:$pinned is published (got '${state:-<no answer>}')" >&2
        infra_exit
        ;;
    esac

    # Published. Whether that is fine depends entirely on whether this commit
    # would rebuild it from different sources.
    rev="$("$TAG_REVISION_CMD" ghcr.io "$image" "$pinned" 2>/dev/null || true)"
    if [[ "$rev" == "none" ]]; then
      bad "$image:$pinned is published but carries no source-revision annotation"
      note "  -> the publish job fails closed on this (\"provenance missing\") and"
      note "     demands a $vfile bump; it will do the same on the tag."
      continue
    fi
    if [[ ! "$rev" =~ ^[0-9a-f]{40}$ ]]; then
      echo "INFRA: could not read the source revision of $image:$pinned (got '${rev:-<no answer>}')" >&2
      infra_exit
    fi

    # A shallow checkout will not have the published commit; fetch just it.
    if ! git cat-file -e "${rev}^{commit}" 2>/dev/null; then
      git fetch --no-tags --depth=1 origin "$rev" >/dev/null 2>&1 || true
    fi
    if ! git cat-file -e "${rev}^{commit}" 2>/dev/null; then
      echo "INFRA: $image:$pinned names commit $rev, which could not be fetched" >&2
      infra_exit
    fi

    if git diff --quiet "$rev" HEAD -- "${srcarr[@]}"; then
      ok "$vfile pins $pinned and its sources are unchanged since $(git rev-parse --short "$rev")"
    else
      bad "$image:$pinned is already published from $(git rev-parse --short "$rev"), but its sources CHANGED here."
      note "  -> exact version tags are never republished, so the tag's Docker"
      note "     Publish will fail, skip every remaining manifest, and stall the"
      note "     whole release chain at resolve-candidate-digest."
      note "  -> bump $vfile before tagging. Changed paths:"
      while IFS= read -r f; do [[ -n "$f" ]] && note "       $f"; done < <(
        git diff --name-only "$rev" HEAD -- "${srcarr[@]}"
      )
      note "  -> neither a main build nor an -rc.N tag can catch this: the publish"
      note "     job only checks the exact tag on a clean refs/tags/v* ref."
    fi
  done
fi
echo

# --- check 5: CHANGELOG <-> commit reconciliation (issue #3537) --------------
#
# Checks 1-4 ask whether the release will BUILD. This one asks whether it will
# be DESCRIBED correctly, which is the failure mode that actually shipped:
# four of the last eight releases carried wrong bookkeeping, every one found
# by a human days later.
#
#   v1.7.1      no curated notes file existed, so release.yml fell back to
#               generate_release_notes -- and auto-notes do not promote the
#               CHANGELOG, so 8 entries that had already SHIPPED stayed under
#               [Unreleased], including an upgrade note that told operators to
#               act "before upgrading to 1.7.2" when they had been exposed for
#               a week (#3318).
#   post-1.7.3  a PR merged ~5h after the tag filed its bullet under
#               `## [1.7.3]`, so the published notes claim a fix that release
#               does not contain.
#   1.7.5 prep  the [Unreleased] heading was renamed without a fresh one being
#               opened; four later PRs merged into the released section with
#               no conflict (#3433).
#   v1.8.1      the two scanner-CVE fixes that unblocked the publish were
#               filed under [Unreleased] instead of [1.8.1].
#
# Nothing caught any of them because the only automated check asserts that a
# `## [X.Y.Z]` heading exists and is non-empty. A heading can exist, be
# non-empty, and describe a different release.
#
# The assertion here is two-way over the PENDING (`## [Unreleased]`) section
# and the commit range `<previous stable tag>..HEAD`:
#
#   forward   every entry's PRIMARY issue reference -- the first `#NNNN` on
#             its top-level `- ` line -- must be accounted for by the range.
#             An entry whose work is not in the range is describing some other
#             release (the v1.7.1 and v1.8.1 shapes: entries left behind after
#             their commits shipped).
#   backward  every merged PR in the range must be cited by the section,
#             either by its own number or by an issue it closes. A commit in
#             the range that the section does not mention is undocumented work
#             (the post-1.7.3 shape: the bullet went into the wrong section, so
#             the pending one no longer covers its commit).
#
# Only the FIRST reference on a bullet is required to resolve. Entries here
# routinely cite prior issues for context -- the current pending section names
# 58 distinct issues across 25 bullets -- and demanding that every one of them
# be in the range would make the check unusable noise. The first reference is
# the one the entry is about.
#
# Resolution needs the API because CHANGELOG entries cite ISSUE numbers while
# squash-merge subjects carry PR numbers: `#3373` in the changelog is PR
# `#3526` in the log. One batched GraphQL query maps every PR in the range to
# the issues it closes, which the repository's linked-issue gate guarantees
# are present. That is a single call, ~1s, well inside the budget.
#
# Dependency bumps and release-prep commits are exempt from the backward
# direction: they are real commits that deliberately carry no user-facing
# entry. The exemption is a subject-line pattern so it stays reviewable.
#
# Outcomes follow the same discipline as checks 3 and 4 -- an answer we could
# not obtain is not an answer:
#   * skipped (PREFLIGHT_SKIP_CHANGELOG_RECON=1)   -> note, not blocking
#   * `gh` absent, or the GraphQL query failed     -> INFRA, exit 2
#   * no previous stable tag reachable from HEAD   -> INFRA, exit 2
#     (a shallow clone without tags cannot bound the range; fetch tags)
#   * no `## [Unreleased]` section                 -> blocking, exit 1
#   * an unreconciled entry or commit              -> blocking, exit 1
echo "5) CHANGELOG <-> commit reconciliation for the pending section"
if [[ "${PREFLIGHT_SKIP_CHANGELOG_RECON:-0}" == "1" ]]; then
  note "NOT MEASURED (PREFLIGHT_SKIP_CHANGELOG_RECON=1) -- this check did not run,"
  note "which is not the same as it passing."
elif [[ ! -f CHANGELOG.md ]]; then
  echo "INFRA: no CHANGELOG.md at the repo root" >&2
  infra_exit
elif ! command -v gh >/dev/null 2>&1; then
  # Deliberately INFRA rather than a note: unlike checks 3 and 4 there is no
  # partial answer to give. Without the issue<->PR map every entry looks
  # unreconciled, so a "soft" version of this check would either spray false
  # positives or quietly pass.
  echo "INFRA: gh is not on PATH; the issue<->PR map cannot be built" >&2
  infra_exit
else
  prev_tag="${PREFLIGHT_PREV_TAG:-}"
  if [[ -z "$prev_tag" ]]; then
    prev_tag="$(git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*' \
                  --exclude '*-*' HEAD 2>/dev/null || true)"
  fi
  if [[ -z "$prev_tag" ]]; then
    echo "INFRA: no previous stable tag is reachable from HEAD -- cannot bound the" >&2
    echo "       commit range. Run 'git fetch --tags' and retry." >&2
    infra_exit
  fi
  note "range: ${prev_tag}..HEAD"

  # THE PENDING SECTIONS. `## [Unreleased]` plus every `## [X.Y.Z]` section
  # whose version is NEWER than the previous stable tag.
  #
  # The second half is load-bearing, and getting it wrong makes the check
  # useless at the moment it matters most. Preflight is RELEASING.md step 1
  # and the CHANGELOG promotion is step 3, so most runs see everything under
  # `[Unreleased]` -- but a run made after the promotion and before the tag
  # (the last chance to catch anything) sees the same work under a `## [X.Y.Z]`
  # heading for a version that has not shipped. Reconciling against
  # `[Unreleased]` alone would then report every commit in the range as
  # undocumented. Replayed against the v1.7.1 cut, that is 27 false failures
  # next to the one true one.
  #
  # "Newer than the previous stable tag" is decided locally by numeric
  # comparison rather than by asking whether a tag exists, so the answer does
  # not depend on fetch state or on a network call.
  prev_ver="${prev_tag#v}"
  pending="$(awk -v prev="$prev_ver" '
    function newer(a, b,   ai, bi, i, x, y) {
      split(a, ai, "."); split(b, bi, ".")
      for (i = 1; i <= 3; i++) {
        x = ai[i] + 0; y = bi[i] + 0
        if (x > y) return 1
        if (x < y) return 0
      }
      return 0
    }
    /^## \[/ {
      inside = 0
      if ($0 ~ /^## \[Unreleased\]/) {
        inside = 1
      } else if (match($0, /^## \[[0-9]+\.[0-9]+\.[0-9]+\]/)) {
        if (newer(substr($0, RSTART + 4, RLENGTH - 5), prev)) inside = 1
      }
      next
    }
    inside { print }' CHANGELOG.md)"
  pending_headings="$(awk -v prev="$prev_ver" '
    function newer(a, b,   ai, bi, i, x, y) {
      split(a, ai, "."); split(b, bi, ".")
      for (i = 1; i <= 3; i++) {
        x = ai[i] + 0; y = bi[i] + 0
        if (x > y) return 1
        if (x < y) return 0
      }
      return 0
    }
    /^## \[Unreleased\]/ { print; next }
    match($0, /^## \[[0-9]+\.[0-9]+\.[0-9]+\]/) {
      if (newer(substr($0, RSTART + 4, RLENGTH - 5), prev)) print
    }' CHANGELOG.md | tr '\n' ' ')"
  note "pending sections: ${pending_headings:-<none>}"
  if ! grep -q '^## \[Unreleased\]' CHANGELOG.md; then
    bad "CHANGELOG.md has no '## [Unreleased]' section -- there is nothing to reconcile."
    note "  -> a release prep must open a fresh empty one above the promoted"
    note "     heading (RELEASING.md step 3, #3433)."
  else
    # Every reference anywhere in the section (used for the backward
    # direction: a bullet may cite its PR in prose rather than in the lead).
    pending_refs="$(printf '%s\n' "$pending" | grep -oE '#[0-9]{2,6}' | tr -d '#' | sort -u || true)"
    # The PRIMARY reference of each entry: the first `#NNNN` on a top-level
    # `- ` line. Continuation paragraphs are indented, so they are not entries.
    #
    # `### Sponsors` and `### Thank You` are skipped. They are mandatory in
    # every section (CLAUDE.md "Changelog and Release Notes") and their bullets
    # cite the issue a reporter FILED -- which is a credit, not a claim that
    # the work is in this range, and may name an issue closed long ago.
    primary_refs="$(printf '%s\n' "$pending" \
      | awk '/^### / { skip = ($0 ~ /^### (Sponsors|Thank You)/) ; next }
             !skip && /^- / { if (match($0, /#[0-9][0-9]+/)) print substr($0, RSTART + 1, RLENGTH - 1) }' \
      | sort -u || true)"

    subjects="$(git log --format='%s' "${prev_tag}..HEAD" 2>/dev/null || true)"
    # Squash-merge subjects end in `(#NNNN)`; that is the PR number.
    range_prs="$(printf '%s\n' "$subjects" | grep -oE '\(#[0-9]+\)$' | tr -d '(#)' | sort -u || true)"
    # Anything a commit message mentions at all also counts as accounted for
    # in the forward direction -- a bullet whose lead names the issue a commit
    # body cites is describing work that is genuinely in the range.
    mentioned="$(git log --format='%s%n%b' "${prev_tag}..HEAD" 2>/dev/null \
      | grep -oE '#[0-9]{2,6}' | tr -d '#' | sort -u || true)"

    # One batched GraphQL query: PR number -> the issues it closes. The
    # repository's linked-issue gate means this is populated for every PR that
    # is not explicitly exempted, which is what makes the mapping reliable
    # enough to gate on.
    closes_map=""
    if [[ -n "$range_prs" ]]; then
      gql="query{repository(owner:\"${REPO%%/*}\",name:\"${REPO##*/}\"){"
      idx=0
      while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        gql+=" p${idx}: pullRequest(number:${p}){number closingIssuesReferences(first:20){nodes{number}}}"
        idx=$((idx + 1))
      done <<< "$range_prs"
      gql+="}}"
      if ! closes_map="$(gh api graphql -f query="$gql" \
            --jq '.data.repository | to_entries[] | "\(.value.number):\([.value.closingIssuesReferences.nodes[].number] | join(","))"' \
            2>/dev/null)"; then
        echo "INFRA: could not resolve the PR->closing-issue map for ${prev_tag}..HEAD" >&2
        infra_exit
      fi
    fi
    closing_issues="$(printf '%s\n' "$closes_map" | cut -d: -f2 | tr ',' '\n' \
      | grep -E '^[0-9]+$' | sort -u || true)"
    accounted="$(printf '%s\n%s\n%s\n' "$range_prs" "$closing_issues" "$mentioned" \
      | grep -E '^[0-9]+$' | sort -u || true)"

    # -- forward: entries whose primary reference is not in the range --------
    unresolved=""
    if [[ -n "$primary_refs" ]]; then
      unresolved="$(grep -Fxv -f <(printf '%s\n' "$accounted") \
                      <(printf '%s\n' "$primary_refs") || true)"
    fi
    if [[ -n "$unresolved" ]]; then
      bad "pending CHANGELOG entries reference work that is NOT in ${prev_tag}..HEAD:"
      while IFS= read -r u; do
        [[ -z "$u" ]] && continue
        note "  - #$u  $(printf '%s\n' "$pending" | grep -m1 -F "#$u" | cut -c1-90)"
      done <<< "$unresolved"
      note "  -> either the entry belongs to an already-released section (it was"
      note "     left behind when its commits shipped -- the v1.7.1 and v1.8.1"
      note "     shape), or its lead reference is wrong."
    fi

    # -- backward: commits in the range that the section does not mention ----
    undocumented=0
    exempted=0
    while IFS= read -r p; do
      [[ -z "$p" ]] && continue
      subj="$(printf '%s\n' "$subjects" | grep -m1 -F "(#${p})" || true)"
      # Deliberately narrow: dependency bumps and the release prep itself are
      # the only commit shapes that legitimately carry no user-facing entry.
      if [[ "$subj" =~ ^chore(\([^\)]*\))?!?:\ bump\  || "$subj" =~ ^chore\(release\) ]]; then
        exempted=$((exempted + 1))
        continue
      fi
      cited=0
      pr_issues="$(printf '%s\n' "$closes_map" | grep -m1 "^${p}:" | cut -d: -f2 | tr ',' '\n' || true)"
      for candidate in "$p" $pr_issues; do
        [[ -z "$candidate" ]] && continue
        if printf '%s\n' "$pending_refs" | grep -qx "$candidate"; then cited=1; break; fi
      done
      if [[ "$cited" -eq 0 ]]; then
        if [[ "$undocumented" -eq 0 ]]; then
          bad "commits in ${prev_tag}..HEAD are not described by the pending section:"
        fi
        undocumented=$((undocumented + 1))
        note "  - #$p  $(printf '%s' "$subj" | cut -c1-90)"
      fi
    done <<< "$range_prs"
    if [[ "$undocumented" -gt 0 ]]; then
      note "  -> add an entry under '## [Unreleased]', or check whether the entry"
      note "     was filed under an ALREADY RELEASED heading (the post-1.7.3 shape:"
      note "     a PR merged after the tag anchored on the released section)."
      note "  -> dependency bumps and 'chore(release):' commits are exempt; nothing else is."
    fi

    if [[ -z "$unresolved" && "$undocumented" -eq 0 ]]; then
      ok "pending sections reconcile with ${prev_tag}..HEAD ($(printf '%s\n' "$primary_refs" | grep -c . || true) distinct entry references, $(printf '%s\n' "$range_prs" | grep -c . || true) merged PRs, $exempted exempt)"
    fi
  fi
fi
echo
# --- verdict ----------------------------------------------------------------
#
# The ref and sha are part of the verdict, not decoration. A bare "READY" is
# ambiguous about WHAT is ready, and that ambiguity is exactly how v1.7.5,
# v1.7.6 and v1.7.7 were each cut from release/1.7.x on the strength of a
# preflight transcript that had, in fact, audited main.
if [[ "$problems" -gt 0 ]]; then
  echo "${RED}NOT READY${RST} to cut from ${AUDIT_REF}@${AUDIT_SHA}: $problems blocking problem(s). Fix them on ${AUDIT_REF} before tagging."
  exit 1
fi
echo "${GRN}READY${RST} to cut from ${AUDIT_REF}@${AUDIT_SHA}: no blocking problems."
exit 0
