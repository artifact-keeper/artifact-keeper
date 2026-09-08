#!/usr/bin/env bash
#
# Release gate: prove that a commit's images passed the full Release Gate
# BEFORE anything gives them a permanent name (issues #3771, #3772).
#
# WHY THIS EXISTS
#   Until now the immutable git tag was the trigger for testing. Everything
#   downstream of the tag push is irreversible -- the tag (ruleset 19144026),
#   `:X.Y.Z`, and for a while `:latest` -- so a gate failure burned a version
#   number. 1.9.0 hit every edge of that at once (#3769). The candidate flow
#   turns it around: release-candidate.yml gates a COMMIT, using the
#   `sha-<sha>` images Docker Publish already built for it, and on green
#   records a certification. This script is how every later step -- the
#   promote, docker-publish.yml's certified-candidate promote, and the run of
#   release.yml the promote dispatches on the tag -- checks that the
#   certification exists for the commit in front of it and still describes
#   what the registry serves. (A stable tag PUSH is refused outright by both
#   workflows before this script runs: the promote creates every stable tag,
#   and a ref created by GITHUB_TOKEN fires no push event.)
#
# THE CARRIER
#   The certification is a signed attestation (actions/attest, Sigstore via
#   GitHub OIDC) whose SUBJECT is each image's manifest-list digest and whose
#   predicate names the commit, the version, the gate run and every digest.
#   It is verified with `gh attestation verify`, pinned to the EXACT signing
#   identity that is allowed to certify: `--cert-identity
#   https://github.com/<repo>/.github/workflows/release-candidate.yml@refs/heads/main`,
#   the certificate's SubjectAlternativeName, compared byte-for-byte (a
#   `!=` in sigstore-go). Neither of gh's looser pins is enough on its own:
#   `--signer-workflow` builds a SAN regex with no `@ref`, so a copy of
#   release-candidate.yml on a topic branch, gate edited out, would match;
#   `--source-ref` compares the ref extension case-insensitively
#   (strings.EqualFold), so a branch named `Main` would too, and git refs are
#   case-sensitive. `--source-ref refs/heads/main` is still passed as a
#   second, independent check on the ref extension. release-candidate.yml
#   also refuses to run off main, by a case-sensitive shell comparison.
#   Nothing that can write an artifact or a commit status can forge it:
#   producing one needs the OIDC identity of release-candidate.yml, on
#   main, in this repository. A workflow artifact and a commit status are
#   written alongside it for humans; they are not what this script trusts.
#
# THE RULE, in one sentence:
#   for every image the release ships, the `sha-<sha>` tag must resolve NOW to
#   a digest that carries a valid certification from release-candidate.yml
#   whose predicate names THIS commit and these SAME digests.
#
#   Each clause is load-bearing:
#     * "resolve now" -- the registry is read at verification time, so an
#       image re-pushed under the same sha tag since certification is refused
#       (its digest has no attestation), and a sha tag that no longer exists
#       is a refusal, never a pass.
#     * "names this commit" -- an attestation is keyed by digest, and the same
#       bytes could in principle be tagged for another commit; the predicate
#       binds the digest set to one commit and the check reads it back.
#     * "these same digests" -- all three images must be named by ONE
#       certification (same candidate run), so a backend certified in one
#       run cannot be paired with an adapter from another. A digest can
#       carry more than one certification (the same commit certified twice
#       is allowed), so the run is chosen by content, deterministically:
#       the highest candidate run id that certified EVERY image for this
#       commit -- never "the first one gh happened to return".
#
# Exit codes (mirrors assert-preflight-evidence.sh):
#   0  certified; the digests and run ids are printed as key=value lines and
#      appended to $GITHUB_OUTPUT when set
#   1  BLOCKED -- no certification for this commit, or it no longer matches
#   2  INFRA   -- could not measure (registry / attestations API). NOT a pass.
#
# Env:
#   CERT_SHA             (required) 40-hex commit
#   CERT_REPO            owner/name (default artifact-keeper/artifact-keeper)
#   CERT_WORKFLOW        path of the certifying workflow within the repo
#                        (default .github/workflows/release-candidate.yml)
#   CERT_SOURCE_REF      the ref that workflow must have run on
#                        (default refs/heads/main)
#   CERT_PREDICATE_TYPE  the predicate type the candidate attests
#   CERT_EXPECT_VERSION  optional: the predicate's version must equal this
#   CERT_IMAGES          space-separated `<key>=<registry/repository>` pairs
#                        (default: backend, openscap, scanner_adapter on ghcr)
#   CERT_DIGEST_CMD      digest probe (default .github/scripts/registry-tag-digest.sh)
#   GHCR_TOKEN, GH_TOKEN for the probe and for gh
#
set -uo pipefail

SHA="${CERT_SHA:-}"
REPO="${CERT_REPO:-artifact-keeper/artifact-keeper}"
WORKFLOW="${CERT_WORKFLOW:-.github/workflows/release-candidate.yml}"
SOURCE_REF="${CERT_SOURCE_REF:-refs/heads/main}"
PREDICATE_TYPE="${CERT_PREDICATE_TYPE:-https://github.com/artifact-keeper/artifact-keeper/attestations/release-candidate/v1}"
EXPECT_VERSION="${CERT_EXPECT_VERSION:-}"
IMAGES="${CERT_IMAGES:-backend=ghcr.io/${REPO}-backend openscap=ghcr.io/${REPO}-openscap scanner_adapter=ghcr.io/${REPO}-scanner-adapter}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIGEST_CMD="${CERT_DIGEST_CMD:-${ROOT}/.github/scripts/registry-tag-digest.sh}"

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; RST=$'\033[0m'
[[ -t 1 ]] || { RED=""; GRN=""; YEL=""; RST=""; }

blocked() { printf '%sBLOCKED%s: %s\n' "$RED" "$RST" "$1"; echo "::error title=No release-candidate certification for this commit::$1"; exit 1; }
infra()   { printf '%sINFRA%s: %s\n'   "$YEL" "$RST" "$1"; echo "::error title=Certification could not be measured::$1 Retry; do not interpret as a pass."; exit 2; }

if [[ ! "$SHA" =~ ^[0-9a-f]{40}$ ]]; then
  infra "CERT_SHA must be a full 40-character commit sha (got '${SHA}')."
fi
command -v gh >/dev/null 2>&1 || infra "gh is not on PATH; the attestation cannot be verified."
command -v jq >/dev/null 2>&1 || infra "jq is not on PATH."
[[ -x "$DIGEST_CMD" ]] || infra "digest probe ${DIGEST_CMD} is not executable."

SHORT="${SHA:0:7}"
SIGNER="${REPO}/${WORKFLOW}"
IDENTITY="https://github.com/${SIGNER}@${SOURCE_REF}"

echo "== release-candidate certification gate =="
echo "repo:      $REPO"
echo "commit:    $SHA"
echo "sha tag:   sha-${SHORT}"
echo "identity:  $IDENTITY"
echo "ref:       $SOURCE_REF"
echo "predicate: $PREDICATE_TYPE"
echo

# Errors that mean "could not reach", as opposed to "looked and it is not
# there". Same vocabulary verify-release-assets.sh uses.
looks_like_infra() {
  grep -qiE 'timeout|timed out|connection refused|dial tcp|i/o timeout|temporarily unavailable|EOF|5[0-9][0-9] |rate limit|no such host|TLS handshake|network is unreachable' <<<"$1"
}

declare -A digest_of=()
declare -A predicate_of=()
declare -A candidates_of=()   # per image: JSON array of predicates naming THIS commit
keys=()

# ---------------------------------------------------------------------------
# 1. what the registry serves for sha-<sha>, per image
# ---------------------------------------------------------------------------
for pair in $IMAGES; do
  key="${pair%%=*}"; ref="${pair#*=}"
  registry="${ref%%/*}"; repository="${ref#*/}"
  keys+=("$key")
  answer="$("$DIGEST_CMD" "$registry" "$repository" "sha-${SHORT}" 2>/dev/null)" || true
  case "$answer" in
    sha256:*)
      digest_of["$key"]="$answer"
      echo "  ${key}: ${ref}:sha-${SHORT} -> ${answer}"
      ;;
    absent)
      blocked "${ref}:sha-${SHORT} does not exist. Docker Publish never built images for ${SHA} (a docs-only commit gets no build, #3629), or they were deleted. Certify a commit that has a green Docker Publish run."
      ;;
    *)
      infra "could not read ${ref}:sha-${SHORT} from the registry (probe said '${answer:-<no answer>}')."
      ;;
  esac
done
echo

# ---------------------------------------------------------------------------
# 2. a certification from the candidate workflow, on each of those digests
# ---------------------------------------------------------------------------
for key in "${keys[@]}"; do
  for pair in $IMAGES; do [[ "${pair%%=*}" == "$key" ]] && ref="${pair#*=}"; done
  subject="oci://${ref}@${digest_of[$key]}"
  out=""; rc=0
  out="$(gh attestation verify "$subject" \
          --repo "$REPO" \
          --cert-identity "$IDENTITY" \
          --source-ref "$SOURCE_REF" \
          --predicate-type "$PREDICATE_TYPE" \
          --format json 2>&1)" || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    printf '%s\n' "$out" | sed 's/^/      /'
    if looks_like_infra "$out"; then
      infra "gh attestation verify could not reach the attestations API or the registry for ${subject}."
    fi
    blocked "${ref}@${digest_of[$key]} (sha-${SHORT}) carries no release-candidate certification signed by ${IDENTITY}. The full Release Gate has not passed on this commit's images. Dispatch the 'Release Candidate' workflow on ${SHA}, get it green, then retry."
  fi
  # Statements are found by shape rather than by position, so a change in
  # gh's JSON envelope does not silently turn every predicate into "missing".
  # ALL of them are kept: a digest certified twice carries two.
  predicates="$(jq -c '[.. | objects | select(has("predicateType") and has("predicate")) | .predicate | select(. != null)]' <<<"$out" 2>/dev/null || true)"
  [[ -n "$predicates" && "$(jq 'length' <<<"$predicates")" -gt 0 ]] || infra "gh attestation verify succeeded for ${subject} but its JSON carried no in-toto statement to read the predicate from."
  mine="$(jq -c --arg sha "$SHA" '[.[] | select(.commit_sha == $sha)]' <<<"$predicates")"
  if [[ "$(jq 'length' <<<"$mine")" -eq 0 ]]; then
    other="$(jq -r 'first | .commit_sha // empty' <<<"$predicates")"
    blocked "the certification on ${key}'s digest names commit '${other:-<none>}', not ${SHA}. These bytes were certified for a different commit."
  fi
  candidates_of["$key"]="$mine"
  echo "  ${key}: certification verified (${IDENTITY}; $(jq 'length' <<<"$mine") statement(s) for this commit)"
done
echo

# ---------------------------------------------------------------------------
# 3. ONE candidate run must have certified every image for this commit. The
#    same commit may have been certified more than once (a re-dispatch after
#    an infra failure is allowed and leaves a second attestation per digest),
#    so the run is selected by content: the highest run id among those that
#    appear on ALL images. gh's ordering of statements plays no part.
# ---------------------------------------------------------------------------
for key in "${keys[@]}"; do
  if [[ "$(jq '[.[] | select((.candidate_run_id // "") != "")] | length' <<<"${candidates_of[$key]}")" -eq 0 ]]; then
    blocked "the certification on ${key}'s digest names no candidate run id; refusing to trust a predicate with no provenance of its own."
  fi
done
run_sets="$(for key in "${keys[@]}"; do printf '%s\n' "${candidates_of[$key]}"; done \
  | jq -s '[.[] | [.[] | .candidate_run_id // empty | tostring] | unique]')"
cert_run="$(jq -r '
  reduce .[1:][] as $s (.[0]; [.[] | select(. as $r | $s | index($r))])
  | sort_by(tonumber? // 0) | last // empty' <<<"$run_sets")"
if [[ -z "$cert_run" ]]; then
  per_image="$(for key in "${keys[@]}"; do printf '%s=%s ' "$key" "$(jq -r '[.[] | .candidate_run_id // "<none>"] | join("/")' <<<"${candidates_of[$key]}")"; done)"
  blocked "no single candidate run certified every image for ${SHA} (runs per image: ${per_image% }); an image set is certified by ONE run or not at all."
fi
for key in "${keys[@]}"; do
  predicate_of["$key"]="$(jq -c --arg r "$cert_run" '[.[] | select((.candidate_run_id | tostring) == $r)] | first' <<<"${candidates_of[$key]}")"
done

# ---------------------------------------------------------------------------
# 4. the selected predicate must be about THESE digests (and this version)
# ---------------------------------------------------------------------------
first_key="${keys[0]}"
p0="${predicate_of[$first_key]}"
cert_version="$(jq -r '.version // empty' <<<"$p0")"
gate_run="$(jq -r '.gate_run_id // empty' <<<"$p0")"

[[ -n "$gate_run" ]] || blocked "the certification names no Release Gate run id."
if [[ -n "$EXPECT_VERSION" && "$cert_version" != "$EXPECT_VERSION" ]]; then
  blocked "the certification is for version '${cert_version:-<none>}', but this release is ${EXPECT_VERSION}. Cargo.toml at ${SHA} must name the version being released; certify again."
fi

for key in "${keys[@]}"; do
  p="${predicate_of[$key]}"
  named="$(jq -r --arg k "$key" '.digests[$k] // empty' <<<"$p")"
  if [[ "$named" != "${digest_of[$key]}" ]]; then
    blocked "the certification names ${key} as '${named:-<none>}' but the registry now serves ${digest_of[$key]} for sha-${SHORT}. The bytes changed since the gate ran; certify again."
  fi
done

printf '%sCERTIFIED%s: %s at %s passed the Release Gate (candidate run %s, gate run %s).\n' \
  "$GRN" "$RST" "${cert_version:-<unversioned>}" "$SHA" "$cert_run" "$gate_run"

emit() {
  echo "$1=$2"
  [[ -n "${GITHUB_OUTPUT:-}" ]] && echo "$1=$2" >> "$GITHUB_OUTPUT"
  return 0
}
emit certified true
emit version "$cert_version"
emit candidate_run_id "$cert_run"
emit gate_run_id "$gate_run"
for key in "${keys[@]}"; do emit "${key}_digest" "${digest_of[$key]}"; done

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "### Release-candidate certification: PASS"
    echo
    echo "| | |"
    echo "|---|---|"
    echo "| commit | \`${SHA}\` |"
    echo "| version | ${cert_version} |"
    echo "| candidate run | ${cert_run} |"
    echo "| gate run | ${gate_run} |"
    for key in "${keys[@]}"; do echo "| ${key} | \`${digest_of[$key]}\` |"; done
  } >> "$GITHUB_STEP_SUMMARY"
fi
exit 0
