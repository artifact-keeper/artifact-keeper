#!/usr/bin/env bash
#
# Candidate-time copy of the scanner-adapter exact-version decision that
# docker-publish.yml makes only on a clean `refs/tags/v*` push (issue #3773).
#
# WHY THIS EXISTS
#   The adapter is versioned by docker/scanner-adapter/VERSION, not by the AK
#   git tag, and its exact tag is never republished. docker-publish.yml's
#   "Decide stable adapter publication" step asks, on a stable tag push and
#   nowhere else: is `adapter:<VERSION>` already published, on which
#   registries, from which sources -- and refuses a changed-source rebuild of
#   an existing version (the collision that killed v1.7.2 and v1.7.5). RELEASING
#   step 6 admitted that a `-rc` candidate never exercised it. In the
#   candidate-then-promote flow the candidate is the ONLY test a release gets,
#   so this asks the same question, against the same registries and the same
#   source paths, of the commit being certified. release-preflight.sh check 4
#   asks it of ghcr only; the publish job asks both registries, and so does
#   this.
#
# Outcomes, matching the publish job step for step:
#   absent on both        -> ok, the promote will create the exact tag from
#                            this commit's sha-<sha> adapter image
#   present on both,
#     same VERSION file, sources unchanged since the published revision
#                         -> ok, the exact tag stays on its published digest
#     sources changed     -> BLOCKED, VERSION bump required
#     VERSION mismatch    -> BLOCKED, version collision
#     no revision         -> BLOCKED, provenance missing (the publish job
#                            hard-fails on this too)
#   present on one only   -> BLOCKED, registries disagree (partial publish)
#   indeterminate         -> INFRA, exit 2 (a registry we could not read is
#                            not a registry that said yes)
#
# Exit codes: 0 ok, 1 BLOCKED, 2 INFRA.
#
# Env:
#   ADAPTER_SHA          (required) commit being certified (40-hex, must be
#                        present in the current git repository)
#   ADAPTER_VERSION      default: docker/scanner-adapter/VERSION at ADAPTER_SHA
#   ADAPTER_GHCR_IMAGE   default artifact-keeper/artifact-keeper-scanner-adapter
#   ADAPTER_HUB_IMAGE    default artifactkeeper/scanner-adapter
#   ADAPTER_SOURCES      default "docker/scanner-adapter docker/Dockerfile.scanner-adapter"
#                        (MUST mirror the paths docker-publish.yml diffs)
#   ADAPTER_TAG_STATE_CMD, ADAPTER_TAG_REVISION_CMD  probe overrides for the
#                        self-test (default the .github/scripts probes)
#   GHCR_TOKEN, DOCKERHUB_USERNAME, DOCKERHUB_TOKEN  passed to the probes
#
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
SHA="${ADAPTER_SHA:-}"
GHCR_IMAGE="${ADAPTER_GHCR_IMAGE:-artifact-keeper/artifact-keeper-scanner-adapter}"
HUB_IMAGE="${ADAPTER_HUB_IMAGE:-artifactkeeper/scanner-adapter}"
SOURCES="${ADAPTER_SOURCES:-docker/scanner-adapter docker/Dockerfile.scanner-adapter}"
STATE_CMD="${ADAPTER_TAG_STATE_CMD:-${ROOT}/.github/scripts/registry-tag-state.sh}"
REV_CMD="${ADAPTER_TAG_REVISION_CMD:-${ROOT}/.github/scripts/registry-tag-revision.sh}"

blocked() { echo "::error title=Scanner adapter exact tag cannot publish::$1"; echo "BLOCKED: $1"; exit 1; }
infra()   { echo "::error title=Scanner adapter registry state unmeasurable::$1"; echo "INFRA: $1"; exit 2; }

[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || infra "ADAPTER_SHA must be a full 40-character sha (got '${SHA}')."
git cat-file -e "${SHA}^{commit}" 2>/dev/null || infra "commit ${SHA} is not in this repository; fetch it first."
[[ -x "$STATE_CMD" && -x "$REV_CMD" ]] || infra "registry probes not executable (${STATE_CMD}, ${REV_CMD})."

VERSION="${ADAPTER_VERSION:-}"
if [[ -z "$VERSION" ]]; then
  VERSION="$(git show "${SHA}:docker/scanner-adapter/VERSION" 2>/dev/null | tr -d '[:space:]')"
fi
[[ -n "$VERSION" ]] || blocked "docker/scanner-adapter/VERSION is empty or missing at ${SHA}; the publish job cannot derive a tag from it."

read -r -a srcarr <<< "$SOURCES"

echo "== scanner-adapter exact-version check (candidate parity, #3773) =="
echo "commit:  ${SHA}"
echo "version: ${VERSION}"
echo

ghcr_state="$("$STATE_CMD" ghcr.io "$GHCR_IMAGE" "$VERSION" 2>/dev/null || true)"
hub_state="$("$STATE_CMD" docker.io "$HUB_IMAGE" "$VERSION" 2>/dev/null || true)"
echo "  ghcr.io/${GHCR_IMAGE}:${VERSION}  -> ${ghcr_state:-<no answer>}"
echo "  docker.io/${HUB_IMAGE}:${VERSION} -> ${hub_state:-<no answer>}"

case "${ghcr_state}|${hub_state}" in
  absent\|absent)
    echo "ok: scanner-adapter ${VERSION} is new on both registries; the promote creates the exact tag from this commit's sha-${SHA:0:7} image."
    exit 0
    ;;
  present\|present)
    ;;
  present\|absent|absent\|present)
    blocked "scanner-adapter ${VERSION} is ${ghcr_state} on ghcr.io but ${hub_state} on docker.io -- likely a partial publish. The publish job refuses this shape (a rebuild cannot re-point the immutable exact tag); finish it with the promote dispatch (promote_version=<AK version>) before certifying."
    ;;
  *)
    infra "unable to prove whether scanner-adapter ${VERSION} is published (ghcr.io=${ghcr_state:-<none>}, docker.io=${hub_state:-<none>}); failing closed rather than risk replacing a published tag."
    ;;
esac

# Present on both: the exact tag stays where it is; this commit may only be
# certified if it is an unchanged-source rebuild of that version.
rev="$("$REV_CMD" ghcr.io "$GHCR_IMAGE" "$VERSION" 2>/dev/null || true)"
echo "  published ${VERSION} was built from: ${rev:-<no answer>}"
if [[ "$rev" == "none" ]]; then
  blocked "ghcr.io/${GHCR_IMAGE}:${VERSION} exists but has no valid source revision annotation, so this commit cannot prove it rebuilds the same sources. Bump docker/scanner-adapter/VERSION."
fi
[[ "$rev" =~ ^[0-9a-f]{40}$ ]] || infra "could not read the source revision of ghcr.io/${GHCR_IMAGE}:${VERSION} (got '${rev:-<none>}')."

if ! git cat-file -e "${rev}^{commit}" 2>/dev/null; then
  git fetch --no-tags --depth=1 origin "$rev" >/dev/null 2>&1 || true
fi
git cat-file -e "${rev}^{commit}" 2>/dev/null || infra "the published adapter names commit ${rev}, which could not be fetched."

existing_version="$(git show "${rev}:docker/scanner-adapter/VERSION" 2>/dev/null | tr -d '[:space:]')"
if [[ "$existing_version" != "$VERSION" ]]; then
  blocked "ghcr.io/${GHCR_IMAGE}:${VERSION} records VERSION=${existing_version:-<none>} at ${rev:0:7}, expected ${VERSION} -- version collision."
fi

if ! git diff --quiet "$rev" "$SHA" -- "${srcarr[@]}"; then
  echo "  changed paths:"
  git diff --name-only "$rev" "$SHA" -- "${srcarr[@]}" | sed 's/^/    /'
  blocked "scanner-adapter ${VERSION} already exists at ${rev:0:7}, but its sources changed at ${SHA:0:7}. Bump docker/scanner-adapter/VERSION; exact version tags are never republished (the v1.7.2 / v1.7.5 collision)."
fi

echo "ok: scanner-adapter ${VERSION} is published from ${rev:0:7} and its sources are unchanged at ${SHA:0:7}; the exact tag stays on its published digest."
exit 0
