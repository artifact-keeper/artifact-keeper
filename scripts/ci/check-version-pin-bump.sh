#!/usr/bin/env bash
#
# Version-pin bump gate (issue #3754).
#
# Asks, on every PR, the question release-preflight.sh check 4 (#3339) asks at
# release-cut time: did this branch change a version-pinned component's sources
# without bumping its VERSION file, when that version is ALREADY PUBLISHED?
#
# Exact version tags are never republished (#2457 / the v1.5.8 integrity
# failure), so such a commit cannot publish. The failure is not local to the
# component either: it skips every remaining manifest, so
# resolve-candidate-digest has nothing to pin and the entire release chain
# stops on a tag that -- being immutable -- has to be deleted by hand.
#
# WHY AT PR TIME
#   Nothing on the PR path can see this. The publish job only evaluates the
#   exact tag when `stable_requested` is true, which needs a clean
#   `refs/tags/v*` ref; on main and on an `-rc.N` tag it publishes dev/sha tags
#   and returns before the collision check. So the offending PR goes green
#   everywhere and the defect surfaces at the cut -- the most expensive place
#   to find it and the one place it cannot be amended.
#
#   It has happened twice in one week. #3579 (dependabot's Go toolchain bump)
#   changed docker/Dockerfile.scanner-adapter and left
#   docker/scanner-adapter/VERSION at 1.2.8; #3752 bumped it at the cut, and
#   #3753 had to bump again for the trivy repoint. Both were one-line changes
#   to a VERSION file. Caught here, that is thirty seconds of an author's time.
#
# WHY NO ESCAPE HATCH
#   Deliberately none -- no env switch, no label. This gate is not a policy
#   preference that a reviewer can weigh against shipping; it is a prediction
#   of a mechanical refusal by the registry, made from the same source paths
#   the publish job diffs. Waving it through does not make the tag publishable,
#   it only moves the discovery back to the cut. The remedy is always the same
#   one line, and it is always available.
#
# Usage:  check-version-pin-bump.sh [<base-ref>]
#
#   base ref: $1, else $GITHUB_BASE_REF, else origin/main. A bare branch name
#   (which is what GITHUB_BASE_REF is) is also tried as `origin/<name>`.
#   The comparison is three-dot (`<base>...HEAD`), i.e. against the merge base,
#   so commits that landed on the base after this branch forked are not read as
#   this branch's changes.
#
# Env:
#   VERSION_PINNED_COMPONENTS_FILE  the component table (default
#                    scripts/ci/version-pinned-components.txt). Shared with
#                    release-preflight.sh check 4 so the two gates cannot
#                    disagree about which paths belong to which component.
#   PREFLIGHT_TAG_STATE_CMD         path to the tag-presence probe
#                    (default .github/scripts/registry-tag-state.sh). Named
#                    for the preflight because it IS the preflight's knob;
#                    the self-test replays canned registry answers through it.
#   VERSION_PIN_REPO  owner/name the images are published under (default:
#                    derived from the origin remote, else
#                    artifact-keeper/artifact-keeper).
#
# Outcomes, kept distinct for the same reason check 4 keeps them distinct -- a
# registry we could not read is not a registry that said yes:
#   sources unchanged                        -> ok
#   sources changed, VERSION bumped          -> ok
#   sources changed, VERSION unchanged and
#     that version is UNPUBLISHED            -> ok (the cut will create it)
#   sources changed, VERSION unchanged and
#     that version is PUBLISHED              -> blocking, exit 1
#   registry unreadable / table unreadable   -> INFRA, exit 2
#
# Exit codes (mirror check-release-branch-commits.sh and the preflight):
#   0  no unbumped version-pinned component.
#   1  at least one; bump its VERSION file.
#   2  INFRA -- could not measure. NOT a verdict, and NOT a pass.
set -uo pipefail

if ! ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"; then
  echo "INFRA: not inside a git work tree" >&2
  exit 2
fi
cd "$ROOT" || exit 2

COMPONENTS_FILE="${VERSION_PINNED_COMPONENTS_FILE:-$ROOT/scripts/ci/version-pinned-components.txt}"
TAG_STATE_CMD="${PREFLIGHT_TAG_STATE_CMD:-.github/scripts/registry-tag-state.sh}"

REPO="${VERSION_PIN_REPO:-}"
if [[ -z "$REPO" ]]; then
  origin="$(git config --get remote.origin.url 2>/dev/null || true)"
  REPO="$(printf '%s' "$origin" | sed -E 's#(git@[^:]+:|https?://[^/]+/)##; s#\.git$##')"
  [[ -z "$REPO" ]] && REPO="artifact-keeper/artifact-keeper"
fi

# --- base ref ---------------------------------------------------------------
BASE_REF="${1:-${GITHUB_BASE_REF:-origin/main}}"
base=''
for candidate in "$BASE_REF" "origin/$BASE_REF" "refs/remotes/origin/$BASE_REF"; do
  if git rev-parse --verify --quiet "${candidate}^{commit}" > /dev/null 2>&1; then
    base="$candidate"
    break
  fi
done
if [[ -z "$base" ]]; then
  echo "INFRA: base ref '${BASE_REF}' does not resolve to a commit (fetch it first; this gate needs history, not a depth-1 checkout)" >&2
  exit 2
fi

# Three-dot: the merge base, so work that landed on the base after this branch
# forked is not attributed to this branch. Resolved explicitly because the
# VERSION comparison below needs the same left-hand side as the source diff.
if ! MERGE_BASE="$(git merge-base "$base" HEAD 2>/dev/null)" || [[ -z "$MERGE_BASE" ]]; then
  echo "INFRA: no merge base between '${base}' and HEAD" >&2
  exit 2
fi

# --- component table --------------------------------------------------------
#
# An unreadable table is not an empty one. Checking nothing and reporting a
# pass is the exact outcome this gate exists to prevent, so it is INFRA.
components=()
if [[ ! -r "$COMPONENTS_FILE" ]]; then
  echo "INFRA: cannot read the version-pinned component table ($COMPONENTS_FILE)" >&2
  exit 2
fi
while IFS= read -r line || [[ -n "$line" ]]; do
  if [[ "$line" =~ ^[[:space:]]*(#|$) ]]; then continue; fi
  if [[ "$line" != *"|"*"|"* ]]; then
    echo "INFRA: malformed row in $COMPONENTS_FILE: $line" >&2
    exit 2
  fi
  components+=("$line")
done < "$COMPONENTS_FILE"
if [[ ${#components[@]} -eq 0 ]]; then
  echo "INFRA: $COMPONENTS_FILE lists no components" >&2
  exit 2
fi

echo "Version-pinned components, ${base} ($(git rev-parse --short "$MERGE_BASE")) -> HEAD:"

problems=0
for component in "${components[@]}"; do
  IFS='|' read -r vfile suffix srcpaths <<< "$component"
  read -r -a srcarr <<< "$srcpaths"

  if [[ ! -f "$vfile" ]]; then
    echo "  - $vfile is not present on this branch; skipping this component"
    continue
  fi

  changed="$(git diff --name-only "${base}...HEAD" -- "${srcarr[@]}" 2>/dev/null)"
  if [[ -z "$changed" ]]; then
    echo "  ✓ ${vfile%/VERSION}: sources unchanged"
    continue
  fi

  # The pinned version as this tree spells it, the way the preflight reads it.
  pinned="$(tr -d '[:space:]' < "$vfile")"
  if [[ -z "$pinned" ]]; then
    echo "  ✗ $vfile is empty -- the publish job cannot derive a tag from it"
    problems=$((problems + 1))
    continue
  fi
  # Absent at the merge base means the component is NEW on this branch: there
  # is no published tag of it to collide with, and `git show` failing is the
  # answer, not an error.
  base_pinned="$(git show "${MERGE_BASE}:${vfile}" 2>/dev/null | tr -d '[:space:]' || true)"
  if [[ -z "$base_pinned" || "$base_pinned" != "$pinned" ]]; then
    echo "  ✓ ${vfile%/VERSION}: sources changed and $vfile moved ${base_pinned:-<new>} -> $pinned"
    continue
  fi

  # Sources changed, VERSION did not. Whether that is a problem depends
  # entirely on whether $pinned is already published -- an unpublished version
  # is created by the cut, no matter how often its sources move first.
  image="${REPO}${suffix}"
  if [[ ! -x "$TAG_STATE_CMD" ]]; then
    echo "INFRA: registry probe not found/executable ($TAG_STATE_CMD)" >&2
    exit 2
  fi
  state="$("$TAG_STATE_CMD" ghcr.io "$image" "$pinned" 2>/dev/null || true)"
  case "$state" in
    absent)
      echo "  ✓ ${vfile%/VERSION}: sources changed, but $pinned is unpublished -- the cut will create it"
      continue
      ;;
    present) ;;
    *)
      # Includes `indeterminate` and an empty/absent probe answer.
      echo "INFRA: could not determine whether ${image}:${pinned} is published (got '${state:-<no answer>}')" >&2
      exit 2
      ;;
  esac

  problems=$((problems + 1))
  echo "  ✗ ${vfile%/VERSION}: sources changed, but $vfile still pins $pinned, which is ALREADY PUBLISHED as ${image}:${pinned}"
  echo "      changed paths:"
  while IFS= read -r f; do [[ -n "$f" ]] && echo "        $f"; done <<< "$changed"
done

echo

if [[ $problems -gt 0 ]]; then
  echo "::error title=Version-pinned component needs a VERSION bump::${problems} component(s) changed without bumping their already-published VERSION file. The release cut will fail on this."
  echo "Exact version tags are never republished (artifact-keeper#2457). A tag cut"
  echo "on this commit would fail the component's Docker Publish, SKIP every"
  echo "remaining manifest, leave resolve-candidate-digest nothing to pin, and"
  echo "stall the whole release chain on an immutable tag."
  echo
  echo "Fix: bump the VERSION file named above in this PR. One line, and the"
  echo "publish job then has a free tag to create."
  echo
  echo "Neither a main build nor an -rc.N tag can catch this: the publish job"
  echo "only checks the exact tag on a clean refs/tags/v* ref, which is why"
  echo "this runs here and why release-preflight.sh check 4 exists at all"
  echo "(artifact-keeper#3339 / artifact-keeper#3754)."
  exit 1
fi

echo "::notice::No version-pinned component changed without a VERSION bump."
