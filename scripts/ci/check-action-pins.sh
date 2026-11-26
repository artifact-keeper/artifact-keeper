#!/usr/bin/env bash
# =============================================================================
# scripts/ci/check-action-pins.sh - every `uses:` in this repo's workflows and
# composite actions names a full commit sha, and every taiki-e/install-action
# tool has an exact version (#6178)
# =============================================================================
# A tag or branch ref (`@v7`, `@v7.1.0`, `@main`, `@1.98.0`) can be moved by
# whoever controls the action's repository, and the next run executes the new
# code with this repo's token. A sha cannot move. Until the organisation-wide
# `sha_pinning_required` setting is on, this is what keeps the rule; once it
# is on, this still catches the miss at PR time instead of at queue time.
#
# The trailing `# vX.Y.Z` comment is for readers; this does not resolve tags
# (no network). Keep it the exact tag whose commit the sha is.
#
# Allowed without a sha: local actions (`uses: ./...`) and `docker://` refs
# with an `@sha256:` digest. Every other ref must be 40 hex characters.
#
# install-action installs `tool:` entries at their latest release unless one
# is versioned, so `tool: cargo-nextest` floats as much as `@v2` would. Each
# entry must be `name@X.Y.Z`.
#
# Usage: scripts/ci/check-action-pins.sh [file...]
#   (default: .github/workflows/*.yml|*.yaml and .github/actions/**/action.yml)
# Exit: 0 clean, 1 an unpinned ref or tool, 2 no file to check.
# =============================================================================
set -euo pipefail

cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

files=("$@")
if [[ ${#files[@]} -eq 0 ]]; then
  while IFS= read -r f; do files+=("$f"); done < <(
    find .github/workflows -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null
    find .github/actions -type f \( -name 'action.yml' -o -name 'action.yaml' \) 2>/dev/null
  )
fi
if [[ ${#files[@]} -eq 0 ]]; then
  echo "check-action-pins: no workflow or action files found" >&2
  exit 2
fi

problems=0
for f in "${files[@]}"; do
  in_install=0
  lineno=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    lineno=$((lineno + 1))
    # Drop a trailing comment (the `# vX.Y.Z` that goes with a sha).
    code="${line%%#*}"
    # Block style (`- uses: x@ref`, `uses: x@ref`) and flow style
    # (`- {uses: x@ref, with: ...}`).
    if [[ "$code" =~ ^[[:space:]]*(-[[:space:]]+)?(\{([^}]*[,[:space:]])?)?uses:[[:space:]]*[\"\']?([^\"\',}[:space:]]+) ]]; then
      ref="${BASH_REMATCH[4]}"
      in_install=0
      [[ "$ref" == taiki-e/install-action@* ]] && in_install=1
      case "$ref" in
        ./*) continue ;;
        docker://*@sha256:*) continue ;;
        docker://*)
          echo "$f:$lineno: $ref: a docker:// action needs an @sha256: digest"
          problems=$((problems + 1)); continue ;;
      esac
      if ! [[ "$ref" =~ @[0-9a-f]{40}$ ]]; then
        echo "$f:$lineno: $ref: pin it to a full commit sha (keep the version as a trailing comment)"
        problems=$((problems + 1))
      fi
      continue
    fi
    # A new step or job ends the install-action step.
    if [[ "$code" =~ ^[[:space:]]*-[[:space:]] ]]; then
      in_install=0
    fi
    if [[ "$in_install" -eq 1 && "$code" =~ ^[[:space:]]*tool:[[:space:]]*(.*)$ ]]; then
      tools="${BASH_REMATCH[1]//[\"\' ]/}"
      IFS=',' read -r -a list <<<"$tools"
      for t in "${list[@]}"; do
        [[ -z "$t" ]] && continue
        if ! [[ "$t" =~ ^[A-Za-z0-9_-]+@[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
          echo "$f:$lineno: install-action tool '$t': give it an exact version (name@X.Y.Z)"
          problems=$((problems + 1))
        fi
      done
    fi
  done <"$f"
done

if [[ "$problems" -gt 0 ]]; then
  echo "check-action-pins: ${problems} unpinned ref(s) or tool(s)" >&2
  exit 1
fi
echo "OK: every action ref is a commit sha and every install-action tool is versioned (${#files[@]} files)"
