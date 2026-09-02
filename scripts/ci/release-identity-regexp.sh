#!/usr/bin/env bash
#
# Print the pinned Fulcio certificate-identity regexp that a release signature
# must match (issue #3558).
#
# The Subject Alternative Name Fulcio puts on a certificate minted for a job
# running directly in a workflow is
#
#     https://github.com/<owner>/<repo>/.github/workflows/<file>@<ref>
#
# and `cosign verify-blob --certificate-identity-regexp` matches a Go RE2
# pattern against it. So the pattern has to be built, not written by hand, and
# the building is the part that goes wrong.
#
# WHY THIS IS A SCRIPT AND NOT THREE LINES IN release.yml
# -------------------------------------------------------
# It was three lines in release.yml, and they were wrong. The escaper was
#
#     sed 's/[.^$*+?()[\]{}|\\]/\\&/g'
#
# which reads as "escape any regex metacharacter" and is in fact a no-op:
# `\` is not special inside a POSIX bracket expression, so the `]` after it
# CLOSES the class, and the rest (`{}|\]`) becomes literal text that must
# follow the matched character. Nothing in a version tag ever matches that, so
# `v1.8.2` came out as `v1.8.2` -- unescaped -- and every `.` in the pinned
# identity was a wildcard.
#
# That is not a dramatic hole (Fulcio only ever issues SANs that really are
# github.com URLs, so there is no certificate whose identity is
# `...releaseXyml@refs/tags/v1X8X2`), but it is precisely the failure this whole
# change exists to prevent: a pin that reads as strict, passes every check
# around it, and is not doing the thing its name says. It was invisible because
# nothing ever asserted on the pattern's TEXT.
#
# So: one function, one place, and a self-test that feeds it the metacharacters
# (`scripts/ci/test-verify-release-assets.sh`, "identity pattern construction").
#
# Escaping is by ALLOWLIST rather than by blocklist, for the same reason the
# original went wrong: a blocklist is only as good as its author's memory of
# the metacharacter set, and a forgotten entry fails open and silently. Every
# character that is not unambiguously inert is backslash-escaped; in Go RE2 a
# backslash before any non-alphanumeric ASCII character is that character as a
# literal, so over-escaping is free and under-escaping is not.
#
# Usage:
#   release-identity-regexp.sh <owner/repo> <workflow-file> <ref>
#
#   $ release-identity-regexp.sh artifact-keeper/artifact-keeper release.yml refs/tags/v1.8.2
#   ^https://github\.com/artifact-keeper/artifact-keeper/\.github/workflows/release\.yml@refs/tags/v1\.8\.2$
#
set -euo pipefail

# Backslash-escape every character outside a small, provably-inert allowlist.
re_escape() {
  local s="$1" out="" c i
  for (( i = 0; i < ${#s}; i++ )); do
    c="${s:i:1}"
    case "$c" in
      [A-Za-z0-9_/:@-]) out+="$c" ;;
      *)                out+="\\$c" ;;
    esac
  done
  printf '%s' "$out"
}

if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
  # Sourced: the caller wants `re_escape` and will build its own string.
  return 0
fi

if [[ $# -ne 3 ]]; then
  echo "usage: $(basename "$0") <owner/repo> <workflow-file> <ref>" >&2
  echo "  e.g. $(basename "$0") artifact-keeper/artifact-keeper release.yml refs/tags/v1.8.2" >&2
  exit 2
fi

REPO="$1"
WORKFLOW="$2"
REF="$3"

[[ -n "$REPO"     ]] || { echo "owner/repo is empty" >&2; exit 2; }
[[ -n "$WORKFLOW" ]] || { echo "workflow file is empty" >&2; exit 2; }
[[ -n "$REF"      ]] || { echo "ref is empty" >&2; exit 2; }

# Anchored at BOTH ends. An unanchored pattern matches any identity that merely
# CONTAINS this one, which an attacker-controlled repository path can arrange.
printf '^https://github\\.com/%s/\\.github/workflows/%s@%s$\n' \
  "$(re_escape "$REPO")" \
  "$(re_escape "$WORKFLOW")" \
  "$(re_escape "$REF")"
