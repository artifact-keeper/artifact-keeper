#!/usr/bin/env bash
#
# The exemption set the two release gates SHARE (#3829). Sourced, never run.
#
# Two gates decide whether a commit on a release line is acceptable, and they
# used to exempt different things:
#
#   * release preflight check 5 (scripts/ci/release-preflight.sh) asks "is
#     this commit described by the pending CHANGELOG section?" and exempted
#     dependency bumps, `chore(release):` and `docs(changelog):` SUBJECTS,
#     with no constraint on what the commit touched;
#   * the release-branch gate (scripts/ci/check-release-branch-commits.sh,
#     path C) asks "did this commit come from main?" and exempted only a
#     `chore(release):` subject whose changed paths were all version /
#     changelog / release-notes files.
#
# So a CHANGELOG-only commit written `docs(changelog): ...` satisfied the
# preflight and was refused by the branch gate -- with a message about
# cherry-picks that never named the rule it actually failed. That cost two
# round trips on the 1.9.1 cut. This file is the one definition both gates
# call, so the two answers cannot drift apart again.
#
# THE UNION, and why each member is safe in BOTH gates. Every rule is a
# SUBJECT **and** a PATH SET, never a subject alone: a subject is free text,
# and an exemption keyed on it alone lets any content ride in under a chosen
# title -- which is why the branch gate's path C was narrow in both dimensions
# from the start, and why the preflight's subject-only list is tightened here
# rather than copied across.
#
#   prep       `chore(release): ...` touching only the version / changelog /
#              release-notes set. The version being prepared exists only on
#              the maintenance branch, so there is nothing on main to trace to
#              and nothing a CHANGELOG entry could usefully add.
#   changelog  `docs(changelog): ...` touching only CHANGELOG.md and
#              .github/release-notes/**. Such a commit cannot describe itself:
#              demanding an entry for it produces another commit of exactly
#              the same shape, and so on (#3624 blocked the 1.8.2 cut that
#              way). Its whole content IS the bookkeeping.
#   bump       `chore(...)!: bump ...` touching only dependency manifests,
#              lockfiles, the CI paths and the changelog set. A bump that also
#              edits shipped source is not a bump and is exempt from neither
#              gate: it changes bytes a user receives, so it owes a CHANGELOG
#              entry and a trip through main like anything else.
#
#              The changelog set is in `bump` because of #4070. A RUSTSEC bump
#              on a maintenance line IS user-visible, so it is written up in
#              the pending `## [X.Y.Z]` section -- in the same commit, which is
#              where it belongs. The 1.7.x rustls/wasmtime bump (PR #3893) did
#              exactly that and the branch gate refused it, because CHANGELOG.md
#              sat outside the bump set; the label was what carried it through.
#              Splitting the entry into a second `docs(changelog):` commit is
#              ceremony, not a control: that commit is exempt on its own, so the
#              union admits no byte class either rule did not already admit.
#   ci         ANY subject, touching only CI/workflow paths. `git cherry-pick
#              -x` of a tooling forward-port keeps its `feat(ci): ...` subject,
#              so check 5 demanded a CHANGELOG entry the change did not
#              deserve; nothing in this set ships to a user.
#
# A commit that changes NOTHING is never exempt -- there is nothing to exempt.
#
# Usage:
#   source "$(dirname "$0")/release-commit-exemptions.sh"
#   rc=0; release_commit_exemption "$sha" "$subject" || rc=$?
#   case "$rc" in
#     0) echo "exempt: ${RELEASE_EXEMPTION_LABEL}" ;;
#     1) echo "not exempt: ${RELEASE_EXEMPTION_DETAIL}" ;;
#     2) echo "INFRA: ${RELEASE_EXEMPTION_DETAIL}" >&2 ;;
#   esac
#
# The answer comes back in globals rather than on stdout ON PURPOSE: a caller
# that wrote `reason="$(release_commit_exemption ...)"` would run the whole
# thing in a subshell and silently lose $RELEASE_EXEMPTION_DETAIL -- which is
# exactly the half a gate needs to name the rule the commit failed.
#
# Exit status: 0 exempt, 1 not exempt, 2 the commit could not be read (the
# caller must treat that as infra, never as a pass).

# Set by release_commit_exemption on every call, and read by the sourcing
# gate -- which shellcheck cannot see from here.
# shellcheck disable=SC2034
RELEASE_EXEMPTION_RULE=""    # the rule whose subject matched, or empty
RELEASE_EXEMPTION_LABEL=""   # human name of the rule that exempted it
RELEASE_EXEMPTION_DETAIL=""  # why it is NOT exempt, in prose

# The path sets, rendered for a failure message.
release_exemption_path_set() { # <rule>
  case "$1" in
    prep)      printf 'Cargo.toml, Cargo.lock, **/openapi.rs, CHANGELOG.md, .github/release-notes/** and docker/*/VERSION' ;;
    changelog) printf 'CHANGELOG.md and .github/release-notes/**' ;;
    bump)      printf 'dependency manifests and lockfiles (Cargo.toml, Cargo.lock, package.json, package-lock.json, yarn.lock), the CI paths and the changelog set (CHANGELOG.md, .github/release-notes/**)' ;;
    ci)        printf '.github/workflows/**, .github/actions/**, .github/scripts/** and scripts/ci/**' ;;
    *)         printf 'no known path set' ;;
  esac
}

# The whole set, for a gate's remedy block. Indented two spaces.
release_exemption_rules_text() {
  cat <<TXT
  - a release prep: subject \`chore(release): ...\` touching only
    $(release_exemption_path_set prep);
  - a changelog-only commit: subject \`docs(changelog): ...\` touching only
    $(release_exemption_path_set changelog);
  - a dependency bump: subject \`chore...: bump ...\` touching only
    $(release_exemption_path_set bump);
  - a CI/workflow-only commit, whatever its subject: every changed path in
    $(release_exemption_path_set ci).
TXT
}

# True when <path> belongs to <rule>'s path set. Bash `case` globs, so `*`
# also spans `/`; that is deliberate -- each pattern is anchored on a concrete
# filename or directory that carries no shipped source.
_release_path_in_set() { # <rule> <path>
  local rule="$1" p="$2"
  # The CI paths are their own rule AND part of `bump` (an action-pin bump).
  if [[ "$rule" == "ci" || "$rule" == "bump" ]]; then
    case "$p" in
      .github/workflows/* | .github/actions/* | .github/scripts/* | scripts/ci/*) return 0 ;;
    esac
  fi
  case "$rule" in
    prep)
      case "$p" in
        Cargo.toml | Cargo.lock) return 0 ;;
        openapi.rs | */openapi.rs) return 0 ;; # **/openapi.rs
        CHANGELOG.md) return 0 ;;
        .github/release-notes/*) return 0 ;;
        docker/*/VERSION) return 0 ;;
      esac
      ;;
    changelog)
      case "$p" in
        CHANGELOG.md) return 0 ;;
        .github/release-notes/*) return 0 ;;
      esac
      ;;
    bump)
      case "$p" in
        Cargo.toml | Cargo.lock | */Cargo.toml | */Cargo.lock) return 0 ;;
        package.json | */package.json) return 0 ;;
        package-lock.json | */package-lock.json) return 0 ;;
        yarn.lock | */yarn.lock) return 0 ;;
        # The bump's own write-up, in the commit that makes the change (#4070).
        CHANGELOG.md) return 0 ;;
        .github/release-notes/*) return 0 ;;
      esac
      ;;
  esac
  return 1
}

# Echoes the FIRST changed path that is outside <rule>'s set and returns 0;
# returns 1 (and echoes nothing) when every path is inside it. The inverted
# sense is deliberate: the caller wants the offending path for its message.
_release_first_path_outside() { # <rule> <path>...
  local rule="$1" f
  shift
  for f in "$@"; do
    [[ -n "$f" ]] || continue
    if ! _release_path_in_set "$rule" "$f"; then
      printf '%s' "$f"
      return 0
    fi
  done
  return 1
}

# The gate-facing predicate. See the header for the contract.
release_commit_exemption() { # <sha> [subject]
  local sha="$1" subject="${2-}" rule="" label="" list outside
  local files=()
  RELEASE_EXEMPTION_RULE=""
  RELEASE_EXEMPTION_LABEL=""
  RELEASE_EXEMPTION_DETAIL=""

  if [[ -z "$subject" ]]; then
    if ! subject="$(git log -1 --format='%s' "$sha" 2> /dev/null)"; then
      RELEASE_EXEMPTION_DETAIL="the subject of ${sha} could not be read"
      return 2
    fi
  fi

  # -r (recurse into trees) and no -M: a rename is reported as its two paths
  # rather than one, so BOTH ends are checked against the allowlist. The
  # 1.7.6 prep renames .github/release-notes/1.7.5.md -> 1.7.6.md.
  if ! list="$(git diff-tree --no-commit-id --name-only -r "$sha" 2> /dev/null)"; then
    RELEASE_EXEMPTION_DETAIL="the changed paths of ${sha} could not be read"
    return 2
  fi
  mapfile -t files <<< "$list"
  # A single empty line from an empty diff becomes one empty element.
  if [[ ${#files[@]} -eq 1 && -z "${files[0]}" ]]; then
    files=()
  fi

  if [[ "$subject" =~ ^chore(\([^\)]*\))?!?:[[:space:]]+bump[[:space:]] ]]; then
    rule="bump"
    label="dependency bump"
  elif [[ "$subject" =~ ^chore\(release\)!?:[[:space:]] ]]; then
    rule="prep"
    label="release prep"
  elif [[ "$subject" =~ ^docs\(changelog\)!?:[[:space:]] ]]; then
    rule="changelog"
    label="changelog-only commit"
  fi

  if [[ -n "$rule" ]]; then
    RELEASE_EXEMPTION_RULE="$rule"
    if [[ ${#files[@]} -eq 0 ]]; then
      RELEASE_EXEMPTION_DETAIL="its subject reads as a ${label}, but it changes no files at all, and a commit with no content has nothing to exempt"
      return 1
    fi
    if outside="$(_release_first_path_outside "$rule" "${files[@]}")"; then
      RELEASE_EXEMPTION_DETAIL="its subject reads as a ${label}, but it touches ${outside}, which is outside the ${label} path set ($(release_exemption_path_set "$rule"))"
      return 1
    fi
    RELEASE_EXEMPTION_LABEL="$label"
    return 0
  fi

  # The CI rule carries no subject condition: a forward-ported workflow change
  # keeps whatever subject the commit it was picked from had.
  if [[ ${#files[@]} -gt 0 ]]; then
    if ! outside="$(_release_first_path_outside ci "${files[@]}")"; then
      RELEASE_EXEMPTION_LABEL="CI/workflow-only commit"
      return 0
    fi
  else
    outside="<nothing>"
  fi
  RELEASE_EXEMPTION_DETAIL="its subject is none of \`chore(release):\`, \`docs(changelog):\` or a dependency bump, and it touches ${outside}, which is outside the CI/workflow path set ($(release_exemption_path_set ci))"
  return 1
}
