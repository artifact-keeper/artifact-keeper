#!/usr/bin/env bash
# `cond && pass ... || fail ...` throughout: pass() only prints, so fail()
# runs exactly when the condition is false.
# shellcheck disable=SC2015
#
# Self-test for the CHANGELOG fragment assembler:
# scripts/ci/changelog-fragments.py (`assemble`, `render-fragments`) and its
# release-prep wrapper scripts/release/assemble-changelog.sh.
#
# Entries are one file per PR under changes/unreleased/ and are rendered into
# CHANGELOG.md only at the release prep. The prep is once per release, so a
# rendering bug would surface exactly once, in the notes of a shipped
# version. Every property the release relies on is pinned here instead:
#
#   - lossless: every fragment body lands in the section byte for byte,
#     multi-paragraph bodies included;
#   - deterministic: Keep a Changelog section order, entries by the number in
#     the file name then the name, identical bytes on a second run;
#   - the transition window: bullets still under `## [Unreleased]` are merged
#     (first within their section), and `### Sponsors` / `### Thank You` /
#     upgrade-note headings are carried through verbatim;
#   - the write: fragments deleted, `.gitkeep` kept, `## [Unreleased]` left
#     with only its pointer (so check-changelog-unreleased.sh still passes),
#     every released section byte-identical;
#   - refusals: an existing `## [X.Y.Z]` without --append (a Cargo.toml nobody
#     bumped names the version that already SHIPPED -- the #3433 shape, by
#     tool), --append once the tag exists, a prerelease version, nothing to
#     assemble, an invalid fragment -- each leaving the tree untouched.
#
# Usage: bash scripts/ci/test-changelog-fragments.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL="$HERE/changelog-fragments.py"
WRAPPER="$HERE/../release/assemble-changelog.sh"
GATE="$HERE/check-changelog-unreleased.sh"
for f in "$TOOL" "$WRAPPER" "$GATE"; do
  [ -f "$f" ] || {
    echo "cannot find $f" >&2
    exit 2
  }
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
n=0
d=""

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() {
  printf '  \033[31mFAIL\033[0m  %s\n' "$*"
  fails=$((fails + 1))
}

# A fresh tree in $d: CHANGELOG.md with the given [Unreleased] body (stdin)
# above one released section, and an empty changes/unreleased/ + .gitkeep.
tree() {
  n=$((n + 1))
  d="$WORK/t.$n"
  mkdir -p "$d/changes/unreleased"
  : > "$d/changes/unreleased/.gitkeep"
  {
    printf '# Changelog\n\nPreamble prose.\n\n## [Unreleased]\n'
    cat
    printf '\n## [1.9.0] - 2026-09-08\n\n### Fixed\n\n- **shipped in 1.9.0** (#900).\n\n### Upgrade note — prose\n\nA paragraph.\n'
  } > "$d/CHANGELOG.md"
}

frag() { # <name> <section> <issue> [lead]
  printf -- '---\nsection: %s\nissues: [#%s]\n---\n- **%s** (#%s). Body.\n' \
    "$2" "$3" "${4:-entry $3}" "$3" > "$d/changes/unreleased/$1"
}

asm() { # [extra args...] -- runs the tool against $d
  python3 "$TOOL" assemble "$@" --changelog "$d/CHANGELOG.md" --dir "$d/changes/unreleased"
}

echo "changelog fragment assembler"

# 1. Section order and entry order.
tree <<< ""
frag 4300-sec.md Security 4300
frag 100-late.md Fixed 100
frag 4-early.md Fixed 4
frag 30-mid-b.md Fixed 30
frag 30-mid-a.md Fixed 30
frag 4301-dep.md Deprecated 4301
frag 4302-add.md Added 4302
frag 4303-rem.md Removed 4303
frag 4304-chg.md Changed 4304
out="$(asm 1.10.0 --date 2026-09-23 --check 2> /dev/null)"
headings="$(printf '%s\n' "$out" | grep '^### ' | tr '\n' '|')"
if [ "$headings" = "### Added|### Changed|### Deprecated|### Removed|### Fixed|### Security|" ]; then
  pass "sections render in Keep a Changelog order"
else
  fail "section order: got '$headings'"
fi
fixed="$(printf '%s\n' "$out" | awk '/^### Fixed/{i=1;next} /^### /{i=0} i && /^- /' | grep -oE '#[0-9]+' | tr '\n' ' ')"
if [ "$fixed" = "#4 #30 #30 #100 " ]; then
  pass "entries order numerically by file-name number, not lexically"
else
  fail "entry order: got '$fixed'"
fi
printf '%s\n' "$out" | head -1 | grep -qxF '## [1.10.0] - 2026-09-23' \
  && pass "heading is '## [X.Y.Z] - <date>'" || fail "heading: $(printf '%s\n' "$out" | head -1)"

# 2. Same number, different slug: tie broken by file name, so the order does
#    not depend on directory listing order.
tree <<< ""
printf -- '---\nsection: Fixed\nissues: [#30]\n---\n- **B** (#30).\n' > "$d/changes/unreleased/30-b.md"
printf -- '---\nsection: Fixed\nissues: [#30]\n---\n- **A** (#30).\n' > "$d/changes/unreleased/30-a.md"
got="$(asm 1.10.0 --date 2026-09-23 --check 2> /dev/null | grep '^- ' | tr '\n' '|')"
[ "$got" = "- **A** (#30).|- **B** (#30).|" ] \
  && pass "equal numbers tie-break on file name" || fail "tie-break: got '$got'"

# 3. Lossless: a multi-paragraph body with odd spacing lands byte for byte.
tree <<< ""
cat > "$d/changes/unreleased/4145-multi.md" << 'EOF'
---
section: Fixed
issues: [#4145, #4129]
---
- **Eight concurrent requests no longer deadlock** (#4145, #4129). `code`, *emphasis*, a trailing  double space
  and a continuation line.

  **A second paragraph** — with an em dash, "quotes" and a list:

  - nested item one
  - nested item two
EOF
if python3 - "$d" "$TOOL" << 'PY'
import subprocess, sys
d, tool = sys.argv[1], sys.argv[2]
src = open(f"{d}/changes/unreleased/4145-multi.md", encoding="utf-8").read()
body = src.split("---\n", 2)[2].rstrip("\n")
out = subprocess.run(["python3", tool, "assemble", "1.10.0", "--date", "2026-09-23", "--check",
                      "--changelog", f"{d}/CHANGELOG.md", "--dir", f"{d}/changes/unreleased"],
                     capture_output=True, text=True).stdout
sys.exit(0 if body in out else 1)
PY
then
  pass "multi-paragraph body rendered byte for byte"
else
  fail "body not rendered verbatim"
fi

# 4. The transition window: legacy bullets under [Unreleased] merge with the
#    fragments, first in their section; recognition headings are carried.
tree << 'EOF'

### Sponsors

Thank you to our backers:
- **Someone** ([@someone](https://github.com/someone))

### Fixed

- **legacy bullet one** (#4100).
- **legacy bullet two** (#4101).

  With a continuation paragraph.

### Upgrade note — read before upgrading

Prose that must survive.
EOF
frag 4000-frag-fix.md Fixed 4000
frag 4001-frag-add.md Added 4001
out="$(asm 1.10.0 --date 2026-09-23 --check 2> /dev/null)"
headings="$(printf '%s\n' "$out" | grep '^### ' | tr '\n' '|')"
fixed="$(printf '%s\n' "$out" | awk '/^### Fixed/{i=1;next} /^### /{i=0} i && /^- /' | grep -oE '#[0-9]+' | tr '\n' ' ')"
if [ "$headings" = "### Sponsors|### Added|### Fixed|### Upgrade note — read before upgrading|" ] \
  && [ "$fixed" = "#4100 #4101 #4000 " ] \
  && printf '%s\n' "$out" | grep -qF 'Prose that must survive.' \
  && printf '%s\n' "$out" | grep -qF '  With a continuation paragraph.' \
  && printf '%s\n' "$out" | grep -qF -- '- **Someone** ([@someone](https://github.com/someone))'; then
  pass "legacy [Unreleased] bullets merged first; other headings carried verbatim"
else
  fail "transition merge: headings '$headings', Fixed order '$fixed'"
  printf '%s\n' "$out" | sed 's/^/        /' >&2
fi

# 5. The write itself, and determinism across two runs.
cp -r "$d" "$d.copy"
before_rest="$(sed -n '/^## \[1.9.0\]/,$p' "$d/CHANGELOG.md")"
if asm 1.10.0 --date 2026-09-23 2> /dev/null; then
  left="$(find "$d/changes/unreleased" -type f | sed "s|$d/||" | tr '\n' ' ')"
  unrel="$(awk '/^## \[/{i=($0=="## [Unreleased]");next} i && NF' "$d/CHANGELOG.md")"
  after_rest="$(sed -n '/^## \[1.9.0\]/,$p' "$d/CHANGELOG.md")"
  [ "$left" = "changes/unreleased/.gitkeep " ] \
    && pass "fragments deleted, .gitkeep kept" || fail "left behind: '$left'"
  case "$unrel" in
    "New entries go in "*"changes/unreleased/"*) [ "$(printf '%s\n' "$unrel" | wc -l)" = 1 ] \
      && pass "[Unreleased] holds only the pointer line" || fail "[Unreleased] holds: $unrel" ;;
    *) fail "[Unreleased] holds: $unrel" ;;
  esac
  [ "$before_rest" = "$after_rest" ] \
    && pass "released sections are byte-identical" || fail "released sections changed"
  head -4 "$d/CHANGELOG.md" | grep -qxF 'Preamble prose.' \
    && pass "file header preserved" || fail "file header lost"
  CHANGELOG_FILE="$d/CHANGELOG.md" bash "$GATE" > /dev/null 2>&1 \
    && pass "check-changelog-unreleased.sh passes on the written file" \
    || fail "check-changelog-unreleased.sh rejects the written file"
  python3 "$TOOL" assemble 1.10.0 --date 2026-09-23 \
    --changelog "$d.copy/CHANGELOG.md" --dir "$d.copy/changes/unreleased" 2> /dev/null
  cmp -s "$d/CHANGELOG.md" "$d.copy/CHANGELOG.md" \
    && pass "two runs over the same tree write the same bytes" || fail "output is not deterministic"
else
  fail "assemble refused a valid tree"
fi

# 6. REFUSED: the version already has a section. Without --append this is a
#    Cargo.toml nobody bumped naming the version that already shipped.
tree <<< ""
frag 4000-x.md Fixed 4000
cp "$d/CHANGELOG.md" "$d/before"
rc=0; asm 1.9.0 --date 2026-09-23 > /dev/null 2>&1 || rc=$?
[ "$rc" = 1 ] && cmp -s "$d/CHANGELOG.md" "$d/before" && [ -f "$d/changes/unreleased/4000-x.md" ] \
  && pass "existing '## [X.Y.Z]' without --append -> refused, tree untouched" \
  || fail "existing version without --append: rc=$rc"

# 7. --append folds late fragments into this cut's own section.
tree <<< ""
frag 4000-x.md Fixed 4000
asm 1.10.0 --date 2026-09-23 2> /dev/null
frag 4001-late.md Fixed 4001
frag 4002-late-add.md Added 4002
if asm 1.10.0 --date 2026-09-24 --append 2> /dev/null; then
  heads="$(grep -c '^## \[1.10.0\] - 2026-09-23' "$d/CHANGELOG.md")"
  fixed="$(awk '/^## \[1.10.0\]/{i=1;next} /^## /{i=0} i' "$d/CHANGELOG.md" | awk '/^### Fixed/{i=1;next} /^### /{i=0} i && /^- /' | grep -oE '#[0-9]+' | tr '\n' ' ')"
  [ "$heads" = 1 ] && [ "$fixed" = "#4000 #4001 " ] \
    && grep -qF '#4002' "$d/CHANGELOG.md" \
    && pass "--append merges into the existing section, keeping its heading and date" \
    || fail "--append: headings=$heads Fixed='$fixed'"
else
  fail "--append refused"
fi

# 8. --append when the section below [Unreleased] is some other version.
rc=0; asm 1.11.0 --date 2026-09-24 --append > /dev/null 2>&1 || rc=$?
[ "$rc" = 1 ] && pass "--append with no such section on top -> refused" || fail "--append mismatch: rc=$rc"

# 9. Nothing to assemble is an error, not an empty release section.
tree <<< ""
rc=0; asm 1.10.0 --date 2026-09-23 > /dev/null 2>&1 || rc=$?
[ "$rc" = 1 ] && pass "nothing to assemble -> refused" || fail "nothing to assemble: rc=$rc"

# 10. An invalid fragment blocks the whole write.
tree <<< ""
frag 4000-x.md Fixed 4000
frag 4001-y.md Bugfix 4001
cp "$d/CHANGELOG.md" "$d/before"
rc=0; asm 1.10.0 --date 2026-09-23 > /dev/null 2>&1 || rc=$?
[ "$rc" = 1 ] && cmp -s "$d/CHANGELOG.md" "$d/before" && [ -f "$d/changes/unreleased/4000-x.md" ] \
  && pass "invalid fragment -> refused, tree untouched" || fail "invalid fragment: rc=$rc"

# 11. --check changes nothing.
tree <<< ""
frag 4000-x.md Fixed 4000
cp "$d/CHANGELOG.md" "$d/before"
asm 1.10.0 --date 2026-09-23 --check > /dev/null 2>&1
cmp -s "$d/CHANGELOG.md" "$d/before" && [ -f "$d/changes/unreleased/4000-x.md" ] \
  && pass "--check leaves CHANGELOG.md and the fragments alone" || fail "--check modified the tree"

# 12. A prerelease has no CHANGELOG section (RELEASING.md).
rc=0; asm 1.10.0-rc.1 --date 2026-09-23 --check > /dev/null 2>&1 || rc=$?
[ "$rc" = 2 ] && pass "prerelease version -> usage error" || fail "prerelease: rc=$rc"

# 13. The wrapper: version from [workspace.package], --append refused once the
#     tag exists.
tree <<< ""
frag 4000-x.md Fixed 4000
mkdir -p "$d/scripts/ci" "$d/scripts/release"
cp "$TOOL" "$d/scripts/ci/"
cp "$WRAPPER" "$d/scripts/release/"
printf '[workspace]\nmembers = ["backend"]\n\n[workspace.package]\nversion = "1.10.0"\n\n[workspace.dependencies]\nfoo = { version = "9.9.9" }\n' > "$d/Cargo.toml"
got="$(bash "$d/scripts/release/assemble-changelog.sh" --check --date 2026-09-23 2> /dev/null | head -1)"
[ "$got" = "## [1.10.0] - 2026-09-23" ] \
  && pass "wrapper reads the version from [workspace.package]" || fail "wrapper version: '$got'"
git -C "$d" init -q . && git -C "$d" -c user.email=t@t -c user.name=t commit -q --allow-empty -m x \
  && git -C "$d" tag v1.9.0
rc=0; bash "$d/scripts/release/assemble-changelog.sh" --append 1.9.0 > /dev/null 2>&1 || rc=$?
[ "$rc" = 1 ] && pass "wrapper refuses --append for a tagged version" || fail "wrapper --append tagged: rc=$rc"

# 14. The live tree: every fragment on this branch renders.
if python3 "$TOOL" assemble 99.0.0 --date 2026-01-01 --check > /dev/null; then
  pass "the fragments on this tree assemble"
else
  fail "the fragments on this tree do not assemble"
fi

echo
if [ "$fails" -gt 0 ]; then
  echo "$fails case(s) failed"
  exit 1
fi
echo "all cases passed"
