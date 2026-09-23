#!/usr/bin/env bash
# Self-test for scripts/ci/coverage-gate.py.
#
# The script decides which instrumented lines are PRODUCTION code for the
# coverage floor and the new-code gate. Both directions matter: counting
# inline `#[cfg(test)]` code (almost always hit) inflates the numbers and
# lets untested production code through -- the bug this replaces -- and
# excluding production code would do the same by hiding it. A fixture
# lcov.info plus a fixture source tree / linemap pins exactly which lines
# count. Offline, ~1s.
#
# Usage: bash scripts/ci/test-coverage-gate.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/coverage-gate.py"
[ -f "$SCRIPT" ] || { echo "cannot find coverage-gate.py next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

# --- fixture source tree ------------------------------------------------------
# lib.rs: two production fns (lines 1-3 hit, 5-7 never run), an inline test
# module (9-15), an out-of-line test-only module (17-18 -> helpers.rs), and
# an INDENTED #[cfg(test)] field that must stay production (20-23).
SRC="$WORK/repo"
mkdir -p "$SRC/backend/src"
cat > "$SRC/backend/src/lib.rs" <<'EOF'
pub fn a() -> u8 {
    1
}

pub fn b() -> u8 {
    2
}

#[cfg(test)]
mod tests {
    #[test]
    fn t() {
        assert_eq!(super::a(), 1);
    }
}

#[cfg(test)]
mod helpers;

pub struct S {
    #[cfg(test)]
    pub probe: u8,
}
EOF
printf 'pub fn h() -> u8 {\n    3\n}\n' > "$SRC/backend/src/helpers.rs"

# Absolute SF paths, as the CI runner writes them.
LCOV="$WORK/lcov.info"
cat > "$LCOV" <<'EOF'
SF:/home/runner/_work/artifact-keeper/artifact-keeper/backend/src/lib.rs
DA:1,4
DA:2,4
DA:3,4
DA:5,0
DA:6,0
DA:7,0
DA:10,5
DA:12,5
DA:13,5
DA:14,5
DA:21,0
end_of_record
SF:/home/runner/_work/artifact-keeper/artifact-keeper/backend/src/helpers.rs
DA:1,3
DA:2,3
DA:3,3
end_of_record
EOF
# production: lib.rs 1,2,3 (hit) 5,6,7 (miss) 21 (miss) = 3/7 = 42.86%
# test code:  lib.rs 10,12,13,14 + helpers.rs 1,2,3 = 7 lines, all hit
# everything: 10/14 = 71.43% -- what the old floor measured

# run <label> <want-exit> <want-output-regex> <args...>
run() {
  local label="$1" want_rc="$2" want_re="$3"; shift 3
  local out rc=0
  out="$(python3 "$SCRIPT" "$@" 2>&1)" || rc=$?
  if [ "$rc" = "$want_rc" ] && grep -Eq -- "$want_re" <<<"$out"; then
    pass "$label"
  else
    fail "$label (wanted rc=$want_rc matching /$want_re/, got rc=$rc)"
    sed 's/^/        | /' <<<"$out" >&2
  fi
}
field() { python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$@"; }

echo "coverage-gate.py floor: production lines only"
run "production is 42.86% (3/7), test code excluded" 0 'production code 42\.86% \(3/7 lines\)' \
  floor --lcov "$LCOV" --root "$SRC" --min 40
run "7 test lines excluded, all lines together 71.43%" 0 'excluded: 7 lines.*all lines together 71\.43%' \
  floor --lcov "$LCOV" --root "$SRC" --min 40
run "a 60% floor FAILS although all-lines coverage is 71%" 1 'FAILED -- production code 42\.86%' \
  floor --lcov "$LCOV" --root "$SRC" --min 60

GH_OUT="$WORK/gh-output"; : > "$GH_OUT"
python3 "$SCRIPT" floor --lcov "$LCOV" --root "$SRC" --min 60 --github-output "$GH_OUT" \
  --json "$WORK/floor.json" --write-linemap "$WORK/linemap.json" >/dev/null
if grep -qx 'verdict=fail' "$GH_OUT" && grep -qx 'pct=42.86' "$GH_OUT"; then
  pass "step outputs verdict=fail pct=42.86"
else
  fail "step outputs: $(tr '\n' ' ' < "$GH_OUT")"
fi
[ "$(field "$WORK/floor.json" total)" = 7 ] && pass "verdict JSON counts 7 production lines" \
  || fail "verdict JSON total: $(field "$WORK/floor.json" total)"

# The linemap is the jscpd-prepare-sources.py shape plus "all" for a test-only file.
want_map='{"backend/src/helpers.rs": "all", "backend/src/lib.rs": [[9, 15]]}'
got_map="$(python3 -c "import json,sys; print(json.dumps(json.load(open(sys.argv[1])), sort_keys=True))" "$WORK/linemap.json")"
[ "$got_map" = "$want_map" ] && pass "linemap: inline module 9-15, helpers.rs whole file (indented cfg(test) kept)" \
  || fail "linemap: got $got_map, want $want_map"

# The same verdict from a fixture linemap with NO sources on disk.
mkdir -p "$WORK/empty"
printf '%s\n' "$want_map" > "$WORK/fixture-linemap.json"
run "a fixture linemap gives the same number without sources" 0 'production code 42\.86% \(3/7 lines\)' \
  floor --lcov "$LCOV" --root "$WORK/empty" --linemap "$WORK/fixture-linemap.json" --min 40

# A report with no production lines at all is a failure, not 100%.
printf 'SF:/x/backend/src/lib.rs\nDA:12,1\nend_of_record\nSF:/x/backend/src/helpers.rs\nDA:1,1\nend_of_record\n' > "$WORK/tests-only.info"
run "a report holding only test code fails" 1 'holds no production lines' \
  floor --lcov "$WORK/tests-only.info" --root "$SRC" --min 1

echo "coverage-gate.py newcode: production lines the PR adds"
# Adds b() (5-7, never run), the test module (9-15), helpers.rs, and deletes
# another file: the /dev/null hunk must not be attributed to lib.rs.
cat > "$WORK/diff-untested" <<'EOF'
diff --git a/backend/src/lib.rs b/backend/src/lib.rs
--- a/backend/src/lib.rs
+++ b/backend/src/lib.rs
@@ -4,0 +5,3 @@ pub fn a() -> u8 {
+pub fn b() -> u8 {
+    2
+}
@@ -5,0 +9,7 @@
+#[cfg(test)]
+mod tests {
+    #[test]
+    fn t() {
+        assert_eq!(super::a(), 1);
+    }
+}
diff --git a/backend/src/helpers.rs b/backend/src/helpers.rs
--- /dev/null
+++ b/backend/src/helpers.rs
@@ -0,0 +1,3 @@
+pub fn h() -> u8 {
+    3
+}
diff --git a/backend/src/gone.rs b/backend/src/gone.rs
--- a/backend/src/gone.rs
+++ /dev/null
@@ -1,2 +0,0 @@
-pub fn gone() {}
-
EOF
run "untested production + well-tested test code -> 0% of 3 lines, FAILS" 1 'FAILED -- 0% of new production lines \(0/3\)' \
  newcode --lcov "$LCOV" --root "$SRC" --diff-file "$WORK/diff-untested" --min 70 --min-lines 1
run "the lines added inside test code are reported, not counted" 1 'inside inline test code \(not counted\): 10\.' \
  newcode --lcov "$LCOV" --root "$SRC" --diff-file "$WORK/diff-untested" --min 70 --min-lines 1
run "the uncovered lines are listed as file: ranges" 1 'backend/src/lib\.rs: 5-7' \
  newcode --lcov "$LCOV" --root "$SRC" --diff-file "$WORK/diff-untested" --min 70 --min-lines 1
run "below --min-lines is N/A" 0 'N/A \(3 instrumented production line\(s\) added, fewer than 10' \
  newcode --lcov "$LCOV" --root "$SRC" --diff-file "$WORK/diff-untested" --min 70 --min-lines 10
run "the same diff via the fixture linemap" 1 '0% of new production lines \(0/3\)' \
  newcode --lcov "$LCOV" --root "$WORK/empty" --linemap "$WORK/fixture-linemap.json" \
  --diff-file "$WORK/diff-untested" --min 70 --min-lines 1

cat > "$WORK/diff-tested" <<'EOF'
diff --git a/backend/src/lib.rs b/backend/src/lib.rs
--- a/backend/src/lib.rs
+++ b/backend/src/lib.rs
@@ -0,0 +1,3 @@
+pub fn a() -> u8 {
+    1
+}
EOF
run "tested production lines pass at 100%" 0 'passed -- 100% of new production lines \(3/3\)' \
  newcode --lcov "$LCOV" --root "$SRC" --diff-file "$WORK/diff-tested" --min 70 --min-lines 1

printf 'diff --git a/README.md b/README.md\n' > "$WORK/diff-none"
run "no Rust lines added is N/A" 0 'N/A \(no Rust lines added\)' \
  newcode --lcov "$LCOV" --root "$SRC" --diff-file "$WORK/diff-none" --min 70

# The git path: --merge-base diffs the working tree against that commit.
G="$WORK/git"
cp -r "$SRC" "$G"
(
  cd "$G" || exit 1
  git init -q . && git config user.email t@t && git config user.name t
  sed -n '1,4p' backend/src/lib.rs > backend/src/lib.rs.base
  mv backend/src/lib.rs backend/src/lib.rs.full
  mv backend/src/lib.rs.base backend/src/lib.rs
  git add backend/src/lib.rs && git commit -qm base
  mv backend/src/lib.rs.full backend/src/lib.rs
) || fail "could not build the git fixture"
MB="$(git -C "$G" rev-parse HEAD)"
run "--merge-base: git diff finds b() untested, test code excluded" 1 '0% of new production lines \(0/4\)' \
  newcode --lcov "$LCOV" --root "$G" --merge-base "$MB" --min 70 --min-lines 1
run "--merge-base that does not exist is bad input (exit 2)" 2 'git diff against' \
  newcode --lcov "$LCOV" --root "$G" --merge-base 0000000000000000000000000000000000000000 --min 70

echo
if [ "$fails" -gt 0 ]; then
  echo "coverage-gate.py: $fails case(s) FAILED"
  exit 1
fi
echo "coverage-gate.py: all cases passed"
