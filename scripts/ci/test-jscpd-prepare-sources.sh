#!/usr/bin/env bash
# Self-test for jscpd-prepare-sources.py (#3495).
#
# The script decides what the duplication gate is allowed to see, so a bug in
# it silently changes the gate's verdict. The dangerous direction is
# over-removal: an INDENTED `#[cfg(test)]` sits inside another item, and
# treating it as a top-level boundary would delete every production line
# between it and the end of the enclosing item -- which the gate would then
# report as a clean measurement. Each case below builds a throwaway source
# file and asserts exactly which lines survive.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/jscpd-prepare-sources.py"

pass=0
fail=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# <label> <src-file> <expected-stripped-file>
check_strip() {
  local label="$1" src="$2" expected="$3"
  local out="$tmp/out.$RANDOM"
  ( cd "$(dirname "$src")" && python3 "$SCRIPT" "$out" "$out.map.json" "$(basename "$src")" >/dev/null )
  local got
  got="$out/$(basename "$src")"
  if diff -u "$expected" "$got" >"$tmp/diff" 2>&1; then
    echo "  ok   $label"
    pass=$((pass + 1))
  else
    echo "  FAIL $label"
    sed 's/^/       | /' "$tmp/diff"
    fail=$((fail + 1))
  fi
}

check_map() { # <label> <src-file> <expected-json>
  local label="$1" src="$2" expected="$3"
  local out="$tmp/out.$RANDOM"
  ( cd "$(dirname "$src")" && python3 "$SCRIPT" "$out" "$out.map.json" "$(basename "$src")" >/dev/null )
  local got
  got="$(python3 -c "
import json, sys
m = json.load(open(sys.argv[1]))
print(json.dumps(list(m.values())[0]))
" "$out.map.json")"
  if [ "$got" = "$expected" ]; then
    echo "  ok   $label"
    pass=$((pass + 1))
  else
    echo "  FAIL $label: expected line map $expected, got $got"
    fail=$((fail + 1))
  fi
}

echo "jscpd-prepare-sources self-test"

# ---------------------------------------------------------------------------
# 1. The ordinary shape: a trailing `#[cfg(test)] mod tests`.
# ---------------------------------------------------------------------------
mkdir -p "$tmp/c1"
cat >"$tmp/c1/a.rs" <<'EOF'
pub fn keep_me() -> u8 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t() {
        assert_eq!(keep_me(), 1);
    }
}
EOF
# The blank line that preceded the removed module survives, so the copy ends
# with one blank line and no trailing newline of its own.
printf 'pub fn keep_me() -> u8 {\n    1\n}\n\n' > "$tmp/c1/a.exp"
check_strip "trailing #[cfg(test)] mod is removed" "$tmp/c1/a.rs" "$tmp/c1/a.exp"
check_map "the removed range is recorded" "$tmp/c1/a.rs" "[[5, 13]]"

# ---------------------------------------------------------------------------
# 2. No test module at all: the copy must be unchanged.
# ---------------------------------------------------------------------------
mkdir -p "$tmp/c2"
printf 'pub fn a() -> u8 {\n    1\n}\n' >"$tmp/c2/a.rs"
cp "$tmp/c2/a.rs" "$tmp/c2/a.exp"
check_strip "a file with no test module is copied verbatim" "$tmp/c2/a.rs" "$tmp/c2/a.exp"
check_map "and records no removed range" "$tmp/c2/a.rs" "[]"

# ---------------------------------------------------------------------------
# 3. THE DANGEROUS ONE: an INDENTED #[cfg(test)] is not a top-level boundary.
#    Treating it as one deletes every production line up to the enclosing
#    item's closing brace -- and the gate would call the result a clean read.
# ---------------------------------------------------------------------------
mkdir -p "$tmp/c3"
cat >"$tmp/c3/a.rs" <<'EOF'
pub struct S {
    pub real_field: u8,
    #[cfg(test)]
    pub test_only_field: u8,
}

pub fn production_after_the_struct() -> u8 {
    42
}
EOF
cp "$tmp/c3/a.rs" "$tmp/c3/a.exp"
check_strip "an indented #[cfg(test)] removes nothing" "$tmp/c3/a.rs" "$tmp/c3/a.exp"
check_map "and records no removed range" "$tmp/c3/a.rs" "[]"

# ---------------------------------------------------------------------------
# 4. An attribute that introduces no braced item is left alone.
# ---------------------------------------------------------------------------
mkdir -p "$tmp/c4"
cat >"$tmp/c4/a.rs" <<'EOF'
#[cfg(test)]
use std::collections::HashMap;

pub fn a() -> u8 {
    1
}
EOF
cp "$tmp/c4/a.rs" "$tmp/c4/a.exp"
check_strip "#[cfg(test)] use ...; is left alone" "$tmp/c4/a.rs" "$tmp/c4/a.exp"

# ---------------------------------------------------------------------------
# 5. `#[cfg(all(test, ...))]` counts, and so does a mid-file module: the
#    production code that FOLLOWS it must survive, and the line map must be
#    able to translate a post-module line back to the original file.
# ---------------------------------------------------------------------------
mkdir -p "$tmp/c5"
cat >"$tmp/c5/a.rs" <<'EOF'
pub fn before() -> u8 {
    1
}

#[cfg(all(test, feature = "extra"))]
mod helpers {
    pub fn h() {}
}

pub fn after() -> u8 {
    2
}
EOF
# Both blank lines around the removed module survive, so two remain.
cat >"$tmp/c5/a.exp" <<'EOF'
pub fn before() -> u8 {
    1
}


pub fn after() -> u8 {
    2
}
EOF
check_strip "a mid-file #[cfg(all(test, ...))] module is removed, later code kept" \
  "$tmp/c5/a.rs" "$tmp/c5/a.exp"
check_map "the mid-file range is recorded for line translation" "$tmp/c5/a.rs" "[[5, 8]]"

# Translating a stripped line back through that map must land on the original.
translated="$(python3 -c "
line_map = [[5, 8]]
def original(line):
    shift = 0
    for start, end in line_map:
        if start <= line + shift:
            shift += end - start + 1
    return line + shift
print(original(5))
")"
if [ "$translated" = "9" ]; then
  echo "  ok   stripped line 5 translates back to original line 9"
  pass=$((pass + 1))
else
  echo "  FAIL line translation: expected 9, got $translated"
  fail=$((fail + 1))
fi

# ---------------------------------------------------------------------------
# 6. Several test modules in one file are all removed.
# ---------------------------------------------------------------------------
mkdir -p "$tmp/c6"
cat >"$tmp/c6/a.rs" <<'EOF'
#[cfg(test)]
mod one {
    fn x() {}
}

pub fn keep() -> u8 {
    1
}

#[cfg(test)]
mod two {
    fn y() {}
}
EOF
cat >"$tmp/c6/a.exp" <<'EOF'

pub fn keep() -> u8 {
    1
}

EOF
check_strip "every top-level test module is removed" "$tmp/c6/a.rs" "$tmp/c6/a.exp"
check_map "both ranges are recorded" "$tmp/c6/a.rs" "[[1, 4], [10, 13]]"

# ---------------------------------------------------------------------------
# 7. Usage error rather than a silent no-op.
# ---------------------------------------------------------------------------
status=0
python3 "$SCRIPT" >/dev/null 2>&1 || status=$?
if [ "$status" -eq 2 ]; then
  echo "  ok   missing arguments is a usage error (exit 2)"
  pass=$((pass + 1))
else
  echo "  FAIL missing arguments: expected exit 2, got $status"
  fail=$((fail + 1))
fi

echo
echo "passed: $pass   failed: $fail"
[ "$fail" -eq 0 ]
