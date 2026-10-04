#!/usr/bin/env bash
# Backticks in the expected Markdown are literal, and sed-indenting a diff is clearer than ${var//}.
# shellcheck disable=SC2016,SC2001
# Self-test for jscpd-repo-report.py (#1619), the whole-repo duplication scan.
#
# The scan is only worth its red run if it measures what the per-PR gate
# measures and reports a regression exactly when there is one. The cases
# below pin: which files are in scope (the .jscpd.json ignore globs), the
# baseline verdict in both directions, that an unanalysed source or a
# missing report is "not a measurement" rather than a clean 0%, and that
# clone line numbers are translated back through stripped test modules.
# Throwaway files, pure python, ~1s.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/jscpd-repo-report.py"

pass=0
fail=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

ok() { echo "  ok   $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL $1"; fail=$((fail + 1)); }

echo "jscpd-repo-report self-test"

# ---------------------------------------------------------------------------
# 1. list-sources applies the .jscpd.json ignore globs.
# ---------------------------------------------------------------------------
mkdir -p "$tmp/tree/backend/src/api/handlers" "$tmp/tree/backend/src/services/tests" "$tmp/tree/backend/src/storage"
for f in api/handlers/npm.rs api/handlers/admin.rs services/x.rs services/x_test.rs \
         services/tests/helpers.rs storage/s3.rs storage/README.md; do
  echo "// $f" > "$tmp/tree/backend/src/$f"
done
cat > "$tmp/tree/.jscpd.json" <<'JSON'
{"ignore": ["**/node_modules/**", "**/*_test.rs", "**/tests/**", "backend/src/api/handlers/npm.rs"]}
JSON
got="$(cd "$tmp/tree" && python3 "$SCRIPT" list-sources .jscpd.json backend/src | tr '\n' ' ')"
want="backend/src/api/handlers/admin.rs backend/src/services/x.rs backend/src/storage/s3.rs "
if [ "$got" = "$want" ]; then
  ok "list-sources keeps admin.rs/x.rs/s3.rs, drops npm.rs, *_test.rs, tests/, non-.rs"
else
  bad "list-sources: expected '$want', got '$got'"
fi

# ---------------------------------------------------------------------------
# summarize fixtures
# ---------------------------------------------------------------------------
write_report() { # <file> <percentage> <sources...>
  local file="$1" pct="$2"; shift 2
  python3 - "$file" "$pct" "$@" <<'PY'
import json, sys
path, pct, names = sys.argv[1], float(sys.argv[2]), sys.argv[3:]
dup = {
    "firstFile": {"name": "a.rs", "startLoc": {"line": 5}, "endLoc": {"line": 16}},
    "secondFile": {"name": "b.rs", "startLoc": {"line": 1}, "endLoc": {"line": 12}},
}
json.dump({
    "statistics": {
        "total": {"percentage": pct, "duplicatedLines": 12, "lines": 1000, "sources": len(names)},
        "formats": {"rust": {"sources": {n: {"duplicatedLines": 12, "percentage": 1.2} for n in names}}},
    },
    "duplicates": [dup],
}, open(path, "w"))
PY
}
printf 'a.rs\nb.rs\n' > "$tmp/sources.txt"
# a.rs had lines 3-6 (a test module) stripped: stripped line 5 is original 9.
echo '{"a.rs": [[3, 6]], "b.rs": []}' > "$tmp/linemap.json"
echo '{"percentage": 2.0, "tolerance": 0.1}' > "$tmp/baseline.json"

run_summarize() { # <report> -> sets rc, out
  rc=0
  out="$(python3 "$SCRIPT" summarize "$1" "$tmp/linemap.json" "$tmp/sources.txt" "$tmp/baseline.json" 2>&1)" || rc=$?
}

# 2. At/below baseline + tolerance: pass.
write_report "$tmp/r-ok.json" 2.05 a.rs b.rs
run_summarize "$tmp/r-ok.json"
if [ "$rc" -eq 0 ] && grep -q '2.05%' <<<"$out" && ! grep -q REGRESSION <<<"$out"; then
  ok "2.05% against 2.00 + 0.10 passes"
else
  bad "2.05% against 2.00 + 0.10: rc=$rc"; echo "$out" | sed 's/^/       | /'
fi

# 3. Above baseline + tolerance: regression, exit 1.
write_report "$tmp/r-reg.json" 2.11 a.rs b.rs
run_summarize "$tmp/r-reg.json"
if [ "$rc" -eq 1 ] && grep -q REGRESSION <<<"$out"; then
  ok "2.11% against 2.00 + 0.10 is a regression (exit 1)"
else
  bad "2.11% against 2.00 + 0.10: expected exit 1 + REGRESSION, got rc=$rc"
fi

# 4. Clearly below baseline: pass, and say the baseline can come down.
write_report "$tmp/r-down.json" 1.5 a.rs b.rs
run_summarize "$tmp/r-down.json"
if [ "$rc" -eq 0 ] && grep -q 'lower' <<<"$out"; then
  ok "1.50% passes and suggests lowering the baseline"
else
  bad "1.50%: expected exit 0 + lower-the-baseline note, got rc=$rc"
fi

# 5. A source missing from the report is not a measurement (exit 2), even at 0%.
write_report "$tmp/r-missing.json" 0 a.rs
run_summarize "$tmp/r-missing.json"
if [ "$rc" -eq 2 ] && grep -q 'NOT A MEASUREMENT' <<<"$out" && grep -q '`b.rs`' <<<"$out"; then
  ok "a source jscpd skipped makes the run exit 2 and names it"
else
  bad "missing source: expected exit 2 naming b.rs, got rc=$rc"
fi

# 6. No report at all is not a measurement either.
run_summarize "$tmp/does-not-exist.json"
if [ "$rc" -eq 2 ] && grep -q 'NOT A MEASUREMENT' <<<"$out"; then
  ok "no jscpd report at all exits 2"
else
  bad "no report: expected exit 2, got rc=$rc"
fi

# 7. Clone lines are translated back through the stripped test module.
run_summarize "$tmp/r-ok.json"
if grep -q '`a.rs:9-20`' <<<"$out" && grep -q '`b.rs:1-12`' <<<"$out"; then
  ok "clone a.rs:5-16 (stripped) is reported as a.rs:9-20 (original)"
else
  bad "line translation: expected a.rs:9-20 and b.rs:1-12 in:"; echo "$out" | sed 's/^/       | /'
fi

echo ""
echo "jscpd-repo-report: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
