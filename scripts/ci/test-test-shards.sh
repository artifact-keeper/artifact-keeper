#!/usr/bin/env bash
# Self-test for test-shards.py and merge-lcov.py (the sharded unit-test job).
#
# Both scripts decide what CI measures without any test of their own noticing
# a mistake. The dangerous directions are silent ones:
#
#   * test-shards.py: a test module left ungated runs in EVERY leg (counted
#     five times, coverage unaffected, nobody notices); one gated to a shard
#     the matrix does not run never runs at all. `check` must refuse both,
#     and `apply` must produce exactly what `check` accepts.
#   * merge-lcov.py: the floor and new-code gates read its output. A merge
#     that took the max instead of the sum, or dropped a file present in only
#     one shard, would still produce a plausible report.
#
# Everything runs on throwaway trees; no cargo, ~1s.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHARDS_PY="$HERE/test-shards.py"
MERGE_PY="$HERE/merge-lcov.py"

pass=0
fail=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

ok() { echo "  ok   $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL $1"; fail=$((fail + 1)); }

# A minimal repo: the manifests test-shards.py cross-checks, and a src tree.
mkrepo() { # <dir>
  local d="$1"
  mkdir -p "$d/backend/src/api/handlers" "$d/backend/src/services" "$d/.github/workflows"
  python3 - "$SHARDS_PY" "$d" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("ts", sys.argv[1])
ts = importlib.util.module_from_spec(spec); spec.loader.exec_module(ts)
d = sys.argv[2]
feats = "".join(f"test-shard-{s} = []\n" for s in ts.SHARDS)
open(f"{d}/backend/Cargo.toml", "w").write(f"[features]\n{feats}")
names = ", ".join(f'"{s}"' for s in ts.SHARDS)
open(f"{d}/backend/build.rs", "w").write(f"const TEST_SHARDS: &[&str] = &[{names}];\n")
main_shard = ts.shard_for("main.rs", "")
open(f"{d}/.github/workflows/ci.yml", "w").write(
    "jobs:\n  u:\n    strategy:\n      matrix:\n"
    f"        shard: [{', '.join(ts.SHARDS)}]\n    env:\n      BIN_SHARD: {main_shard}\n")
PY
  cat >"$d/backend/src/api/handlers/alpha.rs" <<'EOF'
pub fn alpha() {}

#[cfg(test)]
mod tests {
    #[test]
    fn a() {}

    #[cfg(test)]
    mod nested {
        #[test]
        fn inherits_the_outer_gate() {}
    }
}
EOF
  cat >"$d/backend/src/api/handlers/zulu.rs" <<'EOF'
pub fn zulu() {}

#[cfg(test)]
pub(crate) mod test_support {
    pub fn helper() {}
}

/// Doc comment stays attached to the module.
#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn z() {
        let _app = crate::api::routes::create_router(todo!());
    }
}
EOF
  cat >"$d/backend/src/services/beta.rs" <<'EOF'
#[cfg(test)]
mod beta_tests;
EOF
  mkdir -p "$d/backend/src/services/beta"
  cat >"$d/backend/src/services/beta/beta_tests.rs" <<'EOF'
#[test]
fn out_of_line() {}
EOF
  cat >"$d/backend/src/main.rs" <<'EOF'
fn main() {}

#[cfg(test)]
mod tests {
    #[test]
    fn m() {}
}
EOF
}

run_check() { # <repo> -> status, output in $tmp/out
  python3 "$SHARDS_PY" check --src "$1/backend/src" --repo "$1" >"$tmp/out" 2>&1
}

echo "test-shards.py self-test"

r="$tmp/r1"; mkrepo "$r"
if run_check "$r"; then bad "ungated tree must fail check"; else
  grep -q "alpha.rs:3 (mod tests): 2 tests but no" "$tmp/out" \
    && ok "ungated module (with its nested tests counted) is refused" \
    || { bad "ungated module message"; cat "$tmp/out"; }
fi

python3 "$SHARDS_PY" apply --src "$r/backend/src" >/dev/null
if run_check "$r"; then ok "check accepts exactly what apply wrote"; else
  bad "check after apply"; cat "$tmp/out"
fi

grep -q '^#\[cfg(ak_test_shard = "handlers-1")\]$' "$r/backend/src/api/handlers/alpha.rs" \
  && ok "handlers/a* -> handlers-1, attribute above #[cfg(test)]" || bad "alpha shard"
if sed -n '/Doc comment/,/^mod tests/p' "$r/backend/src/api/handlers/zulu.rs" \
    | tr '\n' '|' | grep -q 'Doc comment stays attached to the module.|#\[cfg(ak_test_shard = "router")\]|#\[cfg(test)\]|mod tests'; then
  ok "create_router() module -> router, after its doc comment"
else
  bad "router shard placement"; cat "$r/backend/src/api/handlers/zulu.rs"
fi
grep -c 'ak_test_shard' "$r/backend/src/api/handlers/zulu.rs" | grep -qx 1 \
  && ok "helper module without tests stays ungated" || bad "helper module was gated"
grep -q '^#\[cfg(ak_test_shard = "services-1")\]$' "$r/backend/src/services/beta.rs" \
  && ok "out-of-line test module is gated at its declaration" || bad "out-of-line gate"
[ "$(grep -c 'ak_test_shard' "$r/backend/src/api/handlers/alpha.rs")" = 1 ] \
  && ok "nested test module inherits, no second gate" || bad "nested module gated twice"

before="$(cat "$r"/backend/src/api/handlers/*.rs | md5sum)"
python3 "$SHARDS_PY" apply --src "$r/backend/src" >/dev/null
[ "$before" = "$(cat "$r"/backend/src/api/handlers/*.rs | md5sum)" ] \
  && ok "apply is idempotent" || bad "apply not idempotent"

sed -i 's/ak_test_shard = "handlers-1"/ak_test_shard = "services-1"/' "$r/backend/src/api/handlers/alpha.rs"
run_check "$r" && bad "wrong shard must fail" || {
  grep -q "gated to 'services-1', expected 'handlers-1'" "$tmp/out" \
    && ok "module gated to the wrong shard is refused" || { bad "wrong-shard message"; cat "$tmp/out"; }
}
python3 "$SHARDS_PY" apply --src "$r/backend/src" >/dev/null

printf '\n#[test]\nfn stray() {}\n' >>"$r/backend/src/services/beta.rs"
run_check "$r" && bad "stray test must fail" || {
  grep -q "outside any #\[cfg(test)\] mod" "$tmp/out" \
    && ok "test outside a test module is refused" || { bad "stray message"; cat "$tmp/out"; }
}
sed -i '/^#\[test\]$/,$d' "$r/backend/src/services/beta.rs"

sed -i 's/^\(        shard: \[\)[^,]*, /\1/' "$r/.github/workflows/ci.yml"
run_check "$r" && bad "matrix missing a shard must fail" || {
  grep -q "unit-test matrix" "$tmp/out" && ok "matrix missing a shard is refused" \
    || { bad "matrix message"; cat "$tmp/out"; }
}

r="$tmp/r2"; mkrepo "$r"; python3 "$SHARDS_PY" apply --src "$r/backend/src" >/dev/null
sed -i 's/BIN_SHARD: .*/BIN_SHARD: router/' "$r/.github/workflows/ci.yml"
run_check "$r" && bad "wrong BIN_SHARD must fail" || {
  grep -q "BIN_SHARD is 'router'" "$tmp/out" && ok "BIN_SHARD not matching main.rs's shard is refused" \
    || { bad "BIN_SHARD message"; cat "$tmp/out"; }
}

r="$tmp/r3"; mkrepo "$r"; python3 "$SHARDS_PY" apply --src "$r/backend/src" >/dev/null
sed -i 's/test-shard-router = \[\]//' "$r/backend/Cargo.toml"
run_check "$r" && bad "feature list drift must fail" || {
  grep -q "backend/Cargo.toml test-shard-\* features" "$tmp/out" && ok "Cargo feature drift is refused" \
    || { bad "feature drift message"; cat "$tmp/out"; }
}

echo "merge-lcov.py self-test"

mkdir -p "$tmp/lcov"
cat >"$tmp/lcov/a.info" <<'EOF'
SF:/w/backend/src/lib.rs
FN:1,prod
FNDA:0,prod
FNF:1
FNH:0
DA:1,0
DA:2,3
DA:10,1
LF:3
LH:2
end_of_record
SF:/w/backend/src/only_a.rs
DA:5,2
LF:1
LH:1
end_of_record
EOF
cat >"$tmp/lcov/b.info" <<'EOF'
SF:/w/backend/src/lib.rs
FN:1,prod
FNDA:4,prod
FNF:1
FNH:1
DA:1,4
DA:2,0
DA:11,0
LF:3
LH:1
end_of_record
EOF
python3 "$MERGE_PY" --output "$tmp/lcov/m.info" --totals "$tmp/lcov/t.json" \
  --summary "$tmp/lcov/s.txt" "$tmp/lcov/a.info" "$tmp/lcov/b.info" >/dev/null
expect_lcov() { # <label> <pattern>
  grep -qx "$2" "$tmp/lcov/m.info" && ok "$1" || { bad "$1"; cat "$tmp/lcov/m.info"; }
}
expect_lcov "hits are summed per line (0 + 4)" "DA:1,4"
expect_lcov "hits are summed per line (3 + 0)" "DA:2,3"
expect_lcov "a line present in one report only is kept" "DA:11,0"
expect_lcov "a file present in one report only is kept" "SF:/w/backend/src/only_a.rs"
expect_lcov "function hits are summed" "FNDA:4,prod"
expect_lcov "LF is recomputed over the union" "LF:4"
expect_lcov "LH is recomputed over the union" "LH:3"
got="$(python3 -c "import json,sys; t=json.load(open(sys.argv[1]))['data'][0]['totals']['lines']; print(t['count'], t['covered'], round(t['percent'], 2))" "$tmp/lcov/t.json")"
[ "$got" = "5 4 80.0" ] && ok "totals.json lines.{count,covered,percent} from the merge" \
  || bad "totals.json: expected '5 4 80.0', got '$got'"

# Merging one report must reproduce it (modulo record order).
python3 "$MERGE_PY" --output "$tmp/lcov/one.info" "$tmp/lcov/a.info" >/dev/null
diff <(grep -E '^(SF|DA|LF|LH):' "$tmp/lcov/a.info") \
     <(grep -E '^(SF|DA|LF|LH):' "$tmp/lcov/one.info") >/dev/null \
  && ok "a single report round-trips unchanged" || bad "single-report round trip"

echo
echo "test-shards/merge-lcov self-test: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
