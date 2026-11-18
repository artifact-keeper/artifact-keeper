#!/usr/bin/env bash
# Self-test for test-shards.py and merge-lcov.py (the sharded unit-test job).
#
# Both scripts decide what CI measures without any test of their own noticing
# a mistake. The dangerous directions are silent ones:
#
#   * test-shards.py: a test module left ungated is COMPILED in every leg;
#     unless `filter` keeps its tests to exactly one leg they run five times
#     (coverage unaffected, nobody notices), and a filter that dropped one
#     from every leg would lose it silently. `check` must warn about it but
#     pass (contributor PRs predating the gates stay green); a module gated
#     to a shard the matrix does not run never runs at all, and a test
#     outside any module runs in every leg, so `check` must refuse those.
#     `apply` must produce exactly what `check` accepts without warnings.
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
  cat >"$d/backend/src/services/gamma.rs" <<'EOF'
pub mod inner {
    #[cfg(test)]
    mod tests {
        #[test]
        fn g() {}
    }
}
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

run_filter() { # <repo> <shard> -> stdout
  python3 "$SHARDS_PY" filter --src "$1/backend/src" "$2"
}

r="$tmp/r1"; mkrepo "$r"
if run_check "$r"; then
  grep -q '^::warning file=backend/src/api/handlers/alpha.rs,line=3,title=Test module has no shard gate::api/handlers/alpha.rs:3 (mod tests): 2 tests but no #\[cfg(ak_test_shard = "handlers-1")\].*test-shards.py apply' "$tmp/out" \
    && ok "ungated module (nested tests counted) passes with an annotated warning and the fix" \
    || { bad "ungated module warning"; cat "$tmp/out"; }
  grep -q "5 warning(s)" "$tmp/out" && ok "every ungated test module is warned about" \
    || { bad "ungated warning count"; cat "$tmp/out"; }
else
  bad "ungated tree must pass check (with warnings)"; cat "$tmp/out"
fi

# Each ungated module must run in EXACTLY one leg -- the one apply will gate
# it to -- and nothing else may be filtered out. (main.rs's module is not in
# the list: the bin-target tests are built in the BIN_SHARD leg only.)
declare -A want=(
  [api::handlers::alpha::tests]=handlers-1
  [api::handlers::zulu::tests]=router
  [services::beta::beta_tests]=services-1
  [services::gamma::inner::tests]=services-1
)
mapfile -t shards < <(python3 "$SHARDS_PY" shards)
for s in "${shards[@]}"; do run_filter "$r" "$s" >"$tmp/filter-$s"; done
for path in "${!want[@]}"; do
  legs=""
  for s in "${shards[@]}"; do
    grep -qF "test(/^${path}::/)" "$tmp/filter-$s" || legs="$legs $s"
  done
  [ "$legs" = " ${want[$path]}" ] && ok "filter: $path runs in exactly one leg (${want[$path]})" \
    || bad "filter: $path runs in legs [${legs# }], expected [${want[$path]}]"
done
grep -h -o 'test(/^[^/]*/)' "$tmp"/filter-* | sort -u >"$tmp/excluded"
[ "$(wc -l <"$tmp/excluded")" = "${#want[@]}" ] \
  && ok "filter excludes nothing but ungated lib modules (helpers, main.rs untouched)" \
  || { bad "filter excludes something else"; cat "$tmp/excluded"; }
grep -q '^not (kind(lib) & (test(/^' "$tmp/filter-handlers-1" \
  && ok "filter is scoped to the lib test binary" || { bad "filter shape"; cat "$tmp/filter-handlers-1"; }
run_filter "$r" nope >/dev/null 2>&1 && bad "filter must refuse an unknown shard" \
  || ok "filter refuses an unknown shard"

python3 "$SHARDS_PY" apply --src "$r/backend/src" >/dev/null
if run_check "$r" && ! grep -q '::warning' "$tmp/out"; then
  ok "check accepts exactly what apply wrote, without warnings"
else
  bad "check after apply"; cat "$tmp/out"
fi
all_legs=""
for s in "${shards[@]}"; do all_legs="$all_legs$(run_filter "$r" "$s") "; done
[ "$all_legs" = "$(printf 'all() %.0s' "${shards[@]}")" ] \
  && ok "filter is all() in every leg once every module is gated" \
  || bad "filter after apply: $all_legs"
grep -q '^    #\[cfg(ak_test_shard = "services-1")\]$' "$r/backend/src/services/gamma.rs" \
  && ok "module nested in an inline module is gated at its own indent" || bad "nested gate"

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
if run_check "$r"; then
  grep -q "^::warning file=backend/src/api/handlers/alpha.rs,line=3,.*gated to 'services-1', expected 'handlers-1'" "$tmp/out" \
    && ok "module gated to another real shard passes with a warning (it still runs once)" \
    || { bad "wrong-shard warning"; cat "$tmp/out"; }
else
  bad "module gated to another real shard must pass (with a warning)"; cat "$tmp/out"
fi
python3 "$SHARDS_PY" apply --src "$r/backend/src" >/dev/null

sed -i 's/ak_test_shard = "handlers-1"/ak_test_shard = "handlers-9"/' "$r/backend/src/api/handlers/alpha.rs"
run_check "$r" && bad "gate naming no shard must fail" || {
  grep -q "gated to 'handlers-9', which is not a shard" "$tmp/out" \
    && ok "module gated to a shard that does not exist is refused" || { bad "bogus-shard message"; cat "$tmp/out"; }
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

# A bin target's test module (bin/**) runs only in the BIN_SHARD leg, the
# one that builds `--bins`; gated anywhere else, it never runs (#6133).
r="$tmp/rbin"; mkrepo "$r"; python3 "$SHARDS_PY" apply --src "$r/backend/src" >/dev/null
mkdir -p "$r/backend/src/bin/tool"
printf '%s\n' 'fn main() {}' '' '#[cfg(ak_test_shard = "services-2")]' '#[cfg(test)]' 'mod tests {' '    #[test]' '    fn t() {}' '}' >"$r/backend/src/bin/tool/main.rs"
run_check "$r" && bad "bin/ test module outside BIN_SHARD must fail" || {
  grep -q "bin-target test module gated to 'services-2'" "$tmp/out" && ok "bin/ test module outside BIN_SHARD is refused" \
    || { bad "bin/ gate message"; cat "$tmp/out"; }
}
sed -i 's/ak_test_shard = "services-2"/ak_test_shard = "router"/' "$r/backend/src/bin/tool/main.rs"
run_check "$r" && ok "bin/ test module in BIN_SHARD passes" || { bad "bin/ test module in BIN_SHARD"; cat "$tmp/out"; }

r="$tmp/r2"; mkrepo "$r"; python3 "$SHARDS_PY" apply --src "$r/backend/src" >/dev/null
sed -i 's/BIN_SHARD: .*/BIN_SHARD: services-2/' "$r/.github/workflows/ci.yml"
run_check "$r" && bad "wrong BIN_SHARD must fail" || {
  grep -q "BIN_SHARD is 'services-2'" "$tmp/out" && ok "BIN_SHARD not matching main.rs's shard is refused" \
    || { bad "BIN_SHARD message"; cat "$tmp/out"; }
}

r="$tmp/r3"; mkrepo "$r"; python3 "$SHARDS_PY" apply --src "$r/backend/src" >/dev/null
sed -i 's/test-shard-router = \[\]//' "$r/backend/Cargo.toml"
run_check "$r" && bad "feature list drift must fail" || {
  grep -q "backend/Cargo.toml test-shard-\* features" "$tmp/out" && ok "Cargo feature drift is refused" \
    || { bad "feature drift message"; cat "$tmp/out"; }
}

# Test modules that use other test modules (#3960): the used module must be
# compiled wherever its users are, or that shard fails with E0433.
r="$tmp/r4"; mkrepo "$r"
cat >"$r/backend/src/api/handlers/delta.rs" <<'EOF'
#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn builds_the_router() {
        let _app = crate::api::routes::create_router(todo!());
        super::db_tests::remote_member();
    }
}

#[cfg(test)]
mod db_tests {
    pub fn remote_member() {}

    #[test]
    fn d() {}
}
EOF
cat >"$r/backend/src/services/shared.rs" <<'EOF'
#[cfg(test)]
pub mod tests {
    pub fn fixture() {
        crate::services::leaf::tests::deeper();
    }

    #[test]
    fn s() {}
}
EOF
cat >"$r/backend/src/services/leaf.rs" <<'EOF'
#[cfg(test)]
pub mod tests {
    pub fn deeper() {}

    #[test]
    fn l() {}
}
EOF
for f in alpha2:a zeta2:z; do
  cat >"$r/backend/src/api/handlers/${f%%:*}.rs" <<EOF
#[cfg(test)]
mod tests {
    #[test]
    fn uses_shared_${f##*:}() {
        crate::services::shared::tests::fixture();
    }
}
EOF
done
python3 "$SHARDS_PY" apply --src "$r/backend/src" >/dev/null
grep -A2 '^#\[cfg(ak_test_shard = "router")\]$' "$r/backend/src/api/handlers/delta.rs" | grep -q 'mod db_tests' \
  && ok "same-file sibling used via super:: follows its user into the router shard" \
  || { bad "sibling not pulled into its user's shard"; cat "$r/backend/src/api/handlers/delta.rs"; }
! grep -q ak_test_shard "$r/backend/src/services/shared.rs" \
  && ok "module used from two shards (crate:: paths) is left ungated" \
  || { bad "multi-shard module was gated"; cat "$r/backend/src/services/shared.rs"; }
! grep -q ak_test_shard "$r/backend/src/services/leaf.rs" \
  && ok "module used by an ungated module is ungated too (transitive)" \
  || { bad "transitively used module was gated"; cat "$r/backend/src/services/leaf.rs"; }
if run_check "$r" && ! grep -q '::warning' "$tmp/out"; then
  ok "check accepts the planned gates, no warnings for ungated-by-design modules"
else
  bad "check after apply (dependency case)"; cat "$tmp/out"
fi
for s in "${shards[@]}"; do run_filter "$r" "$s" >"$tmp/dfilter-$s"; done
for pair in services::shared::tests:services-2 services::leaf::tests:services-1; do
  path="${pair%:*}"; legs=""
  for s in "${shards[@]}"; do grep -qF "test(/^${path}::/)" "$tmp/dfilter-$s" || legs="$legs $s"; done
  [ "$legs" = " ${pair##*:}" ] \
    && ok "ungated-by-design $path: helpers compiled in every leg, tests run in one (${pair##*:})" \
    || bad "ungated-by-design $path runs in legs [${legs# }], expected [${pair##*:}]"
done
sed -i 's/^#\[cfg(ak_test_shard = "router")\]$/#[cfg(ak_test_shard = "handlers-1")]/' "$r/backend/src/api/handlers/delta.rs"
sed -i '0,/ak_test_shard = "handlers-1"/s//ak_test_shard = "router"/' "$r/backend/src/api/handlers/delta.rs"
run_check "$r" && bad "a used module missing from its user's shard must fail" || {
  grep -q "delta.rs:2 (mod tests) uses test module api::handlers::delta::db_tests .* not compiled in shard(s) \['router'\].*E0433.*apply\` will gate it 'router'" "$tmp/out" \
    && ok "sibling gated away from its user is refused, naming the shard and the fix" \
    || { bad "sibling-reference message"; cat "$tmp/out"; }
}
python3 "$SHARDS_PY" apply --src "$r/backend/src" >/dev/null
sed -i 's/^#\[cfg(test)\]$/#[cfg(ak_test_shard = "services-2")]\n#[cfg(test)]/' "$r/backend/src/services/shared.rs"
run_check "$r" && bad "gating a module used from two shards must fail" || {
  grep -q "uses test module services::shared::tests .*leave it ungated" "$tmp/out" \
    && ok "gating a module its users need in several shards is refused" \
    || { bad "multi-shard gate message"; cat "$tmp/out"; }
}

# `pub async fn` in test code is a monomorphization root of every test build
# that compiles it (#6143). check refuses it in an inline test module, in an
# out-of-line helper module and on an item that is itself #[cfg(test)];
# apply rewrites each to `pub(crate)` (keeping `unsafe`) and leaves
# production code and `pub(crate)`/plain `pub fn` alone.
r="$tmp/r5"; mkrepo "$r"; python3 "$SHARDS_PY" apply --src "$r/backend/src" >/dev/null
cat >"$r/backend/src/api/handlers/echo.rs" <<'EOF'
pub async fn production_handler() {}

#[cfg(test)]
/// A test-only free function outside any module is a root too.
pub async fn standalone_helper() {}

#[cfg(test)]
pub(crate) mod helpers;

#[cfg(test)]
mod tests {
    pub async fn inline_helper() {}
    pub async unsafe fn unsafe_helper() {}
    pub(crate) async fn already_crate() {}
    pub fn sync_helper() {}

    #[tokio::test]
    async fn e() {
        inline_helper().await;
    }
}
EOF
mkdir -p "$r/backend/src/api/handlers/echo"
cat >"$r/backend/src/api/handlers/echo/helpers.rs" <<'EOF'
pub async fn builds_the_router() {
    let _app = crate::api::routes::create_router(todo!());
}
EOF
if run_check "$r"; then
  bad "pub async fn in test code must fail check"; cat "$tmp/out"
else
  grep -q "echo.rs:5: \`pub async fn\` in test code" "$tmp/out" \
    && grep -q "echo.rs:12: \`pub async fn\` in test code" "$tmp/out" \
    && grep -q "echo.rs:13: \`pub async fn\` in test code" "$tmp/out" \
    && grep -q "echo/helpers.rs:1: \`pub async fn\` in test code" "$tmp/out" \
    && [ "$(grep -c '`pub async fn` in test code:' "$tmp/out")" = 4 ] \
    && grep -q "^Why \`pub(crate)\`:" "$tmp/out" \
    && ok "pub async fn in test code (inline, out-of-line, #[cfg(test)] item, unsafe) is refused, nothing else" \
    || { bad "pub async fn message"; cat "$tmp/out"; }
fi
python3 "$SHARDS_PY" apply --src "$r/backend/src" >/dev/null
if run_check "$r"; then
  ok "apply rewrites pub async fn in test code so check passes"
else
  bad "check after pub async rewrite"; cat "$tmp/out"
fi
grep -q '^pub async fn production_handler' "$r/backend/src/api/handlers/echo.rs" \
  && grep -q '^    pub(crate) async fn inline_helper' "$r/backend/src/api/handlers/echo.rs" \
  && grep -q '^    pub(crate) async unsafe fn unsafe_helper' "$r/backend/src/api/handlers/echo.rs" \
  && grep -q '^pub(crate) async fn standalone_helper' "$r/backend/src/api/handlers/echo.rs" \
  && grep -q '^    pub fn sync_helper' "$r/backend/src/api/handlers/echo.rs" \
  && [ "$(grep -c 'pub(crate) async fn already_crate' "$r/backend/src/api/handlers/echo.rs")" = 1 ] \
  && grep -q '^pub(crate) async fn builds_the_router' "$r/backend/src/api/handlers/echo/helpers.rs" \
  && ok "apply touches only pub async fn inside test code" \
  || { bad "pub async rewrite scope"; cat "$r/backend/src/api/handlers/echo.rs" "$r/backend/src/api/handlers/echo/helpers.rs"; }

# ── archive-filter / partition-check: one build of every test (ci.yml's
# build-once job), five legs selecting from it. The silent failure here is a
# test no leg selects, or one two legs both run; the filters are evaluated
# below with a small model of nextest's filterset language (the subset the
# script emits), against test names laid out the way nextest names them.
echo "archive-filter self-test"
r="$tmp/r4"; mkrepo "$r"
# A test helper module holding no tests of its own, out of line, with a test
# module nested in it that belongs to another shard -- the shape of
# api::handlers::test_db_helpers::poll_tests, which `filter` used to drop
# from every leg.
cat >>"$r/backend/src/api/handlers/zulu.rs" <<'RS'

#[cfg(test)]
pub(crate) mod db_helpers;
RS
mkdir -p "$r/backend/src/api/handlers/zulu"
cat >"$r/backend/src/api/handlers/zulu/db_helpers.rs" <<'RS'
pub(crate) fn helper() {}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod poll_tests {
    #[test]
    fn polls() {}
}
RS
# A module named after a keyword: nextest prints its tests as `r#pub::...`.
mkdir -p "$r/backend/src/formats"
cat >"$r/backend/src/formats/pub.rs" <<'RS'
#[cfg(test)]
mod tests {
    #[test]
    fn p() {}
}
RS
cat >"$tmp/evalfs.py" <<'PY'
"""Evaluate a nextest filterset (the subset test-shards.py emits) against
`<kind> <test name>` lines on stdin; print the names it selects."""
import re, sys

def parse(src):
    toks = re.findall(r"/[^/]*/|\w+|[()&|]", src)
    pos = [0]
    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None
    def take(want=None):
        t = toks[pos[0]]; pos[0] += 1
        if want and t != want:
            raise SystemExit(f"expected {want!r}, got {t!r}")
        return t
    def expr():
        left = term()
        while peek() == "|":
            take(); right = term(); left = (lambda a, b: lambda k, n: a(k, n) or b(k, n))(left, right)
        return left
    def term():
        left = factor()
        while peek() == "&":
            take(); right = factor(); left = (lambda a, b: lambda k, n: a(k, n) and b(k, n))(left, right)
        return left
    def factor():
        t = take()
        if t == "not":
            inner = factor(); return lambda k, n: not inner(k, n)
        if t == "(":
            e = expr(); take(")"); return e
        take("(")
        if t in ("all", "none"):
            take(")"); return (lambda k, n: True) if t == "all" else (lambda k, n: False)
        arg = take(); take(")")
        if t == "kind":
            return lambda k, n: k == arg
        if t == "test":
            rx = re.compile(arg[1:-1]); return lambda k, n: bool(rx.search(n))
        raise SystemExit(f"unknown predicate {t}")
    e = expr()
    if peek() is not None:
        raise SystemExit(f"trailing {toks[pos[0]:]}")
    return e

f = parse(open(sys.argv[1]).read())
for line in sys.stdin:
    kind, name = line.split()
    if f(kind, name):
        print(name)
PY
# Test names as nextest lists them: module path, then the test function.
cat >"$tmp/names" <<'NAMES'
lib api::handlers::alpha::tests::a
lib api::handlers::alpha::tests::nested::inherits_the_outer_gate
lib api::handlers::zulu::tests::z
lib api::handlers::zulu::db_helpers::poll_tests::polls
lib services::beta::beta_tests::out_of_line
lib services::gamma::inner::tests::g
lib macro_generated::tests::unknown_to_the_scan
lib formats::r#pub::tests::p
bin tests::m
NAMES
declare -A owner=(
  [api::handlers::alpha::tests::a]=handlers-1
  [api::handlers::alpha::tests::nested::inherits_the_outer_gate]=handlers-1
  [api::handlers::zulu::tests::z]=router
  [api::handlers::zulu::db_helpers::poll_tests::polls]=services-2
  [services::beta::beta_tests::out_of_line]=services-1
  [services::gamma::inner::tests::g]=services-1
  [macro_generated::tests::unknown_to_the_scan]=router
  [formats::r#pub::tests::p]=services-2
  [tests::m]=router
)
for when in ungated applied; do
  if [ "$when" = applied ]; then
    python3 "$SHARDS_PY" apply --src "$r/backend/src" >/dev/null
    # apply moves the nested module's gate to where its file maps.
    owner[api::handlers::zulu::db_helpers::poll_tests::polls]=handlers-2
  fi
  : >"$tmp/selected"
  for s in "${shards[@]}"; do
    python3 "$SHARDS_PY" archive-filter --src "$r/backend/src" "$s" >"$tmp/af-$s"
    python3 "$tmp/evalfs.py" "$tmp/af-$s" <"$tmp/names" | sed "s/\$/ $s/" >>"$tmp/selected"
  done
  for name in "${!owner[@]}"; do
    legs="$(awk -v n="$name" '$1 == n {printf " %s", $2}' "$tmp/selected")"
    [ "$legs" = " ${owner[$name]}" ] && ok "archive-filter ($when): $name runs in ${owner[$name]} only" \
      || bad "archive-filter ($when): $name runs in [${legs# }], expected [${owner[$name]}]"
  done
  if [ "$when" = ungated ]; then
    # The per-shard build's filter must not drop the nested module either:
    # its gate compiles it in services-2 only, and its ungated parent's
    # tests run elsewhere, so services-2 must carve it out of that skip.
    python3 "$SHARDS_PY" filter --src "$r/backend/src" services-2 >"$tmp/f-s2"
    python3 "$tmp/evalfs.py" "$tmp/f-s2" <"$tmp/names" \
      | grep -qx 'api::handlers::zulu::db_helpers::poll_tests::polls' \
      && ok "filter: a test module nested in another shard's helper module still runs in its own leg" \
      || { bad "filter drops the nested module"; cat "$tmp/f-s2"; }
  fi
done
python3 "$SHARDS_PY" archive-filter --src "$r/backend/src" nope >/dev/null 2>&1 \
  && bad "archive-filter must refuse an unknown shard" || ok "archive-filter refuses an unknown shard"

# partition-check reads nextest's own verdicts.
mkdir -p "$tmp/listing"
listing() { # <shard> <matched name>...
  local s="$1"; shift
  python3 - "$tmp/listing/$s.json" "$@" <<'PY'
import json, sys
out, matched = sys.argv[1], set(sys.argv[2:])
cases = {n: {"filter-match": {"status": "matches" if n in matched else "mismatch"}}
         for n in ("tests::a", "tests::b", "tests::c")}
json.dump({"rust-suites": {"artifact-keeper-backend": {"testcases": cases}}}, open(out, "w"))
PY
}
listing handlers-1 tests::a; listing handlers-2 tests::b; listing services-1
listing services-2; listing router tests::c
python3 "$SHARDS_PY" partition-check "$tmp/listing" >"$tmp/out" 2>&1 \
  && grep -q 'handlers-1 1, handlers-2 1, services-1 0, services-2 0, router 1; 3 in all, 0 #\[ignore\]d' "$tmp/out" \
  && ok "partition-check accepts one leg per test and prints the counts" \
  || { bad "partition-check on a partition"; cat "$tmp/out"; }
listing router tests::c tests::a
python3 "$SHARDS_PY" partition-check "$tmp/listing" >"$tmp/out" 2>&1 \
  && bad "partition-check must refuse a test two legs run" \
  || { grep -q "tests::a: selected by \['handlers-1', 'router'\]" "$tmp/out" \
       && ok "partition-check refuses a test two legs run, naming them" || { bad "dup message"; cat "$tmp/out"; }; }
listing router
python3 "$SHARDS_PY" partition-check "$tmp/listing" >"$tmp/out" 2>&1 \
  && bad "partition-check must refuse a test no leg runs" \
  || { grep -q "tests::c: selected by no leg" "$tmp/out" \
       && ok "partition-check refuses a test no leg runs" || { bad "missing message"; cat "$tmp/out"; }; }
# An #[ignore]d test is in every listing and selected by none: not a gap.
listing router tests::c
python3 - "$tmp/listing/services-1.json" <<'PY2'
import json, sys
d = json.load(open(sys.argv[1]))
d["rust-suites"]["artifact-keeper-backend"]["testcases"]["tests::live"] = {
    "filter-match": {"status": "mismatch", "reason": "ignored"}}
json.dump(d, open(sys.argv[1], "w"))
PY2
python3 "$SHARDS_PY" partition-check "$tmp/listing" >"$tmp/out" 2>&1 \
  && grep -q '; 3 in all, 1 #\[ignore\]d' "$tmp/out" \
  && ok "partition-check leaves #[ignore]d tests out" || { bad "ignored test"; cat "$tmp/out"; }

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
