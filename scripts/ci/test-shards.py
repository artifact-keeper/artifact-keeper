#!/usr/bin/env python3
"""Assign every inline test module in backend/src to a CI test shard.

WHY
---
The lib-test target compiles the production crate AND its ~17.5k inline
`#[cfg(test)]` tests as one rustc invocation, and that one process is what
the unit-test job's memory limit is about. Peak RSS of that rustc, sampled
from /proc (VmHWM) during an instrumented (`cargo llvm-cov show-env`),
debuginfo-off, `-j4` build of `origin/main` @ b79855e8 on a 20-core aarch64
host, 2026-09-23:

    all tests (today's single job)      16.7 GiB
    no inline test modules at all        6.5 GiB
    handlers-1                           9.9 GiB
    handlers-2                           8.9 GiB
    services-1                           8.3 GiB
    services-2                           8.1 GiB
    router                              10.0 GiB  (9.6 GiB once the backend
                                          test build uses 256 codegen units,
                                          #4223; the others not re-measured)

(The non-test library the BIN_SHARD leg also builds for `--bins` peaks at
9.6 GiB in a process of its own. Under sccache that rustc is a child of the
sccache server, not of cargo, so `/usr/bin/time -v cargo ...` -- and with it
the peak run-measured-build.sh records on the pool -- does not see it.)

Memory is NOT proportional to test bytes. A test harness is an executable,
so rustc only generates code for what the tests can reach; a test module
that builds the whole router (`create_router`) reaches every handler and
adds ~2.5 GiB by itself, and every further such module adds almost nothing.
Those modules therefore share one shard (`router`) instead of lifting all
of them. Five shards keep every leg at or under ~10 GiB, inside a standard
16 GB GitHub-hosted runner with room for Postgres and the OS.

"Can reach" includes every `pub async fn` the build compiles, whether or not
anything calls it: rustc makes the body of a `pub async fn` a codegen root
even in an executable. By November 2026 one ungated test helper declared that
way called `create_router`, so every leg built the whole router. Even a
harness with no test modules peaked at 14.7 GiB, and all five legs ran at
15.3-18.1 GiB, into swap (#6143). `check` therefore refuses `pub async fn`
anywhere in test code, and `apply` rewrites it to `pub(crate) async fn`,
which means the same there.

HOW
---
Each test module carries one extra attribute, directly ABOVE its
`#[cfg(test)]` line:

    #[cfg(ak_test_shard = "services-1")]
    #[cfg(test)]
    mod tests {

Two stacked `cfg` attributes are ANDed. `backend/build.rs` sets
`ak_test_shard` from the `test-shard-*` Cargo features: with none of them
enabled (plain `cargo test`, `cargo nextest run`, clippy, an IDE) it sets
EVERY shard value, so every test is compiled exactly as before; with
`--features test-shard-<name>` it sets only that one. The shard attribute
goes above `#[cfg(test)]`, not below it, so every existing tool that finds
test modules by a `#[cfg(test)]` line followed by `mod` (the audit and
token-mint gates, the jscpd source stripper, `streaming_invariant`, the
LIKE-pattern scanners in `api/handlers/mod.rs`) keeps seeing the same shape.

Which shard a module belongs to is a function of its FILE (`shard_for`),
not a choice made per module, so rebalancing is an edit to that function
plus `--apply`. A handful of files are pinned to another shard through
OVERRIDES because a test module in a different file imports helpers from
their `tests` module, and both must be compiled in the same shard.

Helper modules that hold no tests (`test_db_helpers`, `test_support`, ...)
are NOT gated: several shards use them.

A TEST MODULE THAT USES ANOTHER ONE
-----------------------------------
A test module may call helpers defined in another TEST module
(`super::virtual_gallery_db_tests::remote_member(..)` from a sibling, or
`crate::formats::pypi::tests::..` from another file). The used module must
then be compiled in every shard that compiles the user, or that shard fails
with E0433 "found an item that was configured out" (#3960's router shard).
`plan` follows those references (`super::..::<mod>` and `crate::<path>`,
resolved against the paths of the test modules that exist): a used module
goes to the shard of the modules that use it, whatever its own file says;
if they sit in DIFFERENT shards it is left ungated, so it is compiled in
every shard and -- like any ungated module, below -- its tests are run in
one leg only (its own `shard_for` shard) by `filter`. That propagates: a
module used by an ungated one is ungated too. `check` fails, as a hard
error, when the gates as written break that rule, because the build would.

A TEST MODULE WITHOUT THE ATTRIBUTE
-----------------------------------
A `#[cfg(test)] mod` with no shard line is compiled in EVERY shard build,
because nothing gates it out, and a pull request written before the gates
existed adds exactly that. Refusing it made every such contributor PR need
a maintainer push, so instead it is assigned the same way `apply` would
assign it -- `shard_for(file, body)` -- and the other legs skip its tests at
RUN time: `filter <shard>` prints the nextest filterset each unit-test leg
passes with `-E`, which excludes the lib tests of every ungated module
assigned to another shard. Each such test therefore runs in exactly one leg,
the one it will stay in once `apply` adds the attribute, and coverage is
unaffected (every leg instruments the module's lines; only one executes
them, and coverage-gates sums hits per line). `check` reports the module as
a `::warning::` with the one-command fix and still passes. The cost of
leaving it so is compile-time only: the module is built in all five legs.

A module gated to a DIFFERENT shard than `plan` names still runs
exactly once (in the shard it is gated to), so that too is a warning; a gate
naming a shard that does not exist would never run at all, and stays an
error.

USAGE
-----
    test-shards.py check  [--src DIR]  every test module carries the right
                                       shard attribute, no test lives outside
                                       a gated module, and the shard list
                                       matches Cargo.toml / build.rs (CI)
    test-shards.py apply  [--src DIR]  insert or fix the attributes in place
    test-shards.py list   [--src DIR]  per-shard modules / tests / bytes
    test-shards.py filter [--src DIR] SHARD
                                       the nextest `-E` filterset for SHARD's
                                       leg: skip the tests of ungated modules
                                       assigned to another shard
    test-shards.py archive-filter [--src DIR] SHARD
                                       the `-E` filterset for SHARD's leg when
                                       every leg runs from one build of all
                                       the tests (ci.yml's build-once job)
    test-shards.py partition-check DIR every test in DIR/<shard>.json (nextest
                                       listings) is selected by one leg
    test-shards.py shards              the shard names, one per line (the CI
                                       matrix is checked against this)
"""

import argparse
import json
import os
import re
import sys

SHARDS = ["handlers-1", "handlers-2", "services-1", "services-2", "router"]

# file (relative to backend/src) -> (shard, why). The test module in the
# file must be compiled in the same shard as the tests that import it.
# (`plan` now derives this from the `crate::` references too and reaches the
# same shards; the pins keep the base right if a reference is ever written in
# a form it does not follow, e.g. through a `use` alias.)
OVERRIDES = {
    "services/binary_catalog.rs": (
        "handlers-1",
        "api/handlers/conda.rs tests call binary_catalog::tests::build_test_elf",
    ),
    "formats/pypi.rs": (
        "handlers-2",
        "api/handlers/pypi.rs tests import formats::pypi::tests fixtures",
    ),
}

# The bin targets' sources: main.rs (the `artifact-keeper` binary) and
# bin/** (ak-mcp-introspector). Their tests are the bin-target tests, which
# ci.yml builds and runs in ONE leg (BIN_SHARD) with `--bins`. That leg also
# builds the non-test library, about 7 min on a hosted runner, so they go to
# the leg with the least other work: router, a median 9.6 min per job
# (services-1 12.2, handlers-2 12.7, handlers-1 17.8; 52 PR runs,
# 2026-11-14..16), against services-2's 21.2, which was the critical path
# while it carried them (#6133). Single runs vary by several minutes.
BIN_SHARD = "router"


def is_bin(rel):
    """Whether `rel` (path under src/) belongs to a bin target, not the lib."""
    return rel == "main.rs" or rel.startswith("bin/")


# A test module that builds the WHOLE application router goes to the
# `router` shard, wherever it lives. In a test harness (an executable) rustc
# only generates code for what the tests can reach, and `create_router`
# reaches every handler, so the first test module that calls it adds ~2.5 GiB
# to that shard's compile -- and every further one adds almost nothing.
# Measured: a shard with such a module peaked at 10.4-10.8 GiB, the same
# volume of tests without one at 7.5-8.4 GiB. Keeping them together pays
# that cost once instead of in every shard.
ROUTER_MARKER = re.compile(r"\bcreate_router\(")

# Otherwise files under each prefix are split by the first letter of the
# path below it: (last letter, shard) in ascending order.
RANGES = [
    ("api/handlers/", [("o", "handlers-1"), ("z", "handlers-2")]),
    ("services/", [("q", "services-1"), ("z", "services-2")]),
]
# formats, middleware, storage, models, config, ... (bin targets: BIN_SHARD)
DEFAULT_SHARD = "services-2"


def shard_for(rel, body=""):
    """The shard of a test module declared in `rel` (path under src/)."""
    if is_bin(rel):
        return BIN_SHARD
    if rel in OVERRIDES:
        return OVERRIDES[rel][0]
    if ROUTER_MARKER.search(body):
        return "router"
    for prefix, ranges in RANGES:
        if rel.startswith(prefix):
            first = rel[len(prefix)].lower()
            for last, shard in ranges:
                if first <= last:
                    return shard
            return ranges[-1][1]
    return DEFAULT_SHARD


CFG_TEST = re.compile(r"^(\s*)#\[cfg\(test\)\]\s*$")
SHARD_ATTR = re.compile(r'^(\s*)#\[cfg\(ak_test_shard = "([^"]*)"\)\]\s*$')
ANY_SHARD = re.compile(r"ak_test_shard")
MOD_ITEM = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*([{;])")
INLINE_MOD = re.compile(r"^(\s*)(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*\{")
TEST_ATTR = re.compile(r"^\s*#\[(?:tokio::)?test(?:\(|\])")
# A `pub async fn` in test code is a monomorphization ROOT of every test
# harness that compiles it, called or not: rustc treats the body of a free
# `pub async fn` as reachable even in an executable (a `pub(crate)` one, or a
# plain `pub fn`, is only generated when something calls it). Test code is
# never visible outside the crate, so `pub(crate)` means the same there and
# costs nothing; see PUB_ASYNC_WHY.
PUB_ASYNC = re.compile(r'^(\s*)pub\s+async\s+(?:unsafe\s+)?(?:extern\s+"[^"]*"\s+)?fn\b')
PUB_ASYNC_WHY = (
    "rustc generates code for a `pub async fn` and everything it calls in "
    "every test build that compiles it, called or not (#6143: one such "
    "helper that calls create_router put the whole router into every "
    "unit-test leg, +4.2 GiB of rustc peak each); in test code `pub(crate)` "
    "means the same and is generated only where a test calls it")


def count_tests(lines):
    return sum(1 for line in lines if TEST_ATTR.match(line))


def rust_files(src):
    for dirpath, _dirs, files in os.walk(src):
        for name in files:
            if name.endswith(".rs"):
                path = os.path.join(dirpath, name)
                yield os.path.relpath(path, src).replace(os.sep, "/")


def out_of_line_path(src, rel, name):
    """Where `mod <name>;` declared in `rel` lives (None if not found)."""
    base = os.path.dirname(rel)
    stem = os.path.splitext(os.path.basename(rel))[0]
    if stem not in ("mod", "lib", "main"):
        base = os.path.join(base, stem)
    for cand in (os.path.join(base, name + ".rs"), os.path.join(base, name, "mod.rs")):
        if os.path.exists(os.path.join(src, cand)):
            return cand.replace(os.sep, "/")
    return None


def find_modules(src, rel, lines):
    """Yield dicts for every `#[cfg(test)] mod` item in `lines`.

    Nested items inside an already-found module are skipped: they inherit
    the enclosing module's cfg.
    """
    i = 0
    while i < len(lines):
        m = CFG_TEST.match(lines[i])
        if not m:
            i += 1
            continue
        indent = m.group(1)
        j = i + 1
        while j < len(lines) and (
            lines[j].strip().startswith("#[") or lines[j].strip().startswith("//")
        ):
            j += 1
        item = MOD_ITEM.match(lines[j]) if j < len(lines) else None
        if not item:
            i += 1
            continue
        name, opener = item.group(1), item.group(2)
        if opener == ";":
            body_file = out_of_line_path(src, rel, name)
            body = []
            if body_file:
                with open(os.path.join(src, body_file), encoding="utf-8") as fh:
                    body = fh.read().split("\n")
            yield dict(attr=i, start=i, end=j, name=name, body_file=body_file,
                       tests=count_tests(body), nbytes=len("\n".join(body)),
                       indent=indent, body="\n".join(body))
            i = j + 1
            continue
        # `cargo fmt` is enforced, so the module closes at the first line
        # that is exactly its indent plus `}`.
        k = j + 1
        closing = indent + "}"
        while k < len(lines) and lines[k].rstrip() != closing:
            k += 1
        body = lines[i:k + 1]
        yield dict(attr=i, start=i, end=k, name=name, body_file=None,
                   tests=count_tests(body), nbytes=len("\n".join(body)),
                   indent=indent, body="\n".join(body))
        i = k + 1


def scan(src):
    """Return (modules, stray, gated_files) for the whole tree."""
    modules = []
    stray = []  # test attributes outside any test module
    gated_files = set()
    per_file = {}
    for rel in sorted(rust_files(src)):
        with open(os.path.join(src, rel), encoding="utf-8") as fh:
            lines = fh.read().split("\n")
        mods = list(find_modules(src, rel, lines))
        per_file[rel] = (lines, mods)
        for mod in mods:
            mod["file"] = rel
            modules.append(mod)
            if mod["body_file"] and mod["tests"]:
                gated_files.add(mod["body_file"])
    for rel, (lines, mods) in per_file.items():
        if rel in gated_files:
            continue
        covered = set()
        for mod in mods:
            covered.update(range(mod["start"], mod["end"] + 1))
        for n, line in enumerate(lines):
            if TEST_ATTR.match(line) and n not in covered:
                stray.append(f"{rel}:{n + 1}")
    return modules, stray, per_file


def module_path(rel, lines, mod):
    """The Rust path of `mod` inside the crate, e.g.
    `api::handlers::npm::tests` -- the prefix nextest shows its tests under.
    Inline modules enclosing it are found by indentation (`cargo fmt` is
    enforced). `#[path]` is not used in backend/src."""
    stem = rel[:-len(".rs")].split("/")
    if stem[-1] in ("mod", "lib", "main"):
        stem = stem[:-1]
    enclosing = []
    indent = len(mod["indent"])
    for n in range(mod["attr"] - 1, -1, -1):
        if indent == 0:
            break
        m = INLINE_MOD.match(lines[n])
        if m and len(m.group(1)) < indent:
            enclosing.insert(0, m.group(2))
            indent = len(m.group(1))
    return "::".join(stem + enclosing + [mod["name"]])


USE_SUPER = re.compile(r"\b((?:super::)+)(\w+)")
USE_CRATE = re.compile(r"\bcrate::(\w+(?:::\w+)*)")


def plan(modules, per_file):
    """Decide every test module's gate. Returns {key: info} for each module
    holding tests, key = (file, attr line), info = dict(
      mod, path, base (its own `shard_for`), want (the gate it must carry,
      or None: deliberately ungated), run (the one leg its tests run in),
      uses (keys of the test modules it references), users (the reverse)).

    The bin targets (main.rs, bin/**) are left out of the graph: each is a
    bin crate, whose `crate::` is not the library's, and its tests are
    built in one leg anyway."""
    info = {}
    by_path = {}
    for mod in modules:
        if not mod["tests"]:
            continue
        key = (mod["file"], mod["attr"])
        path = module_path(mod["file"], per_file[mod["file"]][0], mod)
        info[key] = dict(mod=mod, path=path, base=shard_for(mod["file"], mod["body"]),
                         uses=set(), users=set())
        if not is_bin(mod["file"]):
            by_path[path] = key
    for key, it in info.items():
        if is_bin(it["mod"]["file"]):
            continue
        parts = it["path"].split("::")
        targets = set()
        for ups, name in USE_SUPER.findall(it["mod"]["body"]):
            depth = ups.count("super::")
            if depth <= len(parts) - 1:
                targets.add("::".join(parts[:len(parts) - depth] + [name]))
        for ref in USE_CRATE.findall(it["mod"]["body"]):
            segs = ref.split("::")
            for n in range(len(segs), 0, -1):
                if "::".join(segs[:n]) in by_path:
                    targets.add("::".join(segs[:n]))
                    break
        for t in targets:
            other = by_path.get(t)
            if other and other != key:
                it["uses"].add(other)
                info[other]["users"].add(key)
    # Monotone fixpoint over "the shards that must compile this module": a
    # module nobody uses is compiled where its file says; a used one wherever
    # its users are; more than one shard means all of them (ungated).
    every = frozenset(SHARDS)
    compiled = {k: ({it["base"]} if not it["users"] else set()) for k, it in info.items()}
    while True:
        changed = True
        while changed:
            changed = False
            for k, it in info.items():
                for u in it["users"]:
                    new = compiled[k] | compiled[u]
                    if len(new) > 1:
                        new = set(every)
                    if new != compiled[k]:
                        compiled[k] = new
                        changed = True
        orphans = [k for k, c in compiled.items() if not c]  # used only in a cycle
        if not orphans:
            break
        for k in orphans:
            compiled[k] = {info[k]["base"]}
    for k, it in info.items():
        it["want"] = next(iter(compiled[k])) if len(compiled[k]) == 1 else None
        it["run"] = it["want"] or it["base"]
    return info


def shard_attr_of(lines, mod):
    """(line index, shard) of the attribute directly above `#[cfg(test)]`."""
    above = mod["attr"] - 1
    if above >= 0:
        m = SHARD_ATTR.match(lines[above])
        if m:
            return above, m.group(2)
    return None, None


def pub_async_in_test_code(src, modules):
    """[(file, line index)] of every `pub async fn` in test code: inside a
    `#[cfg(test)]` module (its own lines, or the whole file of an out-of-line
    one), or itself carrying `#[cfg(test)]`. (A `pub async` method in an
    `impl` block is not a root, but `pub(crate)` costs nothing there either,
    so the rule stays one regex.)"""
    found = set()
    for rel in rust_files(src):
        with open(os.path.join(src, rel), encoding="utf-8") as fh:
            lines = fh.read().split("\n")
        for n, line in enumerate(lines):
            if not CFG_TEST.match(line):
                continue
            j = n + 1
            while j < len(lines) and (lines[j].strip().startswith("#[")
                                      or lines[j].strip().startswith("//")):
                j += 1
            if j < len(lines) and PUB_ASYNC.match(lines[j]):
                found.add((rel, j))
    for mod in modules:
        if mod["body_file"]:
            rel, lo, hi = mod["body_file"], 0, None
        else:
            rel, lo, hi = mod["file"], mod["start"], mod["end"]
        with open(os.path.join(src, rel), encoding="utf-8") as fh:
            lines = fh.read().split("\n")
        for n in range(lo, len(lines) if hi is None else hi + 1):
            if PUB_ASYNC.match(lines[n]):
                found.add((rel, n))
    return sorted(found)


def check_manifest(repo):
    """The shard list here, the Cargo features and build.rs must agree."""
    problems = []
    cargo = open(os.path.join(repo, "backend/Cargo.toml"), encoding="utf-8").read()
    features = set(re.findall(r"^test-shard-([a-z0-9-]+)\s*=", cargo, re.M))
    if features != set(SHARDS):
        problems.append(
            f"backend/Cargo.toml test-shard-* features {sorted(features)} != "
            f"scripts/ci/test-shards.py SHARDS {SHARDS}"
        )
    build = open(os.path.join(repo, "backend/build.rs"), encoding="utf-8").read()
    m = re.search(r"TEST_SHARDS: &\[&str\] = &\[([^\]]*)\]", build)
    listed = re.findall(r'"([^"]+)"', m.group(1)) if m else []
    if listed != SHARDS:
        problems.append(f"backend/build.rs TEST_SHARDS {listed} != SHARDS {SHARDS}")
    return problems


def check_workflow(repo, bin_shard):
    """ci.yml's unit-test matrix runs exactly SHARDS, and its BIN_SHARD leg
    (the one that builds and runs `--bins`) is the shard the bin-target tests
    are gated to. A shard missing from the matrix is a slice of the suite
    that never runs; a wrong BIN_SHARD is main.rs's tests never running."""
    path = os.path.join(repo, ".github/workflows/ci.yml")
    if not os.path.exists(path):
        return []
    text = open(path, encoding="utf-8").read()
    problems = []
    m = re.search(r"^\s*shard:\s*\[([^\]]*)\]", text, re.M)
    matrix = [x.strip() for x in m.group(1).split(",")] if m else []
    if matrix != SHARDS:
        problems.append(f".github/workflows/ci.yml unit-test matrix {matrix} != SHARDS {SHARDS}")
    m = re.search(r"^\s*BIN_SHARD:\s*([\w-]+)", text, re.M)
    declared = m.group(1) if m else None
    if bin_shard and declared != bin_shard:
        problems.append(f".github/workflows/ci.yml BIN_SHARD is {declared!r}, but "
                        f"the bin-target tests (main.rs, bin/) are gated to {bin_shard!r}")
    return problems


def cmd_check(src, repo):
    modules, stray, per_file = scan(src)
    problems = check_manifest(repo)
    warnings = []  # (file, line, title, message)
    info = plan(modules, per_file)
    bin_shards = {it["run"] for it in info.values() if is_bin(it["mod"]["file"])}
    if len(bin_shards) > 1:
        problems.append(f"bin-target (main.rs, bin/) test modules span shards {sorted(bin_shards)}; "
                        "CI runs `--bins` in one leg only")
    problems += check_workflow(repo, next(iter(bin_shards), None))
    for mod in modules:
        lines = per_file[mod["file"]][0]
        where = f"{mod['file']}:{mod['attr'] + 1} (mod {mod['name']})"
        _, have = shard_attr_of(lines, mod)
        if mod["tests"] == 0:
            if have is not None:
                problems.append(f"{where}: holds no tests but is gated to shard {have!r}; "
                                "helper modules must stay ungated")
            continue
        it = info[(mod["file"], mod["attr"])]
        want = it["want"]
        if have is None and want is None:
            continue  # used from several shards: ungated by design
        if have is None:
            warnings.append((mod["file"], mod["attr"] + 1, "Test module has no shard gate",
                             f"{where}: {mod['tests']} tests but no "
                             f'#[cfg(ak_test_shard = "{want}")] above #[cfg(test)]. They '
                             f"still run exactly once, in the {want!r} unit-test leg, but "
                             "every leg compiles them"))
        elif have not in SHARDS:
            problems.append(f"{where}: gated to {have!r}, which is not a shard -- its "
                            f"tests would never run (expected {want!r})")
        elif is_bin(mod["file"]) and have != BIN_SHARD:
            # Only the BIN_SHARD leg builds `--bins`: anywhere else these
            # tests are compiled out of the one build that has them (#6133).
            problems.append(f"{where}: a bin-target test module gated to {have!r}; "
                            f"only the {BIN_SHARD!r} leg runs `--bins`, so its tests "
                            "never run")
        elif want is None:
            pass  # a user in another shard: reported by the reference check below
        elif have != want:
            warnings.append((mod["file"], mod["attr"], "Test module in an unexpected shard",
                             f"{where}: gated to {have!r}, expected {want!r}. Its tests "
                             f"still run exactly once, in the {have!r} leg"))
    # A module compiled in a shard must find every test module it uses there.
    def compiled_in(it):
        have = shard_attr_of(per_file[it["mod"]["file"]][0], it["mod"])[1]
        return set(SHARDS) if have is None else {have}
    for key, it in sorted(info.items()):
        for used in sorted(it["uses"]):
            u = info[used]
            missing = compiled_in(it) - compiled_in(u)
            if missing:
                m, um = it["mod"], u["mod"]
                target = (f"gate it {u['want']!r}" if u["want"]
                          else "leave it ungated (it is used from several shards)")
                problems.append(
                    f"{m['file']}:{m['attr'] + 1} (mod {m['name']}) uses test module "
                    f"{u['path']} ({um['file']}:{um['attr'] + 1}), which is not compiled "
                    f"in shard(s) {sorted(missing)}: those builds fail with E0433 "
                    f"'configured out'. `apply` will {target}")
    # A shard attribute anywhere else is a mistake the check above cannot see.
    known = {(m["file"], m["attr"] - 1) for m in modules}
    for rel, (lines, _mods) in per_file.items():
        for n, line in enumerate(lines):
            if SHARD_ATTR.match(line) and (rel, n) not in known:
                problems.append(f"{rel}:{n + 1}: ak_test_shard attribute not directly "
                                "above a #[cfg(test)] mod")
            elif ANY_SHARD.search(line) and not SHARD_ATTR.match(line) and rel not in (
                "lib.rs", "main.rs"):
                problems.append(f"{rel}:{n + 1}: unexpected ak_test_shard form "
                                "(use exactly #[cfg(ak_test_shard = \"<shard>\")])")
    for rel, n in pub_async_in_test_code(src, modules):
        problems.append(f"{rel}:{n + 1}: `pub async fn` in test code: make it "
                        "`pub(crate) async fn` (`apply` does)")
    for where in stray:
        problems.append(f"{where}: test attribute outside any #[cfg(test)] mod -- it "
                        "would run in EVERY shard; move it into a test module")
    fix = "fix: python3 scripts/ci/test-shards.py apply (then commit the result)"
    src_rel = os.path.relpath(src, repo).replace(os.sep, "/")
    for rel, line, title, msg in warnings:
        # A GitHub annotation on the PR diff; plain text anywhere else.
        print(f"::warning file={src_rel}/{rel},line={line},title={title}::{msg}. {fix}")
    if problems:
        print(f"test-shards: {len(problems)} problem(s):")
        for p in problems:
            print(f"  {p}")
        if any("`pub async fn` in test code" in p for p in problems):
            print(f"Why `pub(crate)`: {PUB_ASYNC_WHY}.")
        print("Module attributes: fix with `python3 scripts/ci/test-shards.py apply`.\n"
              "Shard lists (Cargo.toml, build.rs, ci.yml): edit them to match SHARDS.")
        return 1
    gated = [m for m in modules if m["tests"]]
    print(f"test-shards: OK -- {len(gated)} test modules, "
          f"{sum(m['tests'] for m in gated)} tests, {len(SHARDS)} shards"
          + (f", {len(warnings)} warning(s) ({fix})" if warnings else ""))
    return 0


def lib_owners(src):
    """{module path: the shard whose leg runs the tests written directly in
    it} for every lib test module. A gated module runs where its gate says
    (even when `plan` wants it elsewhere: that is only a warning); an
    ungated one where `plan` assigns it. A test belongs to the DEEPEST test
    module whose path prefixes its name, so a module nested in another one
    (an out-of-line `#[cfg(test)] mod x;` file holding `mod tests`) can
    belong to a different shard than its parent. The bin targets are left
    out: their tests run in the BIN_SHARD leg whatever their gate."""
    modules, _stray, per_file = scan(src)
    owners = {}
    for it in plan(modules, per_file).values():
        if is_bin(it["mod"]["file"]):
            continue
        have = shard_attr_of(per_file[it["mod"]["file"]][0], it["mod"])[1]
        owners[test_name_prefix(it["path"])] = have or it["run"]
    return owners


MODULE_PATH = re.compile(r"^(?:r#)?\w+(?:::(?:r#)?\w+)*$")

# A module named after a keyword (`formats/pub.rs`) is `r#pub` in the crate,
# and in the test names nextest prints.
RUST_KEYWORDS = frozenset(
    "as async await break const continue crate dyn else enum extern false fn "
    "for if impl in let loop match mod move mut pub ref return static struct "
    "super trait true type unsafe use where while abstract become box do final "
    "gen macro override priv try typeof unsized virtual yield".split())


def test_name_prefix(path):
    """`path` as nextest spells it: keyword segments get their `r#`."""
    return "::".join(f"r#{seg}" if seg in RUST_KEYWORDS else seg
                     for seg in path.split("::"))


def _prefixes(paths):
    """One nextest `test()` predicate matching the tests under any of
    `paths`. One regex per predicate, not one predicate per path: nextest
    evaluates every predicate against every test, and ~800 of them
    against ~22k tests is measurable."""
    for path in paths:
        if not MODULE_PATH.match(path):
            raise ValueError(f"unexpected module path {path!r}")
    return f"test(/^(?:{'|'.join(sorted(paths))})::/)"


def _owned_by(owners, shard):
    """nextest filterset for the lib tests `owners` assigns to `shard`, in a
    build that compiles EVERY test module: each test module of that shard,
    minus the test modules nested in it that belong to another one."""
    simple, carved = [], []
    for path in sorted(p for p, s in owners.items() if s == shard):
        others = [q for q, s in owners.items() if s != shard and q.startswith(path + "::")]
        if others:
            carved.append(f"({_prefixes([path])} & not {_prefixes(others)})")
        else:
            simple.append(path)
    terms = ([_prefixes(simple)] if simple else []) + carved
    if not terms:
        return None
    return f"(kind(lib) & ({' | '.join(terms)}))"


def cmd_filter(src, shard):
    """The nextest filterset for `shard`'s leg when that leg builds its own
    test binary (`--features test-shard-<shard>`). Every shard build compiles
    every ungated test module; this keeps each one's tests to the single
    leg `plan` assigns it. `kind(lib)`, and the bin targets left out: the
    bin-target tests are built and run in one leg only (BIN_SHARD) whatever
    their gate. A test module nested in a skipped one that belongs to THIS
    shard is carved back out of the skip (before that, such a module ran in
    no leg at all: `api::handlers::test_db_helpers::poll_tests`)."""
    if shard not in SHARDS:
        print(f"test-shards: unknown shard {shard!r}; one of {SHARDS}", file=sys.stderr)
        return 2
    modules, _stray, per_file = scan(src)
    owners = lib_owners(src)
    skip = sorted(test_name_prefix(it["path"]) for it in plan(modules, per_file).values()
                  if it["run"] != shard and not is_bin(it["mod"]["file"])
                  and shard_attr_of(per_file[it["mod"]["file"]][0], it["mod"])[1] is None)
    if not skip:
        print("all()")
        return 0
    terms = []
    for p in skip:
        mine = [q for q, s in owners.items() if s == shard and q.startswith(p + "::")]
        if mine:
            terms.append(f"(test(/^{p}::/) & not {_prefixes(mine)})")
        else:
            terms.append(f"test(/^{p}::/)")
    print(f"not (kind(lib) & ({' | '.join(terms)}))")
    return 0


def archive_filter(src, shard):
    """The nextest filterset for `shard`'s leg when every leg runs from ONE
    build that compiled every test module (ci.yml's build-once job:
    `cargo nextest archive` with no `test-shard-*` feature, so build.rs
    turns every gate on). Each lib test runs in the leg that owns it
    (`lib_owners`). The BIN_SHARD leg takes everything no other leg claims:
    the bin-target tests, its own modules, and any test the scan above
    does not know about (a macro-generated module, say), so the five
    filters partition the archive by construction and no test can be
    dropped by all of them. ci.yml checks that partition against nextest's
    own listing (`partition-check`) before any leg runs."""
    owners = lib_owners(src)
    if shard == BIN_SHARD:
        others = [e for e in (_owned_by(owners, s) for s in SHARDS if s != BIN_SHARD) if e]
        return f"not ({' | '.join(others)})" if others else "all()"
    return _owned_by(owners, shard) or "none()"


def cmd_archive_filter(src, shard):
    if shard not in SHARDS:
        print(f"test-shards: unknown shard {shard!r}; one of {SHARDS}", file=sys.stderr)
        return 2
    print(archive_filter(src, shard))
    return 0


def cmd_partition_check(listing_dir):
    """Every test in the archive is selected by exactly one leg's filter.
    `listing_dir` holds `<shard>.json` per shard: the output of
    `cargo nextest list -E "$(archive-filter <shard>)" --message-format
    json` over the binaries that were archived, whose testcases carry nextest's own verdict
    (`filter-match.status`). Prints the per-leg counts."""
    seen = {}
    ignored = set()
    for shard in SHARDS:
        path = os.path.join(listing_dir, f"{shard}.json")
        with open(path, encoding="utf-8") as fh:
            listing = json.load(fh)
        for binary, suite in listing.get("rust-suites", {}).items():
            for name, case in suite.get("testcases", {}).items():
                legs = seen.setdefault((binary, name), [])
                match = case.get("filter-match", {})
                if match.get("status") == "matches":
                    legs.append(shard)
                elif match.get("reason") == "ignored":
                    # `#[ignore]`: no leg runs it by default, whatever the
                    # filter (the live S3 suites and friends).
                    ignored.add((binary, name))
    for key in ignored:
        seen.pop(key, None)
    counts = {s: 0 for s in SHARDS}
    problems = []
    for (binary, name), legs in sorted(seen.items()):
        if len(legs) == 1:
            counts[legs[0]] += 1
        else:
            problems.append(f"{binary} {name}: selected by {legs or 'no leg'}")
    print("test-shards: tests per leg: "
          + ", ".join(f"{s} {n}" for s, n in counts.items())
          + f"; {len(seen)} in all, {len(ignored)} #[ignore]d")
    if not seen:
        problems.append("the listings hold no test at all")
    if problems:
        print(f"test-shards: {len(problems)} test(s) not run by exactly one leg:")
        for p in problems[:50]:
            print(f"  {p}")
        return 1
    return 0


def cmd_apply(src):
    modules, stray, per_file = scan(src)
    info = plan(modules, per_file)
    changed = set()
    by_file = {}
    for mod in modules:
        by_file.setdefault(mod["file"], []).append(mod)
    for rel, mods in by_file.items():
        lines = per_file[rel][0]
        # bottom-up so earlier indices stay valid
        edits = False
        for mod in sorted(mods, key=lambda m: -m["attr"]):
            idx, have = shard_attr_of(lines, mod)
            want = info[(rel, mod["attr"])]["want"] if mod["tests"] else None
            attr = f'{mod["indent"]}#[cfg(ak_test_shard = "{want}")]'
            if want is None and idx is not None:
                del lines[idx]
                edits = True
            elif want is not None and idx is None:
                lines.insert(mod["attr"], attr)
                edits = True
            elif want is not None and have != want:
                lines[idx] = attr
                edits = True
        if edits:
            with open(os.path.join(src, rel), "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines))
            changed.add(rel)
    # After the attribute edits (which shift lines), so rescan.
    modules, _stray, _per_file = scan(src)
    by_rel = {}
    for rel, n in pub_async_in_test_code(src, modules):
        by_rel.setdefault(rel, []).append(n)
    for rel, idxs in by_rel.items():
        path = os.path.join(src, rel)
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().split("\n")
        for n in idxs:
            lines[n] = re.sub(r"^(\s*)pub(\s)", r"\1pub(crate)\2", lines[n], count=1)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        changed.add(rel)
    print(f"test-shards: updated {len(changed)} file(s); run `cargo fmt` after it")
    for where in stray:
        print(f"  WARNING {where}: test outside any #[cfg(test)] mod (not handled)")
    return 0


def cmd_list(src):
    modules, _stray, per_file = scan(src)
    info = plan(modules, per_file)
    stats = {s: [0, 0, 0] for s in SHARDS}
    for mod in modules:
        if mod["tests"]:
            s = stats[info[(mod["file"], mod["attr"])]["run"]]
            s[0] += 1
            s[1] += mod["tests"]
            s[2] += mod["nbytes"]
    total = [sum(v[i] for v in stats.values()) for i in range(3)]
    print(f"{'shard':12} {'modules':>8} {'tests':>7} {'test MB':>8}")
    for name, (n, t, b) in stats.items():
        print(f"{name:12} {n:8} {t:7} {b / 1e6:8.2f}")
    print(f"{'total':12} {total[0]:8} {total[1]:7} {total[2] / 1e6:8.2f}")
    return 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("command", choices=["check", "apply", "list", "shards", "filter",
                                            "archive-filter", "partition-check"])
    parser.add_argument("shard", nargs="?",
                        help="filter, archive-filter: the leg's shard; "
                             "partition-check: the directory of listings")
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.normpath(os.path.join(here, "..", ".."))
    parser.add_argument("--src", default=os.path.join(repo, "backend", "src"))
    parser.add_argument("--repo", default=repo)
    args = parser.parse_intermixed_args(argv[1:])
    if args.command == "shards":
        print("\n".join(SHARDS))
        return 0
    if args.command == "apply":
        return cmd_apply(args.src)
    if args.command == "list":
        return cmd_list(args.src)
    if args.command in ("filter", "archive-filter"):
        if not args.shard:
            parser.error(f"{args.command} needs a shard")
        if args.command == "filter":
            return cmd_filter(args.src, args.shard)
        return cmd_archive_filter(args.src, args.shard)
    if args.command == "partition-check":
        if not args.shard:
            parser.error("partition-check needs the listing directory")
        return cmd_partition_check(args.shard)
    return cmd_check(args.src, args.repo)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
