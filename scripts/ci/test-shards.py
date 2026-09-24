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
    test-shards.py shards              the shard names, one per line (the CI
                                       matrix is checked against this)
"""

import argparse
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
# formats, middleware, storage, models, config, main.rs, ...
DEFAULT_SHARD = "services-2"


def shard_for(rel, body=""):
    """The shard of a test module declared in `rel` (path under src/)."""
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

    main.rs is left out of the graph: it is the bin crate, whose `crate::`
    is not the library's, and its tests are built in one leg anyway."""
    info = {}
    by_path = {}
    for mod in modules:
        if not mod["tests"]:
            continue
        key = (mod["file"], mod["attr"])
        path = module_path(mod["file"], per_file[mod["file"]][0], mod)
        info[key] = dict(mod=mod, path=path, base=shard_for(mod["file"], mod["body"]),
                         uses=set(), users=set())
        if mod["file"] != "main.rs":
            by_path[path] = key
    for key, it in info.items():
        if it["mod"]["file"] == "main.rs":
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
    (the one that builds and runs `--bins`) is the shard main.rs's tests
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
                        f"backend/src/main.rs's tests are gated to {bin_shard!r}")
    return problems


def cmd_check(src, repo):
    modules, stray, per_file = scan(src)
    problems = check_manifest(repo)
    warnings = []  # (file, line, title, message)
    info = plan(modules, per_file)
    bin_shards = {it["run"] for it in info.values() if it["mod"]["file"] == "main.rs"}
    if len(bin_shards) > 1:
        problems.append(f"main.rs test modules span shards {sorted(bin_shards)}; "
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
        print("Module attributes: fix with `python3 scripts/ci/test-shards.py apply`.\n"
              "Shard lists (Cargo.toml, build.rs, ci.yml): edit them to match SHARDS.")
        return 1
    gated = [m for m in modules if m["tests"]]
    print(f"test-shards: OK -- {len(gated)} test modules, "
          f"{sum(m['tests'] for m in gated)} tests, {len(SHARDS)} shards"
          + (f", {len(warnings)} warning(s) ({fix})" if warnings else ""))
    return 0


def cmd_filter(src, shard):
    """The nextest filterset for `shard`'s leg. Every shard build compiles
    every ungated test module; this keeps each one's tests to the single
    leg `plan` assigns it. `kind(lib)`, and main.rs left out: the
    bin-target tests are built and run in one leg only (BIN_SHARD) whatever
    their gate."""
    if shard not in SHARDS:
        print(f"test-shards: unknown shard {shard!r}; one of {SHARDS}", file=sys.stderr)
        return 2
    modules, _stray, per_file = scan(src)
    skip = sorted(it["path"] for it in plan(modules, per_file).values()
                  if it["run"] != shard and it["mod"]["file"] != "main.rs"
                  and shard_attr_of(per_file[it["mod"]["file"]][0], it["mod"])[1] is None)
    if not skip:
        print("all()")
    else:
        tests = " | ".join(f"test(/^{p}::/)" for p in skip)
        print(f"not (kind(lib) & ({tests}))")
    return 0


def cmd_apply(src):
    modules, stray, per_file = scan(src)
    info = plan(modules, per_file)
    changed = 0
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
            changed += 1
    print(f"test-shards: updated {changed} file(s)")
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
    parser.add_argument("command", choices=["check", "apply", "list", "shards", "filter"])
    parser.add_argument("shard", nargs="?", help="filter: the leg's shard")
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
    if args.command == "filter":
        if not args.shard:
            parser.error("filter needs a shard")
        return cmd_filter(args.src, args.shard)
    return cmd_check(args.src, args.repo)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
