#!/usr/bin/env python3
"""Production-only coverage verdicts for ci.yml's `coverage-gates` job.

WHY
---
The unit job instruments the whole `backend` crate, inline `#[cfg(test)]`
modules included, and `lcov.info` counts those lines like any other. On
`main` at 438a743e they were 65% of the instrumented lines at ~98% hit, so
the old "total >= 50%" floor read ~90% while production code sat at ~77%,
and a PR adding 300 test lines and 50 untested production lines read ~86% on
the new-code gate and passed. Test code executing is not evidence that
production code is tested; both gates now count production lines only.

WHAT IS TEST CODE
-----------------
Exactly what `jscpd-prepare-sources.py` strips (its parser is imported, not
copied): every column-0 `#[cfg(test)]` / `#[cfg(all(test, ...))]` item that
opens a brace, up to the next column-0 `}`. `cargo fmt` is enforced, so the
rule is exact. In addition, a column-0 `#[cfg(test)]` on an out-of-line
`mod name;` makes the WHOLE file `name.rs` / `name/mod.rs` test code (and
every file it declares in turn), e.g. `api/handlers/test_db_helpers.rs`.
Indented `#[cfg(test)]` attributes (a test-only field or branch) are left in,
as they are for jscpd; they are individually small.

SUBCOMMANDS
-----------
  floor    production line coverage of the whole report vs --min (percent).
  newcode  coverage of the production lines the PR adds vs --min, measured
           against --merge-base (or a pre-computed --diff-file). Fewer than
           --min-lines instrumented production lines -> verdict "na".

Both print a human summary on stdout, append it to --summary (the step
summary) when given, write `key=value` outputs to --github-output when given,
and write a JSON verdict to --json when given. The exit status is 0 for
pass/na and 1 for fail, 2 for bad input; the caller decides what a fail
means (ci-complete, via coverage-gate-decision.sh).

--linemap FILE replaces the source scan with a JSON map
{"repo/relative.rs": [[start, end], ...] | "all"}; "all" marks a whole
test-only file. --write-linemap FILE writes the map that was used.

STALE OBJECTS
-------------
`floor` also counts lcov lines past the end of their source file. Only a
report that read an instrumented binary built from OTHER source has them
(on 2026-09-23 an uncleaned persistent target directory left earlier runs'
binaries for `cargo llvm-cov report` to read); they come with never-hit
lines inside the file too, so the number is not this commit's. The count
is reported as a warning and as `lines_past_eof` in the JSON. It cannot
be seen with --linemap (no sources).
"""

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def _load_stripper():
    spec = importlib.util.spec_from_file_location(
        "jscpd_prepare_sources", os.path.join(HERE, "jscpd-prepare-sources.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_PREP = _load_stripper()
CFG_TEST = _PREP.CFG_TEST
strip_test_modules = _PREP.strip_test_modules

# `mod name;` / `pub mod name;` / `pub(crate) mod name;` at column 0.
OUT_OF_LINE_MOD = re.compile(r"^(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")
# Lines that may sit between `#[cfg(test)]` and the item it applies to.
ATTR_OR_DOC = re.compile(r"^\s*(?:#\s*\[|///|//!|//|$)")


def parse_lcov(path):
    """{SF path: {line: hits}}; repeated records for one SF are summed."""
    data = {}
    current = None
    with open(path, encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.strip()
            if line.startswith("SF:"):
                current = data.setdefault(line[3:], {})
            elif line.startswith("DA:") and current is not None:
                parts = line[3:].split(",")
                try:
                    lineno, count = int(parts[0]), int(parts[1])
                except (IndexError, ValueError):
                    continue
                current[lineno] = current.get(lineno, 0) + count
            elif line == "end_of_record":
                current = None
    return data


class TestCode:
    """Answers "is line N of file F test code?" for repo-relative paths."""

    def __init__(self, root, linemap=None):
        self.root = root
        self.fixed = linemap is not None
        self.ranges = dict(linemap or {})  # rel -> [[s, e], ...] | "all"
        self.children = {}  # rel -> [child rel, ...] declared under #[cfg(test)]
        self.missing = set()

    def _read(self, rel):
        try:
            with open(os.path.join(self.root, rel), encoding="utf-8", errors="replace") as handle:
                return handle.read()
        except OSError:
            self.missing.add(rel)
            return None

    def _scan(self, rel):
        if rel in self.children:
            return
        text = None if self.fixed else self._read(rel)
        if text is None:
            self.children[rel] = []
            self.ranges.setdefault(rel, [])
            return
        _, removed = strip_test_modules(text)
        if self.ranges.get(rel) != "all":
            self.ranges[rel] = [list(r) for r in removed]
        self.children[rel] = test_mod_children(rel, text, self.root)

    def mark_test_only_files(self, universe):
        """Propagate "all" from every #[cfg(test)] `mod x;` to its file."""
        if self.fixed:
            return
        for rel in list(universe):
            self._scan(rel)
        queue = [c for rel in list(self.children) for c in self.children[rel]]
        while queue:
            child = queue.pop()
            if self.ranges.get(child) == "all":
                continue
            self.ranges[child] = "all"
            self._scan(child)
            text = self._read(child) or ""
            queue.extend(all_mod_children(child, text, self.root))

    def line_count(self, rel):
        """Lines in the source file, or None (no sources: fixed linemap)."""
        if self.fixed:
            return None
        text = self._read(rel)
        return None if text is None else len(text.splitlines())

    def is_test(self, rel, line):
        if rel not in self.ranges:
            self._scan(rel)
        spans = self.ranges.get(rel, [])
        if spans == "all":
            return True
        return any(start <= line <= end for start, end in spans)


def _module_dir(rel):
    base = os.path.basename(rel)
    if base in ("mod.rs", "lib.rs", "main.rs"):
        return os.path.dirname(rel)
    return rel[: -len(".rs")]


def _resolve_child(rel, name, root):
    directory = _module_dir(rel)
    for candidate in (f"{directory}/{name}.rs", f"{directory}/{name}/mod.rs"):
        candidate = candidate.lstrip("/")
        if os.path.isfile(os.path.join(root, candidate)):
            return candidate
    return None


def test_mod_children(rel, text, root):
    """Files declared by a column-0 `#[cfg(test)] mod name;`."""
    lines = text.split("\n")
    found = []
    for i, line in enumerate(lines):
        if not CFG_TEST.match(line):
            continue
        for j in range(i + 1, min(len(lines), i + 1 + _PREP.BRACE_LOOKAHEAD)):
            if lines[j].startswith((" ", "\t")):
                break
            m = OUT_OF_LINE_MOD.match(lines[j])
            if m:
                child = _resolve_child(rel, m.group(1), root)
                if child:
                    found.append(child)
                break
            if not ATTR_OR_DOC.match(lines[j]):
                break
    return found


def all_mod_children(rel, text, root):
    """Every out-of-line module a (test-only) file declares at column 0."""
    found = []
    for line in text.split("\n"):
        m = OUT_OF_LINE_MOD.match(line)
        if m:
            child = _resolve_child(rel, m.group(1), root)
            if child:
                found.append(child)
    return found


def resolve_sf(sf_path, root, known):
    """Map an lcov SF path (absolute, CI runner layout) to a repo-relative one."""
    parts = sf_path.replace("\\", "/").split("/")
    for i in range(len(parts)):
        rel = "/".join(parts[i:])
        if not rel:
            continue
        if rel in known or os.path.isfile(os.path.join(root, rel)):
            return rel
    return None


def _lcov_by_rel(lcov, root, known):
    out = {}
    unresolved = []
    for sf, lines in lcov.items():
        rel = resolve_sf(sf, root, known)
        if rel is None:
            unresolved.append(sf)
            continue
        merged = out.setdefault(rel, {})
        for lineno, count in lines.items():
            merged[lineno] = merged.get(lineno, 0) + count
    return out, unresolved


def _ranges(lines):
    """[3,4,5,9] -> "3-5, 9"."""
    out = []
    start = prev = None
    for n in sorted(lines):
        if start is None:
            start = prev = n
        elif n == prev + 1:
            prev = n
        else:
            out.append(f"{start}-{prev}" if start != prev else f"{start}")
            start = prev = n
    if start is not None:
        out.append(f"{start}-{prev}" if start != prev else f"{start}")
    return ", ".join(out)


def _emit(args, verdict, outputs, summary_lines, payload):
    text = "\n".join(summary_lines)
    print(text)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as handle:
            handle.write(text + "\n")
    if args.github_output:
        with open(args.github_output, "a", encoding="utf-8") as handle:
            handle.write(f"verdict={verdict}\n")
            for key, value in outputs.items():
                handle.write(f"{key}={value}\n")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
    if args.write_linemap:
        with open(args.write_linemap, "w", encoding="utf-8") as handle:
            json.dump(payload.get("_linemap", {}), handle, sort_keys=True)
    payload.pop("_linemap", None)
    return 1 if verdict == "fail" else 0


def _load_linemap(path):
    if not path:
        return None
    with open(path, encoding="utf-8") as handle:
        raw = json.load(handle)
    return {k: (v if v == "all" else [list(r) for r in v]) for k, v in raw.items()}


def cmd_floor(args):
    lcov = parse_lcov(args.lcov)
    linemap = _load_linemap(args.linemap)
    tests = TestCode(args.root, linemap)
    by_rel, unresolved = _lcov_by_rel(lcov, args.root, set(linemap or {}))
    tests.mark_test_only_files(by_rel)

    prod_hit = prod_total = test_hit = test_total = 0
    past_eof = {}
    for rel, lines in by_rel.items():
        length = tests.line_count(rel)
        if length is not None:
            beyond = sum(1 for lineno in lines if lineno > length)
            if beyond:
                past_eof[rel] = beyond
        for lineno, count in lines.items():
            if tests.is_test(rel, lineno):
                test_total += 1
                test_hit += count > 0
            else:
                prod_total += 1
                prod_hit += count > 0

    lines_out = []
    if prod_total == 0:
        verdict, pct = "fail", 0.0
        lines_out.append("### Coverage floor: FAILED (the report holds no production lines)")
    else:
        pct = prod_hit * 100.0 / prod_total
        verdict = "pass" if pct >= args.min else "fail"
        mark = "passed" if verdict == "pass" else "FAILED"
        lines_out.append(
            f"### Coverage floor: {mark} -- production code {pct:.2f}% "
            f"({prod_hit}/{prod_total} lines), floor {args.min:g}%"
        )
    all_total = prod_total + test_total
    if all_total:
        lines_out.append(
            f"Inline test code excluded: {test_total} lines "
            f"({test_total * 100.0 / all_total:.1f}% of instrumented), "
            f"{(test_hit * 100.0 / test_total) if test_total else 0:.1f}% hit; "
            f"all lines together {(prod_hit + test_hit) * 100.0 / all_total:.2f}%."
        )
    if unresolved:
        lines_out.append(
            f"::warning::{len(unresolved)} lcov source(s) not found in the checkout; "
            "counted as production: " + ", ".join(unresolved[:5])
        )
    if tests.missing:
        lines_out.append(f"::warning::unreadable sources, counted as production: {sorted(tests.missing)[:5]}")
    if past_eof:
        worst = sorted(past_eof.items(), key=lambda kv: -kv[1])[:5]
        lines_out.append(
            f"::warning title=Stale coverage objects::{sum(past_eof.values())} lcov line(s) lie past the end "
            f"of their source file in {len(past_eof)} file(s), e.g. "
            + ", ".join(f"{rel} ({n})" for rel, n in worst)
            + ". The report read instrumented binaries built from other source (a target directory "
            "that was not cleaned), so this number is not this commit's."
        )
    if verdict == "fail":
        lines_out.append(
            f"::error title=Coverage floor::Production line coverage is {pct:.2f}%, below the {args.min:g}% floor"
        )
    payload = {
        "gate": "floor",
        "verdict": verdict,
        "pct": round(pct, 2),
        "hit": prod_hit,
        "total": prod_total,
        "min": args.min,
        "test_lines_excluded": test_total,
        "lines_past_eof": sum(past_eof.values()),
        "_linemap": {k: v for k, v in tests.ranges.items() if v},
    }
    return _emit(args, verdict, {"pct": f"{pct:.2f}"}, lines_out, payload)


def added_lines(diff_text):
    """{file: set(line numbers)} of lines a `git diff -U0` adds."""
    added = {}
    current = None
    for line in diff_text.split("\n"):
        if line.startswith("+++ "):
            target = line[4:]
            current = target[2:] if target.startswith("b/") else None
        elif line.startswith("@@") and current:
            m = re.search(r"\+(\d+)(?:,(\d+))?", line)
            if m:
                start = int(m.group(1))
                count = int(m.group(2)) if m.group(2) is not None else 1
                added.setdefault(current, set()).update(range(start, start + count))
    return added


def cmd_newcode(args):
    if args.diff_file:
        with open(args.diff_file, encoding="utf-8", errors="replace") as handle:
            diff_text = handle.read()
    else:
        if not args.merge_base:
            print("newcode: --merge-base or --diff-file is required", file=sys.stderr)
            return 2
        proc = subprocess.run(
            ["git", "-C", args.root, "diff", "-U0", "--no-color", "--no-ext-diff",
             args.merge_base, "--", "*.rs"],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            print(f"::error::git diff against {args.merge_base} failed: {proc.stderr.strip()}")
            return 2
        diff_text = proc.stdout

    added = added_lines(diff_text)
    lcov = parse_lcov(args.lcov)
    linemap = _load_linemap(args.linemap)
    tests = TestCode(args.root, linemap)
    by_rel, _ = _lcov_by_rel(lcov, args.root, set(linemap or {}) | set(added))
    tests.mark_test_only_files(set(by_rel) | set(added))

    hit = total = test_added = 0
    uncovered = {}
    for rel, lines in sorted(added.items()):
        counts = by_rel.get(rel, {})
        for lineno in lines:
            if tests.is_test(rel, lineno):
                test_added += 1
                continue
            if lineno not in counts:
                continue  # not instrumented: blank, comment, declaration
            total += 1
            if counts[lineno] > 0:
                hit += 1
            else:
                uncovered.setdefault(rel, []).append(lineno)

    out = []
    pct = (hit * 100) // total if total else 0
    if not added:
        verdict = "na"
        out.append("### New code coverage: N/A (no Rust lines added)")
    elif total < args.min_lines:
        verdict = "na"
        out.append(
            f"### New code coverage: N/A ({total} instrumented production line(s) added, "
            f"fewer than {args.min_lines}; too few to judge)"
        )
    else:
        verdict = "pass" if pct >= args.min else "fail"
        mark = "passed" if verdict == "pass" else "FAILED"
        out.append(
            f"### New code coverage: {mark} -- {pct}% of new production lines "
            f"({hit}/{total}), threshold {args.min}%"
        )
    out.append(f"Lines added inside inline test code (not counted): {test_added}.")
    if args.merge_base:
        out.append(f"Diffed against merge base {args.merge_base}.")
    if uncovered:
        out.append("Uncovered new production lines:")
        out.append("```")
        for rel, nums in sorted(uncovered.items()):
            out.append(f"{rel}: {_ranges(nums)}")
        out.append("```")
    if verdict == "fail":
        out.append(
            f"::error title=New code coverage::{pct}% of the production lines this PR adds are "
            f"covered, below the {args.min}% threshold. Add tests for the lines listed above."
        )
    payload = {
        "gate": "newcode",
        "verdict": verdict,
        "pct": pct,
        "hit": hit,
        "total": total,
        "min": args.min,
        "test_lines_added": test_added,
        "merge_base": args.merge_base or "",
        "uncovered": {k: sorted(v) for k, v in uncovered.items()},
        "_linemap": {k: v for k, v in tests.ranges.items() if v},
    }
    return _emit(args, verdict, {"pct": str(pct), "hit": str(hit), "total": str(total)}, out, payload)


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("floor", "newcode"):
        p = sub.add_parser(name)
        p.add_argument("--lcov", required=True)
        p.add_argument("--root", default=".")
        p.add_argument("--linemap")
        p.add_argument("--write-linemap")
        p.add_argument("--summary")
        p.add_argument("--github-output")
        p.add_argument("--json")
    sub.choices["floor"].add_argument("--min", type=float, required=True)
    nc = sub.choices["newcode"]
    nc.add_argument("--min", type=int, required=True)
    nc.add_argument("--min-lines", type=int, default=10)
    nc.add_argument("--merge-base")
    nc.add_argument("--diff-file")
    args = parser.parse_args(argv[1:])
    return cmd_floor(args) if args.cmd == "floor" else cmd_newcode(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
