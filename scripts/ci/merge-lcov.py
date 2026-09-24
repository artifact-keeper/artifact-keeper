#!/usr/bin/env python3
"""Merge the per-shard lcov reports of the unit-test matrix into one.

The unit-test job runs as a matrix of test shards (scripts/ci/test-shards.py).
Every leg builds the WHOLE production crate instrumented, plus its shard's
inline test modules, and writes its own `lcov.info`. So:

  * a production line appears in every shard's report, and its merged hit
    count is the SUM over shards (a line one shard's tests reach and
    another's do not is covered, exactly as in a single run of all tests);
  * a test-module line appears in exactly one shard's report (the others
    compiled that module out), and passes through unchanged.

The union of lines, with summed counts, is therefore the report a single
unsharded run would have produced, and the coverage gates read it without
any change to their logic.

Usage:
    merge-lcov.py --output merged/lcov.info [--totals merged/totals.json]
                  [--summary merged/summary.txt] shard1/lcov.info shard2/...

`--totals` writes the same JSON shape `cargo llvm-cov report --json
--summary-only` produces (`data[0].totals.lines.{count,covered,percent}`),
computed from the merged DA lines, so the 50% floor keeps reading
`lines.percent`. It is not the number llvm-cov itself reports: llvm-cov's
summary also counts lines the lcov export does not emit (one unsharded run:
89.83% llvm-cov, 90.45% lcov DA lines). `--summary` writes a per-file
line-coverage table (the region/function columns of `cargo llvm-cov report
--summary-only` cannot be recomputed from lcov and are omitted). With `--src-root`, the summary also
reports production-only coverage: lines outside the column-0
`#[cfg(test)]` items that scripts/ci/jscpd-prepare-sources.py strips.
"""

import argparse
import importlib.util
import json
import os
import sys


class Record:
    __slots__ = ("lines", "fn_line", "fn_hits", "branches")

    def __init__(self):
        self.lines = {}  # line -> hits
        self.fn_line = {}  # name -> first line
        self.fn_hits = {}  # name -> hits
        self.branches = {}  # (line, block, branch) -> hits or None ("-")


def parse_into(path, records):
    """Fold one lcov file into `records` (source path -> Record)."""
    rec = None
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if line.startswith("SF:"):
                rec = records.setdefault(line[3:], Record())
            elif rec is None:
                continue
            elif line.startswith("DA:"):
                parts = line[3:].split(",")
                num, hits = int(parts[0]), int(parts[1])
                rec.lines[num] = rec.lines.get(num, 0) + hits
            elif line.startswith("FN:"):
                num, name = line[3:].split(",", 1)
                rec.fn_line.setdefault(name, int(num))
            elif line.startswith("FNDA:"):
                hits, name = line[5:].split(",", 1)
                rec.fn_hits[name] = rec.fn_hits.get(name, 0) + int(hits)
            elif line.startswith("BRDA:"):
                num, block, branch, taken = line[5:].split(",", 3)
                k = (int(num), block, branch)
                t = None if taken == "-" else int(taken)
                prev = rec.branches.get(k)
                if t is None:
                    rec.branches.setdefault(k, None)
                else:
                    rec.branches[k] = (prev or 0) + t
            elif line == "end_of_record":
                rec = None
            # FNF/FNH/LF/LH/BRF/BRH are recomputed on write.


def write_lcov(records, path):
    with open(path, "w", encoding="utf-8") as out:
        for src in sorted(records):
            rec = records[src]
            out.write(f"SF:{src}\n")
            for name, num in sorted(rec.fn_line.items(), key=lambda kv: (kv[1], kv[0])):
                out.write(f"FN:{num},{name}\n")
            for name in sorted(rec.fn_line, key=lambda n: (rec.fn_line[n], n)):
                out.write(f"FNDA:{rec.fn_hits.get(name, 0)},{name}\n")
            out.write(f"FNF:{len(rec.fn_line)}\n")
            out.write(f"FNH:{sum(1 for n in rec.fn_line if rec.fn_hits.get(n, 0) > 0)}\n")
            for (num, block, branch), taken in sorted(rec.branches.items()):
                out.write(f"BRDA:{num},{block},{branch},{'-' if taken is None else taken}\n")
            if rec.branches:
                out.write(f"BRF:{len(rec.branches)}\n")
                out.write(f"BRH:{sum(1 for t in rec.branches.values() if t)}\n")
            for num in sorted(rec.lines):
                out.write(f"DA:{num},{rec.lines[num]}\n")
            out.write(f"LF:{len(rec.lines)}\n")
            out.write(f"LH:{sum(1 for h in rec.lines.values() if h > 0)}\n")
            out.write("end_of_record\n")


def pct(covered, count):
    return 100.0 * covered / count if count else 0.0


def test_ranges_loader(src_root):
    """strip_test_modules() from jscpd-prepare-sources.py, the repo's one
    definition of "inline test module" for the coverage/duplication gates."""
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location(
        "jscpd_prepare_sources", os.path.join(here, "jscpd-prepare-sources.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    cache = {}

    def ranges(sf):
        rel = sf
        marker = "/backend/"
        if marker in sf:
            rel = "backend/" + sf.split(marker, 1)[1]
        if rel not in cache:
            path = os.path.join(src_root, rel)
            if os.path.exists(path):
                with open(path, encoding="utf-8", errors="replace") as fh:
                    cache[rel] = mod.strip_test_modules(fh.read())[1]
            else:
                cache[rel] = []
        return cache[rel]

    return ranges


def main(argv):
    ap = argparse.ArgumentParser(description="Merge lcov reports (summed hits).")
    ap.add_argument("--output", required=True)
    ap.add_argument("--totals")
    ap.add_argument("--summary")
    ap.add_argument("--src-root", help="repo root, for the production-only figure")
    ap.add_argument("inputs", nargs="+")
    args = ap.parse_args(argv[1:])

    records = {}
    for path in args.inputs:
        parse_into(path, records)
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    write_lcov(records, args.output)

    count = sum(len(r.lines) for r in records.values())
    covered = sum(sum(1 for h in r.lines.values() if h > 0) for r in records.values())
    fn_count = sum(len(r.fn_line) for r in records.values())
    fn_covered = sum(sum(1 for n in r.fn_line if r.fn_hits.get(n, 0) > 0)
                     for r in records.values())

    prod = None
    if args.src_root:
        ranges = test_ranges_loader(args.src_root)
        pc = ph = 0
        for sf, rec in records.items():
            rr = ranges(sf)
            for num, hits in rec.lines.items():
                if any(a <= num <= b for a, b in rr):
                    continue
                pc += 1
                ph += hits > 0
        prod = (ph, pc)

    print(f"merged {len(args.inputs)} report(s): {len(records)} files, "
          f"lines {covered}/{count} = {pct(covered, count):.2f}%")
    if prod:
        print(f"production-only lines (outside inline test modules): "
              f"{prod[0]}/{prod[1]} = {pct(*prod):.2f}%")

    if args.totals:
        totals = {
            "lines": {"count": count, "covered": covered, "percent": pct(covered, count)},
            "functions": {"count": fn_count, "covered": fn_covered,
                          "percent": pct(fn_covered, fn_count)},
        }
        doc = {"type": "llvm.coverage.json.export", "version": "merged-lcov",
               "data": [{"totals": totals}]}
        if prod:
            doc["data"][0]["production_lines"] = {
                "count": prod[1], "covered": prod[0], "percent": pct(*prod)}
        with open(args.totals, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1)

    if args.summary:
        common = os.path.commonpath(list(records)) if records else ""
        width = max([len(os.path.relpath(s, common)) for s in records] + [8])
        with open(args.summary, "w", encoding="utf-8") as fh:
            fh.write(f"{'Filename':<{width}}  {'Lines':>8} {'Missed':>8} {'Cover':>8}\n")
            fh.write("-" * (width + 28) + "\n")
            for sf in sorted(records):
                rec = records[sf]
                n = len(rec.lines)
                h = sum(1 for x in rec.lines.values() if x > 0)
                fh.write(f"{os.path.relpath(sf, common):<{width}}  {n:>8} {n - h:>8} "
                         f"{pct(h, n):>7.2f}%\n")
            fh.write("-" * (width + 28) + "\n")
            fh.write(f"{'TOTAL':<{width}}  {count:>8} {count - covered:>8} "
                     f"{pct(covered, count):>7.2f}%\n")
            if prod:
                fh.write(f"{'PRODUCTION (outside inline test modules)':<{width}}  "
                         f"{prod[1]:>8} {prod[1] - prod[0]:>8} {pct(*prod):>7.2f}%\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
