#!/usr/bin/env python3
"""Whole-repository duplication report for the scheduled jscpd scan (#1619).

WHY
---
The per-PR "Code duplication gate" in `.github/workflows/ci.yml` measures
only the Rust files a pull request changes. A duplicated surface that is
already on `main` therefore passes indefinitely: every PR nudges a few lines
and the baseline itself is never measured. `proxy_service.rs` and
`proxy_helpers.rs` grew five copy-paste families that way (#1618). This
script is the complementary whole-tree view, run weekly by
`.github/workflows/scheduled-tests.yml` (job `duplication-report`).

It measures exactly what the per-PR gate would measure if every file
changed at once: the same `.jscpd.json` ignore list and size limits, the same
inline-`#[cfg(test)]` stripping (`jscpd-prepare-sources.py`), the same
`--min-lines 10`. So the number here is comparable with the gate's.

COMMANDS
--------
  list-sources <config> <root>
      Print every `*.rs` file under <root> that `.jscpd.json` does not ignore,
      one per line, sorted.

  summarize <report.json> <linemap.json> <sources.txt> <baseline.json>
            [--top N] [--summary FILE]
      Read the jscpd JSON report and write a Markdown summary (total
      duplication, the largest clone pairs with line numbers translated back
      to the real files, the files carrying the most duplicated lines).
      Exit status:
        0  measured, and not above the baseline's `percentage + tolerance`
        1  measured, and ABOVE it: whole-repo duplication regressed
        2  not a measurement: a source that should have been analysed is
           missing from the report (jscpd skips silently, #3495)
"""

import json
import os
import re
import sys

MIN_LINES = 10


def glob_to_regex(pattern):
    """Translate a jscpd/gitignore-style glob into an anchored regex.

    `**/` matches zero or more whole directories, `**` anything, `*` and `?`
    stay within one path segment.
    """
    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def is_ignored(path, patterns):
    return any(p.match(path) for p in patterns)


def list_sources(config_path, root):
    cfg = json.load(open(config_path))
    patterns = [glob_to_regex(p) for p in cfg.get("ignore", [])]
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in filenames:
            if not name.endswith(".rs"):
                continue
            path = os.path.normpath(os.path.join(dirpath, name))
            if not is_ignored(path, patterns):
                found.append(path)
    return sorted(found)


def to_original(line_map, name, line):
    """Translate a line in the stripped copy back to the original file.

    Same arithmetic as the per-PR gate's clone listing in ci.yml.
    """
    shift = 0
    for start, end in line_map.get(name, []):
        if start <= line + shift:
            shift += end - start + 1
    return line + shift


def clone_lines(dup):
    first = dup["firstFile"]
    return first["endLoc"]["line"] - first["startLoc"]["line"] + 1


def missing_sources(report, sources, prepared_line_counts):
    """Sources jscpd should have analysed but did not report."""
    analysed = set(
        report.get("statistics", {})
        .get("formats", {})
        .get("rust", {})
        .get("sources", {})
        .keys()
    )
    return [
        s
        for s in sources
        if s not in analysed and prepared_line_counts.get(s, 0) >= MIN_LINES
    ]


def summarize(report, line_map, baseline, missing, top):
    """Return (markdown, exit_status)."""
    total = report.get("statistics", {}).get("total", {})
    pct = float(total.get("percentage", 0))
    dup_lines = int(total.get("duplicatedLines", 0))
    lines = int(total.get("lines", 0))
    sources = int(total.get("sources", 0))
    dups = report.get("duplicates", [])

    md = ["## Whole-repo code duplication (jscpd)", ""]
    if missing:
        md.append(
            f"**NOT A MEASUREMENT:** {len(missing)} source file(s) were not "
            "analysed by jscpd, so the figure below does not cover the tree (#3495)."
        )
        md.append("")
        for path in missing[:top]:
            md.append(f"- `{path}`")
        md.append("")

    base_pct = float(baseline.get("percentage", 0))
    tolerance = float(baseline.get("tolerance", 0))
    limit = base_pct + tolerance
    md.append("| | |")
    md.append("|---|---|")
    md.append(f"| Duplication | **{pct:.2f}%** ({dup_lines:,} of {lines:,} lines) |")
    md.append(f"| Clone pairs | {len(dups):,} |")
    md.append(f"| Files analysed | {sources:,} |")
    md.append(
        f"| Baseline | {base_pct:.2f}% + {tolerance:.2f} tolerance "
        f"(`.github/duplication-baseline.json`) |"
    )
    md.append("")

    if missing:
        status = 2
    elif pct > limit + 1e-9:
        status = 1
        md.append(
            f"**REGRESSION:** {pct:.2f}% is above the baseline limit {limit:.2f}%. "
            "The per-PR gate measures only changed files, so this is "
            "duplication that accumulated across several merges (#1619)."
        )
        md.append("")
    else:
        status = 0
        if pct < base_pct - tolerance:
            md.append(
                f"Duplication is down from the {base_pct:.2f}% baseline; lower "
                "`percentage` in `.github/duplication-baseline.json` to lock "
                "the improvement in."
            )
            md.append("")

    ranked = sorted(
        dups,
        key=lambda d: (-clone_lines(d), d["firstFile"]["name"], d["firstFile"]["startLoc"]["line"]),
    )
    if ranked:
        md.append(f"### Largest clone pairs (top {min(top, len(ranked))})")
        md.append("")
        md.append("| Lines | First | Second |")
        md.append("|---:|---|---|")
        for d in ranked[:top]:
            a, b = d["firstFile"], d["secondFile"]
            a1 = to_original(line_map, a["name"], a["startLoc"]["line"])
            a2 = to_original(line_map, a["name"], a["endLoc"]["line"])
            b1 = to_original(line_map, b["name"], b["startLoc"]["line"])
            b2 = to_original(line_map, b["name"], b["endLoc"]["line"])
            md.append(
                f"| {clone_lines(d)} | `{a['name']}:{a1}-{a2}` | `{b['name']}:{b1}-{b2}` |"
            )
        md.append("")

    per_file = report.get("statistics", {}).get("formats", {}).get("rust", {}).get("sources", {})
    hot = sorted(
        ((name, s) for name, s in per_file.items() if s.get("duplicatedLines", 0) > 0),
        key=lambda item: (-item[1].get("duplicatedLines", 0), item[0]),
    )
    if hot:
        md.append(f"### Files with the most duplicated lines (top {min(top, len(hot))})")
        md.append("")
        md.append("| Duplicated lines | % of file | File |")
        md.append("|---:|---:|---|")
        for name, s in hot[:top]:
            md.append(
                f"| {s.get('duplicatedLines', 0):,} | {float(s.get('percentage', 0)):.1f}% | `{name}` |"
            )
        md.append("")

    md.append(
        "Inline `#[cfg(test)]` modules, `*_test.rs`, `tests/` and the "
        "`.jscpd.json` format-handler exemptions are out of scope, as in the per-PR gate."
    )
    return "\n".join(md) + "\n", status


def prepared_line_counts(prepared_root, sources):
    counts = {}
    for s in sources:
        path = os.path.join(prepared_root, s)
        if os.path.exists(path):
            with open(path, encoding="utf-8", errors="replace") as handle:
                counts[s] = len(handle.read().split("\n"))
    return counts


def main(argv):
    if len(argv) >= 4 and argv[1] == "list-sources":
        for path in list_sources(argv[2], argv[3]):
            print(path)
        return 0

    if len(argv) >= 6 and argv[1] == "summarize":
        report_path, map_path, sources_path, baseline_path = argv[2:6]
        rest = argv[6:]
        top, summary_path, prepared_root = 15, None, None
        while rest:
            flag = rest.pop(0)
            if flag == "--top":
                top = int(rest.pop(0))
            elif flag == "--summary":
                summary_path = rest.pop(0)
            elif flag == "--prepared":
                prepared_root = rest.pop(0)
            else:
                print(f"unknown option {flag}", file=sys.stderr)
                return 2

        sources = [l for l in open(sources_path).read().split("\n") if l]
        if not os.path.exists(report_path):
            md = (
                "## Whole-repo code duplication (jscpd)\n\n"
                f"**NOT A MEASUREMENT:** jscpd wrote no report for {len(sources)} "
                "source file(s) (#3495).\n"
            )
            status = 2
        else:
            report = json.load(open(report_path))
            line_map = json.load(open(map_path)) if os.path.exists(map_path) else {}
            baseline = json.load(open(baseline_path))
            counts = (
                prepared_line_counts(prepared_root, sources)
                if prepared_root
                else {s: MIN_LINES for s in sources}
            )
            missing = missing_sources(report, sources, counts)
            md, status = summarize(report, line_map, baseline, missing, top)

        sys.stdout.write(md)
        if summary_path:
            with open(summary_path, "a", encoding="utf-8") as handle:
                handle.write(md)
        return status

    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
