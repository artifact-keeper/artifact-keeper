#!/usr/bin/env python3
"""Copy Rust sources for the duplication gate with inline test modules removed.

WHY (#3495)
-----------
The "Code duplication gate" in `.github/workflows/ci.yml` measures changed
Rust source with jscpd. jscpd's defaults are `maxLines: 1000` and
`maxSize: "100kb"`, and a file over EITHER limit is skipped silently -- no
error, no entry in the report, nothing in the log. On this repository that
was 152 of 336 files under `backend/src` (45%), 125 of them not on
`.jscpd.json`'s ignore list, including `services/`, `storage/` and
`middleware/` files that the config's own comment says must keep failing the
gate. A pull request whose Rust changes landed only in one of those files got
its duplication verdict computed from an empty file set and passed.

Raising the limits is necessary but not sufficient. `backend/src` is 474k
lines, of which 209k are production code: **56% of it is inline
`#[cfg(test)]` modules** -- `repositories.rs` alone is 26,328 lines, 22,164
of them test code. Measured with the limits raised and nothing else changed,
the whole non-ignored tree scores 3.38% and 23 of the last 44 code-touching
commits on `main` would have failed the 3% gate, with 58 of 61 clones in the
issue's own sample sitting entirely inside `#[cfg(test)]` modules. That is
not a duplication problem, it is the gate measuring something it never meant
to measure: `.jscpd.json` already ignores `**/*_test.rs` and `**/tests/**`,
and the CI step already drops `_test`/`tests/` paths from the changed-file
list. Inline test modules were exempt only by accident, because the files
containing them were too big for jscpd to open. Stripping them makes the
same policy explicit: the whole tree then scores 2.25% and 2 of those 44
commits exceed the threshold, both on genuine production-code clones.

WHAT IT DOES
------------
For each source path given, writes a copy under <outdir> at the SAME relative
path with every top-level `#[cfg(test)]` item removed, and writes a JSON map
of the removed line ranges so the caller can translate a line number in the
stripped copy back to the original file.

The end of a `#[cfg(test)]` item is found as the first line that is exactly
`}` in column 0. That is exact rather than heuristic here because `cargo fmt
--check` is enforced in CI (the `check-rust` job), so a top-level item always
closes with an unindented brace and every nested brace is indented.
Attributes that do not introduce a braced item (`#[cfg(test)] use ...;`,
`#[cfg(test)] mod tests;`) are left alone.
"""

import json
import os
import re
import sys

# `#[cfg(test)]` / `#[cfg(all(test, ...))]` at COLUMN 0 only.
#
# The column matters. `cargo fmt` indents every nested item, so an attribute
# in column 0 is a top-level item and its closing brace is the next `}` in
# column 0. An INDENTED `#[cfg(test)]` sits inside some other item -- a
# test-only struct field, a test-only branch, a helper module nested in
# another module -- and the next column-0 `}` closes the ENCLOSING item, so
# treating it as a boundary would delete real production code. There are 22
# files under `backend/src` with indented `#[cfg(test)]` attributes; they are
# deliberately left in place, and they are individually small.
CFG_TEST = re.compile(r"^#\s*\[\s*cfg\s*\(\s*(?:all\s*\(\s*)?test\s*[,)]")

# How far past the attribute we look for the item's opening brace. Attributes
# stack (`#[cfg(test)]` + `#[allow(...)]` + a doc comment), but not deeply.
BRACE_LOOKAHEAD = 8


def strip_test_modules(text):
    """Return (kept_lines, removed_ranges) where ranges are 1-based inclusive."""
    lines = text.split("\n")
    kept = []
    removed = []
    i = 0
    while i < len(lines):
        if CFG_TEST.match(lines[i]):
            brace_at = None
            j = i
            while j < len(lines) and j - i <= BRACE_LOOKAHEAD:
                if "{" in lines[j]:
                    brace_at = j
                    break
                if lines[j].rstrip().endswith(";"):
                    break
                j += 1
            if brace_at is not None:
                k = brace_at + 1
                while k < len(lines) and lines[k] != "}":
                    k += 1
                if k < len(lines):
                    removed.append((i + 1, k + 1))
                    i = k + 1
                    continue
                # Unterminated: leave the file alone rather than guess.
        kept.append(lines[i])
        i += 1
    return kept, removed


def main(argv):
    if len(argv) < 3:
        print(
            "usage: jscpd-prepare-sources.py <outdir> <linemap.json> <file.rs>...",
            file=sys.stderr,
        )
        return 2

    outdir, mapfile = argv[1], argv[2]
    sources = argv[3:]
    line_map = {}

    for path in sources:
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        kept, removed = strip_test_modules(text)

        target = os.path.join(outdir, path)
        os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
        with open(target, "w", encoding="utf-8") as handle:
            handle.write("\n".join(kept))

        line_map[path] = removed
        original = len(text.split("\n"))
        stripped_lines = sum(end - start + 1 for start, end in removed)
        if stripped_lines:
            print(
                f"  {path}: {original} lines, {stripped_lines} in "
                f"{len(removed)} inline test module(s) not measured"
            )
        else:
            print(f"  {path}: {original} lines, no inline test module")

    with open(mapfile, "w", encoding="utf-8") as handle:
        json.dump(line_map, handle)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
