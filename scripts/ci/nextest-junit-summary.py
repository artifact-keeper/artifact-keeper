#!/usr/bin/env python3
"""Summarise nextest JUnit reports for the job summary (#6172).

Usage: nextest-junit-summary.py <title> <junit.xml>...

Prints Markdown (ci.yml appends it to $GITHUB_STEP_SUMMARY) and one
`::warning` / `::error` workflow command per flaky / failed test, so each is
visible on the run page without opening the log.

nextest's JUnit shapes, per <testcase>:
  * <flakyFailure> children and no <failure>/<error>: failed, then passed on
    a retry. FLAKY. Only a profile with retries (`nightly`) produces these;
    the blocking `ci` profile has `retries = 0`.
  * <failure> or <error>: failed on every attempt (<rerunFailure> /
    <rerunError> are the retries). FAILED.

Report only: the exit status is always 0, except 2 on bad usage. The test
step's own exit status is the verdict. A missing or unreadable report is
named in the summary (the step was skipped, or never ran its tests), not
treated as an error.
"""

import sys
import xml.etree.ElementTree as ET


def classify(path):
    """(tests, flaky, failed) for one report; flaky/failed are test names."""
    root = ET.parse(path).getroot()
    tests, flaky, failed = 0, [], []
    for case in root.iter("testcase"):
        tests += 1
        name = f"{case.get('classname', '')} {case.get('name', '')}".strip()
        tags = {child.tag for child in case}
        if tags & {"failure", "error"}:
            failed.append(name)
        elif tags & {"flakyFailure", "flakyError"}:
            attempts = sum(1 for c in case if c.tag in ("flakyFailure", "flakyError"))
            flaky.append(f"{name} (passed after {attempts} failed attempt{'s' if attempts != 1 else ''})")
    return tests, flaky, failed


def esc(text):
    """Escape a workflow-command message (`%`, CR, LF)."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def main(argv):
    if len(argv) < 3:
        print("usage: nextest-junit-summary.py <title> <junit.xml>...", file=sys.stderr)
        return 2
    title, paths = argv[1], argv[2:]
    out = [f"### {title}", ""]
    all_flaky, all_failed, missing = [], [], []
    total = 0
    for path in paths:
        try:
            tests, flaky, failed = classify(path)
        except (OSError, ET.ParseError) as exc:
            missing.append(f"`{path}`: {exc.__class__.__name__}")
            continue
        total += tests
        all_flaky += flaky
        all_failed += failed

    read = len(paths) - len(missing)
    out.append(
        f"{total} tests in {read} JUnit report(s): "
        f"**{len(all_failed)} failed**, **{len(all_flaky)} flaky** (passed on retry)."
    )
    if all_flaky:
        out += ["", "**Flaky** (green, but failed at least once on the same bytes):", ""]
        out += [f"- `{n}`" for n in all_flaky]
    if all_failed:
        out += ["", "**Failed:**", ""]
        out += [f"- `{n}`" for n in all_failed]
    if missing:
        out += ["", "**No report** (the step was skipped, its build failed, or the run did not start):", ""]
        out += [f"- {m}" for m in missing]
    print("\n".join(out) + "\n")

    for name in all_flaky:
        print(f"::warning title=Flaky test ({esc(title)})::{esc(name)}", file=sys.stderr)
    for name in all_failed:
        print(f"::error title=Failed test ({esc(title)})::{esc(name)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
