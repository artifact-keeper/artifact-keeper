#!/usr/bin/env python3
"""CHANGELOG fragments: validate them, render them, assemble them at a cut.

WHY
---
Every PR used to add its bullet under `## [Unreleased]` in CHANGELOG.md. 76 %
of merges to main touched that one file, so every merge put the other open
PRs into conflict -- all five conflicting PRs in the 2026-09 CI survey
conflicted on CHANGELOG.md and nothing else -- and each rebase re-ran the
whole CI pipeline. 69 % of force-pushes landed within an hour of a merge to
main. The shared file was the queue.

So each PR now adds ONE file, `changes/unreleased/<number>-<slug>.md`, that no
other PR touches, and the release prep renders all of them into the new
`## [X.Y.Z] - <date>` section (scripts/release/assemble-changelog.sh, which
calls `assemble` below). CHANGELOG.md itself is written once per release.

FRAGMENT FORMAT
---------------
    ---
    section: Fixed
    issues: [#4145, #4129]
    ---
    - **Bold lead sentence** (#4145, #4129). The why and the what, exactly as
      the bullet would read in CHANGELOG.md.

      Further paragraphs are indented two spaces, as in CHANGELOG.md.

  * name       `<pr-or-issue-number>-<slug>.md`, slug lowercase `[a-z0-9-]`;
  * section    one of Added, Changed, Deprecated, Removed, Fixed, Security
               (Keep a Changelog 1.1.0, rendered in that order);
  * issues     the `#N` references the entry is about, non-empty, each of
               which must also appear in the body (so the rendered CHANGELOG,
               which is what release-preflight check 5 reads, carries it);
  * body       exactly ONE top-level `- ` bullet, byte for byte what would
               have gone into CHANGELOG.md, continuation paragraphs allowed.

TRANSITION
----------
Bullets still written under `## [Unreleased]` in CHANGELOG.md (a PR opened
before fragments existed) are not an error. `assemble` merges them with the
fragments, section by section, and they come first within their section in
the order they were written. Headings that are not one of the six sections
(`### Sponsors`, `### Thank You`, `### Upgrade note -- ...`) are carried
through verbatim.

SUBCOMMANDS (exit 0 ok, 1 invalid input or refused, 2 usage/infra)
  validate [--dir D] [FILE...]    validate every fragment in D (default
                                  changes/unreleased), or just FILEs
  render-fragments [--dir D]      print the fragments as `### Section` lists
  assemble VERSION [--date D] [--changelog F] [--dir D] [--check] [--append]
                                  write the `## [VERSION]` section into F and
                                  delete the fragments; --check prints the
                                  section and changes nothing; --append merges
                                  into an existing, untagged `## [VERSION]`
                                  directly below [Unreleased]
"""

import argparse
import datetime
import os
import re
import sys

SECTIONS = ["Added", "Changed", "Deprecated", "Removed", "Fixed", "Security"]

# The one line left under `## [Unreleased]`. Recognised (and dropped) when a
# cut re-renders the section, so it never leaks into a release.
POINTER = ("New entries go in [`changes/unreleased/`](changes/unreleased/), "
           "one file per PR; see [`changes/README.md`](changes/README.md).")

NAME_RE = re.compile(r"^([0-9]+)-[a-z0-9]+(?:-[a-z0-9]+)*\.md$")
ISSUE_LIST_RE = re.compile(r"^\[\s*(#[0-9]+(?:\s*,\s*#[0-9]+)*)?\s*\]$")
REF_RE = re.compile(r"#[0-9]{2,}")
ALLOWED_EXTRA = {".gitkeep"}

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))


class Fragment:
    def __init__(self, path, number, section, issues, body):
        self.path = path
        self.name = os.path.basename(path)
        self.number = number
        self.section = section
        self.issues = issues
        self.body = body

    def sort_key(self):
        return (self.number, self.name)


def strip_blank_edges(lines):
    """Drop leading and trailing whitespace-only lines, keep everything else."""
    start, end = 0, len(lines)
    while start < end and not lines[start].strip():
        start += 1
    while end > start and not lines[end - 1].strip():
        end -= 1
    return lines[start:end]


def parse_fragment(path, text=None):
    """Return (Fragment or None, [errors], [warnings])."""
    errors, warnings = [], []
    name = os.path.basename(path)
    m = NAME_RE.match(name)
    if not m:
        errors.append(
            f"file name '{name}' is not '<pr-or-issue-number>-<slug>.md' "
            "(slug: lowercase letters, digits and single hyphens)")
    if text is None:
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
        except OSError as exc:
            return None, [f"cannot read: {exc}"], warnings
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None, errors + ["not valid UTF-8"], warnings
    if "\r" in text:
        errors.append("contains a carriage return; use LF line endings")
        return None, errors, warnings
    lines = text.split("\n")
    if not lines or lines[0] != "---":
        errors.append("must start with a '---' front-matter line")
        return None, errors, warnings
    try:
        close = lines.index("---", 1)
    except ValueError:
        errors.append("front matter is not closed by a '---' line")
        return None, errors, warnings

    meta = {}
    for ln in lines[1:close]:
        if not ln.strip():
            continue
        if ":" not in ln:
            errors.append(f"front-matter line is not 'key: value': {ln!r}")
            continue
        key, value = ln.split(":", 1)
        key, value = key.strip(), value.strip()
        if key in meta:
            errors.append(f"front-matter key '{key}' appears twice")
        meta[key] = value
    unknown = sorted(set(meta) - {"section", "issues"})
    if unknown:
        errors.append(f"unknown front-matter key(s): {', '.join(unknown)} "
                      "(only 'section' and 'issues' are read)")

    section = meta.get("section")
    if section is None:
        errors.append("front matter has no 'section:'")
    elif section not in SECTIONS:
        errors.append(f"section '{section}' is not one of {', '.join(SECTIONS)}")

    issues = []
    raw_issues = meta.get("issues")
    if raw_issues is None:
        errors.append("front matter has no 'issues:' (e.g. 'issues: [#1234]')")
    else:
        im = ISSUE_LIST_RE.match(raw_issues)
        if not im:
            errors.append(f"issues must be a list like '[#1234, #1235]', got {raw_issues!r}")
        elif im.group(1):
            issues = [s.strip() for s in im.group(1).split(",")]
        if im and not issues:
            errors.append("issues is empty: an entry must cite the issue or PR it is about")

    body_lines = strip_blank_edges(lines[close + 1:])
    body = "\n".join(body_lines)
    if not body.strip():
        errors.append("body is empty: the bullet itself goes below the front matter")
    else:
        if not body_lines[0].startswith("- "):
            errors.append("body must start with a top-level '- ' bullet")
        tops = [ln for ln in body_lines if ln.startswith("- ")]
        if len(tops) > 1:
            errors.append(f"body has {len(tops)} top-level '- ' bullets; one fragment is one entry")
        heads = [ln for ln in body_lines if re.match(r"^#{1,6} ", ln)]
        if heads:
            errors.append(f"body contains a Markdown heading ({heads[0]!r}); "
                          "the section comes from 'section:'")
        for ref in issues:
            if not re.search(re.escape(ref) + r"(?![0-9])", body):
                errors.append(f"issues lists {ref} but the body never cites it")
        if body_lines and body_lines[0].startswith("- ") and not REF_RE.search(body_lines[0]):
            warnings.append("the lead '- ' line cites no '#NNNN'; release-preflight check 5 "
                            "reconciles each entry by the first reference on that line")

    if errors:
        return None, errors, warnings
    return Fragment(path, int(m.group(1)), section, issues, body), errors, warnings


def list_dir(frag_dir):
    """Return (fragment paths, [(path, error)]) for everything in frag_dir."""
    paths, problems = [], []
    if not os.path.isdir(frag_dir):
        return paths, problems
    for name in sorted(os.listdir(frag_dir)):
        full = os.path.join(frag_dir, name)
        if name in ALLOWED_EXTRA:
            continue
        if os.path.isdir(full):
            problems.append((full, "subdirectories are not read; fragments live directly in "
                                   f"{frag_dir}"))
            continue
        paths.append(full)
    return paths, problems


def check_changes_root(frag_dir):
    """Anything under changes/ that is neither the README nor unreleased/ is a
    fragment in the wrong place -- it would silently never be assembled."""
    problems = []
    root = os.path.dirname(os.path.abspath(frag_dir))
    if os.path.basename(root) != "changes" or not os.path.isdir(root):
        return problems
    for name in sorted(os.listdir(root)):
        if name in ("README.md", os.path.basename(os.path.abspath(frag_dir))):
            continue
        problems.append((os.path.join(root, name),
                         "not read by the assembler: fragments go in "
                         f"{os.path.relpath(os.path.abspath(frag_dir), os.getcwd())}/"))
    return problems


def load_all(frag_dir, files=None, check_root=True, out=sys.stdout):
    """Return (fragments, error count). Prints GitHub annotations to `out`:
    stdout for the CI gate, stderr where stdout carries rendered Markdown."""
    problems = []
    if files:
        paths = list(files)
    else:
        paths, problems = list_dir(frag_dir)
        if check_root:
            problems += check_changes_root(frag_dir)
    frags, nerr = [], 0
    for path, msg in problems:
        print(f"::error file={path}::{msg}", file=out)
        nerr += 1
    for path in paths:
        frag, errors, warnings = parse_fragment(path)
        for w in warnings:
            print(f"::warning file={path}::{w}", file=out)
        for e in errors:
            print(f"::error file={path}::{e}", file=out)
        nerr += len(errors)
        if frag:
            frags.append(frag)
    return frags, nerr


# ── CHANGELOG parsing ──────────────────────────────────────────────────────


class Block:
    """One `### ` subsection: its heading, the prose before its first bullet,
    and its entries (each a list of lines, blank edges stripped)."""

    def __init__(self, heading):
        self.heading = heading
        self.preamble = []
        self.entries = []


def parse_body(lines):
    """Split a version section's body (the lines after its `## [` heading)
    into (preamble lines, [Block])."""
    preamble, blocks, cur, entry = [], [], None, None

    def close_entry():
        nonlocal entry
        if entry is not None:
            cur.entries.append(strip_blank_edges(entry))
            entry = None

    for ln in lines:
        if ln.startswith("### "):
            if cur is not None:
                close_entry()
            cur = Block(ln[4:].rstrip())
            blocks.append(cur)
            continue
        if cur is None:
            preamble.append(ln)
            continue
        is_known = cur.heading in SECTIONS
        if is_known and ln.startswith("- "):
            close_entry()
            entry = [ln]
        elif entry is not None:
            entry.append(ln)
        else:
            cur.preamble.append(ln)
    if cur is not None:
        close_entry()
    preamble = [ln for ln in strip_blank_edges(preamble) if ln.strip() != POINTER]
    return strip_blank_edges(preamble), blocks


def split_changelog(text):
    """Return (header lines, [(heading line, body lines)])."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    header, sections, cur = [], [], None
    for ln in lines:
        if ln.startswith("## ["):
            cur = (ln, [])
            sections.append(cur)
        elif cur is None:
            header.append(ln)
        else:
            cur[1].append(ln)
    return header, sections


def merge(sources, fragments):
    """Merge parsed bodies (in priority order) and fragments into one body.

    Returns rendered lines. Known sections come out in Keep-a-Changelog order;
    any other heading keeps its place relative to them: the ones that preceded
    every known heading in the source go first (Sponsors / Thank You, as the
    CLAUDE.md example writes them), the rest after Security.
    """
    preamble = []
    known = {s: Block(s) for s in SECTIONS}
    lead, tail = [], []
    for pre, blocks in sources:
        if pre:
            preamble += ([""] if preamble else []) + pre
        seen_known = False
        for b in blocks:
            if b.heading in known:
                seen_known = True
                k = known[b.heading]
                pre_lines = strip_blank_edges(b.preamble)
                if pre_lines:
                    k.preamble += ([""] if k.preamble else []) + pre_lines
                k.entries += b.entries
            else:
                (tail if seen_known else lead).append(b)
    for f in sorted(fragments, key=Fragment.sort_key):
        known[f.section].entries.append(f.body.split("\n"))

    out = []

    def emit_block(heading, pre, entries):
        if out:
            out.append("")
        out.append(f"### {heading}")
        chunks = []
        if pre:
            chunks.append(pre)
        chunks += entries
        for chunk in chunks:
            out.append("")
            out.extend(chunk)

    if preamble:
        out.extend(preamble)
    for b in lead:
        emit_block(b.heading, strip_blank_edges(b.preamble), b.entries)
    for s in SECTIONS:
        k = known[s]
        if k.entries or k.preamble:
            emit_block(s, strip_blank_edges(k.preamble), k.entries)
    for b in tail:
        emit_block(b.heading, strip_blank_edges(b.preamble), b.entries)
    return out


def assemble(version, date, changelog, frag_dir, check, append=False):
    if not re.match(r"^[0-9]+\.[0-9]+\.[0-9]+$", version):
        # Prereleases carry no CHANGELOG section (RELEASING.md); assembling
        # into one would strand the entries under an -rc heading.
        print(f"usage: VERSION must be a final X.Y.Z (got {version!r})", file=sys.stderr)
        return 2
    frags, nerr = load_all(frag_dir, out=sys.stderr)
    if nerr:
        print(f"{nerr} fragment problem(s); fix them before assembling.", file=sys.stderr)
        return 1
    try:
        with open(changelog, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        print(f"INFRA: cannot read {changelog}: {exc}", file=sys.stderr)
        return 2
    header, sections = split_changelog(text)
    if not sections or sections[0][0].rstrip() != "## [Unreleased]":
        print(f"::error::the first '## [' heading in {changelog} is not '## [Unreleased]'; "
              "fix that first (check-changelog-unreleased.sh, #3433).", file=sys.stderr)
        return 1
    ver_re = re.compile(r"^## \[" + re.escape(version) + r"\]")
    unreleased = parse_body(sections[0][1])
    rest = sections[1:]
    existing = None
    if append:
        # A second pass over a section THIS cut already opened: entries that
        # merged after the prep are merged into it, not given a second
        # heading. Opt-in only, and only for the section directly below
        # [Unreleased]: without the flag a Cargo.toml that was never bumped
        # would name the version that already shipped, and its fragments would
        # be filed under a released heading -- the #3433 shape, by tool.
        if not (rest and ver_re.match(rest[0][0])):
            print(f"::error::--append: the section directly below '## [Unreleased]' is not "
                  f"'## [{version}]', so there is nothing to append to.", file=sys.stderr)
            return 1
        existing = rest[0]
        rest = rest[1:]
    elif any(ver_re.match(h) for h, _ in rest):
        print(f"::error::{changelog} already has a '## [{version}]' section. If that version "
              "has shipped, bump the version first (RELEASING.md step 2). If it is this cut's "
              "own, not-yet-tagged section, re-run with --append.", file=sys.stderr)
        return 1

    sources = []
    heading = f"## [{version}] - {date}"
    if existing:
        heading = existing[0]
        sources.append(parse_body(existing[1]))
    sources.append(unreleased)
    body = merge(sources, frags)
    if not body:
        print(f"::error::nothing to assemble: no fragments in {frag_dir} and no entries "
              "under '## [Unreleased]'.", file=sys.stderr)
        return 1

    section = [heading, ""] + body
    if check:
        print("\n".join(section))
        return 0

    out = header + ["## [Unreleased]", "", POINTER, ""] + section + [""]
    for h, b in rest:
        out.append(h)
        out.extend(b)
    with open(changelog, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")
    for f in frags:
        os.remove(f.path)
    print(f"{changelog}: wrote '{heading}' from {len(frags)} fragment(s)"
          f"{' and the entries under [Unreleased]' if unreleased[1] or unreleased[0] else ''}; "
          f"deleted {len(frags)} fragment file(s).", file=sys.stderr)
    return 0


def main(argv):
    ap = argparse.ArgumentParser(prog="changelog-fragments.py")
    sub = ap.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("validate")
    v.add_argument("--dir", default=os.path.join(ROOT, "changes", "unreleased"))
    v.add_argument("files", nargs="*")

    r = sub.add_parser("render-fragments")
    r.add_argument("--dir", default=os.path.join(ROOT, "changes", "unreleased"))

    a = sub.add_parser("assemble")
    a.add_argument("version")
    a.add_argument("--date", default=datetime.date.today().isoformat())
    a.add_argument("--changelog", default=os.path.join(ROOT, "CHANGELOG.md"))
    a.add_argument("--dir", default=os.path.join(ROOT, "changes", "unreleased"))
    a.add_argument("--check", action="store_true")
    a.add_argument("--append", action="store_true")

    args = ap.parse_args(argv)
    if args.cmd == "validate":
        frags, nerr = load_all(args.dir, args.files)
        if nerr:
            print(f"{nerr} fragment problem(s).")
            return 1
        print(f"{len(frags)} CHANGELOG fragment(s) valid.")
        return 0
    if args.cmd == "render-fragments":
        frags, nerr = load_all(args.dir, out=sys.stderr)
        if nerr:
            return 1
        body = merge([], frags)
        if body:
            print("\n".join(body))
        return 0
    if args.cmd == "assemble":
        if not re.match(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$", args.date):
            print(f"usage: --date must be YYYY-MM-DD (got {args.date!r})", file=sys.stderr)
            return 2
        return assemble(args.version, args.date, args.changelog, args.dir, args.check,
                        args.append)
    return 2


if __name__ == "__main__":
    try:
        rc = main(sys.argv[1:])
        sys.stdout.flush()
        sys.exit(rc)
    except BrokenPipeError:  # `... --check | head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
