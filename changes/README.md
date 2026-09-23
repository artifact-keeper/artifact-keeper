# CHANGELOG fragments

Every PR that changes what ships records its CHANGELOG entry as **one new
file** in [`unreleased/`](unreleased/), not as an edit to `CHANGELOG.md`. No
two PRs touch the same file, so merging one PR no longer puts every other
open PR into conflict and back through CI. The release prep renders the
fragments into the new `## [X.Y.Z] - <date>` section of `CHANGELOG.md` and
deletes them (`scripts/release/assemble-changelog.sh`, RELEASING.md step 3).

## Format

`changes/unreleased/<pr-or-issue-number>-<slug>.md`, for example
`changes/unreleased/4145-conda-repodata-deadlock.md`:

```markdown
---
section: Fixed
issues: [#4145, #4129]
---
- **Eight concurrent anonymous conda repodata requests no longer deadlock the buffered-metadata proxy path** (#4145, #4129). What was wrong, why, and what changed -- written exactly as the bullet would read in `CHANGELOG.md`.

  Further paragraphs are indented two spaces, as in `CHANGELOG.md`.
```

- **File name**: the issue number the entry is about (or the PR number when
  there is no issue), a hyphen, and a short slug of lowercase letters, digits
  and single hyphens. The number decides the order entries render in within
  their section.
- **`section`**: one of `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`,
  `Security` ([Keep a Changelog](https://keepachangelog.com/en/1.1.0/); they
  render in that order).
- **`issues`**: the `#N` references the entry is about, at least one. Each
  must also appear in the body.
- **Body**: exactly one top-level `- ` bullet, in the house style: a bold lead
  sentence, then the issue references in parentheses on the same line, then
  the why and the what. Release preflight check 5 reconciles each entry by the
  **first** `#N` on its `- ` line, so lead with the issue the PR closes.

One fragment per entry. A PR that genuinely makes two unrelated user-facing
changes adds two fragments.

CI-only and workflow-only changes that ship nothing to a user need no
fragment.

## Checking a fragment

```bash
python3 scripts/ci/changelog-fragments.py validate          # every fragment
scripts/release/assemble-changelog.sh --check 9.9.9         # preview the section
```

CI runs the first as part of `scripts/ci/check-changelog-unreleased.sh`.

## Transition

PRs opened before fragments existed may still add their bullet under
`## [Unreleased]` in `CHANGELOG.md`; CI accepts that, and the assembler merges
those bullets with the fragments at the cut. New PRs should add a fragment.
