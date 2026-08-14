# Releasing Artifact Keeper

Runbook for cutting a release from `main`. Maintenance releases from
`release/X.Y.x` branches follow the same sequence; the only difference is
that fixes reach the branch by cherry-pick from `main` first (see
"Release Branch Strategy" in [CLAUDE.md](CLAUDE.md) and the
release-branch-gate workflow).

Throughout, `X.Y.Z` is the version being released and the git tag is
`vX.Y.Z` (Docker tags drop the `v`).

## Cut sequence

1. **Confirm scope and health.** The milestone for `X.Y.Z` has no open
   issues you still intend to ship, and `main` is green (CI Complete on the
   release candidate commit).

   Then run the **release preflight** and get a `READY` before you tag:

   ```bash
   scripts/ci/release-preflight.sh          # local (needs an authenticated gh)
   # or, from the Actions UI: run the "Release Preflight" workflow
   ```

   It asserts main is actually releasable — `.trivyignore` accounts for
   every active `release/*` branch's suppressions, live or via a
   `# RETIRED:` tombstone (the drift that stalled v1.7.0-rc.1 at Security
   Scan, #3039; the tombstone mechanism is #3309), the version set is
   consistent, Docker Publish for the exact commit being tagged (not
   merely the latest run, #3338) cleanly published its manifest, and no
   component pinned by a checked-in `VERSION` file would try to republish an
   exact tag that already exists with different content (the collision that
   killed the v1.7.2 tag). A `NOT READY` (exit 1) means fix main first;
   tagging over it costs a full re-cut cycle. An exit 2 is `INFRA` — a check
   that could not be measured, which is neither a pass nor a failure.

2. **Bump the version set.** The version is displayed or pinned in several
   decoupled places; a partial bump ships a stale version string. Update
   all of them in one PR (or one PR per repo):
   - `Cargo.toml` (workspace `version`, this repo) and the regenerated
     `Cargo.lock`
   - `backend/src/api/openapi.rs` (hardcoded `version = "..."` in the
     OpenAPI info block, this repo)
   - `package.json` `version` in artifact-keeper-web
   - `charts/artifact-keeper/Chart.yaml` `version` and `appVersion` in
     artifact-keeper-iac

3. **REQUIRED: promote the CHANGELOG.** Before tagging `vX.Y.Z`, promote
   the `## [Unreleased]` section in `CHANGELOG.md` to
   `## [X.Y.Z] - <date>` (and open a fresh empty `## [Unreleased]` above
   it). Include the Sponsors and Thank You recognition sections per the
   "Changelog and Release Notes" policy in [CLAUDE.md](CLAUDE.md).

   This step is enforced, not advisory: the release gate's
   `version-set-integrity` check (artifact-keeper-test) and the
   `verify-images-published` job in `release.yml` both assert that
   `CHANGELOG.md` contains a non-empty `## [X.Y.Z]` section for the
   version being released. A release with no CHANGELOG entry for the
   version will fail the gate and the GitHub Release will not publish
   (it stays a draft). Land the promotion on `main` before tagging.

4. **Pre-tag verification (recommended).** Dispatch the Release Gate
   (Full Suite) in artifact-keeper-test against the candidate images
   (`backend_tag` / `web_tag`). When dispatched with the release version
   as `backend_tag`, `version-set-integrity` also verifies the published
   image set and the CHANGELOG entry before you commit to the tag.

5. **Cut a release candidate first, then tag the release.** Tag
   `vX.Y.Z-rc.N` and let the full chain complete before tagging `vX.Y.Z`.

   ```bash
   git checkout main && git pull
   git tag vX.Y.Z-rc.1 && git push origin vX.Y.Z-rc.1
   # chain completes green, then:
   git tag vX.Y.Z && git push origin vX.Y.Z
   ```

   v1.7.0 was cut this way and took four candidates — rc.1, rc.2 and rc.3
   all failed. v1.7.1 and v1.7.2 went straight to a real tag; v1.7.1 got
   away with it and v1.7.2 did not, failing Docker Publish on an unbumped
   `docker/scanner-adapter/VERSION` and leaving a dead tag that had to be
   deleted by hand.

   This is safe because the repository ruleset applies tag immutability to
   `refs/tags/v*` but **excludes** `v*-rc*`, `v*-beta*` and `v*-alpha*`:
   candidates are deletable and re-cuttable, releases are not.

   A candidate is not a full substitute, though. Some publish logic keys on
   a clean `refs/tags/v*` ref and is skipped for prereleases — the
   scanner-adapter exact-version check is one, which is why that specific
   trap is caught by the preflight in step 1 rather than by the candidate.

   The tag triggers `release.yml` (binaries, gates, GitHub Release) and
   `docker-publish.yml` (backend, web, openscap images on ghcr.io and
   docker.io).

6. **Watch the gates.** `release.yml` runs the E2E gate, the
   artifact-keeper-test release gate, and `verify-images-published`
   (image presence on both registries plus the CHANGELOG entry check).
   If any required gate fails, the GitHub Release is created as a
   **draft** with binaries attached but is not published. Fix the cause
   (for a missing CHANGELOG entry: land the promotion on `main`, delete
   and re-cut the tag) rather than publishing the draft by hand.

7. **Post-release checks.** Confirm the GitHub Release is published (not
   draft), release notes are the curated per-version body (see "Release-notes
   style" below), not the raw auto-generated PR list, `:latest` moved only if this is a stable release, and the demo
   or any pinned environments are updated intentionally (see
   "Infrastructure & Cost Rules" in CLAUDE.md).

## Policy summary

- Every release documents itself: no `vX.Y.Z` tag without a non-empty
  `## [X.Y.Z]` section in `CHANGELOG.md`. Enforced by
  `version-set-integrity` (artifact-keeper-test release gate) and
  `release.yml` `verify-images-published`.
- The GitHub Release body is a curated high-level paraphrase of the
  version's `## [X.Y.Z]` CHANGELOG section (see "Release-notes style"),
  NOT the raw auto-generated PR list; recognition sections (Sponsors,
  Thank You) follow the CLAUDE.md policy.
- Prerelease tags (`-rc.N`, `-beta.N`) are exempt from the CHANGELOG
  entry requirement; final releases are not.
- Cut a release candidate and let the chain finish before tagging the real
  release. Tag immutability covers `refs/tags/v*` and excludes `v*-rc*` /
  `v*-beta*` / `v*-alpha*`, so a failed candidate is re-cuttable while a
  failed release leaves a dead tag that must be deleted by hand (v1.7.2).


## Release-notes style

The GitHub Release body is **not** the raw auto-generated PR list.
`generate_release_notes` produces an unscoped PR dump -- and when
intermediate prereleases did not publish a Release object it reaches back
into prior minor lines -- which buries the value. Instead the body is a
curated **high-level paraphrase of THIS version's `## [X.Y.Z]` CHANGELOG
section**:

- Lead with the big-ticket epics / security themes so the value lands in
  the first few lines.
- Keep the intro human-skimmable: group and paraphrase, do not reproduce
  every PR.
- Point to the full `## [X.Y.Z]` CHANGELOG section for depth (both the
  skimming reader and the auditing reader are served).
- Prepend the required `### Sponsors` and `### Thank You` recognition
  sections (see CLAUDE.md "Changelog and Release Notes").
- Scope strictly to X.Y.Z -- only changes since the previous minor/patch,
  never a multi-version diff.

Mechanics: author the body as `.github/release-notes/<version>.md` and
commit it in the same PR as the CHANGELOG promotion. `release.yml`'s
"Resolve release notes" step uses that file as the Release `body_path`
when present, and falls back to `generate_release_notes` only for versions
without a curated file (e.g. `-rc.N` prereleases). Security hotfix releases
use the tighter "am I affected" table format instead.
