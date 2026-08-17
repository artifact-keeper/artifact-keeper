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
   `## [X.Y.Z] - <date>` **and open a fresh empty `## [Unreleased]` above
   it**. Include the Sponsors and Thank You recognition sections per the
   "Changelog and Release Notes" policy in [CLAUDE.md](CLAUDE.md).

   The fresh `## [Unreleased]` is not cosmetic. Without it, every PR branch
   cut before the promotion still anchors its CHANGELOG hunk on the old
   heading and merges into the *renamed, already-released* section — no
   conflict, no warning. That is how 30 entries of 1.8.0 work ended up filed
   under `[1.7.5]` (#3433). `scripts/ci/check-changelog-unreleased.sh` runs
   in CI's shell-tests job and fails if the first `## [` heading is anything
   other than `## [Unreleased]`.

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

5. **REQUIRED for backports: check the versioned component source sets.**
   Before tagging, confirm no change since the previous tag touches a
   versioned component's source set unless that component's `VERSION` is
   bumped in the same change. Today that is `docker/scanner-adapter/**` and
   `docker/Dockerfile.scanner-adapter`; the general rule is "any directory
   under `docker/` with a `VERSION` file, plus its sibling Dockerfile".

   ```bash
   git ls-files 'docker/*/VERSION'                      # the component list
   git diff --stat vX.Y.Z-1..HEAD -- \
     docker/scanner-adapter docker/Dockerfile.scanner-adapter
   ```

   Any output means either bump `docker/scanner-adapter/VERSION` or drop the
   change. The publish gate treats **any** edit under the source set as a
   source change and refuses to republish an existing exact version tag — a
   comment-only line counts. `v1.7.5` died on exactly that: a comment carried
   along "for tidiness" in the #3424 backport made the tag's Docker Publish
   fail, and the ruleset forbids deleting or moving the tag, so the version
   was burned (#3429). `v1.7.2` died the same way (#3340). When backporting,
   restrict the cherry-pick to files that are functionally required.

   Preflight check 4 (step 1) asserts this against the registry, so a `READY`
   already covers it — this step is the one to run when you are assembling a
   backport, before you get as far as preflight.

6. **Cut a release candidate first, then tag the release.** Tag
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

7. **Watch the gates.** `release.yml` runs the E2E gate, the
   artifact-keeper-test release gate, and `verify-images-published`
   (image presence on both registries plus the CHANGELOG entry check).
   If any required gate fails, the GitHub Release is created as a
   **draft** with binaries attached but is not published. Fix the cause
   (for a missing CHANGELOG entry: land the promotion on `main`, delete
   and re-cut the tag) rather than publishing the draft by hand.

8. **Post-release checks.** Confirm the GitHub Release is published (not
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
- `CHANGELOG.md` always has an open `## [Unreleased]` as its first `## [`
  heading. Enforced by `scripts/ci/check-changelog-unreleased.sh` in CI's
  shell-tests job (#3433).
- No change reaches a tag that touches a versioned component's source set
  (`docker/*/VERSION` and its sibling Dockerfile) without bumping that
  component's `VERSION` — step 5. Exact version tags are never republished,
  and a tag that fails to publish is burned (#3429, #3340).
- Every `release/**` branch publishes images on push, same as `main`
  (#3422). A maintenance-branch commit therefore has a Docker Publish run of
  its own, which is what preflight check 3 resolves by `head_sha` (#3338);
  no manual `workflow_dispatch` is needed before a cut.
- The release-branch gate accepts two shapes that cannot trace to `main` by
  patch-id without the `release-process: approved` label (#3422): a release
  prep (`chore(release): ...` touching only the version/changelog/
  release-notes file set) and a narrowed backport (a
  `(cherry picked from commit <sha>)` trailer naming a commit on `main`).
  Use `git cherry-pick -x` so the trailer is written for you, and keep it
  when you resolve hunks away. Everything else still needs the label.
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
