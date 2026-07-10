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

5. **Tag the release.**

   ```bash
   git checkout main && git pull
   git tag vX.Y.Z && git push origin vX.Y.Z
   ```

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
   draft), release notes are auto-generated (do not hardcode static
   notes), `:latest` moved only if this is a stable release, and the demo
   or any pinned environments are updated intentionally (see
   "Infrastructure & Cost Rules" in CLAUDE.md).

## Policy summary

- Every release documents itself: no `vX.Y.Z` tag without a non-empty
  `## [X.Y.Z]` section in `CHANGELOG.md`. Enforced by
  `version-set-integrity` (artifact-keeper-test release gate) and
  `release.yml` `verify-images-published`.
- Release notes on GitHub are auto-generated; recognition sections
  (Sponsors, Thank You) follow the CLAUDE.md policy.
- Prerelease tags (`-rc.N`, `-beta.N`) are exempt from the CHANGELOG
  entry requirement; final releases are not.
