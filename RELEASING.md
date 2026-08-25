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
   merely the latest run, #3338) cleanly published its manifest, no
   component pinned by a checked-in `VERSION` file would try to republish an
   exact tag that already exists with different content (the collision that
   killed the v1.7.2 tag), and the pending CHANGELOG section and the commit
   range `<previous stable tag>..HEAD` describe the same work in both
   directions (#3537). A `NOT READY` (exit 1) means fix main first;
   tagging over it costs a full re-cut cycle. An exit 2 is `INFRA` — a check
   that could not be measured, which is neither a pass nor a failure. If a
   check has already found a blocking problem and a *later* check cannot be
   measured, you get exit 1, not exit 2 (#3538): the blocking problem is
   definite and retrying will not remove it, so "retryable" would be the wrong
   instruction. The transcript says which checks did not run, so re-run the
   preflight for a full verdict once you have fixed them.

   **This step is now enforced, not advisory (#3538).** `release.yml`'s
   `preflight-evidence` job refuses to proceed unless a green run of the
   **Release Preflight workflow** exists for the exact commit the tag points
   at. A local `scripts/ci/release-preflight.sh` run is still useful, but it
   leaves no evidence — only the workflow does, as a
   `release-preflight-<sha>` artifact carrying the sha it actually checked
   out. So:

   - Run **Release Preflight** from the Actions UI (or
     `gh workflow run release-preflight.yml --ref <branch>`) on the branch
     whose tip is the commit you are about to tag, and wait for it to go
     green. Cutting a maintenance release? Dispatch it **on that branch** —
     the workflow audits the ref it was dispatched on, and says which one in
     its verdict line.
   - A preflight that is still running does **not** satisfy the gate. That is
     deliberate: v1.7.7 was tagged 18 minutes after a preflight reported
     `verdict does not exist yet`, and the run it was waiting on concluded
     `failure` 19 seconds after the tag push.
   - If the branch moves after the preflight goes green, the preflight no
     longer applies — tag the commit it audited, or run it again.

   **Break glass.** The gate predicts whether the chain will stall; it does
   not certify the bytes, so it is override-able (the gates that *do* certify
   bytes — `resolve-candidate-digest`, `release-gate`,
   `verify-images-published` — are not). The override is a trailer in the
   annotated tag's own message, and it requires a real reason:

   ```bash
   git tag -a v1.8.2 -m "Release 1.8.2

   Preflight-Override: cut off-branch at 635496d0, which has no branch to
   dispatch the workflow on; preflight run locally against that exact tree,
   transcript on #3538"
   ```

   It lives there rather than in a workflow input or a repository variable
   because the tag object is immutable (ruleset 19144026), is scoped to
   exactly one version, cannot be added after the fact, and is readable
   forever with `git show v1.8.2`. A trailer with no reason (or under 20
   characters of one) is **refused**, not honoured. Every honoured override is
   printed as a workflow warning and written to the release run's summary,
   together with the verdict it overrode.

   Check 5 reads the issue reference each entry leads with, so **every
   CHANGELOG bullet must name the issue it closes** — `- **Summary**
   (#NNNN). prose` — and every merged PR in the range must be named by some
   pending entry. Dependency bumps (`chore: bump …`) and `chore(release):`
   commits are the only exemptions. `### Sponsors` and `### Thank You`
   bullets are credits, not entries, and are not reconciled.

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

   While the gates run, the registry holds only the immutable `:X.Y.Z`
   tags. `:latest` and `:X.Y` still point at the PREVIOUS release, and
   that is correct: nothing has certified the new bytes yet.

8. **Watch the floating-tag promotion.** After the GitHub Release
   publishes, `promote-floating-tags` dispatches `docker-publish.yml` with
   `promote_version=X.Y.Z -f promote_floating=true`. That run rebuilds
   nothing: it re-points `:latest` and `:X.Y` at the manifest-list digest
   `:X.Y.Z` already names, and the job then asserts that both tags, on both
   registries, resolve to the digest the release gate tested.

   If it fails, the release is published and correct but `:latest` has not
   moved. Re-run the job, or dispatch it by hand:

   ```bash
   gh workflow run docker-publish.yml --repo artifact-keeper/artifact-keeper \
     --ref vX.Y.Z -f promote_version=X.Y.Z -f promote_floating=true
   ```

   A backport moves only its series alias: promoting `1.7.9` while `1.8.2`
   is the newest release advances `:1.7` and leaves `:latest` alone.

9. **Post-release checks.** Confirm the GitHub Release is published (not
   draft), release notes are the curated per-version body (see "Release-notes
   style" below), not the raw auto-generated PR list, `:latest` and `:X.Y`
   moved (stable releases only), and the demo
   or any pinned environments are updated intentionally (see
   "Infrastructure & Cost Rules" in CLAUDE.md).

## Rolling `:latest` back

There is no separate rollback path, because there is nothing to roll back in
the normal failure case: if any gate fails, `:latest` and `:X.Y` were never
moved and still name the previous release. The only visible consequence is
that after a failed cut the registry looks like the release did not happen —
`:X.Y.Z` exists and is immutable, but the floating tags are unchanged.

To move `:latest` back off a release that DID publish and then turned out to
be bad:

1. Delete the bad GitHub Release, or mark it as a prerelease. This is the
   deliberate act; the tag movement follows from it.
2. Dispatch the promotion for the version you want:

   ```bash
   gh workflow run docker-publish.yml --repo artifact-keeper/artifact-keeper \
     --ref vX.Y.Z -f promote_version=X.Y.Z -f promote_floating=true
   ```

`.github/scripts/floating-tag-plan.sh` reads the published-release set, so once
the bad release is gone the previous version is the newest one and the floating
tags are allowed to move to it. While the bad release is still published, the
same command is refused — floating tags never move backwards by accident.

Do NOT delete container tags to roll back. `:X.Y.Z` is immutable and names real,
scanned bytes; deleting it breaks every chart that pins it.

## Policy summary

- Every release documents itself: no `vX.Y.Z` tag without a non-empty
  `## [X.Y.Z]` section in `CHANGELOG.md`. Enforced by
  `version-set-integrity` (artifact-keeper-test release gate) and
  `release.yml` `verify-images-published`.
- The GitHub Release body is a curated high-level paraphrase of the
  version's `## [X.Y.Z]` CHANGELOG section (see "Release-notes style"),
  NOT the raw auto-generated PR list; recognition sections (Sponsors,
  Thank You) follow the CLAUDE.md policy. For a stable release
  `.github/release-notes/<version>.md` is REQUIRED on the ref being
  released — `generate_release_notes` is a prerelease-only fallback, and a
  stable tag without the file is refused (#3537).
- Every CHANGELOG entry names the issue it closes, and every merged PR
  since the previous stable tag is named by some pending entry. Enforced
  in both directions by `release-preflight.sh` check 5 (#3537).
- Prerelease tags (`-rc.N`, `-beta.N`) are exempt from the CHANGELOG
  entry requirement; final releases are not.
- `CHANGELOG.md` always has an open `## [Unreleased]` as its first `## [`
  heading. Enforced by `scripts/ci/check-changelog-unreleased.sh` in CI's
  shell-tests job (#3433).
- Floating tags (`:latest`, `:X.Y`) are applied ONLY after the release gate
  and the GitHub Release, by a build-free promotion that re-points them at the
  digest `:X.Y.Z` already names. A floating tag may only name a version with a
  published, non-draft, non-prerelease GitHub Release, and only if that version
  is the newest in the line the tag represents. Enforced by
  `.github/scripts/floating-tag-plan.sh` and pinned by
  `scripts/ci/check-floating-tag-promotion.sh` in CI's shell-tests job.
  Prereleases never take a floating tag.
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
"Resolve release notes" step uses that file as the Release `body_path`.

For a stable `vX.Y.Z` the file is **required**: with no curated file the
release-preflight job refuses the tag, and the "Resolve release notes" step
refuses it again an hour later. `generate_release_notes` survives only for
prereleases (`-rc.N`, `-beta.N`). That fallback used to apply to everything,
silently: v1.7.1 was cut with no curated file, the step logged "using GitHub
auto-generated notes", and the release published — and because auto-notes do
not promote the CHANGELOG, eight `[Unreleased]` entries that had already
shipped stayed under `[Unreleased]`, one of them telling operators to act
"before upgrading to 1.7.2" when they had been exposed for a week (#3318,
#3537).

The notes file is read from **the ref being released**, not from `main`.
`main` and `release/1.7.x` hold disjoint halves of the 1.7.x set — 1.7.6 and
1.7.8 live only on the release branch, which is where they belong. Put the
file on the branch you are cutting from.

`.github/release-notes/` must also hold no file for a version that has
neither a tag nor a Release. A stale notes file is what a human reads when
reconstructing what shipped, and it is one rename away from being published
as another version's body. Security hotfix releases use the tighter "am I
affected" table format instead.
