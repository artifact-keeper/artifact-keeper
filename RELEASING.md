# Releasing Artifact Keeper

Runbook for cutting a release from `main`. Maintenance releases from
`release/X.Y.x` branches follow the same sequence; the only difference is
that fixes reach the branch by cherry-pick from `main` first (see
"Release Branch Strategy" in [CLAUDE.md](CLAUDE.md) and the
release-branch-gate workflow).

Throughout, `X.Y.Z` is the version being released and the git tag is
`vX.Y.Z` (Docker tags drop the `v`).

**The shape of a cut (#3769):** prep PR → `Release Candidate` dispatch →
green → `Release Promote` dispatch. Nothing gets a permanent name — the git
tag `vX.Y.Z`, the image `:X.Y.Z`, `:latest`, `:X.Y` — until the full gate has
passed on that exact commit. The candidate tests the commit's `sha-<sha>`
images and records a certification; the promote applies `:X.Y.Z` to the
certified digests and creates the tag **last**. You never push a stable tag
by hand any more — and you cannot: the promote creates every stable tag with
`GITHUB_TOKEN`, which fires no `push` event, so a *push* of a `vX.Y.Z` is by
construction a hand push and is refused outright by both `docker-publish.yml`
and `release.yml` before anything is built, whether or not the commit is
certified. (A certified commit is no exception: the push run would build
fresh bytes and name them `:X.Y.Z`, bytes the gate never saw.) If you have
hand-tagged a certified commit, dispatch the promote on it — it accepts an
existing tag that names the same commit.

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
   out. **The Release Candidate (step 6) dispatches the preflight on the
   commit for you and requires its evidence**, so in the normal flow this
   step is "run it early to find out sooner", not a separate chore. So:

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

4. **Pre-tag verification.** This is what step 6 does, against the exact
   images the release will ship, with a certification at the end. A manual
   Release Gate Rehearsal (`release-gate-rehearsal.yml`) is still available
   for poking at one image or one suite, but it certifies nothing.

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

6. **Dispatch the Release Candidate on the prep commit.** Once the prep PR
   (steps 2–3, plus the curated notes file) is the tip of `main` and its
   Docker Publish run is green:

   ```bash
   gh workflow run release-candidate.yml --repo artifact-keeper/artifact-keeper \
     --ref main                       # -f sha=<40-hex> to pick a commit that is not the tip
   ```

   `--ref main` is required, not a convention: the certification is verified
   pinned to the candidate workflow *on main* (an exact `--cert-identity` of
   `release-candidate.yml@refs/heads/main`, plus `--source-ref refs/heads/main`),
   so a run from any other ref is refused at once rather than an hour later.
   The commit need not be the tip. The preflight is dispatched on `main` with
   `ref=<sha>`, so the run's `head_sha` is main's tip, not the commit; the
   evidence gate therefore also finds preflight runs by the
   `release-preflight-<sha>` artifact they left, which names the tree that
   was actually audited. A merge landing on `main` while the candidate runs
   does not invalidate it.

   It reads the version from `Cargo.toml` at that commit (there is no
   version input, on purpose), refuses the commit unless it is on `main`,
   carries the workflows this flow dispatches (a commit whose `release.yml`
   has no `workflow_dispatch` trigger would end in an immutable tag nothing
   can run on), has no `vX.Y.Z` tag and no Release, has a green Docker
   Publish run, and passes the bookkeeping and CHANGELOG assertions; it
   dispatches the **Release Preflight** on the commit and requires its READY
   evidence; it
   runs the stable-only publish checks that a `-rc` tag never exercised
   (#3773) — the exact-tag digest guard for backend and openscap on both
   registries, the scanner-adapter exact-version decision on both registries,
   and the adoption gate (the published `sha-<sha>` images must record this
   commit as their source); and then it runs the **same reusable Release
   Gate** `release.yml` used to run, against the `sha-<sha>` images Docker
   Publish already built for the commit, pinned by digest. Nothing is
   rebuilt and nothing gets a name.

   On green it records a **certification**: a signed attestation
   (`actions/attest`, Sigstore via GitHub OIDC) on each image's digest whose
   predicate names the commit, the version, the run and every digest. A
   `release-candidate-<sha>` artifact and a `release-candidate/certified`
   status on the commit are written for humans; the release path verifies
   the attestation (`scripts/ci/assert-candidate-certified.sh`, pinned to
   the candidate workflow's identity), nothing else.

   **If it fails, fix the cause and dispatch a new candidate.** Do not
   "Re-run failed jobs" on a failed gate: GitHub replays the gate's `deploy`
   outputs instead of re-executing them, so every suite targets a namespace
   the first attempt's teardown already deleted and dies on "backend not
   ready" (#3774; how v1.9.0's re-runs failed). The workflow refuses a
   re-run of the gate and says so. Nothing was named, so a failed candidate
   costs a gate run and nothing else — the version number is intact.

   **Fallback: a prerelease tag.** `vX.Y.Z-rc.N` still works as it always
   did (the ruleset excludes `v*-rc*`, `v*-beta*`, `v*-alpha*` from
   immutability, so it is deletable and re-cuttable) and still runs the gate
   inside `release.yml`. It is the old path, kept for a rehearsal that needs
   a real tag; it certifies nothing and it does not run the stable-only
   checks. Cut stable releases with the candidate — including patch releases
   from a maintenance branch, which now have their own candidate path (see
   "Patch releases from a `release/X.Y.x` branch").

7. **Dispatch the Release Promote.** With the candidate green:

   ```bash
   gh workflow run release-promote.yml --repo artifact-keeper/artifact-keeper \
     --ref main                       # -f sha=<the certified commit> if it is not the tip
   ```

   In order: it verifies the certification for the commit and that the
   registry still serves the certified digests for `sha-<sha>`; re-checks the
   preflight evidence; applies `:X.Y.Z` to the certified digests through
   Docker Publish's PROMOTE mode (`promote_version=X.Y.Z
   promote_source_sha=<sha>` — no rebuild, the digest-aware guard still runs,
   the same signing and verification steps run, and the scanner-adapter's
   exact tag is applied to *its* certified digest with the adapter VERSION
   read from the promoted commit); asserts `:X.Y.Z` now resolves to the
   certified digests; **creates the annotated `vX.Y.Z` tag last**, on the
   commit, with `GITHUB_TOKEN`; dispatches `docker-publish.yml` on the tag
   (a no-op re-apply plus `verify-published`, and the successful publish run
   `release.yml` requires for the tag); and dispatches `release.yml` on the
   tag. A ref created by `GITHUB_TOKEN` fires no `push` event, which is why
   both are dispatched explicitly — and why no PAT, App or ruleset bypass is
   involved: ruleset 19144026 restricts updates and deletions of `v*`, not
   creation. The promote is idempotent: if it dies after the tag exists,
   dispatch it again on the same commit.

   **After the `:X.Y.Z` step, the version belongs to these digests.** The
   merge jobs of that Docker Publish run write `:X.Y.Z` on both registries in
   parallel, so a promote that fails there may have applied the exact tag for
   some images already. Re-dispatching is safe (same digests; the digest
   guard passes), but a candidate for a *different* commit at the same
   version will now be refused by the exact-tag guard: to abandon the commit
   after that point, bump `Cargo.toml` and certify the new commit as the next
   version.

8. **Watch `release.yml` on the tag.** It requires the preflight evidence
   and the certification for the commit, resolves `:X.Y.Z` and asserts it is
   the certified digest, **skips the gate** (it already passed on these exact
   bytes; running it again after the tag exists is the failure mode the
   candidate removes), builds and signs the binaries, verifies the images on
   both registries plus the CHANGELOG entry, creates the GitHub Release, and
   then `promote-floating-tags` dispatches `docker-publish.yml` with
   `promote_version=X.Y.Z -f promote_floating=true`. That run rebuilds
   nothing: it re-points `:latest` and `:X.Y` (and the scanner-adapter's own
   floating tags, #3770) at the manifest-list digest `:X.Y.Z` already names,
   and the job then asserts that both tags, on both registries, resolve to
   the digest the gate tested.

   Until the GitHub Release exists, `:latest` and `:X.Y` still point at the
   PREVIOUS release, and that is correct. A failure in a post-gate job
   (signing, the Release object, the floating promotion) is a genuine
   re-run: every step there is idempotent, and the tag is already correct.

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

   Then verify the release the way an operator would, from a clean directory —
   the `release` job already did this before publishing, but running it from
   outside proves the assets a downloader actually receives are the ones that
   were verified:

   ```bash
   REPO_DIR="$PWD"                       # your artifact-keeper checkout
   IDENTITY="$("$REPO_DIR"/scripts/ci/release-identity-regexp.sh \
     artifact-keeper/artifact-keeper release.yml refs/tags/vX.Y.Z)"

   cd "$(mktemp -d)"
   gh release download vX.Y.Z --repo artifact-keeper/artifact-keeper

   cosign verify-blob \
     --bundle checksums.txt.cosign.bundle \
     --certificate-identity-regexp "$IDENTITY" \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     checksums.txt
   sha256sum -c checksums.txt
   gh attestation verify artifact-keeper-linux-amd64.tar.gz \
     --repo artifact-keeper/artifact-keeper \
     --signer-workflow artifact-keeper/artifact-keeper/.github/workflows/release.yml
   ```

   `scripts/ci/release-identity-regexp.sh` is the same script the release job
   uses to build its pin, so this checks the release against exactly the
   identity the job required — not a hand-typed approximation of it.

   `SECURITY.md` carries the same commands written out for a user who does
   not have the repository checked out; keep the two in step.

## Patch releases from a `release/X.Y.x` branch

A patch release (1.9.1, 1.7.6) is cut from its maintenance branch, not from
`main`. The candidate-then-promote flow above is the same flow, dispatched the
same way: **both workflows are dispatched on `main`**, and you name the commit.

```bash
# 0. the branch exists and carries the flow
#    Creating a release/X.Y.x ref is refused by ruleset 20038606 for
#    everyone, admins included; cutting a NEW line is a deliberate,
#    announced ruleset toggle by a repository admin, for as long as the push
#    takes. An existing line needs no toggle.
#    The branch must carry scripts/ci/resolve-certified-ref.sh,
#    assert-candidate-certified.sh, follow-dispatched-run.sh and a
#    dispatchable release.yml / promotable docker-publish.yml; the candidate
#    refuses the commit by name if any is missing.

# 1. land the fixes on main first, then cherry-pick onto release/1.9.x
#    (Release Branch Gate enforces this)

# 2. the release prep commit on release/1.9.x sets Cargo.toml to 1.9.1 and
#    opens the CHANGELOG section, exactly as on main

# 3. certify — ON MAIN, naming the maintenance commit
gh workflow run release-candidate.yml --repo artifact-keeper/artifact-keeper \
  --ref main -f sha=<the release/1.9.x commit>

# 4. promote — ON MAIN, same commit
gh workflow run release-promote.yml --repo artifact-keeper/artifact-keeper \
  --ref main -f sha=<the certified commit>
```

There is no `--ref release/1.9.x` step, and that is the security property.

### The signing identity never widens

A certification is trusted because of one thing: the Sigstore certificate's
SubjectAlternativeName, pinned byte-for-byte to
`...release-candidate.yml@refs/heads/main`. A maintenance release does **not**
relax that pin. `release-candidate.yml` is dispatched on `main` and certifies
the maintenance commit from there, so main's copy of the workflow remains the
only thing that can produce an accepted certification. A copy of that file on
a `release/*` branch — including one an attacker managed to create — signs
with an identity nothing accepts, exactly as a copy on any topic branch does.
The alternative was to widen the pin to
`...release-candidate.yml@refs/heads/release/1.9.x`; certifying from main is
strictly stronger, because the attack of creating a `release/*` ref, putting
an edited workflow on it and satisfying an exact pin has no identity to reach
for at all, rather than being bounded by argument.

Nothing in the workflow depended on the dispatched ref for this to work: every
job but `resolve` already checks out the resolved sha explicitly, the reusable
Release Gate is an absolute cross-repository reference
(`artifact-keeper-test/.../release-gate.yml@main`) that takes the images by
digest, and none of the scripts run at the certified sha reads `GITHUB_REF`.

### Which commits main may certify

That is the second, independent control, and it lives in one place:
`scripts/ci/resolve-certified-ref.sh`, which every consumer asks — the
candidate, the promote, `release.yml` on the tag, and `docker-publish.yml`'s
certified-candidate promote. The commit must be an ancestor of `main`; failing
that, an ancestor of `refs/heads/release/<X>.<Y>.x`, where X and Y are read
from `Cargo.toml` **at that commit**, its existence checked case-sensitively
against the git-refs API. The line is therefore a function of the commit's own
content and the repository's refs; no dispatch input names it. The predicate
records the resolved line as `certified_ref`, and the verifier asks the
repository the same question again at promote time — a disagreement is never
promoted.

The resolver also **pins the content** of `release-candidate.yml` at the
certified commit: it must be byte-identical (same git blob id) to the copy
`main` carries at the merge base of main and that commit, or to main's current
copy, which is what a forward-port produces. That is no longer load-bearing
for the identity, but it is cheap and it backstops the window in which an
admin has the release ruleset toggled off to create a line: a `release/6.6.x`
created in that window, carrying an edited workflow, is refused on content as
well as on identity. If it refuses with "not a copy that lives on main", do
**not** edit the workflow on the branch — cherry-pick main's copy across and
dispatch a new candidate.

### Branch protection, for reference

Relevant because it decides who can put a commit on a release line at all
(ruleset 20038606 vs `branches/main/protection`), not because the
certification depends on it:

| write path | `main` | `refs/heads/release/X.Y.x` |
|---|---|---|
| direct push | allowed, if the required contexts are green on that sha | **refused** — a pull request is required |
| force push / rewrite | blocked (`allow_force_pushes: false`) | blocked (`non_fast_forward`) |
| deletion | blocked (`allow_deletions: false`) | blocked (`deletion`) |
| ref creation | n/a (it exists) | **refused** — `do_not_enforce_on_create: false`, no bypass actor |
| required checks | 3 | 2, incl. `Verify commits trace back to main` |
| required approvals | none configured | none configured |
| admin bypass | **yes** — `enforce_admins: false` | **no** — `bypass_actors: []` |

One thing to fix, and it is bigger than the release flow: on **both**
branches, a pull request's required checks are defined by workflows the pull
request itself can edit, and neither branch requires an approval. The real
floor under a release is therefore *write access*, not review. Raising
`required_approving_review_count` above 0 on ruleset 20038606, and giving
`main` a ruleset of its own, would raise it.

## Supply chain: what the release job signs, and what it refuses

Release binaries used to ship with a `<name>.sha256` beside them and nothing
else, which is a corruption check routinely read as an authenticity check: it
is served from the same place, by the same authority, as the artifact it
describes. Since #3558 the `release` job does four things between "Collect
release assets" and "Create Release", **in this order**:

1. writes one `checksums.txt` covering every asset (the per-file `.sha256`
   files stay, and are themselves listed in it);
2. signs `checksums.txt` with **cosign keyless** — GitHub OIDC to Fulcio to
   Rekor, no key material to hold or rotate — producing
   `checksums.txt.cosign.bundle`;
3. attaches **build provenance** to every archive, SBOM and the manifest with
   `actions/attest-build-provenance`;
4. **verifies all of it** with `scripts/ci/verify-release-assets.sh` before
   anything is published.

The order is the point, and it is not stylistic. `assert-release-absent.sh`
refuses to run against a tag that already has a release and
`softprops/action-gh-release` runs with `overwrite_files: false`, so a
*partial* publish is not recoverable by re-running — it burns an immutable
version number. Everything that can fail therefore fails while the job has
produced nothing public, and the recovery is "re-run the job".

The verification refuses, among other things: an asset missing from
`checksums.txt` (an unlisted asset is an unsigned asset), digests that do not
match the bytes on disk, a missing signature, a valid signature carrying the
**wrong certificate identity**, a certificate-identity pattern permissive
enough to accept one, provenance signed by a different workflow, and a missing
`.cdx.json`. It separates a Sigstore or GitHub API outage (exit 2, INFRA,
"retry") from a genuine mismatch (exit 1, BLOCKED, "something replaced your
bytes"); both stop the release. Every one of those legs is exercised offline
by `scripts/ci/test-verify-release-assets.sh` in CI's shell-tests job, because
this code path runs once per release and cannot be rehearsed without cutting a
tag.

Binaries are built with `cargo auditable`, so the dependency graph is embedded
in the shipped executable and a `.cdx.json` CycloneDX SBOM ships per target.
`scripts/ci/assert-binary-sbom.sh` asserts the embedding actually happened,
which is necessary rather than belt-and-braces: `cargo audit bin` **exits 0**
on a binary with no embedded data, printing a warning and falling back to a
partial list scraped from panic messages. Without an assertion on its output,
dropping `auditable` from the build command leaves CI green and every shipped
binary hollow.

**Do not add `continue-on-error` to any of these steps.**
`scripts/ci/check-supply-chain-soft-fail.sh` blocks it, for the reason #2824
exists: a soft-failed cosign step let 1.6.1 ship unsigned and a human found it
later.


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
- A stable release is the promotion of a **certified commit**, and which
  branch may have certified it is **derived** from the commit
  (`scripts/ci/resolve-certified-ref.sh`), never passed in: `main`, or the
  `release/X.Y.x` its own `Cargo.toml` names. The Release Candidate is always
  dispatched on `main`, including for a maintenance release, so the signing
  identity is always `...release-candidate.yml@refs/heads/main` and never
  widens; `release-candidate.yml` at the certified commit must additionally be
  byte-identical to a copy that lives on `main`. See "Patch releases from a
  `release/X.Y.x` branch".
- Floating tags (`:latest`, `:X.Y`) are applied ONLY after the release gate
  and the GitHub Release, by a build-free promotion that re-points them at the
  digest `:X.Y.Z` already names. A floating tag may only name a version with a
  published, non-draft, non-prerelease GitHub Release, and only if that version
  is the newest in the line the tag represents. Enforced by
  `.github/scripts/floating-tag-plan.sh` and pinned by
  `scripts/ci/check-floating-tag-promotion.sh` in CI's shell-tests job.
  Prereleases never take a floating tag. The scanner-adapter's own
  `:latest` / `:X.Y` / `:X` follow the same rule and the same moment (#3770):
  its "published set" is the `docker/scanner-adapter/VERSION` each published
  release ships, so a normal build writes no adapter floating tag (its exact
  version, `sha-*` and the branch `dev` tags only), and a base-image errata
  rebuild reaches the chart-pinned `:1` through a VERSION bump and a release.
  The promote resolves the adapter version from `v<promote_version>` itself,
  so the dispatch ref does not matter.
- Release binaries are signed and verified before publication, never after:
  one `checksums.txt` over every asset, a cosign keyless signature over it, and
  build provenance on the assets — all three VERIFIED by
  `scripts/ci/verify-release-assets.sh` before `Create Release` runs, because
  `overwrite_files: false` plus `assert-release-absent.sh` make a partial
  publish unrecoverable. The certificate identity is pinned to this repository,
  this workflow file and this tag; a permissive pattern is refused by the gate
  rather than passed to cosign (#3558).
- Binaries embed their dependency graph (`cargo auditable`) and ship a
  per-target CycloneDX SBOM, and the embedding is ASSERTED at build time —
  `cargo audit bin` exits 0 on a binary that has none (#3558).
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
- No permanent name until the full gate has passed on the exact commit
  (#3769). A stable release is the promotion of a commit certified by
  `release-candidate.yml`; `release-promote.yml` applies `:X.Y.Z` to the
  certified digests and creates `vX.Y.Z` last. Both `release.yml` and
  `docker-publish.yml` refuse every stable-tag *push* (the promote creates
  the tag, and a token-created ref fires no push); `release.yml` refuses a
  dispatched stable tag whose commit has no certification
  (`scripts/ci/assert-candidate-certified.sh`, a signed attestation pinned
  to the candidate workflow's exact identity on `main`) and does not re-run
  the gate on a certified tag; `docker-publish.yml`'s plain promote on the
  tag can only re-apply an existing `:X.Y.Z` to its own digest. Prerelease tags (`v*-rc*` / `v*-beta*` / `v*-alpha*`) are
  the fallback: excluded from tag immutability, re-cuttable, gated inside
  `release.yml` as before, certifying nothing.
- Every check that runs only on a clean `refs/tags/v*` ref runs in the
  candidate too, against the same inputs (#3773): bookkeeping, the CHANGELOG
  entry, the preflight evidence, the exact-tag digest guard and the
  scanner-adapter exact-version decision on both registries, and the image
  adoption gate.
- A failed Release Gate is never re-run; the recovery is a new candidate
  (#3774). "Re-run failed jobs" replays the gate's `deploy` outputs, so the
  suites target a namespace that no longer exists. Both workflows refuse the
  re-run and say why.


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
