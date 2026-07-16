# Release Assurance Baseline — 2026-07-15

## Purpose

This document is the verified starting point for hardening Artifact Keeper's
release process. It separates observed facts from proposed changes so later
work can show which risks were actually removed.

The target design is in
`docs/plans/2026-07-15-release-assurance-design.md`. The delivery sequence is
in `docs/plans/2026-07-15-release-assurance-implementation-plan.md`.

## Scope and evidence

Reviewed:

- `artifact-keeper/artifact-keeper` at local commit `7e58b86c`.
- `artifact-keeper/artifact-keeper-test` at commit `83e6963`.
- GitHub Actions run history, release state, branch protection, and rulesets
  queried on 2026-07-15 with GitHub CLI.
- Release, container publication, CI, E2E, security, upgrade, resilience, and
  test-rollup behavior.

Live evidence used for the latest release:

- Release workflow: <https://github.com/artifact-keeper/artifact-keeper/actions/runs/29454678955>
- Container publication: <https://github.com/artifact-keeper/artifact-keeper/actions/runs/29454678618>
- Public release: <https://github.com/artifact-keeper/artifact-keeper/releases/tag/v1.5.8>

## Executive assessment

The present process has substantial test volume, but it cannot yet prove that
the artifacts made public are the artifacts that passed the required tests.
The largest risks are release identity, promotion ordering, and enforcement —
not the raw number of tests.

| ID | Finding | Severity | Release consequence |
|---|---|---:|---|
| RA-01 | A release can become public while required gates are red | Critical | A known-failing version can be distributed |
| RA-02 | Semver and `latest` images publish from a tag independently of release validation | Critical | Untested or incomplete images become stable |
| RA-03 | Release tests consume mutable `dev`, `latest`, and `main` references | Critical | Test success cannot be tied to released bytes |
| RA-04 | Branch protections do not enforce the complete quality policy | Critical | Changes can merge without review or release-relevant checks |
| RA-05 | Required image verification checks tag presence, not a locked tested digest set | High | A tag can exist but point at unexpected content |
| RA-06 | Several suites and rollup predicates are fail-open | High | Failed, skipped, or unexecuted tests can appear acceptable |
| RA-07 | Test inventory and workflow selection are not reconciled automatically | High | New tests can exist without ever running in a release |
| RA-08 | Release environments omit important production topology and controls | High | HA, storage, networking, and dependency defects escape |
| RA-09 | Container vulnerability scans are informational during publication | High | High/critical findings do not stop stable tags |
| RA-10 | Release evidence is distributed across jobs and mutable references | Medium | Approval and audit decisions are hard to reproduce |

## Verified release behavior

### v1.5.8 was public with red release evidence

The latest v1.5.8 release-gate attempt failed. Required failures included:

- Pinned vulnerable-image efficacy: Trivy could not download its database from
  `mirror.gcr.io` because the request was unauthorized. The required Trivy
  image scan ended in `failed` with zero findings.
- Lifecycle: `test-oci-gc-mark-sweep.sh` exited because `LAYER_DIGEST` was an
  unbound variable.
- Platform: `/metrics` was unavailable or empty, so unmatched-path and health
  route metric assertions failed.
- The aggregate release result failed.

Soft/optional evidence was also red:

- Security reported 71 passing scripts and 1 failing script, but the job is
  configured `continue-on-error` and excluded from the blocking rollup.
- Mesh failed peer registration and failover behavior, but is optional.

The container publication run separately failed its final verification because
`ghcr.io/artifact-keeper/artifact-keeper-scanner-adapter:1.5.8` was missing.
The backend and OpenSCAP semver tags were already present.

The release job log evaluated the required release result as `failure` and
requested `draft: true`. GitHub's release API nevertheless showed v1.5.8 as a
public, non-draft release with `publishedAt=2026-07-15T23:05:14Z`. The exact
organization audit event was unavailable, but the release-triggered workflow
records `triggering_actor=brandonrc`. The subsequent failed-gate release job
found the public release and replaced every binary asset while requesting
`draft: true`. See `release-v1.5.8-incident-2026-07-15.md` for the timeline and
checksums. The control gap is that publication and mutation remain possible
after a failed verdict.

The same `v1.5.8` tag was used for two source commits: `69994531...` and later
`97680d2...`. All five attached binary checksums changed between the two tag
runs. The independently versioned scanner-adapter `1.2.0` tag also moved after
the release without a VERSION bump.

All visible tag-triggered release workflow executions from v1.3.0 through
v1.5.8 were failed or cancelled at the time of review.

### Release workflow does not fail closed

In `.github/workflows/release.yml`:

- The external release gate is called at `artifact-keeper-test@main`.
- The gate receives `backend_tag: dev`; its defaults include `web_tag: latest`
  and an IAC reference on `main`.
- Binary builds explicitly accept either `success` or `failure` from the full
  release gate.
- The GitHub Release job runs after successful binary builds even when the full
  release gate failed; it changes only the requested draft flag.

In `.github/workflows/docker-publish.yml`:

- A `v*` tag triggers semver and stable-tag publication independently of the
  release gate.
- Trivy uses `exit-code: 0`, so scan findings remain informational.
- Published-tag verification checks whether expected tags exist, not whether
  their digests equal an immutable tested release manifest.

## Gate accuracy baseline

In `artifact-keeper-test`:

- There are 382 `test-*.sh` files under `tests/`.
- There are 118 format test scripts, while the release matrix names 59.
- Security contains 72 tests, resilience 20, stress 5, and mesh 13.
- `test-oci-token-refresh-reuse-2477.sh` exists but is not named by the release
  format matrix.
- Security, stress, and mesh use `continue-on-error` and are excluded or
  softened by policy.
- Resilience test execution uses step-level `continue-on-error`; the job can be
  green after emitting failure warnings.
- Most aggregate predicates reject only `failure` or `cancelled`, allowing a
  required job to be `skipped` without failing the release. Only a small subset
  requires exact `success`.
- The test repository is checked out without an explicit `ref`, so jobs consume
  its default branch rather than a caller-recorded immutable revision.
- Chart default mismatches produce warnings instead of failures.
- Full-dependency clean-install smoke is opt-in and disabled in the release
  call.
- Chart upgrade uses hardcoded previous release `1.1.9`.
- Scan-completion validation is enforced for npm; OCI, Maven, PyPI, Cargo, and
  Helm remain warning-only scaffolds.

## Main-repository CI baseline

- `artifact-keeper/main` requires only `Backend Unit Tests`, `CI Complete`, and
  `Check Rust`.
- Required checks are not strict/up-to-date.
- Pull-request reviews, conversation resolution, and administrator enforcement
  are not required.
- No repository ruleset supplements branch protection.
- `artifact-keeper-test/main` has no branch protection or ruleset.
- Change detection runs only for push events. On pull requests, dependent image
  builds and smoke E2E can be skipped.
- `CI Complete` reports coverage as a warning rather than a blocking result.
- Coverage executes the library-test target with a 50% project floor and 70%
  changed-line threshold.
- There are 51 Rust files under `backend/tests`; 48 contain test annotations.
  The current integration workflow selects 15 files or partial groups, leaving
  33 annotated files and approximately 169 test functions outside that job.

## Environment-parity baseline

The release environment intentionally favors a small smoke topology:

- One backend and one web replica.
- Filesystem-style storage for primary flows.
- Rate limiting, network policy, ingress, autoscaling, and disruption budgets
  disabled.
- Dependency Track, edge replication, and some scanner/dependency services
  disabled in the default release path.
- Single-replica OpenSearch with reduced persistence/topology.
- Full-dependency smoke disabled by default.

These choices are reasonable for a fast smoke tier, but no mandatory
production-shaped tier compensates for the omitted behavior before promotion.

## Immediate containment criteria

Before the next stable release:

1. Resolve or formally disposition every deterministic v1.5.8 failure.
2. Produce a complete digest inventory for all release images and binaries.
3. Verify scanner-adapter version/tag policy and repair the missing-image path.
4. Complete the publication audit using organization audit data if/when the
   endpoint becomes available; retain the correlated event evidence meanwhile.
5. Run the full gate twice against the same immutable candidate and test SHA.
6. Require a named approver to record any temporary exception and expiration.

## Baseline limitations

- This is a point-in-time assessment; GitHub settings and action history can
  change independently of the repository.
- The actor or automation that published v1.5.8 after the draft decision still
  requires organization audit-log review.
- Script inventory measures discoverability, not assertion quality. Coverage
  mapping must classify each test by requirement and product risk.
- Production incident and escaped-defect history was not available in this
  repository and should be added to release-risk scoring when available.
