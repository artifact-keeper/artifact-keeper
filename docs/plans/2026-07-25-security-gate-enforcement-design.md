# Security Gate Enforcement: Design

**Date**: 2026-07-25
**Branch**: `fix/scan-policy-enforcement` (worktree, based on origin/main c88fc0ae)
**Repos touched**: `artifact-keeper` (backend fix), `artifact-keeper-test` (DTF release-gate tests)

## Context

Live verification during demo preparation (recorded in the demo repo's
`attack/findings.md`, verified against both a running 1.5.8 instance and
current source) found three enforcement gaps where existing API surface and
schema promise behavior the runtime does not deliver:

1. `scan_policies` (name, max_severity, block_unscanned, block_on_fail) are
   full CRUD via `/api/v1/security/policies`, and
   `PolicyService::evaluate_artifact` implements the evaluation completely,
   but nothing ever calls it. Policies are decorative.
2. The quarantine state machine has `clean`, `flagged`, and `quarantined`
   states with admin release/reject endpoints, but no transition from
   `flagged` to `quarantined`. `/quarantine/{id}/reject` returns 409 unless
   the artifact is already quarantined. Findings can flag, never block, and
   an admin cannot escalate.
3. Repositories carry `curation_enabled` / `curation_default_action`
   columns and `/api/v1/curation/rules` accepts global block rules, but only
   the RPM/Debian curation-sync paths consult them. A block rule has no
   effect on proxy traffic. `CurationService` has zero references in
   `pypi.rs`.

These are completions of half-wired features, not new features. One GitHub
issue in `artifact-keeper` covers all three; one PR closes it. A companion
issue and PR in `artifact-keeper-test` add release-gate coverage (each
repo's PR must link an issue in that same repo).

## Goals

- A scan-policy violation actually blocks downloads, with the policy reason
  visible to the client and an admin release path.
- An admin can escalate a flagged artifact to quarantined.
- Curation block rules gate PyPI proxy traffic by package name, before
  upstream lookup.
- DTF tests prove all three behaviors in the release gate, version-gated so
  older release candidates are not failed retroactively.
- All verified locally (unit tests, DTF scripts against a locally built
  image, and the demo repo's attack script) before any push.

## Non-goals

- Download-time policy re-evaluation (policies apply at scan time; a rescan
  or new scan picks up policy changes).
- Curation enforcement for formats other than PyPI, and for the `review`
  action on proxies (only `block` is enforced; `allow` and non-matching
  fall through).
- Scanning proxy-cached artifacts (scan eligibility remains hosted-only).
- UI changes. All new behavior is API-visible; the existing UI already
  renders quarantine states.

## Design

### 1. Scan-policy enforcement at scan completion

`backend/src/services/scanner_service.rs`

Today `update_quarantine_status(artifact_id, findings_count)` sets `clean`
or `flagged` after a scan completes, and deliberately never downgrades an
existing `quarantined` status. Change the completion path to:

1. Look up the artifact's `repository_id`.
2. Call `PolicyService::evaluate_artifact(artifact_id, repository_id)`.
3. If the result has violations: set `quarantine_status = 'quarantined'`
   and record the joined violation strings as the quarantine reason,
   preserving the existing no-downgrade guard semantics.
4. If no violations: existing behavior exactly (clean or flagged by
   findings_count).

The status decision (findings_count, policy violations) -> (status, reason)
is extracted as a pure function with unit tests, following the codebase's
pure-core convention (see `block_unscanned_violated` in
`policy_service.rs`).

Because `check_artifact_download` already runs in every download handler
(28 files, hosted and proxy paths alike), blocking requires no new wiring.
The existing `POST /api/v1/quarantine/{id}/release` endpoint is the
recovery path; a release followed by an identical rescan will re-quarantine,
which is correct fail-closed behavior (acknowledging findings via the
existing acknowledge endpoint is the way to accept a risk permanently,
since `evaluate_artifact` only counts non-acknowledged findings).

Failure handling: if policy evaluation itself errors, log and fall back to
the current flagged/clean behavior rather than failing the scan write. A
broken policy engine must not take scanning down.

### 2. Admin quarantine transition

`backend/src/api/handlers/quarantine.rs`, `backend/src/services/quarantine_service.rs`

New endpoint: `POST /api/v1/quarantine/{artifact_id}` (admin-only, utoipa
annotated, registered in the quarantine router and ApiDoc). Body:
`{ "reason": string (optional) }`. Sets `quarantine_status = 'quarantined'`
with the given reason (default "Quarantined by administrator"). Valid from
`clean`, `flagged`, or NULL; a no-op 200 if already quarantined. Emits an
audit entry (same pattern as release/reject). The service half is a small
function beside the existing release/reject logic, with the state
transition expressed as a pure function and unit-tested.

### 3. Curation gating on the PyPI proxy

`backend/src/api/handlers/pypi.rs`, `backend/src/services/curation_service.rs`

At the same interception points where the age gate hooks the PyPI proxy
(simple index project listing and file download), add a curation check that
runs only when the repository has `curation_enabled = true`:

1. Load enabled curation rules scoped to this repo or global
   (`staging_repo_id = repo.id OR staging_repo_id IS NULL`), ordered by
   priority. Reuse `CurationService`; rule matching itself is the existing
   pure `evaluate_in_memory` (package name against `package_pattern` glob,
   version wildcard on the index path since versions are not yet known,
   exact version on the download path).
2. If the winning action is `block`: return HTTP 403 with a JSON body
   carrying the rule's `reason`, before any upstream request. pip surfaces
   the body text.
3. `allow`, `review`, or no match: fall through to normal proxy behavior
   (on proxies, `review` is not yet meaningful; documented as such in the
   endpoint docs).

Rule loading per request is one indexed query; PyPI proxy metadata requests
already do repo-row lookups on this path, and rules tables are tiny. No
caching in this change (YAGNI; noted as a follow-up if profiling ever
cares).

Enabling curation on a repo: verify whether the repository update endpoint
already accepts `curation_enabled`; if not, add it (and
`curation_default_action`) to `UpdateRepositoryRequest` minimally.

### 4. Backend tests

- Unit tests beside each pure function: status decision (component 1),
  quarantine transition legality (component 2), proxy curation decision
  including priority and glob edge cases (component 3).
- Handler tests in `pypi.rs` following the existing age-gate test patterns:
  curation-enabled repo with a block rule returns 403 with the reason body
  on index and download paths; disabled repo unaffected.
- Handler test for the new quarantine POST endpoint (auth required, state
  transitions, audit row).
- `cargo sqlx prepare` regenerated for any new queries (dev DB on
  localhost:30432). `cargo fmt --check`, `cargo clippy --workspace`,
  `cargo test --workspace --lib` all green before push.

### 5. DTF release-gate tests

`artifact-keeper-test` repo, following its script contract (source
`tests/lib/common.sh`, RUN_ID-scoped resource names, PASS/FAIL sections,
JUnit XML, exit codes), all version-gated via `tests/lib/feature-flags.sh`
so pre-fix versions skip rather than fail:

- `tests/security/test-scan-policy-enforcement.sh`: create a blocking
  policy on a RUN_ID-scoped hosted repo, upload an artifact with known
  findings, wait for auto-scan, assert quarantined status, assert download
  blocked with policy reason, admin release, assert download succeeds.
- `tests/security/test-quarantine-admin-transition.sh`: upload a clean
  artifact, POST quarantine with a reason, assert blocked, release, assert
  unblocked; also assert the 409 behavior of reject on non-quarantined
  artifacts is unchanged.
- `tests/pullthrough/test-curation-proxy-block.sh`: curation-enabled PyPI
  remote with a block rule; blocked name returns 403 with reason at index
  and download paths; a non-matching package proxies normally.

### Demo integration (in the demo repo, after the fix verifies locally)

Build the backend image from the worktree, tag it locally (for example
`artifact-keeper-backend:demo-fix`), point the demo stack's
`ARTIFACT_KEEPER_VERSION` at it, re-run `act1-admin-setup.sh` (extended to
set `curation_enabled` on pypi-proxy), rework attack Moments 1 and 3 to
their originally planned blocking behavior, and re-verify all four moments
end to end. Repin to the real release tag once the PR merges and a release
is cut. Local builds are permitted (the cost rule forbids cloud builds
only).

## Delivery process

1. Implement on `fix/scan-policy-enforcement` in the isolated worktree
   (`/tmp/D1D8DEA9-BB0B-4381-953B-39F87F687E26-ak`); the main checkout's
   unpushed `feat/repo-export-import` work is untouched.
2. Verify: backend test suite, DTF scripts run locally against the locally
   built image, demo attack script green.
3. File the `artifact-keeper` issue (three gaps, evidence, fix summary);
   push branch; open PR with `Closes #N` using the PR template.
4. File the `artifact-keeper-test` companion issue; push the DTF test
   branch; open its PR referencing that issue.
5. After merge and release: repin the demo stack, update
   `attack/findings.md` to record the now-fixed behaviors.

## Risks

| Risk | Mitigation |
|------|------------|
| Scan completion writes fail if policy evaluation errors | Fail-open to flagged/clean on evaluation error; never break the scan write |
| Release gate breaks for older RCs | All DTF tests version-gated via feature-flags.sh |
| Re-quarantine after admin release surprises operators | Documented; acknowledge-findings is the permanent-accept path |
| Demo runs unreleased code | Honest: it is the product's main-bound fix, demoed from the fix branch; repin after release |
| Time (call is Tuesday) | Components 1+2 are small and independent of 3; land them first if 3 runs long |
