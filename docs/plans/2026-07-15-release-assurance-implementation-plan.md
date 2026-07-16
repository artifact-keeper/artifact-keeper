# Release Assurance Implementation Plan

**Status:** Proposed

**Design:** `docs/plans/2026-07-15-release-assurance-design.md`

**Goal:** Migrate from tag-triggered, mutable-input publication to an immutable
candidate and fail-closed promotion process without introducing an untested
big-bang release workflow.

## Working rules

- Implement this plan as small pull requests; do not combine all phases.
- No PR weakens an existing assertion merely to make a gate green.
- Workflow changes include fixture-based tests for success, failure, skipped,
  cancelled, and missing outcomes.
- Rehearsal runs use prerelease/candidate namespaces and cannot change `latest`.
- Do not change branch settings until the named checks exist and are stable.
- Each phase updates the baseline risk IDs it closes or reduces.

## Phase 0 — Contain and establish ownership

### Task 0.1: Resolve the current release incident

**Repositories:** both

- [ ] Inventory v1.5.8 binary and image digests across GHCR and Docker Hub.
- [ ] Confirm scanner-adapter version policy and why its `1.5.8` tag was absent.
- [ ] Identify the organization audit-log event that published the draft.
- [ ] Fix Trivy database acquisition without making efficacy checks optional.
- [ ] Fix the OCI GC test's unbound `LAYER_DIGEST` behavior.
- [ ] Resolve the `/metrics` environment/product mismatch.
- [ ] Identify and disposition the single failing security script.
- [ ] Decide whether current mesh failures are product defects, unsupported
      capability, or environment defects; record the policy explicitly.
- [ ] Run the existing full gate twice against the same candidate inputs.

**Exit criteria:** Every deterministic failure has an owner and issue; no
unknown public-release transition remains; same-input reruns are understood.

### Task 0.2: Approve policy and ownership

- [ ] Assign owners for release workflow, test gate, security policy, charts,
      registries, and production-parity environment.
- [ ] Approve which suites are candidate blockers and which are scheduled
      qualifications.
- [ ] Approve waiver schema, maximum lifetime, and approvers.
- [ ] Record the current previous GA version source of truth.

**Exit criteria:** No implementation depends on an unnamed owner or unresolved
blocking-policy choice.

## Phase 1 — Make test execution measurable

### PR T1: Add a complete test manifest

**Repository:** `artifact-keeper-test`

**Expected files:**

- Create `tests/release-manifest.yaml`.
- Create `scripts/validate-release-manifest.sh`.
- Add manifest validation workflow/job.
- Update test contributor documentation.

**Work:**

- [ ] Inventory all 382 `test-*.sh` files.
- [ ] Give each test an ID, owner, capability, tier, environment requirements,
      timeout, and supported profiles.
- [ ] Classify all 118 format tests, including the 59 not currently named by
      the release matrix and `test-oci-token-refresh-reuse-2477.sh`.
- [ ] Make discovery-vs-manifest drift a required repository check.
- [ ] Add fixtures proving missing, stale, duplicated, and expired-exclusion
      entries fail validation.

**Validation:**

- Validator succeeds for the committed manifest.
- Adding an unlisted `test-example.sh` makes validator tests fail.
- Deleting a listed path makes validator tests fail.

**Risk reduced:** RA-07.

### PR T2: Normalize test results and gate evaluation

**Repository:** `artifact-keeper-test`

**Expected files:**

- Create a gate-evaluator script and JSON policy file.
- Add evaluator fixtures/tests.
- Modify `.github/workflows/release-gate.yml` rollup.

**Work:**

- [ ] Produce one normalized result per selected test and job.
- [ ] Validate JUnit selected/executed/pass/fail/skip counts.
- [ ] Fail a required suite that selected or executed zero tests.
- [ ] Require exact `success` for every policy-required job.
- [ ] Treat `skipped`, `neutral`, `cancelled`, `timed_out`, `action_required`,
      absent, and unknown as failures for required work.
- [ ] Keep an observation-mode flag for shadow rollout, but make its verdict
      explicit and never label red evidence green.

**Validation fixtures:**

- All required success: pass.
- One failure: fail.
- One skipped result: fail.
- One missing result: fail.
- Optional failure: verdict records failure but follows policy.
- Expired waiver: fail.

**Risk reduced:** RA-06, RA-10.

### PR T3: Pin the test repository and environment contract

**Repository:** `artifact-keeper-test`

- [ ] Add required `test_repo_sha`, candidate-manifest, and IAC SHA inputs.
- [ ] Set `ref: ${{ inputs.test_repo_sha }}` on every test-repository checkout.
- [ ] Verify the checked-out SHA before executing tests.
- [ ] Record effective Helm values and environment topology as evidence.
- [ ] Reject mutable image tags in strict/candidate mode.

**Validation:** A deliberately mismatched SHA or tag-only image fails before
environment creation.

**Risk reduced:** RA-03, RA-10.

## Phase 2 — Stabilize required gates

### PRs T4a–T4n: Fix or explicitly quarantine current failures

Split fixes by cause and owner:

- [ ] Trivy database authentication/cache/bootstrap reliability.
- [ ] OCI GC mark-sweep test variable handling and assertion coverage.
- [ ] Metrics route/configuration and route-cardinality assertions.
- [ ] Remaining security failure.
- [ ] Mesh registration/failover behavior if mesh is supported for release.
- [ ] Resilience execution: remove step-level `continue-on-error` and return the
      actual aggregate status.
- [ ] Security execution: remove job-level `continue-on-error` after known
      prerequisites are stable.
- [ ] Stress/mesh: replace `continue-on-error` with explicit policy output.

Each defect fix requires a test that fails before the fix. Infrastructure
repairs require an observable preflight and actionable diagnostic.

**Exit criteria:** Two consecutive full runs at the same source, test, IAC, and
image digests produce the same required verdict.

### PR T5: Complete upgrade and scan-efficacy gates

- [ ] Discover the previous GA dynamically; remove hardcoded `1.1.9`.
- [ ] Make chart/app/image version mismatches blocking.
- [ ] Enable full-dependency clean-install for stable candidates.
- [ ] Implement scan-completion fixtures for OCI, Maven, PyPI, Cargo, and Helm.
- [ ] Keep pinned-known-vulnerability tests fail-closed for each required
      scanner.

**Risk reduced:** RA-06, RA-08, RA-09.

## Phase 3 — Build immutable candidates

### PR A1: Introduce candidate construction and lock manifest

**Repository:** `artifact-keeper`

**Expected files:**

- Add a candidate workflow or refactor `.github/workflows/docker-publish.yml`
  into reusable build and promotion workflows.
- Add a lock-manifest generator and schema validation tests.
- Update release documentation.

**Work:**

- [ ] Build all images and binaries from one source SHA.
- [ ] Push images only to candidate/SHA namespaces during construction.
- [ ] Resolve every multi-architecture image to an immutable index digest.
- [ ] Generate checksums for every binary.
- [ ] Record source, test, IAC, workflow, chart, configuration, image, and
      binary identities in the candidate lock manifest.
- [ ] Sign/attest the lock manifest and upload it as an immutable artifact.
- [ ] Do not create semver, major/minor, `latest`, or GitHub Release outputs.

**Validation:** Re-running construction for an existing candidate cannot
silently replace the lock; schema/digest mismatch fails.

**Risk reduced:** RA-02, RA-03, RA-05, RA-10.

### PR A2: Call the release gate with immutable inputs

**Repository:** `artifact-keeper`

- [ ] Call the reusable workflow at an explicit test-repository SHA.
- [ ] Pass the matching `test_repo_sha`, IAC SHA, and candidate manifest.
- [ ] Replace `backend_tag: dev`, web `latest`, and mutable IAC inputs.
- [ ] Verify returned verdict manifest/candidate identity before continuing.
- [ ] Remove the condition that permits binary/release continuation after a
      required release-gate failure.

**Validation:** Changing any returned SHA/digest or returning skipped for a
required job stops the workflow.

**Risk reduced:** RA-01, RA-03, RA-06.

## Phase 4 — Rehearse, then cut over promotion

### PR A3: Add protected promotion

**Repository:** `artifact-keeper`

**Expected files:**

- Create `.github/workflows/promote-release.yml` or equivalent reusable job.
- Modify `.github/workflows/release.yml` and
  `.github/workflows/docker-publish.yml`.

**Work:**

- [ ] Require successful candidate, strict gate, required-image verification,
      and protected-environment approval.
- [ ] Promote existing digests to semver and stable tags without rebuilding.
- [ ] Verify every registry/platform tag equals the lock manifest.
- [ ] Make vulnerability-policy, SBOM, provenance, signature, and VEX checks
      blocking according to policy.
- [ ] Create the public GitHub Release only after promotion verification.
- [ ] On failure, retain evidence but create no publishable release object.
- [ ] Make released versions immutable and refuse conflicting reruns.

**Validation:**

- A failed gate creates no stable tags or GitHub Release.
- A missing scanner-adapter image stops promotion.
- A digest mismatch stops promotion.
- A successful prerelease rehearsal changes only prerelease tags.
- `latest` changes only for approved stable promotion.

**Risk reduced:** RA-01, RA-02, RA-05, RA-09.

### Operational cutover

- [ ] Run at least two shadow rehearsals against the same immutable candidate.
- [ ] Run one prerelease end-to-end promotion and installation.
- [ ] Confirm rollback procedure and registry permissions.
- [ ] Disable the old tag-triggered stable publication jobs.
- [ ] Enable protected-environment approval on the new promotion job.
- [ ] Monitor the first stable promotion with all owners present.

**Rollback:** Disable the new promotion trigger while preserving candidate
artifacts and evidence. Do not restore automatic stable publication before a
gate. Do not overwrite a version already made public.

## Phase 5 — Enforce merge quality

### PR A4: Correct pull-request change detection and CI rollup

**Repository:** `artifact-keeper`

- [ ] Run change detection for pull requests as well as pushes.
- [ ] Require image build and smoke E2E when relevant paths change.
- [ ] Make coverage failures block `CI Complete` when coverage is required.
- [ ] Make unexpected skips fail the CI rollup.
- [ ] Add workflow-lint and release-contract tests.

### PR A5: Expand Rust integration coverage deliberately

- [ ] Inventory the 33 annotated integration files outside the selected job.
- [ ] Map each to a capability and required environment.
- [ ] Execute, quarantine with owner/expiry, consolidate, or remove each file.
- [ ] Expand coverage to the agreed all-target/integration scope.
- [ ] Ratchet thresholds based on measured baseline rather than an arbitrary
      one-step jump.

### Repository settings change

After checks have stable names and acceptable reliability:

- [ ] Protect `main` in both repositories.
- [ ] Require pull requests, CODEOWNERS/owner review, current branches, and
      conversation resolution.
- [ ] Enforce required checks for administrators.
- [ ] Require manifest validation in `artifact-keeper-test`.
- [ ] Require CI aggregate, smoke/integration as applicable, coverage, and
      release-contract validation in `artifact-keeper`.

**Risk reduced:** RA-04, RA-07.

## Phase 6 — Add production-parity qualification

### PR T6: Stable-candidate environment profile

**Repository:** `artifact-keeper-test`

- [ ] Add multiple backend/web replicas.
- [ ] Use external object storage.
- [ ] Enable ingress/TLS and network policies.
- [ ] Enable rate limiting, autoscaling, and disruption budgets.
- [ ] Enable production-required scanner/dependency services.
- [ ] Exercise production-shaped OpenSearch.
- [ ] Capture the rendered manifests and effective values.

### PR T7: Upgrade and rollback qualification

- [ ] Install the dynamically discovered previous GA.
- [ ] Seed representative data and artifacts for supported formats.
- [ ] Upgrade to the exact candidate digests.
- [ ] Verify API, metadata, downloads, scans, and migrations.
- [ ] Execute the supported rollback strategy.
- [ ] Verify artifact readability and schema expectations after rollback.

**Risk reduced:** RA-08.

## Phase 7 — Release evidence and continuous risk management

### PR A6/T8: Generate the release evidence report

- [ ] Publish immutable refs/digests and configuration digest.
- [ ] Report selected/executed/pass/fail/skip/quarantine counts.
- [ ] Report retries, flakes, durations, coverage, and relevant changed areas.
- [ ] Report vulnerability policy and attestation verification.
- [ ] Report install, upgrade, rollback, and production-parity results.
- [ ] Attach active waivers and approval identity.

### Operating metrics

Track by release and rolling window:

- Required-gate first-pass rate.
- Flake/retry rate by test and runner pool.
- Median and p95 candidate-to-verdict time.
- Unexpected skips and zero-test suites.
- Quarantine count and age.
- Escaped defects by capability and missing test tier.
- Rollback success and time.
- Release exceptions and expiration compliance.

## Program completion checklist

- [ ] Every public release has one immutable candidate lock manifest.
- [ ] Tested and released digests are byte-identical.
- [ ] Failed candidates cannot create stable tags or publishable releases.
- [ ] Every required job must be exactly successful.
- [ ] Every test is manifested or has an owned, expiring exclusion.
- [ ] Both main branches enforce review and the declared quality checks.
- [ ] Stable candidates pass production-parity install, upgrade, and rollback.
- [ ] Release evidence is sufficient to reproduce the decision without reading
      raw workflow logs.

