# Release Assurance Design

**Status:** Proposed

**Baseline:** `docs/audits/release-assurance-baseline-2026-07-15.md`

**Goal:** Make every public Artifact Keeper release reproducibly traceable to
an immutable candidate that passed the declared release policy.

## Problem statement

The existing system builds, tests, publishes images, and creates releases in
overlapping tag-triggered workflows. Those workflows do not share a single
immutable description of the candidate. Mutable tags and branches are used as
inputs, while some failures are allowed and semver publication can precede the
final verdict.

The design must answer one question with machine-verifiable evidence:

> Are the bytes being promoted exactly the bytes that passed every required
> check under the approved release configuration?

## Non-goals

- Rewriting all existing tests before improving release controls.
- Making every load or experimental test block every patch release.
- Replacing GitHub Actions or the existing container registries.
- Treating a higher test count as a substitute for artifact identity and
  fail-closed policy.

## Release invariants

These are implementation requirements, not recommendations:

1. **Build once, promote by digest.** A release candidate is built once. Stable
   tags are attached to the tested digest; stable artifacts are not rebuilt.
2. **No stable publication before verdict.** Semver, major/minor, and `latest`
   tags do not exist until all required gates pass.
3. **Immutable inputs.** Source, test repository, IAC/chart, images, binaries,
   actions, and configuration are recorded by SHA or digest.
4. **Exact success.** Every required job must return `success`. Missing,
   skipped, neutral, timed-out, cancelled, or failed are not success.
5. **Complete inventory.** Every test is either assigned to a suite or carries
   an owned, expiring exclusion.
6. **No publishable draft on failure.** A red candidate may retain workflow
   artifacts and reports, but no GitHub Release that can be manually published.
7. **Promotion is monotonic.** A released version and its digests are immutable;
   reruns cannot silently replace them.
8. **Exceptions are evidence.** A waiver identifies risk, owner, approver,
   issue, reason, scope, and expiration. It cannot be a workflow comment alone.

## Target release flow

```text
source SHA
    |
    v
build candidate ----------> candidate lock manifest
    |                              |
    +------------------------------+
                   |
                   v
       tests use exact digests + exact refs
                   |
                   v
          signed gate verdict + evidence
                   |
             required success?
              /           \
            no             yes
            |               |
       retain report   protected approval
       no stable tags        |
                             v
             promote existing digests atomically
                             |
                             v
             verify registry + attestations + assets
                             |
                             v
                    create public release
```

The version tag is a promotion input, not a command to start publishing
unvalidated bytes. Initially the flow may be manually dispatched from an
approved source SHA. A later automation can create the version tag after the
candidate verdict rather than before it.

## Candidate lock manifest

Every candidate produces a JSON document stored as an immutable workflow
artifact and signed/attested before promotion. At minimum it contains:

```json
{
  "schema_version": 1,
  "version": "1.5.9-rc.1",
  "source_sha": "...",
  "test_repo_sha": "...",
  "iac_sha": "...",
  "workflow_refs": {"candidate": "...", "gate": "..."},
  "images": {
    "backend": "ghcr.io/...@sha256:...",
    "web": "ghcr.io/...@sha256:...",
    "openscap": "ghcr.io/...@sha256:...",
    "scanner_adapter": "ghcr.io/...@sha256:..."
  },
  "binaries": {"target": {"sha256": "...", "artifact": "..."}},
  "chart": {"version": "...", "digest": "sha256:..."},
  "configuration_digest": "sha256:...",
  "created_at": "..."
}
```

The gate validates the schema and rejects tags, absent digests, duplicate
platforms, unapproved registries, or a source/version mismatch.

## Cross-repository contract

The application repository owns candidate construction and promotion. The test
repository owns test inventory, environment provisioning, and gate evaluation.

The caller supplies:

- Candidate manifest artifact/digest.
- `source_sha`, `test_repo_sha`, and `iac_sha`.
- Release-policy version.
- Requested gate profile.

The called workflow:

- Checks out `artifact-keeper-test` at the supplied SHA.
- Pulls images only by digest from the candidate manifest.
- Records effective Helm values and environment topology.
- Produces normalized JUnit plus a machine-readable gate verdict.
- Returns success only when all policy-required suites are exactly successful.

The application workflow verifies the verdict belongs to the same candidate
manifest before promotion.

## Gate policy

Tests are classified by release risk rather than historical workflow layout.

| Tier | Purpose | Typical execution | Policy |
|---|---|---|---|
| Merge | Prevent obvious regressions | Every PR | Required when relevant paths change |
| Candidate | Validate exact releasable bytes | Every candidate | Always required |
| Production parity | Validate topology, upgrade, rollback, dependencies | Every stable candidate | Required for stable promotion |
| Operational qualification | Load, long soak, destructive chaos | Scheduled and release-candidate window | Required when its SLO/policy says due |

Candidate blockers include:

- Version and digest-set integrity.
- Unit, selected integration, migration, and supported-format E2E.
- Authentication, authorization, security, and vulnerability efficacy.
- Clean install and upgrade from the current previous GA.
- SBOM, provenance, signature, and required-image completeness.
- API/schema compatibility and critical lifecycle operations.

Stress or long-soak tests may run outside the critical path only when the
release policy records a recent qualifying run against the same source lineage
and no relevant code has changed. A failing qualification is never converted
to green with `continue-on-error`.

## Test inventory contract

`artifact-keeper-test` gains a versioned manifest. Each entry defines:

- Stable test ID and script path.
- Owning team.
- Product capability and risk tags.
- Required environment/features.
- Gate tiers and supported release profiles.
- Timeout and expected result type.
- Quarantine/waiver metadata when applicable.

CI fails when:

- A discoverable `test-*.sh` is absent from the manifest.
- A manifest path no longer exists.
- A required suite selects zero tests.
- A quarantine is expired or lacks an issue and owner.
- JUnit counts disagree with selected/executed tests.

## Promotion and verification

Promotion performs registry-side tag attachment or digest copy from candidate
digests. It then verifies:

- Every expected registry and platform resolves to the locked digest.
- No expected component is missing.
- SBOM, provenance, and signature attestations refer to that digest.
- Binary checksums match the candidate lock.
- Chart defaults resolve to the same release component versions.
- `latest` moves only for a stable, non-prerelease promotion.

Only after verification does the workflow create a public GitHub Release and
attach the already-verified binaries, manifest, checksums, and evidence report.

## Protection and approval model

- Both repositories require pull requests, owner approval, current branches,
  conversation resolution, and required checks.
- Administrators follow the same protection for normal changes.
- Promotion uses a protected GitHub Environment with named approvers.
- The test manifest, gate evaluator, promotion workflow, and waiver policy have
  CODEOWNERS coverage.
- A break-glass path requires an incident/exception issue and separate approval.
  It cannot overwrite an existing released version or bypass digest validation.

## Production-parity profile

The stable-candidate profile adds the behavior omitted by fast smoke tests:

- Multiple backend/web replicas.
- External object storage.
- Ingress/TLS and network policies.
- Rate limiting and shared-state concurrency.
- Autoscaling and pod-disruption behavior.
- Production-shaped OpenSearch and required dependencies.
- Upgrade from the immediately previous GA discovered from release metadata.
- Rollback with artifact readability and schema compatibility checks.

Fast smoke remains useful, but it is not the final stable-release verdict.

## Release evidence report

The promotion job publishes a concise report containing:

- Candidate identity and all immutable refs/digests.
- Required, optional, skipped, quarantined, and waived tests.
- JUnit totals, duration, retries, and flake signals.
- Coverage and changed-risk mapping.
- Vulnerabilities, efficacy checks, SBOM/provenance/signature verification.
- Install, upgrade, rollback, and production-parity results.
- Approval identity and any active exception.

The report is generated from machine results; prose summaries cannot override
the verdict.

## Rollout strategy

1. Make current deterministic gates green without weakening assertions.
2. Add the manifest and strict evaluator in observation mode.
3. Build immutable candidates and run the new gate as a shadow workflow.
4. Prove two consecutive same-candidate rehearsals are green and reproducible.
5. Switch stable tags and GitHub Release creation to the promotion workflow.
6. Disable the old tag-triggered stable publication path.
7. Tighten branch protections and expand production-parity coverage.

The old publication path remains available only until shadow evidence proves
the new path, but it must not run concurrently after cutover.

## Definition of done

- A public version maps to one immutable candidate manifest.
- All public images and binaries match the manifest exactly.
- Every required gate is `success`; required skipped/missing work fails closed.
- A failed candidate cannot produce stable tags or a publishable release.
- Both repositories enforce review and the declared required checks.
- Test inventory reconciliation is automatic.
- Stable candidates pass install, previous-GA upgrade, rollback, and the agreed
  production-parity profile.
- Two independent rehearsals can reproduce the verdict for the same candidate.

