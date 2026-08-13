# Proxy Scan Visibility and SBOM — Design

**Date**: 2026-08-13
**Status**: Approved for implementation
**Target milestone**: 1.8.0
**Branch**: `feat/proxy-scan-visibility`

## Problem

Artifact Keeper scans proxy-cached artifacts and blocks vulnerable ones at
download time. That capability shipped in #2954 (PyPI) and #3003 (npm,
Docker/OCI). None of it is visible.

A user who enables `scan_on_proxy` gets enforcement with no instrumentation:

- No API exposes `proxy_scan_results`. The only reads are internal gate logic.
- The artifact detail view renders **"This artifact cannot be scanned."** for an
  artifact the gate may have just blocked.
- Repository security scores ignore proxy repositories entirely; a proxy repo
  that has blocked hundreds of pulls still grades A.
- The admin dashboard's "Policy Blocks" tile is hardcoded to `0`.
- `Scan All` is enabled on proxy repositories and silently reports success
  having scanned zero artifacts.
- The user-facing error string claims security scanning is unavailable for
  proxy-cached artifacts, which has been false since #2954 (tracked: #3344).

Separately, every inline proxy scan already generates a complete CycloneDX SBOM
and deletes it milliseconds later (see "Prior art" below).

## Evidence

Reproduced end-to-end on a local stack (backend 1.7.1, web 1.7.0) on
2026-08-13.

Proxy repository with `scan_enabled=true`, `scan_on_proxy=true`,
`proxy_scan_action=fail_closed`, pulling `requests-2.32.5-py3-none-any.whl`
from pypi.org:

```
GET /pypi/ak-demo-proxy/simple/requests/requests-2.32.5-py3-none-any.whl
  → HTTP 403 {"error":"scan_blocked","reason":"blocked by inline vulnerability scan policy"}

SELECT ... FROM proxy_scan_results;
  digest 2462f946… | grype | vulnerable | medium | 2 findings | grype-0.116.0
```

The verdict exists. Nothing surfaces it.

A byte-identical copy of the same wheel uploaded to a hosted repository
(`sha256` matches exactly) produces a full CycloneDX SBOM, a completed grype
scan, and a CVE history entry. The content is not the obstacle; the absence of
an `artifacts` row is.

## Prior art and constraints

**Why proxy content has no `artifacts` row.** #1278 — an `artifacts` row whose
`storage_key` points at the global backend, read back through the per-repo
backend, produced a doubled path (`/data/storage/<repo>/proxy-cache/<repo>/…`)
and HTTP 500 on filesystem backends. #1280 fixed it by deleting the insert. The
root cause was never repaired: `storage_for_artifact` does not exist anywhere in
the codebase, and `registry.rs:51-53` plus `filesystem.rs:99-118` are unchanged.
Re-enabling the insert today would produce cluster-lock-taking 507s on most
formats, and on PyPI a silent duplicate write that serves stale content
indefinitely.

This design therefore does **not** write `artifacts` rows for proxy content.
That remains a valid long-term direction (OCI already does it safely for
proxied manifests via #1505, using the per-repo key convention) and is filed
separately.

**The SBOM is already generated.** `run_grype_dir_with_catalog`
(`grype_scanner.rs:1096`) invokes grype with two presenters in one subprocess:

```rust
.args(["-o", "json",
       "-o", &format!("cyclonedx-json={}", bom_path.to_string_lossy())])
```

The in-repo comment states the intent: *"emits the FULL catalog (every component
syft found, matched or not), so we ask for both in the SAME invocation: no
second scan, no extra extraction, one subprocess."*

`parse_cyclonedx_catalog` (`grype_scanner.rs:289-306`) then reduces that BOM to
`{name, version}` pairs, uses it for one boolean identity check, and the file is
deleted at `grype_scanner.rs:1144`. PURL, licenses, and component type are
discarded at parse time.

## Scope

Two independent issues, split by risk rather than by feature. Issue 1 ships
without waiting on Issue 2.

### Issue 1 — Surface proxy scan results (read-only)

No migration. No writes. No changes to the gate's block/serve decision.

**Data source.** `proxy_cache_artifacts.checksum_sha256` joined to
`proxy_scan_results.checksum_sha256`. Verified query plan uses two existing
indexes (`idx_proxy_cache_repo`, `idx_proxy_scan_checksum`); no new index is
required.

**Three-state contract.** Absence of a verdict row is the common case and MUST
NOT render as "clean":

| State | Condition | Renders as |
|---|---|---|
| Not scanned | no row, or `checksum_sha256 IS NULL` | "Not scanned" + why (scanning disabled / format unsupported) |
| Clean | `verdict='clean'` | "Clean" + scanned timestamp |
| Vulnerable | `verdict='vulnerable'` | severity counts + max severity + blocked state |
| Error | `verdict='error'` | "Scan failed" — explicitly not clean |

**API.** New additive field on proxy artifact responses. `analyzable` is
deliberately left unchanged.

```jsonc
{
  "analyzable": false,          // unchanged: SBOM/on-demand scan still unavailable
  "proxy_scan": {               // null when never scanned
    "verdict": "vulnerable",
    "max_severity": "medium",
    "findings_count": 2,
    "critical_count": 0,
    "high_count": 0,
    "medium_count": 2,
    "low_count": 0,
    "scanner_version": "grype-0.116.0",
    "scanned_at": "2026-08-13T20:11:49Z"
  }
}
```

Rationale for not flipping `analyzable`: it gates the SBOM button. Flipping it
before Issue 2 lands would enable that button and return 404 — reintroducing the
exact defect this work exists to fix.

Endpoints:

- Repository artifact listing gains `proxy_scan` inline via `LEFT JOIN` (no N+1).
- `GET /api/v1/repositories/:key/security/proxy-verdicts` — repo-level summary
  and paged list.

**Web.**

- Artifact Security tab renders the verdict panel for proxy artifacts, replacing
  "This artifact cannot be scanned."
- SBOM tab copy narrowed to SBOM specifically, not "SBOM and scanning".
- Repository Security tab shows a proxy summary (scanned / clean / vulnerable /
  not scanned counts).
- `Scan All` disabled on proxy repositories, with an explanatory tooltip. Today
  it returns `{"artifacts_queued": 0}` with HTTP 200 — a false success.
- Admin dashboard: stop reporting a hardcoded `0` for Policy Blocks; report
  proxy and hosted separately rather than blending them.

Client uses `apiFetch` rather than the generated SDK, since
`@artifact-keeper/sdk` regenerates only on `release: published`. Migration to
the SDK is a follow-up.

### Issue 2 — Persist the component catalog and generate SBOMs for proxy content

One migration. Touches the gate's write path (not its decision path).

**Changes.**

1. `parse_cyclonedx_catalog` (`grype_scanner.rs:289`) retains `purl`,
   `licenses`, and component `type` in addition to name and version.
2. The CycloneDX BOM is serialized before `remove_file`
   (`grype_scanner.rs:1144`).
3. `ProxyScanVerdict` (`scanner_service.rs:2491`) carries the catalog;
   `run_inline_proxy_scanners_target` (`scanner_service.rs:2623`) stops dropping
   it.
4. New digest-keyed table `proxy_sbom_components`, written by
   `proxy_scan_and_record` (`proxy_helpers.rs:6229`) inside the existing
   transaction, using bulk `UNNEST` insert.
5. SBOM served for proxy artifacts from the persisted catalog, reusing
   `generate_cyclonedx_inner` / `generate_spdx_inner`, which take a
   `Vec<DependencyInfo>` and are already database-independent.
6. `analyzable` becomes `true` for proxy artifacts once a catalog exists —
   deferred to this issue, not Issue 1.

**Why this is cheap.** No new subprocess, no new grype flag, no syft install
(grype embeds syft). The expensive cataloging pass already runs on every scan.

**Digest-keyed SBOMs never go stale.** The component inventory of fixed bytes
cannot change. Unlike vulnerability verdicts, which rot as the CVE database
updates, an SBOM keyed on content digest is write-once and reusable forever,
across repositories and across cache evictions.

**Component truncation.** OCI images routinely produce thousands of components.
Persist at most `PROXY_SBOM_MAX_COMPONENTS = 5000` per digest, ordered by
component name for determinism. On overflow, record `truncated = true` on the
parent row and surface it in both the API response and the SBOM's generator
metadata, so a truncated SBOM is never presented as complete. Bulk insert via
`UNNEST`, never row-at-a-time.

**Provenance caveat.** For file-format scans, `ScanWorkspace::prepare_pinned`
(`scanner_service.rs:963`) injects a synthetic `METADATA` or
`package-lock.json` so grype has something to grade. That pin appears in the
CycloneDX catalog. It reflects the request coordinate and is defensible as the
SBOM's top-level component, but it is a component Artifact Keeper injected
rather than one discovered from the bytes. This must be recorded in the SBOM's
generator metadata and MUST NOT be presented as attestation-grade provenance
without an explicit decision.

## Out of scope

- Per-CVE finding detail for proxy content. `proxy_scan_results` stores counts
  only; individual CVEs are computed and discarded. Requires its own table and
  a resolution to the cross-tenant acknowledgment question (see Risks).
- Audit trail for proxy blocks (no audit write exists on the gate path today).
- Prometheus metrics for proxy scan decisions.
- `severity_threshold` ignored by the proxy gate (#3243) — blocked on #3306.
- Verdict staleness: `scanner_version` records the grype CLI version only, so
  CVE-database updates never invalidate a verdict (#3287).
- Writing `artifacts` rows for proxy content (separate issue).
- Extending proxy scan coverage beyond PyPI, npm, and Docker/OCI.

## Risks

**Cross-tenant data sharing.** `proxy_scan_results` and any digest-keyed
component table are global across repositories and tenants. Per-finding
acknowledgment or waivers therefore cannot be stored on these tables — one
tenant waiving a CVE would waive it for everyone. Issue 2 deliberately omits
acknowledgment columns. A scoped waiver model is a separate design.

**Provenance leakage.** `proxy_scan_results.repository_id` records which
repository first scanned a digest. It MUST NOT be exposed on a repo-scoped read.

**Stale verdicts rendered authoritatively.** Because of #3287, a verdict can be
up to 30 days old while looking current. Any verdict UI must display
`scanned_at` and `scanner_version` prominently.

**Eviction.** Verdicts and SBOM components survive proxy cache eviction by
design (they are digest-keyed). The repo-level listing joins from the cache
side, so an evicted-but-scanned digest disappears from the repository view while
its verdict is retained for reuse. This is intended and should be documented.

## Testing

**Unit.** Three-state mapping (not scanned / clean / vulnerable / error),
including `checksum_sha256 IS NULL` and `verdict='error'`. Catalog parsing with
PURL and license fields. Truncation behavior.

**Integration.** Verdict persisted by the gate is readable through the new API.
Repo summary counts correct across mixed states. Provenance field not exposed on
repo-scoped reads.

**End-to-end** (reproducible on the local stack):

1. Create a proxy repository; enable `scan_enabled`, `scan_on_proxy`,
   `proxy_scan_action=fail_closed`.
2. Pull a CVE-bearing package; assert HTTP 403 `scan_blocked`.
3. Assert a `proxy_scan_results` row exists with the expected verdict.
4. Assert the artifact listing returns a populated `proxy_scan` object.
5. Assert the repo summary reports the artifact as vulnerable.
6. Assert the UI renders the verdict rather than "cannot be scanned".
7. Issue 2 only: assert an SBOM is generated for the proxy artifact and its
   component list is non-empty and includes non-vulnerable components.

**Regression.** `analyzable` remains `false` for proxy artifacts throughout
Issue 1. The gate's block/serve decision is unchanged — existing proxy scan
tests must pass untouched.

## Coverage and duplication gates

Per CLAUDE.md: changed lines require >= 70% coverage and <= 3% duplication.
Read-path mapping logic should be extracted into pure functions so it is
coverable without database fixtures.
