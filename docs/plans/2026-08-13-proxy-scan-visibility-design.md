# Proxy Scan Visibility and SBOM — Design (v2)

**Date**: 2026-08-13
**Status**: Revised after four-lens audit; two prerequisite bugs must land first
**Target milestone**: 1.8.0
**Branch**: `feat/proxy-scan-visibility`
**Supersedes**: v1 of this document (commit `177e179f`)

## Revision note

v1 was audited by four independent reviewers (security, architecture,
fact-check, adversarial). Of six load-bearing claims, only one survived
unqualified. This revision incorporates their findings. Material corrections
from v1 are listed in "Corrections to v1" at the end.

Cite **symbols, not line numbers**. v1's line references had drifted in four
places; this document names functions and files only.

## Problem

Artifact Keeper scans proxy-cached artifacts and blocks vulnerable ones at
download time (#2954 PyPI, #3003 npm and Docker/OCI). None of it is visible.

- No API exposes `proxy_scan_results`; the only reads are gate logic.
- The artifact Security tab renders a green shield reading **"No vulnerabilities
  detected for this artifact"** for proxy artifacts, including ones the gate
  just returned 403 for (`security-tab-content.tsx`, `total === 0` branch). This
  is more dangerous than the "cannot be scanned" string and is the primary bug
  to fix.
- Repository security scores ignore proxy repositories entirely.
- `Scan All` is enabled on all proxy repositories regardless of whether they
  have scannable rows.
- The user-facing string claims security scanning is unavailable for
  proxy-cached artifacts, false since #2954 (#3344).

## Prerequisites — must land before this work

Two defects were discovered during the audit. Both corrupt the numbers this
design would surface, so both block it.

### P1 — Proxy `findings_count` is inflated by pin duplication

**Empirically confirmed** on a local stack, backend 1.7.1, Trivy not
registered (so this is not multi-scanner overlap):

```
same digest 2462f946… , same scanner grype-0.116.0
  proxy verdict  : findings_count = 2, medium_count = 2
  hosted scan    : findings_count = 1
  distinct CVEs  : 1  (CVE-2026-25645, medium, requests)
```

`ScanWorkspace::prepare_pinned` extracts the archive into a subdirectory and
writes the synthetic component pin into the workspace root. Syft therefore
catalogs the same component twice — once from the artifact's real
`dist-info/METADATA`, once from the pin — and grype matches the same CVE
against both. `aggregate_proxy_verdict` counts `findings.len()` with no dedup
by `cve_id`.

Consequence: every pinned file-format proxy verdict overstates its finding
count, roughly 2x. Surfacing this number in the UI would ship the miscount.
Fix requires dedup by `(cve_id, affected_component, affected_version)` before
aggregation.

### P2 — `scanner_version` records the first applicable scanner, not the CVE-authoritative one

`run_inline_proxy_scanners_target` captures the version of whichever scanner
runs first. Registration order places TrivyFsScanner before GrypeScanner, and
Trivy is applicable to `.whl`/`.tgz`. The freshness gate
(`verdict_is_fresh`) compares the stored string against
`cve_scanner_version()`, which resolves the **CVE-authoritative** scanner
(only grype is). In any Trivy-enabled deployment the two never match, so
`verdict_is_fresh` returns false permanently, the verdict cache is silently
defeated, and every proxy pull re-scans inline.

This design proposes displaying `scanner_version` to users. It must be the
right engine's before it is shown.

Both are separate bug issues, not part of this feature.

## Scope

Three slices, split by risk and by data store. Each ships independently.

### Issue 1 — Surface proxy scan verdicts for PyPI and npm (read-only)

**Format coverage is explicitly PyPI and npm only.** Docker/OCI is a different
data store and a different response shape; see Issue 1b. v1 claimed all three
formats and could not have delivered OCI.

**Data source.** `proxy_cache_artifacts ⋈ proxy_scan_results` on
`checksum_sha256`, filtered `scan_type = 'grype'`. The `scan_type` filter is
mandatory: `uq_proxy_scan` is `(checksum_sha256, scan_type)`, so a join without
it will duplicate listing rows the day a second scan type is written.

**Query shape.** Use `LEFT JOIN LATERAL (… LIMIT 1)` on the paginated listing,
or a second batched `WHERE checksum_sha256 = ANY($1)` over the already-sliced
page. A plain `LEFT JOIN` combined with the listing's `path ILIKE '%…%'` filter
risks the planner flipping to a hash join and materialising the entire global
`proxy_scan_results` table. Both alternatives avoid N+1 and are plan-stable.

**Index.** The repo-level summary aggregates over all of a repository's cache
rows against a global verdict table on every Security-tab render. It requires
`CREATE INDEX idx_proxy_cache_repo_checksum ON proxy_cache_artifacts
(repository_id, checksum_sha256)` — migration **196** (next free slot,
collision-checked against all active `release/*` branches).

v1 claimed "no migration required" on the strength of an EXPLAIN run against a
single-row table. That EXPLAIN covered the listing query, not the summary
query, and proved nothing at scale. The claim is withdrawn.

**State contract.** Five states. `verdict='error'` is **not** among them — it
is unreachable dead code with zero production writers.

| State | DB predicate | Renders as |
|---|---|---|
| `clean` | row, `verdict='clean'`, fresh | "Clean" + relative age |
| `vulnerable` | row, `verdict='vulnerable'` | severity counts + max severity |
| `stale` | row exists, `verdict_is_reusable` false | prior verdict, explicitly marked no longer authoritative |
| `pending` | no row, recent serve with `X-AK-Scan: pending` | "Scan in progress" |
| `not_scanned` | no row | "Not scanned" **plus a reason** |

`not_scanned` MUST carry a reason discriminant. The reasons are materially
different and at least two of them mean *content was served without ever being
scanned*:

- `scanning_disabled` — `scan_on_proxy` off for this repository.
- `format_unsupported` — format has no proxy gate wiring.
- `exceeds_size_cap` — object over `PROXY_SCAN_MAX_BYTES` (200 MiB). Under
  fail-open the handler streams it and never calls `proxy_scan_and_record`,
  not even asynchronously. No rescan job exists. This is permanent.
- `identity_unestablished` — the gate deliberately declines to scan rather than
  record an unfounded clean verdict. Also permanent.
- `inconclusive` — the scan ran and failed (engine error, budget timeout, empty
  catalog). Writes no row today. Under `fail_closed` the user received a 423.

Rendering `inconclusive` or `exceeds_size_cap` as "scanning disabled" would be
the same false reassurance this work exists to remove.

**Freshness.** Compute a `stale: bool` from the existing pure
`verdict_is_reusable` predicate. Do not require the user to infer staleness by
reading a timestamp. A `clean` verdict older than the freshness threshold must
not render with the same visual confidence as a same-day scan.

**Cross-tenant caveat.** Verdicts are global by content digest. A repository
with `scan_on_proxy` **off** can inherit a verdict recorded by another
repository or tenant for byte-identical content. The UI must not imply "this
repository scanned this," and the API must not expose
`proxy_scan_results.repository_id`. Add a source-scanning test asserting the
query never selects that column; `security.rs` already has this test idiom.

**API.** `analyzable` is unchanged. A new always-serialized field is added —
never `skip_serializing_if`, because clients must distinguish "old server" from
"never scanned":

```jsonc
{
  "analyzable": false,
  "capabilities": { "sbom": false, "on_demand_scan": false, "verdict": true },
  "scan_verdict": {                    // null when no row
    "source": "proxy",
    "state": "vulnerable",
    "stale": false,
    "max_severity": "medium",
    "findings_count": 1,
    "critical_count": 0, "high_count": 0, "medium_count": 1, "low_count": 0,
    "scanner_version": "grype-0.116.0",
    "scanned_at": "2026-08-13T20:11:49Z"
  },
  "not_scanned_reason": null           // set when scan_verdict is null
}
```

Named `scan_verdict` with a `source` discriminant rather than `proxy_scan`:
the latter bakes a workaround into the public API and would be wrong forever if
unification lands.

`capabilities` replaces the impulse to flip `analyzable`. `analyzable` means
"this id resolves to an `artifacts` row" — it is also `false` for historical
`artifact_versions` rows, which have nothing to do with proxying — and it gates
three affordances, not one: the SBOM generate button, the Security tab empty
state, and the scans section empty state. Issue 1 ships `capabilities` with
only `verdict` true; Issue 2 flips `sbom`; unification would make them all true
and retire the object.

**Endpoint.** `GET /api/v1/repositories/:key/security/proxy-scans` — vocabulary
matches the existing `scans`/`findings`/`scores`/`policies` siblings. It must be
scoped through `proxy_cache_artifacts` for the calling repository and must not
accept a caller-supplied digest, which would make it a cross-tenant lookup
oracle.

**Authorization — explicit, because the two candidate patterns differ.**
`list_repo_scans` and `get_repo_security` require authentication
unconditionally, *including for public repositories*. `list_artifacts` does
not — `require_visible` returns `Ok(())` immediately when `repo.is_public`.
Attaching verdict data to the artifact listing without a decision here would
make vulnerability data anonymously readable on public proxy repositories.

**Decision: vulnerability data follows the `security.rs` pattern.**
`scan_verdict` is omitted (null) for unauthenticated callers on public
repositories; the new endpoint requires authentication. Integration test
required.

**Web.**

- Replace the green "No vulnerabilities detected" shield for proxy artifacts
  with the verdict panel. This is the primary fix.
- Narrow the SBOM tab copy to SBOM specifically. Note
  `ARTIFACT_NOT_ANALYZABLE_MSG` is shared by SBOM, scan trigger, and signing —
  changing it touches all three (#3344).
- Repository Security tab: proxy summary by state.
- `Scan All`: gate on **whether the repository has scannable rows**, not on
  `repo_type == Remote`. OCI remote repositories accumulate real `artifacts`
  rows for proxied manifests (#1505) and `Scan All` genuinely works there today;
  a repo-type check would remove working functionality.
- The verdict panel MUST state that per-CVE detail is unavailable for
  proxy-cached content and name the available workaround. This is a hard
  requirement, not polish — without it Issue 1 tells users they are blocked and
  offers no path forward.

**Policy Blocks tile: removed from scope.** v1 filed it under Web; the hardcoded
`0` is in the backend (`build_dashboard_summary`). More importantly there is no
data source for a block *count* — `proxy_scan_results` stores verdicts, not
events — and both candidate sources (audit trail, metrics) are out of scope.
Replacing a hardcoded `0` with a differently-wrong number under a security label
is worse than leaving it.

### Issue 1b — Extend verdict visibility to Docker/OCI

Separate slice, different data store. OCI content is in `oci_blobs` /
`manifest_blob_refs`, not `proxy_cache_artifacts`. The Docker view requests
`group_by=docker_tag`, which returns `DockerTag[]` and never reaches
`ArtifactResponse`, so the Issue 1 field addition does not surface there. The
join key also differs: `proxy_scan_results.checksum_sha256` stores bare hex,
while manifest digests carry a `sha256:` prefix requiring normalisation, as the
existing OCI verdict joins already do.

Also in scope here: the virtual-repository path, where verdicts resolve through
members.

### Issue 2 — SBOMs for proxy-cached content

**Reuse the existing SBOM tables. Do not create `proxy_sbom_components`.**

`sbom_components` already has exactly the required columns: `name, version,
purl, cpe, component_type, licenses TEXT[], sha256, supplier, external_refs`.
The only obstacle is `sbom_documents.artifact_id UUID NOT NULL REFERENCES
artifacts(id)`.

**Migration (197):** make `artifact_id` nullable, add `content_digest TEXT`, a
CHECK that exactly one of the two is set, and a partial unique index on
`(content_digest, format)`.

This is smaller than a new table plus a new insert path plus a new serve path.
It reuses the `#903` content-hash cache and the licenses GIN index, makes every
existing SBOM consumer (license policy, Dependency-Track export) work for proxy
content for free, and is the **first step of unification** rather than a fourth
parallel structure to unwind later.

**Catalog retention.**

1. Do **not** extend `CatalogedComponent`. That type feeds the #3003 fail-closed
   identity check and its derived `PartialEq`; changing it is a security-path
   change, not a refactor. Add a separate detail type, or carry the BOM bytes
   through unparsed.
2. Retain `purl`, `licenses`, and component `type`. Note `type` is currently the
   filter predicate (`type == "library"`), so retaining it is a change to that
   filter's behaviour — `type: "file"` entries are excluded today by design.
3. **Bound the parse.** Enforce `PROXY_SBOM_MAX_COMPONENTS = 10_000` *during*
   collection — stop consuming once the limit is reached and mark the document
   as refused — and cap individual field lengths at
   `PROXY_SBOM_MAX_FIELD_LEN = 1024` for `name`, `purl`, and `license`.
   These strings originate in files inside untrusted upstream artifacts. v1
   specified collect-then-sort-then-truncate, which fully materialises an
   attacker-influenced vector and runs an O(n log n) sort that the scan's
   `tokio::timeout` cannot preempt.
4. **Sanitize before persisting.** A raw BOM carries syft
   `evidence.occurrences.location` values exposing internal workspace paths.
5. **Deduplicate.** Per P1, the pin causes duplicate components. Dedup by
   `(name, version, purl)` before persisting.

**Write path.** `record_verdict` is a single statement whose failure is
swallowed with `warn!` — there is no transaction today. Choose explicitly:
either introduce one, or accept a verdict without its catalog and define the
recovery. **The catalog write must sit outside `PROXY_SCAN_INLINE_BUDGET`** — a
slow insert inside the budget can push the scan future into timeout and thereby
change the block/serve decision.

**Completeness.** Reuse the existing `inventory_completeness` mechanism
(`artifact-keeper:scan-completeness`, #1153) rather than a bespoke `truncated`
flag. Policy on overflow is **document-level refusal**, not truncation: an SBOM
missing components while looking complete is worse than no SBOM for its actual
uses (license compliance, VEX matching).

**Render path.** `generate_cyclonedx_inner` and `generate_spdx_inner` take
`&[DependencyInfo]` and are `&self` methods on `SbomService`, so reuse requires
a service instance. `DependencyInfo.license` is **singular** and
`component_type` is hardcoded `"library"`. Persisting `licenses[]` and `type`
without widening `DependencyInfo` would store data the renderer discards.

**Capabilities.** Flip `capabilities.sbom` only. `on_demand_scan` stays false:
`trigger_scan` resolves ids against `artifacts` and would 404 on a synthetic id.

**Provenance — stronger than v1 stated.** The pin is not merely an extra
top-level component:

- It **duplicates** a component the artifact genuinely contains (P1).
- For npm the pin merges into `package-lock.json`, which lists *declared
  transitive dependencies*. An npm tarball does not vendor `node_modules`, so
  the resulting BOM asserts components the artifact does not contain.
- `proxy_scan_results` has no format column, so byte-identical content pulled
  through a PyPI proxy and a Generic proxy shares a digest; the Generic repo
  would serve an SBOM built from the PyPI repo's request coordinate.

These SBOMs describe *what the scanner cataloged*, not *what the artifact
contains*. They MUST be labelled accordingly and MUST NOT be presented as
attestation-grade without an explicit product decision.

## Out of scope

- Per-CVE finding detail for proxy content. Note this is **not** blocked on
  unresolved design — the findings exist at `aggregate_proxy_verdict` and cost
  one digest-keyed table. It is deferred on value, not feasibility, and should
  be compared against SBOM on user value before either is built.
- Audit trail for proxy blocks; Prometheus metrics for proxy scan decisions.
- `severity_threshold` ignored by the proxy gate (#3243), blocked on #3306.
- Verdict staleness root cause (#3287). This design renders staleness; it does
  not fix it.
- Writing `artifacts` rows for proxy content (see below).

## Why unification is deferred

v1 argued this on storage-key doubling. That is the weaker half. The stronger
argument: four subsystems now treat "proxy content has no `artifacts` row" as a
correctness invariant, not a workaround — the trigger-maintained usage ledger
charges `hosted_bytes` on `storage_key NOT LIKE 'proxy-cache/%'` (migrations
171/182), quarantine (#2940), `artifacts_search_vector` (176), and the
digest-keyed verdict model itself, which shares verdicts cross-repo and
survives cache eviction. An `artifacts`-row model would lose that last
property.

Unification is a data-model migration with a ledger backfill, not a
storage-routing fix. It is also true that #1278's root cause is unrepaired
(`storage_for_artifact` does not exist), and OCI demonstrates the pattern can be
done safely with the per-repo key convention (#1505).

## Risks

- **Fail-closed caches the bytes it refuses to serve.** The cache write happens
  inside the fetch, before the gate decides. A 403'd vulnerable artifact is
  resident in local storage and counted in the catalog. This is why the join
  works at all; it is also an undocumented posture, and the listing will now
  advertise "vulnerable, blocked" for bytes on disk.
- **Legacy cold caches.** A repository with zero catalog rows falls back to
  storage enumeration and would render `scan_verdict: null` for everything.
- **Placeholder rows.** `record_proxy_download` upserts a row with
  `checksum_sha256 NULL` before the content commits; that row transiently joins
  to nothing.
- Cross-tenant verdict inheritance and `scanned_at` timing as an inferential
  side channel (low value for public upstream content).

## Testing

**Unit.** State mapping across all five states plus every `not_scanned` reason,
including `checksum_sha256 IS NULL`. Staleness computation. Catalog parse with
`purl`/`licenses`/`type`, bounded collection, field-length caps, dedup.

**Integration.** Verdict written by the gate is readable through the new API.
Summary counts correct across mixed states. `repository_id` never selected.
`scan_verdict` omitted for anonymous callers on public repos. Serde test
asserting the field is always serialized.

**Performance.** Plan-stability test for the listing join and the summary
aggregate at representative scale. v1 had none; this is how the index gap was
missed.

**End-to-end** (reproducible locally): enable `scan_on_proxy` + `fail_closed`,
pull a CVE-bearing package, assert 403, assert the verdict row, assert the API
surfaces it, assert the UI renders it instead of the green shield.

**Regression.** `analyzable` unchanged throughout. The gate's block/serve
decision unchanged — existing proxy scan tests pass untouched. #3003 identity
check untouched.

## Corrections to v1

| v1 claim | Correction |
|---|---|
| Covers PyPI, npm, Docker/OCI | Issue 1 covers PyPI and npm only; OCI is a different store, shape and join key |
| No migration required | Summary endpoint needs an index (196) |
| "Verified query plan" | EXPLAIN was one row and covered a different query; claim withdrawn |
| Four states incl. `error` | `error` is unreachable; five states plus a reason discriminant |
| Fix Policy Blocks tile (Web) | Backend hardcode, and no data source exists; removed from scope |
| Fix "cannot be scanned" copy | The dangerous string is the green "No vulnerabilities detected" shield |
| Disable `Scan All` on proxy repos | Would break OCI proxies where it works; gate on scannable rows |
| Flip `analyzable` in Issue 2 | `analyzable` also gates on-demand scan, which would 404; use `capabilities` |
| New `proxy_sbom_components` table | Relax `sbom_documents.artifact_id`; reuse `sbom_components` |
| Write "inside the existing transaction" | No transaction exists; must be chosen explicitly |
| Generators take `Vec<DependencyInfo>` | `&[DependencyInfo]`, `&self` methods, singular license, hardcoded type |
| Field named `proxy_scan` | `scan_verdict` + `source` discriminant |
| Cap at persist, sorted, truncate | Bound during parse; refuse at document level |
| Pin is a defensible top-level component | Also duplicates real components and inflates npm transitives |
| Evidence: "2 findings" | One CVE double-counted (P1) |

## Coverage and duplication gates

Per CLAUDE.md: >= 70% coverage on changed lines, <= 3% duplication. Extract
state-mapping and staleness logic into pure functions so they are coverable
without database fixtures.
