# Proxy Scan Visibility — Design (v3)

**Date**: 2026-08-13
**Status**: Scoped to what is implementable against the current schema
**Target milestone**: 1.8.0
**Branch**: `feat/proxy-scan-visibility`
**Supersedes**: v1 (`177e179f`), v2 (`14bf52e7`)

## Revision note

v1 and v2 were each audited by independent reviewers. Both were found
unimplementable for the same root reason:

> **The system persists successful verdicts, not scan attempts.**

Every "why was this not scanned?" question is unanswerable from stored data.
v1 and v2 both specified UI states that no query can produce. v3 specifies only
what is derivable today, and names the rest as deferred with the write path each
would require.

v3 is deliberately smaller than v2. It drops the artifact-listing changes
entirely, which removes the anonymous-exposure problem, the join plan-stability
problem, and the `capabilities` contract problem in one move.

Cite symbols, not line numbers.

## Problem

Proxy-cached artifacts are scanned and blocked at download time (#2954, #3003).
None of it is visible. The specific, primary bug:

`security-tab-content.tsx` renders a green `ShieldCheck` headline reading
**"No vulnerabilities detected for this artifact"** whenever its finding total is
zero. For proxy-cached artifacts that total is *always* zero — it is driven by
CVE history, which is artifact-keyed and therefore structurally empty for proxy
content. So an artifact the gate returned 403 for displays a green all-clear.

That is the bug to fix. Everything else in this document is in service of
replacing that shield with the truth.

## Prerequisite

### P1 — Proxy `findings_count` is inflated for pinned wheel scans

Measured on a local stack (backend 1.7.1, Trivy not registered, so not
multi-scanner overlap):

| package | proxy `findings_count` | hosted findings | distinct CVEs |
|---|---|---|---|
| requests 2.32.5 | 2 | 1 | 1 |
| jinja2 2.11.2 | 10 | 5 | 5 |

`ScanWorkspace::prepare_pinned` extracts the archive into a subdirectory when a
pin is present and writes the synthetic pin into the workspace root. For a
**wheel**, the pin is a `<name>-<version>.dist-info/METADATA` — the same
cataloger input shape as the wheel's own METADATA — so syft catalogs the
component twice and grype matches each copy. `aggregate_proxy_verdict` is
`findings.len()` with no dedup.

**Correct characterisation** (v2 over-generalised this to "roughly 2x for all
pinned scans"):

- **PyPI wheels** — top-level findings are doubled. The observed 2x holds only
  because all findings in both samples were on the top-level component.
- **PyPI sdists** — *zero* inflation. A bare root `PKG-INFO` is not cataloged,
  so the pin is the only copy. That is why the pin exists.
- **npm** — a different bug. The top-level pin usually has no counterpart
  because syft does not catalog `package/package.json`. npm's real inflation is
  overlapping transitives when a tarball ships both `package-lock.json` and
  `npm-shrinkwrap.json`.

**Fix.** Dedup before `aggregate_proxy_verdict`, so severity buckets are
corrected too, on a key of `(cve_id, normalized_component_name,
affected_version)`. The name **must** be ecosystem-normalized: the pin uses the
PEP 503-canonical name while a wheel's own METADATA may say `PyYAML` or
`zope.interface`. Reuse `ExpectedComponent::normalize_name`, which exists for
exactly this comparison. A raw-string key would pass both samples above and fail
silently on any non-canonical distribution name. `cve_id` is `Option` and must
be handled. The hosted path counts with the same unguarded `findings.len()` and
should share the fix.

**P2 (`scanner_version` records the first applicable scanner rather than the
CVE-authoritative one) is no longer a prerequisite**, because v3 does not
display `scanner_version` and does not derive staleness from it. It remains a
real bug — it permanently defeats the verdict-reuse cache in any Trivy-enabled
deployment, forcing an inline re-scan on every proxy pull — and should be filed
and fixed on its own merits.

## Scope

One issue. PyPI and npm proxy repositories.

### What ships

**A single authenticated, repository-scoped endpoint.**

```
GET /api/v1/repositories/:key/security/proxy-scans          → summary + paged list
GET /api/v1/repositories/:key/security/proxy-scans?path=…   → one cached path
```

Lookup is **by cache path, not by digest**. A digest parameter would make the
endpoint a cross-tenant lookup oracle; a path is inherently scoped to the
calling repository. The join to `proxy_scan_results` happens server-side after
the path is resolved through `proxy_cache_artifacts` for that repository.

**Authorization** follows the `security.rs` pattern — authentication required
unconditionally, including for public repositories, matching `list_repo_scans`
and `get_repo_security`. Vulnerability data is not anonymously readable.

**`list_artifacts` is not modified.** v2 proposed attaching verdicts to the
artifact listing. That is dropped:

- It is anonymous-readable for public repositories (`require_visible` returns
  early on `is_public`), so it would have leaked vulnerability data.
- It would have needed a `LEFT JOIN LATERAL` for plan stability against the
  listing's `ILIKE` filter.
- It would have put a new field on the shared `ArtifactResponse`, which is also
  used for hosted artifacts and historical `artifact_versions` rows.

The web fetches verdicts from the dedicated endpoint instead. No per-row badge
in the listing in this iteration.

**`analyzable` is unchanged, and no `capabilities` object is introduced.** v2
proposed `capabilities` but specified only its proxy values; landing it on the
shared `ArtifactResponse` without hosted values would have disabled SBOM and
scan affordances on every hosted artifact. Deferred until something needs it.

**States — only what is derivable.**

| State | Derivation |
|---|---|
| `clean` | verdict row, `verdict='clean'` |
| `vulnerable` | verdict row, `verdict='vulnerable'` |
| `not_scanned` | no verdict row, plus a reason (below) |

`stale` is an **orthogonal boolean**, not a state — v2 listed it as both.

`verdict='error'` is not used; it is unreachable dead code with zero production
writers.

**`not_scanned` reasons — three, all derivable:**

| Reason | Derivation |
|---|---|
| `scanning_disabled` | `scan_configs.scan_on_proxy` is false for this repository |
| `format_unsupported` | repository format has no proxy gate wiring |
| `unknown` | everything else |

v2 specified `exceeds_size_cap`, `identity_unestablished`, `inconclusive`, and a
`pending` state. **All four are dropped as unimplementable.** They all write no
row, and nothing at rest distinguishes them. v2's `pending` predicate was also
actively wrong: npm's `Unestablished` path returns `Serve { pending: true }` and
sets `X-AK-Scan: pending` *without spawning any scan*, so the header fires on
permanently-unscannable content.

`unknown` must be worded so it does not imply safety. Recommended copy: *"Not
scanned — this artifact has no scan verdict on record."* It must not say
"scanning is disabled" unless that is the derived reason, and it must never
render as clean.

**Staleness is age-based only.**

```
stale := scanned_at < now() - DEDUP_TTL_DAYS
```

Pure SQL, derivable today, immune to P2, and expressible in a `GROUP BY` so the
summary remains a real aggregate.

v2 specified `verdict_is_reusable`. That is wrong on three counts: it is
policy-contaminated (it factors in `fail_closed`, so the same row would render
stale in one repository and fresh in another), it requires a live async scanner
probe so the summary could not aggregate, and it depends on `scanner_version`,
which P2 makes permanently mismatched — meaning every verdict would have
rendered stale.

**This staleness signal does not capture CVE-database staleness (#3287).** A
verdict inside the TTL can still be scanned against an outdated vulnerability
database. The UI must not imply otherwise. Suggested copy for a fresh clean
verdict: *"Clean as of <date>"* — a statement about when, not a guarantee about
now.

**Migration 196** — `CREATE INDEX idx_proxy_cache_repo_checksum ON
proxy_cache_artifacts (repository_id, checksum_sha256)`, enabling an index-only
outer scan for the summary aggregate. Collision-checked: main tops out at 195;
release/1.7.x at 192, 1.6.x at 175, 1.5.x at 155.

This is the only migration. Issue 1 is therefore not strictly "no migration" —
v1's claim to the contrary rested on a single-row EXPLAIN of a different query
and is withdrawn.

**The join must filter `scan_type = 'grype'`.** `uq_proxy_scan` is
`(checksum_sha256, scan_type)`, so an unfiltered join will duplicate rows the
day a second scan type is written.

**Rows with `checksum_sha256 IS NULL` are excluded explicitly.**
`record_proxy_download` upserts a placeholder before content commits; those rows
join to nothing and must not be counted as `not_scanned`.

**Deduplicate by digest in the summary.** One repository can cache the same
digest at many paths. The summary counts **distinct digests**, not paths, and
says so in the UI label.

**Web.**

- Replace the green shield for proxy-cached artifacts with the verdict panel.
  Note the shield and the #3344 caveat line are the *same component*, about ten
  lines apart — this is one edit, not two.
- The panel states that per-CVE detail is unavailable for proxy-cached content
  and names the available path (ingest into a hosted repository). Hard
  requirement: without it the feature reports a problem and offers no remedy.
- Repository Security tab: proxy summary by state, over distinct digests.
- The summary panel sits on the same tab as the repository security **grade**,
  which is computed from `artifacts ⋈ scan_results ⋈ scan_findings` and
  therefore reads **A** for a proxy repository full of blocked content. The
  panel must be visually adjacent to the grade and the grade must be labelled as
  covering hosted artifacts only. Otherwise this feature ships a contradiction
  on one screen.

### Deferred, with the reason

| Item | Blocked on |
|---|---|
| `exceeds_size_cap` / `identity_unestablished` / `inconclusive` reasons, `pending` state | A persisted scan-attempt-outcome table and a write on every failure branch. This moves the work out of the read-only risk class. |
| Per-row verdict badge in the artifact listing | Anonymous exposure on public repos; needs a separate decision |
| `Scan All` gating | Needs a new `scannable_artifact_count` on `RepositoryResponse`. No existing field works: `pagination.total` counts proxy-cache objects for Remote repos, not `artifacts` rows. A `repo_type` check is wrong because OCI remotes do get `artifacts` rows and `Scan All` works there today. |
| Docker/OCI verdicts | Different store (`oci_blobs` / `manifest_blob_refs`), different join key (`sha256:` prefix vs bare hex). Note the Docker **flat** view does return `ArtifactResponse` rows, so any future listing-level work must handle it. |
| Policy Blocks tile | No data source. `proxy_scan_results` stores verdicts, not events; audit and metrics are both out of scope. |
| Displaying `scanner_version` | P2 |
| Per-CVE detail for proxy content | Deferred on value, not feasibility — findings exist at `aggregate_proxy_verdict` and cost one digest-keyed table. Should be compared against SBOM on user value. |
| Proxy SBOM | See below |
| `artifacts`-row unification | See below |

### Proxy SBOM — deferred, with findings recorded

Every inline proxy scan already emits a complete CycloneDX BOM
(`run_grype_with_catalog` invokes grype with `-o json` and
`-o cyclonedx-json=<path>` in one subprocess) and deletes it after reducing it to
name/version pairs for one identity check. The data is produced and discarded.

Reusing `sbom_documents` / `sbom_components` is still the right shape —
`sbom_components` needs no changes, and a separate table cannot work because
`sbom_components.sbom_id` can only reference one parent. But the following must
be resolved first, and none were budgeted in v2:

1. **`sbom_documents.repository_id` is `NOT NULL … ON DELETE CASCADE`**, which
   conflicts with one shared row per digest: deleting whichever repository
   cached the bytes first would destroy the SBOM other repositories are serving,
   and `ensure_sbom_repo_access` joins through it, leaking across tenants. It
   must become nullable with `ON DELETE SET NULL`, matching
   `proxy_scan_results.repository_id`. That is an authorization-boundary change
   (#3174).
2. **No sqlx macro covers these tables** — every SBOM query is the runtime
   `query_as::<_, SbomDocument>("SELECT *")` form with `artifact_id: Uuid`. A
   nullable column therefore fails at *runtime* with `UnexpectedNullError`, not
   at compile time. One digest-keyed row would break the unfiltered admin list
   for every user. `SbomDocument.artifact_id` must become `Option<Uuid>` in the
   same commit, which converts the problem into compile errors across ~8 sites,
   including OpenAPI and proto contract surfaces.
3. **Field caps must match column widths.** v2 specified 1024;
   `sbom_components.name` is `VARCHAR(500)` and `purl` is `VARCHAR(1000)`.
   Postgres errors on overflow rather than truncating, so a 1024 cap on `name`
   is a guaranteed insert failure on exactly the adversarial input the cap
   exists to stop.
4. **Refusal and `inventory_completeness` are mutually exclusive.** v2 specified
   both. `inventory_completeness` is a property rendered into a produced
   document; if the policy is document-level refusal there is no document to
   carry it. Pick one.
5. **The read path is not free.** `get_sbom_by_artifact`,
   `list_sboms_for_artifact`, and `/sbom/by-artifact/:id` are all artifact-keyed
   and need parallel digest-keyed paths. v2 claimed license policy and
   Dependency-Track export would work for free; both are false —
   `check_license_compliance` is stateless and takes licenses from the request
   body, and there is no SBOM export to Dependency-Track anywhere in the
   backend.
6. **Pin contamination affects SBOM contents**, not just counts: duplicate
   components (P1), and for npm a BOM listing declared transitives the tarball
   does not vendor. These SBOMs describe what the scanner cataloged, not what the
   artifact contains, and must be labelled accordingly.

### `artifacts`-row unification — deferred

Not because of #1278's storage-key doubling (though its root cause is
unrepaired — `storage_for_artifact` does not exist), but because four subsystems
now treat "proxy content has no `artifacts` row" as a correctness invariant: the
usage ledger's `storage_key NOT LIKE 'proxy-cache/%'` predicate, quarantine
(#2940), `artifacts_search_vector`, and the digest-keyed verdict model itself,
which shares verdicts cross-repo and survives cache eviction. An `artifacts`-row
model would lose that last property. This is a data-model migration with a
ledger backfill, not a routing fix. OCI demonstrates it can be done safely with
the per-repo key convention (#1505).

## Risks

- **Fail-closed caches the bytes it refuses to serve.** The cache write happens
  inside the fetch, before the gate decides, so a 403'd artifact is resident on
  disk and in the catalog. This is why the join finds anything; it is also an
  undocumented posture, and the UI will now show "vulnerable" for bytes present
  locally.
- **Cross-tenant verdict inheritance.** Verdicts are global by digest. A
  repository with `scan_on_proxy` off can display a verdict recorded by another
  repository for byte-identical content. The UI must not say "this repository
  scanned this," and the API must never expose
  `proxy_scan_results.repository_id`. Add a source-scanning test asserting the
  query does not select it; `security.rs` has that idiom.
- **Legacy cold caches.** A repository with zero catalog rows falls back to
  storage enumeration. That path does carry `checksum_sha256`, so it can be
  joined — v2 wrongly claimed it could not — but it is a second code path and
  needs its own test.
- **`unknown` is a large bucket.** It covers over-cap, identity-unestablished,
  and failed scans — including cases where content was served without ever being
  scanned. The copy must not imply safety, and the deferred scan-attempt table
  is what eventually shrinks it.

## Testing

**Unit.** State mapping for all three states and all three `not_scanned`
reasons, including `checksum_sha256 IS NULL` exclusion. Age-based staleness at
the TTL boundary. P1 dedup: canonical-vs-non-canonical names (`PyYAML`,
`zope.interface`), `cve_id: None`, sdist (expect no change), npm
shrinkwrap∩lockfile overlap.

**Integration.** Verdict written by the gate is readable through the endpoint.
Summary counts distinct digests, not paths. `repository_id` never selected.
Unauthenticated request rejected on a public repository. Path parameter cannot
address a digest outside the calling repository.

**Performance.** Summary aggregate at representative scale with the index in
place. v1 and v2 had no perf test, which is how the index question was missed.

**End-to-end**, reproducible locally: enable `scan_on_proxy` + `fail_closed`,
pull a CVE-bearing package, assert 403, assert the verdict row, assert the
endpoint reports `vulnerable` with the **deduplicated** count, assert the UI
renders the panel instead of the green shield.

**Regression.** `analyzable` unchanged. `list_artifacts` unchanged. The gate's
block/serve decision unchanged. The #3003 identity check untouched.

## Corrections from v2

| v2 | v3 |
|---|---|
| Five states incl. `pending`, `stale` as a state | Three states; `stale` is an orthogonal boolean |
| Five `not_scanned` reasons | Three; the other three need a write path that does not exist |
| `pending` from the `X-AK-Scan` header | Dropped — the header fires on permanently-unscannable npm content with no scan running |
| `stale` from `verdict_is_reusable` | Age-based only; `verdict_is_reusable` is policy-contaminated, needs an async probe, and is broken by P2 |
| P2 blocks the feature | P2 blocks only `scanner_version` display, which v3 drops |
| Attach `scan_verdict` to `list_artifacts` | Dedicated authenticated endpoint; listing untouched |
| Always-serialize + null for anonymous | Contradiction removed with the listing change |
| Introduce `capabilities` | Deferred; v2 never specified hosted values |
| P1 is "roughly 2x for pinned scans" | Wheels double top-level findings; sdists have zero inflation; npm is a different bug |
| Dedup on raw component name | PEP 503-normalized, before aggregation, shared with the hosted path |
| `sbom_documents.artifact_id` is the only obstacle | `repository_id NOT NULL … CASCADE` is worse; and nullability fails at runtime, not compile time, here |
| `PROXY_SBOM_MAX_FIELD_LEN = 1024` | Must be ≤500 for `name`, ≤1000 for `purl` |
| Refusal *and* `inventory_completeness` | Mutually exclusive; pick one |
| License policy / Dependency-Track work "for free" | Both false; the export does not exist |
| Fix `Scan All` gating | Deferred; needs a new backend field |

## Coverage and duplication gates

Per CLAUDE.md: >= 70% coverage on changed lines, <= 3% duplication. Keep state
mapping, staleness, and the dedup key in pure functions so they are testable
without database fixtures.
