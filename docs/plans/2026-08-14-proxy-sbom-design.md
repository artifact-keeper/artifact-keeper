# Proxy SBOM Generation — Design

**Date**: 2026-08-14
**Status**: Ready to implement
**Branch**: `feat/proxy-scan-visibility`
**Supersedes**: the "Proxy SBOM — deferred" section of
`2026-08-13-proxy-scan-visibility-design.md`

## Why the deferral is withdrawn

The v4 deferral recorded six blockers. Five of them were consequences of a
single assumption: that a proxy SBOM must be stored in `sbom_documents`.

That assumption is unnecessary. Dropping it removes the blockers rather than
solving them.

## Findings that changed the estimate

**1. The package inventory is already computed on every proxy pull, and thrown
away.**

`ScanOutput` carries two distinct fields:

```rust
pub struct ScanOutput {
    pub findings: Vec<RawFinding>,
    pub packages: Vec<RawPackage>,          // full inventory
    pub scan_completeness: ScanCompleteness,
    pub cataloged: Option<Vec<CatalogedComponent>>,  // {name, version} only
}
```

`run_inline_proxy_scanners_target` consumes `findings` and `cataloged` and
**ignores `packages` entirely**. So the expensive work — fetch, extract,
catalog with syft/grype — already runs on every proxied download. Only the
result is discarded.

**2. `RawPackage` is already the exact shape an SBOM needs.**

```rust
pub struct RawPackage { name, version, purl, license, source_target }
```

`DependencyInfo` — the input to the SBOM generators — needs
`{name, version, purl, license, sha256}`. Four of five fields map directly.
This is not a coincidence: `scan_packages` (the hosted inventory table) stores
the same tuple, and `extract_dependencies_for_artifact` reads exactly those
four columns to build the hosted SBOM.

**3. The SBOM generators are pure.**

```rust
fn generate_cyclonedx_inner(&self, deps: &[DependencyInfo], completeness: Option<&str>)
    -> Result<(serde_json::Value, Vec<ComponentInfo>)>
```

Synchronous, no database, no storage. `generate_sbom` is a persistence wrapper
around them; the document itself is a pure function of the dependency list.

**4. `sbom_documents.artifact_id` is `NOT NULL` with
`FK -> artifacts(id) ON DELETE CASCADE`.**

Proxy content deliberately has no `artifacts` row (#1278/#1280). Synthetic ids
therefore cannot be stored here — the FK rejects them. This is the one real
blocker, and it only binds if we insist on using this table.

## Design

**Persist the inventory, generate the document on demand.**

### Write path

New digest-keyed table, mirroring the proven `proxy_scan_results` shape:

```sql
CREATE TABLE proxy_scan_packages (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    checksum_sha256  TEXT NOT NULL,
    scan_type        TEXT NOT NULL,
    name             TEXT NOT NULL,
    version          TEXT,
    purl             TEXT,
    license          TEXT,
    recorded_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (checksum_sha256, scan_type, name, version)
);
CREATE INDEX idx_proxy_scan_packages_digest
    ON proxy_scan_packages (checksum_sha256, scan_type);
```

Written from `output.packages` in the inline proxy scan path, in the same
transaction that records the verdict. Digest-keyed, so identical content
cached in ten repositories stores one inventory — the same dedup property
`proxy_scan_results` already relies on.

### Read path

`GET /api/v1/repositories/:key/security/proxy-sbom?path=<cache path>&format=cyclonedx`

1. Authenticate unconditionally, then `require_visible` — the ordering used by
   every read in `security.rs`.
2. Resolve `path` -> `checksum_sha256` through `proxy_cache_artifacts` **scoped
   to the calling repository**. Path-keyed, never digest-keyed, for the same
   cross-tenant-oracle reason as the proxy-scans endpoint.
3. Read `proxy_scan_packages` for that digest, filtered on `PROXY_SCAN_TYPE`.
4. Map `RawPackage` -> `DependencyInfo`.
5. Call `generate_cyclonedx_inner` / `generate_spdx_inner` directly.
6. Return the document. **Nothing is written.**

### What this avoids

| v4 blocker | Status under this design |
|---|---|
| `sbom_documents.repository_id NOT NULL ON DELETE CASCADE` destroys SBOMs other repos serve | Not applicable — no `sbom_documents` row |
| `ensure_sbom_repo_access` joins through `repository_id`, leaking cross-tenant | Not applicable — access is checked against the caller's own repo |
| `artifact_id` must become `Option<Uuid>`, touching every `SELECT *` SBOM query for every user | Not applicable — no shared struct changes |
| `sbom_components` column widths | Not applicable — no component rows persisted |
| Artifact-keyed read path (`get_sbom_by_artifact` etc.) | Untouched. New endpoint, no shared handler |
| No Dependency-Track export | Still true; explicitly out of scope |

The hosted SBOM path is not modified in any way. Zero regression surface on
the existing feature.

### Cost

Regenerating the JSON per request instead of caching a `content_hash`. The
generators are pure in-memory assembly over a bounded row set; this is not a
meaningful cost, and it removes the stale-cache invalidation logic that
`generate_sbom` needs for the hosted path.

## Honest limitations

- **The SBOM describes what the scanner cataloged, not a resolved dependency
  tree.** For a Python wheel that is the wheel's own declared distribution
  metadata. It is an accurate inventory, not a transitive closure. The API
  response and UI must say so rather than implying a full dependency graph.
- **Only artifacts pulled *after* this ships have an inventory.** The table is
  populated by the scan path, so previously cached digests return "no inventory
  recorded" until re-pulled. This must render as unknown, never as an empty
  (and therefore falsely clean) SBOM.
- **Only where the gate is wired**: PyPI, npm, Docker/OCI. Maven and Go proxies
  have no inline scan and therefore no inventory.
- **`scan_completeness` must be carried through.** `ScanOutput` reports whether
  the scanner hit a target it could not parse. The hosted path threads this into
  the document via `inventory_completeness`; the proxy path must do the same, or
  a partial inventory renders as complete.

## Testing

- Inventory is persisted on an inline proxy scan, digest-keyed, deduped across
  repositories.
- A digest with no inventory row returns the unknown state, never an empty SBOM.
- Path resolution is repository-scoped: a path cached in repo A is not
  resolvable through repo B.
- Anonymous request is rejected before repository visibility is consulted.
- `PROXY_SCAN_TYPE` filtering: a second scan type does not duplicate components.
- Partial `scan_completeness` surfaces in the generated document.
