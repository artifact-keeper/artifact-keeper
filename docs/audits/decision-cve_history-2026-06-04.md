# Decision: DROP `cve_history`, repoint reads at `scan_findings` (Issue #1616)

**Date:** 2026-06-04 · **Status:** Recommendation (pending maintainer sign-off) · **Unblocks:** #1616, #1561

## Recommendation

**Adopt Option A: DROP `cve_history` and make `scan_findings` the sole source of truth for per-artifact CVE state.** REPAIR (wiring a scanner write into `cve_history`) is the wrong call: it would create a second, perpetually-drifting copy of data that `scan_findings` already holds per scan run, re-introduce the dual-write/dual-acknowledge bug class that #1375/#1426 spent two issues partially untangling, and add no information `scan_findings` cannot already express. The only thing `cve_history` can represent that `scan_findings` cannot — a curated four-state lifecycle (`open/fixed/acknowledged/false_positive`) — has **zero production writers** and is already collapsed to a boolean by every live read path.

The codebase has already done ~80% of the DROP work incrementally (#1375 repointed the Security-tab reads; #1426 wired the acknowledge write to `scan_findings`). The table is formally deprecated in-schema (`backend/migrations/112_deprecate_cve_history.sql:23`). Finish the job rather than leave a half-migrated, false-positive-producing table in place through another release.

> **New defect found during this investigation:** `promotion_policy_service.rs:428-429` still reads `cve_history` (always empty), so **promotion policies that should block on open CVEs silently pass.** This was missed by #1375/#1426 and is a concrete, unfixed bug — repointing it is the most important behavioral fix in this work.

## Evidence

### 1. Definition, columns, indexes
`cve_history` is created in `backend/migrations/045_sbom_documents.sql:87-126`. Columns: `id`, `artifact_id` (FK→artifacts CASCADE), `sbom_id`, `component_id`, `scan_result_id`, `cve_id`, `affected_component/version`, `fixed_version`, `severity`, `cvss_score`, `cve_published_at`, `first_detected_at`, `last_detected_at`, a four-state `status` CHECK (`open/fixed/acknowledged/false_positive`, default `open`), and acknowledge audit columns. Indexes on `artifact_id`, `cve_id`, `status`, `first_detected_at DESC`, `severity`, plus UNIQUE `(artifact_id, cve_id)`. Deprecation comments at `112_deprecate_cve_history.sql:23-43`.

### 2. READ sites
- **HTTP findings/Security-tab** — `SbomService::get_cve_history` (`sbom_service.rs:1009`) and `get_cve_history_by_cve_id` (`:1070`) `SELECT … FROM cve_history` then supplement with synthetic rows from `scan_findings` via `build_cve_entries_from_scan_findings` (`:1184`). Since `cve_history` is empty, `scan_findings` carries 100% of real data.
- **CVE trends** — `get_cve_trends` (`:1368`) and `FIXED_CVES_COUNT_{REPO,ALL}_SQL` (`:563`, `:611`) `UNION` a `curated_fixed` CTE from `cve_history WHERE status='fixed'` (always empty) with a `disappeared` CTE from `scan_findings` (correct).
- **gRPC** — `sbom_server.rs:284` delegates to the same service methods.
- **Promotion gating (UN-REPOINTED, live bug)** — `promotion_policy_service.rs:428-429`: `SELECT DISTINCT cve_id FROM cve_history WHERE artifact_id=$1 AND status='open'` → `open_cves` always `[]` → gating silently passes.

Routes: `/sbom/cve/history/by-artifact/:id`, `/by-cve/:cve_id`, `/history/:id`, `/trends` (`sbom.rs:99-113`).

### 3. WRITE sites — confirms "never populated"
Only `INSERT INTO cve_history` is `SbomService::record_cve` (`sbom_service.rs:969-1007`) — **zero callers** (repo-wide grep finds only definition, docs, tests). The lone `UPDATE cve_history` is `update_cve_status` (`:1224`) via `POST /cve/status/:id` (`sbom.rs:996`) — can only mutate rows never inserted. **"Never populated" confirmed.**

### 4. Comparison to `scan_findings`
`scan_findings` (`022_security_scanning.sql:41-60`) holds per-scan-run findings incl. live acknowledge state (`is_acknowledged`, `acknowledged_by/reason/at`) and is **populated by the real scanner pipeline**. `cve_history`-exclusive fields (`cvss_score`, `cve_published_at`, explicit `first/last_detected_at`, four-state `status`) have no writer; timestamps are derivable as MIN/MAX of `scan_findings.created_at`. **`scan_findings` alone serves every live read** — which `build_cve_entries_from_scan_findings` already proves.

### 5. Duplicate / unwired acknowledge paths
- **Legacy (writes `cve_history`)** — `update_cve_status` (`sbom_service.rs:1224`) via `POST /sbom/cve/status/:id`. 404s on synth rows → the original #1561 false-positive→NOT_FOUND.
- **Working (writes `scan_findings`)** — `update_cve_status_by_artifact_cve` (`:1284`) via `POST /sbom/cve/status/by-artifact/:artifact_id/by-cve/:cve_id`; and `ScanResultService::acknowledge_finding`/`revoke_acknowledgment` (`scan_result_service.rs:1431`, `:1462`) via `POST|DELETE /security/findings/:id/acknowledge`.

### 6. OpenAPI/handler contract
Handlers respond with `CveHistoryEntry`/`Vec<CveHistoryEntry>`. The DTO stays; only its data source changes — **external contract unchanged.**

## Implementation plan (Option A)

**Migration** `backend/migrations/113_drop_cve_history.sql` (confirm next number via `ls backend/migrations/ | tail -5`): guarded archive only if `COUNT(*) > 0` (almost certainly empty), then `DROP TABLE cve_history CASCADE;`.

**Read sites to repoint:**
- `promotion_policy_service.rs:428-429` → `scan_findings`-based query: `SELECT DISTINCT sf.cve_id FROM scan_findings sf JOIN <latest completed scan_result for artifact> WHERE NOT sf.is_acknowledged AND sf.cve_id IS NOT NULL`. **Most important fix — restores promotion blocking.**
- `get_cve_history` (`:1009`) / `get_cve_history_by_cve_id` (`:1070`): delete the `cve_history` SELECT blocks; call `build_cve_entries_from_scan_findings` directly (keep dedupe + `filter_entries_by_repo`).
- `FIXED_CVES_COUNT_{REPO,ALL}_SQL` (`:563`, `:611`): drop the `curated_fixed` CTE + `UNION`; keep `disappeared`.

**Write site:** Delete dead `record_cve` (`:969`), legacy `update_cve_status` (`:1224`) + route `POST /cve/status/:id` (`sbom.rs:104`, `:996`). Keep `update_cve_status_by_artifact_cve` and `security/findings/:id/acknowledge` as the **single** acknowledge surface.

**Backward-compat:** External `CveHistoryEntry` JSON unchanged; gRPC unchanged. Removing `POST /cve/status/:id` is the one client-visible break (it only ever 404'd on synth rows) — note in PR "API Changes" + CHANGELOG.

**Tests / E2E proving #1561 fixed:**
- New promotion-policy test: an artifact with an unacknowledged `scan_findings` CVE yields non-empty `open_cves` and **blocks** promotion.
- New: `get_cve_history` returns the scan-derived entry and `POST /cve/status/by-artifact/:id/by-cve/:cve` returns **200 (not 404)** — the exact #1561 scenario.
- E2E: `./scripts/native-tests/test-grpc-sbom.sh` + release-gate `GET /sbom/cve/history/CVE-2019-10744`.

**Files:** `backend/migrations/{045,112,022}*.sql`, `backend/src/services/{sbom_service,promotion_policy_service,scan_result_service}.rs`, `backend/src/api/handlers/{sbom,security}.rs`, `backend/src/grpc/sbom_server.rs`.
