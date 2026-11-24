//! Online-migration safety gate (PF-008, #2524 — part of the million-artifact
//! perf epic #2516).
//!
//! At one million artifacts a migration that takes a table-level lock is an
//! outage, not a deploy step. The epic's "Online upgrades" release gate reads:
//! *large indexes and backfills have an online/concurrent runbook with
//! progress, throttling, retry and rollback; normal upload/download SLOs remain
//! within 2× baseline.* Nothing in the repository enforced that, so every new
//! migration was free to add another write-blocking statement to the upgrade
//! path and nobody would notice until an operator's uploads stalled.
//!
//! This module is that enforcement, in the same shape as the repository's other
//! invariant gates ([`crate::ci_test_surface`], `tests/streaming_invariant.rs`):
//! a text-level scan of `backend/migrations/*.sql` whose findings must match an
//! explicit allowlist exactly. New blocking DDL on a hot table fails the build;
//! an allowlist entry that no longer matches anything also fails, so the list
//! cannot silently rot.
//!
//! Like [`crate::ci_test_surface`] it lives in the LIBRARY rather than
//! `backend/tests/`, so `--lib` runs it unconditionally in both the unit-test
//! and coverage jobs and the gate cannot fall out of CI's `--test` allowlist.
//!
//! # What counts as blocking, and why
//!
//! The target is PostgreSQL 16/18 (`docker-compose.yml`, CI services), which
//! matters: several patterns that were rewrites on older servers are not any
//! more, and gating them would be noise.
//!
//! | Pattern | Lock taken | Effect on a hot table |
//! |---|---|---|
//! | `CREATE [UNIQUE] INDEX` without `CONCURRENTLY` | `SHARE` | reads continue, **every write blocks** for the whole build |
//! | `ALTER TABLE … ADD CONSTRAINT` without `NOT VALID` | `ACCESS EXCLUSIVE` | reads and writes block while every existing row is validated |
//! | `ALTER TABLE … ALTER COLUMN … TYPE` | `ACCESS EXCLUSIVE` | full table + index rewrite |
//! | `ALTER TABLE … ALTER COLUMN … SET NOT NULL` | `ACCESS EXCLUSIVE` | full scan unless a validated `CHECK (col IS NOT NULL)` already exists |
//! | `ADD COLUMN … DEFAULT <volatile>` | `ACCESS EXCLUSIVE` | full rewrite — a *non-volatile* default is catalog-only since PG 11 and is **not** gated |
//! | unbounded `UPDATE` / `DELETE` | row locks, one transaction | rewrites every matching row, doubles the heap, one WAL burst |
//! | `CLUSTER` / `VACUUM FULL` / `REINDEX` (non-concurrent) | `ACCESS EXCLUSIVE` | rewrites the table |
//!
//! Note the first row. Three migrations already in history
//! (`106_artifacts_lower_name_index.sql`, `108_artifacts_filename_index.sql`,
//! `110_artifacts_repo_path_pattern_ops.sql`) describe their non-concurrent
//! index build as taking `ACCESS EXCLUSIVE`. It is actually `SHARE`: concurrent
//! readers are fine, writers are not. Those files are history and must not be
//! edited, and the operational conclusion they draw — uploads stall for the
//! build duration — is correct either way.
//!
//! # The structural problem this gate exposes
//!
//! `sqlx::migrate!` runs each migration file inside a transaction unless the
//! file's **first bytes** are exactly `-- no-transaction` (sqlx 0.9,
//! `sqlx-core/src/migrate/source.rs`: `sql.starts_with("-- no-transaction")`).
//! `CREATE INDEX CONCURRENTLY` is rejected inside a transaction block, so for
//! as long as no migration carries that header, *no* index in this repository
//! can be built online. That is why the allowlist below is 42 entries long: the
//! authors were not careless, the mechanism to do better was never wired up.
//!
//! Two further checks make that escape hatch usable rather than a new footgun:
//!
//! * `concurrent_ddl_requires_no_transaction_header` fails a migration that
//!   reaches for `CONCURRENTLY` without the header, which would otherwise blow
//!   up at runtime on the operator's database rather than in CI.
//! * `no_transaction_migrations_hold_one_statement` fails a `-- no-transaction`
//!   migration that contains more than one statement. sqlx runs a migration as
//!   `conn.execute(&sql)` with no bind parameters, which is the *simple* query
//!   protocol, and PostgreSQL puts a multi-statement simple query in an implicit
//!   transaction block. Verified against postgres:16-alpine:
//!
//!   ```text
//!   psql -c "CREATE INDEX CONCURRENTLY i ON t (v);"                 -> CREATE INDEX
//!   psql -c "DROP INDEX IF EXISTS i; CREATE INDEX CONCURRENTLY ..." -> ERROR: CREATE INDEX
//!                                    CONCURRENTLY cannot run inside a transaction block
//!   psql -c "DO $$ BEGIN COMMIT; END $$;"                           -> DO
//!   psql -c "SELECT 1; DO $$ BEGIN COMMIT; END $$;"                 -> ERROR: invalid
//!                                                                      transaction termination
//!   ```
//!
//!   So `-- no-transaction` buys exactly one statement, and the `DROP INDEX IF
//!   EXISTS` reset migration belongs in its own file. That reset runs once
//!   (sqlx records it), so it only clears an index left INVALID by an attempt
//!   made outside the migrator. A build that fails part-way inside the
//!   migrator is repaired at startup instead: `CONCURRENT_INDEX_MIGRATIONS`
//!   in `migration_repair` names the build migration and its index, and an
//!   INVALID index of a not-yet-recorded build is dropped before it re-runs
//!   (#4519).
//!
//! See `docs/operations/online-migrations.md` for the preflight/postflight
//! runbook a new online migration is expected to follow.
//!
//! # Deliberate limits
//!
//! * Only [`HOT_TABLES`] are gated. A blocking index on `system_settings` is
//!   not an outage and gating it would bury the signal in noise.
//! * A table created in the same migration file is skipped: it is empty, so
//!   indexing and constraining it is free.
//! * Dynamic DDL assembled with `format()` inside a single-quoted string
//!   (`125_repo_delete_fk_cascade.sql`, `200_users_fk_on_delete_actions.sql`)
//!   is masked away with the rest of the string literals and is NOT classified.
//!   Those two rebuild foreign keys across a table list computed at runtime;
//!   they need the runbook treatment, not a regex.
//! * `DO $$ … $$` bodies ARE scanned — a dollar-quoted block is executed SQL,
//!   and several migrations put their `ALTER TABLE` inside one.

#![allow(dead_code)]

/// Tables whose row count grows with the artifact catalogue or with request
/// traffic, per the workload model in epic #2516 (1M catalog rows, 10–100M
/// retained download events, ~2M remote-cache object keys). Blocking DDL on
/// one of these is an upgrade-window outage; blocking DDL on a configuration
/// table is not.
///
/// Each entry carries the reason it is hot, so a future reader can judge
/// whether a newly added table belongs here.
const HOT_TABLES: &[(&str, &str)] = &[
    (
        "artifacts",
        "the catalogue itself — 1M+ rows at the acceptance workload",
    ),
    (
        "artifact_metadata",
        "one row per artifact carrying the per-format JSONB sidecar",
    ),
    (
        "download_statistics",
        "one row per download; the epic budgets 10–100M retained events",
    ),
    (
        "audit_log",
        "one row per mutating request, retained for compliance",
    ),
    (
        "packages",
        "one row per (repository, package name) — 100K+ distinct names",
    ),
    (
        "package_versions",
        "one row per published version of every package",
    ),
    (
        "scan_results",
        "one row per (artifact, scanner) on scan-on-upload installs",
    ),
    (
        "scan_packages",
        "component inventory rows — tens per scan result",
    ),
    (
        "oci_blobs",
        "one row per OCI layer/config blob; ~2M keys on a 1M-artifact remote",
    ),
    (
        "oci_manifest_refs",
        "one row per manifest-to-manifest reference in an OCI index",
    ),
    ("oci_tags", "one row per tag across every OCI repository"),
    (
        "oci_manifests",
        "one row per OCI manifest per repository (#1683), at least as large as oci_tags",
    ),
    (
        "manifest_blob_refs",
        "one row per blob referenced by a manifest — the widest OCI fan-out",
    ),
    (
        "scan_findings",
        "one row per finding per scan; the highest-cardinality scan table",
    ),
    ("sbom_components", "one row per component per SBOM document"),
    (
        "proxy_cache_artifacts",
        "remote-cache rows; the epic budgets 1M cached artifacts",
    ),
    ("proxy_download_statistics", "one row per proxied download"),
    (
        "package_analysis",
        "one row per analyzed artifact — tracks the catalogue 1:1",
    ),
    (
        "package_vendored_components",
        "native libraries per package; a scientific-Python artifact vendors tens",
    ),
    (
        "package_install_scripts",
        "one row per install-time script; sparse, but grows with the catalogue",
    ),
];

/// Statement classes this gate recognises. The string form is what appears in
/// [`ALLOWLIST`] and in failure output.
const KIND_BLOCKING_INDEX: &str = "blocking_index";
const KIND_VALIDATING_CONSTRAINT: &str = "validating_constraint";
const KIND_COLUMN_REWRITE: &str = "column_rewrite";
const KIND_SET_NOT_NULL: &str = "set_not_null";
const KIND_VOLATILE_DEFAULT: &str = "volatile_default";
const KIND_UNBOUNDED_BACKFILL: &str = "unbounded_backfill";
const KIND_TABLE_REWRITE: &str = "table_rewrite_maintenance";

/// Every blocking statement already in migration history, with the lock it
/// takes and why it cannot be changed. **Migrations that have run on production
/// databases must never be edited**, so this list only ever shrinks when a file
/// is superseded, never when someone "fixes" one.
///
/// Shape: `(migration file, kind, table, count, why it is grandfathered)`.
///
/// Read as an inventory it says: 47 statements across 34 migrations would block
/// writes on a hot table at the one-million-artifact operating point: 27
/// non-concurrent index builds, 8 constraints validated as they are added, 8
/// whole-table backfills and 4 column rewrites. The single worst file is
/// `176_artifacts_search_vector.sql` — a whole-table `UPDATE` computing
/// `to_tsvector` for every live row, then a GIN build over the result, in one
/// transaction.
const ALLOWLIST: &[(&str, &str, &str, usize, &str)] = &[
    (
        "022_security_scanning.sql",
        KIND_BLOCKING_INDEX,
        "artifacts",
        1,
        "quarantine_status partial index added alongside the scanning tables; \
         `artifacts` already existed from 004",
    ),
    (
        "032_scanner_types.sql",
        KIND_VALIDATING_CONSTRAINT,
        "scan_results",
        1,
        "scan_type CHECK rebuilt to widen the allowed set — DROP + ADD validates \
         every row; the NOT VALID + VALIDATE split was not used",
    ),
    (
        "033_scan_dedup.sql",
        KIND_BLOCKING_INDEX,
        "scan_results",
        1,
        "dedup index on the new checksum_sha256 column",
    ),
    (
        "033_scan_dedup.sql",
        KIND_UNBOUNDED_BACKFILL,
        "scan_results",
        1,
        "one-shot UPDATE joining every scan_results row to artifacts to populate \
         checksum_sha256; no batching",
    ),
    (
        "034_openscap_scan_type.sql",
        KIND_VALIDATING_CONSTRAINT,
        "scan_results",
        1,
        "same DROP + ADD CHECK rebuild as 032, one scan type wider",
    ),
    (
        "060_incus_scan_type.sql",
        KIND_VALIDATING_CONSTRAINT,
        "scan_results",
        1,
        "same DROP + ADD CHECK rebuild as 032/034",
    ),
    (
        "075_quarantine_period.sql",
        KIND_BLOCKING_INDEX,
        "artifacts",
        1,
        "quarantine_until partial index for the quarantine-release sweep",
    ),
    (
        "075_quarantine_period.sql",
        KIND_VALIDATING_CONSTRAINT,
        "artifacts",
        1,
        "quarantine_status CHECK widened on `artifacts` — the most expensive \
         validating constraint in history, ACCESS EXCLUSIVE over the catalogue",
    ),
    (
        "087_scan_packages_fk_inventory_status.sql",
        KIND_BLOCKING_INDEX,
        "scan_results",
        1,
        "inventory_status partial index (#1154)",
    ),
    (
        "087_scan_packages_fk_inventory_status.sql",
        KIND_VALIDATING_CONSTRAINT,
        "scan_results",
        1,
        "UNIQUE (id, artifact_id) added inside a DO block so the scan_packages FK \
         can reference it; builds a unique index under ACCESS EXCLUSIVE",
    ),
    (
        "090_scan_packages_validation.sql",
        KIND_COLUMN_REWRITE,
        "scan_packages",
        1,
        "purl widened to VARCHAR(2048) with a USING clause — a USING expression \
         forces a full rewrite even when widening (#1151)",
    ),
    (
        "101_partial_index_scan_results_latest.sql",
        KIND_BLOCKING_INDEX,
        "scan_results",
        2,
        "two EXECUTE'd index variants (legacy-unverified vs clean schema) inside \
         a DO block; exactly one runs per database (#1030)",
    ),
    (
        "105_partial_index_running_scans.sql",
        KIND_BLOCKING_INDEX,
        "scan_results",
        1,
        "partial index on started_at WHERE status='running' for the stuck-scan \
         janitor (#1061)",
    ),
    (
        "106_artifacts_lower_name_index.sql",
        KIND_BLOCKING_INDEX,
        "artifacts",
        1,
        "LOWER(name) functional index; the file documents the write stall and \
         gives operators an out-of-band CONCURRENTLY recipe (#1217)",
    ),
    (
        "107_artifacts_checksum_sha1_md5_indexes.sql",
        KIND_BLOCKING_INDEX,
        "artifacts",
        2,
        "checksum_sha1 and checksum_md5 partial indexes for checksum search",
    ),
    (
        "108_artifacts_filename_index.sql",
        KIND_BLOCKING_INDEX,
        "artifacts",
        1,
        "reverse(path) text_pattern_ops index for suffix resolution; the file \
         documents the out-of-band CONCURRENTLY playbook (#1266)",
    ),
    (
        "110_artifacts_repo_path_pattern_ops.sql",
        KIND_BLOCKING_INDEX,
        "artifacts",
        1,
        "path text_pattern_ops index for left-anchored prefix LIKE; same \
         documented out-of-band playbook",
    ),
    (
        "113_packages_one_row_per_name.sql",
        KIND_UNBOUNDED_BACKFILL,
        "package_versions",
        2,
        "repoints then de-duplicates every package_versions row onto the \
         canonical package id, in one transaction",
    ),
    (
        "113_packages_one_row_per_name.sql",
        KIND_UNBOUNDED_BACKFILL,
        "packages",
        1,
        "deletes every non-canonical packages row in the same transaction",
    ),
    (
        "113_packages_one_row_per_name.sql",
        KIND_VALIDATING_CONSTRAINT,
        "packages",
        1,
        "UNIQUE (repository_id, name) — builds a unique index under ACCESS \
         EXCLUSIVE; the online shape is CREATE UNIQUE INDEX CONCURRENTLY then \
         ADD CONSTRAINT … USING INDEX",
    ),
    (
        "124_scan_results_status_not_applicable.sql",
        KIND_VALIDATING_CONSTRAINT,
        "scan_results",
        1,
        "status CHECK widened for the not_applicable terminal state (#1470)",
    ),
    (
        "140_artifact_metadata_maven_gav_index.sql",
        KIND_BLOCKING_INDEX,
        "artifact_metadata",
        1,
        "Maven GAV expression index for maven-metadata.xml generation",
    ),
    (
        "141_oci_blobs_pending_delete.sql",
        KIND_BLOCKING_INDEX,
        "oci_blobs",
        1,
        "pending_delete_at partial index backing the blob mark-and-sweep (#1660)",
    ),
    (
        "151_download_telemetry_ip_index.sql",
        KIND_BLOCKING_INDEX,
        "download_statistics",
        1,
        "(ip_address, downloaded_at) index — the one blocking build on the \
         highest-cardinality table in the schema (#2365)",
    ),
    (
        "153_audit_correlation_text.sql",
        KIND_COLUMN_REWRITE,
        "audit_log",
        1,
        "correlation_id UUID -> TEXT with a USING cast: a full rewrite of the \
         audit table (#2414)",
    ),
    (
        "153_audit_correlation_text.sql",
        KIND_VALIDATING_CONSTRAINT,
        "audit_log",
        1,
        "octet_length CHECK added and validated in the same statement as the \
         rewrite above",
    ),
    (
        "157_artifacts_storage_key_index.sql",
        KIND_BLOCKING_INDEX,
        "artifacts",
        1,
        "storage_key index for the cross-repository overwrite guard (#2504)",
    ),
    (
        "162_repository_storage_stats.sql",
        KIND_BLOCKING_INDEX,
        "oci_blobs",
        1,
        "digest index added while creating the storage-stats rollup tables \
         (#2056); oci_blobs itself is pre-existing",
    ),
    (
        "166_artifacts_cocoapods_cdn_shard_index.sql",
        KIND_BLOCKING_INDEX,
        "artifacts",
        1,
        "left(md5(name),3) shard index for the CocoaPods CDN layout (#2638)",
    ),
    (
        "173_artifacts_lower_trgm_indexes.sql",
        KIND_BLOCKING_INDEX,
        "artifacts",
        2,
        "two GIN trigram indexes on LOWER(name)/LOWER(path) for catalog search \
         (PF-001 #2518); GIN builds are the slowest shape here",
    ),
    (
        "176_artifacts_search_vector.sql",
        KIND_BLOCKING_INDEX,
        "artifacts",
        1,
        "GIN index on the new search_vector column (PF-009 #2871)",
    ),
    (
        "176_artifacts_search_vector.sql",
        KIND_UNBOUNDED_BACKFILL,
        "artifacts",
        1,
        "WORST OFFENDER: one UPDATE computes to_tsvector for every live artifact \
         row in a single transaction, then the GIN index is built above it — \
         at 1M rows this is a heap doubling plus a write stall in one file",
    ),
    (
        "177_maven_packages_grouped_name_backfill.sql",
        KIND_UNBOUNDED_BACKFILL,
        "packages",
        1,
        "rewrites every Maven packages.name row to groupId:artifactId form \
         (#2723)",
    ),
    (
        "179_artifact_metadata_files_gin.sql",
        KIND_BLOCKING_INDEX,
        "artifact_metadata",
        1,
        "jsonb_path_ops GIN index for Maven flat-key attribution (#2942)",
    ),
    (
        "192_maven_package_versions_version_backfill.sql",
        KIND_UNBOUNDED_BACKFILL,
        "package_versions",
        2,
        "two unbounded CTE backfills of package_versions.version for Maven rows \
         written before the write-path fix (#3064)",
    ),
    (
        "193_oci_blobs_storage_key_index.sql",
        KIND_BLOCKING_INDEX,
        "oci_blobs",
        1,
        "storage_key index for the OCI cleanup sweep's liveness re-check (#3085)",
    ),
    (
        "202_proxy_scan_visibility.sql",
        KIND_BLOCKING_INDEX,
        "proxy_cache_artifacts",
        1,
        "(repository_id, checksum_sha256) index on the remote-cache table so proxy \
         scan verdicts can be joined back to cached artifacts",
    ),
    (
        "206_artifacts_storage_key_trgm_index.sql",
        KIND_BLOCKING_INDEX,
        "artifacts",
        1,
        "GIN trigram index on storage_key for the Maven flat-object GC guard \
         (#3384 follow-up)",
    ),
    (
        "209_scan_results_pin_identity.sql",
        KIND_BLOCKING_INDEX,
        "scan_results",
        1,
        "dedup index rebuilt to carry pin_identity (#3604)",
    ),
    (
        "211_packages_version_oci_tag_length.sql",
        KIND_COLUMN_REWRITE,
        "packages",
        1,
        "version VARCHAR(100) -> VARCHAR(128) for the OCI tag grammar (#3611). \
         A pure widening with no USING clause is catalog-only on PG 16/18, so \
         this one is cheap in practice — it is listed because the gate cannot \
         prove the absence of a rewrite from the text alone",
    ),
    (
        "211_packages_version_oci_tag_length.sql",
        KIND_COLUMN_REWRITE,
        "package_versions",
        1,
        "same widening on package_versions.version; same catalog-only caveat",
    ),
    (
        "214_artifact_metadata_pypi_classifiers_gin.sql",
        KIND_BLOCKING_INDEX,
        "artifact_metadata",
        1,
        "GIN index on the PyPI trove-classifier array for XML-RPC browse (#3783)",
    ),
    (
        "339_scan_findings_text_columns.sql",
        KIND_COLUMN_REWRITE,
        "scan_findings",
        6,
        "six scanner text columns VARCHAR(n) -> TEXT so one long fixed-version \
         string cannot fail a scan's whole findings batch (#5534). Binary \
         coercible with no USING clause and no index on any of the six, so it \
         is catalog-only on PG 16/18 (heap, TOAST and index relfilenodes \
         unchanged, verified); the lock is taken with a 5s lock_timeout and \
         retried. `cve_id` was left out because its partial index would be \
         rebuilt",
    ),
    (
        "342_scan_results_text_columns.sql",
        KIND_COLUMN_REWRITE,
        "scan_results",
        2,
        "scanner_version and vuln_db_version VARCHAR(n) -> TEXT so a long \
         scanner-supplied provenance string cannot fail `complete_scan` and \
         strand the scan `running` (#5564). Binary coercible with no USING \
         clause and no index on either column, so it is catalog-only on PG \
         16/18 (heap and TOAST relfilenodes unchanged, verified); the lock is \
         taken with a 5s lock_timeout and retried",
    ),
    (
        "385_packages_version_text_columns.sql",
        KIND_COLUMN_REWRITE,
        "packages",
        1,
        "version VARCHAR(128) -> TEXT so a 150-character PyPI version cannot \
         fail the best-effort catalog upsert and silently drop the version from \
         the listing (#5641). Binary coercible with no USING clause, and \
         `packages` has no index on `version` (its UNIQUE constraint is \
         (repository_id, name), 113), so it is catalog-only on PG 16/18 (heap \
         and TOAST relfilenodes unchanged, verified); the lock is taken with a \
         5s lock_timeout and retried",
    ),
    (
        "385_packages_version_text_columns.sql",
        KIND_COLUMN_REWRITE,
        "package_versions",
        1,
        "same VARCHAR(128) -> TEXT widening on package_versions.version; the \
         UNIQUE btree index (package_id, version) keeps its relfilenode, so it \
         is catalog-only on PG 16/18 (#5641). Bounded by the same 5s \
         lock_timeout and retry",
    ),
];

/// Blank out `--` line comments, `/* … */` block comments and `'…'` string
/// literals (newlines preserved so line numbers survive), leaving executable
/// SQL in place.
///
/// Dollar-quoted bodies are deliberately NOT blanked: `DO $$ … $$` and
/// `EXECUTE $idx$ … $idx$` contents are SQL that runs, and several migrations
/// put their `ALTER TABLE` / `CREATE INDEX` inside one. The corpus uses no
/// `E'…'` escape strings, so `''` doubling is the only quote escape handled.
fn mask_sql(src: &str) -> String {
    let b = src.as_bytes();
    let n = b.len();
    let mut out = Vec::with_capacity(n);
    let mut i = 0usize;
    let blank = |out: &mut Vec<u8>, c: u8| out.push(if c == b'\n' { b'\n' } else { b' ' });
    while i < n {
        let c = b[i];
        let nx = if i + 1 < n { b[i + 1] } else { 0 };
        if c == b'-' && nx == b'-' {
            while i < n && b[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
        } else if c == b'/' && nx == b'*' {
            out.push(b' ');
            out.push(b' ');
            i += 2;
            let mut depth = 1u32;
            while i < n && depth > 0 {
                if b[i] == b'/' && i + 1 < n && b[i + 1] == b'*' {
                    depth += 1;
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                } else if b[i] == b'*' && i + 1 < n && b[i + 1] == b'/' {
                    depth -= 1;
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                } else {
                    blank(&mut out, b[i]);
                    i += 1;
                }
            }
        } else if c == b'\'' {
            out.push(b' ');
            i += 1;
            while i < n {
                if b[i] == b'\'' && i + 1 < n && b[i + 1] == b'\'' {
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                } else if b[i] == b'\'' {
                    out.push(b' ');
                    i += 1;
                    break;
                } else {
                    blank(&mut out, b[i]);
                    i += 1;
                }
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    // Safe: only ASCII was pushed at code positions; multi-byte UTF-8 can only
    // appear inside comments/literals, which are now blanked.
    String::from_utf8(out).expect("masked SQL is valid UTF-8")
}

/// `;`-delimited fragments of masked SQL, as `(byte offset, text)`.
///
/// A `;` inside a `DO $$ … $$` body splits that body into several fragments.
/// That is fine for classification: every fragment still carries the
/// `ALTER TABLE` / `CREATE INDEX … ON` token the table is attributed from.
fn statements(masked: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut start = 0usize;
    for (idx, ch) in masked.char_indices() {
        if ch == ';' {
            out.push((start, &masked[start..idx + 1]));
            start = idx + 1;
        }
    }
    if !masked[start..].trim().is_empty() {
        out.push((start, &masked[start..]));
    }
    out
}

/// Case-insensitive search for `needle` in `hay` at or after `from`, matching
/// whitespace in `needle` against any run of ASCII whitespace in `hay` and
/// requiring word boundaries at both ends. Returns `(start, end)` byte offsets.
fn find_phrase(hay: &str, needle: &str, from: usize) -> Option<(usize, usize)> {
    let h = hay.as_bytes();
    let words: Vec<&str> = needle.split_whitespace().collect();
    let mut at = from;
    'outer: while at < h.len() {
        // Anchor on the first word.
        let start = at;
        let mut p = at;
        for (w, word) in words.iter().enumerate() {
            if w > 0 {
                // Require at least one whitespace byte between words.
                let ws_start = p;
                while p < h.len() && h[p].is_ascii_whitespace() {
                    p += 1;
                }
                if p == ws_start {
                    at = start + 1;
                    continue 'outer;
                }
            }
            let wb = word.as_bytes();
            if p + wb.len() > h.len() || !h[p..p + wb.len()].eq_ignore_ascii_case(wb) {
                at = start + 1;
                continue 'outer;
            }
            p += wb.len();
        }
        let before_ok = start == 0 || !is_word_byte(h[start - 1]);
        let after_ok = p >= h.len() || !is_word_byte(h[p]);
        if before_ok && after_ok {
            return Some((start, p));
        }
        at = start + 1;
    }
    None
}

fn is_word_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// The identifier immediately following byte offset `from`, skipping
/// whitespace, an optional `IF EXISTS` / `IF NOT EXISTS` / `ONLY` qualifier, an
/// optional `schema.` prefix and optional double quotes. Lower-cased.
fn identifier_after(hay: &str, from: usize) -> Option<String> {
    let h = hay.as_bytes();
    let mut p = from;
    loop {
        while p < h.len() && h[p].is_ascii_whitespace() {
            p += 1;
        }
        let mut skipped = false;
        for kw in ["IF NOT EXISTS", "IF EXISTS", "ONLY"] {
            if let Some((s, e)) = find_phrase(hay, kw, p) {
                if s == p {
                    p = e;
                    skipped = true;
                    break;
                }
            }
        }
        if !skipped {
            break;
        }
    }
    while p < h.len() && h[p].is_ascii_whitespace() {
        p += 1;
    }
    if p < h.len() && h[p] == b'"' {
        p += 1;
    }
    let start = p;
    while p < h.len() && is_word_byte(h[p]) {
        p += 1;
    }
    if p == start {
        return None;
    }
    let first = hay[start..p].to_ascii_lowercase();
    // `schema.table` — take the last component.
    if p < h.len() && h[p] == b'.' {
        return identifier_after(hay, p + 1).or(Some(first));
    }
    Some(first)
}

/// One classified statement.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Finding {
    file: String,
    line: usize,
    kind: &'static str,
    table: String,
    excerpt: String,
}

/// Classify one `;`-delimited masked fragment, returning every blocking
/// statement it contains together with the table each one targets.
fn classify(stmt: &str) -> Vec<(&'static str, String, usize)> {
    let mut out = Vec::new();

    // CREATE [UNIQUE] INDEX … ON <table>, unless CONCURRENTLY follows.
    for opener in ["CREATE INDEX", "CREATE UNIQUE INDEX"] {
        let mut from = 0usize;
        while let Some((s, e)) = find_phrase(stmt, opener, from) {
            from = e;
            if find_phrase(stmt, "CONCURRENTLY", e).map(|(cs, _)| cs) == Some(skip_ws(stmt, e)) {
                continue;
            }
            if let Some((_, on_end)) = find_phrase(stmt, "ON", e) {
                if let Some(t) = identifier_after(stmt, on_end) {
                    out.push((KIND_BLOCKING_INDEX, t, s));
                }
            }
        }
    }

    // ALTER TABLE … ADD CONSTRAINT …, unless the statement says NOT VALID.
    let mut from = 0usize;
    while let Some((s, e)) = find_phrase(stmt, "ADD CONSTRAINT", from) {
        from = e;
        if find_phrase(stmt, "NOT VALID", e).is_some() {
            continue;
        }
        if let Some(t) = alter_target(stmt, s) {
            out.push((KIND_VALIDATING_CONSTRAINT, t, s));
        }
    }

    // ALTER TABLE … ALTER [COLUMN] <col> [SET DATA] TYPE …
    let mut from = 0usize;
    while let Some((s, e)) = find_phrase(stmt, "TYPE", from) {
        from = e;
        if find_phrase(stmt, "ALTER TABLE", 0).is_none() {
            continue;
        }
        if let Some(t) = alter_target(stmt, s) {
            out.push((KIND_COLUMN_REWRITE, t, s));
        }
    }

    // ALTER TABLE … SET NOT NULL
    let mut from = 0usize;
    while let Some((s, e)) = find_phrase(stmt, "SET NOT NULL", from) {
        from = e;
        if let Some(t) = alter_target(stmt, s) {
            out.push((KIND_SET_NOT_NULL, t, s));
        }
    }

    // ADD COLUMN … DEFAULT <volatile>. A non-volatile default has been a
    // catalog-only change since PG 11, so only the volatile shapes are gated.
    if let Some((add_s, add_e)) = find_phrase(stmt, "ADD COLUMN", 0) {
        if let Some((_, def_e)) = find_phrase(stmt, "DEFAULT", add_e) {
            let tail = &stmt[def_e..];
            let volatile = [
                "gen_random_uuid",
                "uuid_generate_v4",
                "random",
                "clock_timestamp",
            ]
            .iter()
            .any(|f| tail.to_ascii_lowercase().contains(&format!("{f}(")));
            if volatile {
                if let Some(t) = alter_target(stmt, add_s) {
                    out.push((KIND_VOLATILE_DEFAULT, t, add_s));
                }
            }
        }
    }

    // Unbounded UPDATE / DELETE. A statement carrying LIMIT (keyset batch) or
    // LOOP (a plpgsql batch driver) is already bounded and is not gated.
    let bounded = find_phrase(stmt, "LIMIT", 0).is_some() || find_phrase(stmt, "LOOP", 0).is_some();
    if !bounded {
        let mut from = 0usize;
        while let Some((s, e)) = find_phrase(stmt, "UPDATE", from) {
            from = e;
            if let Some(t) = identifier_after(stmt, e) {
                out.push((KIND_UNBOUNDED_BACKFILL, t, s));
            }
        }
        let mut from = 0usize;
        while let Some((s, e)) = find_phrase(stmt, "DELETE FROM", from) {
            from = e;
            if let Some(t) = identifier_after(stmt, e) {
                out.push((KIND_UNBOUNDED_BACKFILL, t, s));
            }
        }
    }

    // CLUSTER / VACUUM FULL / REINDEX — whole-table rewrites.
    for opener in ["CLUSTER", "VACUUM FULL", "REINDEX TABLE", "REINDEX INDEX"] {
        let mut from = 0usize;
        while let Some((s, e)) = find_phrase(stmt, opener, from) {
            from = e;
            if find_phrase(stmt, "CONCURRENTLY", e).is_some() {
                continue;
            }
            if let Some(t) = identifier_after(stmt, e) {
                out.push((KIND_TABLE_REWRITE, t, s));
            }
        }
    }

    out
}

fn skip_ws(hay: &str, from: usize) -> usize {
    let h = hay.as_bytes();
    let mut p = from;
    while p < h.len() && h[p].is_ascii_whitespace() {
        p += 1;
    }
    p
}

/// Table named by the nearest `ALTER TABLE` at or before `pos`. A fragment may
/// contain several (`087` alters two tables inside one `DO` block), so the
/// *nearest preceding* one is the right attribution.
fn alter_target(stmt: &str, pos: usize) -> Option<String> {
    let mut best: Option<usize> = None;
    let mut from = 0usize;
    while let Some((s, e)) = find_phrase(stmt, "ALTER TABLE", from) {
        from = e;
        if s <= pos {
            best = Some(e);
        } else {
            break;
        }
    }
    identifier_after(stmt, best?)
}

/// Byte ranges of every dollar-quoted body (`$$ … $$`, `$idx$ … $idx$`),
/// outermost first — a nested tag inside an open body is skipped over.
fn dollar_spans(masked: &str) -> Vec<(usize, usize)> {
    let b = masked.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        if b[i] != b'$' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < b.len() && is_word_byte(b[j]) {
            j += 1;
        }
        if j >= b.len() || b[j] != b'$' {
            i += 1;
            continue;
        }
        let tag = &masked[i..=j];
        let body_start = j + 1;
        let Some(rel) = masked[body_start..].find(tag) else {
            break;
        };
        let end = body_start + rel + tag.len();
        out.push((i, end));
        i = end;
    }
    out
}

/// The subset of [`dollar_spans`] that are `CREATE [OR REPLACE] FUNCTION` /
/// `PROCEDURE` bodies.
///
/// Statements inside a routine body run when the routine is *called*, not when
/// the migration runs, so a per-row `UPDATE` in a trigger function is not an
/// upgrade-time lock and must not be classified as one (see
/// `182_usage_ledger_triggers.sql`). `DO $$ … $$` blocks are deliberately NOT
/// excluded — those execute during the migration, and
/// `087_scan_packages_fk_inventory_status.sql` and
/// `101_partial_index_scan_results_latest.sql` put real blocking DDL in one.
fn routine_bodies(masked: &str) -> Vec<(usize, usize)> {
    dollar_spans(masked)
        .into_iter()
        .filter(|(start, _)| {
            // Owner = the text since the previous statement terminator.
            let prev = masked[..*start].rfind(';').map(|p| p + 1).unwrap_or(0);
            let head = &masked[prev..*start];
            find_phrase(head, "FUNCTION", 0).is_some()
                || find_phrase(head, "PROCEDURE", 0).is_some()
        })
        .collect()
}

/// Number of top-level statements in a migration, counting a `;` only when it
/// is outside every dollar-quoted body.
fn top_level_statement_count(masked: &str) -> usize {
    let spans = dollar_spans(masked);
    let mut count = 0usize;
    let mut last_end = 0usize;
    for (idx, ch) in masked.char_indices() {
        if ch != ';' || spans.iter().any(|(s, e)| idx >= *s && idx < *e) {
            continue;
        }
        if !masked[last_end..idx].trim().is_empty() {
            count += 1;
        }
        last_end = idx + 1;
    }
    if !masked[last_end..].trim().is_empty() {
        count += 1;
    }
    count
}

/// Tables created by a migration file. Indexes and constraints on a table born
/// in the same file are free — the table is empty.
fn tables_created(masked: &str) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    for opener in ["CREATE TABLE", "CREATE UNLOGGED TABLE"] {
        let mut from = 0usize;
        while let Some((_, e)) = find_phrase(masked, opener, from) {
            from = e;
            if let Some(t) = identifier_after(masked, e) {
                out.insert(t);
            }
        }
    }
    out
}

/// First migration the timeout rule ([`timeout_findings`]) applies to
/// (#4153). Everything before it is history: 222-269 had already run on
/// development and staging databases when the rule was added, and editing an
/// applied migration breaks its sqlx checksum. Migration 270 is the follow-up
/// that carries the timeouts those files lacked.
const TIMEOUT_RULE_FROM: u32 = 270;

/// Why a migration must bound its lock waits, or is forbidden outright
/// (#4153); `None` when it is fine.
///
/// Three shapes qualify when they touch a [`HOT_TABLES`] entry outside a
/// routine body:
///
/// * a backfill: any `UPDATE <hot>`, `DELETE FROM <hot>` or
///   `INSERT INTO <hot> … SELECT`, batched or not. Row locks queue behind a
///   long transaction like any other lock, and a batch that cannot get its
///   rows must give up and retry rather than stall the deploy for the
///   session's 5-minute `lock_timeout` (main.rs);
/// * `CREATE [OR REPLACE | CONSTRAINT] TRIGGER … ON <hot>`: it takes
///   `SHARE ROW EXCLUSIVE`, which queues behind any open transaction on the
///   table and blocks every write behind it while it waits;
/// * `ALTER TABLE <hot> DISABLE|ENABLE [ALWAYS|REPLICA] TRIGGER`: forbidden,
///   timeouts or not. Besides the table lock, in a `-- no-transaction` file
///   the disabled state commits and is visible to every session. Relax a
///   trigger through its function instead (docs/operations/online-migrations.md).
///
/// The first two must contain `SET [LOCAL] lock_timeout`. The check is
/// file-level: it cannot tell whether the SET reaches every batch, so a file
/// that sets it once and then COMMITs inside a DO block passes; the runbook's
/// per-batch `SET LOCAL` is the author's responsibility. `statement_timeout`
/// is deliberately not required: set inside a DO block it does not apply to
/// the block's statements (the timer is armed per top-level statement), so the
/// migration session's 30-minute `statement_timeout` is the only bound there.
fn timeout_findings(masked: &str, hot: &std::collections::BTreeSet<&str>) -> Option<String> {
    let routines = routine_bodies(masked);
    let outside = |at: usize| !routines.iter().any(|(s, e)| at >= *s && at < *e);
    let is_hot = |t: &Option<String>| t.as_deref().is_some_and(|t| hot.contains(t));
    let mut reasons: Vec<String> = Vec::new();
    let mut forbidden: Vec<String> = Vec::new();
    for (offset, stmt) in statements(masked) {
        let note = |list: &mut Vec<String>, at: usize, what: &str, table: Option<String>| {
            if is_hot(&table) && outside(offset + at) {
                let entry = format!("{what} on `{}`", table.unwrap_or_default());
                if !list.contains(&entry) {
                    list.push(entry);
                }
            }
        };
        for opener in ["UPDATE", "DELETE FROM"] {
            let mut from = 0usize;
            while let Some((s, e)) = find_phrase(stmt, opener, from) {
                from = e;
                note(&mut reasons, s, "backfill", identifier_after(stmt, e));
            }
        }
        let mut from = 0usize;
        while let Some((s, e)) = find_phrase(stmt, "INSERT INTO", from) {
            from = e;
            if find_phrase(stmt, "SELECT", e).is_some() {
                note(&mut reasons, s, "backfill", identifier_after(stmt, e));
            }
        }
        for opener in [
            "CREATE TRIGGER",
            "CREATE OR REPLACE TRIGGER",
            "CREATE CONSTRAINT TRIGGER",
        ] {
            let mut from = 0usize;
            while let Some((s, e)) = find_phrase(stmt, opener, from) {
                from = e;
                let table =
                    find_phrase(stmt, "ON", e).and_then(|(_, on)| identifier_after(stmt, on));
                note(&mut reasons, s, "trigger", table);
            }
        }
        for toggle in [
            "DISABLE TRIGGER",
            "ENABLE TRIGGER",
            "ENABLE ALWAYS TRIGGER",
            "ENABLE REPLICA TRIGGER",
        ] {
            let mut from = 0usize;
            while let Some((s, e)) = find_phrase(stmt, toggle, from) {
                from = e;
                note(&mut forbidden, s, toggle, alter_target(stmt, s));
            }
        }
    }
    if !forbidden.is_empty() {
        return Some(format!("forbidden: {}", forbidden.join(", ")));
    }
    let sets_lock_timeout = find_phrase(masked, "SET LOCAL lock_timeout", 0).is_some()
        || find_phrase(masked, "SET lock_timeout", 0).is_some();
    if reasons.is_empty() || sets_lock_timeout {
        return None;
    }
    Some(format!("{} without SET lock_timeout", reasons.join(", ")))
}

// ---------------------------------------------------------------------------
// Expand/contract: backward-compatible migrations for rolling deploys (#5920)
// ---------------------------------------------------------------------------
//
// During a rolling update the previous release keeps serving on the schema the
// new release just migrated. A migration is safe for that window only if it
// EXPANDS the schema (new tables, new nullable or defaulted columns, new
// indexes, looser constraints). A statement that removes or tightens something
// the previous release may read or write is a CONTRACT and has to ship a
// release later than the expand that moved the code off the object.
//
// From [`CONTRACT_RULE_FROM`] on, a contracting migration is named
// `NNN_contract_of_MMM_<what>.sql`, where MMM is that expand migration. The
// name is what a running binary reads back from `_sqlx_migrations.description`
// (`contract of MMM ...`, `crate::migration_compat`): an older pod started with
// `MIGRATIONS_IGNORE_MISSING=true` accepts an unknown contract only when it
// embeds migration MMM itself, i.e. it is the expand release or later.
//
// The scan is token-level over SQL with comments and string literals masked:
// it reads every action of an `ALTER TABLE` (with or without the optional
// `COLUMN` keyword, quoted identifiers included), every `DROP <object>`, the
// renames and tightenings of other objects, and `CREATE UNIQUE INDEX`. A
// statement on an object the same file creates, or inside a routine body, is
// skipped; dynamic SQL in string literals is not seen. Every migration before
// [`CONTRACT_RULE_FROM`] that it flags is listed in [`HISTORICAL_CONTRACTS`],
// and the list must match exactly, so the scanner is exercised on real
// history and the list cannot rot.

/// First migration the expand/contract naming rule applies to (#5920). 1-417
/// are history: they have run on operator databases and cannot be renamed.
const CONTRACT_RULE_FROM: u32 = 418;

/// The migrations before [`CONTRACT_RULE_FROM`], frozen: their count and an
/// FNV-1a hash of their sorted file names ([`history_fingerprint`]). A file
/// added below the cutoff (a gap such as 015 or 095 filled), removed or
/// renamed fails `migration_history_is_frozen`, so nothing new can enter the
/// grandfathered range or [`HISTORICAL_CONTRACTS`]; new migrations are
/// numbered above every existing one.
const FROZEN_HISTORY: (usize, u64) = (334, 0x06ff1f16d1b27693);

/// Reviewed false positives of [`contract_statements`] from
/// [`CONTRACT_RULE_FROM`] on: `(file, why it is backward compatible)`. An entry
/// whose file no longer has a finding fails the gate.
const CONTRACT_ALLOWLIST: &[(&str, &str)] = &[];

/// Migrations before [`CONTRACT_RULE_FROM`] that contract the schema, as
/// `(file, what it contracts)`. They are history: each shipped in a release
/// before the rule existed, has run on operator databases and cannot be
/// renamed, and each release's notes covered the rollback boundary it set
/// (`docs/operations/rollback.md`). Listed so the scanner is proven against
/// real history; the list must match the scanner's findings exactly.
///
/// 67 of migrations 1-417. Most are not real contracts but the scanner cannot
/// prove it from the text: a CHECK list dropped and re-added with more values
/// (a status or scan type added), a VARCHAR widened to TEXT, or an index
/// replaced by a better one. The real ones
/// include 036 (the peer-mesh renames), 086 (a dropped table), 245 (SET NOT
/// NULL on `repositories`) and 243 (the unique key whose rollback boundary
/// `docs/operations/rollback.md` documents).
const HISTORICAL_CONTRACTS: &[(&str, &str)] = &[
    ("003_repositories.sql", "ADD CONSTRAINT on `permission_grants`; ADD CONSTRAINT on `role_assignments`"),
    ("032_scanner_types.sql", "DROP CONSTRAINT on `scan_results`; ADD CONSTRAINT on `scan_results`"),
    ("034_openscap_scan_type.sql", "DROP CONSTRAINT on `scan_results`; ADD CONSTRAINT on `scan_results`"),
    ("036_peer_mesh_network.sql", "RENAME (type) on `edge_status`; RENAME on `edge_nodes`; RENAME on `peer_instances`; RENAME on `edge_repo_assignments`; RENAME on `peer_repo_subscriptions`; DROP COLUMN on `peer_repo_subscriptions`; RENAME on `sync_tasks`; DROP CONSTRAINT on `sync_tasks`; ADD CONSTRAINT on `sync_tasks`; RENAME on `sync_tasks`; RENAME on `edge_cache_entries`; RENAME on `peer_cache_entries`; DROP CONSTRAINT on `peer_cache_entries`; ADD CONSTRAINT on `peer_cache_entries`; RENAME on `peer_cache_entries`; RENAME on `transfer_sessions`; DROP CONSTRAINT on `transfer_sessions`; ADD CONSTRAINT on `transfer_sessions`; RENAME on `transfer_sessions`; RENAME on `transfer_chunks`; DROP CONSTRAINT on `transfer_chunks`; ADD CONSTRAINT on `transfer_chunks`; RENAME on `chunk_availability`; DROP CONSTRAINT on `chunk_availability`; ADD CONSTRAINT on `chunk_availability`; RENAME on `chunk_availability`; RENAME on `peer_connections`; DROP CONSTRAINT on `peer_connections`; ADD CONSTRAINT on `peer_connections`; DROP CONSTRAINT on `peer_connections`; ADD CONSTRAINT on `peer_connections`"),
    ("042_migration_items_unique_constraint.sql", "CREATE UNIQUE INDEX on `migration_items`"),
    ("046_license_policies_unique_constraint.sql", "CREATE UNIQUE INDEX on `license_policies`"),
    ("060_incus_scan_type.sql", "DROP CONSTRAINT on `scan_results`; ADD CONSTRAINT on `scan_results`"),
    ("064_sync_task_type.sql", "DROP CONSTRAINT on `sync_tasks`; ADD CONSTRAINT on `sync_tasks`"),
    ("075_quarantine_period.sql", "DROP CONSTRAINT on `artifacts`; ADD CONSTRAINT on `artifacts`"),
    ("081_migrate_notification_subscriptions_to_webhooks.sql", "CREATE UNIQUE INDEX on `webhooks`"),
    ("083_download_tickets_cascade.sql", "ADD CONSTRAINT on `download_tickets`"),
    ("086_drop_notification_subscriptions.sql", "DROP TABLE on `notification_subscriptions`"),
    ("087_scan_packages_fk_inventory_status.sql", "ADD CONSTRAINT on `scan_results`; ADD CONSTRAINT on `scan_packages`"),
    ("089_upload_chunks_status_uploading.sql", "ADD CONSTRAINT on `upload_chunks`"),
    ("090_scan_packages_validation.sql", "ALTER COLUMN ... TYPE on `scan_packages`"),
    ("111_drop_webhooks_url_repo_unique.sql", "DROP INDEX on `idx_webhooks_url_repo_unique`"),
    ("113_packages_one_row_per_name.sql", "DROP CONSTRAINT on `packages`; ADD CONSTRAINT on `packages`"),
    ("115_oci_upload_session_parts.sql", "ADD CONSTRAINT on `oci_upload_sessions`"),
    ("124_scan_results_status_not_applicable.sql", "ADD CONSTRAINT on `scan_results`"),
    ("126_incus_upload_session_finalize_status.sql", "DROP CONSTRAINT on `incus_upload_sessions`; ADD CONSTRAINT on `incus_upload_sessions`"),
    ("136_promotion_rules_cve_default_null.sql", "ALTER COLUMN ... DROP DEFAULT/IDENTITY/EXPRESSION on `promotion_rules`"),
    ("153_audit_correlation_text.sql", "ALTER COLUMN ... TYPE on `audit_log`; ADD CONSTRAINT on `audit_log`"),
    ("167_hex_registry_signing_key.sql", "CREATE UNIQUE INDEX on `signing_keys`"),
    ("168_maven_flat_object_attribution_backend.sql", "SET NOT NULL on `maven_flat_object_owner`; ADD CONSTRAINT on `maven_flat_object_owner`"),
    ("186_password_expiry_notification_claims.sql", "ALTER COLUMN ... DROP DEFAULT/IDENTITY/EXPRESSION on `password_expiry_notifications`; ADD CONSTRAINT on `password_expiry_notifications`"),
    ("187_upload_sessions_completion_lease.sql", "DROP CONSTRAINT on `upload_sessions`; ADD CONSTRAINT on `upload_sessions`"),
    ("207_migration_jobs_completed_with_errors_status.sql", "DROP CONSTRAINT on `migration_jobs`; ADD CONSTRAINT on `migration_jobs`"),
    ("211_packages_version_oci_tag_length.sql", "ALTER COLUMN ... TYPE on `packages`; ALTER COLUMN ... TYPE on `package_versions`"),
    ("217_lifecycle_policy_exclusions.sql", "DROP CONSTRAINT on `lifecycle_policies`; ADD CONSTRAINT on `lifecycle_policies`"),
    ("220_external_scan_type.sql", "DROP CONSTRAINT on `scan_results`; ADD CONSTRAINT on `scan_results`"),
    ("223_scan_not_cataloged.sql", "ADD CONSTRAINT on `scan_results`"),
    ("227_artifacts_origin.sql", "ADD CONSTRAINT on `artifacts`"),
    ("229_artifacts_origin_validate.sql", "DROP INDEX on `idx_artifacts_origin_upstream_url`"),
    ("233_lifecycle_policy_assignments.sql", "DROP CONSTRAINT on `lifecycle_policies`; ADD CONSTRAINT on `lifecycle_policies`"),
    ("238_permission_conditions.sql", "ADD CONSTRAINT on `permissions`"),
    ("243_oci_cleanup_keys_per_repository.sql", "CREATE UNIQUE INDEX on `oci_upload_cleanup_keys`"),
    ("245_repository_visibility.sql", "SET NOT NULL on `repositories`; ADD CONSTRAINT on `repositories`"),
    ("256_proxy_scan_record_only.sql", "DROP CONSTRAINT on `scan_configs`; ADD CONSTRAINT on `scan_configs`"),
    ("257_ci_oidc_provider_key_source.sql", "ADD CONSTRAINT on `ci_oidc_providers`"),
    ("260_scan_findings_finding_class.sql", "ADD CONSTRAINT on `scan_findings`"),
    ("263_bundle_jobs.sql", "ADD CONSTRAINT on `scan_results`"),
    ("264_webhook_asymmetric_signing.sql", "DROP CONSTRAINT on `webhooks`; ADD CONSTRAINT on `webhooks`"),
    ("265_download_holds_quarantine_index_reset.sql", "DROP INDEX on `idx_artifacts_download_holds_quarantine`; DROP INDEX on `idx_proxy_cache_download_holds`"),
    ("269_lifecycle_composite_policy_type.sql", "DROP CONSTRAINT on `lifecycle_policies`; ADD CONSTRAINT on `lifecycle_policies`"),
    ("273_scan_results_dedup_local_index_reset.sql", "DROP INDEX on `idx_scan_results_dedup_local`"),
    ("275_scan_results_dedup_index_drop_old.sql", "DROP INDEX on `idx_scan_results_dedup`"),
    ("277_proxy_download_statistics_history_key.sql", "ADD CONSTRAINT on `proxy_download_statistics`"),
    ("279_proxy_download_statistics_keep_history.sql", "DROP CONSTRAINT on `proxy_download_statistics`; ADD CONSTRAINT on `proxy_download_statistics`"),
    ("280_proxy_download_statistics_repo_path_index_reset.sql", "DROP INDEX on `idx_proxy_dl_stats_repo_path`"),
    ("282_proxy_download_statistics_ip_index_reset.sql", "DROP INDEX on `idx_proxy_dl_stats_ip`"),
    ("296_proxy_download_statistics_checksum_index_reset.sql", "DROP INDEX on `idx_proxy_dl_stats_checksum`"),
    ("299_artifact_quarantine_source.sql", "ADD CONSTRAINT on `artifacts`"),
    ("303_repo_security_score_grade_status.sql", "ADD CONSTRAINT on `repo_security_scores`"),
    ("307_ci_oidc_provider_token_ttl.sql", "ADD CONSTRAINT on `ci_oidc_providers`"),
    ("312_download_statistics_downloaded_at_index_reset.sql", "DROP INDEX on `idx_download_stats_downloaded_at`"),
    ("314_proxy_download_statistics_downloaded_at_index_reset.sql", "DROP INDEX on `idx_proxy_dl_stats_downloaded_at`"),
    ("318_scan_results_source_scan_fk.sql", "DROP CONSTRAINT on `scan_results`; ADD CONSTRAINT on `scan_results`"),
    ("327_mcp_lint_scan_type.sql", "DROP CONSTRAINT on `scan_results`; ADD CONSTRAINT on `scan_results`"),
    ("331_model_scan_type.sql", "DROP CONSTRAINT on `scan_results`; ADD CONSTRAINT on `scan_results`"),
    ("339_scan_findings_text_columns.sql", "DROP VIEW on `scan_findings_effective`; ALTER COLUMN ... TYPE on `scan_findings`"),
    ("340_sync_tasks_delete_survives_artifact.sql", "DROP CONSTRAINT on `sync_tasks`; ADD CONSTRAINT on `sync_tasks`"),
    ("342_scan_results_text_columns.sql", "ALTER COLUMN ... TYPE on `scan_results`"),
    ("360_conda_shard_dirty_append_only.sql", "DROP CONSTRAINT on `conda_shard_dirty`; ADD CONSTRAINT on `conda_shard_dirty`"),
    ("361_grade_status_enforcement.sql", "ADD CONSTRAINT on `quality_gates`; ADD CONSTRAINT on `promotion_rules`; ADD CONSTRAINT on `repositories`"),
    ("383_scan_queue_hosted_upload_image.sql", "DROP CONSTRAINT on `scan_queue`; ADD CONSTRAINT on `scan_queue`; DROP CONSTRAINT on `scan_queue`; ADD CONSTRAINT on `scan_queue`; CREATE UNIQUE INDEX on `scan_queue`"),
    ("384_scan_rescan.sql", "DROP CONSTRAINT on `scan_queue`; ADD CONSTRAINT on `scan_queue`; DROP CONSTRAINT on `scan_queue`; ADD CONSTRAINT on `scan_queue`"),
    ("385_packages_version_text_columns.sql", "ALTER COLUMN ... TYPE on `packages`; ALTER COLUMN ... TYPE on `package_versions`"),
];

/// One lexical token of masked SQL.
#[derive(Debug, Clone)]
struct Tok {
    /// Byte offset in the masked text.
    at: usize,
    /// An unquoted word upper-cased, a quoted identifier lower-cased without
    /// its quotes, or one punctuation byte.
    text: String,
    /// A `"quoted"` identifier: never a keyword.
    quoted: bool,
}

impl Tok {
    fn is(&self, kw: &str) -> bool {
        !self.quoted && self.text == kw
    }
    fn ident(&self) -> String {
        self.text.to_ascii_lowercase()
    }
}

/// Words, quoted identifiers and the punctuation that matters (`( ) , . ;`)
/// of masked SQL (comments and string literals already blanked).
fn tokens(masked: &str) -> Vec<Tok> {
    let b = masked.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_alphanumeric() || c == b'_' {
            let s = i;
            while i < b.len() && (is_word_byte(b[i]) || b[i] == b'$') {
                i += 1;
            }
            out.push(Tok {
                at: s,
                text: masked[s..i].to_ascii_uppercase(),
                quoted: false,
            });
        } else if c == b'"' {
            let s = i;
            i += 1;
            let start = i;
            while i < b.len() && b[i] != b'"' {
                i += 1;
            }
            out.push(Tok {
                at: s,
                text: masked[start..i.min(b.len())].to_string(),
                quoted: true,
            });
            i += 1;
        } else {
            if matches!(c, b'(' | b')' | b',' | b'.' | b';') {
                out.push(Tok {
                    at: i,
                    text: (c as char).to_string(),
                    quoted: false,
                });
            }
            i += 1;
        }
    }
    out
}

/// The (possibly schema-qualified) object name at `t[i..]`, after an optional
/// `IF [NOT] EXISTS` / `ONLY`: the last component lower-cased, and the index
/// just past it.
fn object_name(t: &[Tok], mut i: usize) -> (Option<String>, usize) {
    loop {
        if t.get(i).is_some_and(|x| x.is("IF")) {
            i += if t.get(i + 1).is_some_and(|x| x.is("NOT")) {
                3
            } else {
                2
            };
        } else if t
            .get(i)
            .is_some_and(|x| x.is("ONLY") || x.is("CONCURRENTLY"))
        {
            i += 1;
        } else {
            break;
        }
    }
    let mut name = None;
    while let Some(x) = t.get(i) {
        if x.text.len() == 1 && !x.quoted && !x.text.as_bytes()[0].is_ascii_alphanumeric() {
            break;
        }
        name = Some(x.ident());
        i += 1;
        if t.get(i).is_some_and(|x| x.is(".")) {
            i += 1;
        } else {
            break;
        }
    }
    (name, i)
}

/// Objects a migration creates, by kind (`TABLE`, `VIEW`, `FUNCTION`, ...):
/// dropping or changing one of them in the same file is free.
fn objects_created(t: &[Tok]) -> std::collections::BTreeSet<(String, String)> {
    let mut out = std::collections::BTreeSet::new();
    let mut i = 0usize;
    while i < t.len() {
        if t[i].is("CREATE") {
            let mut j = i + 1;
            while t.get(j).is_some_and(|x| {
                [
                    "OR",
                    "REPLACE",
                    "UNLOGGED",
                    "TEMP",
                    "TEMPORARY",
                    "MATERIALIZED",
                    "CONSTRAINT",
                    "UNIQUE",
                ]
                .iter()
                .any(|k| x.is(k))
            }) {
                j += 1;
            }
            if let Some(kind) = t.get(j).filter(|x| !x.quoted) {
                let kind = kind.text.clone();
                if let (Some(name), _) = object_name(t, j + 1) {
                    out.insert((kind, name));
                }
            }
            i = j;
        }
        i += 1;
    }
    out
}

/// Kinds a top-level `DROP <kind>` contracts when the object pre-exists.
/// `INDEX` is one: the previous release's `ON CONFLICT` may name the unique
/// index (or the constraint) being dropped. A file whose header carries
/// [`INDEX_DROP_MARKER`] with a reason drops indexes and constraints it has
/// reviewed.
const DROPPED_KINDS: &[&str] = &[
    "INDEX",
    "TABLE",
    "VIEW",
    "MATERIALIZED",
    "TYPE",
    "DOMAIN",
    "FUNCTION",
    "PROCEDURE",
    "AGGREGATE",
    "SEQUENCE",
    "SCHEMA",
    "TRIGGER",
    "RULE",
    "POLICY",
    "EXTENSION",
];

/// Kinds whose `ALTER <kind> ... RENAME` (or `SET SCHEMA`) contracts.
const RENAMED_KINDS: &[&str] = &[
    "TYPE",
    "DOMAIN",
    "VIEW",
    "MATERIALIZED",
    "SEQUENCE",
    "FUNCTION",
    "PROCEDURE",
    "SCHEMA",
    "TRIGGER",
];

/// Classify one action of an `ALTER TABLE` (the tokens between top-level
/// commas): what it contracts, or `None` when it expands or loosens.
fn classify_alter_table_action(a: &[Tok]) -> Option<&'static str> {
    let first = a.first()?;
    let at = |k: usize, kw: &str| a.get(k).is_some_and(|x| x.is(kw));
    let has_seq = |seq: &[&str]| {
        a.windows(seq.len())
            .any(|w| w.iter().zip(seq).all(|(x, k)| x.is(k)))
    };
    if first.is("DROP") {
        // DROP CONSTRAINT loosens; DROP [COLUMN] [IF EXISTS] c contracts.
        return Some(if at(1, "CONSTRAINT") {
            "DROP CONSTRAINT"
        } else {
            "DROP COLUMN"
        });
    }
    if first.is("RENAME") {
        return Some("RENAME");
    }
    if first.is("SET") && at(1, "SCHEMA") {
        return Some("SET SCHEMA");
    }
    if first.is("ALTER") {
        if at(1, "CONSTRAINT") {
            return None;
        }
        let rest = if at(1, "COLUMN") { 3 } else { 2 };
        let r = a.get(rest..).unwrap_or(&[]);
        let r_at = |k: usize, kw: &str| r.get(k).is_some_and(|x| x.is(kw));
        if r_at(0, "TYPE") || (r_at(0, "SET") && r_at(1, "DATA") && r_at(2, "TYPE")) {
            return Some("ALTER COLUMN ... TYPE");
        }
        if r_at(0, "SET") && r_at(1, "NOT") && r_at(2, "NULL") {
            return Some("SET NOT NULL");
        }
        if r_at(0, "DROP") && (r_at(1, "DEFAULT") || r_at(1, "IDENTITY") || r_at(1, "EXPRESSION")) {
            return Some("ALTER COLUMN ... DROP DEFAULT/IDENTITY/EXPRESSION");
        }
        return None;
    }
    if first.is("ADD") {
        let tightening = ["CHECK", "UNIQUE", "PRIMARY", "EXCLUDE", "FOREIGN"];
        if at(1, "CONSTRAINT") {
            return a
                .get(3)
                .is_some_and(|k| tightening.iter().any(|kw| k.is(kw)))
                .then_some("ADD CONSTRAINT");
        }
        if a.get(1)
            .is_some_and(|k| tightening.iter().any(|kw| k.is(kw)))
        {
            return Some("ADD CONSTRAINT");
        }
        // ADD [COLUMN] [IF NOT EXISTS] c <type> ...: an INSERT of the previous
        // release, which does not name the column, must still succeed.
        let required = has_seq(&["NOT", "NULL"]) || has_seq(&["PRIMARY", "KEY"]);
        let filled = has_seq(&["DEFAULT"]) || has_seq(&["GENERATED"]);
        return (required && !filled).then_some("ADD COLUMN ... NOT NULL without DEFAULT");
    }
    None
}

/// Every statement in a masked migration that contracts the schema of an
/// object the file did not create, as `(byte offset, what)`. Pure.
fn contract_statements(masked: &str) -> Vec<(usize, String)> {
    let all = tokens(masked);
    let created = objects_created(&all);
    let created_table = |name: &str| created.contains(&("TABLE".to_string(), name.to_string()));
    let routines = routine_bodies(masked);
    let in_routine = |at: usize| routines.iter().any(|(s, e)| at >= *s && at < *e);
    // Statement by statement (a `;` inside a DO block splits it too, which is
    // fine: each piece still starts at its own keyword).
    let mut out: Vec<(usize, String)> = Vec::new();
    for stmt in all.split(|x| x.is(";")) {
        let t: Vec<&Tok> = stmt.iter().filter(|x| !in_routine(x.at)).collect();
        let t: Vec<Tok> = t.into_iter().cloned().collect();
        let mut i = 0usize;
        while i < t.len() {
            let kw = |k: usize, s: &str| t.get(k).is_some_and(|x| x.is(s));
            if kw(i, "ALTER") && kw(i + 1, "TABLE") {
                let (name, mut j) = object_name(&t, i + 2);
                if t.get(j).is_some_and(|x| x.text == "*") {
                    j += 1;
                }
                let Some(table) = name else {
                    i += 2;
                    continue;
                };
                // The actions run to the end of the statement, split at
                // top-level commas.
                let mut depth = 0i32;
                let mut start = j;
                let mut k = j;
                while k <= t.len() {
                    let end = k == t.len();
                    if !end {
                        match t[k].text.as_str() {
                            "(" if !t[k].quoted => depth += 1,
                            ")" if !t[k].quoted => depth -= 1,
                            _ => {}
                        }
                    }
                    if end || (depth == 0 && t[k].is(",")) {
                        if let Some(what) = classify_alter_table_action(&t[start..k]) {
                            if !created_table(&table) {
                                out.push((t[start].at, format!("{what} on `{table}`")));
                            }
                        }
                        start = k + 1;
                    }
                    k += 1;
                }
                i = t.len();
                continue;
            }
            if kw(i, "DROP") {
                if let Some(kind) = t
                    .get(i + 1)
                    .filter(|x| DROPPED_KINDS.iter().any(|k| x.is(k)))
                {
                    let kind_text = kind.text.clone();
                    let name_at = if kind_text == "MATERIALIZED" {
                        i + 3
                    } else {
                        i + 2
                    };
                    let (name, _) = object_name(&t, name_at);
                    if let Some(name) = name {
                        let lookup = if kind_text == "MATERIALIZED" {
                            "VIEW"
                        } else {
                            kind_text.as_str()
                        };
                        if !created.contains(&(lookup.to_string(), name.clone())) {
                            let label = if kind_text == "MATERIALIZED" {
                                "MATERIALIZED VIEW".to_string()
                            } else {
                                kind_text.clone()
                            };
                            out.push((t[i].at, format!("DROP {label} on `{name}`")));
                        }
                    }
                }
                i += 1;
                continue;
            }
            if kw(i, "ALTER") {
                if let Some(kind) = t
                    .get(i + 1)
                    .filter(|x| RENAMED_KINDS.iter().any(|k| x.is(k)))
                {
                    let kind_text = kind.text.clone();
                    let name_at = if kind_text == "MATERIALIZED" {
                        i + 3
                    } else {
                        i + 2
                    };
                    let (name, j) = object_name(&t, name_at);
                    let rest = &t[j.min(t.len())..];
                    let any = |seq: &[&str]| {
                        rest.windows(seq.len())
                            .any(|w| w.iter().zip(seq).all(|(x, k)| x.is(k)))
                    };
                    let what = if any(&["RENAME"]) {
                        Some("RENAME")
                    } else if any(&["SET", "SCHEMA"]) {
                        Some("SET SCHEMA")
                    } else if kind_text == "TYPE" && any(&["DROP", "ATTRIBUTE"]) {
                        Some("DROP ATTRIBUTE")
                    } else if kind_text == "DOMAIN"
                        && (any(&["ADD", "CONSTRAINT"])
                            || any(&["ADD", "CHECK"])
                            || any(&["SET", "NOT", "NULL"]))
                    {
                        Some("tighten DOMAIN")
                    } else {
                        None
                    };
                    let lookup = if kind_text == "MATERIALIZED" {
                        "VIEW"
                    } else {
                        kind_text.as_str()
                    };
                    if let (Some(what), Some(name)) = (what, name) {
                        if !created.contains(&(lookup.to_string(), name.clone())) {
                            out.push((
                                t[i].at,
                                format!("{what} ({}) on `{name}`", kind_text.to_ascii_lowercase()),
                            ));
                        }
                    }
                }
                i += 1;
                continue;
            }
            if kw(i, "CREATE") && kw(i + 1, "UNIQUE") && kw(i + 2, "INDEX") {
                if let Some(on) = (i + 3..t.len()).find(|&k| t[k].is("ON")) {
                    if let (Some(table), _) = object_name(&t, on + 1) {
                        if !created_table(&table) {
                            out.push((t[i].at, format!("CREATE UNIQUE INDEX on `{table}`")));
                        }
                    }
                }
                i += 3;
                continue;
            }
            i += 1;
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Header marker of a migration whose `DROP INDEX` / `DROP CONSTRAINT`
/// statements were reviewed: no release in service names the index or
/// constraint (an `ON CONFLICT` target, a hint) or relies on what it
/// enforces. Followed by the reason: `-- migration-safety: index-only, <why>`.
const INDEX_DROP_MARKER: &str = "migration-safety: index-only,";

/// The reason after [`INDEX_DROP_MARKER`] in a migration's leading comment
/// lines, when present and non-empty.
fn index_drop_reason(body: &str) -> Option<&str> {
    body.lines()
        .map(str::trim)
        .take_while(|l| l.is_empty() || l.starts_with("--"))
        .find_map(|l| {
            l.strip_prefix("--")
                .map(str::trim_start)
                .and_then(|l| l.strip_prefix(INDEX_DROP_MARKER))
                .map(str::trim)
        })
        .filter(|r| !r.is_empty())
}

/// Whether a finding is one [`INDEX_DROP_MARKER`] covers.
fn is_index_or_constraint_drop(what: &str) -> bool {
    what.starts_with("DROP INDEX ") || what.starts_with("DROP CONSTRAINT ")
}

/// The expand migration a file named `NNN_contract_of_MMM_<what>.sql` names
/// (`Some(MMM)`), `Some(None)` for a file named as a contract without a valid
/// `of_MMM`, and `None` for a file not named as a contract.
fn contract_name(file: &str) -> Option<Option<u32>> {
    let stem = file.split_once('_')?.1.trim_end_matches(".sql");
    if stem != "contract" && !stem.starts_with("contract_") {
        return None;
    }
    Some(
        stem.strip_prefix("contract_of_")
            .and_then(|r| r.split('_').next())
            .and_then(|v| v.parse().ok()),
    )
}

/// FNV-1a 64 over the sorted names, each followed by a newline: stable across
/// Rust versions and platforms, unlike the std hasher. Pure.
fn history_fingerprint(names: &[&str]) -> u64 {
    let mut sorted = names.to_vec();
    sorted.sort_unstable();
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for name in sorted {
        for b in name.bytes().chain(std::iter::once(b'\n')) {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    h
}

/// The expand/contract violations of one migration file from
/// [`CONTRACT_RULE_FROM`] on (#5920), given every migration version in the
/// tree. Empty when the file is expand-only, or a correctly named contract.
/// Pure.
fn contract_violations(file: &str, body: &str, versions: &[u32]) -> Vec<String> {
    let version: u32 = file
        .split('_')
        .next()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let masked = mask_sql(body);
    let reviewed_drops = index_drop_reason(body).is_some();
    let found: Vec<(usize, String)> = contract_statements(&masked)
        .into_iter()
        .filter(|(_, what)| !(reviewed_drops && is_index_or_constraint_drop(what)))
        .collect();
    let line = |at: usize| masked[..at].bytes().filter(|&c| c == b'\n').count() + 1;
    let mut bad = Vec::new();
    if body.contains(INDEX_DROP_MARKER) && !reviewed_drops {
        bad.push(format!(
            "{file}: `-- {INDEX_DROP_MARKER}` needs a reason after it, in the leading comments"
        ));
    }
    bad.extend(match contract_name(file) {
        None if found.is_empty() => Vec::new(),
        None => {
            let list: Vec<String> = found
                .iter()
                .map(|(at, what)| format!("line {}: {what}", line(*at)))
                .collect();
            vec![format!(
                "{file}: contracts the schema ({}) but is not named \
                 `{version:03}_contract_of_<expand version>_<what>.sql`",
                list.join("; ")
            )]
        }
        Some(None) => vec![format!(
            "{file}: a contract migration is named `{version:03}_contract_of_<expand version>_<what>.sql`"
        )],
        Some(Some(of)) if of < version && versions.contains(&of) => Vec::new(),
        Some(Some(of)) => vec![format!(
            "{file}: `contract_of_{of}` must name an earlier migration in the tree"
        )],
    });
    bad
}

/// One line per finding, for the inventory and failure output.
fn finding_summary(body: &str) -> String {
    let masked = mask_sql(body);
    let mut whats: Vec<String> = contract_statements(&masked)
        .into_iter()
        .map(|(_, w)| w)
        .collect();
    whats.dedup();
    whats.join("; ")
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn migrations_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("migrations")
    }

    fn migration_files() -> Vec<(String, String)> {
        let dir = migrations_dir();
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&dir).expect("backend/migrations/ readable") {
            let path = entry.expect("dir entry").path();
            if path.is_file() && path.extension().is_some_and(|e| e == "sql") {
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                let body = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
                out.push((name, body));
            }
        }
        out.sort();
        assert!(
            out.len() >= 190,
            "found only {} migrations — wrong repo root?",
            out.len()
        );
        out
    }

    /// Every blocking statement this gate finds on a hot, pre-existing table.
    fn findings() -> Vec<Finding> {
        let hot: std::collections::BTreeSet<&str> = HOT_TABLES.iter().map(|(t, _)| *t).collect();
        let mut out = Vec::new();
        for (name, body) in migration_files() {
            let masked = mask_sql(&body);
            let created = tables_created(&masked);
            let routines = routine_bodies(&masked);
            for (offset, stmt) in statements(&masked) {
                for (kind, table, at) in classify(stmt) {
                    if !hot.contains(table.as_str()) || created.contains(&table) {
                        continue;
                    }
                    let abs = offset + at;
                    if routines.iter().any(|(s, e)| abs >= *s && abs < *e) {
                        continue;
                    }
                    out.push(Finding {
                        file: name.clone(),
                        line: masked[..abs].bytes().filter(|&c| c == b'\n').count() + 1,
                        kind,
                        table,
                        excerpt: stmt
                            .split_whitespace()
                            .collect::<Vec<_>>()
                            .join(" ")
                            .chars()
                            .take(110)
                            .collect(),
                    });
                }
            }
        }
        out
    }

    /// THE gate (PF-008, #2524): the set of write-blocking statements against a
    /// hot table in `backend/migrations/` must equal [`ALLOWLIST`] exactly.
    ///
    /// A new migration that adds one fails here. An allowlist entry that stops
    /// matching also fails, so the inventory cannot rot.
    #[test]
    fn no_new_blocking_ddl_on_hot_tables() {
        let mut actual: BTreeMap<(String, &str, String), usize> = BTreeMap::new();
        let mut where_: BTreeMap<(String, &str, String), Vec<String>> = BTreeMap::new();
        for f in findings() {
            let key = (f.file.clone(), f.kind, f.table.clone());
            *actual.entry(key.clone()).or_default() += 1;
            where_
                .entry(key)
                .or_default()
                .push(format!("{}:{} {}", f.file, f.line, f.excerpt));
        }

        let mut expected: BTreeMap<(String, &str, String), usize> = BTreeMap::new();
        let mut reason: BTreeMap<(String, &str, String), &str> = BTreeMap::new();
        for (file, kind, table, count, why) in ALLOWLIST {
            let key = (file.to_string(), *kind, table.to_string());
            assert!(
                expected.insert(key.clone(), *count).is_none(),
                "duplicate ALLOWLIST entry for {key:?}"
            );
            reason.insert(key, why);
        }

        if actual == expected {
            return;
        }

        let mut diff = String::new();
        for (key, want) in &expected {
            match actual.get(key) {
                Some(got) if got == want => {}
                Some(got) => diff.push_str(&format!(
                    "  {} [{}] on `{}`: allowlist={want} actual={got}\n",
                    key.0, key.1, key.2
                )),
                None => diff.push_str(&format!(
                    "  {} [{}] on `{}`: allowlist={want} actual=0 — the statement is gone; \
                     drop the entry (reason was: {})\n",
                    key.0,
                    key.1,
                    key.2,
                    reason.get(key).copied().unwrap_or("")
                )),
            }
        }
        for (key, got) in &actual {
            if !expected.contains_key(key) {
                diff.push_str(&format!(
                    "  {} [{}] on `{}`: allowlist=<absent> actual={got}\n{}\n",
                    key.0,
                    key.1,
                    key.2,
                    where_
                        .get(key)
                        .map(|v| v
                            .iter()
                            .map(|l| format!("      {l}"))
                            .collect::<Vec<_>>()
                            .join("\n"))
                        .unwrap_or_default()
                ));
            }
        }

        panic!(
            "Migration blocking-DDL inventory no longer matches the allowlist \
             (PF-008, #2524 / epic #2516).\n\
             \n\
             A statement listed below blocks writes to a table that holds a row per \
             artifact, download or scan. At the one-million-artifact operating point \
             the upgrade that runs it is an outage, and the epic's `Online upgrades` \
             gate requires upload/download SLOs to stay within 2x baseline during a \
             large index or backfill.\n\
             \n\
             If you ADDED one, do not add it to the allowlist — make it online:\n\
               * index build   -> a migration of its own whose FIRST LINE is exactly \
             `-- no-transaction` and whose ONLY statement is `CREATE INDEX CONCURRENTLY`;\n\
               * constraint    -> `ADD CONSTRAINT ... NOT VALID`, then a later \
             `VALIDATE CONSTRAINT` (SHARE UPDATE EXCLUSIVE, no write block);\n\
               * unique key    -> `CREATE UNIQUE INDEX CONCURRENTLY`, then \
             `ADD CONSTRAINT ... USING INDEX`;\n\
               * backfill      -> a keyset-batched loop with a LIMIT per batch, not \
             one whole-table UPDATE;\n\
               * column rewrite-> add a new column, backfill in batches, swap.\n\
             See docs/operations/online-migrations.md for the full runbook.\n\
             \n\
             If a line below says `actual=0`, a migration already in history changed. \
             Migrations that have run on production databases must NOT be edited \
             (see 106/108/110) -- revert the edit rather than updating this list.\n\
             \n{diff}"
        );
    }

    /// `sqlx::migrate!` wraps each file in a transaction unless its first bytes
    /// are exactly `-- no-transaction` (sqlx 0.9,
    /// `sqlx-core/src/migrate/source.rs`). PostgreSQL rejects every
    /// `CONCURRENTLY` form inside a transaction block, so a migration that uses
    /// one without the header cannot work — it would fail on the operator's
    /// database at upgrade time, after earlier migrations had already applied.
    #[test]
    fn concurrent_ddl_requires_no_transaction_header() {
        let mut broken = Vec::new();
        for (name, body) in migration_files() {
            let masked = mask_sql(&body);
            if find_phrase(&masked, "CONCURRENTLY", 0).is_none() {
                continue;
            }
            if !body.starts_with("-- no-transaction") {
                broken.push(name);
            }
        }
        assert!(
            broken.is_empty(),
            "migration(s) use CONCURRENTLY inside a transaction-wrapped migration \
             (PF-008, #2524): {}\n\
             PostgreSQL rejects CREATE INDEX CONCURRENTLY / REINDEX CONCURRENTLY inside \
             a transaction block, and sqlx wraps every migration in one unless the file's \
             FIRST LINE is exactly `-- no-transaction`. Add that header as the very first \
             line, and read docs/operations/online-migrations.md first: a no-transaction \
             migration that fails part-way is NOT rolled back and NOT recorded, so it must \
             be written to be safely re-runnable. For `CREATE INDEX CONCURRENTLY`, register \
             the migration (version, index name) in `CONCURRENT_INDEX_MIGRATIONS` \
             (migration_repair.rs): a failed build leaves an INVALID index, which \
             `CREATE INDEX CONCURRENTLY IF NOT EXISTS` skips on the re-run and records as \
             done, and the startup repair drops it first. A `DROP INDEX IF EXISTS` \
             migration before the build runs only once, so it covers out-of-band attempts \
             only.",
            broken.join(", ")
        );
    }

    /// A `-- no-transaction` migration may contain exactly ONE statement.
    ///
    /// sqlx applies a migration with `conn.execute(&sql)` and no bind
    /// parameters (`sqlx-postgres/src/migrate.rs::execute_migration`), which is
    /// the simple query protocol; PostgreSQL wraps a multi-statement simple
    /// query in an implicit transaction block. So a `-- no-transaction` file
    /// with two statements is back inside a transaction and its
    /// `CREATE INDEX CONCURRENTLY` — or a `COMMIT` inside a batching `DO` block
    /// — fails on the operator's database, not here. One statement per file.
    #[test]
    fn no_transaction_migrations_hold_one_statement() {
        let mut bad = Vec::new();
        for (name, body) in migration_files() {
            if !body.starts_with("-- no-transaction") {
                continue;
            }
            let n = top_level_statement_count(&mask_sql(&body));
            if n != 1 {
                bad.push(format!("{name}: {n} statements"));
            }
        }
        assert!(
            bad.is_empty(),
            "`-- no-transaction` migration(s) contain more than one statement \
             (PF-008, #2524): {}\n\
             sqlx sends the whole file as one simple query, and PostgreSQL runs a \
             multi-statement simple query inside an implicit transaction block — which \
             is exactly what the header was supposed to avoid. Split the file so each \
             `-- no-transaction` migration carries a single statement. A `DROP INDEX IF \
             EXISTS` reset goes in its own transactional migration before the build (it \
             runs once, so it only covers out-of-band attempts); a failed in-migrator \
             build is repaired at startup when the build migration is registered in \
             `CONCURRENT_INDEX_MIGRATIONS` (migration_repair.rs). See \
             docs/operations/online-migrations.md.",
            bad.join(", ")
        );
    }

    /// #4153: a migration from [`TIMEOUT_RULE_FROM`] on that backfills a hot
    /// table or creates a trigger on one must bound its lock waits, and none
    /// may disable or enable a trigger on one.
    #[test]
    fn hot_table_backfills_and_triggers_set_timeouts() {
        let hot: std::collections::BTreeSet<&str> = HOT_TABLES.iter().map(|(t, _)| *t).collect();
        let mut bad = Vec::new();
        for (name, body) in migration_files() {
            let version: u32 = name
                .split('_')
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| panic!("{name}: no numeric version prefix"));
            if version < TIMEOUT_RULE_FROM {
                continue;
            }
            if let Some(why) = timeout_findings(&mask_sql(&body), &hot) {
                bad.push(format!("{name}: {why}"));
            }
        }
        assert!(
            bad.is_empty(),
            "migration(s) touch a hot table without bounding their lock waits, or toggle \
             a trigger on one (#4153): {}\n\
             Add `SET LOCAL lock_timeout = '5s'` to every transaction that runs the \
             statement (inside a batching DO block, once per batch, since COMMIT ends SET \
             LOCAL), and retry a batch that hits lock_not_available instead of waiting. \
             Never DISABLE/ENABLE TRIGGER: relax the trigger through its function. See \
             docs/operations/online-migrations.md.",
            bad.join("; ")
        );
    }

    #[test]
    fn timeout_findings_flags_only_unbounded_hot_table_work() {
        let hot: std::collections::BTreeSet<&str> = ["artifacts"].into_iter().collect();
        let check = |sql: &str| timeout_findings(&mask_sql(sql), &hot);

        // Backfill and trigger shapes without a lock timeout are flagged.
        let backfill = "DO $$ BEGIN LOOP UPDATE artifacts SET x = 1 WHERE id IN \
                        (SELECT id FROM artifacts LIMIT 10); COMMIT; END LOOP; END $$;";
        assert_eq!(
            check(backfill).as_deref(),
            Some("backfill on `artifacts` without SET lock_timeout")
        );
        for trigger in [
            "CREATE TRIGGER t BEFORE UPDATE ON artifacts FOR EACH ROW EXECUTE FUNCTION f();",
            "CREATE OR REPLACE TRIGGER t BEFORE UPDATE ON artifacts \
             FOR EACH ROW EXECUTE FUNCTION f();",
            "CREATE CONSTRAINT TRIGGER t AFTER INSERT ON artifacts \
             FOR EACH ROW EXECUTE FUNCTION f();",
        ] {
            assert_eq!(
                check(trigger).as_deref(),
                Some("trigger on `artifacts` without SET lock_timeout"),
                "{trigger}"
            );
        }
        assert_eq!(
            check("INSERT INTO artifacts (id) SELECT id FROM legacy;").as_deref(),
            Some("backfill on `artifacts` without SET lock_timeout")
        );
        // A plain VALUES insert is not a backfill.
        assert_eq!(check("INSERT INTO artifacts (id) VALUES (1);"), None);

        // Toggling a trigger on a hot table is forbidden, timeouts or not.
        for toggle in [
            "DISABLE TRIGGER t",
            "ENABLE TRIGGER t",
            "ENABLE ALWAYS TRIGGER t",
        ] {
            let sql = format!("SET LOCAL lock_timeout = '5s'; ALTER TABLE artifacts {toggle};");
            assert!(
                check(&sql).is_some_and(|w| w.starts_with("forbidden:")),
                "{sql}"
            );
        }

        // Bounded, a cold table, a routine body, or a comment: not flagged.
        let bounded = format!("SET LOCAL lock_timeout = '5s'; {backfill}");
        assert_eq!(check(&bounded), None);
        assert_eq!(check("UPDATE system_settings SET v = 1;"), None);
        assert_eq!(
            check("ALTER TABLE system_settings DISABLE TRIGGER t;"),
            None
        );
        assert_eq!(
            check(
                "CREATE FUNCTION f() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN \
                 UPDATE artifacts SET x = 1; RETURN NEW; END $f$;"
            ),
            None
        );
        assert_eq!(check("-- UPDATE artifacts SET x = 1\nSELECT 1;"), None);
    }

    /// Every hot table named in [`HOT_TABLES`] must actually exist in the
    /// schema, so a rename cannot silently empty the gate's scope.
    #[test]
    fn hot_tables_exist_in_the_schema() {
        let mut created = std::collections::BTreeSet::new();
        for (_, body) in migration_files() {
            created.extend(tables_created(&mask_sql(&body)));
        }
        let missing: Vec<&str> = HOT_TABLES
            .iter()
            .map(|(t, _)| *t)
            .filter(|t| !created.contains(*t))
            .collect();
        assert!(
            missing.is_empty(),
            "HOT_TABLES names table(s) no migration creates: {missing:?}. \
             If a table was renamed, rename it here too — otherwise the PF-008 gate \
             silently stops covering it.",
        );
    }

    /// #5920: every migration is expand-only, a correctly named contract
    /// (from [`CONTRACT_RULE_FROM`] on), or a listed piece of history.
    #[test]
    fn migrations_are_expand_only_unless_named_as_contracts() {
        let files = migration_files();
        let versions: Vec<u32> = files
            .iter()
            .filter_map(|(n, _)| n.split('_').next().and_then(|v| v.parse().ok()))
            .collect();
        let allow: BTreeMap<&str, &str> = CONTRACT_ALLOWLIST.iter().copied().collect();
        let history: BTreeMap<&str, &str> = HISTORICAL_CONTRACTS.iter().copied().collect();
        assert_eq!(
            history.len(),
            HISTORICAL_CONTRACTS.len(),
            "duplicate HISTORICAL_CONTRACTS entry"
        );
        let mut bad = Vec::new();
        let mut flagged_history = BTreeMap::new();
        for (name, body) in &files {
            let version: u32 = name
                .split('_')
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            if version < CONTRACT_RULE_FROM {
                let summary = finding_summary(body);
                if !summary.is_empty() {
                    flagged_history.insert(name.clone(), summary);
                }
                continue;
            }
            if allow.contains_key(name.as_str()) {
                if contract_statements(&mask_sql(body)).is_empty() {
                    bad.push(format!(
                        "CONTRACT_ALLOWLIST names {name}, which no longer has a finding"
                    ));
                }
                continue;
            }
            bad.extend(contract_violations(name, body, &versions));
        }
        for file in allow.keys() {
            if !files.iter().any(|(n, _)| n == file) {
                bad.push(format!(
                    "CONTRACT_ALLOWLIST names {file}, which is not a migration"
                ));
            }
        }
        let unlisted: Vec<String> = flagged_history
            .iter()
            .filter(|(f, _)| !history.contains_key(f.as_str()))
            .map(|(f, w)| format!("    ({f:?}, {w:?}),"))
            .collect();
        for (file, what) in HISTORICAL_CONTRACTS.iter() {
            if what.trim().is_empty() {
                bad.push(format!(
                    "HISTORICAL_CONTRACTS entry {file} has no description"
                ));
            }
            if let Some(found) = flagged_history.get(*file) {
                if found != what {
                    bad.push(format!(
                        "HISTORICAL_CONTRACTS describes {file} as {what:?}, the scanner finds {found:?}"
                    ));
                }
            }
        }
        for (file, why) in CONTRACT_ALLOWLIST.iter() {
            if why.trim().is_empty() {
                bad.push(format!("CONTRACT_ALLOWLIST entry {file} has no reason"));
            }
        }
        let stale: Vec<&str> = history
            .keys()
            .filter(|f| !flagged_history.contains_key(**f))
            .copied()
            .collect();
        if !unlisted.is_empty() {
            bad.push(format!(
                "historical migration(s) the scanner flags but HISTORICAL_CONTRACTS does not list:\n{}",
                unlisted.join("\n")
            ));
        }
        if !stale.is_empty() {
            bad.push(format!(
                "HISTORICAL_CONTRACTS lists file(s) the scanner no longer flags: {stale:?}"
            ));
        }
        assert!(
            bad.is_empty(),
            "migration(s) break the expand/contract rule for rolling deploys (#5920):\n  {}\n\
             During a rolling update the previous release serves on the schema this migration \
             produces. Ship the change as EXPAND first (new nullable or defaulted columns, new \
             tables, code that stops using the old object), then CONTRACT in a later release, \
             in a file named `NNN_contract_of_<expand version>_<what>.sql`. See \
             docs/operations/online-migrations.md#rolling-deploys-expand-then-contract.",
            bad.join("\n  ")
        );
    }

    #[test]
    fn contract_statements_catch_every_form_5920() {
        let flagged = |sql: &str| {
            contract_statements(&mask_sql(sql))
                .into_iter()
                .map(|(_, w)| w)
                .collect::<Vec<_>>()
        };
        let one = |sql: &str, want: &str| assert_eq!(flagged(sql), vec![want.to_string()], "{sql}");
        // Drops, long and short forms, quoted and schema-qualified names.
        one("DROP TABLE IF EXISTS widgets;", "DROP TABLE on `widgets`");
        one(
            "DROP TABLE public.\"Widgets\" CASCADE;",
            "DROP TABLE on `widgets`",
        );
        one(
            "ALTER TABLE widgets DROP COLUMN color;",
            "DROP COLUMN on `widgets`",
        );
        one(
            "ALTER TABLE widgets DROP color;",
            "DROP COLUMN on `widgets`",
        );
        one(
            "ALTER TABLE IF EXISTS ONLY widgets DROP IF EXISTS \"Color\";",
            "DROP COLUMN on `widgets`",
        );
        one(
            "ALTER TABLE \"widgets\" DROP \"type\";",
            "DROP COLUMN on `widgets`",
        );
        for (kind, label) in [
            ("VIEW", "VIEW"),
            ("MATERIALIZED VIEW", "MATERIALIZED VIEW"),
            ("TYPE", "TYPE"),
            ("DOMAIN", "DOMAIN"),
            ("FUNCTION", "FUNCTION"),
            ("PROCEDURE", "PROCEDURE"),
            ("SEQUENCE", "SEQUENCE"),
            ("SCHEMA", "SCHEMA"),
        ] {
            one(
                &format!("DROP {kind} IF EXISTS obj;"),
                &format!("DROP {label} on `obj`"),
            );
        }
        one(
            "DROP FUNCTION widget_total(uuid);",
            "DROP FUNCTION on `widget_total`",
        );
        one(
            "DROP TRIGGER IF EXISTS t_sync ON widgets;",
            "DROP TRIGGER on `t_sync`",
        );
        // Renames.
        one(
            "ALTER TABLE widgets RENAME COLUMN a TO b;",
            "RENAME on `widgets`",
        );
        one("ALTER TABLE widgets RENAME a TO b;", "RENAME on `widgets`");
        one(
            "ALTER TABLE widgets RENAME TO gadgets;",
            "RENAME on `widgets`",
        );
        one(
            "ALTER TABLE widgets SET SCHEMA archive;",
            "SET SCHEMA on `widgets`",
        );
        one(
            "ALTER TYPE widget_kind RENAME VALUE 'a' TO 'b';",
            "RENAME (type) on `widget_kind`",
        );
        one(
            "ALTER SEQUENCE widget_seq RENAME TO s2;",
            "RENAME (sequence) on `widget_seq`",
        );
        one(
            "ALTER FUNCTION f(int) RENAME TO g;",
            "RENAME (function) on `f`",
        );
        one(
            "ALTER TYPE addr DROP ATTRIBUTE zip;",
            "DROP ATTRIBUTE (type) on `addr`",
        );
        one(
            "ALTER DOMAIN pos ADD CONSTRAINT p CHECK (VALUE > 0);",
            "tighten DOMAIN (domain) on `pos`",
        );
        // Tightening a column, long and short forms.
        one(
            "ALTER TABLE widgets ALTER COLUMN a SET NOT NULL;",
            "SET NOT NULL on `widgets`",
        );
        one(
            "ALTER TABLE widgets ALTER a SET NOT NULL;",
            "SET NOT NULL on `widgets`",
        );
        one(
            "ALTER TABLE widgets ALTER COLUMN a TYPE INT;",
            "ALTER COLUMN ... TYPE on `widgets`",
        );
        one(
            "ALTER TABLE widgets ALTER a TYPE bigint USING a::bigint;",
            "ALTER COLUMN ... TYPE on `widgets`",
        );
        one(
            "ALTER TABLE widgets ALTER COLUMN a SET DATA TYPE INT;",
            "ALTER COLUMN ... TYPE on `widgets`",
        );
        one(
            "ALTER TABLE widgets ALTER COLUMN a DROP DEFAULT;",
            "ALTER COLUMN ... DROP DEFAULT/IDENTITY/EXPRESSION on `widgets`",
        );
        one(
            "ALTER TABLE widgets ALTER id DROP IDENTITY IF EXISTS;",
            "ALTER COLUMN ... DROP DEFAULT/IDENTITY/EXPRESSION on `widgets`",
        );
        one(
            "ALTER TABLE widgets ADD COLUMN owner UUID NOT NULL;",
            "ADD COLUMN ... NOT NULL without DEFAULT on `widgets`",
        );
        one(
            "ALTER TABLE widgets ADD owner int NOT NULL;",
            "ADD COLUMN ... NOT NULL without DEFAULT on `widgets`",
        );
        one(
            "ALTER TABLE widgets ADD IF NOT EXISTS k int PRIMARY KEY;",
            "ADD COLUMN ... NOT NULL without DEFAULT on `widgets`",
        );
        // New constraints and unique indexes.
        one(
            "ALTER TABLE widgets ADD CONSTRAINT w_pos CHECK (n > 0) NOT VALID;",
            "ADD CONSTRAINT on `widgets`",
        );
        one(
            "ALTER TABLE widgets ADD UNIQUE (name);",
            "ADD CONSTRAINT on `widgets`",
        );
        one(
            "ALTER TABLE widgets ADD CONSTRAINT fk FOREIGN KEY (o) REFERENCES users(id);",
            "ADD CONSTRAINT on `widgets`",
        );
        one(
            "ALTER TABLE widgets ADD PRIMARY KEY (id);",
            "ADD CONSTRAINT on `widgets`",
        );
        one(
            "CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS w_name ON widgets (name);",
            "CREATE UNIQUE INDEX on `widgets`",
        );
        one(
            "CREATE UNIQUE INDEX w_name ON ONLY public.widgets (name);",
            "CREATE UNIQUE INDEX on `widgets`",
        );
        // Several actions in one ALTER TABLE, and several statements in one
        // file, comments between them: each counted.
        assert_eq!(
            flagged(
                "ALTER TABLE widgets ADD COLUMN note TEXT, /* gone */ DROP legacy, \
                 ALTER n TYPE bigint; -- trailing\nALTER TABLE gadgets DROP CONSTRAINT g_pos, DROP x;"
            ),
            vec![
                "DROP COLUMN on `widgets`".to_string(),
                "ALTER COLUMN ... TYPE on `widgets`".to_string(),
                "DROP CONSTRAINT on `gadgets`".to_string(),
                "DROP COLUMN on `gadgets`".to_string(),
            ]
        );
        // Inside a DO block: still executed at migration time.
        one(
            "DO $$ BEGIN ALTER TABLE widgets DROP color; END $$;",
            "DROP COLUMN on `widgets`",
        );

        // Index and constraint drops: the previous release's ON CONFLICT may
        // name them.
        one(
            "ALTER TABLE widgets DROP CONSTRAINT w_pos;",
            "DROP CONSTRAINT on `widgets`",
        );
        one(
            "ALTER TABLE widgets DROP CONSTRAINT IF EXISTS widgets_pkey;",
            "DROP CONSTRAINT on `widgets`",
        );
        one(
            "DROP INDEX CONCURRENTLY IF EXISTS w_n;",
            "DROP INDEX on `w_n`",
        );
        one("DROP INDEX public.w_uniq;", "DROP INDEX on `w_uniq`");
        // ...but not one the same file creates.
        assert_eq!(
            flagged("CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS w_tmp ON fresh (id); DROP INDEX w_tmp; CREATE TABLE fresh (id INT);"),
            Vec::<String>::new()
        );

        // Expanding or loosening statements, and anything on an object born in
        // the file, a routine body, a comment or a string literal.
        for sql in [
            "ALTER TABLE widgets ADD COLUMN note TEXT;",
            "ALTER TABLE widgets ADD note TEXT;",
            "ALTER TABLE widgets ADD COLUMN n INT NOT NULL DEFAULT 0;",
            "ALTER TABLE widgets ADD COLUMN IF NOT EXISTS n INT NOT NULL DEFAULT 0, ADD COLUMN m TEXT;",
            "ALTER TABLE widgets ADD COLUMN g INT GENERATED ALWAYS AS (n + 1) STORED NOT NULL;",
            "ALTER TABLE widgets ADD COLUMN o UUID REFERENCES users(id);",
            "ALTER TABLE widgets ALTER COLUMN a DROP NOT NULL;",
            "ALTER TABLE widgets ALTER a SET DEFAULT 1;",
            "ALTER TABLE widgets ALTER COLUMN a SET STATISTICS 100;",
            "ALTER TABLE widgets ALTER CONSTRAINT fk DEFERRABLE;",
            "ALTER TABLE widgets ADD COLUMN type TEXT;",
            "ALTER TABLE widgets VALIDATE CONSTRAINT w_pos;",
            "ALTER TABLE widgets ENABLE ROW LEVEL SECURITY;",
            "ALTER TYPE widget_kind ADD VALUE 'c';",
            "ALTER INDEX w_n RENAME TO w_n2;",
            "CREATE INDEX CONCURRENTLY w_n ON widgets (n);",
            "CREATE TABLE fresh (id INT); ALTER TABLE fresh ADD CONSTRAINT u UNIQUE (id); \
             ALTER TABLE fresh ALTER COLUMN id SET NOT NULL; CREATE UNIQUE INDEX f_u ON fresh (id); \
             DROP TABLE fresh;",
            "DROP TRIGGER IF EXISTS t_sync ON widgets; CREATE TRIGGER t_sync AFTER INSERT ON widgets \
             FOR EACH ROW EXECUTE FUNCTION f();",
            "DROP FUNCTION IF EXISTS f(); CREATE OR REPLACE FUNCTION f() RETURNS int LANGUAGE sql AS $f$ SELECT 1 $f$;",
            "DROP VIEW IF EXISTS v; CREATE VIEW v AS SELECT 1;",
            "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $f$ BEGIN \
             DROP TABLE widgets; END $f$;",
            "-- ALTER TABLE widgets DROP COLUMN color;\nSELECT 1;",
            "/* DROP TABLE widgets; */ SELECT 1;",
            "SELECT 'ALTER TABLE widgets DROP color';",
        ] {
            assert_eq!(flagged(sql), Vec::<String>::new(), "{sql}");
        }
    }

    #[test]
    fn a_contract_is_named_after_its_expand() {
        let versions = [400, 418, 419, 420];
        let drop = "ALTER TABLE widgets DROP color;\n";
        assert_eq!(
            contract_violations(
                "418_widgets_add_paint.sql",
                "ALTER TABLE widgets ADD paint TEXT;",
                &versions
            ),
            Vec::<String>::new(),
            "expand-only"
        );
        let unmarked = contract_violations("419_widgets_drop_color.sql", drop, &versions);
        assert_eq!(unmarked.len(), 1);
        assert!(
            unmarked[0].contains("line 1: DROP COLUMN on `widgets`"),
            "{unmarked:?}"
        );
        assert_eq!(
            contract_violations("420_contract_of_418_widgets_color.sql", drop, &versions),
            Vec::<String>::new(),
            "a named contract"
        );
        for (file, want) in [
            ("420_contract_widgets.sql", "is named `420_contract_of_"),
            (
                "420_contract_of_x_widgets.sql",
                "is named `420_contract_of_",
            ),
            ("420_contract_of_420_widgets.sql", "earlier migration"),
            ("420_contract_of_417_widgets.sql", "earlier migration"),
        ] {
            let got = contract_violations(file, drop, &versions);
            assert!(got.iter().any(|v| v.contains(want)), "{file}: {got:?}");
        }
        // A reviewed index or constraint drop needs the marker and a reason.
        let idx = "DROP INDEX CONCURRENTLY IF EXISTS w_old;\n";
        assert!(!contract_violations("419_w_index.sql", idx, &versions).is_empty());
        assert_eq!(
            contract_violations(
                "419_w_index.sql",
                &format!("-- -- no-transaction is not needed here\n-- migration-safety: index-only, w_old is a plain index no ON CONFLICT names\n{idx}"),
                &versions
            ),
            Vec::<String>::new()
        );
        let no_reason = contract_violations(
            "419_w_index.sql",
            &format!("-- migration-safety: index-only,\n{idx}"),
            &versions,
        );
        assert!(
            no_reason.iter().any(|v| v.contains("needs a reason")),
            "{no_reason:?}"
        );
        // The marker covers index and constraint drops only.
        let mixed = contract_violations(
            "419_w_index.sql",
            &format!("-- migration-safety: index-only, reviewed\n{idx}ALTER TABLE w DROP c;\n"),
            &versions,
        );
        assert!(
            mixed.iter().any(|v| v.contains("DROP COLUMN on `w`")),
            "{mixed:?}"
        );
        assert!(!mixed.iter().any(|v| v.contains("DROP INDEX")), "{mixed:?}");

        assert_eq!(contract_name("420_contract_of_418_x.sql"), Some(Some(418)));
        assert_eq!(contract_name("420_contract_x.sql"), Some(None));
        assert_eq!(contract_name("420_contractor_x.sql"), None);
    }

    /// #5920: nothing enters the grandfathered range. The files below
    /// [`CONTRACT_RULE_FROM`] are exactly the frozen set, and every newer
    /// migration has a version of its own above it.
    #[test]
    fn migration_history_is_frozen() {
        let files = migration_files();
        let version = |n: &str| -> u32 {
            n.split('_')
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| panic!("{n}: no numeric version prefix"))
        };
        let history: Vec<&str> = files
            .iter()
            .map(|(n, _)| n.as_str())
            .filter(|n| version(n) < CONTRACT_RULE_FROM)
            .collect();
        let actual = (history.len(), history_fingerprint(&history));
        assert_eq!(
            actual, FROZEN_HISTORY,
            "the migrations below {CONTRACT_RULE_FROM} changed (a file added in a numbering gap, \
             removed or renamed): history is frozen (#5920). Number a new migration above every \
             existing one; never edit, rename or backfill history. (count, fingerprint) is now \
             {actual:?}"
        );
        let mut newer: Vec<u32> = files
            .iter()
            .map(|(n, _)| version(n))
            .filter(|v| *v >= CONTRACT_RULE_FROM)
            .collect();
        let count = newer.len();
        newer.dedup();
        assert_eq!(
            newer.len(),
            count,
            "two migrations share a version: {newer:?}"
        );
    }

    #[test]
    fn history_fingerprint_is_order_free_and_name_sensitive() {
        let a = history_fingerprint(&["001_a.sql", "002_b.sql"]);
        assert_eq!(a, history_fingerprint(&["002_b.sql", "001_a.sql"]));
        assert_ne!(a, history_fingerprint(&["001_a.sql", "002_c.sql"]));
        assert_ne!(
            a,
            history_fingerprint(&["001_a.sql", "002_b.sql", "095_x.sql"])
        );
        assert_ne!(
            history_fingerprint(&["ab", "c"]),
            history_fingerprint(&["a", "bc"]),
            "names are delimited"
        );
    }
}
