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
//!   EXISTS` that clears a leftover invalid index belongs in its own file.
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
             be written to be safely re-runnable (drop a leftover INVALID index before \
             rebuilding -- `CREATE INDEX CONCURRENTLY IF NOT EXISTS` will happily skip an \
             invalid one and leave it invalid forever).",
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
             `-- no-transaction` migration carries a single statement; a `DROP INDEX IF \
             EXISTS` that clears a leftover invalid index goes in its own migration \
             before the build. See docs/operations/online-migrations.md.",
            bad.join(", ")
        );
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
}
