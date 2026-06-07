# OCI Blob Layer Garbage Collection — Design (#1408)

Status: design + safe first slice shipped (read-only report).
Author: Backend Architecture review for issue #1408.
Scope: backend (`backend/src/services/storage_gc_service.rs`,
`backend/src/api/handlers/oci_v2.rs`, `backend/migrations/`).

## 1. Problem

`StorageGcService` (`backend/src/services/storage_gc_service.rs`) only
reclaims **manifest JSON** storage keys. It iterates `artifacts` rows and
applies `ORPHAN_PREDICATE_SQL`, which contains an `oci_blobs` clause — but
that clause is *defensive*: it stops a soft-deleted artifact that happens
to share a blob storage key from being collected. There is no source that
iterates `oci_blobs` itself, and `DELETE FROM oci_blobs` exists nowhere in
the tree.

Consequently the actual large objects of an image — the config blob plus
every entry in `layers[].digest` — leak in the storage backend forever
once their parent manifests are deleted or soft-deleted. Observed in
production on a Ceph RGW bucket: 426 GB bucket, `SUM(oci_blobs.size_bytes)`
≈ 403 GB, of which an out-of-band reconciler reclaimed ~344 GB (≈81%) in a
single pass. On long-lived registries blob accumulation is unbounded.

## 2. Reference model in THIS codebase

Tables that participate (migrations `026`, `092`):

- **`oci_blobs`** — `(id, repository_id, digest, size_bytes, storage_key,
  created_at)`, `UNIQUE(repository_id, digest)`. One row **per repository**
  per blob. The physical object lives at storage key `oci-blobs/<digest>`
  with **no per-repo prefix**, so the same bytes back every row sharing a
  digest. This is the cross-repo dedup hazard.
- **`oci_tags`** — `(repository_id, name, tag, manifest_digest, ...)`. The
  tag → manifest-digest mapping. Only the *tagged* (and, for multi-arch,
  the *index*) digest appears here.
- **`oci_manifest_refs`** — `(parent_digest, child_digest, repository_id)`.
  Records image-index → per-arch-child-manifest edges, written at PUT time
  by the v2 handler and backfilled at startup. Index `idx_oci_manifest_refs_child`
  supports the reverse lookup.
- **`artifacts`** — the manifest JSON bodies are tracked here as
  `oci-manifests/<digest>` storage keys; layers/config are **not** tracked
  in `artifacts`.

**Missing link.** There is no manifest → blob reference table. Nothing in
the schema says "manifest digest X references config/layer blob digest Y".
So today the only data the GC could use to judge a blob is
`(repository_id, digest)` from `oci_blobs` — which is exactly the data that
makes a per-repo orphan rule *wrong*.

### Why per-repo orphan classification is unsafe

Because `oci-blobs/<digest>` is global and deduplicated, classifying
orphan-ness per `(repository_id, digest)` and deleting the storage object
on the first orphan row breaks every surviving repo that still references
that digest. The out-of-band reconciler that ran a per-`(repo, digest)`
rule produced 57 broken blobs (1.73 GB) across 85 tags in three repos
(`konflux-step-images:task-runner-1.6.0-kub2`, `kub-coreos:2`,
`stream-coreos:4.20` all returned `BLOB_UNKNOWN`). **Any in-tree GC must
evaluate orphan-ness per digest, globally**, mirroring how
`ORPHAN_PREDICATE_SQL` already treats cloud backends as a shared keyspace.

## 3. Proposed GC subsystem

### 3.1 `manifest_blob_refs` table

```
manifest_blob_refs(
  manifest_digest TEXT NOT NULL,
  blob_digest     TEXT NOT NULL,
  repository_id   UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  kind            TEXT NOT NULL,   -- 'config' | 'layer'
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (manifest_digest, blob_digest, repository_id)
);
CREATE INDEX idx_manifest_blob_refs_blob ON manifest_blob_refs(blob_digest);
```

The reverse index on `blob_digest` is the hot path for the GC predicate
("is this blob referenced by any live manifest anywhere?"). Mirror the
existing `record_oci_manifest_refs` UNNEST batch-insert so a manifest with
N layers costs one round-trip.

Populate at push time inside `handle_put_manifest`, for **non-index**
manifests (image manifests carry `config.digest` + `layers[].digest`;
indexes carry no layers and are already covered by `oci_manifest_refs`).
Use `ON CONFLICT DO NOTHING` for idempotency.

### 3.2 Startup backfill

Mirror `oci_manifest_refs` backfill: on boot, walk every image manifest
reachable through `oci_tags` or `oci_manifest_refs.child_digest` that has
zero rows in `manifest_blob_refs`, load each body from per-repo storage,
parse `config` + `layers`, and insert edges. Idempotent on re-runs. This is
what makes GC safe for the existing ~403 GB that predates the table.

### 3.3 `run_blob_gc` — mark and sweep with global predicate

New source on `oci_blobs`:

```
-- candidate: blob with no live manifest reference, anywhere, and old enough
SELECT ob.digest, MAX(ob.size_bytes) AS size_bytes
FROM oci_blobs ob
WHERE ob.created_at < NOW() - make_interval(hours => $grace)
  AND NOT EXISTS (
    SELECT 1 FROM manifest_blob_refs mbr WHERE mbr.blob_digest = ob.digest
  )
GROUP BY ob.digest;
```

The predicate keys on `blob_digest` **globally** — never per repo. A digest
is reclaimable only when *no* manifest in *any* repo references it.

**Per-digest delete transaction** (mirrors the manifest GC TOCTOU
protection from #1180):

1. `BEGIN`.
2. `SELECT ... FROM oci_blobs WHERE digest = $1 FOR UPDATE` — lock every
   row for the digest.
3. Re-check the predicate under the lock (`NOT EXISTS manifest_blob_refs`
   and still older than grace). If a push landed a reference, `ROLLBACK`
   and skip.
4. **Delete from object storage first** is wrong here — see §3.5. Instead:
   delete the `oci_blobs` rows for the digest inside the tx, `COMMIT`, then
   delete `oci-blobs/<digest>` from storage. Bias to leaking over losing
   data.

### 3.4 Grace window

`oci_blobs.created_at` younger than the grace window (default 24h) is never
collected. A blob upload and its parent manifest push are **not**
transactionally bundled: during a `docker push` the blob rows exist before
the manifest that references them commits, so a fresh blob is legitimately
"unreferenced" for the duration of the client's push. The grace window
absorbs that without a global lock. Residual sub-second TOCTOU (a manifest
push landing mid-sweep for a blob older than grace) is closed fully by
having the push path `SELECT ... FOR UPDATE` the `oci_blobs` rows before
writing `manifest_blob_refs`; that can ship as a follow-up.

### 3.5 Ordering rule — bias to leaking, never to data loss

Storage backends are not inside Postgres' atomic boundary. The rule:
**commit the metadata transaction first, delete the object afterward.**

- If we crash after COMMIT but before the storage delete, we leak one
  object (recoverable: a later sweep with an "objects with no `oci_blobs`
  row" reconciler picks it up). Harmless.
- If we deleted storage first and then failed to commit, a surviving
  reference would point at a missing object → `BLOB_UNKNOWN` on pull. Data
  loss. Forbidden.

This is the inverse of the manifest GC (which deletes storage while holding
the row lock) because there the lock + `is_deleted` flag guarantee no live
reference; here the cross-repo dedup means we prefer the leak.

### 3.6 Single-leader execution across replicas

Two replicas must never sweep concurrently. Wrap each `run_blob_gc` pass in
a Postgres **advisory lock**:

```
SELECT pg_try_advisory_lock($BLOB_GC_LOCK_KEY);   -- e.g. hashtext('ak.blob_gc')
-- if false: another replica is sweeping; return early.
-- ... run sweep ...
SELECT pg_advisory_unlock($BLOB_GC_LOCK_KEY);
```

`pg_try_advisory_lock` is non-blocking and session-scoped; a crashed leader
releases it when its connection drops. The per-digest `FOR UPDATE` is the
inner correctness guarantee; the advisory lock is the outer
single-leader/throughput guarantee.

### 3.7 Dry-run, audit log, admin surface

- **Dry-run** computes the reclaimable set and reports digest count + bytes
  without deleting (same shape as the existing `StorageGcResult.dry_run`).
- **Audit log**: every real deletion writes a row `(blob_digest,
  size_bytes, repository_ids[], deleted_at, actor)` to a
  `blob_gc_audit` table so every reclamation is attributable and
  reversible-by-re-push.
- **Admin surface**: extend `POST /api/v1/admin/storage-gc` (admin-gated)
  and the scheduler; add the **read-only** `GET .../oci-blob-report`
  shipped in this PR for visibility ahead of deletion.

## 4. What ships in THIS PR (safe first slice)

A **read-only** OCI blob footprint report — no deletion, no locks, pure
aggregate `SELECT`s over `oci_blobs`:

- `GET /api/v1/admin/storage-gc/oci-blob-report?grace_hours=24` (admin only).
- `StorageGcService::oci_blob_footprint_report(grace_hours)` returning
  `OciBlobFootprintReport`: `total_blob_rows`, `distinct_digests`,
  `logical_bytes` (sum over all rows, double-counts dedup),
  `physical_bytes` (distinct-digest sum ≈ bytes on disk),
  `aged_distinct_digests` / `aged_physical_bytes` (older than the grace
  window), and a per-repository breakdown.

It deliberately does **not** emit a "reclaimable orphans" number. That
number is impossible to compute correctly until `manifest_blob_refs`
exists; a per-`(repo, digest)` heuristic would reproduce the exact bug that
broke 57 blobs in production. The report gives operators immediate
visibility into the ~403 GB (the `physical_bytes` figure maps directly to
the bucket observation) with zero deletion risk.

## 5. Why deletion is not in this PR

Actual blob reclamation depends on three pieces that need human design
review and their own migrations/PRs:

1. `manifest_blob_refs` table + push-path write + startup backfill — without
   it, GC has no safe global reference signal.
2. The global (not per-repo) sweep predicate, advisory-lock leadership, and
   commit-then-delete ordering.
3. The `blob_gc_audit` table and dry-run/report parity.

Shipping any deletion path before (1) lands would either delete in-use
blobs or delete nothing. **Recommended next step:** land
`manifest_blob_refs` (table + synchronous push-path writer + idempotent
startup backfill) as its own reviewed PR, verify the backfill reconstructs
references for the existing corpus, *then* add `run_blob_gc` behind dry-run
with the advisory lock and audit table.
