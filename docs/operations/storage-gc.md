# Storage garbage collection: budgets, deletes and metrics

Storage GC reclaims objects that nothing references any more: storage keys whose
`artifacts` rows are all soft-deleted (and past `GC_TRASH_RETENTION_DAYS`), OCI
blobs that blob GC marked and that stayed unreferenced, objects a repository
delete left behind (`oci_gc_candidates`), abandoned OCI upload sessions and,
when `MAVEN_FLAT_GC_ENABLED` is set, orphaned row-less Maven objects. It runs
on `GC_SCHEDULE` (one replica per tick, through the `storage_gc` scheduler
lease) and on demand through `POST /api/v1/admin/storage-gc` and the
per-repository endpoint.

## How a delete runs

Since 1.12.0 (#2524) every sweep reclaims an object in two steps, so no database
transaction, row lock or pooled connection is held while the object store
answers:

1. **Claim.** A short transaction re-checks the candidate under its row lock,
   removes the rows that made it a candidate (the soft-deleted `artifacts`
   rows, the marked `oci_blobs` row, the attribution row, the abandoned upload
   session) and writes a durable record of the delete in flight. For artifact
   keys, recorded candidates and Maven objects that record is an
   `oci_gc_candidates` row stamped with the current time. For OCI blobs it is
   a tombstoned `oci_upload_cleanup_keys` row under a 15-minute claim, which
   the push path honours: a push of that digest while the delete is in flight
   is answered `503 BLOB_UPLOAD_INVALID` ("retry the upload") instead of
   committing a row for bytes that are being deleted. Docker, containerd and
   other OCI clients retry it. The transaction commits.
2. **Delete.** With nothing held, GC re-checks the key against every
   reference table, deletes the object (an already-absent object counts as
   deleted), and removes the record. Up to `STORAGE_GC_DELETE_CONCURRENCY`
   deletes run at once.

If a delete fails, or the process stops between the two steps, the record
stays. An `oci_gc_candidates` row is retried by the candidate sweep once it is
older than `BLOB_GC_MIN_AGE_SECS` (24 hours by default), with the same
reference re-check. A blob tombstone's claim is released (or lapses after 15
minutes) and the unreferenced cleanup-key sweep retries it. The rows removed in
step 1 are not restored: an object can be left on storage for a while, but a
row never points at an object that is gone.

A key that gained a reference between the two steps (for example a re-upload
of the same content into another repository) is kept, and its record is
dropped. That is counted in `ak_storage_gc_deletes_skipped_live_total`.

Uploads honour the same record (#4980). An upload whose content is already
stored skips the write, and one that writes does so before its row commits, so
a GC delete could otherwise land between the upload's write (or its check that
the object exists) and its commit, leaving a live row without its object. The
transaction that commits an upload's row (generic, native and chunked uploads
that go through the shared upload service or the chunked completion) therefore
first takes the key's `oci_gc_candidates` slot and checks that the object is
stored:

- While GC holds the record as a lease for a delete it is running (it took
  the record in the last 15 minutes; the `leased_at` column, migration 302),
  the delete may still land, so the upload waits for it for up to 5 seconds.
  GC deletes right after its claim, so the wait normally ends quickly. A
  record a repository delete wrote, which only waits out
  `BLOB_GC_MIN_AGE_SECS`, is not a lease and does not hold uploads up.
- If the object is gone, the upload writes it again from the bytes it still
  holds (the request body, its staged copy, or a body the deduplication left
  unread) and re-checks. An upload that streamed its body straight to the
  final key no longer holds it and answers `503` instead. A chunked completion
  releases its lease and answers `503`; retrying the completion writes the
  object again from the staged chunks.
- A GC delete that fails clears its own lease, so it does not hold uploads up.
  The record stays for the candidate sweep, which re-checks it and keeps an
  object an upload has committed since.
- If the lease outlives the wait, which happens when a GC process stopped
  between its claim and its delete less than 15 minutes ago, the upload is
  answered `503 SERVICE_UNAVAILABLE` ("retry the upload") and commits nothing.
  A retry after the lease ages out succeeds; the candidate sweep later
  re-checks the record and keeps the object.

A repository delete hands its objects to the same record and re-checks
references before each delete (#4311): every storage key the deleted
repository's rows named is recorded in `oci_gc_candidates` (with the
repository as `source_repository_id`, so it reads as a waiting candidate, not a
lease), and the delete job then takes each key's slot as a lease, checks
whether any other repository on the same storage still references the key, and
deletes the object only if none does. An upload of identical content into
another repository that committed before that check keeps the object; one that
reaches its commit while the lease is fresh waits for the delete to finish and
writes its bytes again. A key the job keeps, or fails to delete, stays recorded
for the candidate sweep. See `docs/operations/repository-delete.md`.

The slot is held only for the commit and a HEAD of the object, never across a
write. Uploads of identical content take the same slot, so their commits run
one after another (each waiting on a database connection meanwhile). Format handlers that write their own content-addressed rows outside the
shared upload service are not covered yet.

That re-check consults every reference table, which is wider than the
soft-deleted-key scan alone. In particular an object that an `artifact_versions`
row still names is kept: when the newest revision of an artifact in a
versioning-enabled repository is trashed and its retention passes, the
`artifacts` row is removed but the revision's bytes stay, as older revisions'
bytes always have, until the repository itself is deleted. Before 1.12.0 GC
deleted that object and left the revision pointing at nothing.

## Per-run budgets

A large deletion wave (a lifecycle policy that expires millions of artifacts, a
repository delete) can otherwise turn one GC pass into hours of object-store
traffic. Budgets cap a pass. All default to `0`, which means unlimited and keeps
the previous behaviour.

| Variable | Caps | Notes |
|---|---|---|
| `STORAGE_GC_MAX_KEYS_PER_RUN` | storage keys claimed per pass | Counted across every sweep of the pass. Blob GC's sweep phase has its own pass with the same budget. |
| `STORAGE_GC_MAX_BYTES_PER_RUN` | bytes claimed per pass | The key that crosses the budget is still reclaimed, so a pass can overshoot by one object. |
| `STORAGE_GC_MAX_RUN_SECS` | wall-clock seconds per pass | Checked before each claim; a pass ends at most one delete chunk (64 deletes) after the limit. |
| `STORAGE_GC_DELETE_CONCURRENCY` | storage deletes in flight | Default 4, clamped to 1 to 64. |

A pass that spends a budget stops claiming new work and reports it in the GC
result as `"budget_exhausted": "keys"` (or `"bytes"`, `"time"`). The next pass
starts again from the remaining candidates, so an hourly `GC_SCHEDULE` with
`STORAGE_GC_MAX_KEYS_PER_RUN=10000` reclaims at most 10,000 keys an hour and
works through a backlog over several ticks. A dry run applies the same budget,
so its numbers predict what one live pass would reclaim.

Blob GC's mark phase is never budgeted: it performs no storage I/O and must
keep up with the orphan set.

The two OCI upload cleanup-key sweeps (unreferenced and pending journal rows)
are not charged to the budget either. They already delete outside a
transaction and keep their own cap of 1,000 rows each per pass.

## Metrics

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `ak_storage_gc_objects_deleted_total` | counter | `sweep` | Objects deleted by GC. |
| `ak_storage_gc_bytes_freed_total` | counter | `sweep` | Bytes freed, where the sweep knows the size. |
| `ak_storage_gc_delete_failures_total` | counter | `sweep` | Deletes that failed and were left for a retry. |
| `ak_storage_gc_deletes_skipped_live_total` | counter | `sweep` | Claimed keys found referenced again just before the delete, and kept. |
| `ak_storage_gc_budget_stops_total` | counter | `budget` | Passes that stopped on a budget (`keys`, `bytes`, `time`). |
| `ak_storage_gc_journal_rows` | gauge | | `oci_gc_candidates` rows waiting for a sweep, including failed deletes waiting to be retried. |
| `ak_storage_gc_journal_oldest_age_seconds` | gauge | | Age of the oldest of those rows. |

`sweep` is one of `orphan_keys`, `blobs`, `oci_candidates`, `maven_flat`,
`abandoned_uploads`. A journal backlog that keeps growing while
`ak_storage_gc_delete_failures_total` rises points at the storage backend; one
that grows while failures stay flat means a budget is too small for the
deletion rate.

## Rolling upgrades

The change needs no migration. A 1.11.x replica that runs a GC tick against the
same database keeps its old in-transaction deletes and ignores nothing it needs:
it treats the new `oci_gc_candidates` rows like the ones repository deletes
write, after the same grace window, and its push path already refuses a digest
under a live blob tombstone.
