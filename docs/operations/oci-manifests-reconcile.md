# OCI manifest existence table: reconcile and readers

`oci_manifests` records each OCI manifest a repository holds, independent of
its tags (#1683, first slice #4433). Every push, proxy cache fill and
migration import writes its row in the same transaction as the tag, and a
delete by digest or a delete of the last tag removes it (#4449).

Since 1.12.0 the table is also what the registry reads (#1683, third slice):

- **Manifest GET, HEAD and DELETE by digest** on a hosted (local or staging)
  repository resolve through the repository's row, scoped to the requested
  image name. A tag of the image always resolves. Without one, the row
  resolves unless the digest was deleted under that image name (every
  manifest row of the image for those bytes is in the trash, #4525), with one
  exception: a manifest whose rows went to the trash only through tag
  deletes still resolves while an index that references it is live under the
  image, so the untagged child of a tagged index keeps pulling. A tagged
  manifest with no row yet is served from its tag and counted in
  `ak_oci_manifest_reads_without_row_total`; the read does not write the row,
  the next reconcile adds it. 1.11 writes the row in the same transaction as
  the tag, so this only happens for a manifest committed before 1.11 whose
  row the backfill could not add (its body unreadable or not matching its
  digest, counted in `ak_oci_manifests_reconcile_failures_total`), or while a
  replica older than 1.11 still takes pushes. A Virtual repository resolves a
  hosted member's digest through the member's row first.
- **The referrers API** lists a referrer while the repository records the
  referrer itself; a referrer that was deleted, or whose row the reconcile
  removed, is not listed. The listing follows the referrer, not the subject:
  the distribution spec lists every manifest whose `subject` names the digest
  and lets referrers be pushed before their subject, so a referrer is listed
  whether its subject was never pushed, was deleted, or was deleted and pushed
  again. Deleting a subject does not delete its signatures or SBOMs; delete
  them by digest when they should go too.
- **Storage GC** keeps an `oci-manifests/<digest>` object while any repository
  on its backend records the digest, in the orphan-key sweep, the recorded
  candidate sweep and the pre-delete re-check. The tag and tagged-index-edge
  arms it used before stay as a guard for a manifest not recorded yet. The
  blob-ref prune keeps the `manifest_blob_refs` of a child whose index is
  still recorded (so pulling the index never fails on the child's layers),
  and when it prunes the refs of a manifest it retires the manifest's row in
  the same run if nothing else keeps it.

Since 1.12.0 a hosted repository also scopes manifest and blob digests to the
image name that holds them, through per-image links the reconcile backfills;
see [OCI digests scoped to the image name](oci-image-scope.md) (#5793).

The #1681 content-addressable fallback, which inferred that a repository owned
a digest from its `manifest_blob_refs` and `oci_manifest_refs` rows, is gone:
the row is that proof now. Like those rows it is per repository, which is what
stops one repository from serving another's manifest by digest on a shared
cloud backend.

## Why a reconcile

Some changes reach the reference tables without passing through the writers
that keep `oci_manifests` exact:

- a 1.11.x replica serving pushes or deletes during a rolling upgrade (a
  pre-268 replica writes no row at all);
- the lifecycle tag prune, which removes the tags of expired images;
- the startup orphan-tag reconciliation of migrated repositories.

Without a repair, the table would claim manifests that answer 404 by digest,
or miss manifests that serve fine.

## What it does

Each pass, under a cluster-wide advisory lock (one replica at a time):

1. **Adds** a row for every manifest that is tagged, is a locally stored child
   of an index, or is proven by its own edge rows (an image manifest's
   `manifest_blob_refs` or an index's `oci_manifest_refs` parent rows, written
   at push time and kept across a tag overwrite), and has no row. Not for a
   manifest whose manifest-shaped `artifacts` rows are all in the trash. The
   body is read from storage and its digest verified first, exactly as the
   startup backfill does.
2. **Removes** a row when the manifest is no longer addressable:
   - no tag points at it;
   - no index edge names it as a child while that index is tagged, has a live
     `artifacts` row, or still has its own row (so the leaf of an index of
     indexes and the child of a migrated index kept only by checksum keep
     theirs);
   - no live `artifacts` row in its repository stores it (by
     `oci-manifests/<digest>` key or, for an older migrated manifest, by
     checksum); and
   - its own edge rows (above) are gone, or every manifest-shaped `artifacts`
     row of the digest is in the trash.

   Rows touched in the last 10 minutes are left alone. Each removal re-checks
   the condition under the row's lock, so a push that re-tags the digest in
   between keeps its row. A pass sweeps again while the previous sweep removed
   something (a removed index can leave its children stale), up to eight
   sweeps.

Removing a row deletes no storage object itself: storage GC reclaims the bytes
on its next run once nothing records the manifest.

## Rolling upgrade from 1.11

A 1.11 replica still derives existence from tags: it serves a digest that a
tag of the image points at, or that the repository's edge rows prove it
pushed and that was not deleted under the image. 1.11 writes and removes
`oci_manifests` rows itself (the dual write since 1.11.0), but has no
reconcile. In a mixed fleet:

| Manifest | 1.11 replica | 1.12 replica |
|---|---|---|
| Tagged | 200 | 200 |
| Last tag deleted | 404 | 404 |
| Tag moved to another digest (old digest, refs not yet pruned by GC) | 200 | 200 (row kept by its refs) |
| Same, after a GC run pruned its refs | 404 | 404 (row retired in that GC run) |
| Expired by a lifecycle policy | 404 | 404 (per-image trash check; row removed by the next reconcile) |
| Untagged child of a tagged index, its own tag deleted | 404 | 200 |
| Child of a tagged index, deleted by digest | 404 | 404 (its row is removed by the delete; the index's edge stays) |
| Child of an untagged index that still pulls by digest | 404 once its own tag was deleted, and a 1.11 GC run may reclaim its object and layers | 200, kept by GC |
| Tagged, no row yet (a pre-1.11 manifest the backfill could not record) | 200 | 200 (served from the tag until the reconcile adds the row) |

The reconcile never removes a row a 1.11 replica has just written: the 1.11
push writes the row and its tag in one transaction and refreshes
`last_referenced_at`, and rows younger than 10 minutes are skipped. Every
removal it does make is of a manifest a 1.11 replica already answers 404 for.

Storage GC is a singleton across replicas, so during the upgrade a 1.11
replica may win a scheduled GC run. A 1.11 GC run uses the old predicate and
can reclaim the child of an untagged index (the "child of an untagged index"
row above): its manifest object once the child's trashed `artifacts` rows
pass `GC_TRASH_RETENTION_DAYS`, and its layers once a live blob pass
(`BLOB_GC_ENABLED=true`) prunes the child's blob refs. There is no switch that
turns the scheduled GC off on one replica, so while 1.11 replicas run:

- leave `BLOB_GC_ENABLED` unset on the 1.11 replicas (the default: the blob
  pass dry-runs and prunes no blob refs);
- set `GC_TRASH_RETENTION_DAYS` on the 1.11 replicas to more days than the
  rollout takes (the shipped default `0` reaps trashed rows on the next run);
- do not call the admin storage-GC endpoints on a 1.11 replica.

A delete served by a 1.11 replica also still runs the 1.11 unwind: deleting
the last tag of an index that a tagged index of indexes references drops the
middle index's child edges, so its children lose their rows at the next
reconcile and their blob protection. Avoid deleting nested index tags until
the rollout is finished.

## Schedule

The pass runs at startup (it includes the backfill that used to run alone)
and then every `OCI_MANIFESTS_RECONCILE_INTERVAL_SECS` seconds, default 21600
(6 hours). `0` keeps only the startup pass. The value is read once at
startup, so changing it takes a restart. Every replica runs its own timer; a
pass that finds another replica holding the lock is skipped, not queued.

The removal scan walks `oci_manifests` in primary-key order and answers each
row with index lookups on `oci_tags`, `oci_manifest_refs`,
`manifest_blob_refs`, `oci_manifests` and `artifacts`, so its cost grows with
the table, not with `artifacts`.

## Metrics

| Metric | Type | Meaning |
|---|---|---|
| `ak_oci_manifests_reconcile_rows_added_total` | counter | Rows added for manifests that had none. |
| `ak_oci_manifests_reconcile_rows_removed_total` | counter | Rows removed for manifests that are no longer addressable, by the reconcile or by the GC's blob-ref prune. |
| `ak_oci_manifests_reconcile_failures_total` | counter | Candidates that could not be added (unreadable or mismatching body) or rows that could not be removed. Retried next pass. |
| `ak_oci_manifest_reads_without_row_total` | counter | Digest reads on a hosted repository served from a tag because the manifest has no row yet. |

A healthy instance settles at zero additions per pass once the upgrade is
complete, and `ak_oci_manifest_reads_without_row_total` stays flat. Removals
follow deletes and lifecycle expiries. Steady failures point at manifest
bodies missing from storage.
