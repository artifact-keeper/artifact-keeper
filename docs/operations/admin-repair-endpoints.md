# Admin repair endpoints: storage reindex and Debian backfill

Two admin endpoints repair a repository whose `artifacts` rows have drifted
from what its storage holds:

| Endpoint | Repairs | Repositories |
| --- | --- | --- |
| `POST /api/v1/admin/repositories/{key}/reindex-storage` | Objects in storage with no `artifacts` row ("ghost artifacts", #1570), and reports rows whose object is gone. | Maven and Gradle |
| `POST /api/v1/admin/repositories/{key}/backfill-debian` | `.deb` rows with no Debian control document, so `Packages` and the UI do not list them (#4740). | Hosted Debian |

Both share these rules:

- **Admin only.** They sit in the `/api/v1/admin` block, so a caller that is
  not an administrator gets `403`; the handler checks `is_admin` again.
- **`dry_run` is required.** A body without it, or with an unknown field, is
  refused with `422` before anything runs. A dry run reports what a real run
  would do and writes nothing.
- **One run per repository at a time.** Each takes a per-repository Postgres
  advisory lock; a second call for the same repository while one runs gets
  `409`. Different repositories can run in parallel.
- **Bounded per call.** `limit` defaults to `1000` and is clamped to
  `1..=10000`. A call that stops at the limit says `truncated: true`; call
  again to continue (see [Paging](#paging)).
- **Safe on a live repository and idempotent.** Neither overwrites an existing
  row or takes a table lock, and a second run over a repaired repository does
  nothing.
- **Audited before the work starts.** Each call writes a `phase: "started"`
  audit row before it touches any row or object, then a second row when it
  returns: `completed` with the report counts, or `failed` with the `error`
  for refusals (`404` unknown key, `409`, `422`) and failures. A call dropped
  mid-run (request timeout, client disconnect) records `cancelled` instead.
  `failed` and `cancelled` carry outcome `failure`. The action is
  `STORAGE_REINDEX_RUN` or `DEBIAN_BACKFILL_RUN`; every row carries
  `repository`, `dry_run`, `limit` (and `after` for the backfill), plus a
  `run_id` shared by the rows of one call.
- **Answered inside the request timeout.** These are ordinary requests, so
  `GLOBAL_REQUEST_TIMEOUT_SECS` (120 s by default) applies. A call cut off by
  the timeout answers `503` and is audited as `cancelled`; the rows it
  already wrote stay (each is its own statement or transaction) and the lock
  is released, so the next call carries on. Lower `limit` if a call comes
  near the timeout.

## Storage reindex (Maven, Gradle)

**When to run it.** After an upload or delete failed between writing the
object and writing its row, or after copying objects into a repository's
storage by hand. The symptom is a file that a derived read (a Maven
`maven-metadata.xml`, a directory listing of storage) shows but the
repository's artifact list and the artifact API do not.

**What it reads and writes.** It lists every object under the repository's own
key prefix (`maven/` under a filesystem repository root, or
`maven/{repository_id}/` on a shared cloud bucket) and the repository's
`artifacts` rows. For each object that is a Maven coordinate and has no row
(live or soft-deleted) at its path, it hashes the object while streaming it and
inserts a row with its real size, SHA-256, SHA-1 and MD5, the coordinate
metadata (marked `reindexedFromStorage: true`) and the calling admin as
uploader. It never changes or deletes a row or an object.

It leaves alone:

- row-less Maven files (checksum sidecars, `maven-metadata.xml`) and paths that
  are not Maven coordinates;
- a path with any row, live or soft-deleted: a soft-deleted row's object
  belongs to [storage GC](storage-gc.md) and is not resurrected;
- an object modified in the last 5 minutes, whose upload may still be writing
  its row (`skipped_recent`), and an object whose listing gave no modification
  time (`skipped_unknown_age`).

It answers `422` for a format other than Maven or Gradle, for a storage
backend that cannot list objects, and for a repository that writes legacy flat
keys shared by every repository (`STORAGE_KEY_SCHEME=flat` on a cloud
backend), since those objects cannot be attributed to one repository.

Request:

```json
{ "dry_run": true, "limit": 1000 }
```

Report:

| Field | Meaning |
| --- | --- |
| `dry_run` | Echo of the request. |
| `scanned` | Objects listed under the repository's prefix. |
| `registered` | Rows created (on a dry run, that would be created). |
| `skipped` | Objects left alone: already registered, row-less files, not a coordinate, owned by a soft-deleted row, or registered by a concurrent upload first. |
| `skipped_recent` | Unregistered objects modified within the last 5 minutes. |
| `skipped_unknown_age` | Unregistered objects with no modification time in the listing. |
| `missing_objects` | Live rows under the prefix whose object is missing. Reported only; nothing is changed. |
| `truncated` | `true` when `limit` stopped registration with ghosts left. |
| `registered_paths` | Up to 100 registered paths. |
| `missing_object_paths` | Up to 100 paths of rows whose object is missing. |
| `errors` | Up to 100 per-object failures (`path: reason`); the rest of the run carries on. |

`missing_objects` is the other half of the drift: rows that point at nothing.
The reindex cannot repair those; restore the objects from a backup, or delete
the rows.

## Debian backfill (hosted Debian)

**When to run it.** On a hosted Debian repository imported by the migration
job before 1.12.0 (#4657), whose packages are stored but missing from
`Packages` and the repository UI. Re-running the migration also repairs it,
but needs the source system; the backfill works from the repository's own
storage.

**What it reads and writes.** Candidates are live `.deb`, `.udeb` and `.ddeb`
rows outside `dists/` that have no Debian control document. For each, it
reads the package's `control.tar` member from storage with ranged reads (a
multi-GiB package costs a few bounded reads, not a full download) and records
what a native upload records: the control document, the package catalog row
and the maintainer-script analysis.

It also files each package under the component the migration importer now
picks: the path's own `pool/<component>/` segment, else `main` (for
`pool/<file>.deb`, a `pool/<letter>/<name>/` layout from Nexus or an Ubuntu
pool mirror, or any other path). A row outside its component is moved to
`pool/<component>/...`; the storage key, and so the bytes, stay where they are.
When the destination path is already taken:

| At the destination | Result |
| --- | --- |
| Nothing | The row moves. |
| A live row with the same SHA-256 | That row keeps the package and gets the control document; the misfiled row is soft-deleted. |
| A live row with different bytes (another package) | Reported in `errors` and counted in `artifacts_failed`; neither row changes. |
| A soft-deleted row | Reported and counted the same way. Purge it from the trash, then run the backfill again. |

Last, it soft-deletes the live `dists/` rows the migration imported (rows
whose origin is `migration`): those are the source's own signed indices, and
Artifact Keeper renders and signs its own. A file uploaded under `dists/` by
other means is left alone. This step runs on every call, truncated or not.

A package whose stored bytes cannot be read, or whose control file disagrees
with its file name, is reported in `errors` and skipped. It stays a candidate
for the next run.

It answers `422` for a repository that is not Debian or is not hosted (a
Remote caches upstream bytes and a Virtual has no rows of its own).

Request:

```json
{ "dry_run": true, "limit": 1000, "after": null }
```

Report:

| Field | Meaning |
| --- | --- |
| `dry_run` | Echo of the request. |
| `artifacts_scanned` | Candidates examined in this call. |
| `packages_registered` | Control documents written (on a dry run, that would be written). |
| `packages_relocated` | Of those, packages moved under `pool/<component>/`. Included in `packages_registered`. |
| `artifacts_skipped` | Candidates that are not Debian package paths. |
| `artifacts_failed` | Packages whose bytes or control file could not be used, or whose destination is taken (see the table above). |
| `dists_removed` | Migration-origin `dists/` rows soft-deleted (on a dry run, that would be). Counts the whole repository, not one page. |
| `truncated` | `true` when `limit` stopped the walk with candidates left. |
| `next_after` | When `truncated`, the cursor to send as `after` on the next call. |
| `registered_paths` | Up to 100 registered paths, each the path the package is filed under. |
| `errors` | Up to 100 per-package failures (`path: reason`). |

A dry run does not check the destination of a move, so a package whose
destination is taken is counted in `packages_registered` and
`packages_relocated` by the dry run and in `artifacts_failed` by the real run.

## Paging

**Debian backfill.** The walk goes through candidates in row id order. A
truncated call returns `next_after`; send it as `after` to continue past the
packages already examined, including the ones that failed, so a set of
packages that keeps failing never holds back the rest. Without `after`, a call
starts from the first candidate again: registered packages are no longer
candidates, but failed ones are.

```sh
AK=https://registry.example.com
REPO=debian-hosted
after=null
while :; do
  body=$(jq -nc --argjson after "$after" '{dry_run: false, limit: 1000, after: $after}')
  resp=$(curl -fsS -X POST "$AK/api/v1/admin/repositories/$REPO/backfill-debian" \
    -H "Authorization: Bearer $AK_TOKEN" -H 'Content-Type: application/json' \
    -d "$body")
  echo "$resp" | jq -c '{artifacts_scanned, packages_registered, artifacts_failed, truncated}'
  echo "$resp" | jq -r '.errors[]'
  [ "$(echo "$resp" | jq -r .truncated)" = true ] || break
  after=$(echo "$resp" | jq -c .next_after)
done
```

Run it once with `dry_run: true` first to see the counts. A dry run writes
nothing, so its candidates do not shrink, but `next_after` still advances, so
the same loop pages through the whole repository.

**Storage reindex.** There is no cursor. Each call lists the whole prefix and
registers up to `limit` ghosts; the next call finds them registered and moves
on to the rest. Repeat while `truncated` is `true`:

```sh
while :; do
  resp=$(curl -fsS -X POST "$AK/api/v1/admin/repositories/$REPO/reindex-storage" \
    -H "Authorization: Bearer $AK_TOKEN" -H 'Content-Type: application/json' \
    -d '{"dry_run": false, "limit": 1000}')
  echo "$resp" | jq -c '{scanned, registered, skipped_recent, missing_objects, truncated}'
  [ "$(echo "$resp" | jq -r .truncated)" = true ] || break
done
```

A truncated dry run does not advance: it reports the same first `limit` ghosts
each time. To size the work, run one dry run with `"limit": 10000`. Objects
that fail to register (see `errors`) do not count towards `limit`, so they do
not keep a call truncated; they are retried by the next call.

## Large repositories

Every reindex call lists all objects under the repository's prefix and reads
all of its `artifacts` paths, whatever `limit` is, so its cost grows with the
repository rather than the page.

The backfill pages candidates by row id inside one repository (`WHERE
repository_id = ... AND id > after ORDER BY id`, 500 at a time, joined
against the Debian metadata rows). No index on `artifacts` matches that order
today; the closest is `(repository_id, path)`. On a very large repository,
time a call (or `EXPLAIN ANALYZE` the candidate query) before reaching for an
index on `artifacts (repository_id, id)`, and if the measurements show one is
needed, file an issue so it ships as a migration rather than as a local
change.

## Related

- [Storage scrub](download-integrity.md) (`POST /api/v1/admin/storage-scrub`)
  re-hashes stored objects and repairs a corrupt or missing one from a verified
  copy of the same digest.
- [Storage GC](storage-gc.md) reclaims objects whose rows are all soft-deleted,
  including the misfiled Debian rows and `dists/` rows the backfill retires.
