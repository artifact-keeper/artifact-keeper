# Migrating a date window (incremental migrations)

A migration job can be limited to the artifacts modified inside a window with
`date_from` and `date_to` in its `config`. Both are optional RFC 3339
timestamps. The window works the same way for an Artifactory and a Nexus
source.

```bash
curl -X POST https://registry.example.com/api/v1/migrations \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "source_connection_id": "'"$CONNECTION_ID"'",
        "job_type": "incremental",
        "config": {
          "include_repos": ["libs-release"],
          "conflict_resolution": "skip",
          "date_from": "2026-11-01T00:00:00Z",
          "date_to":   "2026-11-08T00:00:00Z"
        }
      }'
```

## Both bounds are exclusive

An artifact is migrated when its last-modified time is **strictly after**
`date_from` and **strictly before** `date_to`:

| Source      | `date_from`              | `date_to`                |
|-------------|--------------------------|--------------------------|
| Artifactory | AQL `"modified": {"$gt"}` | AQL `"modified": {"$lt"}` |
| Nexus       | `lastModified > date_from` | `lastModified < date_to` |

An artifact modified exactly at a bound is in neither window that shares it.
If you chain incremental runs by reusing one run's `date_to` as the next run's
`date_from`, an artifact modified at exactly that instant is skipped by both
runs. With millisecond timestamps this is unlikely, but it can happen (#6260).

**Overlap consecutive windows instead.** Start each window a little before the
previous one ended, for example a minute or an hour:

```text
run 1: date_from = 2026-11-01T00:00:00Z   date_to = 2026-11-08T00:00:00Z
run 2: date_from = 2026-11-07T23:59:00Z   date_to = 2026-11-15T00:00:00Z
```

With `conflict_resolution: skip` (the default) the overlap is free: an artifact
the earlier run already migrated, with a matching checksum, is counted as
skipped and not transferred again.

An artifact with no last-modified time on a Nexus source is always listed: the
window cannot rule it out, so it is left to the duplicate check.

## How a Nexus source applies the window

Nexus has no server-side date filter on its listing API, so Artifact Keeper
walks the repository's `/components` (and, for raw and Maven repositories,
`/assets`) pages and keeps only the rows inside the window. With a narrow
window over a large repository most pages hold nothing to migrate.

One listing call fetches at most 50 upstream pages and then returns what it
has, even an empty page, and the job carries on from where it stopped (#6260).
Between calls the job checks for a pause or cancel, so both take effect within
one budget of pages instead of after the whole repository has been walked.
`MIGRATION_NEXUS_LIST_PAGE_BUDGET` changes the number of pages; `0` or an
invalid value keeps the default.

The pre-migration assessment counts a Nexus repository with its own walk: up
to 200 `/components` pages and, for raw and Maven repositories, up to 400
`/assets` pages. The count is exact when the repository has at most 2,000
components and, for raw and Maven repositories, at most 4,000 assets in its
asset listing (component files, files without a component and Maven metadata
together). Otherwise it is reported as not exact: normally a lower bound, though for a
repository past the 1,000,000-path dedupe cap it can be too high. The migration
job publishes the real total as it lists.
