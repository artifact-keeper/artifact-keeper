# Keeping source dates on a migration

By default a migration writes every artifact with the import time as its creation date and with no download history, so every migrated artifact looks brand new and never downloaded. Set `import_source_timestamps` in the job's `config` to keep the source's dates instead. It is off by default and applies to that one job.

```bash
curl -X POST https://registry.example.com/api/v1/migrations \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "source_connection_id": "'"$CONNECTION_ID"'",
        "job_type": "full",
        "config": {
          "include_repos": ["libs-release"],
          "import_source_timestamps": true
        }
      }'
```

**Review your lifecycle policies before the first lifecycle run after the cutover.** Without the flag, every migrated artifact is protected by looking new. With it, old artifacts and artifacts not downloaded for a long time in the source become eligible for `max_age` and `no_downloads_days` policies straight away.

## What is imported

| Destination | Nexus source | Artifactory source |
|---|---|---|
| `created_at` | the earlier of `blobCreated` and `lastModified` | AQL `created` |
| last download | `lastDownloaded`, as one marker row | not imported |
| `updated_at` | not imported, stays the import time | not imported |

Nexus emits `blobCreated` twice per asset on some versions. The earliest non-null value is used. The Nexus UI shows "Blob created" as the earlier of the two dates to work around NEXUS-31391, and the import applies the same rule.

Every imported date is capped at the current time, so a source with a skewed clock cannot date an artifact in the future. A missing or unparseable date keeps the import time.

`updated_at` stays "last changed in this instance": incremental backups and peer sync use it as a change cursor, and a date in the past would leave migrated artifacts out of the next incremental backup.

OCI images keep the import time.

## The last-download marker row

Nexus has a last-download date but no download count. The import keeps it as one row in the download history with no user and no IP address, and the user agent `artifact-keeper-migration/nexus (lastDownloaded)`. Stats, analytics and lifecycle read the last download from that history, so they pick it up without any other change.

Side effects:

- A migrated artifact with a source last download has a download count of one instead of zero
- The rows show up as anonymous downloads in the admin download views and in download trends, on their historical date. The user agent tells them apart
- The CVE blast radius reports an anonymous download for these artifacts. The exposure in the source was real, only the actor is unknown
- With `DOWNLOAD_STATS_RETENTION_DAYS` set, retention deletes old marker rows like any other old download

## Delta runs

Running the job again before the cutover refreshes the dates of artifacts it skips as already migrated: the marker row moves forward to a newer source last download (never a second row) and `created_at` can only move earlier. Only artifacts the migration wrote are touched, an artifact uploaded natively with the same checksum keeps its dates. A re-run with the flag also fills in the dates of artifacts migrated without it.
