# Download statistics retention

Every served download writes one row: hosted serves to `download_statistics`,
proxy (Remote) serves to `proxy_download_statistics`. Since 1.11.0 proxy
history is kept when a cache entry is evicted (#4540), so neither table
shrinks except when its repository is deleted. On a busy instance they grow
without bound (#4541).

## Turning it on

| Variable | Default | Meaning |
|---|---|---|
| `DOWNLOAD_STATS_RETENTION_DAYS` | unset (off) | Delete statistics rows whose `downloaded_at` is older than this many days. Zero, negative or not a number also means off; a value above 365000 is lowered to it. |
| `DOWNLOAD_STATS_RETENTION_INTERVAL_SECS` | `3600` | How often the pass runs (at least 10 seconds). |

With a period set, a scheduler pass trims both tables every interval. It runs
on one replica at a time (scheduler lease `download_stats_retention`, renewed
while the pass runs) and deletes in batches of 5000 rows, one short statement
each, so a large backlog is worked off without a long transaction or table
lock. Batches find their rows through an index on `downloaded_at` on each
table, so a pass costs what it deletes, not the size of the table: a pass with
nothing to delete reads a few index pages, plus the index entries of rows
already deleted that vacuum has not removed yet. Each pass logs one `Download statistics retention pass` line with
the rows it deleted from each table; the period in force is logged at startup.

Nothing is deleted unless you set a period: the default keeps today's
behaviour.

## What the period costs

Every figure computed from these rows forgets downloads older than the period:

- per-artifact and per-path download counts, the download trend and the
  most-downloaded views, the downloader and by-IP lists;
- the `no_downloads_days` lifecycle policy: a download older than the period
  no longer protects its artifact or cache entry. Keep the period longer than
  the longest `no_downloads_days` window you use, and it makes no difference;
- the security blast-radius report: a pull older than the period is no longer
  attributed to the digest it served.

Choose a period at least as long as the longest analytics window, lifecycle
window and incident look-back you rely on. Daily `storage_metrics` snapshots
already taken are not changed.

## Proxy pulls keep their digest

Since 1.12.0 each `proxy_download_statistics` row also records the
`checksum_sha256` that was served (#4542). The admin blast-radius report
(`GET /api/v1/admin/security/cve/{cve_id}/blast-radius`) attributes proxy pulls by that
digest, so they stay attributed after the cache entry is evicted or purged.
Rows recorded before the upgrade have no digest and are attributed through
their cache entry for as long as it exists, as before.
