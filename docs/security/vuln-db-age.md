# Vulnerability database age

A scan is only as current as the vulnerability database it ran against. Every
scan row records that database (`vuln_db_version`, `vuln_db_published_at`).
Artifact Keeper also reports the database each scanner engine has installed
now, how old it is, and whether it is older than a limit you set (#5177).

## The report

`GET /api/v1/admin/security/vuln-db` (administrators):

```json
{
  "checked_at": "2026-11-23T12:00:00Z",
  "max_age_seconds": 604800,
  "any_stale": true,
  "affects_verdicts": false,
  "engines": [
    {
      "engine": "trivy",
      "scan_types": ["image"],
      "version": "trivy-db-v2",
      "published_at": "2026-10-01T00:00:00Z",
      "age_seconds": 4579200,
      "next_update": "2026-10-02T00:00:00Z",
      "offline": true,
      "source": "adapter",
      "state": "stale"
    },
    {
      "engine": "grype",
      "scan_types": ["grype"],
      "version": "grype-db-v6.0.2",
      "published_at": "2026-11-23T04:10:00Z",
      "age_seconds": 28200,
      "next_update": null,
      "offline": null,
      "source": "scanner",
      "state": "ok"
    }
  ]
}
```

`state` is `ok`, `stale` (older than the limit) or `unknown` (the engine is
configured but no source reported a build time). `max_age_seconds` is `null`
while no limit is set; the example above runs with
`SCAN_VULN_DB_MAX_AGE_HOURS=168`. Age is measured against the
current time, not the last scan, so an air-gapped install whose database never
updates becomes `stale` on schedule even when nothing new is scanned.

## Where the age comes from

| Engine | Source, in order |
| --- | --- |
| Trivy (`image`, `filesystem`, `incus` scans) | The scanner adapter's `GET /api/v1/vulndb`, which reads the installed database's `metadata.json`. Then recent scan history. |
| Grype | `grype db status`, the probe the scanner already runs and caches for five minutes. Then recent scan history. |

The adapter's DB route needs the adapter's `SCANNER_ADAPTER_TOKEN`. Give the
backend the same value as `TRIVY_ADAPTER_VULNDB_TOKEN` (or
`TRIVY_ADAPTER_VULNDB_TOKEN_FILE`). When it is unset the scan token
`TRIVY_ADAPTER_TOKEN` is tried. Without a usable token, and in trivy client
mode (`SCANNER_TRIVY_SERVER`), the adapter refuses and the backend falls back
to scan history: the newest database a completed scan recorded in the last
48 hours, and the last build the rescan worker saw (`scan_vuln_db_builds`).
With neither, the engine is `unknown`.

Live advisory feeds (the dependency scanner's OSV and GitHub Advisory
lookups) have no local database and are not listed.

## Settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `SCAN_VULN_DB_MAX_AGE_HOURS` | unset (off) | Age past which a database is `stale`, for example `168` for 7 days. Unset, `0` or not a whole number: the check is off, no engine is ever `stale` and nothing is logged; ages are still reported. |
| `TRIVY_ADAPTER_VULNDB_TOKEN` | unset | Bearer token for the adapter's DB route (its `SCANNER_ADAPTER_TOKEN`). |

## Metrics and logs

| Metric | Labels | Meaning |
| --- | --- | --- |
| `ak_scanner_vuln_db_age_seconds` | `engine` | Age of the installed database. `NaN` while the engine is `unknown`, never a frozen earlier value. |
| `ak_scanner_vuln_db_stale` | `engine` | `1` while the database is older than the limit, else `0`. |
| `ak_scanner_vuln_db_state` | `engine`, `state` | `1` for the engine's current state (`ok`, `stale`, `unknown`), `0` for the others. |
| `ak_scanner_vuln_db_max_age_seconds` | | The limit in seconds, `0` when off. |
| `ak_scanner_vuln_db_stale_warnings_total` | `engine` | Stale warnings logged. |

An engine that stops reporting (the adapter lost its token, no scans in 48
hours) turns `unknown`, which an age alert does not see: alert on
`ak_scanner_vuln_db_state{state="unknown"} == 1` as well as on
`ak_scanner_vuln_db_stale == 1`.

While an engine is stale the backend logs a warning naming the engine, its
database and its age: at once when it becomes stale, then at most once an
hour.

## Cost

The report is computed from the probes above, shared by the API and the
metrics, and reused for 60 seconds; concurrent callers wait for the one
refresh in flight. A background task recomputes it every five minutes so the
gauges move without anyone calling the API. Polling the route never starts a
scan or downloads a database.

## Stale databases do not change verdicts

A stale database is reported, and nothing else: scans still run, and their
verdicts, quarantine decisions and repository grades are computed exactly as
before (`affects_verdicts` is always `false`). Failing closed on age would
block every download on an air-gapped install the moment its imported database
passed the limit. That is an outage, not added safety, and the scan results
it would hide are still the best the instance has. To act on staleness, alert
on `ak_scanner_vuln_db_stale == 1` and import a fresh database
(`PUT /api/v1/vulndb` on the scanner adapter) or restore the mirror.
