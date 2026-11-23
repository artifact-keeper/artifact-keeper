# Instance quotas: storage, download transfer, upload size

When Artifact Keeper runs on metered object storage or behind metered
egress, the operator needs a hard ceiling on what the instance stores and
what it serves. Three limits provide one (#5912). Each is optional, and an
unset value or `0` turns it off.

| Variable | Default | Meaning |
|---|---|---|
| `STORAGE_QUOTA_BYTES` | off | Total bytes the instance may store |
| `STORAGE_QUOTA_WARN_PERCENT` | `80` | Storage warning threshold (1-100) |
| `TRANSFER_QUOTA_BYTES` | off | Artifact download bytes per calendar month (UTC) |
| `TRANSFER_QUOTA_WARN_PERCENT` | `80` | Transfer warning threshold (1-100) |
| `TRANSFER_QUOTA_GRACE_PERCENT` | `0` | How far above the quota downloads keep working (0-1000) |
| `MAX_UPLOAD_SIZE` | 10 GiB | Largest single upload (existing setting) |
| `QUOTA_HELP_URL` | none | An `http(s)` link added to refusals and shown in the web UI |
| `QUOTA_PRECHECK_BUDGET_MS` | `500` | How long the check before the body is read may wait on the database (`0` skips its lookups) |
| `STORAGE_DISK_WARN_PERCENT` | `95` | Storage volume usage that logs a warning (0-100, `0` off); see [Disk usage thresholds](#disk-usage-thresholds) |
| `STORAGE_DISK_BLOCK_PERCENT` | off | Storage volume usage at which writes are refused (0-100) |
| `STORAGE_DISK_CHECK_INTERVAL_SECS` | `5` | How often the volume is measured |

Every value is in bytes. The messages use binary units (1 GiB = 1024^3 bytes).

## Storage quota

Usage is the instance's total of the per-repository usage ledger, the same
figure `GET /api/v1/admin/stats` reports as `total_storage_bytes`: hosted
artifacts, OCI blobs and proxy-cached objects. The ledger is updated in the
same transaction as every write and delete, so enforcement is live, and a
delete frees its bytes for the next upload at once. Artifacts in the trash
(soft-deleted) do not count.

At the quota the instance is **read-only for writes**:

- Every request that would store new bytes is refused with
  `403 STORAGE_QUOTA_EXCEEDED`. That covers artifact uploads in every
  format, OCI blob and manifest pushes (session start, every chunk, and
  completion), the repository artifact API, the chunked upload API, and
  replication pushes from a peer.
- A request that declares a `Content-Length` is refused **before its body is
  read**, both when the instance is already at the quota and when the declared
  length would take it over. A body sent without a length is admitted, then
  checked once its size is known, before anything is recorded.
- The check before the body is read gets `QUOTA_PRECHECK_BUDGET_MS` for its
  database lookups. When the connection pool is exhausted and the budget runs
  out, the request is admitted with one `warn` line and a
  `ak_quota_precheck_skipped_total` increment, and the quota is enforced once
  the body is read.
- A remote (proxy) repository keeps serving content from upstream at the
  quota. It only stops caching it.
- Downloads, deletes, listing, search, sign-in and settings are never refused.

Admission is not serialized across the instance. Two uploads that each fit
but together go over the quota can both be admitted, so usage can overshoot
the quota by what is in flight at once: at most `MAX_UPLOAD_SIZE` per
concurrent upload.

Each time usage crosses the warning threshold or the quota, the backend logs
it once (a `warn` line).

## Disk usage thresholds

The storage quota counts what the instance stores. It does not see the disk
it stores it on: repository quotas can add up to more than the volume, proxy
caches grow on their own, and deleted artifacts wait in the trash for
`GC_TRASH_RETENTION_DAYS` before their space comes back. Two thresholds on
the storage volume itself catch a filling disk before it is full (#5191):

- **Warn** (`STORAGE_DISK_WARN_PERCENT`, default `95`): a `warn` log line
  (`storage volume is 95.3% full (...): free disk or add storage`) when usage
  crosses it, repeated at most every 10 minutes while it stays above, and
  `ak_storage_disk_state` = 1. Nothing is refused.
- **Block** (`STORAGE_DISK_BLOCK_PERCENT`, off by default): writes that
  would store new bytes are refused with **`403 DISK_THRESHOLD_EXCEEDED`**. A
  write whose declared `Content-Length` would take the volume to the
  threshold is refused too. Writes resume by themselves once usage is one
  percentage point below the threshold (so a volume hovering at the line does
  not flap). Where it applies:
  - **Format uploads, OCI pushes, the repository artifact API and the chunked
    upload API** (every chunk): refused before the body is read, as for the
    storage quota. An OCI cross-repository blob mount writes no bytes and is
    not refused.
  - **npm publishes**: checked once the package document is read, because the
    same `PUT` also carries metadata-only changes (dist-tags, deprecations)
    that are not refused.
  - **Peer replication** (trusted sessions included), **OCI promotion** and
    every other write through the shared publish admission: refused once the
    size is known.
  - **Artifactory/Nexus migration imports**: an item that would cross the
    threshold is not written and fails with the refusal message; while the
    volume stays blocked the job is **paused** (`error_summary` says why), and
    `POST /api/v1/migrations/{id}/resume` continues it once space is freed.
  - **Backups** whose archive is written to filesystem storage (no
    `BACKUP_S3_BUCKET`) fail at the start with the refusal. An archive in a
    separate bucket is not affected.
  - **Restores are exempt**: an operator restoring from a backup needs it to
    complete. A restore that runs while the volume is blocked logs a `warn`.

While blocked, downloads, listing, search, deletes, lifecycle policies and
storage garbage collection keep working, so you can free space without a
restart. A remote (proxy) repository keeps serving what it fetches upstream,
streamed to the client, but does not write it to the cache (Debian `dists`
revalidation included). A replicating peer that is refused backs off and
retries the delivery later; the task is not failed. (Under an active
package age hold such a fetch answers `409`, as it does whenever a fill
cannot be cached.)

Usage is what `df` reports: bytes in use over bytes in use plus bytes
available, so space reserved for root counts as used. The backend measures
`STORAGE_PATH` when `STORAGE_BACKEND=filesystem`, and `AK_UPLOAD_STAGING_DIR`
when it is set; the fuller one decides. The reading is taken on a background
thread every `STORAGE_DISK_CHECK_INTERVAL_SECS`, and every second while the
volume is at the warn threshold or blocked, and cached, so no request waits on
the filesystem. Under pressure every chunk of a long upload session is
checked against a reading at most a second old. Until the first reading, nothing is refused. A
failed reading keeps the last state and logs a warning (at most every 10
minutes).

The thresholds do not apply to object storage (S3, Azure Blob, GCS): there is
no volume to measure, and only the staging directory is watched when it is
set. A repository configured with its own filesystem storage location on
another volume is not measured either. Measuring needs Linux (`statvfs`);
elsewhere the thresholds are off with a startup warning.

Why `403` and not `507`: a 5xx is retried by npm, pip, Maven, cargo, NuGet,
Docker and Helm clients, often with backoff or a chunked re-upload, and a
retry storm against a nearly full disk adds partial writes and temp files at
the worst moment. Why not `STORAGE_QUOTA_EXCEEDED`: raising a quota frees no
disk, so its remedy would point the wrong way. A write that still finds the
disk genuinely full (for example with the block threshold off) answers
`507 STORAGE_FULL` as before.

The refusal:

```json
{
  "code": "DISK_THRESHOLD_EXCEEDED",
  "message": "server storage nearly full: free disk or add storage (the storage volume is 98.4% full, 98.4 GiB of 100.0 GiB; writes are refused from 98%). Downloads are not affected.",
  "limit_bytes": 105226698752,
  "used_bytes": 105656795136,
  "threshold_percent": 98,
  "used_percent": 98.4
}
```

`limit_bytes` is the usage the threshold stands for, `used_bytes` the bytes in
use. Over HTTP/1.1 the reason phrase is `403 Disk Threshold Exceeded`; on
`/v2` the code is `DENIED` with the message, and docker prints
`denied: server storage nearly full: ...`.

## Repository and project quotas

A repository's own quota (`quota_bytes`) and its project's quota are
enforced as before. Their refusal is now **`403 QUOTA_EXCEEDED`**, where
releases before 1.12 answered `507`. A 5xx made clients retry and made
monitoring read the refusal as a server fault. The body names the scope, the
repository and the figures. A declared `Content-Length` that does not fit is
refused before the body is read.

A quota refusal is only given to a caller who may write the repository.
Anyone else gets the same answer as for any other write they may not make:
`401` without credentials, `403 FORBIDDEN` (`DENIED` on `/v2`) for a caller
who can read but not write, and `404` for a caller who cannot read the
repository either. The quota figures are never shown to them.

A storage backend that is genuinely full (a bucket quota on the object store,
a full volume) still answers `507 STORAGE_FULL`. In that case the server
failed to store what it accepted, and the operator has to act. That is not a
limit the client reached.

## Download transfer quota

The backend counts the bytes it actually sends on successful `GET`
responses of the format routes, OCI `/v2` and the repository download API,
for every format and for UI and API downloads. A presigned redirect (see
[presigned-downloads.md](presigned-downloads.md)) counts the object's size
when the URL is issued, because those bytes leave the object store without
passing through the backend.

The counter is per calendar month in UTC. Each replica counts in memory and
adds its count to one row per month in Postgres (`transfer_quota_usage`)
every 10 seconds. The upsert returns the month's total, so every replica and
every restart shares one counter. A replica that crashes loses at most its
last 10 seconds of counting.

The quota is soft up to the grace band:

| Usage | State | Downloads |
|---|---|---|
| below `TRANSFER_QUOTA_WARN_PERCENT` | `ok` | served |
| at or above the warning threshold | `warning` | served |
| at or above the quota | `over` | served (grace band) |
| at or above `quota * (100 + grace) / 100` | `refusing` | artifact downloads answer `429` |

While refusing, artifact downloads answer `429 TRANSFER_QUOTA_EXCEEDED` with
`Retry-After` set to the seconds until the next month starts (00:00 UTC on
the 1st). Metadata responses (JSON, XML, HTML, text and YAML index
documents) are still served, so clients that read metadata before they
publish (`mvn deploy`, Gradle) keep working. Uploads, deletes, the API and
the UI are not affected.

## Upload size

`MAX_UPLOAD_SIZE` is now checked on the declared `Content-Length` before the
body is read, on every upload route, and the refusal is a JSON
`413 PAYLOAD_TOO_LARGE`. A body without a length is cut off with the same
413 once it crosses the limit. Incus/LXC image uploads keep their own
unlimited body size.

## Refusal bodies

Every refusal is a 4xx with the standard error object, plus extra fields:

```json
{
  "code": "STORAGE_QUOTA_EXCEEDED",
  "message": "Storage quota reached: 10.0 GiB of 10.0 GiB used. Delete artifacts or raise the quota to upload again. Downloads are not affected.",
  "scope": "instance",
  "limit_bytes": 10737418240,
  "used_bytes": 10737418240,
  "help_url": "https://example.com/usage"
}
```

A storage refusal while usage is still below the quota means that this
upload does not fit in the space left. Smaller uploads still succeed. The
message says so, and the body carries the upload's declared size:

```json
{
  "code": "STORAGE_QUOTA_EXCEEDED",
  "message": "This upload (512.0 MiB) would exceed the storage quota: 9.8 GiB of 10.0 GiB used, 256.0 MiB free. Smaller uploads still fit; delete artifacts or raise the quota to upload this one. Downloads are not affected.",
  "scope": "instance",
  "limit_bytes": 10737418240,
  "used_bytes": 10468982784,
  "content_length": 536870912
}
```

The code and fields are the same in both cases. A client tells them apart
with `used_bytes < limit_bytes`. Repository and project refusals follow the
same rule, keeping their usual leading phrase ("Repository storage quota
exceeded: this upload (...) does not fit in the space left; repository 'libs'
uses ...").

| Refusal | Status | `code` | Extra fields |
|---|---|---|---|
| Instance storage | 403 | `STORAGE_QUOTA_EXCEEDED` | `scope: "instance"`, `limit_bytes`, `used_bytes`, `content_length` (when declared), `help_url` |
| Repository or project quota | 403 | `QUOTA_EXCEEDED` | `scope: "repository"` or `"project"`, `repository`, `project`, `limit_bytes`, `used_bytes`, `content_length` (when declared) |
| Transfer | 429 + `Retry-After` | `TRANSFER_QUOTA_EXCEEDED` | `limit_bytes` (the monthly quota), `used_bytes`, `period_end`, `retry_after_seconds`, `help_url` |
| Upload size | 413 | `PAYLOAD_TOO_LARGE` | `limit_bytes`, `content_length` (when declared) |
| Disk usage threshold | 403 | `DISK_THRESHOLD_EXCEEDED` | `limit_bytes`, `used_bytes`, `threshold_percent`, `used_percent`, `content_length` (when declared) |

`help_url` is present only when `QUOTA_HELP_URL` is set.

Some format clients only read their own error shape:

- **OCI** (`/v2`): `{"errors":[{"code":"DENIED" | "TOOMANYREQUESTS" | "SIZE_INVALID","message":"...","detail":{...the fields above}}]}`.
  Docker prints `denied: <message>`.
- **npm**: the standard object plus `"error": "<message>"`, which npm prints.
- **Protobuf (Connect)** keeps its Connect envelope (`resource_exhausted`)
  with the same status and message.

Over HTTP/1.1 the status line also carries a short reason phrase
(`403 Storage Quota Exceeded`, `403 Quota Exceeded`,
`429 Transfer Quota Exceeded`, `403 Disk Threshold Exceeded`), because Maven and twine print the reason
phrase rather than the body.

## Reading the figures

`GET /api/v1/system/quota` returns the figures to any authenticated user.
The same four fields are part of `GET /api/v1/admin/stats` for
administrators.

```json
{
  "storage_quota": {"enabled": true, "quota_bytes": 10737418240, "used_bytes": 8858370048,
                    "percent": 82.5, "warn_percent": 80, "state": "warning"},
  "transfer_quota": {"enabled": true, "quota_bytes": 53687091200, "used_bytes": 1073741824,
                     "percent": 2.0, "warn_percent": 80, "grace_percent": 25,
                     "hard_limit_bytes": 67108864000, "state": "ok",
                     "period_start": "2026-11-01T00:00:00Z", "period_end": "2026-12-01T00:00:00Z"},
  "max_upload_bytes": 2147483648,
  "quota_help_url": null,
  "disk": {"enabled": true, "warn_percent": 95, "block_percent": 98, "volume": "storage",
           "reading": {"total_bytes": 107374182400, "used_bytes": 96636764160, "free_bytes": 5368709120},
           "used_percent": 94.74, "state": "ok"}
}
```

Disk `state` is `ok`, `warning` or `blocked`; `enabled` is `false` when both
thresholds are off or there is no volume to measure.

Storage `state` is `ok`, `warning` or `exceeded`. Transfer `state` is `ok`,
`warning`, `over` or `refusing`.

## Metrics

| Metric | Type | Meaning |
|---|---|---|
| `ak_storage_quota_bytes` | gauge | `STORAGE_QUOTA_BYTES` (0 when off) |
| `ak_storage_used_bytes` | gauge | Stored bytes (refreshed every 10 seconds while a storage quota is set) |
| `ak_transfer_quota_bytes` | gauge | `TRANSFER_QUOTA_BYTES` (0 when off) |
| `ak_transfer_used_bytes` | gauge | Download bytes of the current month, all replicas |
| `ak_quota_refusals_total{kind}` | counter | Refusals by `kind`: `storage`, `repository`, `transfer`, `upload_size`, `disk` |
| `ak_storage_disk_state` | gauge | `0` ok, `1` at the warn threshold, `2` writes refused |
| `ak_storage_disk_used_percent{volume}` | gauge | Usage of the `storage` or `staging` volume, as `df` reports it |
| `ak_storage_disk_total_bytes{volume}` | gauge | The volume's size |
| `ak_storage_disk_free_bytes{volume}` | gauge | Bytes still available to the backend |
| `ak_storage_disk_threshold_percent{level}` | gauge | `STORAGE_DISK_WARN_PERCENT` (`level="warn"`) and `STORAGE_DISK_BLOCK_PERCENT` (`level="block"`) |
| `ak_quota_precheck_skipped_total` | counter | Uploads admitted unchecked before the body was read because the pre-check ran out of `QUOTA_PRECHECK_BUDGET_MS` |

A useful alert is
`ak_storage_used_bytes / ak_storage_quota_bytes > 0.8 and ak_storage_quota_bytes > 0`.
For the disk, alert on `ak_storage_disk_state > 0`, and page on
`rate(ak_quota_refusals_total{kind="disk"}[5m]) > 0`.

## In front of the backend

The pre-body check only helps if the reverse proxy passes the request
headers on before it has the whole body. ingress-nginx buffers request bodies
by default, so set `nginx.ingress.kubernetes.io/proxy-request-buffering: "off"`
on the backend's ingress. A proxy body-size limit, if you keep one, should sit
above `MAX_UPLOAD_SIZE` so that the backend's JSON 413 is the answer clients
see.
