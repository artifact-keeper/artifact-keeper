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
- A remote (proxy) repository keeps serving content from upstream at the
  quota. It only stops caching it.
- Downloads, deletes, listing, search, sign-in and settings are never refused.

Admission is not serialized across the instance. Two uploads that each fit
but together go over the quota can both be admitted, so usage can overshoot
the quota by what is in flight at once: at most `MAX_UPLOAD_SIZE` per
concurrent upload.

Each time usage crosses the warning threshold or the quota, the backend logs
it once (a `warn` line).

## Repository and project quotas

A repository's own quota (`quota_bytes`) and its project's quota are
enforced as before. Their refusal is now **`403 QUOTA_EXCEEDED`**, where
releases before 1.12 answered `507`. A 5xx made clients retry and made
monitoring read the refusal as a server fault. The body names the scope, the
repository and the figures. A declared `Content-Length` that does not fit is
refused before the body is read.

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

| Refusal | Status | `code` | Extra fields |
|---|---|---|---|
| Instance storage | 403 | `STORAGE_QUOTA_EXCEEDED` | `scope: "instance"`, `limit_bytes`, `used_bytes`, `help_url` |
| Repository or project quota | 403 | `QUOTA_EXCEEDED` | `scope: "repository"` or `"project"`, `repository`, `project`, `limit_bytes`, `used_bytes` |
| Transfer | 429 + `Retry-After` | `TRANSFER_QUOTA_EXCEEDED` | `limit_bytes` (the monthly quota), `used_bytes`, `period_end`, `retry_after_seconds`, `help_url` |
| Upload size | 413 | `PAYLOAD_TOO_LARGE` | `limit_bytes`, `content_length` (when declared) |

`help_url` is present only when `QUOTA_HELP_URL` is set.

Some format clients only read their own error shape:

- **OCI** (`/v2`): `{"errors":[{"code":"DENIED" | "TOOMANYREQUESTS" | "SIZE_INVALID","message":"...","detail":{...the fields above}}]}`.
  Docker prints `denied: <message>`.
- **npm**: the standard object plus `"error": "<message>"`, which npm prints.
- **Protobuf (Connect)** keeps its Connect envelope (`resource_exhausted`)
  with the same status and message.

Over HTTP/1.1 the status line also carries a short reason phrase
(`403 Storage Quota Exceeded`, `403 Quota Exceeded`,
`429 Transfer Quota Exceeded`), because Maven and twine print the reason
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
  "quota_help_url": null
}
```

Storage `state` is `ok`, `warning` or `exceeded`. Transfer `state` is `ok`,
`warning`, `over` or `refusing`.

## Metrics

| Metric | Type | Meaning |
|---|---|---|
| `ak_storage_quota_bytes` | gauge | `STORAGE_QUOTA_BYTES` (0 when off) |
| `ak_storage_used_bytes` | gauge | Stored bytes (refreshed every 10 seconds while a storage quota is set) |
| `ak_transfer_quota_bytes` | gauge | `TRANSFER_QUOTA_BYTES` (0 when off) |
| `ak_transfer_used_bytes` | gauge | Download bytes of the current month, all replicas |
| `ak_quota_refusals_total{kind}` | counter | Refusals by `kind`: `storage`, `repository`, `transfer`, `upload_size` |

A useful alert is
`ak_storage_used_bytes / ak_storage_quota_bytes > 0.8 and ak_storage_quota_bytes > 0`.

## In front of the backend

The pre-body check only helps if the reverse proxy passes the request
headers on before it has the whole body. ingress-nginx buffers request bodies
by default, so set `nginx.ingress.kubernetes.io/proxy-request-buffering: "off"`
on the backend's ingress. A proxy body-size limit, if you keep one, should sit
above `MAX_UPLOAD_SIZE` so that the backend's JSON 413 is the answer clients
see.
