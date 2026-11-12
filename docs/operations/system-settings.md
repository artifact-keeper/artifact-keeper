# System settings (`/api/v1/admin/settings`)

`GET /api/v1/admin/settings` reports the settings **in force**, and
`POST /api/v1/admin/settings` changes the writable ones (#5652). Both are
admin-only.

| Field | Writable | Range | What reads it |
|---|---|---|---|
| `storage_backend`, `storage_path`, `environment` | no | | `STORAGE_BACKEND`, `STORAGE_PATH`, `ENVIRONMENT` |
| `max_upload_size_bytes` | no | | the upload limit in force, `MAX_UPLOAD_SIZE` (bytes, `0` = no limit) |
| `audit_retention_days` | yes | `0..=36500` | the hourly `audit_log` retention job; `0` = off (see [audit-events.md](../audit-events.md)) |
| `retention_days` | yes | `0..=36500` | `POST /api/v1/admin/cleanup` with `cleanup_old_backups`: completed backups older than this many days, beyond the newest `backup_retention_count`, are deleted |
| `backup_retention_count` | yes | `1..=10000` | the same cleanup: the newest completed backups it always keeps |
| `edge_stale_threshold_minutes` | yes | `1..=10080` | the background stale-peer detector (re-read every check) and `POST /api/v1/admin/cleanup` with `cleanup_stale_peers`. `PEER_STALE_THRESHOLD_MINUTES` pins it when set |

## Updating

The body is a partial update: a field that is absent keeps its value. The
body `GET` returns may be posted back with only some values changed.

- A value outside its range answers `400 VALIDATION_ERROR` naming the field.
  Nothing is stored. Negative values used to be stored.
- A read-only field may be sent only with the value in force. A different
  `max_upload_size_bytes` answers `400`: set `MAX_UPLOAD_SIZE` and restart.
  Before 1.12.0 the value was stored and ignored, and `GET` showed a `100 MB`
  limit while `MAX_UPLOAD_SIZE` (10 GiB by default) was the one enforced.
- With `PEER_STALE_THRESHOLD_MINUTES` set, a different
  `edge_stale_threshold_minutes` answers `400`.
- `allow_anonymous_download` has been removed: it was stored but never
  enforced. Sending it, with any value, answers `400`. Anonymous access is the
  guest-access setting (`PATCH /api/v1/admin/settings/system` with
  `guest_access_enabled`, or `AK_GUEST_ACCESS_ENABLED`). An existing stored row
  is left in place and ignored.

The response is the settings in force after the update.

## Audit

Each field a `POST` changes writes one `SETTING_CHANGED` row (`resource_type:
setting`, the acting admin as `user_id`), with `details`
`{key, old_value, new_value, setting, from, to}`. A field sent with its
current value writes nothing.

## Upgrading to 1.12.0

- A client that sets `max_upload_size_bytes` (the web UI's upload-size editor
  did) now gets `400`; set `MAX_UPLOAD_SIZE` instead.
- A client that sends `allow_anonymous_download` gets `400`; drop the field.
- A stored `edge_stale_threshold_minutes` now drives the background detector
  when `PEER_STALE_THRESHOLD_MINUTES` is unset. Before, the detector used the
  environment variable or 5 minutes, and the setting applied only to the
  manual cleanup.
