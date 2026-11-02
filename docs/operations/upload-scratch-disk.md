# Sizing local scratch disk for uploads

Artifact Keeper stores artifacts in each repository's storage backend
(filesystem, S3, GCS or Azure), but some upload paths still write the incoming
body to a local scratch file on the replica that received it before the bytes
reach that backend. On those paths, local disk use scales with **concurrent
upload volume**, not with repository size, and it drops back as each upload
finishes. This page lists which paths spool, where, and how to size the volume
(#3916).

## Where scratch files go

| Location | Used by |
|---|---|
| `$AK_UPLOAD_STAGING_DIR` if set, else `$STORAGE_PATH/.incoming` | single-request uploads that spool (see below) and Incus image uploads |
| `$STORAGE_PATH/.uploads` | completion of a chunked upload session (`/api/v1/uploads`) that has to assemble locally (see below) |

`AK_UPLOAD_STAGING_DIR` lets you put upload staging on a separate volume (for
example a dedicated `emptyDir` or ephemeral PVC) from `STORAGE_PATH`. It does
**not** move `.uploads`: a chunked completion that must assemble locally always
does so under `$STORAGE_PATH/.uploads`, so `STORAGE_PATH` must still be sized for
those. A completion on an S3-, GCS- or Azure-backed repository whose format does
not need the body as a file assembles on the repository's backend instead and
needs no local space at all.

Every file is removed when its upload succeeds or fails. Files left behind by a
replica that crashed mid-upload are removed by a cleanup pass that runs hourly
but only reaps files past an age threshold, so the space does not come back
within the hour:

- staging files (`$AK_UPLOAD_STAGING_DIR` / `$STORAGE_PATH/.incoming`): older
  than 24 hours;
- chunked-completion scratch (`$STORAGE_PATH/.uploads`): older than 7 hours
  (the 6-hour completion lease plus one hour);
- objects staged on the repository's backend (`generic-upload-staging/`):
  older than 24 hours;
- a chunked session's backend staging (`upload-staging/<session-id>/`, chunks
  and any `assembled` object): reclaimed with the session by the upload reaper,
  on the same schedule as an abandoned session.

## Which uploads use local scratch

**Do not spool** (the body goes straight to the repository's object storage,
with bounded memory):

- Generic uploads into S3-, GCS- and Azure-backed repositories, through either
  `PUT /api/v1/repositories/{key}/artifacts/{path}` or the multipart `POST`
  routes on `/api/v1/repositories/{key}/artifacts`. The body streams into a
  `generic-upload-staging/<uuid>` object on the repository's backend and is
  copied to its content-addressed key.
- The chunks of a chunked upload session, which are staged as objects on the
  repository's backend as they arrive.
- Completion of a chunked upload session into an S3-, GCS- or Azure-backed
  repository, unless the format needs the body as a local file (see the next
  list). The staged chunks stream, in order, into one
  `upload-staging/<session-id>/assembled` object on the repository's backend,
  which is verified and then copied server-side to the content-addressed key.
- OCI/Docker blob uploads, which are staged under `oci-uploads/` on the
  repository's backend.
- Maven deploys (`PUT /maven/{key}/{path}`: jars, POMs, checksum sidecars,
  `maven-metadata.xml`) and the format-native single-PUT routes for NuGet,
  PyPI, Terraform, JetBrains, Swift, Git LFS, Helm, Ansible, Chef and Pub into
  S3-, GCS- and Azure-backed repositories (#4990, #5002). The body streams into
  a `generic-upload-staging/<uuid>` object on the repository's backend, with
  SHA-256, SHA-1 and MD5 computed on the way, and is copied server-side to its
  final key (for NuGet and PyPI, promoted to the content-addressed key) once
  the publish holds its lock.
  A route that has to open the archive to parse it — a NuGet `.nuspec`, a
  wheel or sdist, a Terraform module archive or provider manifest, a Swift
  manifest fallback, a Helm `Chart.yaml`, an Ansible collection manifest, a Pub
  `pubspec.yaml` — downloads the staged object to one temporary file just for
  that read, then removes it. The artifact itself is never staged locally.

Whether a repository's uploads stage on its backend is decided by the
backend's native streaming capability (S3, GCS and Azure have it), the same
capability the chunked completion uses, not by the backend's name.

**Spool one full-size file per in-flight upload:**

- Generic uploads into **filesystem-backed** repositories (the file is then
  moved into place on the same disk).
- Generic uploads that need the body as a local file even on object storage:
  `.rpm` packages in RPM repositories (header parse), and every upload into a
  repository whose format is served by a WASM plugin. In an object-storage RPM
  repository, `POST /api/v1/repositories/{key}/artifacts` (path given as a form
  field) spools every file, whatever its name, because the form can name the
  path after the file field. `POST .../artifacts/{path}` and `PUT` know the
  path up front and spool only `.rpm` packages.
- **Chunked upload completion that must assemble locally.** This is the case
  for a filesystem-backed repository, for every backend that has no native
  streaming upload, and for formats whose finalize reads the body as a file
  (`.rpm` in an RPM repository, a wheel or sdist in a PyPI repository, and
  Incus/Debian packages; see `docs/chunked-uploads.md`). A Maven POM and an npm
  tarball are read from the staged chunks instead and need no local file. The
  staged chunks are
  reassembled into one file on the replica handling
  `PUT /api/v1/uploads/{id}/complete`, verified, and then written to the
  backend, so each concurrent completion needs the full artifact size. On
  S3/GCS/Azure without such a format, completion instead assembles on the
  backend and uses no local scratch.
- Incus/LXC image uploads (monolithic and chunked).
- Format-native publish routes into a **filesystem-backed** repository, or into
  a backend without native streaming: Ansible, Chef, Helm, JetBrains, NuGet,
  Pub, PyPI, Swift and Terraform, plus Git LFS objects and Maven. The same
  routes into an S3-, GCS- or Azure-backed repository stage on the backend (see
  the previous list); only a route that parses the archive takes a transient
  local copy for that read.

Other format-native publish routes (npm, Cargo, Debian, RubyGems and similar)
read the request body into memory instead of onto disk, bounded by
`MAX_UPLOAD_SIZE` per request; size replica memory for those, not scratch disk.

The routes that open the package to validate it (conda, RubyGems, npm, Cargo,
Composer, Hex, VS Code, Go modules, Alpine, Pacman, CRAN and RPM) receive the
body into one buffer of exactly its declared size, charged to a process-wide
budget, `UPLOAD_MEMORY_BUDGET_BYTES` (#4609). Unset, the budget is half the
container's cgroup memory limit (no cap without a limit); `0` disables it. An
upload that does not fit while others hold the budget is refused at once with
`503` and `Retry-After`, and one larger than the whole budget with `413`, so
concurrent large uploads are shed instead of getting the replica OOM-killed.
Size the replica's memory limit at roughly twice the largest package you expect
on these routes, plus the concurrency you want to admit.

Conan recipe and package files are received the same way (#4329), so a
`conan_package.tgz` cut short is refused with `408` and nothing is stored.
Conan file transfers (`/conan/.../files/<name>`) are also exempt from the
request timeout described below.

## When an upload cannot be received

The server only parses a package after it has received the whole body. When it
cannot, the response says why, so a client does not go debugging a package that
was never the problem (#4609):

| Situation | Response |
|---|---|
| The body ended before its `Content-Length`, or the connection broke | `408`, `{"code": "incomplete_body"}` |
| The body made too little progress (see below) | `408` |
| The in-memory upload budget is in use by other uploads, or the buffer could not be allocated | `503` + `Retry-After`, `{"code": "upload_capacity_exhausted"}` |
| Reading the body failed for a reason that is not the client's | `503` + `Retry-After`, `{"code": "upload_receive_failed"}` |
| The scratch or storage disk is full (or over quota) | `507` + `Retry-After`, `{"code": "insufficient_storage"}` |
| The scratch file could not be written for another reason | `503` + `Retry-After`, `{"code": "upload_spool_failed"}` |
| The body is larger than `MAX_UPLOAD_SIZE` | `413` |

A `400` from a publish route therefore means the complete package was received
and is itself invalid. The server-side cause of a `503` or `507` is logged at
`error`; the response carries a fixed message.

## Sizing rule of thumb

```
scratch bytes ≈ (largest expected artifact) × (concurrent spooling uploads per replica)
```

`MAX_UPLOAD_SIZE` (default 10 GiB) caps a single spooled body. A replica that
accepts *N* concurrent spooling uploads of that size can need up to *N* ×
`MAX_UPLOAD_SIZE` of free scratch space at once. Artifact Keeper caps upload
concurrency per principal (below) and overall (`GLOBAL_MAX_CONCURRENCY`,
default 512 requests of any kind), but most deployments run far below those
caps, so measure concurrency from your traffic rather than assuming the worst
case.

## Limits on slow and concurrent uploads

Upload and download routes are exempt from the router-wide
`GLOBAL_REQUEST_TIMEOUT_SECS` wall-clock timeout, because that clock includes
the time the client spends sending the body (#3263). Two other limits keep a
slow or stalled upload from holding server capacity indefinitely
(GHSA-9f9r-c4w8-rjv9):

| Setting | Default | Effect |
|---|---|---|
| `UPLOAD_PROGRESS_WINDOW_SECS` | `60` | An upload body that delivers fewer than `UPLOAD_MIN_PROGRESS_BYTES` during one window spent waiting for data is aborted with `408 Request Timeout`, and its scratch file is removed. `0` disables the deadline. |
| `UPLOAD_MIN_PROGRESS_BYTES` | `16384` | The bytes required per window (about 270 B/s at the default window). |
| `UPLOAD_MAX_IN_FLIGHT_PER_PRINCIPAL` | `64` | Concurrent uploads one user, or one client address for an anonymous caller, may have in flight on the native-format routes, the repository artifact routes and `/api/v1/uploads`. Further uploads get `429 Too Many Requests` with `Retry-After`. `0` disables the cap. |

Time the server spends on its own work (authentication, database lookups,
writing to the storage backend) does not count against the progress window;
only time spent waiting for the client to send does. Health and readiness
probes (`/health`, `/healthz`, `/ready`, `/readyz`, `/livez`) are never refused
by the `GLOBAL_MAX_CONCURRENCY` limit, so a replica saturated by uploads still
reports itself alive.

Practical guidance:

- With every repository on object storage and uploads going through the
  generic API, scratch only has to cover RPM packages, Incus/Debian finalizes,
  chunked completions whose format needs a local file, and one transient parse
  copy for a format-native route that opens the archive (NuGet, PyPI,
  Terraform, the Swift manifest fallback, Helm, Ansible and Pub). Size for the
  largest of those you expect and the number you expect at once.
- When `STORAGE_PATH` is an `emptyDir` with a `sizeLimit`, exceeding the limit
  evicts the pod mid-upload. Leave headroom over the estimate. Pointing
  `AK_UPLOAD_STAGING_DIR` at a separate volume moves single-request staging
  off `STORAGE_PATH`; a chunked completion that must assemble locally still
  lands on `STORAGE_PATH`, so size it for those either way.
- Watch free space on the scratch volume under load; it should return to its
  baseline once uploads finish. Space that does not return points to files left
  by a crashed replica, which the cleanup reclaims once they pass the age
  thresholds above (7 or 24 hours).
