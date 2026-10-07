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
| `$STORAGE_PATH/.uploads` | completion of a chunked upload session (`/api/v1/uploads`) |

`AK_UPLOAD_STAGING_DIR` lets you put upload staging on a separate volume (for
example a dedicated `emptyDir` or ephemeral PVC) from `STORAGE_PATH`. It does
**not** move `.uploads`: chunked-upload completion always reassembles under
`$STORAGE_PATH/.uploads`, so `STORAGE_PATH` must still be sized for concurrent
chunked completions even when staging lives elsewhere.

Every file is removed when its upload succeeds or fails. Files left behind by a
replica that crashed mid-upload are removed by a cleanup pass that runs hourly
but only reaps files past an age threshold, so the space does not come back
within the hour:

- staging files (`$AK_UPLOAD_STAGING_DIR` / `$STORAGE_PATH/.incoming`): older
  than 24 hours;
- chunked-completion scratch (`$STORAGE_PATH/.uploads`): older than 7 hours
  (the 6-hour completion lease plus one hour);
- objects staged on the repository's backend (`generic-upload-staging/`):
  older than 24 hours.

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
- OCI/Docker blob uploads, which are staged under `oci-uploads/` on the
  repository's backend.

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
- **Chunked upload completion.** The staged chunks are reassembled into one
  file on the replica handling `PUT /api/v1/uploads/{id}/complete`, verified,
  and then written to the backend, so each concurrent completion needs the full
  artifact size.
- Incus/LXC image uploads (monolithic and chunked).
- Format-native publish routes that stream to staging: Ansible, Chef, Helm,
  JetBrains, Maven, NuGet, Pub, PyPI, Swift and Terraform.

Other format-native publish routes (npm, Cargo, Debian, RubyGems and similar)
read the request body into memory instead of onto disk, bounded by
`MAX_UPLOAD_SIZE` per request; size replica memory for those, not scratch disk.

## Sizing rule of thumb

```
scratch bytes ≈ (largest expected artifact) × (concurrent spooling uploads per replica)
```

`MAX_UPLOAD_SIZE` (default 10 GiB) caps a single spooled body. A replica that
accepts *N* concurrent spooling uploads of that size can need up to *N* ×
`MAX_UPLOAD_SIZE` of free scratch space at once. Artifact Keeper does not cap
upload concurrency itself; your ingress and clients do, so measure it from
your traffic rather than assuming the worst case.

Practical guidance:

- With every repository on object storage and uploads going through the
  generic API, scratch only has to cover chunked completions, RPM packages,
  Incus images and the spooling format routes above. Size for the largest of
  those you expect and the number you expect at once.
- When `STORAGE_PATH` is an `emptyDir` with a `sizeLimit`, exceeding the limit
  evicts the pod mid-upload. Leave headroom over the estimate. Pointing
  `AK_UPLOAD_STAGING_DIR` at a separate volume moves single-request staging
  off `STORAGE_PATH`, but chunked completions still land on `STORAGE_PATH`, so
  size it for those either way.
- Watch free space on the scratch volume under load; it should return to its
  baseline once uploads finish. Space that does not return points to files left
  by a crashed replica, which the cleanup reclaims once they pass the age
  thresholds above (7 or 24 hours).
