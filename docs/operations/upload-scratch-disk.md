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
example a dedicated `emptyDir` or ephemeral PVC) from `STORAGE_PATH`. Every
file is removed when its upload succeeds or fails, and the hourly cleanup
sweeps files left behind by a replica that crashed mid-upload.

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
  repository whose format is served by a WASM plugin. A multipart upload into
  an object-storage RPM repository spools whatever the file is, because the
  form can name its path after the file field.
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
  evicts the pod mid-upload. Leave headroom over the estimate, or point
  `AK_UPLOAD_STAGING_DIR` at a volume sized for uploads alone.
- Watch free space on the scratch volume under load; it should return to its
  baseline once uploads finish. Space that does not return points to files left
  by a crashed replica, which the hourly cleanup reclaims.
