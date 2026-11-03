# Download integrity verification

Every content-addressed artifact row records the SHA-256 of the bytes it was
written with. When a download serves those bytes, the server verifies them
against the record while it streams them, so an object corrupted in storage
(bit rot, a truncated write, someone editing the bucket) is never delivered
as a clean response under its original digest (#3919, #4323).

## Where it applies

- The generic download route `GET /api/v1/repositories/{key}/download/{path}`,
  including `?version=` revisions and the `/general/{key}/...` mount.
- Every hosted member a virtual repository serves from, for every format.
- Format routes that read hosted artifacts through the shared hosted fetch,
  among them Terraform modules and providers, Go modules, Composer, pacman,
  VS Code extensions and sbt.
- Incus image downloads, checked against the `X-Checksum-Sha256` the
  response advertises (a mismatch aborts the transfer before its last bytes).
- OCI blob pulls (`GET /v2/<name>/blobs/<digest>`) served from a repository's
  stored blobs or a Virtual's local member, checked against the blob's digest
  (`Docker-Content-Digest`). The error body is the OCI error shape,
  `{"errors": [{"code": "STORED_OBJECT_INTEGRITY", ...}]}`. A Remote repairs
  what it finds (see below). Blobs streamed from an upstream on a proxy miss
  are not checked.

Not yet covered: the Maven, npm, PyPI, Cargo, NuGet and
Helm hosted download handlers, which read storage through their own paths. Protobuf commit bundles are never
checked, because their recorded digest is a commit digest, not the digest of
the stored bundle.

## What a client sees

- An object of at most 4 MiB is read and checked before anything is sent,
  while the verification memory budget has room (see [Cost](#cost)). A
  mismatch is answered `502 Bad Gateway` with
  `{"code": "STORED_OBJECT_INTEGRITY", ...}` and none of the object's bytes.
  Through a virtual repository the 502 is final: the walk does not fall
  through to another member's bytes for the same path.
- A larger object streams as it is read. A mismatch is only known at the end,
  after the `200` was sent, so the transfer is aborted before its final bytes
  and the client sees a short read, never a complete body.
- A range request for part of an object is not checked (a window cannot be
  checked against a whole-object digest); a range covering the whole object
  is.
- A `HEAD` on the generic route, including one a virtual repository answers
  from a hosted member there (#4989), or one the shared hosted fetch answers
  from the artifact row, reads no body and is not checked.

## Repair on a Remote OCI repository

A Remote can hold a stored copy of a blob (for example a layer staged for the
inline proxy scan), and it has an upstream to replace a corrupt copy from
(#5169), directly or as a member of a Virtual:

- A blob of at most 4 MiB that fails the check is treated as a cache miss. It
  is fetched again through the Remote's usual gates. Once the new bytes hash to
  the digest and match the recorded size they overwrite the stored object, and
  the pull is answered from the store, `200` (or `206` for a range covering
  the whole object).
- If the fetch fails or its bytes do not match, the pull keeps the `502` and
  the stored object is not touched. A proxy-cache copy that does not match is
  evicted, and the upstream is asked once.
- A larger blob, or a small one that had no room in the verification budget,
  is only found corrupt after the `200` went out. That transfer is aborted as
  above and the object is repaired in the background, so the client's retry
  succeeds.
- The new bytes are spooled in the upload staging directory
  (`AK_UPLOAD_STAGING_DIR`, default `<STORAGE_PATH>/.incoming`) while they are
  checked, so a repair needs free space there for one copy of the blob.
- A `HEAD`, a range for part of the object and a presigned redirect
  (`PRESIGNED_DOWNLOADS_ENABLED`) read no whole object here, so they do not
  detect corruption and do not start a repair.

Hosted (local and staging) repositories have no upstream and keep the `502`.

Each repair logs its outcome at `info` (`Repaired a corrupt stored blob from
upstream`) or `warn` (`Could not repair a corrupt stored blob from upstream`).

## Cost

Every checked serve hashes the bytes it sends (SHA-256, one pass, no second
read of the object). An object of at most 4 MiB is held in memory until it has
been checked, so its first byte leaves only after its last byte was read, and
it stays in memory until the client has read it. Those buffers share one
process-wide budget, `AK_SERVE_VERIFY_BUFFER_BUDGET_BYTES` (default 256 MiB,
#4989). When it is full, a small object streams and is checked like a large
one: still never delivered complete if it is corrupt, but aborted instead of
answered `502`. The budget's metrics are in
[load shedding](load-shedding.md#download-verification-memory-budget). A
larger object streams with one chunk held back. Virtual-repository `HEAD`
requests that a format route resolves through a member walk still read a
small object to check it; on the generic route they read nothing.

Each failure logs `stored object failed integrity verification on serve`
at error level with the object, the expected and actual digest and length.
Run the storage scrub (`POST /api/v1/admin/storage-scrub`) to find other
damaged objects.

## Turning it off

`DOWNLOAD_VERIFY_CHECKSUMS=false` (default `true`) turns verification off on
every route above. Integrity is then the client's responsibility.
