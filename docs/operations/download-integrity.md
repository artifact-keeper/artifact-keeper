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

- The hosted downloads of Maven (including a `-SNAPSHOT` alias), npm
  tarballs, PyPI files, Cargo crates, NuGet packages (V3 flat container and
  V2) and Helm charts, and every other format route that serves a hosted row
  through the shared `serve_local_artifact` tail (#4989).
- The artifact route `GET /api/v1/repositories/{key}/artifacts/{path}` of a
  virtual repository, which serves the member's bytes. A corrupt member is the
  final `502` there too, not a `404` (#4989).

- Every proxy-cache hit of a Remote, on its own route and through a virtual
  repository, checked against the SHA-256 the cache entry's sidecar records
  (#4323). See [Proxy-cache hits](#proxy-cache-hits) for what a mismatch does.

Protobuf commit bundles are never
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
- A `HEAD` on the generic route or the artifact route, including one a
  virtual repository answers from a hosted member there (#4989), on one of the
  hosted format downloads above that stream, or one the shared hosted fetch
  answers from the artifact row, reads no body and is not checked. Helm and
  the other `serve_local_artifact` formats read the object for a `HEAD` too,
  so they check it.

## Proxy-cache hits

A Remote's cached object is verified while it streams, for every size, with
one chunk held back and nothing read ahead (#4323):

- A mismatch is known only at the end, after the `200` went out, so the
  transfer is aborted before its last bytes and the client sees a short read,
  never a complete body. Package clients retry a short read.
- The entry is evicted (body and sidecar), so the retry is a cache miss and
  fetches the object again from upstream through the Remote's usual gates
  (origin policy, Package Age Policy, scan, the expected digest where the
  format knows one). The eviction leaves an entry alone if a refill already
  replaced it.
- A `HEAD` reads no body and is not checked.
- An entry whose sidecar records no SHA-256 (an empty body, or a sidecar from
  before digests were recorded) is served unchecked, as before.
- A presigned redirect hands out the object without the bytes passing through
  the backend, so it is not checked here: the client's own integrity check
  (Cargo's `cksum`, npm's `integrity`, an OCI digest) applies.

`ak_proxy_cache_integrity_evictions_total{repository}` counts the evictions.

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
- A `HEAD` and a range for part of the object read no whole object here, so
  they do not detect corruption and do not start a repair. A presigned redirect
  (`PRESIGNED_DOWNLOADS_ENABLED`) also reads no bytes in the request, but at
  most once every 24 hours it claims a background check for that blob (#5217).
  The check hashes the stored object without delaying the redirect; on a
  mismatch it runs the same upstream repair, so the client's retry is served
  good bytes. Hosted repositories have no upstream and are not checked.

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
small object to check it; on the generic and artifact routes they read
nothing.

Each failure logs `stored object failed integrity verification on serve`
at error level with the object, the expected and actual digest and length,
and increments `ak_stored_object_integrity_failures_total`: `phase` is
`before_headers` (an object of at most 4 MiB answered `502`, or a Remote OCI
blob repaired from upstream) or `streaming` (aborted mid-transfer: a larger
object, a small one the budget had no room for, and every proxy-cache hit).
The buffered proxy-cache read, which treats a mismatch as a cache miss, is not
counted there; it shows as `ak_proxy_cache_lookups_total{result="miss_checksum_mismatch"}`. Any increase means damaged storage.
Run the storage scrub (`POST /api/v1/admin/storage-scrub`) to find other
damaged objects.

## Turning it off

`DOWNLOAD_VERIFY_CHECKSUMS=false` (default `true`) turns verification off on
every route above. Integrity is then the client's responsibility.

### Skipping it where the client checks the digest

Verification hashes every byte served, once. On a core without SHA
instructions that is the main cost of a large pull: measured on a 2013 Xeon
(E5-2680 v2), a warm 1 GiB OCI blob pull took about 8 CPU-seconds and ran at
about 140 MB/s with verification, and 1.2 CPU-seconds at about 1.2 GB/s
without it (`scripts/perf/serve-verify-large-objects.sh`,
`cargo bench --bench serve_verify`). Cores with SHA extensions (most x86
server CPUs since 2019, and Arm v8.2+) hash several times faster.

`DOWNLOAD_VERIFY_SKIP_CLIENT_VERIFIED=oci` (default unset) turns verification
off on OCI blob pulls only. A blob is fetched by its `sha256:` digest, and
`docker`, containerd, Podman and every OCI distribution client refuse a body
that does not hash to it, so a corrupt blob cannot be accepted silently. What
you give up on that route: the server no longer aborts the transfer, counts the
failure in `ak_stored_object_integrity_failures_total`, or repairs a Remote's
blob from upstream when a pull finds it corrupt; the client sees a digest
error instead. The storage scrub still finds and repairs the object. Every
other route keeps verifying. `oci` is the only accepted value today; other
names are logged at startup and ignored.
