# Chunked uploads into format repositories

The resumable upload API (`/api/v1/uploads`) accepts large artifacts in
chunks: create a session, `PATCH` each chunk with `Content-Range`, then
complete it with `PUT /api/v1/uploads/{session_id}/complete`. The completion
verifies the size and SHA-256 declared at session create, stores the bytes
under their content-addressed key and commits the artifact row.

## Format processing on completion (#1846)

The completion resolves the session's repository format. When the format has a
native upload route that indexes the artifact, the completion runs the parsers
that route runs and records the rows it records, so the artifact appears in the
format's own index exactly as a single upload through the native route makes it
appear. A package the native route would refuse is refused with `400` and
nothing is stored; the session is failed.

| Format | Paths indexed | What the completion derives | Index it appears in |
|---|---|---|---|
| Maven, Gradle | any GAV path except checksum sidecars and `maven-metadata.xml` | name = artifactId, version from the path; for a `.pom`, the POM's name, description, URL and dependencies | generated `maven-metadata.xml`, grouped `groupId:artifactId` listings |
| npm | `{package}/{version}/{file}.tgz` (scoped: `@scope/name/...`); the registry URL layout `{package}/-/{file}.tgz` stays generic | the tarball's root `package.json`, which must name the same package and version as the path (compared as npm normalizes them: case-insensitive name, version without a leading `v` or build metadata) | the packument (`GET /npm/{repo}/{package}`), with `package.json` as the version document |
| PyPI | a wheel or sdist file name (`name-version-...whl`, `name-version.tar.gz`) | the archive's `METADATA` or `PKG-INFO`, which must name the same project and version as the file name, plus the content analysis twine uploads get | `/simple/{project}/` with `data-requires-python` |
| RPM | `name-version-release.arch.rpm` | the header metadata, install scriptlets, catalog entry under the NEVRA name | `repodata/primary.xml.gz` |
| Incus, LXC | `{product}/{version}/{file}` | image metadata (arch, os, release) | `streams/v1/images.json` |
| Debian | `pool/{component}/...` packages | the control file, which must agree with the file name, and maintainer scripts | `Packages` |

Other formats still get a format dispatch on completion (#5002): the
completion runs the format handler's `parse_metadata` against the artifact
path, with an empty body, and records the document it returns. A handler that
does not recognise the path, and the generic handler whose document is only the
path, record nothing and keep the generic behaviour: the artifact is named
after its file and its version comes from the session or the path. Paths a
native format's route would not index (a Maven checksum sidecar, an RPM file
that is not a package) stay generic too.

A trusted replication session (an administrator or service account sending the
replication header with source metadata) keeps the metadata the source
instance sent instead.

Like the native routes, the completion applies the repository's upload
quarantine hold (when enabled) and its storage quota; only a trusted
replication session is exempt from the quota.

The artifact keeps the content-addressed storage key every chunked upload
uses. Format download routes read the key from the artifact row, so artifacts
committed before this change remain readable unchanged; they are not
re-indexed retroactively. Re-upload one through the chunked API, or through its
native route, to index it.

On an S3-, GCS- or Azure-backed repository a Maven POM or npm tarball is parsed
from the staged chunks; RPM, PyPI, Incus and Debian packages are assembled into
a local scratch file first (see `docs/operations/upload-scratch-disk.md`).

## Incus native chunked uploads (deprecated)

Incus clients can still start, continue and finish an image through the
format's own chunked endpoints:

- `POST /incus/{repo_key}/images/{product}/{version}/{filename}/uploads`
- `PATCH`, `PUT`, `GET` and `DELETE /incus/{repo_key}/uploads/{uuid}`

These endpoints predate `/api/v1/uploads` and keep their own session and
staging state. They are deprecated in favour of the shared resumable API, and
every response now carries the RFC 9745 and RFC 8288 headers:

```http
Deprecation: @1793404800
Link: </api/v1/uploads>; rel="successor-version"
```

The headers are added even to error responses, so a client or an intermediary
can surface the migration without parsing the body. The native routes remain
functional until a future removal; use `/api/v1/uploads` with an Incus
repository for new integrations.

## Asynchronous completion

A completion that has to parse a multi-GiB package can outlast the timeout of a
proxy or load balancer in front of the server. Send `Prefer: respond-async`
(RFC 7240) with the completion request to get `202 Accepted` as soon as the
server holds the session's completion lease. The response carries
`Location: /api/v1/uploads/{session_id}` and `Preference-Applied:
respond-async`, and its body is the session status. Poll that location:

| `status` | Meaning |
|---|---|
| `committing` | still running |
| `completed` | committed; `artifact_id` names the artifact |
| `failed` | refused for good (checksum mismatch, a package the format refuses, quota); `error` says why |
| `in_progress` | a retryable failure released the lease (storage or database briefly unavailable, identical content being collected by storage GC); repeat the completion request |

Without the header the completion answers in the request, as before.

The background commit runs on the replica that accepted the request. It does
not survive a restart of that replica: the session then stays `committing`
until its completion lease lapses (ten minutes after the last renewal), after
which the same completion request can be sent again; the staged chunks are
kept until then. The renewal loop extends the lease every few minutes while the
commit is alive, so a slow parse or a large server-side copy keeps it; a
crashed replica stops renewing and the session becomes retryable in ten
minutes rather than six hours. A `Prefer` header without `respond-async` (or
with an unrecognised preference) is ignored and the completion answers in the
request.
