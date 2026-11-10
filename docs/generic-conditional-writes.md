# Conditional writes on generic repositories

`PUT /api/v1/repositories/{key}/artifacts/{path}` accepts the HTTP
preconditions `If-Match` and `If-None-Match` (RFC 9110 section 13), so a tool
that keeps an index document (`index.yaml`, a lock file, a manifest) in a
generic repository can update it without losing a concurrent writer's change
(#4186). The multipart upload routes (`POST .../artifacts/{path}` and
`POST .../artifacts`) evaluate the same headers.

## The ETag

An artifact's entity tag is its recorded SHA-256 in double quotes:

```
ETag: "3bfc269594ef649228e9a74bab00f042efc91d5acc6fbee31a382e80d42388fe"
```

It is returned on the upload's `201` and on `GET` / `HEAD` of
`/api/v1/repositories/{key}/download/{path}` (next to `X-Checksum-Sha256`,
which carries the same value unquoted). It is a strong tag.

A download through a virtual repository carries the validator of the member
that served it: a hosted member's quoted SHA-256 as above, or a remote
member's upstream `ETag`. A ranged `GET` with `If-Range` naming that value
answers `206`; any other value answers `200` with the whole object (#5615).

## Preconditions

| Header | Write proceeds when | Otherwise |
|---|---|---|
| `If-Match: "<sha256>"[, ...]` | the path holds a live artifact whose ETag is listed | 412 |
| `If-Match: *` | the path holds a live artifact | 412 |
| `If-None-Match: *` | the path holds no live artifact (absent or deleted) | 412 |
| `If-None-Match: "<sha256>"[, ...]` | the live artifact's ETag is not listed | 412 |

`If-Match` uses the strong comparison, so a weak tag (`W/"..."`) never
matches. A header that is not `*` or a list of quoted tags is a 400, so a
typo cannot silently turn a compare-and-swap into a blind write.

A matched `If-Match` replaces the live artifact, also on a repository
without versioning, where an unconditional second upload to an occupied
path is a 409. On a versioning-enabled repository it appends a revision, as
an unconditional upload does. A released coordinate (a path with a version
segment such as `pkg/1.0/pkg.tgz`) still cannot change its bytes: that is a
409 with or without a precondition.

## Concurrency

The precondition is checked before the body is read, so a client that lost
the race does not upload a body that would be discarded, and again when the
upload commits, with the artifact row locked. Of several conditional uploads
against the same ETag exactly one gets 2xx and every other gets
`412 PRECONDITION_FAILED`:

```json
{"code": "PRECONDITION_FAILED", "message": "Precondition failed: the current state of 'index.yaml' does not match If-Match / If-None-Match"}
```

A client that gets 412 re-reads the document (its new ETag is on the
download), re-applies its change and retries.

## Example

```bash
etag=$(curl -sI -u "$AUTH" "$AK/api/v1/repositories/tools/download/index.yaml" \
  | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')
curl -s -u "$AUTH" -X PUT -H "If-Match: $etag" --data-binary @index.yaml \
  "$AK/api/v1/repositories/tools/artifacts/index.yaml"
```

## Storage

The object a conditional replace leaves without any row is recorded as a
storage GC candidate (`oci_gc_candidates`); the candidate sweep deletes it
after the grace window unless another artifact still references the same
content. See `docs/operations/storage-gc.md`.
