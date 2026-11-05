# Upstream filters on Remote repositories

A Remote repository can be limited to a set of paths it is allowed to request
from its upstream. A path the filter refuses answers 404 without anything being
sent upstream, and a Virtual repository skips that member for the path.

```bash
# Allow only the com.acme Maven group
curl -X PUT https://registry.example.com/api/v1/repositories/maven-remote/upstream-filter \
  -H "Authorization: Bearer $AK_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"include_patterns": ["^com/acme/"], "exclude_patterns": []}'

# Read it back, or remove it
curl -H "Authorization: Bearer $AK_ADMIN_TOKEN" \
  https://registry.example.com/api/v1/repositories/maven-remote/upstream-filter
curl -X DELETE -H "Authorization: Bearer $AK_ADMIN_TOKEN" \
  https://registry.example.com/api/v1/repositories/maven-remote/upstream-filter
```

The calls need repository admin rights and work on Remote repositories only.
Sending two empty lists removes the filter.

## Rules

- **`include_patterns`**: if the list is non-empty, a path is fetched only when
  it matches at least one entry.
- **`exclude_patterns`**: a path matching any entry is never fetched.
  Exclusion wins over inclusion.
- Patterns are regular expressions in Rust
  [`regex`](https://docs.rs/regex/latest/regex/#syntax) syntax, matched
  **anywhere** in the subject. Anchor them with `^` and `$`: `com/acme/` also
  matches `org/evil/com/acme/...`, while `^com/acme/` does not.
- Matching is case-sensitive; prefix a pattern with `(?i)` to ignore case.
- Limits: 64 patterns per list, 512 bytes per pattern, and each list must
  compile to a small program (an expensive pattern such as `(\w{1000}){1000}`
  is rejected when it is saved). A path longer than 4 KiB is refused.

## The subject

The pattern is matched against the path as it would be sent upstream:
relative to the Remote's `upstream_url`, without a leading `/`, with the query
string if there is one. That is often not the path the client asked for:

| Format | What the subject looks like |
|--------|-----------------------------|
| Maven, Debian, RPM, Go and similar | The repository layout path: `com/acme/lib/1.0/lib-1.0.jar` |
| OCI | `v2/<name>/manifests/<ref>`, `v2/<name>/blobs/<digest>` |
| npm | Metadata is requested as `@scope%2Fname`, tarballs as `@scope/name/-/name-1.0.0.tgz`. Match both: `^@acme(/|%2F)` |
| Hugging Face | Model info is `api/models/<org>/<name>...`, files are `<org>/<name>/resolve/...`. Match both: `^(api/models/)?acme/[^/]+(/|$)`. See [Hugging Face](huggingface.md#restricting-which-models-a-remote-can-fetch) |
| PyPI files, cargo `dl` hosts, NuGet service URLs | The full absolute URL (`https://files.pythonhosted.org/...`), unless it lies under `upstream_url` |

npm and Hugging Face are the two formats where one package is fetched under
two path shapes, so a pattern written for only one shape breaks installs:
metadata is refused while files are allowed, or the other way round.

Only the request to the upstream is matched. Redirects the upstream answers
with (to a CDN, for example) are followed without being filtered again.

The filter also applies to the npm `/-/` passthroughs and audit, the curation
upstream sync (RPM and Debian index walks, PyPI attestation enrichment) and
the admin `test-upstream` probe, which requests the upstream root (an empty
subject). The npm upstream change feed is not filtered: it is a single global
subscription with no per-repository path.

## Already-cached content

A cached object whose path the filter now refuses is served only while its
cache entry is fresh. Once it expires it is not revalidated, since that would
contact the upstream, and it is not served stale either: it answers 404 like
a miss. Immutable entries (released Maven artifacts, content-addressed blobs)
effectively never expire, so purge them to hide them at once, one path per
call (the `path` is the artifact path, as in
`GET /api/v1/repositories/{key}/artifacts/{path}`):

```bash
curl -X POST -H "Authorization: Bearer $AK_ADMIN_TOKEN" \
  "https://registry.example.com/api/v1/repositories/maven-remote/cache/invalidate?path=com/evil/lib/1.0/lib-1.0.jar"
```

## Propagation

A change applies at once on the replica that saved it and is pushed to the
others; a replica that missed the notification picks it up within 30 seconds.
A stored filter that can no longer be parsed or compiled refuses every path
rather than letting everything through.
