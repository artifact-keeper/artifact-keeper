# Virtual repository artifact downloads

A download through a virtual repository (a Maven JAR, an npm tarball, a PyPI
wheel, an OCI blob, ...) is served by the first member, in priority order, that
holds the artifact. Hosted members answer from the database and storage. Each
Remote member answers from its proxy cache, or else from its upstream.

The members that need an upstream request are asked in parallel once the
highest-priority one has missed. The answer is still settled in priority
order: a lower member's copy is served only once every member above it has
missed or is unavailable.

## What each Remote member's answer does to the download

| Member answer | Effect |
|---|---|
| The artifact | Served, unless a higher-priority member is still within its deadline. |
| `404`, or another permanent `4xx` (`401`, `403`, `451`, ...) | A miss. The next member is tried. |
| Unavailable: an upstream `5xx`, a transport failure or timeout, nothing within the download deadline, or an open member breaker (below) | The next member is tried. When no member serves, the answer is `503 Service Unavailable` with `Retry-After`, not `404`. With [strict member fallback](#strict-member-fallback), the `503` is answered at once. |
| A Package Age Policy hold, a quarantine or scan-policy block | Terminal: the block is returned and no lower member is tried. |

## The download deadline

`AK_VIRTUAL_MEMBER_DOWNLOAD_DEADLINE_SECS` (default `20`) bounds how long one
Remote member may take to start answering. It is measured from the request to
that member until its response headers arrive and, when the member declares a
`Content-Length`, its first body byte. The body transfer is never bounded by
it: a large artifact that has started streaming takes as long as it takes.

A member past the deadline is treated as unavailable for this request. Its
late answer is discarded and the next member in priority order is settled. A
hung member in front of a healthy one therefore delays the download by the
deadline, not by the upstream client's own read timeout
(`PROXY_UPSTREAM_READ_TIMEOUT_SECS`, default `60`).

- The value is capped at `PROXY_UPSTREAM_READ_TIMEOUT_SECS`.
- `0` disables the deadline: every member is waited for until its upstream
  client gives up.
- Each miss is logged at `WARN` with the member and the path, and counted in
  `ak_virtual_member_download_timeouts_total{member}`.

The deadline does not change the order between members that answer in time.
A member that answers within the deadline wins over every member below it,
even one that answered sooner.

### Content-addressed downloads

An OCI blob is requested by its digest. Any member's copy is the same bytes:
the client verifies the digest, and the proxy cache keeps only bytes that
match it. The deadline applies there in the same way.

## The member breaker

A Remote member that keeps failing would cost every download one deadline
before the next member serves. After `AK_VIRTUAL_MEMBER_BREAKER_FAILURES`
(default `3`) failures in a row, the member's breaker opens. For
`AK_VIRTUAL_MEMBER_BREAKER_OPEN_SECS` (default `30`) downloads pass over the
member without dialling it, as if it were unavailable. Then one download is
let through as a probe. If the member answers, the breaker closes. If it
fails, the breaker opens for another period.

- A failure is a missed download deadline, a connect or transport error, or
  an upstream `5xx`. An answer of any kind (`200`, `404`, `401`, `403`, ...)
  closes the breaker and resets the count. A `408`, `425` or `429` neither
  trips nor resets it.
- For OCI blobs only a missed deadline trips the breaker.
- The state is kept in memory on each replica. Each replica learns on its own
  that a member is down, and a restart closes every breaker.
- `AK_VIRTUAL_MEMBER_BREAKER_OPEN_SECS=0` disables the breaker.
- `ak_virtual_member_breaker_open{member}` is `1` while a member's breaker is
  open and `0` once it closes. Opening is logged at `WARN`, closing at `INFO`.

## Strict member fallback

By default (`available`), a download passes over an unavailable member and
serves the next member's copy. Some virtuals must not do that: when two
members can hold different content at the same coordinates, the lower
member's copy is a different artifact, not a fallback. Set
`virtual_member_fallback` to `strict` on such a virtual repository through the
repository API:

```bash
curl -X PUT "$AK/api/v1/repositories/<virtual-key>" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"virtual_member_fallback": "strict"}'
```

The value can also be sent when the virtual is created
(`POST /api/v1/repositories`). `GET /api/v1/repositories/<key>` and the
repository listing report it as `virtual_member_fallback` on virtual
repositories: `available` when never set. The field is omitted for other
repository types, and setting it on one is refused with `400`. Any value
other than `available` or `strict` is refused with `400`.

In strict mode, the first member in priority order that is unavailable ends
the download with `503 Service Unavailable` and `Retry-After`. No lower
member's copy is served. The client retries, and the download succeeds once
that member answers again.

- A `404` or another permanent `4xx` is still a miss: the next member is
  tried.
- A member that serves, and a Package Age Policy hold or a quarantine or scan
  block, behave as they do by default.
- Only the members ranked above the one that serves matter. A member ranked
  below it is never waited for.
- With the [download deadline](#the-download-deadline), a hung member costs
  the deadline (20 s by default), then the download answers `503`.
- With the [member breaker](#the-member-breaker) open, the download answers
  `503` at once, without dialling the member, until the breaker lets a probe
  through.
- With nested virtual repositories, the setting of the virtual named in the
  request governs the whole walk, including the members of nested virtuals.
- Metadata merges are not affected. They have their own policy,
  [`virtual_metadata_partial`](virtual-metadata-merges.md#virtual_metadata_partial).
- An OCI blob is requested by its digest, so no member can hold different
  bytes for it. Blob pulls are not affected.
- The setting is read once per download. If the read fails, the download
  uses `available` and logs a `WARN`.

## Upgrade note

Before this release a download through a virtual repository waited for the
upstream read timeout (60 s by default) behind a higher-priority Remote
member that accepted the connection and never answered. It now waits at most
`AK_VIRTUAL_MEMBER_DOWNLOAD_DEADLINE_SECS` (20 s by default) and then serves
the next member's copy.

- If a member's upstream is slow to send the first byte of a cold artifact
  (over 20 s), raise `AK_VIRTUAL_MEMBER_DOWNLOAD_DEADLINE_SECS`.
- To keep the old behaviour, set `AK_VIRTUAL_MEMBER_DOWNLOAD_DEADLINE_SECS=0`.
- If two members can hold *different* content at the same coordinates (an
  internal mirror that republishes a version under a public name, for
  example), a lower member's copy can now be served while the higher member
  is unresponsive. Set the virtual to
  [strict member fallback](#strict-member-fallback) so it answers `503`
  instead, or give each Remote member an
  [upstream filter](upstream-filter.md) so only the member meant to serve a
  path is asked for it.

Metadata merges have their own member deadline; see
[virtual metadata merges](virtual-metadata-merges.md).
