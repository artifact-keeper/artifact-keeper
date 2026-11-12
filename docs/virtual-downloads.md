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
| Unavailable: an upstream `5xx`, a transport failure or timeout, or nothing within the download deadline (below) | The next member is tried. When no member serves, the answer is `503 Service Unavailable` with `Retry-After`, not `404`. |
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
  is unresponsive. Give each Remote member an
  [upstream filter](upstream-filter.md) so only the member meant to serve a
  path is asked for it.

Metadata merges have their own member deadline; see
[virtual metadata merges](virtual-metadata-merges.md).
