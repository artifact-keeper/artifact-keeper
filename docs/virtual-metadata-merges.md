# Virtual repository metadata merges

Some formats serve a virtual repository's index by merging the documents of
its members: Helm `index.yaml`, conda `repodata.json` / `channeldata.json` /
the CEP-16 shard index, Maven `maven-metadata.xml` (and its `.sha1`, `.md5`,
`.sha256`), and the CRAN, Hex, Puppet and Bazel indexes. Hosted members
contribute what they hold. Each Remote member's document is fetched from its
upstream through the proxy cache, bounded by a per-member deadline.

## What each Remote member's answer does to the merge

| Member answer | Effect on the merge |
|---|---|
| A document | Merged. |
| `404`, or another permanent `4xx` (`401`, `403`, `451`, ...) | A miss. The member contributes nothing and the merge is complete. This matches the artifact walk. |
| Unavailable: an upstream `5xx`, a transport failure or connect timeout, a retryable `408`/`425`/`429`, or no answer within the member deadline | The member is left out. The merge of the members that answered is served as a **partial** response (below). Maven `maven-metadata.xml` and `.meta/prefixes.txt` are strict by default and answer the retryable `503` instead; see [Maven virtual metadata](#maven-virtual-metadata). |
| A document that cannot be read: it does not parse, does not decode, or exceeds the member size ceiling (conda) | **Strict** by default: `502` naming the member. Partial when the virtual opted in with `virtual_metadata_partial` (below). |

When no member contributed (there is no hosted member, and no Remote member
served the document) and at least one member was unavailable, the answer is
`503 Service Unavailable` with `Retry-After`. It is never a `404` or an empty
index, because Maven, Gradle, Helm and conda clients cache those as "no
versions". When every member answered a permanent `404`/`4xx`, the answer is
the format's normal not-found.

## Partial responses

A partial response carries:

- `X-AK-Partial-Members: <member-key>[,<member-key>...]`: the members it lacks.
- `Cache-Control: no-store`, and no `ETag`.
- `Warning: 199 - "partial merge: members <keys> are missing"`.

A partial merge is never kept in the server's own merge caches. The next
request asks the missing members again. Each member left out is counted in
`ak_virtual_member_metadata_failures_total{format,virtual_repo,member,reason}`.
`reason` is `fetch`, `timeout`, `cap`, `decode` or `parse`. A member that
misses the deadline is also counted in
`ak_virtual_member_metadata_timeouts_total{member}`.

A response built from a member body served under the `stale-if-error` grace
also carries `Warning: 110` and `X-AK-Stale-Since`. See
[proxy cache freshness](proxy-cache-freshness.md).

## The member deadline

`AK_VIRTUAL_MEMBER_METADATA_TIMEOUT_SECS` (default `20`) bounds how long one
Remote member may take to answer a metadata fetch. For conda this covers every
encoding the member is asked for (`.zst`, `.bz2`, `.json`). A member past the
deadline is treated as unavailable, so a hung upstream in front of a healthy
one delays the merge by the deadline, not by the upstream client's own 60 s
timeout. Raise it if a member's cold metadata fetch (for example a large conda
channel's `repodata.json.zst` over a slow link) takes longer.

Artifact downloads through a virtual repository have a separate deadline,
`AK_VIRTUAL_MEMBER_DOWNLOAD_DEADLINE_SECS`. See
[virtual downloads](virtual-downloads.md).

## Maven virtual metadata

The Maven `maven-metadata.xml` merge (GA, plugin-prefix and SNAPSHOT
version-level documents, plus their checksums) and the `.meta/prefixes.txt`
union are strict by default: when any member was unavailable, the answer is
the retryable `503` with `Retry-After`, even if other members answered. A
merged `<versions>` list without that member makes Maven pick the wrong
`latest`/`release` and resolve a version range without its versions, and a
partial prefix allowlist makes Resolver skip everything behind the missing
member. Set `virtual_metadata_partial` on the virtual repository to serve the
merge of the answering members instead, marked partial and uncacheable
(#5777).

## `virtual_metadata_partial`

Set on a virtual repository through the repository API. For the formats whose
unavailable-member merges are already partial, the setting controls only the
strict case: a member that answered with a document that cannot be read. For
Maven virtual metadata it also selects strict versus partial for an
unavailable member (see [Maven virtual metadata](#maven-virtual-metadata)).

```bash
curl -X PUT "$AK/api/v1/repositories/<virtual-key>" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"virtual_metadata_partial": true}'
```

`true` serves such a merge as partial. `false` (the default) answers `502`.
`GET /api/v1/repositories/<key>` and the repository listing report the
current value as `virtual_metadata_partial` on virtual repositories. It is
`false` when never set, and the field is omitted for other repository types.
Setting it on a non-virtual repository is refused with `400`.
