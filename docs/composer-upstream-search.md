# Composer search through a Remote's upstream

`GET /composer/{repo}/search.json` answers from hosted packages: a Local or
Staging repository's own, a Remote's cached ones, and a Virtual's readable
Local and Staging members (#6285). A Remote can also forward the search to its
upstream (Packagist serves `search.json`) and merge the upstream's hits after
the local ones (#6332).

## Turning it on

Forwarding sends the search term, which may be an internal package name, to
the upstream. It is **off** for every Remote until an administrator turns it
on for that Remote:

```bash
curl -X PATCH "$AK/api/v1/repositories/packagist-remote" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"composer_upstream_search": true}'
```

The setting is accepted on create too, is read back as
`composer_upstream_search` on a Composer Remote, and is refused (`400`) on any
other repository. It is stored in `repository_config` under
`composer_upstream_search`. A Virtual forwards only to its Remote members that
have it on.

## What a search returns

Every source is asked for the same page (`q`, `type`, `page`, `per_page`):

1. hosted hits first (for a Virtual, its Local and Staging members in priority
   order);
2. then each forwarding Remote's upstream hits, in member priority order.

A package name appears once, from the first source that has it. Each hit's
`url` points at the repository that was asked. `total` is the sum of the
sources' totals, an upper bound when sources share names, and `next` is set
while any source has another page.

Upstream hits pass the curation rules of the Remote they came from and, for a
Virtual search, of the Virtual: a `block` rule (or a rule evaluation error)
drops the hit. Composer has no age gate, and a search hit names a package
rather than a version, so no version rule applies to search; the client
fetches the package metadata to choose a version.

## Limits and failures

| | |
| --- | --- |
| Body | At most 1 MiB per upstream answer, read under a buffered-metadata budget permit. |
| Time | `AK_COMPOSER_UPSTREAM_SEARCH_TIMEOUT_SECS` (default `5`), never above the virtual member deadline (`AK_VIRTUAL_MEMBER_METADATA_TIMEOUT_SECS`). |
| Fan-out | At most 4 forwarding Remote members per Virtual search. |
| Sharing | Identical searches share one upstream read while it is in flight and for 60 seconds after, in a cache bounded at 16 MiB. The key is the Remote, its upstream URL, a fingerprint of its upstream credentials, and every search parameter, so two Remotes, or one Remote before and after a credential change, never share an answer. |

An upstream that is down, slow, answers `5xx` or something that is not a
search answer contributes nothing, and the search still answers `200` with
the local hits. The unavailable Remotes are named in `X-AK-Partial-Members`.
A Virtual that found nothing at all while a forwarded member was unavailable
answers `503` with `Retry-After` (the virtual rule of #5495), because "no such
package" cannot be known then. An upstream that has no search (`404`) is a
miss, not an outage. Unavailable answers are not cached.

`ak_composer_upstream_search_fetches_total{outcome}` counts upstream reads
(`page`, `miss`, `unavailable`); a search served from the cache reads nothing
and is not counted.
