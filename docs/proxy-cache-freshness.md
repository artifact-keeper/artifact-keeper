# Proxy cache freshness and the yank asymmetry

Remote and Virtual repositories cache upstream responses on disk. Every cached
response is classified as **mutable** or **immutable**, and the two classes
expire on radically different schedules. That split explains the one symptom
operators find surprising: an upstream **yank** makes a resolve-then-fetch
client (npm, pip, Maven, …) fail at *resolution* even though the package's
artifact is still cached and downloadable.

## Two lifetimes

| Class | Examples | Default lifetime | On expiry |
| --- | --- | --- | --- |
| **Mutable** | npm packument, PyPI simple index, `maven-metadata.xml`, OCI tag, Go `@v/list`, Cargo sparse index, conda `repodata.json`, RPM `repomd.xml`, Hugging Face `resolve/main/...` and model info at a branch, Go checksum database tree head (`sumdb/<host>/latest`) | 300 s (5 min) | revalidated against upstream, then refilled |
| **Immutable** | npm tarball (`…/-/<pkg>-<ver>.tgz`), wheel/sdist, `.jar`, `.crate`, OCI digest blob, RPM package, Hugging Face file or model info at a 40-hex commit sha (`<model>/resolve/<sha>/...`), Go checksum database tiles and `lookup/<module>@<version>` | 315360000 s (~10 years) | never expires, never revalidated |

Classification is by **path shape**, not by format alone — see
`backend/src/services/cache_classifier.rs`. The bias is deliberate: a mutable
path misclassified as immutable would serve stale pointers forever, whereas the
reverse only costs a cheap revalidation.

## Revalidation and stale-if-error

When a mutable entry passes its TTL the proxy **revalidates** it with a
conditional request:

- **304 Not Modified** → the TTL is extended and the cached body is served.
- **200 with new content** → the body is refilled.
- **5xx, timeout or transport error** → **stale-if-error** (RFC 5861): the stale
  body is served for up to the repository's grace window past expiry (3600 s by
  default, see [below](#the-stale-if-error-grace-window-4581)) and is marked as
  stale. This is the *only* case where expired content is served as a fallback.
- **404 or 410** → **not** stale-if-error. A definitive "not here" is treated as
  a real answer and **deletes the cached body** (see below) — unless the
  repository opts into `on_upstream_not_found = keep` (#4640), which serves the
  cached body instead (see below).

## The stale-if-error grace window (#4581)

The grace window bounds how long past its expiry a cached body is still served
when upstream is unreachable. It applies on every fetch path (buffered and
streaming, revalidation and a refill whose upstream fetch fails), measured from
the entry's stamped expiry. Past it, the upstream error is returned instead.

- **Instance default**: `PROXY_STALE_IF_ERROR_GRACE_SECS`, default `3600`
  (the previously hard-coded value), clamped to `[0, 2592000]` (30 days). `0`
  disables serving stale bodies.
- **Per repository** (Remote only), same administrative tier as the cache TTL:

```bash
curl -X PUT "$AK/api/v1/repositories/<key>/stale-if-error-grace" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"stale_if_error_grace_seconds":600}'

# Read it back: the override, the effective value and when this replica last
# served a stale response for the repository (within the past day).
curl "$AK/api/v1/repositories/<key>/stale-if-error-grace" \
  -H "Authorization: Bearer $TOKEN"
```

A response served under the grace carries `Warning: 110 - "Response is stale"`
and `X-AK-Stale-Since: <RFC 3339 instant the entry expired>`, including a
virtual repository merge with a stale member, and increments
`ak_proxy_stale_if_error_responses_total{repo="<key>"}`. A fresh hit, a body
confirmed by a `304` revalidation and a copy served under
`on_upstream_not_found = keep` carry neither header.

## Negative caching

A definitive upstream **404 / 410** on a cacheable path writes a
**negative-cache marker**: any cached positive body for that path is deleted,
and for the next 45 s (`NEGATIVE_CACHE_TTL_SECS`) reads answer `404` straight
from the marker, without contacting upstream. (An upstream 410 is cached the
same way and is also served as `404` — a gone object is the same statement, one
step more definite.) The marker is a hot-loop guard: a miss for a
not-yet-published artifact must not hammer the origin. If upstream is still 404
when the marker expires, the next request re-checks, gets 404 again, and
refreshes the marker, so the 404 persists for as long as upstream keeps saying
404.

## Keeping content upstream has withdrawn (`on_upstream_not_found`, #4640)

Deleting on a definitive 404/410 is right when upstream is the source of truth.
It is wrong when the proxy cache is used as a **continuity copy** of an external
registry that may retract, rename or takedown content: the bytes are already on
local disk, and only upstream has stopped serving them.

A remote (proxy) repository can make that a choice:

```bash
# Serve the cached copy when upstream answers 404/410 (the continuity stance).
curl -X PUT "$AK/api/v1/repositories/<key>/on-upstream-not-found" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"on_upstream_not_found":"keep"}'

# Read it back (any repository type; non-remote repositories report the default).
curl "$AK/api/v1/repositories/<key>/on-upstream-not-found" \
  -H "Authorization: Bearer $TOKEN"
```

| Value | On a definitive upstream 404/410 for a cached path |
| --- | --- |
| `delete` *(default)* | Delete the cached body and write a negative-cache marker. Today's behaviour. |
| `keep` | Serve the cached body, leave it in place and write no marker. |

Details that make `keep` safe:

- **Nothing unsaid is kept.** A path that was never cached still answers `404`
  and is still negative-cached, so a hot loop of misses does not hammer
  upstream.
- **The normal TTL is kept.** The entry's expiry is *not* extended on a 404/410,
  so a later upstream `200` (a re-publish) is picked up on the next
  revalidation.
- **The other gates still apply.** The Package Age Policy / quarantine hold,
  curation and lifecycle policy still gate a kept copy exactly as they gate a
  fresh hit.
- **It is observable.** Every kept serve increments
  `ak_proxy_kept_on_upstream_not_found_total{repository="<key>"}`, so an
  operator can list the content being kept past its upstream life and evict it
  deliberately with `POST /api/v1/repositories/{key}/cache/invalidate?path=<path>`.
- **It covers every fetch path**: the buffered and streaming proxy paths, the
  conditional `HEAD` revalidation probe, and the npm computed-packument cache.

`on_upstream_not_found` is a per-repository policy on the same administrative
tier as the cache TTL and repository delete/update: it needs the
`write:repositories` scope and `admin` on the repository for non-administrators.

## Cache-only (offline) mode (`upstream_mode`, #5282)

A Remote that was seeded while connected and then cut off can be declared
**cache-only**. It then serves what it holds and never contacts its upstream:

```bash
# Take the Remote offline: serve the cache, never contact upstream.
curl -X PUT "$AK/api/v1/repositories/<key>/upstream-mode" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"upstream_mode":"cache_only"}'

# Read it back. `effective_upstream_mode` is `cache_only` whenever the
# instance-wide PROXY_UPSTREAM_MODE=cache_only override is set.
curl "$AK/api/v1/repositories/<key>/upstream-mode" \
  -H "Authorization: Bearer $TOKEN"

# Back online: the next read of an expired entry revalidates as usual.
curl -X PUT "$AK/api/v1/repositories/<key>/upstream-mode" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"upstream_mode":"online"}'
```

| Value | Behaviour |
| --- | --- |
| `online` *(default)* | Normal pull-through proxying, revalidation and stale-if-error. |
| `cache_only` | No upstream contact. Every cached entry is served, fresh or stale. A miss is `404`. |

In `cache_only`:

- **Nothing leaves the process.** The mode is checked by the same gate as the
  upstream filter, which every proxy fetch, the stale revalidation probe, the
  npm `/-/` passthroughs and `npm audit`, the curation upstream sync and the
  `test-upstream` probe pass through. A miss therefore answers at once, even
  when the upstream address drops packets.
- **Stale entries are served, not revalidated.** An expired mutable entry
  (`maven-metadata.xml`, a packument, an index) is served as it is, with no
  grace window, and is marked with `Warning: 110` and `X-AK-Stale-Since` like a
  stale-if-error serve. It does not count toward
  `ak_proxy_stale_if_error_responses_total` or `last_stale_served_at`: the
  upstream was not tried.
- **A miss names the mode.** The `404` reason is
  `not in cache; repository '<key>' is cache-only`, so "not seeded" is
  distinguishable from "excluded by the upstream filter". A miss writes no
  negative-cache marker; a marker written while online still answers `404`
  until it lapses. Each miss counts as
  `ak_proxy_cache_lookups_total{result="cache_only_miss"}`.
- **Virtual repositories skip the member.** A cache-only member that does not
  hold the path is skipped without contact, so the next member answers with no
  wait.
- **Switching back takes effect at once** on the replica that served the `PUT`
  and on the others through the cache-invalidation channel (at most 30 s if
  that notification is lost); no restart.

The setting is Remote-only (`400` on other types), needs the
`write:repositories` scope and `admin` on the repository, and each change is
recorded as `REPOSITORY_UPDATED` with `upstream_mode_change`
`{previous_upstream_mode, upstream_mode}`. Setting `PROXY_UPSTREAM_MODE=cache_only`
in the environment puts every Remote in cache-only mode at once (read at
startup).

### How it differs from an exclude-everything upstream filter

An upstream filter with `exclude_patterns: [".*"]` also stops upstream contact,
but it is a security control, not an offline mode: an expired entry for a
refused path is refused with `404` instead of served (so a seeded index file
disappears once its TTL passes), and the `404` gives the filter's reason. Use
`upstream_mode` for "disconnected now", and the filter for "never fetch this".

## The yank asymmetry

Combining the two lifetimes produces a symptom that looks like a cache bug but
is a direct consequence of the design:

1. `npm install <pkg>` caches two things: the **packument** (`/<pkg>`, mutable,
   5 min) and the **tarball** (`/<pkg>/-/<pkg>-<ver>.tgz`, immutable, ~10 years).
2. The upstream registry **yanks** the version (or the whole package).
3. Within 5 minutes the packument's TTL elapses; the proxy revalidates; upstream
   answers **404**; the cached packument body is **deleted** and a negative
   marker is written.
4. `npm install` now fails at **resolution** — `404 Not Found - GET /<pkg>` —
   because the packument is gone.
5. The **tarball still serves** (immutable), so fetching the exact tarball URL
   still returns `200` and downloads the bytes.

So the package manager reports "not found" while Artifact Keeper still holds the
artifact. The metadata and the artifact expired on different schedules — that is
the entire story. It is expected behaviour, not cache corruption, and it is
format-general: any format whose mutable metadata points at immutable artifacts
behaves this way (PyPI simple index vs wheel, `maven-metadata.xml` vs `.jar`,
OCI tag vs digest blob, Cargo index vs `.crate`, conda repodata vs package, …).

## What to do about it

- **Resolution vs download.** A failed resolution does not mean the artifact is
  unavailable. Given the exact tarball/artifact URL, fetch it directly —
  immutable entries keep serving.
- **`npm ci` with a lockfile.** `npm ci` installs straight from the lockfile, so
  it can fetch the already-pinned tarball URLs (which still serve) without
  re-resolving the packument. It is `npm install` — which may re-resolve
  metadata — that surfaces the yank.
- **After an upstream re-publish.** Resolution recovers automatically as soon as
  upstream answers again. While upstream keeps returning 404, the marker is
  refreshed every 45 s and resolution keeps failing — which is correct: upstream
  says the version is gone.
- **Force a re-check now.** `POST /api/v1/repositories/{key}/cache/invalidate?path=<path>`
  evicts a single entry, including a negative marker, so the next request
  re-resolves immediately. It needs the `write:repositories` scope, plus `admin`
  on the repository when the caller is not an administrator.
- **The TTL override applies to mutable paths only.** `PUT /api/v1/repositories/{key}/cache-ttl`
  with `cache_ttl_seconds` (1 … 315360000) changes the mutable lifetime;
  immutable artifacts are cached forever regardless. Lowering it surfaces a yank
  *sooner*; the maximum makes mutable paths effectively never revalidate, which
  avoids surfacing the yank only by knowingly serving a stale pointer. It cannot
  make immutable artifacts expire.

Serving the stale index while the corresponding artifacts are still held is a
deliberate behaviour change — it contradicts the "a definitive 404 deletes the
cached body" invariant — and is therefore **opt-in** per repository, not the
default: see [`on_upstream_not_found`](#keeping-content-upstream-has-withdrawn-on_upstream_not_found-4640)
above (#4640).

## See also

- [cache-seed.md](cache-seed.md) — fill a Remote's cache from a list of paths
  ahead of time, with a per-path inventory (#5284).
- `backend/src/services/cache_classifier.rs` — classification rules and TTL
  constants (`MUTABLE_DEFAULT_TTL_SECS`, `NEGATIVE_CACHE_TTL_SECS`,
  `STALE_IF_ERROR_GRACE_SECS`, `STALE_IF_ERROR_GRACE_MAX_SECS`,
  `MAX_CACHE_TTL_SECS`).
- `backend/src/services/upstream_not_found_policy.rs` — the
  `on_upstream_not_found` policy shared by the proxy and the npm packument
  cache (#4640).
- `backend/src/services/upstream_mode.rs` — the `upstream_mode`
  (online / cache-only) setting and its gate (#5282).
- `backend/src/services/proxy_service.rs` — revalidation, stale-if-error and
  negative caching on the buffered and streaming paths.
- Cache-correctness invariants: #1611, #3749 (410 negative-cached like 404).
- #4028 — the yank asymmetry documented above.
- #4640 — the opt-in `on_upstream_not_found` policy.
- #3990 — the planned mirror `on_upstream_delete` policy, which shares the
  `keep` / `delete` vocabulary.
