# Air-gapped and disconnected deployments

This page collects what a disconnected Artifact Keeper install needs: how to
get content onto it, which settings keep it from reaching out, which
background jobs still try, and how to prove that nothing leaves the network.
Read it before you cut the link. Once the instance is inside the enclave you
cannot search for the answer.

The page is written for the Docker Compose stack in `docker-compose.yml`. The
same settings apply to Helm and other deployments; only where you set them
changes.

## 1. Topologies

Pick one before you start. They differ in how new content reaches the
disconnected side.

| Topology | How content moves | Use when |
| --- | --- | --- |
| Seed, then disconnect | One instance fills its caches while connected, then the network is removed. | A lab, a ship, a site that is connected once and then sealed. |
| Low-side / high-side pair | A connected instance (low side) pushes to a disconnected one (high side) over the peer mesh. | There is a controlled, one-way-initiated network path between the two. |
| Bundles across a physical gap | Export to a file, carry it across, import it. | There is no network path at all. **Planned** (#2464), see below. |

### Seed, then disconnect

1. Bring the stack up on a connected network. Set
   `AUDIT_UPSTREAM_FETCHES=all` if you want the audit log to list every
   upstream request of the seed window ([section 7](#7-verification-checklist)).
2. Create the Remote repositories you need and apply the offline settings in
   [section 3](#3-remote-repositories) **before** you seed. A raised cache TTL
   only applies to an entry from its next revalidation, so set it first.
3. Fill the caches. Either pull everything the site will need through
   Artifact Keeper (run the builds, `pip install -r`, `npm ci`, `docker pull`,
   `hf download` and so on against it; every path that is fetched once is
   cached), or, where you have the list of paths, seed a Remote on the server
   side with a cache seed job ([Seeding the cache](#seeding-the-cache)).
4. Refresh the scanner databases ([section 4](#4-scanners)).
5. Put every Remote in cache-only mode
   ([Cache-only mode](#cache-only-mode)) and pause the scheduled upstream jobs
   ([section 5](#5-background-jobs-that-reach-out)).
6. Disconnect, then run the [verification checklist](#7-verification-checklist).

Anything you did not fetch in step 3 is not there afterwards. Fetch the exact
versions the site will use, not only the latest ones.

### Low-side / high-side pair over the peer mesh

The low side is connected and proxies the public registries. The high side is
disconnected. The low side pushes artifacts to the high side; the high side
never opens a connection out.

Set `PEER_INSTANCE_NAME`, `PEER_PUBLIC_ENDPOINT` and `PEER_API_KEY` on both
instances. Then, on the low side, register the high side and subscribe a
repository to it:

```bash
# On the low side: register the high side as a peer.
curl -X POST "$LOW/api/v1/peers" \
  -H "Authorization: Bearer $LOW_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name": "high-side", "endpoint_url": "https://ak.high.example", "api_key": "<token issued on the high side>"}'

# Subscribe a repository. The high side needs a repository with the same key.
curl -X POST "$LOW/api/v1/peers/<peer-id>/repositories" \
  -H "Authorization: Bearer $LOW_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"repository_id": "<repo-uuid>", "replication_mode": "push"}'

# Copy what the repository already holds (new uploads are pushed as they land).
curl -X POST "$LOW/api/v1/peers/<peer-id>/repositories/<repo-uuid>/sync" \
  -H "Authorization: Bearer $LOW_ADMIN_TOKEN"

# Watch the queue.
curl "$LOW/api/v1/peers/<peer-id>/sync/tasks" -H "Authorization: Bearer $LOW_ADMIN_TOKEN"
```

Notes:

- The low side sends `api_key` to the high side as a bearer token on every
  transfer, so issue it on the high side with write access to the target
  repositories. Issue it as an instance administrator's token, with the
  `admin` (or `*`) scope: the high side honors the replication exemptions
  (quota, the source's metadata, mirrored deletes of released artifacts, MCP
  registries) only for an administrator sending the replication header
  (#5455). A service-account token, or an administrator token without the
  `admin` scope, replicates as an ordinary writer: its mirrored deletes of
  released artifacts and its writes over a quota are refused and fail those
  tasks, and the high side logs `replication header from non-admin principal
  ignored` (at most once a minute).
- Restrict that administrator token to the replicated repositories when you
  mint it (`repository_ids`), so it cannot write anywhere else. Even so it is
  an administrator's credential: whoever reads the low side's database (where
  `peer_instances.api_key` is stored) holds administrator access to every
  instance it pushes to. Protect the low side's database accordingly. A
  credential bound to replication alone is tracked in #5516.
- Each artifact is written to the high side at the same repository key and
  path, with `PUT /api/v1/repositories/{key}/artifacts/{path}`. Create the
  matching repositories on the high side first. The usual pattern is to
  promote vetted content into a Local repository on the low side and
  subscribe that repository.
- To create those repositories with the low side's settings, export the low
  side's repository configuration with `GET /api/v1/admin/config/export`
  (optionally `?repositories=a,b`), then on the high side review it with
  `POST /api/v1/admin/config/import?mode=plan` and write it with
  `mode=apply`. Credentials are not exported; supply them in the import's
  `secrets` map. The document covers repositories and their per-repository
  settings only. See [Config as code](config-as-code.md).
- The peer endpoint URL goes through the same SSRF check as Remote upstream
  URLs. If the high side is on a private address, list it in
  `AK_SSRF_ALLOW_PRIVATE_CIDRS` on the low side.
- A sync policy (`POST /api/v1/sync-policies`) can create the same
  subscriptions for many repositories and peers at once.

#### `push` and `mirror`; `pull` is refused

`replication_mode` takes `push`, `mirror` or `none`. An omitted mode is
`push`.

| Mode | What it does today |
| --- | --- |
| `push` | Every artifact uploaded to the repository is queued for the peer as it lands. Existing content is sent when you call the subscription's `sync` route. |
| `mirror` | Queued like `push` as each artifact is uploaded. With a cron `replication_schedule` (UTC, for example `0 */6 * * *`), the sync worker also runs a whole-repository pass each time the schedule is due: it queues every artifact the peer has no task for, the same work as the `sync` route, and sets `last_replicated_at` when the pass is queued. A subscription that has never completed a pass runs one on the first check (about once a minute). Missed occurrences, for example while the backend was down or upstream jobs were paused, add up to one pass, not a backlog. An invalid cron expression is refused with 400. Without a schedule, `mirror` behaves exactly like `push`. |
| `none` | Assigned, not replicated. |
| `pull` | Refused with 400 on `POST /api/v1/peers/{id}/repositories` and on sync policies. It was accepted before, but nothing ever created a sync task for it, so such a subscription never moved a byte. Existing `pull` rows are left in place, logged once at startup and reported as inactive. Re-subscribe them with `push` or `mirror`. |

For a low/high pair, subscribe on the **low** side with `push`: the side that
has the content initiates every transfer, which is what a high side that may
not open outbound connections needs. The subscriber-polls-the-source model
that `pull` names is not implemented.

Use `POST /api/v1/peers/{id}/repositories/{repo_id}/sync` after the first
subscription and after any gap in connectivity, to resend what the high side
is missing, or give a `mirror` subscription a schedule so this happens on its
own. Either way, tasks that already completed are not repeated, and a `sync`
call counts as a pass: the schedule next fires at its first occurrence after
the call.

Read the subscription back with `GET /api/v1/peers/{id}/repositories/{repo_id}`
to check its mode, schedule and filter. A `replication_filter`
(`{"include_patterns": [...], "exclude_patterns": [...]}`) limits which paths
are sent.

### Bundles across a physical gap (planned)

Content bundles (#2464, epic #2463) are the answer for a true air gap: export
a set of repositories to a signed file on the low side, carry it across, and
import it on the high side. The bundle routes exist (`GET /api/v1/bundles/format` describes the format), but
`POST /api/v1/bundles/exports` and `POST /api/v1/bundles/imports` answer 501
on the current release. Until they ship, use one of the two topologies above,
or seed an instance on the low side and move its storage and database across.

## 2. Images

The stack needs these images. Pull them while connected, or through a
registry you already have inside the enclave.

| Service | Image in `docker-compose.yml` |
| --- | --- |
| `backend` | `ghcr.io/artifact-keeper/artifact-keeper-backend` |
| `web` | `ghcr.io/artifact-keeper/artifact-keeper-web` |
| `openscap` | `ghcr.io/artifact-keeper/artifact-keeper-openscap` |
| `trivy` | `ghcr.io/aquasecurity/trivy:0.76.0` |
| `postgres` | `docker.io/library/postgres:18-alpine` |
| `opensearch` | `docker.io/opensearchproject/opensearch:2.19.6` |
| `caddy` | `docker.io/library/caddy:2-alpine` |
| `pg-certs`, `scan-workspace-init`, `dtrack-init` | `docker.io/library/alpine:3.24` |
| `scanner-adapter` (optional) | `ghcr.io/artifact-keeper/artifact-keeper-scanner-adapter:1` |
| `dependency-track-*` (`dtrack` profile) | `docker.io/dependencytrack/apiserver` and `frontend`, `4.14.3` |

The Artifact Keeper images are also published on Docker Hub as
`docker.io/artifactkeeper/{backend,web,openscap}`.

**Through another registry.** An OCI Remote repository of `https://ghcr.io`
and one of `https://registry-1.docker.io`, on a connected Artifact Keeper or
any other registry, can serve these images to the disconnected host. Rewrite
the `image:` lines to that registry, for example
`registry.example.com/ghcr-remote/artifact-keeper/artifact-keeper-backend`.

**Pin digests.** `latest` and other tags move. Pin each image by digest so the
enclave runs exactly what you tested and a re-pull cannot change it:

```yaml
backend:
  image: registry.example.com/ghcr-remote/artifact-keeper/artifact-keeper-backend@sha256:<digest>
```

At minimum set `ARTIFACT_KEEPER_VERSION` (backend and openscap) and
`ARTIFACT_KEEPER_WEB_VERSION` (web) in `.env`. They are released separately.

**Init containers that reach out.** Two of the compose init containers install
packages at run time with `apk add`:

- `pg-certs` installs `openssl` the first time it runs, to generate the
  Postgres TLS certificates. Its output persists in the `pg_certs` volume, so
  it only needs the network on the first boot. Run that boot while connected,
  or supply your own certificates.
- `dtrack-init` installs `curl` and `jq` on every run. It only starts with the
  `dtrack` profile.

**TLS.** Caddy requests a certificate over ACME when `SITE_ADDRESS` is a
public domain. Offline, give Caddy certificates from your own CA or use its
internal issuer.

## 3. Remote repositories

A Remote repository fetches from its upstream on a miss and revalidates its
mutable paths (indexes, packuments, tags) when their TTL passes. Background
on the two lifetimes is in [Proxy cache freshness](proxy-cache-freshness.md).
For a disconnected site, set the following on every Remote. All routes need
the `write:repositories` scope and `admin` on the repository.

| Setting | Route | What it does | Offline value |
| --- | --- | --- | --- |
| Cache TTL | `PUT /api/v1/repositories/{key}/cache-ttl` | Lifetime of mutable paths. Immutable artifacts are cached forever regardless. | `{"cache_ttl_seconds": 315360000}` (the maximum: never revalidate). Set it before seeding. |
| Upstream 404/410 | `PUT /api/v1/repositories/{key}/on-upstream-not-found` | Whether a definitive upstream 404/410 deletes the cached copy. | `{"on_upstream_not_found": "keep"}` |
| Stale-if-error grace | `PUT /api/v1/repositories/{key}/stale-if-error-grace` | How long past expiry a cached body is still served when upstream is unreachable. Instance default `PROXY_STALE_IF_ERROR_GRACE_SECS` (3600). | `{"stale_if_error_grace_seconds": 2592000}` (the maximum, 30 days) |
| Upstream mode | `PUT /api/v1/repositories/{key}/upstream-mode` | Whether the Remote contacts its upstream at all. | `{"upstream_mode": "cache_only"}` once seeded (see [below](#cache-only-mode)) |
| Upstream filter | `PUT /api/v1/repositories/{key}/upstream-filter` | Which paths may be requested from upstream at all. | Not needed for offline use; a security control (see [below](#cache-only-mode)) |
| Egress proxy | `PUT /api/v1/repositories/{key}/egress-proxy` | Which forward proxy this Remote uses. | `{"mode": "explicit", "proxy_url": "http://egress-ledger:3128"}` to log, or leave at `inherit` |

```bash
for key in pypi-remote npm-remote ghcr-remote hf-remote; do
  curl -X PUT "$AK/api/v1/repositories/$key/cache-ttl" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"cache_ttl_seconds": 315360000}'
  curl -X PUT "$AK/api/v1/repositories/$key/on-upstream-not-found" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"on_upstream_not_found": "keep"}'
done
```

**Set upstream mode and egress proxy on create.** `POST /api/v1/repositories`
takes `upstream_mode` and `egress_proxy` (the same bodies as the two `PUT`
routes) for a Remote, and stores them before anything else, so the
repository's first upstream request already obeys them (#5402). That
matters for a Remote that contacts its upstream on its own, without a
client: an MCP Remote's first sync used to start before a separate
`PUT .../egress-proxy` or `PUT .../upstream-mode` could run, so its first
pages bypassed the logging proxy. Create Remotes in their final state
instead of pausing scheduled upstream jobs around the create:

```bash
curl -X POST "$AK/api/v1/repositories" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"key": "mcp-official", "name": "mcp-official", "format": "mcp", "repo_type": "remote",
       "upstream_url": "https://registry.modelcontextprotocol.io",
       "egress_proxy": {"mode": "explicit", "proxy_url": "http://egress-ledger:3128"},
       "mcp_remote_sync_paused": true}'
```

`mcp_remote_sync_paused: true` (MCP Remotes only) also holds back the
scheduled sync until you clear it with `PATCH`, for the settings that have
no create field (cache TTL, upstream credentials set later). A Remote that
was never synced is not due until it is a minute old in any case. Set the
other settings in the table right after the create.

Why each one matters:

- **Cache TTL.** With the default 5 minutes, every index goes stale shortly
  after the cable is cut and each request then tries upstream first. At the
  maximum a mutable entry is fresh for about ten years and is served without
  any upstream contact. Raising the TTL takes effect for an entry at its next
  revalidation, so set it before you seed. If you raise it on an instance that
  is already seeded, wait out the old TTL and request everything again while
  still connected.
- **`on_upstream_not_found = keep`.** Matters on the low side and in a near-gap,
  where upstream is still reachable: a yanked or deleted package then keeps
  serving from the cache instead of being evicted. A disconnected upstream
  gives transport errors, not 404s, so this does not change what a sealed
  instance serves.
- **Stale-if-error grace.** If a mutable entry does expire while upstream is
  unreachable, the grace window decides how long it keeps serving. A response
  served this way carries `Warning: 110 - "Response is stale"` and
  `X-AK-Stale-Since`, and counts in
  `ak_proxy_stale_if_error_responses_total`. With the TTL at the maximum it is
  a safety net, not the main mechanism.

### Seeding the cache

A cache seed job fetches a list of paths into a Remote's cache on the server,
instead of replaying client installs, and reports per path what happened:

```bash
curl -X POST "$AK/api/v1/repositories/maven-remote/cache/seed" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"kind": "paths", "content": ["org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar"]}'
```

The answer is `202` with a job id; `GET
/api/v1/repositories/{key}/cache/seed/{job_id}` returns the inventory, one
row per path (`cached`, `already_cached`, `refused` or `failed`) with size and
SHA-256. A job takes at most 10,000 paths. Each path goes through the same
proxy entry as a client download, so the upstream filter, the Package Age
Policy, quotas and the scan-on-proxy refusal apply to it. Only the `paths`
manifest exists in this release: the typed manifests (`pypi-requirements`,
`npm-lockfile`, `oci-images`, `hf-models`) and seeding a Virtual repository
answer `400`. See [Seeding a Remote's proxy cache](cache-seed.md).

An MCP Remote has its own list form: `POST /api/v1/repositories/{key}/mcp/seed`
with `{"servers": [{"name": "...", "version": "..."}]}` fetches each named
server version from the upstream registry and pins it, without syncing the
whole registry first (#5408). It runs in the background like a cache seed,
answers `202` with a `statusUrl`, and reports each item as `pinned`,
`already_pinned`, `refused` or `failed`. The item's packages are pinned
through the Remote's own backing repositories, so seed those (npm, PyPI, OCI
Remotes) too. See
[MCP registry: Seeding named servers](mcp-registry.md#seeding-named-servers).

### Cache-only mode

Once a Remote is seeded, declare it cache-only. It then serves what it holds
and never contacts its upstream:

```bash
for key in pypi-remote npm-remote ghcr-remote hf-remote; do
  curl -X PUT "$AK/api/v1/repositories/$key/upstream-mode" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"upstream_mode": "cache_only"}'
done
```

Or set `PROXY_UPSTREAM_MODE=cache_only` in the backend environment, which
puts every Remote in cache-only mode at once (read at startup).
`GET /api/v1/repositories/{key}/upstream-mode` reports the stored and the
effective mode. With it:

- **Every cached entry is served, fresh or stale**, with no revalidation. A
  stale entry carries `Warning: 110` and `X-AK-Stale-Since`, so the cache TTL
  no longer decides whether seeded indexes keep serving.
- **A miss answers 404 at once**, with the reason
  `not in cache; repository '<key>' is cache-only`, and counts as
  `ak_proxy_cache_lookups_total{result="cache_only_miss"}`. No connection is
  attempted, so a client fails fast instead of waiting for a connect timeout.
- The mode is checked by the same gate as the upstream filter, so the npm
  `/-/` passthroughs and `npm audit`, the curation upstream sync and the
  `test-upstream` probe honour it too.
- A Virtual repository skips a cache-only member that does not hold the path.

The setting is Remote-only and needs `write:repositories` and `admin` on the
repository. Set `{"upstream_mode": "online"}` to let a Remote fetch again.

An upstream filter that excludes everything (`"exclude_patterns": [".*"]`)
also stops upstream contact, but it is a security control, not an offline
mode: an expired entry for a refused path answers 404 instead of being served,
so a seeded index file disappears once its TTL passes. Use `upstream_mode` for
"disconnected now" and the filter for "never fetch this". The details are in
[Proxy cache freshness](proxy-cache-freshness.md#cache-only-offline-mode-upstream_mode-5282);
pattern syntax and the per-format subjects are in
[Upstream filters](upstream-filter.md).

### Internal upstreams

A Remote whose upstream is on a private address (another registry inside the
enclave, or the low side) is refused by the SSRF guard unless its network is
allowed. List it in `AK_SSRF_ALLOW_PRIVATE_CIDRS` (comma-separated CIDRs, for
example `10.20.0.0/16`). The blanket `UPSTREAM_ALLOW_PRIVATE_IPS` also works,
but the CIDR list is narrower and is the one to prefer. Cloud metadata,
loopback and link-local addresses stay blocked either way.

### Egress proxy

By default (`inherit`) a Remote uses the process `HTTP_PROXY`, `HTTPS_PROXY`,
`ALL_PROXY` and `NO_PROXY` (either case; upper case wins). A destination that
would go through that proxy is first resolved by the backend and refused when
it does not resolve or the outbound address policy refuses any of its
addresses, exactly as a direct request would be. This applies to each new
connection, each redirect hop and each plain-HTTP Remote request. The backend
therefore needs its own DNS for proxied hosts. The proxy resolves the name
again itself, so a DNS answer that changes between the two lookups is only
caught by the proxy: give it a destination policy that refuses loopback,
link-local, metadata and internal ranges as well. Set
`AK_UPSTREAM_ENV_PROXY=ignore` to keep Remote and other upstream fetches off
the environment proxy entirely (webhook, SSO and internal-service requests
still use it). Per repository you can set `direct` (never proxy) or
`explicit` with its own `proxy_url` and `no_proxy`; an explicit setting
replaces the environment, it does not merge with it. The proxy URL may carry
credentials; it is encrypted at rest and redacted in responses and logs. Read
it back with `GET /api/v1/repositories/{key}/egress-proxy`.

On a seeding or low-side instance, pointing every Remote at a logging forward
proxy gives you a ledger of every upstream request, which the checklist below
uses.

## 4. Scanners

Each scanner matches against a vulnerability database. Offline, nothing
updates it, so plan how each one gets a fresh copy and accept that findings
are only as current as the last refresh.

### grype (in the backend image)

The backend image ships grype with its database baked in at build time. The
image sets `GRYPE_DB_AUTO_UPDATE=false`, `GRYPE_DB_VALIDATE_AGE=false` and
`GRYPE_CHECK_FOR_APP_UPDATE=false`, and the backend forces the same three
values on every grype run, so grype never tries to download a database and
never refuses an old one.

To refresh it:

- **Pull a newer backend image.** Each image build seeds a current database.
  This is the supported path.
- **Mount your own database.** Set `GRYPE_DB_CACHE_DIR` to a mounted
  directory. An explicit value wins over the baked one. Fill that directory on
  a connected host by running `grype db update` with the same
  `GRYPE_DB_CACHE_DIR` and the grype version the backend ships, then copy it
  across.

### trivy server (compose `trivy` service)

The `trivy` service runs `trivy server`, which downloads its database into the
`trivy_cache` volume. Offline, seed the volume while connected and add
`--skip-db-update` so the server uses it as is (`docker-compose.yml` carries
this line commented out). trivy refuses `--skip-db-update` on a first run, so
the volume must already hold `db/trivy.db` and `db/metadata.json`, for example
the `db.tar.gz` from `oras pull ghcr.io/aquasecurity/trivy-db:2`, unpacked:

```yaml
trivy:
  image: ghcr.io/aquasecurity/trivy:0.76.0
  command: ["server", "--listen", "0.0.0.0:8090", "--skip-db-update"]
```

To refresh, replace the volume's contents with a newer database fetched on a
connected host, or point the server at a database copy inside the enclave with
`--db-repository`.

### trivy scanner-adapter (optional, container images)

The adapter (`docker/scanner-adapter`) has its own settings:

| Variable | What it does | Offline value |
| --- | --- | --- |
| `SCANNER_OFFLINE` | The single air-gap switch (adapter 1.7.0 and later). Implies `SCANNER_TRIVY_SKIP_DB_UPDATE=true`, skips the startup database download, and runs every image and filesystem scan with `--skip-db-update --skip-java-db-update --offline-scan`, so trivy contacts no database registry, no Java DB registry and no other network API. | `true` |
| `SCANNER_ADAPTER_TOKEN` | Shared bearer token for the adapter's own `vulndb` route (`PUT` imports a database, `GET` reports it). Unset, both answer 403. | A secret you generate |
| `SCANNER_TRIVY_SKIP_DB_UPDATE` | Skip the startup download and pass `--skip-db-update` to image and filesystem scans. | `true` (implied by `SCANNER_OFFLINE`) |
| `SCANNER_TRIVY_DB_REPOSITORY` | OCI repository the database is pulled from (`--db-repository`). Default is trivy's public mirror. | An OCI repository in your Artifact Keeper that holds a copy of the trivy DB artifact |
| `SCANNER_TRIVY_SERVER` | Run every scan as a client of a `trivy server`, which owns the database. | `http://trivy:8090` (the compose server started with `--skip-db-update`) |
| `SCANNER_TRIVY_CACHE_DIR` | Local cache and database directory. | A volume seeded while connected |

The adapter stays not-ready until a database is present, so a missing
database fails scans closed instead of reporting them clean.

**Importing a database without shell access.** In standalone mode the adapter
takes a trivy database over HTTP and swaps it in with no restart. On a
connected machine, `oras pull ghcr.io/aquasecurity/trivy-db:2` writes
`db.tar.gz`. Carry it across and `PUT` it to the adapter's `vulndb` route with
the `SCANNER_ADAPTER_TOKEN` bearer token; a `GET` of the same route reports the
installed database's build date and age (`age_seconds`, `stale`). The import
checks that the archive holds exactly `trivy.db` and `metadata.json` with the
expected schema version, refuses a database older than the installed one with
409 unless `?force=true` is given, and makes an adapter that had no database
ready. In client mode the trivy server owns the database and the import
answers 409. The route belongs to the scanner-adapter service (port 8080 in
the compose example), not to the backend; the exact `curl` commands are under
"Offline use and vulnerability-DB import" in `docker/scanner-adapter/README.md`.

With `SCANNER_OFFLINE=true` the Java DB is never downloaded, so JAR files are
matched only if a Java DB is already in `SCANNER_TRIVY_CACHE_DIR`. Seed it
while connected if you scan Java.

### Dependency scanner (OSV)

The built-in dependency scanner looks up advisories at scan time on
`api.osv.dev`, and on the GitHub advisory API only when `GITHUB_TOKEN` is set.
Offline these lookups fail and the result is recorded as degraded, not clean.
Leave `GITHUB_TOKEN` unset on a sealed instance. There is no switch to turn
this scanner off.

### Dependency-Track and OpenSCAP

Dependency-Track is off by default (`DEPENDENCY_TRACK_ENABLED`, `dtrack`
profile). It keeps its own NVD mirror, and OSV too when
`DTRACK_INIT_OSV_ENABLED` is true; both need its own update path, so leave it
off unless you plan that. OpenSCAP uses the content baked into its image.

### Database age (#5177)

Scan results record the database version and publish date
(`vuln_db_version`, `vuln_db_published_at`), but the backend does not warn
when the database is old, and grype is told not to check. An air-gapped scan
against a six-month-old database looks the same as one against today's. The
scanner-adapter's `vulndb` route reports its own database's age
(`age_seconds`, `stale`); for the rest, track the age yourself until #5177
adds a view and a threshold.

## 5. Background jobs that reach out

These run on a timer or as a standing subscription and contact the internet
without a client request. **One switch pauses the scheduled ones**: set
`UPSTREAM_JOBS_PAUSED=true` in the backend environment (pins it on), or turn
it on at run time with no restart:

```bash
curl -X PATCH "$AK/api/v1/admin/settings/system" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"upstream_jobs_paused": true}'
```

It pauses the curation upstream sync and its popularity lookups, the
environment advisory re-evaluation (OSV), the npm change feed consumer, peer
replication transfers and scheduled `mirror` passes, and the Remote MCP
registry sync. A `mirror` schedule that comes due while paused runs once on
the first check after the switch is turned off. Each skips its tick
before any network work and resumes where it stopped when the switch is
turned off. `GET /api/v1/admin/settings/system` reports the state
(`upstream_jobs_paused`, `upstream_jobs_paused_source`). Local jobs and
request-time proxy fetches are not affected; the latter are what
[cache-only mode](#cache-only-mode) covers. See
[Disconnected operation](operations/disconnected-operation.md) for the full
list, including the scheduled jobs it does not pause.

What each job contacts, and how to handle it individually:

| Job | Contacts | How to turn it off |
| --- | --- | --- |
| npm change feed | `replicate.npmjs.com` | Off by default. Leave `NPM_UPSTREAM_FEED_ENABLED` unset (and `NPM_UPSTREAM_FEED_URL` unused). Paused by the switch; the upstream filter does not gate it. |
| Curation upstream sync | The source Remote's upstream (RPM and Debian index walks, PyPI attestation enrichment), every 5 minutes for each staging repository with curation enabled | Paused by the switch. A cache-only source Remote also refuses it. Turning curation off on the staging repository also stops it, but that also stops rule enforcement. |
| Popularity lookups | `pypistats.org`, `api.npmjs.org`, during curation evaluation, only for `popularity` rules | The switch pauses the lookups of the scheduled sync, not those made when a rule evaluates a package at request time. Set `CURATION_POPULARITY_PYPI_URL` and `CURATION_POPULARITY_NPM_URL` to an internal mirror, or to `off` so each lookup answers unknown at once. Or disable or delete the rule: `PUT /api/v1/curation/rules/{id}` with `"enabled": false`, or `DELETE /api/v1/curation/rules/{id}`. Offline, an unknown count flags the package for review, so a live rule sends every new package to review. |
| Dependency scanner advisories | `api.osv.dev`, `api.github.com` | Runs on each scan, not on a timer. Leave `GITHUB_TOKEN` unset; see [section 4](#dependency-scanner-osv). |
| Peer heartbeats and sync | The registered peers | Only peers you registered. The switch pauses replication transfers (queued tasks stay queued), not heartbeats; set `PEER_HEARTBEAT_ENABLED=false` to stop those. Unregister or disable subscriptions you no longer use. |
| Webhooks, SMTP, LDAP, OIDC, tracing | Whatever you configured (`OTEL_EXPORTER_OTLP_ENDPOINT` for traces) | Point them at services inside the enclave, or leave them unset. |
| MCP Remote sync | The upstream registry of each Remote MCP repository, hourly by default (`MCP_REMOTE_SYNC_INTERVAL_SECS`) | Paused by the switch (job `mcp_remote_sync`); the per-repository cursor survives, so it resumes from there. `mcp_remote_sync_paused: true` pauses one Remote. A cache-only Remote's sync makes no upstream request (the shared upstream gate refuses each page that is not cached). Set any of these in the create body, not after it (#5402): see below and [MCP registry: Remote repositories](mcp-registry.md#remote-repositories). |

Crash reporting is opt-in and off by default
(`GET /api/v1/admin/telemetry/settings`). The backend has no update check.

## 6. Format notes

**Hugging Face.** Set `HF_ENDPOINT` to the Remote and `HF_HUB_DISABLE_XET=1`
on clients, so `huggingface_hub` never tries the Hub's Xet storage directly.
`snapshot_download` with a branch revision such as `main` calls model info
first, which is a mutable path, so the cache TTL above matters on a Remote
that is not cache-only. The files it then fetches by commit sha are immutable
cache entries (#5283). A Remote forwards the tree listing's `recursive`,
`expand` and `cursor` (#5321), so a snapshot seeded through it includes the
files in subdirectories. See [Hugging Face](huggingface.md).

**Go.** Point `GOPROXY` at the Go Remote. Artifact Keeper also answers the
checksum database under the same prefix (`sumdb/sum.golang.org/...`) and
caches its answers in the Remote's proxy cache (#5344), so `go` can verify a
seeded module offline with the default `GOSUMDB`. The tiles
(`sumdb/<host>/tile/...`) and the per-version lookups
(`sumdb/<host>/lookup/<module>@<version>`) are immutable entries. The signed
tree head (`sumdb/<host>/latest`) is mutable: it is revalidated after the
cache TTL, served stale within the stale-if-error grace while the checksum
database is unreachable, and served as it is in cache-only mode. To seed it,
run the same `go mod download` through the Remote while it is connected; the
toolchain fetches the lookups and tiles it needs.

The upstream filter sees these fetches as the absolute URL
(`https://sum.golang.org/...`), so an exclude pattern such as
`^https://sum\.golang\.org/` stops them. Only `sum.golang.org` and
`sum.golang.google.cn` are proxied, and the Remote's upstream credentials are
never sent to them. A Hosted Go repository has no proxy cache and still
passes these requests through uncached.

Private modules, and modules added on the high side, are not in the public
checksum database at all. Exclude them from lookups on the client, and commit
`go.sum`:

```bash
export GOPROXY=https://registry.example.com/go/go-remote
export GONOSUMDB=example.com/internal/*
```

**npm.** `npm ci` from a lockfile installs cached tarballs without needing
fresh metadata. `npm audit` and `npm audit signatures` call upstream endpoints
(`/-/npm/v1/security/...`, `/-/npm/v1/attestations/...`) that Artifact Keeper
passes through and does not cache positively. Run them on the low side before
content crosses. Offline, a Remote answers them as follows:

| Request | Upstream unreachable | Refused by the upstream filter | Cache-only |
| --- | --- | --- | --- |
| `GET /-/npm/v1/attestations/...`, `/-/v1/search` and other `/-/` reads | `503 upstream unreachable: ...` | `404 path excluded by the upstream filter of repository '<key>'` | `404 not in cache; repository '<key>' is cache-only` |
| `POST /-/npm/v1/security/advisories/bulk`, `/-/npm/v1/security/audits/quick` | `200` with an empty advisory set | `200` with an empty advisory set | `200` with an empty advisory set |
| `GET /-/ping`, `/-/whoami` | answered locally | `404` (filter reason) | `404` (cache-only reason) |

- An attestation answer still held in the attestation negative cache
  (`NPM_ATTESTATION_NEGATIVE_CACHE_*`, a `404`/`410` for that version, held
  for up to an hour by default) is served instead of the refusal or the `503`.
  Positive attestation bundles are never cached, so `npm audit signatures`
  cannot verify provenance offline.
- The audit endpoints degrade to an empty advisory set (#1400), so offline
  `npm audit` reports `found 0 vulnerabilities`. That is not a clean audit:
  audit on the low side.
- A Virtual repository tries each Remote member in turn. When none answers it
  returns `503` if a member was unreachable, otherwise `404` listing each
  member's refusal reason.
- `501 ... is not implemented for local repositories` is the answer of a Local
  repository only (and of a Virtual repository with no Remote member, which
  says so).

**PyPI.** Hash-checking installs work offline: the hashes come from your lock
file and the wheels are immutable cache entries. Only the simple index is
mutable, and the cache TTL keeps it.

```bash
pip install --require-hashes -r requirements.txt \
  --index-url https://registry.example.com/pypi/pypi-remote/simple/
```

## 7. Verification checklist

Run these after you disconnect, and again after any change.

1. **No route out.** Put the stack, or a client container, on a Docker network
   with `internal: true`, which has no gateway:

   ```yaml
   networks:
     default:
       internal: true
   ```

   Install and build from Artifact Keeper. Then confirm that a container
   cannot reach the outside, for example that `curl -m 5 https://pypi.org/`
   fails from the backend's network.

2. **The egress ledger is quiet.** On a seeding or low-side instance, with
   every Remote's egress proxy pointed at a logging forward proxy, repeat the
   same installs. The proxy log should gain no new lines for content that is
   already cached.

   **The audit log agrees.** With `AUDIT_UPSTREAM_FETCHES=all`, every request
   the proxy sends upstream (a cache-miss fetch, a revalidation, an OCI token
   exchange) writes an `UPSTREAM_FETCHED` audit entry with the repository,
   host, path, status and result; a cache hit writes nothing. List what came
   in during the seed window, and check that nothing was fetched after the
   cut:

   ```bash
   curl "$AK/api/v1/admin/audit?action=UPSTREAM_FETCHED&from=<cut time, RFC 3339>" \
     -H "Authorization: Bearer $ADMIN_TOKEN"
   ```

   Requests made outside the proxy service (the `test-upstream` probe,
   curation sync, the popularity source, the npm change feed and `/-/`
   passthroughs, the Go sumdb pass-through of a Hosted repository) are not
   recorded. See
   [Upstream contact](audit-events.md#upstream-contact).

3. **Hits, not misses.** Scrape `GET /api/v1/admin/metrics` (or `/metrics` on
   `METRICS_PORT`) and chart `ak_proxy_cache_lookups_total` by `result` and
   `repository`. A sealed instance serving seeded content should show `hit`
   rising and the `miss_*` results flat. A rising `miss_no_metadata` names
   content you did not seed.

4. **Nothing stale.** `ak_proxy_stale_if_error_responses_total` stays flat and
   responses carry no `X-AK-Stale-Since`. If it rises, a mutable entry has
   expired: raise the cache TTL.

5. **Unseeded paths fail fast.** Request a package you did not seed. A
   cache-only Remote answers 404 at once, without a timeout, with the reason
   `not in cache; repository '<key>' is cache-only`, and
   `ak_proxy_cache_lookups_total{result="cache_only_miss"}` rises.

6. **Scheduled upstream jobs are paused.**
   `GET /api/v1/admin/settings/system` shows `"upstream_jobs_paused": true`.

7. **Scanners are ready.** The scanner-adapter reports ready, its
   `vulndb` route shows the database you imported, and recent scan
   results show the database version you expect.

8. **Replication is active.** On the low side,
   `GET /api/v1/peers/{id}/repositories/{repo_id}` shows `push` or `mirror`
   and `"effective": "active"` for each subscription, and
   `GET /api/v1/peers/{id}/sync/tasks` drains.

## See also

- [Proxy cache freshness](proxy-cache-freshness.md): TTLs, stale-if-error and `on_upstream_not_found`.
- [Upstream filters](upstream-filter.md): pattern syntax and per-format subjects.
- [Seeding a Remote's proxy cache](cache-seed.md): the cache seed job and its inventory.
- [Disconnected operation](operations/disconnected-operation.md): the switch that pauses scheduled upstream jobs.
- [Config as code](config-as-code.md): export, plan and apply repository configuration.
- [Audit events](audit-events.md#upstream-contact): `UPSTREAM_FETCHED` and `AUDIT_UPSTREAM_FETCHES`.
- [Hugging Face](huggingface.md): `HF_ENDPOINT`, gated models and Xet.
- `backend/src/services/egress_proxy.rs`: egress proxy modes and precedence.
- `docker/scanner-adapter/README.md`: scanner-adapter client/server mode.
- #2463, #2464 (bundles, planned), #5177 (scanner DB age, open). New in
  1.12.0: #5282 (cache-only mode), #5284 (cache seed), #5286
  (`UPSTREAM_FETCHED`), #5287 (scanner offline mode and DB import), #5288
  (pause scheduled upstream jobs), #5292 (config export and plan/apply).
