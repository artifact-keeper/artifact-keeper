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

1. Bring the stack up on a connected network.
2. Create the Remote repositories you need and apply the offline settings in
   [section 3](#3-remote-repositories) **before** you seed. A raised cache TTL
   only applies to an entry from its next revalidation, so set it first.
3. Pull everything the site will need through Artifact Keeper: run the
   builds, `pip install -r`, `npm ci`, `docker pull`, `hf download` and so on
   against it. Every path that is fetched once is cached.
4. Refresh the scanner databases ([section 4](#4-scanners)).
5. Disconnect, then run the [verification checklist](#7-verification-checklist).

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
  repositories.
- Each artifact is written to the high side at the same repository key and
  path, with `PUT /api/v1/repositories/{key}/artifacts/{path}`. Create the
  matching repositories on the high side first. The usual pattern is to
  promote vetted content into a Local repository on the low side and
  subscribe that repository.
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
| `mirror` | Queued exactly like `push`. The subscription also stores a cron `replication_schedule`, but nothing acts on it yet, so run the `sync` route yourself for a whole-repository pass. |
| `none` | Assigned, not replicated. |
| `pull` | Refused with 400 on `POST /api/v1/peers/{id}/repositories` and on sync policies. It was accepted before, but nothing ever created a sync task for it, so such a subscription never moved a byte. Existing `pull` rows are left in place, logged once at startup and reported as inactive. Re-subscribe them with `push` or `mirror`. |

For a low/high pair, subscribe on the **low** side with `push`: the side that
has the content initiates every transfer, which is what a high side that may
not open outbound connections needs. The subscriber-polls-the-source model
that `pull` names is not implemented.

Use `POST /api/v1/peers/{id}/repositories/{repo_id}/sync` after the first
subscription and after any gap in connectivity, to resend what the high side
is missing. Tasks that already completed are not repeated.

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
| Upstream filter | `PUT /api/v1/repositories/{key}/upstream-filter` | Which paths may be requested from upstream at all. | `{"include_patterns": [], "exclude_patterns": [".*"]}` for cache-only (see below) |
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

### Cache-only today: exclude everything

There is no declared cache-only mode yet (#5282). Today an upstream filter
that refuses every path gives the same effect:

```bash
curl -X PUT "$AK/api/v1/repositories/pypi-remote/upstream-filter" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"include_patterns": [], "exclude_patterns": [".*"]}'
```

With it:

- A path that is not cached answers 404 at once. No connection is attempted,
  so a client fails fast instead of waiting for a connect timeout.
- A Virtual repository skips this member for the path without contacting it.
- The filter also gates the npm `/-/` passthroughs and audit, the curation
  upstream sync and the `test-upstream` probe.
- **Expired entries stop serving.** A cached entry for a refused path is
  served only while it is fresh. Once it expires it is not revalidated and
  stale-if-error does not apply: it answers 404 like a miss. So pair the
  filter with the maximum cache TTL, set before seeding. Immutable artifacts
  never expire and are not affected.

Remove the filter with `DELETE /api/v1/repositories/{key}/upstream-filter` to
let a Remote fetch again. Pattern syntax, the subject each format matches and
the npm and Hugging Face path shapes are in
[Upstream filters](upstream-filter.md).

### Internal upstreams

A Remote whose upstream is on a private address (another registry inside the
enclave, or the low side) is refused by the SSRF guard unless its network is
allowed. List it in `AK_SSRF_ALLOW_PRIVATE_CIDRS` (comma-separated CIDRs, for
example `10.20.0.0/16`). The blanket `UPSTREAM_ALLOW_PRIVATE_IPS` also works,
but the CIDR list is narrower and is the one to prefer. Cloud metadata,
loopback and link-local addresses stay blocked either way.

### Egress proxy

By default (`inherit`) a Remote uses the process `HTTP_PROXY`, `HTTPS_PROXY`
and `NO_PROXY`. Per repository you can set `direct` (never proxy) or
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
`--skip-db-update` so the server uses it as is:

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
| `SCANNER_TRIVY_SKIP_DB_UPDATE` | Skip the startup download and pass `--skip-db-update` to image scans. | `true` |
| `SCANNER_TRIVY_DB_REPOSITORY` | OCI repository the database is pulled from (`--db-repository`). Default is trivy's public mirror. | An OCI repository in your Artifact Keeper that holds a copy of the trivy DB artifact |
| `SCANNER_TRIVY_SERVER` | Run every scan as a client of a `trivy server`, which owns the database. | `http://trivy:8090` (the compose server started with `--skip-db-update`) |
| `SCANNER_TRIVY_CACHE_DIR` | Local cache and database directory. | A volume seeded while connected |

The adapter stays not-ready until a database is present, so a missing
database fails scans closed instead of reporting them clean.

Prefer client/server mode (`SCANNER_TRIVY_SERVER`) offline. In standalone mode
`SCANNER_TRIVY_SKIP_DB_UPDATE` is only passed to image scans; filesystem scans
are not given the flag, so they can still try to download a database. In
either mode trivy fetches its separate Java DB on the client the first time it
analyzes a JAR, so seed `SCANNER_TRIVY_CACHE_DIR` with it while connected if
you scan Java.

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
(`vuln_db_version`, `vuln_db_published_at`), but nothing warns when the
database is old, and grype is told not to check. An air-gapped scan against a
six-month-old database looks the same as one against today's. Track the age
yourself until #5177 adds a view and a threshold. An admin route to import a
database and report its age, and offline defaults for the trivy services, are
#5287.

## 5. Background jobs that reach out

These run on a timer or as a standing subscription and contact the internet
without a client request. There is no single switch yet; #5288 proposes one.
Until then, handle each:

| Job | Contacts | How to turn it off |
| --- | --- | --- |
| npm change feed | `replicate.npmjs.com` | Off by default. Leave `NPM_UPSTREAM_FEED_ENABLED` unset (and `NPM_UPSTREAM_FEED_URL` unused). The upstream filter does not gate it. |
| Curation upstream sync | The source Remote's upstream (RPM and Debian index walks, PyPI attestation enrichment), every 5 minutes for each staging repository with curation enabled | Exclude everything in the source Remote's upstream filter. Turning curation off on the staging repository also stops it, but that also stops rule enforcement. |
| Popularity lookups | `pypistats.org`, `api.npmjs.org`, during curation evaluation, only for `popularity` rules | Disable or delete the rule: `PUT /api/v1/curation/rules/{id}` with `"enabled": false`, or `DELETE /api/v1/curation/rules/{id}`. Offline, an unknown count flags the package for review, so a live rule sends every new package to review. |
| Dependency scanner advisories | `api.osv.dev`, `api.github.com` | Runs on each scan, not on a timer. Leave `GITHUB_TOKEN` unset; see [section 4](#dependency-scanner-osv). |
| Peer heartbeats and sync | The registered peers | Only peers you registered. Unregister or disable subscriptions you no longer use. |
| Webhooks, SMTP, LDAP, OIDC, tracing | Whatever you configured (`OTEL_EXPORTER_OTLP_ENDPOINT` for traces) | Point them at services inside the enclave, or leave them unset. |
| MCP Remote sync | The MCP registry a Remote proxies | Forthcoming with the MCP registry repository type (#5257); its switch will be documented there. |

Crash reporting is opt-in and off by default
(`GET /api/v1/admin/telemetry/settings`). The backend has no update check.

## 6. Format notes

**Hugging Face.** Set `HF_ENDPOINT` to the Remote and `HF_HUB_DISABLE_XET=1`
on clients, so `huggingface_hub` never tries the Hub's Xet storage directly.
`snapshot_download` with a branch revision such as `main` calls model info
first, which is a mutable path, so the cache TTL above matters. See
[Hugging Face](huggingface.md).

**Go.** Point `GOPROXY` at the Go Remote. Artifact Keeper also answers the
checksum database under the same prefix (`sumdb/sum.golang.org/...`), but
that route is a pass-through: it is not cached, so it fails offline. Commit
`go.sum`: a module whose hash is already in `go.sum` is not checked against
the checksum database. For modules that are not (private modules, or new ones
added on the high side), exclude them from checksum database lookups on the
client:

```bash
export GOPROXY=https://registry.example.com/go/go-remote
export GONOSUMDB=example.com/internal/*
```

**npm.** `npm ci` from a lockfile installs cached tarballs without needing
fresh metadata. `npm audit` and `npm audit signatures` call upstream endpoints
(`/-/npm/v1/security/...`, `/-/npm/v1/attestations/...`) that Artifact Keeper
passes through and does not cache positively. Offline they fail. Run them on
the low side before content crosses.

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

3. **Hits, not misses.** Scrape `GET /api/v1/admin/metrics` (or `/metrics` on
   `METRICS_PORT`) and chart `ak_proxy_cache_lookups_total` by `result` and
   `repository`. A sealed instance serving seeded content should show `hit`
   rising and the `miss_*` results flat. A rising `miss_no_metadata` names
   content you did not seed.

4. **Nothing stale.** `ak_proxy_stale_if_error_responses_total` stays flat and
   responses carry no `X-AK-Stale-Since`. If it rises, a mutable entry has
   expired: raise the cache TTL.

5. **Unseeded paths fail fast.** Request a package you did not seed. With the
   exclude-everything filter it answers 404 at once, without a timeout.

6. **Scanners are ready.** The scanner-adapter reports ready, and recent scan
   results show the database version you expect.

7. **Replication is active.** On the low side,
   `GET /api/v1/peers/{id}/repositories/{repo_id}` shows `push` or `mirror`
   and `"effective": "active"` for each subscription, and
   `GET /api/v1/peers/{id}/sync/tasks` drains.

## See also

- [Proxy cache freshness](proxy-cache-freshness.md): TTLs, stale-if-error and `on_upstream_not_found`.
- [Upstream filters](upstream-filter.md): pattern syntax and per-format subjects.
- [Hugging Face](huggingface.md): `HF_ENDPOINT`, gated models and Xet.
- `backend/src/services/egress_proxy.rs`: egress proxy modes and precedence.
- `docker/scanner-adapter/README.md`: scanner-adapter client/server mode.
- #2463, #2464 (bundles), #5177 (scanner DB age), #5282 (cache-only mode),
  #5287 (scanner offline DB), #5288 (pause scheduled upstream jobs).
