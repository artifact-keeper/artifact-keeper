# scanner-adapter

Independent semver, source of truth: `docker/scanner-adapter/VERSION`. The image is
tagged by its own version (`1.0.0` / `1.0` / `1` / `latest`), decoupled from AK's
appVersion.

Compat: backend ≥1.2.4 requires scanner-adapter major 1.x (Harbor Pluggable Scanner API v1).

## Client/server mode (adapter >= 1.4.0)

By default the adapter runs trivy standalone: it downloads its own
vulnerability DB into `SCANNER_TRIVY_CACHE_DIR` at startup and does all
analysis and matching locally. Several adapters can instead share one
`trivy server`:

| Variable | Effect |
|---|---|
| `SCANNER_TRIVY_SERVER` | `http(s)://host[:port]` of a `trivy server`: no path, query or credentials (a malformed value keeps the adapter not-ready). Every image and filesystem scan runs as `trivy --server <url>`. No local vulnerability DB is downloaded; `/probe/ready` answers 200 only while `GET <url>/version` reports a loaded DB and the same trivy release as the bundled CLI (re-checked at most every 10s, 3s timeout). Empty (default): standalone. |
| `SCANNER_TRIVY_SERVER_INSECURE` | Default `false`. Required to use an `https` server while `SCANNER_TRIVY_INSECURE` is `true` (see TLS below); the adapter logs a warning at startup when it is set. |
| `SCANNER_TRIVY_CACHE_PARTITION` | Optional. Partitions the analysis-cache keys this adapter reads and writes on the server (it adds a never-matching `--skip-dirs` entry, which trivy folds into every cache key). Adapters with different partitions share the server's DB but never each other's cached layer analysis. In `registry` mode it is the prefix of every derived partition. |
| `SCANNER_TRIVY_CACHE_PARTITION_MODE` | `static` (default) or `registry`; see [Per-registry cache partitions](#per-registry-cache-partitions-adapter--170). Any other value stops the adapter at startup. |
| `TRIVY_TOKEN`, `TRIVY_TOKEN_HEADER` | trivy's own variables, inherited by every invocation; set them when the server runs with `--token`. |

What the server shares and what it does not, per trivy's client/server design:

- Shared: the vulnerability DB and the vulnerability matching (server side),
  and for **image** scans the per-layer analysis cache. A client asks the
  server which layer keys are missing and only downloads and analyzes those;
  a layer another client already analyzed is neither pulled nor re-analyzed.
- Not shared, mostly: **filesystem** scans analyze locally and share the DB.
  The one exception is a workspace that is a clean git repository: trivy then
  keys its analysis by the HEAD commit and reuses a cached analysis from the
  server. In `registry` partition mode the adapter does not extract a root
  `.git` from an uploaded workspace, so that never happens. The Java DB, needed to analyze JAR files, is downloaded on the
  client when a JAR is analyzed, so `SCANNER_TRIVY_CACHE_DIR` still needs room
  for it.
- Trust: an image layer's cache key is derived from the diff ID the image's
  config *claims*; trivy does not re-hash the layer content against it. A
  client that scans a crafted image first can therefore store a false
  analysis under the diff ID of a real layer, and every later client in the
  same partition reuses it. Give adapters that do not trust each other
  distinct `SCANNER_TRIVY_CACHE_PARTITION` values (or separate servers), and
  run an adapter that serves several Artifact Keeper instances in `registry`
  partition mode (below).
- The server must run the same trivy release as the adapter image (trivy does
  not refuse a mismatched client; the adapter does). The release compared is
  the bundled CLI's own `trivy --version`, probed at startup even when
  `SCANNER_SCANNER_VERSION` pins the *reported* version. Besides the readiness
  check, every scan is checked against the server info trivy embeds in its
  report (`Trivy.Server`): a scan whose report shows a different server
  release, a server without a DB, or no server info at all fails (500).
- TLS: `SCANNER_TRIVY_INSECURE` (default `true`, meant for pulling from the AK
  registry over plain HTTP) maps to trivy's `--insecure`, which is global: in
  client mode it **also disables TLS verification of the trivy server**, so
  `TRIVY_TOKEN` and the scan results would travel over unverified TLS. With an
  `https` server the adapter therefore stays not-ready unless either
  `SCANNER_TRIVY_INSECURE=false` (registry reached over verified HTTPS) or the
  explicit `SCANNER_TRIVY_SERVER_INSECURE=true` opt-in is set. With the opt-in,
  the readiness check skips verification too, matching the scans. A plain
  `http` server is unaffected (and unencrypted).
- DB provenance: the `vulnerability_db` field on scan results (#3014) names
  the server's DB in this mode, taken from the scan's own report
  (`Trivy.Server.VulnerabilityDB`, the same document as the server's
  `/version`), never from `SCANNER_TRIVY_CACHE_DIR/db/metadata.json` (which
  holds no DB, or a stale one, in client mode). A DB block that cannot be
  parsed omits the field without failing the scan.

## Per-registry cache partitions (adapter >= 1.7.0)

`SCANNER_TRIVY_CACHE_PARTITION` is one value for the whole adapter process,
so an adapter that serves several Artifact Keeper instances puts every
instance's layer analysis into one partition: anyone who can push to one
instance can plant a false analysis that the others reuse (see Trust above).
`SCANNER_TRIVY_CACHE_PARTITION_MODE=registry` derives the partition per image
scan instead (#5943):

- partition = `SCANNER_TRIVY_CACHE_PARTITION` + `|` + the request's
  `registry.url` host, lowercased, without scheme or trailing slash, port
  kept. `http://ak.example:8080/` and `ak.example:8080` share a partition;
  `ak.example:8080` and `ak.example:8081` do not.
- Two registry hosts never share layer analysis, so a scan for one instance
  never reuses analysis cached by another instance's scan.
- **Each instance must set a stable, unique `TRIVY_ADAPTER_REGISTRY_URL`**
  (a service DNS name such as `http://ak-backend.<namespace>.svc:8080`) in
  this mode. Without it the backend advertises `http://<pod IP>:8080`, and
  cached analysis has no expiry on the trivy server: when that pod IP is later
  given to another instance's backend, the second instance would read the
  first one's partition, including anything planted in it. The adapter logs
  a warning (once per host) when a registry-mode partition is keyed by a bare
  IPv4 or IPv6 address; it still scans. Instances behind one shared host name
  share a partition, as they share a registry.
- The operator-set value stays a prefix, so two adapter fleets scanning the
  same host still stay apart. It may be empty in this mode, and must not
  contain `|` (the separator; the adapter refuses to start).
- The partition applies in standalone mode too: trivy keys the local on-disk
  cache the same way.
- Filesystem scans carry no registry and keep the static partition. In this
  mode the adapter does not extract a root `.git` from the uploaded workspace,
  the only case in which trivy reuses a cached filesystem analysis (keyed by
  the HEAD commit the `.git` claims), so there is nothing to partition. trivy
  skips `.git` when scanning, so no finding changes.
- A scan request with no registry host (an empty or scheme-only
  `registry.url`) is refused with `400` in this mode.
- Switching modes changes every image-layer cache key once, so the first
  scans afterwards re-analyze their layers.

The startup log reports the mode, and in `registry` mode `GET /api/v1/metadata`
adds `properties."env.SCANNER_TRIVY_CACHE_PARTITION_MODE"`; neither ever shows
a partition value. In `static` mode the metadata document is unchanged.
The startup log no longer prints the static partition's `--skip-dirs` hash
either.

Upgrading changes nothing unless the mode is set: the default `static` mode
uses `SCANNER_TRIVY_CACHE_PARTITION` exactly as before.

## Concurrent scans (adapter >= 1.7.0)

trivy keeps its image-layer analysis cache in `SCANNER_TRIVY_CACHE_DIR/fanal/fanal.db`
and locks it for the whole of a scan; a second scan that cannot take the lock
within 5s fails with `cache may be in use by another process: timeout`
(#5657). One image scan at a time now uses that cache, and image scans started
while it is held run with `--cache-backend memory`: the same report, without
reusing cached layers. A scan that still hits the lock (held by another
process sharing the cache volume) is rerun once on the memory backend.
Filesystem scans and client mode (`SCANNER_TRIVY_SERVER`) never take the lock.

At most `SCANNER_MAX_CONCURRENT_SCANS` scans (image and filesystem together,
default `4`, `0` for no bound) run trivy at once. Further jobs wait for a slot
instead of starting: their report route answers `302` with
`X-Scan-Status: Queued` (`Running` once trivy runs), and the scan's own
timeout starts only when it leaves the queue. The backend does not charge
queued time to its poll budget (up to 30 minutes of queueing per scan), so a
burst of scans waits rather than timing out. Each trivy run holds the
vulnerability DB and the analysed layers in memory, so raise the bound only
with the pod's memory limit.

Jobs live in memory, so a restarted or replaced adapter answers `404 unknown
scan id` for jobs its predecessor accepted. The backend submits such a scan
again (up to three submissions in all), and does the same for a job that
failed on the cache lock, so neither ends as a failed scan. While the old pod
is gone and the new one not yet answering, the backend keeps polling for up
to two minutes instead of failing on the gap.

## Authenticating the scan routes (adapter >= 1.7.0)

By default anything that can reach the adapter can submit a scan, which makes
it pull and analyze an image of the caller's choosing (in client mode, into
its cache partition on the trivy server; see "Trust" above). Network isolation
is the only defence then, and it is hard to keep once the adapter sits behind
a shared proxy or load balancer, or serves several Artifact Keeper instances.
A bearer token closes that:

| Variable | Effect |
|---|---|
| `SCANNER_SCAN_TOKEN` | When set, `POST /api/v1/scan`, `POST /api/v1/filesystem/scan` and both report routes require `Authorization: Bearer <token>` (compared in constant time) and answer `401` otherwise. Unset (default): those routes are open, as before. |
| `SCANNER_SCAN_TOKENS_FILE` | Path to a file with one token per line (blank lines and lines starting with `#` are ignored); any of them is accepted, alongside `SCANNER_SCAN_TOKEN` if both are set. The file is re-read when its modification time or size changes, so a mounted Secret can add or drop a token without a restart. A file that is empty or holds only comments accepts no token from it. If the file cannot be read (deleted, unreadable, a line over 1 MiB), the last set read stays valid for at most 60 s, which covers an atomic swap of a mounted Secret, and is then dropped, so deleting the file revokes its tokens. A leading UTF-8 BOM is ignored. In every case the routes fail closed. |

`/probe/ready`, `/probe/healthy` and `GET /api/v1/metadata` stay open either
way. The scan token is separate from `SCANNER_ADAPTER_TOKEN` (the
vulnerability-DB import credential below), so the two rotate independently;
neither is accepted in place of the other. Giving each Artifact Keeper
instance its own line in the tokens file lets one adapter serve several of
them and revoke one without touching the others.

On the backend, set `TRIVY_ADAPTER_TOKEN` (or `TRIVY_ADAPTER_TOKEN_FILE`, a
path to a mounted secret) to the same value. It is sent on every adapter
request, image and filesystem scans alike, and never logged. The Harbor scan
request's `registry.authorization` remains the separate credential the
adapter uses to pull the image.

To rotate the backend's token without a failed scan: add the new token as a
line of `SCANNER_SCAN_TOKENS_FILE` (picked up without a restart), point
`TRIVY_ADAPTER_TOKEN` / `TRIVY_ADAPTER_TOKEN_FILE` at it and restart the
backend (it reads the token at startup), then remove the old line.

## Image size limit (adapter >= 1.7.0)

trivy downloads every layer of an image into `SCANNER_TRIVY_CACHE_DIR` and
holds the analysed layers in memory, so an image larger than the pod's memory
or ephemeral-storage limit gets the adapter OOM-killed or evicted part-way
through the scan, along with every other scan running on it (#5909).

| Variable | Effect |
|---|---|
| `SCANNER_MAX_IMAGE_BYTES` | Default `0` (no bound). Bytes, optionally with a Kubernetes-style suffix: `Ki`/`Mi`/`Gi`/`Ti` (powers of 1024) or `K`/`M`/`G`/`T` (powers of 1000), e.g. `4Gi`. A value that does not parse is ignored with a warning in the log, and the startup log states the limit in effect. When set, the adapter reads the image manifest with the scan request's credential before running trivy (for an index, the `linux/amd64` image, which is the one trivy scans when given no `--platform`, whatever the adapter's own architecture) and adds up the config and layer sizes. Above the limit the image is not scanned: trivy does not run and the report route answers `422` with `X-Scan-Status: TooLarge` and `not scanned: image too large: <image> is <n> bytes (compressed layers), over SCANNER_MAX_IMAGE_BYTES=<limit>`. A manifest that cannot be read or measured never blocks a scan: the adapter logs why and scans as it would without the limit. The check gives up after 10s (an unreachable or hung registry), so it never takes much of the backend's report-poll budget. |

The sizes are the compressed sizes the registry reports, i.e. what trivy
downloads; unpacked layers are larger. Set the limit well under both the
pod's memory limit and its ephemeral-storage limit (`SCANNER_TRIVY_CACHE_DIR`
and the temp dir), and lower it, or lower `SCANNER_MAX_CONCURRENT_SCANS`,
when several large images can be scanned at once. The backend records a
refused image as a failed scan whose error reads `not scanned: image too
large ...`, and does not resubmit it.

A filesystem-scan upload over `SCANNER_FS_MAX_UPLOAD_BYTES` is answered `413`
with `not scanned: workspace too large` (it was a `400 invalid workspace tar`).

## Offline use and vulnerability-DB import (adapter >= 1.7.0)

For a disconnected install, set one switch:

| Variable | Effect |
|---|---|
| `SCANNER_OFFLINE` | Default `false`. `true` implies `SCANNER_TRIVY_SKIP_DB_UPDATE=true` (even if that is set to `false`), skips the startup DB download, and runs every image and filesystem scan with `--skip-db-update --skip-java-db-update`, so trivy contacts no DB registry and no Java DB registry. `--offline-scan --skip-version-check --disable-telemetry` are on for every scan in every mode (see below). Logged once at startup. JAR files are matched only if a Java DB is already in the cache. |
| `SCANNER_ADAPTER_TOKEN` | Shared bearer token for `GET`/`PUT /api/v1/vulndb`. Unset (default): both routes answer 403. The scan routes are not affected. |
| `SCANNER_TRIVY_DB_SCHEMA_VERSION` | Default `2`. The `Version` an imported `metadata.json` must carry. trivy does not report the schema it expects, so it is configured; it is the major tag of the DB artifact (`trivy-db:2`) and only changes with a trivy release that moves to a new schema. |
| `SCANNER_VULNDB_MAX_UPLOAD_BYTES` | Default 2 GiB. Cap on the compressed upload (413 above it). |
| `SCANNER_VULNDB_MAX_EXTRACTED_BYTES` | Default 8 GiB. Cap on the unpacked files (400 above it). |

### No lookups during a scan (adapter >= 1.7.0)

Connected or not, every scan runs with `--offline-scan`,
`--skip-version-check` and `--disable-telemetry` (#5666). trivy therefore
never resolves a `pom.xml` parent or unpinned version against
`repo.maven.apache.org` (which failed scans on air-gapped installs, went
around AK's own proxy, and disclosed the artifact's dependency coordinates),
and never calls `check.trivy.dev`. The vulnerability and Java DB downloads
are unchanged; `SCANNER_OFFLINE` governs those.

`trivy filesystem` does not open `.jar` files. For JVM archives the backend
adds `.ak-scan-jar-inventory/pom.xml` to the uploaded workspace, naming every
library bundled in it (a fat jar's `BOOT-INF/lib/`, a war's `WEB-INF/lib/`)
at the version its `pom.properties` declares, so those are graded with no
remote resolution.

Offline, a standalone adapter with an empty cache starts and stays
not-ready (`/probe/ready` 503) until a DB is imported, then becomes ready
with no restart. `SCANNER_TRIVY_SKIP_DB_UPDATE` alone now also applies to
filesystem scans (it used to reach image scans only).

### Carrying the DB across the gap

On a connected machine, pull the trivy DB artifact; `oras` writes its single
layer as `db.tar.gz` (`trivy.db` + `metadata.json`):

```sh
oras pull ghcr.io/aquasecurity/trivy-db:2
```

On the disconnected side, import it into the adapter:

```sh
curl -fsS -X PUT \
  -H "Authorization: Bearer $SCANNER_ADAPTER_TOKEN" \
  --data-binary @db.tar.gz \
  http://scanner-adapter:8080/api/v1/vulndb
```

and check what is installed and how old it is:

```sh
curl -fsS -H "Authorization: Bearer $SCANNER_ADAPTER_TOKEN" \
  http://scanner-adapter:8080/api/v1/vulndb
# {"version":2,"updated_at":"...","next_update":"...","downloaded_at":"...","age_seconds":21600,"stale":false,"offline":true}
```

`age_seconds` is measured from `updated_at`, the upstream build time;
`downloaded_at` is the import time; `stale` is true once `next_update` has
passed. `GET` answers 404 when no DB is installed, and in client mode (the
trivy server holds the DB; `PUT` answers 409 there).

What `PUT` checks, refusing with 400 and leaving the installed DB untouched:
the body is a gzip tar (read to its end, so a truncated or corrupt stream is
caught) holding exactly the regular files `trivy.db` and `metadata.json`
(no paths, links, directories, duplicates or other entries); `trivy.db` is a
bolt database; `metadata.json` parses, carries an `UpdatedAt` and the
expected schema version. A DB older (by `UpdatedAt`) than the installed one
is refused with 409 unless `?force=true` is given. A successful import
answers 200 with the imported and previous metadata and the upload's sha256.

The upload is staged in a temp dir inside `SCANNER_TRIVY_CACHE_DIR` and
swapped in by renaming the old `db/` aside, renaming the new one into place
(the old one is put back if that fails) and deleting the old one. Scans hold
a read lock on the DB for their whole trivy run and the swap takes the write
lock, so an import waits for in-flight scans (up to their timeout) and scans
started meanwhile wait for the two renames; no scan sees a missing or
half-written DB.
