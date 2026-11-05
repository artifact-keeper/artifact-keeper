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
| `SCANNER_TRIVY_CACHE_PARTITION` | Optional. Partitions the analysis-cache keys this adapter reads and writes on the server (it adds a never-matching `--skip-dirs` entry, which trivy folds into every cache key). Adapters with different partitions share the server's DB but never each other's cached layer analysis. |
| `TRIVY_TOKEN`, `TRIVY_TOKEN_HEADER` | trivy's own variables, inherited by every invocation; set them when the server runs with `--token`. |

What the server shares and what it does not, per trivy's client/server design:

- Shared: the vulnerability DB and the vulnerability matching (server side),
  and for **image** scans the per-layer analysis cache. A client asks the
  server which layer keys are missing and only downloads and analyzes those;
  a layer another client already analyzed is neither pulled nor re-analyzed.
- Not shared: **filesystem** scans always analyze locally (the server's cache
  is only consulted for clean git repositories), so they share the DB and
  nothing else. The Java DB, needed to analyze JAR files, is downloaded on the
  client when a JAR is analyzed, so `SCANNER_TRIVY_CACHE_DIR` still needs room
  for it.
- Trust: an image layer's cache key is derived from the diff ID the image's
  config *claims*; trivy does not re-hash the layer content against it. A
  client that scans a crafted image first can therefore store a false
  analysis under the diff ID of a real layer, and every later client in the
  same partition reuses it. Give adapters that do not trust each other
  distinct `SCANNER_TRIVY_CACHE_PARTITION` values (or separate servers).
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

## Offline use and vulnerability-DB import (adapter >= 1.7.0)

For a disconnected install, set one switch:

| Variable | Effect |
|---|---|
| `SCANNER_OFFLINE` | Default `false`. `true` implies `SCANNER_TRIVY_SKIP_DB_UPDATE=true` (even if that is set to `false`), skips the startup DB download, and runs every image and filesystem scan with `--skip-db-update --skip-java-db-update --offline-scan`, so trivy contacts no DB registry, no Java DB registry and no other network API. Logged once at startup. JAR files are matched only if a Java DB is already in the cache. |
| `SCANNER_ADAPTER_TOKEN` | Shared bearer token for `GET`/`PUT /api/v1/vulndb`. Unset (default): both routes answer 403. The scan routes are not affected. |
| `SCANNER_TRIVY_DB_SCHEMA_VERSION` | Default `2`. The `Version` an imported `metadata.json` must carry. trivy does not report the schema it expects, so it is configured; it is the major tag of the DB artifact (`trivy-db:2`) and only changes with a trivy release that moves to a new schema. |
| `SCANNER_VULNDB_MAX_UPLOAD_BYTES` | Default 2 GiB. Cap on the compressed upload (413 above it). |
| `SCANNER_VULNDB_MAX_EXTRACTED_BYTES` | Default 8 GiB. Cap on the unpacked files (400 above it). |

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
