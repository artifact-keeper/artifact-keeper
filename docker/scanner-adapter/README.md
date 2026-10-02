# scanner-adapter

Independent semver, source of truth: `docker/scanner-adapter/VERSION`. The image is
tagged by its own version (`1.0.0` / `1.0` / `1` / `latest`), decoupled from AK's
appVersion.

Compat: backend ≥1.2.4 requires scanner-adapter major 1.x (Harbor Pluggable Scanner API v1).

## Client/server mode (adapter >= 1.3.0)

By default the adapter runs trivy standalone: it downloads its own
vulnerability DB into `SCANNER_TRIVY_CACHE_DIR` at startup and does all
analysis and matching locally. Several adapters can instead share one
`trivy server`:

| Variable | Effect |
|---|---|
| `SCANNER_TRIVY_SERVER` | Absolute `http(s)://host:port` of a `trivy server`. Every image and filesystem scan runs as `trivy --server <url>`. No local vulnerability DB is downloaded; `/probe/ready` answers 200 only while `GET <url>/version` reports a loaded DB and the same trivy release as the bundled CLI (re-checked at most every 10s). Empty (default): standalone. |
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
  not refuse a mismatched client; the readiness check does).
