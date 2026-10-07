# Scan-on-proxy

Scan-on-proxy scans package bytes that a Remote repository fetches from its
upstream, and refuses to serve them when the scan finds vulnerabilities your
policy blocks. It works per repository and per format: the
[coverage table](#coverage) lists the formats whose proxy path runs the gate.
For any other format the setting is stored, but proxied downloads are served
unscanned.

`GET /api/v1/formats` reports the same information for each format handler as
`scan_on_proxy`: `enforced`, `accepted` (stored, not enforced) or `unsupported`
(a WASM plugin format). A unit test keeps the table below in step with that
capability, so a format cannot start or stop enforcing without this page
changing too.

## Turning it on

The settings live in the repository's scan configuration
(`GET`/`PUT /api/v1/repositories/{key}/security`):

| Field | Meaning |
| --- | --- |
| `scan_on_proxy` | Run the gate on this repository's proxied downloads. Off by default. |
| `proxy_scan_action` | `fail_open` (default), `fail_closed` or `record_only`. See [Actions](#actions). |
| `block_on_policy_violation` | Off (default): any finding blocks. On: only findings at or above `severity_threshold` block. |
| `severity_threshold` | `critical`, `high`, `medium`, `low` or `info`. Used only with `block_on_policy_violation`. |

A Virtual repository has its own scan configuration too. See
[Virtual repositories](#virtual-repositories).

## What the gate does

For each proxied package file of an enforced format:

1. The file is fetched buffered, cache-first, up to 200 MiB. A repeat pull is
   answered from the proxy cache with no upstream request.
2. The SHA-256 of the exact bytes is computed. Verdicts are keyed by this
   digest, never by name or URL.
3. The digest's stored verdict is looked up (see
   [Verdicts and freshness](#verdicts-and-freshness)). A reusable `vulnerable`
   verdict blocks at once and a reusable `clean` verdict serves at once, both
   without scanning again.
4. Otherwise the bytes are scanned, inline or in the background depending on
   the action, and the verdict is stored.
5. The download is recorded and the bytes are served with an `X-AK-Scan`
   header, or the pull is refused.

Responses:

| Outcome | Status | Body / header |
| --- | --- | --- |
| Clean | `200` | `X-AK-Scan: clean` |
| Served before a verdict exists (fail-open, record-only) | `200` | `X-AK-Scan: pending` |
| Vulnerable, record-only | `200` | `X-AK-Scan: recorded` |
| Vulnerable and blocked by the policy | `403` | `{"error": "scan_blocked", "file": ...}` |
| No conclusive verdict under fail-closed | `423` | `{"error": "scan_pending", "file": ...}`; retry later |
| Scan configuration unreadable (database fault) | `503` | Retry later; never served unscanned |
| Requested through the generic download route instead of the format route | `403` | `{"error": "scan_on_proxy_route_required", "file": ..., "handler": ...}`; see [The generic download route](#the-generic-download-route) |

**Identity.** The gate takes the package coordinate from the request (for
example the NuGet id and version in the URL) and checks it against the
package's own metadata (`.nuspec`, `Cargo.toml`, `package.json`,
`pom.properties`, ...). When they agree, the scan must actually grade that
coordinate before a clean verdict counts. When they do not agree, or the bytes
are not a readable package, the scan is inconclusive: these bytes are not what
they are served as. A `vulnerable` verdict on the bytes still blocks either
way.

**One decision per request.** Each enforced format derives the proxy-cache key
and the "is this a package the gate must see" decision from the same
normalized request path, so two spellings of one file (a trailing `/`, a
re-capitalised VS Code asset type) share one cache entry and one decision. A
path holding `?`, `#`, `;`, a control character or a stray `%` is always
treated as a package.

**Ambiguous upstream paths.** For every format, a Remote fetch whose relative
upstream path contains `#`, a `;`, a control character or a `%` that is not a
valid `%XX` escape in a path segment, or a `?` that does not start a non-empty
query without `/`, is refused with `400` before any upstream request. Such a
path could make the upstream answer for a different file than the one
classified and cached. Valid escapes (npm's scoped `%2F`), Go's `!`
case-escaping and absolute URLs taken from an upstream index (Helm, PyPI,
npm) are unaffected.

**Unreadable configuration.** If a repository's scan configuration cannot be
read, the pull fails with a retryable `503` on every enforced format's Remote
arm, every Virtual walk and the generic download route. It is never treated
as "scanning off" (#4365).

## Actions

| `proxy_scan_action` | First pull of unknown bytes | Vulnerable | Inconclusive (over the byte cap, scan error, timeout, identity mismatch) |
| --- | --- | --- | --- |
| `fail_open` | Served with `X-AK-Scan: pending`, scanned in the background. The next pull of the same digest is gated. | `403` | Served, `pending` |
| `fail_closed` | Scanned inline before a byte is served. | `403` | `423`, never unscanned bytes |
| `record_only` | As `fail_open`. | Served with `X-AK-Scan: recorded`; the verdict and findings are still recorded | Served, `pending` |

`record_only` (migration 256) gives you visibility without enforcement: every
pull is scanned and recorded, and no pull is withheld. An object over the
200 MiB cap is never buffered. Under `fail_closed` it is `423`. Otherwise it
streams unscanned with `X-AK-Scan: pending`.

## Verdicts and freshness

Verdicts are stored per content digest in `proxy_scan_results` and shared
across repositories: identical bytes have identical vulnerabilities. They
survive proxy-cache eviction. A stored verdict is reused while both of these
hold:

- it is less than 30 days old, and
- the scanner version it was recorded with matches the live scanner version
  (a vulnerability-database update changes the version, so the bytes are
  scanned again against the new data).

If either version string is unknown, a `fail_open` or `record_only`
repository falls back to the 30-day window alone. A `fail_closed` repository
reuses a `clean` verdict only when both versions are known and equal;
otherwise it scans again, and an inconclusive result is `423`.

## Virtual repositories

A Virtual repository walks its members in their configured priority order,
over the members the caller may read.

- A Remote member is scanned under the **stricter of two** policies: the
  Virtual's own scan configuration and the member's. Scanning is on if either
  side enables it. `fail_closed` beats `fail_open`, which beats `record_only`,
  and the severity gate is the stricter of the two.
- A hosted member, or a Remote member that does not scan, is served as before.
  A lower-priority Remote member never shadows a hosted copy.
- A scanning member's `403`, `409` (quarantine hold) or `423` is its verdict
  on bytes it holds, and ends the walk. Any other failure (`404`, an upstream
  error, a `502` checksum mismatch) moves on to the next member.
- If the members' scan configuration cannot be read, the pull fails with a
  retryable `503` instead of serving unscanned.
- On the generic routes that serve a member's bytes (`download/*path` and
  `artifacts/*path`), a Virtual repository refuses with `403` when
  a Remote member the caller may read would scan under the stricter-of-two
  rule. See [The generic download route](#the-generic-download-route).

## The generic download route

`GET /api/v1/repositories/{key}/download/*path` serves any repository's files,
and the web UI's download button and file viewer use it. The same handler also
answers on `/general/{key}/*path`. It has no per-format request identity to run
the gate against, so for an enforced format it does not proxy while scanning
is on (#4442):

- A Remote repository with `scan_on_proxy` on refuses every file it would
  fetch from its proxy cache or upstream: `403` with
  `{"error": "scan_on_proxy_route_required", "file": ..., "handler": ...}`.
  `handler` is the format handler whose route serves the file through the
  gate, for example `npm` (`/npm/{key}/...`) or `maven` (`/maven/{key}/...`,
  for Gradle too). Two handlers are mounted under another name: `sbt` serves
  `/ivy/{key}/...` and `oci` serves `/v2/...`.
- The refusal applies under every `proxy_scan_action`, `record_only`
  included, and to every path, metadata included. That is stricter than the
  Maven route, which serves POMs, `.xml` metadata and checksums unscanned.
  It applies to `HEAD` as well, so a `HEAD` can neither confirm an upstream
  file nor cost an upstream request.
- A Virtual repository refuses the same way when a Remote member the caller
  may read scans under the stricter-of-two rule. This also covers
  `GET /api/v1/repositories/{key}/artifacts/*path`, which serves a Virtual
  member's bytes through the same member walk. A hosted member that owns the
  exact path is still served.
- If the `scan_on_proxy` flag cannot be read, the route answers `503` instead
  of serving unscanned.

Files stored in the repository itself (an `artifacts` row) are still served
from storage behind the repository's download gate. Formats that do not
enforce scan-on-proxy, and repositories with it off, are unaffected.

## Coverage

`enforced`: the format's Remote and Virtual download paths run the gate on the
files listed. `accepted`: the setting is stored and proxied downloads are
served unscanned. WASM plugin formats are `unsupported` (not applicable): they
have no core proxy path to gate.

<!-- coverage-table:start -->
| Handler | Repository formats | Scan-on-proxy | What is gated |
| --- | --- | --- | --- |
| `maven` | `maven`, `gradle` | enforced | Every proxied file on the Maven route except POMs, `.xml` metadata, Gradle `.module` files, checksums, signatures and `-sources`/`-javadoc` jars. Only `.jar`/`.war`/`.ear` carry an identity pin. |
| `npm` | `npm`, `yarn`, `bower`, `pnpm` | enforced | Package tarballs, Remote and Virtual. |
| `pypi` | `pypi`, `poetry`, `jupyter` | enforced | Package files (wheels and sdists), Remote and Virtual. |
| `nuget` | `nuget`, `chocolatey`, `powershell` | enforced | `.nupkg` downloads on the V3 flat container and the V2 `package/{id}/{version}` route, Remote and Virtual. The `.nuspec` manifest passes unscanned; against a V2 upstream, which has no separate manifest, the flat container answers only the `.nupkg` itself. |
| `go` | `go` | accepted | |
| `rubygems` | `rubygems` | accepted | |
| `oci` | `docker`, `podman`, `buildx`, `oras`, `wasm_oci`, `helm_oci` | enforced | Image manifests: the whole image (config and layers) is scanned, and blob pulls re-check the verdict of the image they belong to. Remote and Virtual. |
| `helm` | `helm` | accepted | |
| `rpm` | `rpm` | accepted | |
| `debian` | `debian` | accepted | |
| `conan` | `conan` | accepted | |
| `cargo` | `cargo` | enforced | `.crate` downloads, Remote and Virtual. |
| `generic` | `generic`, `github`, `mise`, `aqua` | accepted | |
| `conda` | `conda` | accepted | |
| `terraform` | `terraform`, `opentofu` | accepted | |
| `alpine` | `alpine` | accepted | |
| `conda_native` | `conda_native` | accepted | |
| `composer` | `composer` | accepted | |
| `hex` | `hex` | accepted | |
| `cocoapods` | `cocoapods` | accepted | |
| `swift` | `swift` | accepted | |
| `pub` | `pub` | accepted | |
| `sbt` | `sbt` | enforced | As `maven`, on the Ivy route. |
| `chef` | `chef` | accepted | |
| `puppet` | `puppet` | accepted | |
| `ansible` | `ansible` | accepted | |
| `gitlfs` | `gitlfs` | accepted | |
| `vscode` | `vscode` | enforced | Extension packages: the gallery download (Remote) and the legacy `.vsix` route (Remote and Virtual). Gallery asset types are matched ignoring case; only display metadata (manifest, details, changelog, license, icons, `.vsixmanifest`, signature) streams unscanned, and any other asset type is `404` while scanning is on. |
| `jetbrains` | `jetbrains` | accepted | |
| `huggingface` | `huggingface` | accepted | |
| `mlmodel` | `mlmodel` | accepted | |
| `cran` | `cran` | accepted | |
| `vagrant` | `vagrant` | accepted | |
| `opkg` | `opkg` | accepted | |
| `p2` | `p2` | accepted | |
| `bazel` | `bazel` | accepted | |
| `protobuf` | `protobuf` | accepted | |
| `incus` | `incus`, `lxc` | accepted | |
| `pacman` | `pacman` | accepted | |
<!-- coverage-table:end -->

## Known gaps

- **Cache commit before the verdict.** The buffered fetch commits upstream
  bytes to the proxy cache before the gate decides. A route that does not
  re-check the verdict can then serve them warm (#4514; see the design note
  [proxy-cache-commit-after-gate.md](proxy-cache-commit-after-gate.md)). The generic download
  route refuses before it reads the cache for a repository that scans on
  proxy. A non-scanning Remote member of a scanning Virtual is still subject
  to this gap: bytes the Virtual refused can be served warm by addressing the
  member directly, on its format route or on the generic route.
- **Maven-layout archives other than `.jar`/`.war`/`.ear`** (`.aar`,
  `.hpi`/`.jpi`, `.nbm`, `.jmod`, `.rar`, `.zip`) are scanned as raw files,
  not unpacked, and carry no identity pin.
- **NuGet package rows in a Remote repository.** A Remote NuGet repository
  can hold `artifacts` rows of its own (from before proxied content stopped
  being recorded as rows, from replication, or from a publish into the
  remote). A row whose blob is present is served from storage without the
  gate. If the blob has gone missing:
  - and the row records a SHA-256, the re-fetched bytes are held to that
    digest instead of being scanned, and a stored `vulnerable` verdict for
    that digest refuses the pull (`403`);
  - and the row records no digest, the re-fetch goes through the gate.
- **NuGet symbols packages** (`.snupkg`) are scanned without an identity pin:
  they hold `.pdb` files and no package identity the engine grades, so a
  vulnerable verdict blocks them but a missing pin does not withhold them.
