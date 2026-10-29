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

### Instance lock

An instance administrator can hold a repository's proxy scan policy
centrally (#4363, migration 300). Any `PUT .../security` by an instance
administrator locks the policy unless the body says `"instance_locked": false`,
which hands it back to the repository's administrators. The lock is shown as
`instance_locked` on `GET .../security` and on `GET /api/v1/security/configs`.

While the lock is on, a repository administrator can still tighten the proxy
scan policy but gets `403` (and nothing is written) for any change that
weakens it:

- turning `scan_on_proxy` off;
- moving `proxy_scan_action` towards `record_only` (`fail_closed` to
  `fail_open`, or either to `record_only`);
- loosening the severity gate: turning `block_on_policy_violation` on (from
  "any finding blocks") or raising `severity_threshold` (for example `high`
  to `critical`).

A repository administrator who sends `instance_locked` at all gets `403`.
`scan_enabled` and `scan_on_upload` are not governed by the lock. Existing
configurations start unlocked. During a rolling upgrade a replica still on
1.11 does not know the lock and accepts any write a repository administrator
makes; finish the upgrade before relying on it.

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

**Duplicate entry paths.** A package archive in which two files share one path
(after `./` and empty path components are dropped), in the archive itself or,
for a conda `.conda`, across its payload tars, is inconclusive before any of
the checks above run. The metadata check reads one copy of a manifest and the
scan workspace unpacks the other, so neither can be vouched for. Published
packages do not carry repeated paths.

**Archive formats graded on their contents (Go, Composer, Conan, CocoaPods, Swift).** The gate
takes the coordinate from the request and checks it against the archive
first, as for every format: a Go module zip must hold only
`{module}@{version}/` entries and its `go.mod` (when it has one) must declare
that module; a Composer dist's own `composer.json` (at the archive root, or
under the one top-level directory a VCS zipball wraps it in) must name the
requested package, and a `version` it declares must be the requested one;
a CocoaPods pod archive's own `{name}.podspec.json` (at the root or one
directory down) must declare the requested name and version; a Conan
archive carries no coordinate of its own, so it must only be a readable
gzipped tar, and a Swift source archive must be a readable zip with a
`Package.swift` at the root or under its one top-level directory (the
registry's `scope.name` appears nowhere in the archive). Bytes that fail that check, or are not a readable archive of that kind, are
inconclusive and are not scanned, so no verdict is recorded for them:
`423` under `fail_closed`, served `pending` under `fail_open` and
`record_only`.

The bundled engine does not catalog a module zip, a dist archive or a Conan
archive as itself. For Go, Composer and Conan the gate therefore pins the
requested coordinate, as it does for npm or Cargo: the scan workspace gets a
one-line `go.mod` that requires `{module} {version}`, a `composer.lock`
naming the requested package and version, or a `conan.lock` requiring the
requested `name/version` (#4952). The engine grades that coordinate itself
(an advisory against `golang.org/x/text v0.3.0`, pulled as its own module
zip, blocks it), and it must catalog it before a `clean` verdict counts.
A coordinate the pin file cannot carry exactly (a space, a quote, a newline)
is inconclusive and not scanned.

The archive is still graded on what it contains too: the requirements in a
module's `go.mod`, a `composer.lock` or `installed.json` shipped in a dist,
a `conanfile.txt` or `conan.lock` in a recipe's sources, a binary in a
package, a vendored package of any ecosystem the engine recognises. CocoaPods
and Swift have no pin and are graded on their contents alone: a scan that ran
to completion and found nothing is `clean`, recorded with how many components
were cataloged (often `0`) and reused like any other verdict. See
[Known gaps](#known-gaps).

**Pub.** A Pub archive's root `pubspec.yaml` must declare the requested
name and version, or the archive is inconclusive and not scanned. The
bundled engine catalogs a `pubspec.yaml` as the package it declares, so an
archive that agrees is graded as that package version.

**Operating-system packages (Debian, RPM, Alpine).** A Debian, RPM or Alpine
package is graded by the scanner only against the advisory feed of one
distribution release (`debian:12`, `ubuntu:22.04`, `rhel:9`, `alpine:3.19`),
and a lone package file names none. The gate therefore checks the package
against the request, determines the release, and writes a synthetic installed
system into the scan workspace: an `etc/os-release` naming the release, plus,
for Debian, a one-entry `var/lib/dpkg/status` built from the package's own
`control`, and for Alpine a one-entry `lib/apk/db/installed` built from its
own `.PKGINFO` (the scanner reads an RPM's own header). The package is graded
as itself, through its source package too (`libssl3` is graded as `openssl`,
and so is Alpine's `libcrypto3` through its `origin`).

- *Identity.* A `.deb`'s own `control` must name the package, version (a pool
  file name carries no epoch) and architecture of the requested file name; an
  `.rpm`'s own header must name its name, version, release and architecture;
  an `.apk`'s own `.PKGINFO` must name exactly the requested
  `{pkgname}-{pkgver}.apk`, for the requested architecture or `noarch`.
  Bytes that disagree, that are not a readable package, or whose metadata can
  be read in more than one way (two `control.tar` members, two `control`
  entries, two `.PKGINFO` entries, a field or an RPM header tag given twice)
  are inconclusive and not scanned.
- *Release, Debian.* The release the remote's own cached `Release` /
  `InRelease` names (`Origin` Debian or Ubuntu, then `Version` or
  `Codename`), for the suite whose cached `Packages` index lists the file, or
  else the one release every cached suite of the remote agrees on; failing
  both, a stable-update or backport version (`+deb12u1`, `~bpo12+1`). The
  remote's `Release` is cached by any `apt update` through it.
- *Release, RPM.* The dist tag in the package's release: `el9` / `el9_2` is
  RHEL 9 (RHEL rebuilds such as Rocky, AlmaLinux and Oracle Linux are graded
  against the RHEL feed, as the scanner itself grades them), `fc40` Fedora 40,
  `amzn2023` Amazon Linux 2023.
- *Release, Alpine.* The requested branch: `v3.19` is Alpine 3.19, `edge`
  is edge. A branch such as `latest-stable` names no fixed release.
- A release is used only when the bundled vulnerability database has an
  advisory feed for it (Debian 7 to 14, the Ubuntu releases from 12.04,
  RHEL 5 to 10, Fedora, Amazon Linux 2 and 2023, Alpine 3.2 to 3.24 and
  edge): the scanner matches nothing on a release it has no feed for, which
  would read as clean.
- A package for which no release the scanner has a feed for can be
  determined is inconclusive and not scanned: `423` under `fail_closed`,
  served `pending` under `fail_open` and `record_only`. See
  [Known gaps](#known-gaps).
- *Debian `Packages` digest.* When a cached `Packages` index records the
  file's SHA-256 (#2459), bytes that do not match it are evicted from the
  proxy cache and refused with `502` before the gate, as before for the
  unscanned path.

**Packages the scanner does not catalog as themselves (conda).** For npm,
PyPI, RubyGems, Cargo, NuGet and Maven the scanner catalogs the package itself
(through the pin the gate writes, or the archive's own metadata), so a scan
that catalogs nothing graded nothing and is inconclusive. No bundled scanner
catalogs a conda package as a conda component: it catalogs what the package
installs (a `.dist-info`, a binary it recognises). A compiled library or a
data package (`tzdata`, `ca-certificates`) has nothing of that kind. For
`conda` and `conda_native`, a scan that ran to completion over the unpacked
archive and cataloged nothing is therefore graded on its findings: no
findings is a `clean` verdict, and a finding is `vulnerable` as usual. The
verdict is stored with `components_cataloged: 0` and reused like any other,
so `fail_closed` serves it inline and `fail_open` records it for the next
pull (#4594). The rule does not relax anything else:

- a scan that could not run (archive not unpackable, scanner error, timeout,
  over the byte cap) is still inconclusive;
- a package whose `info/index.json` disagrees with its file name is still
  withheld without a scan;
- a scan that cataloged a `name@version` other than the one in the file name
  is still inconclusive.

`generic` does not run the gate, so the rule does not apply to it. If it
adopts the gate, a generic file has no coordinate to pin and an empty catalog
is already graded on its findings.

**One decision per request.** Each enforced format derives the proxy-cache key
and the "is this a package the gate must see" decision from the same
normalized request path, so two spellings of one file (a trailing `/`, a
re-capitalised VS Code asset type) share one cache entry and one decision. A
path holding `?`, `#`, `;`, a control character or a stray `%` is always
treated as a package.

**Ambiguous proxied paths.** Two checks keep the upstream from answering for a
different file than the one classified and cached, each a `400` before any
upstream request:

- *What the client sent.* On the npm tarball, PyPI file and Cargo download
  routes, the VS Code gallery routes (asset, `vspackage`, legacy download),
  the generic download route's Remote arm, and (already before) the Maven,
  sbt and NuGet routes, a client path containing any `?`,
  `#`, `;`, `\`, a control character or a `%` that is not a valid `%XX`
  escape is refused. The format routes also refuse raw spaces; the generic
  route allows them, since stored file names may contain them. Since
  1.12.0 the same check runs on every Remote and Virtual route of Go,
  RubyGems, Composer, Pub, Conan, CocoaPods, Swift, Debian (pool, `dists/`
  and flat layouts), RPM (`/packages/` and the catch-all, metadata
  included) and Alpine.
- *The upstream path ProxyService builds.* Every relative upstream path a
  Remote fetch sends, for every format, is refused if its path part contains
  `#`, `;`, `\`, a control character, a stray `%` or a trailing space, or if
  a `?` starts an empty query or one containing `/`. Queries a handler
  appends itself (Ansible version pages, Conan search, OCI `tags/list`) pass.
  Absolute URLs a handler builds or takes from an upstream index (Helm,
  PyPI, npm, NuGet, the VS Code gallery) are not checked here; those
  handlers validate the client's segments themselves before building them.

Valid escapes (npm's scoped `%2F`) and Go's `!` case-escaping are unaffected.

**Unreadable configuration.** If a repository's scan configuration cannot be
read, the pull fails with a retryable `503` on every enforced format's Remote
arm, every Virtual walk and the generic download route. It is never treated
as "scanning off" (#4365).

## Seeing what was blocked

- `GET /api/v1/security/dashboard` returns `proxy_blocked`: the distinct
  proxied digests that a repository's proxy scan gate refuses right now.
  `policy_violations_blocked` keeps its meaning (hosted rejections plus these).
- `GET /api/v1/security/proxy-blocked` lists them across repositories:
  repository, cached path, digest, highest severity and counts, CVE ids (most
  severe first, at most 20), and when the verdict was recorded. Query:
  `repository`, `min_severity`, `page`, `per_page`. Instance administrators
  with an unrestricted credential only. An item is listed only where that
  repository's own settings refuse it: a record-only repository, or one whose
  threshold is above the verdict, does not list content it serves. Like the
  gate, a verdict older than the 30-day window is not listed (the next pull
  scans the bytes again).
- `GET /api/v1/admin/holds/policy-blocks` shows the same proxied content next
  to the hosted artifacts a scan policy refuses (see
  [download holds](download-holds.md)).
- Each refused pull writes a `PROXY_SCAN_BLOCKED` audit entry with the
  principal, client IP, repository, path, digest and verdict, aggregated per
  digest and principal per minute; see
  [audit events](../audit-events.md#proxy-scan-refusals).

Refusals answered outside the shared gate are not audited yet: a conda
attestation sidecar of a blocked package, the NuGet digest-pinned row repair
path, and OCI image pulls.

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

A verdict also records the coordinate it was graded as (`pin_identity`,
migration 301). For most formats the bytes name that coordinate themselves (an
npm tarball's `package.json`, a crate's `Cargo.toml`), so one verdict per
digest is enough. Go, Composer, Conan, Debian, RPM and Alpine are graded as
the coordinate the REQUEST names, which the bytes need not carry: a Composer
dist usually declares no version, a Conan archive names no reference, and an
OS package is graded against the release its repository names. For those
formats a stored verdict is reused only when it was graded as the coordinate
being requested. A verdict graded as another version, reference or release,
or a `clean` one graded without a coordinate (the rescan endpoint), is not
reused, and the bytes are scanned again as for a first pull; a `vulnerable`
verdict graded without a coordinate still blocks. A pull whose identity
cannot be established (for example an OS package whose release cannot be
determined) never inherits a `clean` verdict graded as another coordinate or
graded without one, and is still refused by a stored `vulnerable` one
(#4952).

Each verdict also records `components_cataloged`: how many distinct
components the scanner cataloged when it graded the bytes (migration 287).
`GET /api/v1/repositories/{key}/security/proxy-scans` returns it on every
`clean` or `vulnerable` item. `0` means the verdict was graded on the file
contents only (see the conda rule above); `null` means the scanner reported no
catalog, or the verdict was recorded before 1.11.0.

A `fail_closed` repository does not reuse a `clean` verdict that has no
findings, cataloged no components (`0` or `null`) and was recorded without a
coordinate. Verdicts are shared by every repository that serves the same
bytes, and such a verdict says only that a scan saw nothing it could grade.
The bytes are scanned again as for a first pull, and a pull whose identity
cannot be established is withheld (`423`). A `clean` verdict recorded with a
coordinate, such as a conda package graded on its contents, is reused as
before. A rescan in a repository whose format does not scan on proxy (for
example `generic`) in which the scanner catalogs nothing and finds nothing is
inconclusive: it answers `503` and records no verdict.

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

## The artifacts routes

The repository `artifacts` routes behave the same for every enforced format.
The formats gated in 1.12.0 (Go, RubyGems, Composer, Pub, Conan, CocoaPods and
Swift) follow the rules the earlier formats (npm, PyPI, Maven, NuGet, Cargo
and the rest of the [coverage table](#coverage)) already did. For a Remote
repository that scans on proxy:

| Route | What it returns | Gate |
| --- | --- | --- |
| `GET /api/v1/repositories/{key}/artifacts` | The files the proxy cache holds, rebuilt from the proxy-cache catalog: path, size, when it was cached, download count. Each item has a synthetic id and `analyzable: false`. | None. It serves no bytes and does not read verdicts, so a cached file is listed whatever its verdict. |
| `GET /api/v1/repositories/{key}/artifacts/*path` | The metadata (JSON) of an `artifacts` row at that path; `404` when there is none. It never reads the proxy cache or the upstream. | None. It serves no bytes. |
| `GET /api/v1/repositories/{key}/download/*path` | A file the cache or the upstream would supply: `403` `scan_on_proxy_route_required` (see [The generic download route](#the-generic-download-route)). An `artifacts` row: its bytes from storage. | Refuses proxied files; serves rows without a scan. |
| The format route (`/go/{key}/...`, `/gems/{key}/...`, ...) | An `artifacts` row: its bytes from storage, through the gate. Otherwise the file through the gate. | Gates proxied files and rows. |

The reasoning:

- The listing and the metadata route are catalogs, not downloads. The web UI
  lists a Remote's cached files through the first route and downloads one
  through the generic download route, which refuses it for a scanning
  Remote; a client pulls it through the format route, which gates it.
- The gate grades bytes against the coordinate a format route parses from its
  own request (#3003), so only the format route can run it. The generic route
  has no such parser and refuses instead of serving unscanned.
- An `artifacts` row in a Remote repository (from replication, or recorded
  before proxied content stopped being stored as rows) is content the
  repository holds, not a proxied fetch. The format route serves it from
  storage through the gate (#4514): a blocking verdict for its SHA-256 is
  the `403`, under `fail_closed` a row with no reusable verdict is scanned
  inline (`423` if the scan is inconclusive), under `fail_open` it is served
  `pending` and scanned in the background, and a row over the scan cap is
  `423` under `fail_closed` and served `pending` otherwise. The row is
  graded as the coordinate the request names, by the same identity rule a
  proxied file of that format is, so a row whose archive declares another
  package or version, cannot be read, or holds two entries at one path is
  withheld under `fail_closed` exactly as the proxied file would be. The
  generic download route still serves a row without a scan. See
  [Known gaps](#known-gaps).

For a Virtual repository, `GET .../artifacts/*path` serves a member's bytes
through the member walk, so it takes the same refusal as the generic download
route: `403` when a Remote member the caller may read scans under the
stricter-of-two rule (see [Virtual repositories](#virtual-repositories)). The
listing aggregates the `artifacts` rows of the members the caller may see and
serves no bytes.

A unit test in `api/handlers/repositories.rs`
(`generic_route_checks_exactly_the_enforced_formats_4442`) pins the generic
route's refusal to exactly the formats `GET /api/v1/formats` reports as
`enforced`, and names each 1.12.0 format, so a format cannot adopt the gate
without the generic route refusing it too.

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
| `go` | `go` | enforced | Module `.zip` downloads, Remote and Virtual, graded as the requested `module@version` and on their contents (see [Archive formats graded on their contents](#archive-formats-graded-on-their-contents)). `.mod`, `.info`, `@v/list` and `@latest` are not gated. |
| `rubygems` | `rubygems` | enforced | `.gem` downloads, Remote and Virtual. The gem is graded as the `{name}-{version}` its file name names, which its gemspec must declare. Spec indexes and the JSON API are not gated. |
| `oci` | `docker`, `podman`, `buildx`, `oras`, `wasm_oci`, `helm_oci` | enforced | Image manifests: the whole image (config and layers) is scanned, and blob pulls re-check the verdict of the image they belong to. Remote and Virtual. |
| `helm` | `helm` | accepted | |
| `rpm` | `rpm` | enforced | Every file on the `/packages/` route and the catch-all, Remote and Virtual, except repository metadata and signing material (anything under `repodata/`, `repomd.xml` and its signature and key, `.treeinfo`, `media.repo`, `RPM-GPG-KEY*`, `.asc`/`.sig`/`.gpg`/`.key` files). An `.rpm` is graded as itself on the release its dist tag names (see [Operating-system packages](#what-the-gate-does)); any other file (a `.drpm`, an installer image) is inconclusive. A package of a published `@N` snapshot is served checksum-verified against the snapshot and is not gated. |
| `debian` | `debian` | enforced | Every `pool/` file except `.dsc`, `.buildinfo` and `.changes`, and the `.deb`/`.udeb`/`.ddeb` packages of a `dists/` or flat layout, Remote and Virtual. A binary package is graded as itself on the release the remote's `Release` names (see [Operating-system packages](#what-the-gate-does)); a source tarball or diff is inconclusive. `Release`, `InRelease`, `Packages`, `Sources`, every other index and the installer files under `dists/` (`installer-<arch>/`) are not gated. |
| `conan` | `conan` | enforced | Every recipe and package file except `conanfile.py`, `conanmanifest.txt` and `conaninfo.txt`, Remote and Virtual: the `.tgz` archives (`conan_export.tgz`, `conan_sources.tgz`, `conan_package.tgz`) and any other file name, graded as the requested `name/version` and on their contents (see [Archive formats graded on their contents](#archive-formats-graded-on-their-contents)). A file that is not a gzipped tar (a zstd `.tzst`, a Conan 2 metadata file) is inconclusive: `423` under `fail_closed`. The three metadata files, revision lists and search are not gated. |
| `cargo` | `cargo` | enforced | `.crate` downloads, Remote and Virtual. |
| `generic` | `generic`, `github`, `mise`, `aqua` | accepted | |
| `conda` | `conda` | enforced | `.conda` and `.tar.bz2` package downloads, Remote and Virtual, including the `/t/<token>/` URL forms. A `.sigs` attestation sidecar follows its package: a stored verdict that blocks the package refuses the sidecar too. Channel indexes (repodata in every encoding, channeldata, shards) are not gated. |
| `terraform` | `terraform`, `opentofu` | accepted | |
| `alpine` | `alpine` | enforced | `.apk` downloads on the `{branch}/{repository}/{arch}/` route, Remote and Virtual, graded as themselves on the release the branch names (see [Operating-system packages](#what-the-gate-does)). `APKINDEX.tar.gz` and the signing key are not gated. |
| `conda_native` | `conda_native` | enforced | As `conda` (the same route). |
| `composer` | `composer` | enforced | Dist archives on the `dist/` route, Remote and Virtual, graded as the requested package version and on their contents (see [Archive formats graded on their contents](#archive-formats-graded-on-their-contents)). Package metadata is not gated. |
| `hex` | `hex` | accepted | |
| `cocoapods` | `cocoapods` | enforced | Pod archives on the `pods/` route, Remote and Virtual, graded on their contents (see [Archive formats graded on their contents](#archive-formats-graded-on-their-contents)). The pod's own `.podspec.json` must declare the requested name and version. Specs and CDN index files are not gated. |
| `swift` | `swift` | enforced | Source archives (`{scope}/{name}/{version}.zip`), Remote and Virtual, graded on their contents (see [Archive formats graded on their contents](#archive-formats-graded-on-their-contents)). Release metadata, release lists and `Package.swift` are not gated. |
| `pub` | `pub` | enforced | Package archives on the `packages/{name}/versions/{version}.tar.gz` route, Remote and Virtual. The root `pubspec.yaml` must declare the requested name and version; the scanner then catalogs the package from it. The JSON API is not gated. |
| `sbt` | `sbt` | enforced | As `maven`, on the Ivy route. |
| `chef` | `chef` | accepted | |
| `puppet` | `puppet` | accepted | |
| `ansible` | `ansible` | accepted | |
| `gitlfs` | `gitlfs` | accepted | |
| `vscode` | `vscode` | enforced | Extension packages: the gallery download (Remote) and the legacy `.vsix` route (Remote and Virtual). Gallery asset types are matched ignoring case; only display metadata (manifest, details, changelog, license, icons, `.vsixmanifest`, signature, language-pack translations) streams unscanned, and any other asset type is `404` while scanning is on. |
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
- **Package rows in a Remote repository.** A Remote can hold `artifacts`
  rows of its own (from replication, from a publish into the remote, or
  recorded before proxied content stopped being stored as rows).
  - Go, RubyGems, Composer, Pub, Conan, CocoaPods and Swift: the format
    route serves such a row through the gate (see
    [The artifacts routes](#the-artifacts-routes)).
  - NuGet, Debian, RPM and Alpine, and the rows of the other enforced
    formats: the format route still serves a row whose blob is present from
    storage without the gate. For NuGet, if the blob has gone missing and
    the row records a SHA-256, the re-fetched bytes are held to that digest
    instead of being scanned, and a stored `vulnerable` verdict for that
    digest refuses the pull (`403`); a row with no digest is re-fetched
    through the gate.
  - Every enforced format: the generic download route serves a row from
    storage without the gate.
- **Conda packages graded on file contents.** A conda package the scanner
  catalogs nothing for is graded on its findings alone and recorded with
  `components_cataloged: 0` (#4594). A clean result there means the scanner
  read the unpacked files and matched no advisory; there was no component
  identity to look up, so a vulnerable library the scanner does not recognise
  is not found. The proxy-scans view shows the `0` so these verdicts can be
  told apart from component-graded ones.
- **Conda packages cataloged under a different name.** When the scanner does
  catalog something for a conda package but not the `name@version` in the
  file name (a binary it recognises under its upstream name or version), the
  scan is still inconclusive: `423` under `fail_closed`, served `pending`
  (and not recorded) under `fail_open`.
- **CocoaPods and Swift have no advisory data in the bundled scanner.** The
  engine catalogs a `Podfile.lock` or `Package.resolved`, but no advisory
  database it ships covers either ecosystem, so a pod or Swift package is
  only ever `vulnerable` for something of another ecosystem inside it (a
  vendored `Gemfile.lock`, `package-lock.json`, a jar).
- **Hex is not gated.** `hex` stays `accepted` (#4106): the scan workspace
  does not unpack a Hex tarball (an uncompressed outer tar around
  `contents.tar.gz`), so wiring the gate would grade bytes nothing read.
- **Only bytes fetched through the repository are gated.** A CocoaPods
  Remote proxying the CocoaPods CDN serves podspecs whose `source` names a
  git repository or an outside URL, and the client fetches the pod from
  there, not through the `pods/` route; the same holds for a Composer
  package installed from `source` (a VCS checkout) instead of its `dist`,
  and for a Go client whose `GOPROXY` falls back to `direct`.
- **One stored verdict per digest.** A digest holds one verdict row, so
  byte-identical files pulled alternately as two coordinates (see
  [Verdicts and freshness](#verdicts-and-freshness)) are scanned again on
  each switch, and the proxy-scans view, the dashboard and the listings show
  the verdict of the coordinate graded last.
- **Conan references are graded by name and version only.** The Conan pin
  is the requested `name/version`; the user, channel and revisions are not
  part of what the engine grades, so two revisions of one version get the
  same advisories.
- **OS packages need a release the scanner has a feed for.** A Debian
  package from a remote whose `Release` names another origin (a vendor
  repository built on Debian) and whose version names no Debian release, an
  RPM without an `el`, `fc` or `amzn` dist tag (a third-party package), an Alpine
  package requested through a branch that names no release (`latest-stable`),
  and a package of a release the bundled scanner has no feed for (Debian
  `sid`) are
  inconclusive: `423` under `fail_closed`, served `pending` and never given a
  verdict under `fail_open`. A Debian Remote that has never served its
  `Release` (no `apt update` through it) falls back to the version, so a
  package of the base release (`2.10-3`) is inconclusive until one has.
- **Debian source packages and RPM non-packages are inconclusive.** Under
  `fail_closed` a scanning Debian Remote withholds source tarballs and diffs
  from `pool/` (`apt-get source` fails), and a scanning RPM Remote withholds
  every file that is not an `.rpm` and not repository metadata (`.drpm`
  deltas, installer trees under `images/` or `LiveOS/`).
- **OS package paths and releases come from the upstream's metadata.** A
  Remote does not verify the upstream's signature on `Release` /
  `InRelease` or `repomd.xml`; it re-signs what it serves. The release a
  Debian package is graded against is the one that `Release` names, and the
  paths a client fetches packages from are the ones the upstream's
  `Packages` (`Filename`) and `primary.xml` (`location`) name. Both are
  trusted as the package bytes themselves are: an upstream that names an
  older release than the package's own grades it against that release's
  feed, and a package file the upstream's index places under a metadata name
  (a `.dsc`, a `repodata/` path, a `.asc` file) streams unscanned. Alpine
  file names and branches come from the client's request, and an RPM's
  release from its own header.
- **Conda `.sigs` sidecars** follow the stored verdict of their package's
  cached bytes. Before the package has been pulled through the repository
  there is nothing to follow and the sidecar is served.
- **NuGet symbols packages** (`.snupkg`) are scanned without an identity pin:
  they hold `.pdb` files and no package identity the engine grades, so a
  vulnerable verdict blocks them but a missing pin does not withhold them.
