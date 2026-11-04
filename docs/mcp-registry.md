# MCP registry

An `mcp` repository is a private catalog of [Model Context Protocol](https://modelcontextprotocol.io)
servers. It speaks the MCP **registry API v0.1** (with the `/v0` alias) and
stores **server.json** documents (schema `2025-12-11`), so the clients that
read the official registry (`https://registry.modelcontextprotocol.io`) can
read it instead: VS Code's MCP gallery, GitHub Copilot's private registry
policy, and `mcp-publisher`.

It is not the MCP protocol itself (the `2026-07-28` protocol revision is what
a server speaks to its client). The registry only says which servers exist and
how to run them. The packages those servers run (an npm package, a PyPI
distribution, a container image) live in ordinary Artifact Keeper
repositories, and by default the registry refuses any server whose packages
are not there (see [Package policy](#package-policy)).

Every repository type is supported: **Local** and **Staging** (hosted,
publish here), **Remote** (an allowlist populated from an upstream registry,
deny by default) and **Virtual** (merges MCP repositories). See
[Remote repositories](#remote-repositories) and
[Virtual repositories](#virtual-repositories).

## Routes

Base: `https://<ak>/mcp/<repo_key>`. Every route below is also served under
`/v0` with identical bodies. `{serverName}` is the full name, either
URL-encoded (`com.acme%2Fweather`) or with a literal slash
(`com.acme/weather`).

| Method and path | Auth | What it does |
| --- | --- | --- |
| `GET /v0.1/servers` | read | List server versions. Query: `cursor`, `limit` (default 30, max 100; larger values clamp, `0`/negative/non-numeric is `400`), `search` (case-insensitive substring of the name, at least 3 characters or `422`), `version` (`latest` or an exact version), `updated_since` (RFC 3339; implies `include_deleted`, and `include_deleted=false` with it is `400`), `include_deleted`. |
| `GET /v0.1/servers/{serverName}/versions` | read | Every servable version, ordered by version text. `404` when none is servable. |
| `GET /v0.1/servers/{serverName}/versions/{version}` | read | One version; `{version}` may be `latest` (the newest servable version). |
| `POST /v0.1/publish` | write | Publish a server.json. `200` with `{server, _meta}` exactly as it will be served; `202` with the same plus `"status": "resolving"` when a package is still being filled into a Remote backing repository (see [Write path](#write-path-phase-2-and-3)). |
| `POST /v0.1/validate` | read | Dry run of a publish: `200` with `{valid, issues, packages}`; nothing is written. |
| `PUT /v0.1/servers/{serverName}/versions/{version}` | repository admin | Replace a version's document (admin edit). |
| `DELETE /v0.1/servers/{serverName}/versions/{version}` | write | Soft delete: status `deleted`, tombstoned. |
| `PUT /v0.1/servers/{serverName}/versions/{version}/bundles/{file}.mcpb` | write | Upload an MCPB bundle for a version before publishing it. |
| `GET /v0.1/servers/{serverName}/versions/{version}/bundles/{file}.mcpb` | read | Download a bundle of a published version. |
| `PATCH /v0.1/servers/{serverName}/versions/{version}/status` | write | `{"status": "active" \| "deprecated" \| "deleted", "statusMessage": "..."}` |
| `PATCH /v0.1/servers/{serverName}/status` | write | The same for every version; answers `{updatedCount, servers}`. |
| `GET /v0.1/ping`, `/health`, `/version` | read | `{"status":"ok"}`, a database-checked health answer, `{"version": "<AK version>"}`. |

The list envelope is upstream's:
`{"servers": [{"server": {...}, "_meta": {...}}], "metadata": {"nextCursor": "...", "count": N}}`.
There is no `nextCursor` on the last page. Each entry's `_meta` carries:

- `io.modelcontextprotocol.registry/official`: `status`, `statusMessage`,
  `statusChangedAt`, `publishedAt`, `updatedAt`, `isLatest`. `status` is only
  ever `active`, `deprecated` or `deleted`: a hold is never written here.
  `isLatest` is computed on every read: it marks the server's newest version
  that is servable now, so it agrees with `/versions/latest` while a newer
  version is held.
- `com.artifactkeeper.registry/source`: the repository, the server.json
  artifact id and sha256, and the package policy the version was published
  under.

The publisher's own `_meta` is reduced to
`io.modelcontextprotocol.registry/publisher-provided` (at most 4096 bytes),
as upstream does.

Choices pinned for this release: list order is name then version as text
(upstream's); a version is write-once (`409` on republish, even with identical
bytes, and for ever after the version was deleted, trashed or purged: see
[Tombstones](#tombstones)); `latest` is the newest version that is servable now, ordered as
upstream orders versions (SemVer by SemVer precedence, a `v` prefix allowed; a
SemVer version always ranks above a non-SemVer one; two non-SemVer versions by
`publishedAt`); `version=latest` picks each server's newest version first and
only then applies `updated_since` to it; a `deleted` version answers `404`
unless `include_deleted=true`; publish bodies are capped at 256 KiB (`413`);
documents nest at most 32 levels deep (`400`).

Listing work is bounded: one `/servers` request gates at most 1000 rows (and
`version=latest` at most 1000 versions, at most 100 per server) and answers a
`nextCursor` to resume whenever it stops early, so a page can be short without
being the last. `/versions` lists at most the newest 1000 versions of a
server.

## Authentication and publishing

Reads follow the repository's visibility: a public repository is readable
anonymously, a private one needs a credential (an anonymous read of a private
repository gets the same `401` challenge every format route gives). Publishing
and status changes need repository `write` and, for an API token, the
`write:artifacts` scope. Any Artifact Keeper credential works as the bearer
token; there is no separate registry login.

```bash
curl -X POST https://ak.example.com/mcp/mcp-local/v0.1/publish \
  -H "Authorization: Bearer $AK_TOKEN" \
  -H "Content-Type: application/json" \
  --data @server.json
```

`mcp-publisher` reads its registry URL and token from
`~/.config/mcp-publisher/token.json` (`{"token", "method", "registry"}`).
Write the file yourself with an Artifact Keeper API token instead of running
`mcp-publisher login`:

```bash
mkdir -p ~/.config/mcp-publisher
cat > ~/.config/mcp-publisher/token.json <<EOF
{"token": "$AK_TOKEN", "method": "none", "registry": "https://ak.example.com/mcp/mcp-local"}
EOF
mcp-publisher publish
```

Names follow the schema (`namespace/name`, 3 to 200 characters). The
`io.modelcontextprotocol` namespace and its sub-namespaces (including
`io.modelcontextprotocol.anonymous`) are reserved and refused with `403`. A
repository may restrict names further with a namespace allowlist
(`mcp_namespace_allow`, below): `com.acme` admits `com.acme/x` and
`com.acme.team/x`, not `com.acmecorp/x`.

Upstream's ownership proofs (DNS, GitHub OIDC, `mcpName` in `package.json`)
are not applied: in a private registry the repository's permissions decide who
may publish.

## Clients

- **VS Code**: set `"chat.mcp.gallery.serviceUrl": "https://ak.example.com/mcp/mcp-local"`
  (or the `McpGalleryServiceUrl` policy). The gallery reads
  `/v0.1/servers` and `/versions/latest`.
- **GitHub Copilot**: set the organization's MCP registry URL to
  `https://ak.example.com/mcp/mcp-local`. Copilot appends `/v0.1/servers`
  itself and checks the CORS headers below.
- **Claude Code** has no registry subscription; configure servers directly,
  using the coordinates the registry serves.

The read routes answer CORS with `Access-Control-Allow-Origin: *`, methods
`GET, OPTIONS` and headers `Authorization, Content-Type`, without credentials.

Behind a reverse proxy, forward `Host`/`X-Forwarded-Host` and
`X-Forwarded-Proto` (or set `AK_EXTERNAL_URL`): the served package
coordinates are built from the request's external base URL.

## Package policy

Each repository has a package policy (`mcp_package_policy`):

- **`own-repos`** (the default, also when the setting is absent). Every
  `packages[]` entry must name something this instance already hosts or has
  proxied, in the repository mapped to its `registryType`
  (`mcp_package_repos`). The publish looks it up in the database; it never
  contacts the package's registry. The version is pinned, and every read
  serves the package's Artifact Keeper coordinates, gated like any download.
- **`open`**. An explicit opt-out for a catalog of servers whose packages live
  elsewhere: `packages[]` is stored and served verbatim after the shape
  checks. Nothing is resolved, rewritten or gated, so a held or vulnerable
  package does not hide the server. Treat an `open` repository as a list of
  links, not as a control.

Settings are part of the repository API (`POST`/`PATCH /api/v1/repositories`):

```json
{
  "key": "mcp-local", "format": "mcp", "repo_type": "local",
  "mcp_package_policy": "own-repos",
  "mcp_package_repos": {"npm": "npm-local", "pypi": "pypi-remote", "oci": "docker-local"},
  "mcp_namespace_allow": ["com.acme"]
}
```

Each `mcp_package_repos` value must be an existing repository whose format
serves that registry type (an `npm`, `yarn` or `pnpm` repository for `npm`; a
`docker`/`podman`/`oras` repository for `oci`, an `mcp` or `generic` repository
for `mcpb`, and so on); it may be Local,
Remote or Virtual. The caller saving the setting must be able to read each
repository it names: an administrator, or `read` through a grant; a public
repository needs no grant, an `internal` one does (the mapping re-exports what
the repository holds to every reader of the MCP registry). A repository the
caller cannot read is refused with the same message as one that does not
exist.

Server versions enter an MCP repository only through `POST .../publish`. The
generic artifact upload routes (`PUT`/`POST /api/v1/repositories/{key}/artifacts/...`
and `/api/v1/uploads`) refuse an MCP repository with `400`, except for a
trusted peer replication (an administrator or service account sending the
replication header).

To publish a server under `own-repos`, publish (or pull through a Remote) its
package first, then publish the server.json. A publish answers `422` with one
`detail` line naming the entry and the fix:

| `error` | When |
| --- | --- |
| `mcp_external_registry` | The `registryType` has no backing repository, `registryBaseUrl` names anything other than this instance's backing repository (or is present on an `mcpb` entry), an OCI image's host is not the backing Remote's upstream, or (for a Local or Staging OCI backing repository) not this instance: name the image as `<ak-host>/<repo>/<image>:<tag>`. |
| `mcp_package_not_found` | The exact package version (npm, PyPI, NuGet, Cargo) or image tag/digest (OCI) is not in a hosted backing repository, or an `mcpb` entry's `fileSha256` matches no uploaded bundle. A package missing from a Remote backing repository is not refused: it is filled (`202`, see [Write path](#write-path-phase-2-and-3)). |
| `mcp_package_version_unpinned` | An npm, PyPI, NuGet or Cargo entry has no `version`. |
| `mcp_oci_floating_tag` | An OCI identifier is `:latest` or has no tag and no digest. |
| `mcp_oci_legacy_fields` | An OCI entry carries `version`, `registryBaseUrl` or `fileSha256` (the tag or digest belongs in `identifier`). |
| `mcp_oci_not_an_image` | The pinned manifest is not a runnable image or image index. |

What is served for a pinned package:

Names and versions are matched the way each backing format stores them: an
npm identifier is percent-decoded (`%40acme%2Fx` is `@acme/x`), PyPI names are
PEP 503-normalised, NuGet ids are case-insensitive and versions are compared
in NuGet's normalised form (`1.0`, `1.0.0` and `1.0.0.0` are one version),
Cargo names are case-insensitive with `-` and `_` equivalent.

- **npm, PyPI, NuGet, Cargo**: `identifier` and `version` unchanged,
  `registryBaseUrl` set to the backing repository
  (`https://<ak>/npm/<repo>`, `/pypi/<repo>`, `/nuget/<repo>/v3/index.json`,
  `/cargo/<repo>`). A client that honours `registryBaseUrl` installs through
  Artifact Keeper.
- **OCI**: write a specific tag. Artifact Keeper resolves it to the image
  (index) digest at publish and serves
  `<ak-host>/<repo>/<path>:<tag>@sha256:<digest>`
  (`@sha256:<digest>` alone when the publish named only a digest). The
  submitted identifier, digest, media type, platform children and backing
  repository are in the package's `_meta["com.artifactkeeper/resolved"]`. A
  multi-arch image pins the index digest and gates on the runner
  architecture's child, which is what the scanner scanned.

A pinned tag that later moves (a re-push, an upstream refresh, or a delete
and re-push) changes nothing for the published version: it keeps serving the
pinned digest, the stored package records `drift`, and
`MCP_PIN_DRIFT_DETECTED` is audited. To ship a new image, publish a new server
version.

The gate always evaluates the pinned digest, never whatever the tag names now:
it looks up the manifest records that carry the pinned index digest or its
runner-architecture child. A tag push records the manifest only at the tag,
and the next push of that tag rewrites that record, so for a Local (or a
Virtual's Local member) repository the pin also writes a manifest record at
`v2/<name>/manifests/<digest>`, copied from the record at publish (with its
hold) and scanned like a pushed manifest. The pinned bytes stay gateable after
the tag moves. If every record of the pinned digest is gone anyway, the
version becomes `unresolvable` (hidden) rather than served ungated. A publish
whose image has no manifest record at all is refused with
`mcp_package_not_found`. When the publish named both a tag and
a digest and they disagree, the digest is pinned and the pin records the
warning `oci_tag_digest_mismatch`.

For a Local OCI repository (including the Local member a Virtual mapping
resolved the image in) the pin also writes a digest-keyed tag row, which
keeps storage GC from collecting the pinned manifest when its tag moves or is
deleted. A `DELETE /v2/<name>/manifests/sha256:<digest>` of a digest that a
server version (in any status, `deleted` included, as long as its artifact is
not in the trash) pins as its index or gated child digest is refused in a
Local or Staging repository with `405` and the OCI error body
`{"errors":[{"code":"UNSUPPORTED","message":"this manifest is pinned by a published MCP server version ..."}]}`
(the message names no MCP repository or server). Deleting the tag is still
allowed (the retention row keeps the manifest). There is no override flag: to
free the digest, move the server version's artifact to the trash through the
artifact API; a restored version is then `unresolvable`.

Switching a repository from `open` to `own-repos` does not resolve versions
already published: they are `unresolvable` until republished as a new version.

## What a client sees

A version is **held** when Artifact Keeper will not hand its recipe to a
client: its server.json artifact is quarantined or refused by scan policy, or
a package it pins is quarantined, refused by scan policy, rejected, younger
than the age gate of the Remote it was pulled through, refused by that
Remote's stored proxy-scan verdict, or gone.
One decision function (`decide_mcp_serve`) answers every read:

| State | `/servers`, `/versions`, `search` | `latest` | Exact version, reader | Exact version, repository holder | `error` |
| --- | --- | --- | --- | --- | --- |
| server.json quarantined | omitted | skipped | `404` plain | `404` + reason, `hold: quarantine` | `mcp_pending_review` |
| server.json refused by scan policy or rejected | omitted | skipped | `404` plain | `404` + reason | `mcp_rejected` |
| pinned package quarantined | omitted | skipped | `404` plain | `404` + `package`, `gate: quarantine` | `mcp_backing_artifact_blocked` |
| pinned package refused by scan policy or rejected, or by its Remote's stored proxy-scan verdict | omitted | skipped | `404` plain | `404` + `package`, `gate: scan_policy` | `mcp_backing_artifact_blocked` |
| pinned package younger than its Remote's age gate | omitted | skipped | `404` plain | `404` + `package`, `gate: age_gate`, `review_id`, `min_age_days`, `requested_age_days` | `mcp_age_gate_blocked` |
| pinned package gone, or the policy changed | omitted | skipped | `404` plain | `404` + `package` | `mcp_unresolvable` |
| a gate cannot be evaluated (database error) | omitted | `503` | `503` | `503` | `mcp_gate_unavailable` |
| `deprecated` | listed | eligible | `200` | `200` | |
| `deleted` | omitted unless `include_deleted=true` | skipped | `404` plain; `200` with `include_deleted=true` | same | |

- **`404` plain** is byte for byte the answer for a name that does not exist:
  `{"detail":"Server not found","status":404,"title":"Not Found","type":"about:blank"}`
  with the same headers. A reader cannot tell a held version from a missing
  one.
- A **repository holder** (an administrator, or a user with read on the
  repository through a grant, with a credential scoped to it; the same
  predicate as `GET /api/v1/quarantine/{id}`) gets an RFC 9457 body with
  `error`, `name`, `version`, `hold`, `instance` and, for a package hold, the
  `package` as submitted (`npm:@acme/db-tool@2.0.0`) and the `gate`. It never
  names the backing repository, an artifact id, a finding or a policy.
- Every refusal is `application/problem+json` with `Cache-Control: no-store`,
  and is audited as `MCP_SERVER_DOWNLOAD_REFUSED`. That includes the refusals
  the shared middleware in front of the registry gives on `/mcp/` paths
  (`401`, `404`, `429`, `503`), which keep their `WWW-Authenticate` and
  `Retry-After` headers; read refusals carry the read routes' CORS headers.
- Listings evaluate the scan-policy gate afresh on every request (no cached
  decision), since a listing entry is the whole document.
- `include_deleted=true` widens only `deleted`; it never reveals a hold.

Why `404` and not `403`/`409`/`451`: VS Code treats a `404` on
`/versions/latest` as "not in the registry" (and, under Copilot's
"registry only" policy, disables the server), while any other non-2xx is a
transient failure that keeps a previously verified server enabled. On the
surface that decides what an agent may run, a status the client ignores is
not a control. The artifact routes (`/api/v1/repositories/{key}/artifacts/...`)
keep the usual `409`/`403`.

Releasing a hold restores the version on the next read.

The age gate is evaluated without contacting the upstream. Under
`first_seen` the basis is the recorded first sighting; under
`upstream_publish_time` it is the publish time a review of the version has
recorded, otherwise the time this instance cached the package (never earlier
than its upstream publish, so a version is never treated as older than it
is). A package pulled through recently is therefore held until its cached
copy is old enough, unless an administrator approves its age-gate review; an
exact read of the held version records that review as pending (with an
unknown publish time) so it appears in the review queue. A rejected review
holds the version. Formats without an age gate (OCI, NuGet) are not affected.

## Storage

One server version is one artifact: path `servers/<name>/<version>/server.json`
(visible in `GET /api/v1/repositories/{key}/artifacts` and on the Packages
page), content the key-sorted canonical JSON of the accepted document, stored
under the content-addressed key `mcp/<name>/<version>/<sha256>.json` so a
publish that loses a race for the same version cannot overwrite the winner's
bytes. Status changes of a server run in one transaction with the `isLatest`
recompute. The
pins, registry state and package policy live in the artifact's metadata.
Published versions fire `artifact.uploaded` webhooks, are scanned on upload
and replicate like any other artifact.

## Not in this release

- Drift detection for tag writes made by promotion and migration imports
  (pushes and Remote refreshes are covered).

## Security notes

- Artifact Keeper never dereferences a URL in a server.json (`websiteUrl`,
  `icons`, `repository.url`, `remotes[].url`). Publish, list and read are
  database and object-storage operations only.
- Descriptions, titles, argument and variable text, and every string (key
  or value) of the publisher-provided `_meta`, refuse control characters,
  bidirectional marks, overrides and isolates (including U+061C), zero-width
  and invisible formatting characters (U+200B-U+200F, U+2060-U+2064, the
  BOM), the line and paragraph separators (U+2028/U+2029) and Unicode tag
  characters (U+E0000-U+E007F). URLs must be absolute `http`/`https`.
- Publishes are quota-admitted like any upload and capped at 256 KiB, 16
  packages, 8 remotes and 64 entries per list.

## Write path (Phase 2 and 3)

Every route here is under `/mcp/<repo_key>/v0.1` and `/v0` (identical), with
both `{serverName}` spellings. Every refusal is `application/problem+json`
with `Cache-Control: no-store` and an `error` code. Writes need repository
`write` (an API token needs `write:artifacts`) on a Local or Staging MCP
repository (`405 mcp_read_only` on Remote, `400` on Virtual) and are refused
on a promotion-only repository (`409 mcp_promotion_only`).

### Packages in a Remote backing repository

A package pulled through a Remote is held in the Remote's proxy cache, not as
an artifact row. Publish finds it there (npm tarball, PyPI distribution file,
NuGet `.nupkg`, Cargo `.crate`) and pins its cache path and sha256; the gate
then evaluates exactly those cached bytes: the cache entry's Package Age
Policy hold (quarantine), the Remote's stored proxy-scan verdict for that
sha256, and the Remote's age gate. If the Remote refreshes the path to other
bytes, or evicts it, the version is `unresolvable` (hidden) until the package
is pulled again; nothing else is ever served in its place. OCI pulls through
a Remote write manifest records, which publish already finds.

A package that is not in the Remote yet (directly mapped, or the first Remote
member by priority of a mapped Virtual) is **filled** instead of refused:

1. Publish stores the version and answers **`202 Accepted`** with the served
   entry plus two members:
   ```json
   {"server": {...}, "_meta": {...}, "status": "resolving", "pendingPackages": [0]}
   ```
   Already-pinned packages are rewritten as usual; pending ones are served as
   submitted (no client sees the version yet).
2. The version is held as `resolving`: omitted from every listing and
   `latest`, exact reads answer the plain `404` (a repository holder gets
   `404 mcp_resolving`, `hold: "resolving"`).
3. A background job (every replica runs it; jobs are claimed with `FOR UPDATE
   SKIP LOCKED` and a claim token; tick `MCP_RESOLVER_INTERVAL_SECS`, default
   15 s) requests the package from the Remote through the Remote's own
   download route, in process, as the publisher: the Remote's curation rules,
   age gate, scan-on-proxy and quarantine apply exactly as for a client pull.
   The publisher must be able to read the Remote. npm: the tarball
   `<name>/-/<base>-<version>.tgz`; PyPI: `/pypi/<project>/<version>/json`,
   then its first wheel (else first file); NuGet: the flat-container
   `.nupkg`; Cargo: `/api/v1/crates/<name>/<version>/download`; OCI: the
   manifest by tag or digest (with a five-minute pull token of the publisher
   pinned to the Remote).
4. Then it looks again and pins. When every pending package is pinned the
   version is served (`MCP_PACKAGE_PINNED` audited per package).
5. A definitive refusal fails the version: upstream `404`/`410`
   (`mcp_package_not_found`), `401`/`403`/`451` from the Remote (access,
   curation or age policy: `mcp_package_refused`), a mapping removed
   (`mcp_external_registry`), the publishing account gone or disabled. A
   transient one (`429`, `5xx`, timeout after 300 s) is retried with backoff
   (30 s doubling, at most 1 h) up to 8 attempts (`mcp_resolve_exhausted`).
   A failed version stays stored and hidden (`404 mcp_unresolvable` for a
   holder) and the name@version stays taken: publish a new version.

The state is in the version's metadata (`GET /api/v1/packages` rows and the
artifact metadata API carry it), under `resolution`:

```json
{"state": "resolving" | "resolved" | "failed",
 "pending": [{"index": 0, "registryType": "npm", "identifier": "@acme/x", "version": "1.0.0",
              "fillRepository": "npm-remote", "fillRepositoryId": "...", "fillFormat": "npm"}],
 "requestedAt": "...", "requestedBy": "<user id>", "baseUrl": "https://ak.example.com",
 "attempts": 1, "lastError": "...",
 "resolvedAt": "...", "failedAt": "...",
 "error": {"error": "mcp_package_not_found", "detail": "...", "index": 0}}
```

Note: `mcp-publisher publish` accepts only `200`/`201` and prints a `202` as an
error even though the publish was stored; pull packages through the Remote
first (then publish answers `200`), or use `curl`.

### Tombstones

Every `name@version` a repository ever stored is recorded in
`mcp_version_tombstones` (written by a database trigger on every server.json
row insert, so publish, peer replication and promotion are all covered). A
publish (or a bundle upload) of a recorded `name@version` answers
`409 mcp_version_exists`, whether the version is live, soft-deleted, in the
trash, or purged from it. The ledger is removed only with the repository.

### `POST /validate`

Body: a server.json (256 KiB cap, `413`). No credential is needed beyond
reading the registry (`mcp-publisher validate` and its fallback after a `422`
send none); nothing is written, pinned, held or filled. Always `200` for a
document, with upstream's `ValidationResult` plus `packages`:

```json
{"valid": false,
 "issues": [{"type": "schema" | "semantic", "path": "packages[0]",
             "message": "packages[0]: npm @acme/x@1.0.0 is not in repository 'npm-local'",
             "severity": "error" | "info", "reference": "mcp_package_not_found"}],
 "packages": [{"index": 0, "registryType": "npm", "outcome": "pinned" | "fill" | "unchecked",
               "fillRepository": "npm-remote"}]}
```

`reference` is the error code the publish would answer. Validation stops at
the first error (one `error` issue); a package that a publish would fill is an
`info` issue (`mcp_package_fill`) with `valid: true`. What is checked depends
on the caller, so `/validate` reveals nothing a read would not:

- everyone: parsing, schema, caps, characters, reserved and allowlisted
  namespaces;
- a repository holder (administrator, or `read` through a grant): also
  whether `name@version` is taken (`mcp_version_exists`; a reader could
  otherwise learn of a held version);
- an authenticated caller who can read every mapped backing repository: also
  package resolution. Anyone else gets `outcome: "unchecked"` per package and
  an `info` issue `mcp_packages_unchecked`.

### `PUT .../versions/{version}` (admin edit)

Needs repository administration (instance administrator or the `admin`
action on the repository; `403 mcp_forbidden` otherwise). Body: the full
server.json, validated exactly as a publish (`400`/`403`/`422` as there); its
`name` and `version` must be the route's (`400`). An unknown or trashed
version is `404`. The stored document is replaced (new content-addressed
bytes, new sha256, scanned again); registry state is kept and `updatedAt`
bumped. When `packages[]` is unchanged the pins are kept as they are;
otherwise every package is resolved again (and may answer `202` with
`status: "resolving"` exactly as a publish). Identical bytes answer `200`
without a write. Audited `MCP_SERVER_EDITED`
(`previous_sha256`, `sha256`, `packages_changed`, `resolving`).

### `DELETE .../versions/{version}` (soft delete)

Needs repository `write` (as a status change). Optional body
`{"statusMessage": "..."}` (at most 500 characters). Sets status `deleted`
(`400` if it already is), recomputes `isLatest`, keeps the artifact, its bytes
and its tombstone; the version answers `404` unless `include_deleted=true`.
`200` with the served entry (`status: "deleted"`). Audited
`MCP_SERVER_DELETED` (`from`, `status_message`).

### MCPB bundles

An MCPB bundle (`.mcpb`, a ZIP with `manifest.json`) is uploaded beside a
version **before** the version is published:

```bash
curl -X PUT -H "Authorization: Bearer $AK_TOKEN" --data-binary @echo.mcpb \
  https://ak.example.com/mcp/mcp-local/v0.1/servers/com.acme/echo/versions/1.0.0/bundles/echo.mcpb
```

- File name: `<name>.mcpb`, letters, digits, `.`, `_`, `-`, at most 200
  characters (`400 mcp_invalid_server_json`). The name must pass the
  namespace rules (`403`). A version already recorded (published, even
  deleted) is `409 mcp_version_exists`. Body at most 256 MiB
  (`413 mcp_bundle_too_large`); streamed to staging, not buffered.
- AK reads `manifest.json` (at most 1 MiB, an object with string `name` and
  `version`; else `400 mcp_bundle_invalid`) and verifies the signature
  block the `mcpb sign` tool appends (`MCPB_SIG_V1`, PKCS#7 detached
  SignedData, `MCPB_SIG_END`; both the current layout, which grows the ZIP
  comment length, and the earlier one are accepted). A signature is `valid`
  when the SignedData's SHA-256 message digest matches the archive, its RSA
  (PKCS#1 v1.5, SHA-256) signature over the signed attributes verifies with
  the certificate it carries, and that certificate was valid at the signing
  time. AK does not check the certificate against a trust store: the
  result records `signer` (subject CN), `issuer`, `fingerprint` (SHA-256 of
  the certificate) and `selfSigned`, for the UI and policy to judge.
- A present but invalid signature (tampered bytes, broken block, an
  algorithm other than RSA/SHA-256) is always refused:
  `422 mcp_bundle_signature_invalid`. An unsigned bundle is refused with
  `422 mcp_bundle_unsigned` when `mcp_require_bundle_signature` is on. Both
  are audited `MCP_BUNDLE_SIGNATURE_REJECTED` (`file`, `file_sha256`,
  `signature`, `require_signature`, `error`).
- `201` (or `200` for a re-upload of identical bytes; other bytes under the
  same file name are `409 mcp_bundle_exists`):
  ```json
  {"file": "echo.mcpb", "fileSha256": "<hex>", "size": 1234,
   "signature": {"state": "valid" | "unsigned", "signer": "...", "issuer": "...",
                 "fingerprint": "...", "selfSigned": true, "signedAt": "..."},
   "manifest": {...}, "artifactId": "...",
   "downloadUrl": "https://ak.example.com/mcp/mcp-local/v0.1/servers/com.acme/echo/versions/1.0.0/bundles/echo.mcpb",
   "packageEntry": {"registryType": "mcpb", "identifier": "<downloadUrl>",
                    "fileSha256": "<hex>", "transport": {"type": "stdio"}}}
  ```
  The bundle is an artifact at `servers/<name>/<version>/bundles/<file>`
  (metadata format `mcpb`), scanned and quota-admitted like any upload.

Publishing the version then resolves `mcpb` entries under `own-repos` by
`fileSha256`: a bundle uploaded for this version, else one in the
repository `mcp_package_repos.mcpb` maps (an MCP registry's bundles, or a
`.mcpb` file in a Generic repository). `registryBaseUrl` on an `mcpb` entry
is `422 mcp_external_registry`; no match is `422 mcp_package_not_found`. A
document with no `mcpb` entry gets one `packages[]` entry per uploaded bundle
(the `packageEntry` above), so `fileSha256` never has to be computed by hand.
The served `identifier` is the bundle's Artifact Keeper URL; on an exact read
by an authenticated caller it carries a single-use download ticket
(`?ticket=...`, five minutes), so a client handed the document can fetch the
bundle of a private registry without its own credential. Listings serve the
plain URL.

The version's metadata gains `bundles[]`, one per pinned bundle:

```json
{"index": 1, "artifactId": "...", "file": "echo.mcpb", "fileSha256": "<hex>", "size": 1234,
 "signature": {"state": "valid" | "unsigned" | "invalid", "signer": "..."},
 "manifest": {"name": "...", "version": "...", "tools": [{"name": "...", "description": "..."}],
              "prompts": [...], "...": "..."}}
```

(A manifest over 64 KiB keeps only its identity, `tools` and `prompts`, with
`"truncated": true`. A bundle from a Generic repository has no upload facts:
`signature.state` is `unsigned`, `manifest` is `null`.)

`GET .../bundles/{file}` serves a bundle of a published, not deleted,
version: `200 application/zip` with `X-Checksum-Sha256` and
`Cache-Control: private, no-store`, streamed. A bundle under quarantine or
refused by scan policy, an unknown file, or a version that is not published
answers the plain unknown-name `404` (`503 mcp_gate_unavailable` when the gate
cannot be evaluated). The gate of a pinned bundle also holds its server
version on every read, as any backing package does.

## Repository settings (Phase 2 and 3)

Set on `POST /api/v1/repositories` and `PATCH /api/v1/repositories/{key}`
and echoed (effective value, defaults filled in) on every repository
response. Each is a `repository_config` key of the same name. `null`/absent on
a request leaves the stored value unchanged. A setting that does not apply to
the repository type is refused with `400`; a response omits it.

| Field | Types | Values (default first) | Meaning |
| --- | --- | --- | --- |
| `mcp_server_deny` | all | glob list (`[]`) | Server names refused on publish and hidden on serve. `*` matches any run of characters including `/`; matching is ASCII case-insensitive. Deny always wins, even over an approval. |
| `mcp_remote_posture` | Remote | `approval_required` \| `allow_with_gates` | `approval_required` serves only approved names; `allow_with_gates` serves every name whose version passes the gates (lint, backing scan, age gate and typosquat still apply; flags route to review). |
| `mcp_remote_posture_locked` | Remote | `false` \| `true` | Instance-administrator lock on `mcp_remote_posture`. |
| `mcp_auto_approve_namespaces` | Remote | glob list (`[]`) | Names in these namespaces are approved on sync. |
| `mcp_oci_floating_tag_policy` | Remote | `pin` \| `hide` | Upstream OCI entries tagged `latest` or untagged: pin the digest at sync and warn, or hide the version. |
| `mcp_remote_mode` | Remote | `allowlist` \| `mirror` | `allowlist` ingests approved names only; `mirror` ingests every upstream name hourly (serving is still curated). |
| `mcp_probe_remotes` | Local, Staging, Remote | `off` \| `hosted_only` \| `all` | Opt-in remote `tools/list` probe by the isolated introspector worker. |
| `mcp_probe_remotes_locked` | Local, Staging, Remote | `false` \| `true` | Instance-administrator lock on `mcp_probe_remotes`. |
| `mcp_require_oci_label` | all | `false` \| `true` | Refuse an OCI package whose image lacks a matching `io.modelcontextprotocol.server.name` label (otherwise a lint warning). |
| `mcp_require_namespace_grant` | Local, Staging, Remote | `false` \| `true` | Publishing needs a namespace-conditioned grant, not just repository write. |
| `mcp_sandbox_introspection` | Local, Staging, Remote | `off` \| `on` | Queue sandboxed stdio introspection runs for the isolated worker. |
| `mcp_require_bundle_signature` | Local, Staging, Remote | `false` \| `true` | Refuse unsigned MCPB bundles on upload (see [MCPB bundles](#mcpb-bundles)). A present but invalid signature is always refused. |

Locks: only an instance administrator may set or clear a `*_locked` field
(`403` otherwise), and while a lock is set only an instance administrator may
change the locked setting (`403`).

## Remote repositories

(Filled in by the Remote workstream.)

## Virtual repositories

(Filled in by the Virtual workstream.)
