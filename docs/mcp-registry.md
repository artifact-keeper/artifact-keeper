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

This release serves **Local** and **Staging** repositories. Creating a Remote
or Virtual `mcp` repository is refused with `400` (see
[Remote and Virtual](#remote-and-virtual)).

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
| `POST /v0.1/publish` | write | Publish a server.json. `200` with `{server, _meta}` exactly as it will be served. |
| `PATCH /v0.1/servers/{serverName}/versions/{version}/status` | write | `{"status": "active" \| "deprecated" \| "deleted", "statusMessage": "..."}` |
| `PATCH /v0.1/servers/{serverName}/status` | write | The same for every version; answers `{updatedCount, servers}`. |
| `GET /v0.1/ping`, `/health`, `/version` | read | `{"status":"ok"}`, a database-checked health answer, `{"version": "<AK version>"}`. |

The list envelope is upstream's:
`{"servers": [{"server": {...}, "_meta": {...}}], "metadata": {"nextCursor": "...", "count": N}}`.
There is no `nextCursor` on the last page. Each entry's `_meta` carries:

- `io.modelcontextprotocol.registry/official`: `status`, `statusMessage`,
  `statusChangedAt`, `publishedAt`, `updatedAt`, `isLatest`. `status` is only
  ever `active`, `deprecated` or `deleted`: a hold is never written here.
- `com.artifactkeeper.registry/source`: the repository, the server.json
  artifact id and sha256, and the package policy the version was published
  under.

The publisher's own `_meta` is reduced to
`io.modelcontextprotocol.registry/publisher-provided` (at most 4096 bytes),
as upstream does.

Choices pinned for this release: list order is name then version as text
(upstream's); a version is write-once (`409` on republish, even with identical
bytes); `latest` is the newest version that is servable now; a `deleted`
version answers `404` unless `include_deleted=true`; publish bodies are capped
at 256 KiB (`413`); documents nest at most 32 levels deep (`400`).

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
`docker`/`podman`/`oras` repository for `oci`, and so on); it may be Local,
Remote or Virtual.

To publish a server under `own-repos`, publish (or pull through a Remote) its
package first, then publish the server.json. A publish answers `422` with one
`detail` line naming the entry and the fix:

| `error` | When |
| --- | --- |
| `mcp_external_registry` | The `registryType` has no backing repository (this includes `mcpb` in this release), `registryBaseUrl` names anything other than this instance's backing repository, or an OCI image's host is not the backing Remote's upstream. |
| `mcp_package_not_found` | The exact package version (npm, PyPI, NuGet, Cargo) or image tag/digest (OCI) is not in the backing repository. For a Remote backing repository, pull it through Artifact Keeper first. |
| `mcp_package_version_unpinned` | An npm, PyPI, NuGet or Cargo entry has no `version`. |
| `mcp_oci_floating_tag` | An OCI identifier is `:latest` or has no tag and no digest. |
| `mcp_oci_legacy_fields` | An OCI entry carries `version`, `registryBaseUrl` or `fileSha256` (the tag or digest belongs in `identifier`). |
| `mcp_oci_not_an_image` | The pinned manifest is not a runnable image or image index. |

What is served for a pinned package:

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
runner-architecture child. A multi-arch push records each platform child by
digest, so those records survive a tag move. A single-architecture image
pushed only by tag has one record, at the tag, which the next push of that tag
rewrites; once that happens the pinned digest has nothing left to gate and the
version becomes `unresolvable` (hidden) rather than served ungated. A publish
whose image has no manifest record at all is refused with
`mcp_package_not_found`. When the publish named both a tag and
a digest and they disagree, the digest is pinned and the pin records the
warning `oci_tag_digest_mismatch`.

For a Local OCI repository the pin also writes a digest-keyed tag row, which
keeps storage GC from collecting the pinned manifest when its tag moves or is
deleted. Known limit in this release: an explicit
`DELETE /v2/<name>/manifests/sha256:<digest>` still removes the manifest; the
server version then becomes `unresolvable` and is hidden (below), it does not
error.

Switching a repository from `open` to `own-repos` does not resolve versions
already published: they are `unresolvable` until republished as a new version.

## What a client sees

A version is **held** when Artifact Keeper will not hand its recipe to a
client: its server.json artifact is quarantined or refused by scan policy, or
a package it pins is quarantined, refused by scan policy, rejected, or gone.
One decision function (`decide_mcp_serve`) answers every read:

| State | `/servers`, `/versions`, `search` | `latest` | Exact version, reader | Exact version, repository holder | `error` |
| --- | --- | --- | --- | --- | --- |
| server.json quarantined | omitted | skipped | `404` plain | `404` + reason, `hold: quarantine` | `mcp_pending_review` |
| server.json refused by scan policy or rejected | omitted | skipped | `404` plain | `404` + reason | `mcp_rejected` |
| pinned package quarantined | omitted | skipped | `404` plain | `404` + `package`, `gate: quarantine` | `mcp_backing_artifact_blocked` |
| pinned package refused by scan policy or rejected | omitted | skipped | `404` plain | `404` + `package`, `gate: scan_policy` | `mcp_backing_artifact_blocked` |
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
  and is audited as `MCP_SERVER_DOWNLOAD_REFUSED`.
- `include_deleted=true` widens only `deleted`; it never reveals a hold.

Why `404` and not `403`/`409`/`451`: VS Code treats a `404` on
`/versions/latest` as "not in the registry" (and, under Copilot's
"registry only" policy, disables the server), while any other non-2xx is a
transient failure that keeps a previously verified server enabled. On the
surface that decides what an agent may run, a status the client ignores is
not a control. The artifact routes (`/api/v1/repositories/{key}/artifacts/...`)
keep the usual `409`/`403`.

Releasing a hold restores the version on the next read.

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

- Age-gate evaluation of backing packages at read time. A package pulled
  through a Remote has already passed that Remote's age gate on the way in;
  the `mcp_age_gate_blocked` answer exists for when this lands.
- Refusing a `DELETE` by digest of a pinned manifest (see above).
- Drift detection for tag writes made by promotion and migration imports
  (pushes and Remote refreshes are covered).

## Security notes

- Artifact Keeper never dereferences a URL in a server.json (`websiteUrl`,
  `icons`, `repository.url`, `remotes[].url`). Publish, list and read are
  database and object-storage operations only.
- Descriptions, titles, argument and variable text refuse control,
  bidirectional-override and zero-width characters. URLs must be absolute
  `http`/`https`.
- Publishes are quota-admitted like any upload and capped at 256 KiB, 16
  packages, 8 remotes and 64 entries per list.

## Remote and Virtual

Proxying the official registry (an allowlist populated from it, deny by
default: an upstream server is invisible until approved) and Virtual
repositories that merge MCP repositories come in a later release. Until then
`POST /api/v1/repositories` refuses them with `400`.
