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
| `POST /v0.1/publish` | write | Publish a server.json. `200` with `{server, _meta}` exactly as it will be served. |
| `PATCH /v0.1/servers/{serverName}/versions/{version}/status` | write | `{"status": "active" \| "deprecated" \| "deleted", "statusMessage": "..."}` |
| `PATCH /v0.1/servers/{serverName}/status` | write | The same for every version; answers `{updatedCount, servers}`. |
| `GET /v0.1/ping`, `/health`, `/version` | read | `{"status":"ok"}`, a database-checked health answer, `{"version": "<AK version>"}`. |
| `GET /v0.1/servers/{serverName}/versions/{version}/capabilities` | read | Capability snapshots of a version (see [Capabilities and introspection](#capabilities-and-introspection)). |
| `POST /v0.1/servers/{serverName}/versions/{version}/capabilities` | write | Report a CI- or gateway-observed capability list. `201`. |
| `GET /v0.1/servers/{serverName}/versions/{version}/capabilities/diff` | read | Tool, resource and prompt diff between two snapshots (approval queue). |
| `POST /v0.1/servers/{serverName}/versions/{version}/capabilities/probe` | repository admin | Queue introspection jobs when the repository's settings allow them. `202`. |
| `POST /api/v1/mcp/introspection/jobs/claim` | `mcp:introspect` token | Worker API: claim the next job (`200`) or nothing due (`204`). |
| `POST /api/v1/mcp/introspection/jobs/{id}/complete` | `mcp:introspect` token | Worker API: post a job's result. |

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
bytes, and also while a version deleted through the artifact API is in the
trash); `latest` is the newest version that is servable now, ordered as
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
`docker`/`podman`/`oras` repository for `oci`, and so on); it may be Local,
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
deleted. Known limit in this release: an explicit
`DELETE /v2/<name>/manifests/sha256:<digest>` still removes the manifest; the
server version then becomes `unresolvable` and is hidden (below), it does not
error.

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

- Refusing a `DELETE` by digest of a pinned manifest (see above).
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
| `mcp_require_bundle_signature` | Local, Staging, Remote | `false` \| `true` | Refuse unsigned MCPB bundles. A present but invalid signature is always refused. |

Locks: only an instance administrator may set or clear a `*_locked` field
(`403` otherwise), and while a lock is set only an instance administrator may
change the locked setting (`403`).

## Remote repositories

(Filled in by the Remote workstream.)

## Virtual repositories

(Filled in by the Virtual workstream.)

## Capabilities and introspection

A **capability snapshot** records what one server version advertises: its
`tools`, `resources`, `prompts` (MCP spec objects, stored as received) and
`instructions`, with where the list came from. Snapshots feed the Tools tab,
the approval queue's tool diff and the `tool_drift` finding. **No snapshot
ever marks a server safe**: tool lists vary by the caller's authorization,
annotations such as `destructiveHint` are asserted by the server, and a
declared list is a claim, not an observation. Every response repeats this in
a `notice` member.

| `source` | Produced by | Badge |
| --- | --- | --- |
| `publisher_declared` | `_meta["com.artifactkeeper/capabilities"]` of the published server.json, or an MCPB bundle's `manifest.json` (`tools[]`, `prompts[]`, `tools_generated`) | declared |
| `ci_reported` | the publisher's pipeline, `POST .../capabilities` | CI-reported |
| `gateway_reported` | an operator's Docker MCP Gateway / ToolHive inventory, `POST .../capabilities` (see `ak-mcp-introspector push`) | gateway-reported |
| `remote_probe` | the `ak-mcp-introspector` worker against a `remotes[]` URL | observed (remote) |
| `sandbox_run` | the `ak-mcp-introspector` worker running a stdio package in a sandbox | observed (sandbox) |

The **current** snapshot is the newest successful (`outcome: ok`) one of the
best source in this order: `sandbox_run`, `remote_probe`, `gateway_reported`,
`ci_reported`, `publisher_declared`. History is kept.

### Declaring capabilities at publish

Add a `com.artifactkeeper/capabilities` member to the document's `_meta`
(top level, or inside `io.modelcontextprotocol.registry/publisher-provided`,
which is where an upstream registry keeps it). It is served back as part of
the document.

```json
"_meta": {
  "com.artifactkeeper/capabilities": {
    "protocolVersion": "2026-07-28",
    "generatedBy": "make tools-json",
    "tools": [{"name": "get_forecast", "description": "...", "inputSchema": {"type": "object"},
               "annotations": {"readOnlyHint": true}}],
    "resources": [{"uri": "weather://stations", "name": "stations"}],
    "prompts": [{"name": "summarise", "arguments": []}],
    "instructions": "..."
  }
}
```

Rules (publish answers `400` with the field path otherwise): an object of at
most 128 KiB; each list at most 1000 entries; every tool and prompt has a
non-empty string `name` (at most 256 bytes), every resource a `uri` (at most
2048 bytes), unique per list; `instructions` a string of at most 64 KiB; the
same character rules as every other rendered string (no control,
bidirectional or zero-width characters). MCPB bundles stored by the bundle
upload (`metadata.bundles[*].manifest`) are recorded as one declared snapshot
per bundle (`origin: "mcpb:<fileSha256>"`). Declared snapshots are recorded
once per (version, origin, content); a Remote's ingest and the bundle upload
call the same builder (`services::mcp_capabilities::record_declared_snapshot`).

### Hashing and drift

Each item is hashed over the canonical (key-sorted) JSON of its identity
members only: tools `name, title, description, inputSchema, outputSchema,
annotations`; resources `uri, name, title, description, mimeType,
annotations`; prompts `name, title, description, arguments`. `_meta` and any
other member are carried but never count as a change. The per-item hashes
are sorted, so order does not matter. `toolsHash` is the hash of the tool
list; `contentHash` covers tools, resources, prompts and instructions.

When a new successful snapshot of a version differs (`contentHash`) from the
previous successful one **of the same source** (and, for declarations, the
same origin), AK records a `tool_drift` finding and audits `MCP_TOOLS_DRIFT`.
The finding is an `external` scan result (scanner `ak-mcp-capabilities`,
`source: mcp-capabilities`, class `policy`) on the server.json artifact, so
the findings UI, acknowledgement and the scan-policy gate apply unchanged:

| Source of the changed snapshot | Severity |
| --- | --- |
| `remote_probe`, `sandbox_run` | `high` (same version, different tools: the remote rug pull) |
| `ci_reported`, `gateway_reported` | `medium` |
| `publisher_declared` | `low` |

Title: `tool_drift: <source> snapshot of <name>@<version> changed (<old hash
prefix> -> <new hash prefix>)`; the description carries the diff summary and
both snapshot ids. A version whose repository has a scan policy that blocks
on `high` is therefore held until the finding is acknowledged.

### `GET .../servers/{serverName}/versions/{version}/capabilities`

Read access as for the version itself. A caller who may read why a version is
held (the repository's members and administrators) sees every stored
version, held or not, so the approval queue can show pending versions; every
other caller sees only a version that is servable now, and anything else is
the unknown-name `404` byte for byte. `{version}` is an exact version
(`latest` is not resolved here).

Query: `source` (one of the sources: restricts `current` and the list),
`snapshot` (a snapshot id: answered as `current`), `limit` (history length,
default 50, max 200).

```json
{
  "repository": "mcp-local",
  "server": "com.acme/weather",
  "version": "1.0.0",
  "artifactId": "uuid",
  "current": {
    "id": "uuid",
    "source": "remote_probe",
    "provenance": "observed by remote probe",
    "origin": "remote:0",
    "observed": true,
    "authState": "none",
    "outcome": "ok",
    "protocolVersion": "2026-07-28",
    "observedAt": "2026-11-03T10:00:00Z",
    "ttlMs": 3600000,
    "cacheScope": "public",
    "counts": {"tools": 3, "resources": 0, "prompts": 1},
    "toolsHash": "hex", "contentHash": "hex",
    "workerVersion": "ak-mcp-introspector/1.11.3",
    "reportedBy": null,
    "details": {"era": "modern", "serverInfo": {"name": "...", "version": "..."}},
    "createdAt": "2026-11-03T10:00:01Z",
    "tools": [], "resources": [], "prompts": [], "instructions": null
  },
  "snapshots": [ /* summaries, newest first: `current` without tools/resources/prompts/instructions */ ],
  "introspection": {
    "remoteProbe": "off", "probeEnabled": false,
    "sandbox": "off", "sandboxEnabled": false,
    "jobs": [ /* members/administrators only, see below */ ]
  },
  "notice": "Capability lists are untrusted. ..."
}
```

`current` is `null` when no successful snapshot exists. Field values:
`authState` `none` | `auth_required` (the server answered `401`/`403`: not
observable without credentials) | `caller_specific` (a page was
`cacheScope: private`: the list may differ per user) | `unknown` (reports and
declarations); `outcome` `ok` | `auth_required` | `rate_limited` | `timeout`
| `start_failed` | `needs_config` (the sandboxed server would not start or
answer without configuration) | `refused` (redirect, private address, over
the size cap) | `unsupported` | `error`. Failed attempts are listed in
`snapshots` (with empty lists and `details.error`) but are never `current`.
`details` by source: declared `{generatedBy}` or `{bundleArtifactId,
fileSha256, signature, toolsGenerated, promptsGenerated}`; observed `{era:
modern|legacy, serverInfo, capabilities, droppedItems?, truncated?, jobId,
target, error?}` plus, for the sandbox, `{runner, image, notes}`.

A job entry: `{id, kind: remote_probe|sandbox_run, target: "remote:<i>" |
"package:<i>", status: pending|claimed|completed|failed|cancelled, attempts,
maxAttempts, notBefore, claimedBy, leaseExpiresAt, lastError, snapshotId,
completedAt, createdAt}`.

### `POST .../servers/{serverName}/versions/{version}/capabilities`

A CI pipeline or gateway reports what it observed. Needs `write:artifacts`
and repository `write`; the version must be visible to the caller. Allowed on
Local, Staging and Remote repositories (it does not change the served
document). Body at most 1 MiB, nesting at most 64 levels.

```json
{
  "source": "ci_reported",
  "generatedBy": "github-actions/acme/weather",
  "observedAt": "2026-11-03T09:58:00Z",
  "protocolVersion": "2026-07-28",
  "authState": "none",
  "ttlMs": 3600000,
  "cacheScope": "public",
  "tools": [], "resources": [], "prompts": [], "instructions": "..."
}
```

`source` is required and must be `ci_reported` or `gateway_reported`; every
other member is optional (`observedAt` defaults to now and may not be more
than 5 minutes in the future; `authState` defaults to `unknown`;
`cacheScope` is `public` or `private`; `ttlMs` a non-negative integer). Item
rules are the declaration rules above. The display label is set by AK, never
by the caller: `reported by CI (<username>[, <generatedBy>])` /
`reported by a gateway (...)`.

`201`:

```json
{"snapshot": { /* as `current` above */ }, "previousSnapshotId": "uuid|null",
 "drift": {"scanId": "uuid"} }
```

`drift` is `null` unless this report differs from the previous one of the
same source. Errors: `400 mcp_invalid_capabilities` (`detail` names the
field), `401 mcp_unauthorized`, `403 mcp_forbidden`, `404` (unknown or
invisible version), `413 mcp_too_large`. Audited `MCP_CAPABILITIES_INGESTED`.

### `GET .../servers/{serverName}/versions/{version}/capabilities/diff`

Query: `to` and `from`, each a snapshot id of this server (any version) or a
version string (that version's current snapshot); `source` restricts which
snapshot "current" means. Defaults: `to` = the path version's current
snapshot; `from` = the previous successful snapshot of the same source for
the same version, else the current snapshot (same source) of the previous
version (version order as for `latest`). Both sides must be visible to the
caller as above. `404 mcp_capabilities_not_found` when there is no `to`.

```json
{
  "from": { /* snapshot summary */ } ,
  "to": { /* snapshot summary */ },
  "fromVersion": "0.9.0", "toVersion": "1.0.0",
  "summary": {
    "text": "Tools: +1 added, 1 changed (`delete_repo` now destructiveHint: true)",
    "tools": {"added": 1, "removed": 0, "changed": 1, "unchanged": 4},
    "resources": {"added": 0, "removed": 0, "changed": 0, "unchanged": 0},
    "prompts": {"added": 0, "removed": 0, "changed": 0, "unchanged": 1},
    "instructionsChanged": false,
    "destructiveAdded": ["delete_repo"],
    "identical": false
  },
  "tools": {
    "added":   [{"key": "delete_repo", "item": { /* Tool */ }}],
    "removed": [{"key": "...", "item": {}}],
    "changed": [{"key": "update_repo", "fields": ["description", "annotations"],
                 "before": {}, "after": {}}],
    "unchanged": 4
  },
  "resources": { /* same shape, key = uri */ },
  "prompts":   { /* same shape */ },
  "instructionsChanged": false,
  "notice": "..."
}
```

`from` is `null` (and everything is `added`) when there is no baseline.
`destructiveAdded` lists tools that are new with `destructiveHint: true` or
whose `destructiveHint` became `true`. The approval queue calls this with the
`artifact_id`'s version and shows `summary.text`.

### `POST .../servers/{serverName}/versions/{version}/capabilities/probe`

Repository `admin` (or instance administrator). Queues the jobs the
repository's settings allow for this version (an open job per target is not
duplicated). `202 {"queued": ["uuid"], "jobs": [ /* open jobs */ ]}`;
`409 mcp_introspection_disabled` when both `mcp_probe_remotes` and
`mcp_sandbox_introspection` are off for the repository. Publishing a version
queues the same jobs automatically.

### Introspection jobs

| Kind | Queued for | When |
| --- | --- | --- |
| `remote_probe` | each `remotes[]` entry of type `streamable-http` with a concrete `http(s)` URL (no `{template}` variables, no userinfo). Legacy `sse` remotes are not probed. | `mcp_probe_remotes`: `all` (Local, Staging, Remote), `hosted_only` (Local and Staging only), `off` (never, the default). Re-queued every `max(ttlMs, 6 h)` after the last probe, because a remote can change its tools without a version bump. |
| `sandbox_run` | each stdio `packages[]` entry of type `npm`, `pypi` or `oci` that the package policy pinned to an AK repository | `mcp_sandbox_introspection: on`. Never re-queued (the bytes are version pinned). Handed out only while the version is servable (its own and its backing packages' gates pass), so the bytes executed are the bytes AK scanned. |

Attempts: 3. `timeout`, `rate_limited` and `error` results are retried after
`2^attempts` minutes (a `429`'s `Retry-After`, clamped to 1 minute .. 24 h);
a claim not completed within 10 minutes returns to the queue. The scheduler
pass (every 15 minutes, idempotent) reaps expired claims and re-queues due
probes.

### Worker API (`/api/v1/mcp/introspection`)

Authenticated with an API token minted with the **`mcp:introspect`** scope
(admin-only to mint; a token with `*`/`admin` or an interactive session does
not qualify: `403 mcp_forbidden`). Mint it for a dedicated service account.

`POST /jobs/claim` with `{"kinds": ["remote_probe", "sandbox_run"],
"workerId": "pod-a"}` (both optional) answers `204` when nothing is due, or
`200`:

```json
{
  "jobId": "uuid",
  "claimToken": "opaque, single use",
  "kind": "remote_probe",
  "attempt": 1,
  "leaseExpiresAt": "2026-11-03T10:10:00Z",
  "repository": "mcp-local",
  "server": {"name": "com.acme/weather", "version": "1.0.0", "artifactId": "uuid"},
  "akBaseUrl": "https://ak.example.com",
  "target": {"type": "remote", "index": 0, "transport": "streamable-http", "url": "https://mcp.acme.com/mcp"},
  "limits": {"connectTimeoutMs": 10000, "totalTimeoutMs": 30000, "maxResponseBytes": 1048576,
             "maxItems": 1000, "followRedirects": false}
}
```

A `sandbox_run` target is `{"type": "package", "index": 0, "registryType":
"npm", "package": { /* the package exactly as AK serves it: registryBaseUrl /
OCI identifier rewritten to akBaseUrl */ }}` with limits `{"wallClockMs":
120000, "maxResponseBytes": 1048576, "maxItems": 1000, "network":
"ak-only"}`. The publisher's `remotes[].headers` are never handed out.
`akBaseUrl` is the base URL the worker reached the backend on.

`POST /jobs/{id}/complete`:

```json
{
  "claimToken": "...",
  "outcome": "ok",
  "authState": "none",
  "protocolVersion": "2026-07-28",
  "observedAt": "2026-11-03T10:00:00Z",
  "ttlMs": 3600000,
  "cacheScope": "public",
  "tools": [], "resources": [], "prompts": [], "instructions": null,
  "workerVersion": "ak-mcp-introspector/1.11.3",
  "retryAfterMs": null,
  "error": null,
  "details": {}
}
```

A failed outcome carries no lists. `200 {"status": "stored", "snapshotId",
"contentHash", "drift": {"scanId"} | null}` or `200 {"status": "retry",
"notBefore"}`; `409 mcp_claim_invalid` when the token does not match the
current claim (expired, re-claimed or already completed); `400` for a
malformed result.

### The `ak-mcp-introspector` worker

A separate binary of the backend crate (`cargo build --release --bin
ak-mcp-introspector`). It is not part of the backend image and the server
process never runs it: it holds no database or storage credentials and talks
to the backend only through the worker API.

```text
ak-mcp-introspector run [--sandbox] [--once] [--poll-secs 30]
    AK_URL, AK_MCP_INTROSPECTOR_TOKEN (mcp:introspect), AK_MCP_INTROSPECTOR_ID
ak-mcp-introspector probe <url>                      # one probe, printed; no backend
ak-mcp-introspector convert --from <inventory> <file> # print a report body
ak-mcp-introspector push --from <inventory> --repo <key> --server <name> --version <v> <file>
    AK_URL, AK_TOKEN (write:artifacts)
ak-mcp-introspector render-sandbox <job.json>         # print the guest spec and runner command
```

**Remote probe.** Per job: the URL must pass `validate_outbound_url` (public
addresses only; the worker refuses to start while `UPSTREAM_ALLOW_PRIVATE_IPS`
or `AK_SSRF_ALLOW_PRIVATE_CIDRS` is set); connections go through
`SsrfGuardResolver` (the address is re-checked at connect, closing DNS
rebinding); redirects are refused (`refused`); proxy variables are ignored;
10 s connect, 30 s per request and 30 s for the whole probe; every response
read is capped at 1 MiB; at most 1000 items per list and 50 pages. Requests
carry only `Content-Type`, `Accept: application/json, text/event-stream`,
`MCP-Protocol-Version`, `Mcp-Method`, a legacy server's own
`Mcp-Session-Id`, and `User-Agent: ak-mcp-introspector/<version> (+<docs>;
capability probe; never calls tools)`. Never a header from the server.json,
never credentials.

Protocol: `server/discover` with `_meta` `io.modelcontextprotocol/
protocolVersion: 2026-07-28`, `clientInfo` and empty `clientCapabilities`;
then `tools/list`, `resources/list`, `prompts/list` for the capabilities the
server advertises, following `nextCursor`. JSON and SSE answers are both
read. A `-32022` `UnsupportedProtocolVersionError` whose `supported` list
names a legacy version, or any other error / non-modern `4xx` (the fallback
does not key on one code), falls back to `initialize` (`2025-11-25`,
`2025-06-18`, `2025-03-26`, `2024-11-05`), `notifications/initialized`, then
the lists. `401`/`403` -> `auth_required`; `429` -> `rate_limited` with
`Retry-After`; `ttlMs` (smallest seen) and `cacheScope` (`private` ->
`authState: caller_specific`) are reported. The client can only send
`server/discover`, `initialize`, `notifications/initialized` and the three
list methods: `tools/call`, `resources/read` and `prompts/get` are refused in
code. Server-to-client requests over stdio are answered "method not found".

**Sandbox runner** (`--sandbox`). A pluggable `SandboxRunner` renders a
runner-neutral guest spec:

- npm: image `AK_MCP_SANDBOX_NODE_IMAGE` (default `node:22-alpine`),
  `npx --yes --registry=<registryBaseUrl> <identifier>@<version> <args>` and
  `npm_config_registry=<registryBaseUrl>`;
- pypi: image `AK_MCP_SANDBOX_PYTHON_IMAGE` (default
  `ghcr.io/astral-sh/uv:python3.12-alpine`), `uvx --no-config
  --default-index <registryBaseUrl>/simple <identifier>@<version> <args>`;
- oci: the AK-served `<ak host>/<repo>/<name>[:tag]@sha256:...` itself, no
  network.

Only what AK serves is run: a `registryBaseUrl` or OCI identifier that is not
this AK instance is refused; publisher `runtimeArguments` are dropped;
environment variables that steer a package manager or runtime (`NPM_CONFIG_*`,
`UV_*`, `PIP_*`, `PYTHON*`, `NODE_OPTIONS`, `LD_*`, proxy variables, `PATH`,
`HOME`, ...) are dropped. Every `isSecret` value, every required value
without a default and every `{template}` value is the placeholder
`AK_PLACEHOLDER_<NAME>`. The whole run, install included, is capped at 120 s,
after which the guest is killed. A guest that exits before answering is
reported `needs_config`.

Runners:

- **OCI runner** (default): `AK_MCP_SANDBOX_ENGINE` (`podman` default, or
  `docker`), `AK_MCP_SANDBOX_RUNTIME` (`runsc`, gVisor, by default; `kata-fc`
  or another microVM runtime works the same way; an empty runtime is refused
  unless `AK_MCP_SANDBOX_ALLOW_DEFAULT_RUNTIME=true`, because a plain
  container is not a boundary for attacker-chosen install scripts),
  `AK_MCP_SANDBOX_NETWORK` (default `ak-mcp-sandbox`), `AK_MCP_SANDBOX_MEMORY`
  (`1g`), `AK_MCP_SANDBOX_CPUS` (`1`). Rendered as `<engine> run --rm -i
  --name=ak-mcp-sbx-<job> --runtime=runsc --network=<net | none>
  --read-only --tmpfs=/tmp:rw,exec,nosuid,nodev,size=512m
  --user=65532:65532 --cap-drop=ALL --security-opt=no-new-privileges
  --pids-limit=256 --memory=1g --cpus=1 --pull=missing --stop-timeout=1
  --workdir=/tmp -e ... <image> <argv>`.
- **External runner**: `AK_MCP_SANDBOX_COMMAND=/path/to/launcher` is started
  as `<launcher> '<guest spec JSON>'` and must connect the guest's stdio to
  its own (a Firecracker launcher, a Kubernetes job wrapper). The spec:
  `{jobId, image, argv, env: [[name, value]], network: "ak-only" | "none",
  akBaseUrl, wallClockMs, notes}`.

**Inventory adapters** (`convert` / `push`, posted as `gateway_reported`):
`docker-gateway` (the array `docker mcp tools ls --format=json` prints),
`docker-catalog` (`tools.json` of the `docker/mcp-registry` catalog;
`arguments` become an `inputSchema`), `toolhive` (`thv mcp list tools
--format json`, or a ToolHive registry entry's list of tool names;
`set_during_runtime` is skipped), `static` (`{tools, resources, prompts,
instructions}`, e.g. Cisco MCP Scanner static JSON).

### Deploying the worker

1. Mint the credential: create a service account, then an API token for it
   with exactly the `mcp:introspect` scope (an instance administrator must
   mint it).
2. Run the binary where its egress is restricted. Remote probes: a pod whose
   NetworkPolicy allows the AK service and `0.0.0.0/0` **except** RFC 1918,
   CGNAT (`100.64.0.0/10`), link-local (`169.254.0.0/16`, including cloud
   metadata), loopback and the IPv6 equivalents. The in-process guard is
   defence in depth, not a substitute.
3. Sandbox (optional, `--sandbox`): a node with gVisor (`runsc` registered
   with podman/docker) or a microVM runtime, and a container network that
   reaches only the AK host (for example an internal network whose sole
   route is an egress proxy allowing the AK hostname). Mirror the runner
   images through an AK OCI repository and point the image variables at
   them. The worker needs the engine socket; isolate the node accordingly.
4. Turn it on per repository: `mcp_probe_remotes` (`hosted_only` / `all`)
   and/or `mcp_sandbox_introspection: on`. Both default to off and can be
   locked by an instance administrator.

The repository ships no container image or compose service for the worker;
build it with `cargo build --release --bin ak-mcp-introspector` and package
it with your deployment.

Audit: `MCP_CAPABILITIES_INGESTED` for every stored snapshot (declared,
reported or observed; the reporter as actor when there is one) and
`MCP_TOOLS_DRIFT` for every drift finding.
