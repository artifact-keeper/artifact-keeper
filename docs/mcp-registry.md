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
| `GET /v0.1/openapi.yaml` | read | The upstream registry API specification (`info.version: 2025-12-01`), vendored verbatim; `Content-Type: application/yaml`. See [OpenAPI document](#openapi-document). |
| `GET /v0.1/x/com.artifactkeeper/holds` | repository holder | Held versions with their hold class and reason, for CI tooling. See [Holds listing](#holds-listing). |
| `POST /v0/auth/github-oidc` (also `/v0.1`) | none (the OIDC token is the credential) | `mcp-publisher login github-oidc`. See [GitHub Actions login](#github-actions-login-mcp-publisher-login-github-oidc). |
| `ANY /v0/auth/*` (other) | none | `501 mcp_auth_not_supported`: use an Artifact Keeper token. |

Administration (instance administrators, under `/api/v1/admin`):

| Method and path | What it does |
| --- | --- |
| `GET /api/v1/admin/mcp/namespace-proofs` | `{"items": [Proof]}`, at most 1000, by namespace. |
| `POST /api/v1/admin/mcp/namespace-proofs` | `{"namespace": "com.acme", "method": "dns" \| "http"}` -> `Proof` (`status: pending`). `400` for another method or a namespace that is not reverse-DNS. |
| `GET /api/v1/admin/mcp/namespace-proofs/{id}` | `Proof`, `404` unknown. |
| `POST /api/v1/admin/mcp/namespace-proofs/{id}/verify` | Run the check now; `Proof` with `status` `verified` or `failed` (`last_error` says why). |
| `DELETE /api/v1/admin/mcp/namespace-proofs/{id}` | `200`, `404` unknown. |

Namespace grants are ordinary permission rules (`/api/v1/permissions`) with
`conditions.mcp_namespaces`; see [Namespace grants](#namespace-grants).

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
may publish (optionally per namespace, see [Namespace grants](#namespace-grants)).

### GitHub Actions login (`mcp-publisher login github-oidc`)

`POST /mcp/<repo>/v0/auth/github-oidc` (and `/v0.1/...`) is upstream's
exchange, bridged to Artifact Keeper's CI OIDC exchange
(`/api/v1/auth/ci/token`, same providers, identity mappings and service
accounts):

- Request: `Content-Type: application/json`, body `{"oidc_token": "<GitHub Actions ID token>"}`
  (at most 16 KiB), no `Authorization` header. The route is outside the
  repository visibility check, so it works for a private repository; the
  repository segment does not change what is minted.
- `200`: `{"registry_token": "<Artifact Keeper access token>", "expires_at": <unix seconds>}`
  (upstream's `auth.TokenResponse`). The token is the CI identity mapping's
  service-account token (provider `token_ttl_secs`, default 900 s; no
  refresh).
- `401 mcp_unauthorized` (problem+json) when the token is not accepted: no
  enabled provider for its issuer, a bad signature, audience or expiry, or no
  mapping matches. `400 mcp_bad_request` for another body; `503` when the
  instance sheds load.
- Every other `/auth/*` route (`none`, `github-at`, `dns`, `http`, ...)
  answers `501 mcp_auth_not_supported`.

Set it up once: an administrator creates a CI OIDC provider for
`https://token.actions.githubusercontent.com` whose `audience` is the
registry URL's scheme and host, lowercased, without a path
(`https://ak.example.com`; that is the audience `mcp-publisher` requests),
and an identity mapping (claim filters such as `repository_owner`), then
grants the mapping's service account `write` on the repository, typically as
a namespace grant. In the workflow (`permissions: id-token: write`):

```bash
mcp-publisher login github-oidc --registry https://ak.example.com/mcp/mcp-local
mcp-publisher publish
```

### Namespace grants

A permission rule (`POST /api/v1/permissions`) may carry
`conditions.mcp_namespaces`, a list of 1 to 64 server-name patterns:

```json
{"principal_type": "service_account", "principal_id": "<id>",
 "target_type": "repository", "target_id": "<mcp repo id>",
 "actions": ["read", "write"],
 "conditions": {"mcp_namespaces": ["io.github.{repository_owner}/*", "com.acme"]}}
```

- On an MCP write (publish, status change; edit and delete use the same
  gate) the rule applies only when the server name matches a pattern. `*`
  matches any run of characters including `/`, matching is ASCII
  case-insensitive, and a pattern without `/` means the namespace's servers
  (`com.acme` = `com.acme/*`, not `com.acmecorp/*`). Patterns contain letters,
  digits, `.`, `_`, `-`, `*`, at most one `/`, and `{claim}` placeholders
  (lowercase claim names); anything else is `400` at write time.
- `{claim}` is replaced by that claim of the CI OIDC assertion the calling
  token was exchanged for (through `/auth/github-oidc` or
  `/api/v1/auth/ci/token`; the bounded string claims are kept with the token
  until it expires). A value is used only when it is a plain label
  (`[A-Za-z0-9._-]`, at most 256 characters), so a claim can never widen a
  pattern; a missing claim, an unusable value, or a credential that did not
  come from a CI exchange makes the pattern match nothing.
- Without `mcp_require_namespace_grant`, a matching namespace rule is an
  applicable rule like any other, and a non-matching one does not apply to
  that write (the decision falls to the caller's other rules, then to its
  role assignments, exactly as for an IP-conditioned rule).
- With `mcp_require_namespace_grant: true` on the repository, repository
  `write` is not enough: only an instance administrator or a matching
  namespace rule granting the action (`write`, or `admin`) may write.
- A refused write answers `403 mcp_namespace_not_granted`
  (`"this credential holds no grant for namespace 'com.other' in this repository"`).
- Creating, changing or deleting a rule audits `MCP_NAMESPACE_GRANTED` for
  each pattern added and `MCP_NAMESPACE_REVOKED` for each pattern removed.
- The condition is ignored by every check other than MCP writes. The generic
  artifact delete route (`DELETE /api/v1/repositories/{key}/artifacts/...`)
  is not namespace-aware in this release.

### Namespace proofs

An administrator may record proof that the owner of a domain controls a
reverse-DNS namespace (`com.acme` is `acme.com`, `io.github.acme` is
`acme.github.io`). A proof is evidence shown and audited; it grants nothing
(namespace grants do).

`Proof`:

```json
{"id": "<uuid>", "namespace": "com.acme", "domain": "acme.com", "method": "dns",
 "status": "pending", "last_error": null, "created_by": "<uuid>",
 "created_at": "...", "last_checked_at": null, "verified_at": null,
 "challenge": {"type": "TXT", "name": "_ak-mcp-challenge.acme.com",
               "value": "ak-mcp-verification=<64 hex>"}}
```

For `method: "http"` the challenge is
`{"url": "https://acme.com/.well-known/ak-mcp-challenge", "content": "ak-mcp-verification=<64 hex>"}`:
the file must contain that value on a line of its own.

`POST .../{id}/verify` is the only time Artifact Keeper contacts the domain:
the DNS check asks a DNS-over-HTTPS resolver (JSON API,
`MCP_NAMESPACE_PROOF_DOH_URL`, default `https://cloudflare-dns.com/dns-query`)
for the TXT record; the HTTP check fetches the well-known URL. Both go through
the outbound URL policy and the SSRF-guarding DNS resolver (no private,
loopback, link-local or metadata addresses), follow no redirects, read at most
64 KiB and time out after 10 seconds. The outcome is stored (`verified` with
`verified_at`, or `failed` with `last_error`; re-verifying a verified proof
that no longer checks out marks it failed) and audited as
`MCP_NAMESPACE_PROOF_VERIFIED` or `MCP_NAMESPACE_PROOF_FAILED`.

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

**Host-level registry (`MCP_DEFAULT_REPO`).** Off by default. Set
`MCP_DEFAULT_REPO=<repo_key>` and `https://<ak>/v0.1/...` and
`https://<ak>/v0/...` (and nothing else) are served exactly as
`https://<ak>/mcp/<repo_key>/v0.1/...`, so a client can be given the bare
host. The rewrite happens before routing (authentication and visibility see
the repository path); no other Artifact Keeper route starts with `/v0`. A value
that is not a plain repository key is ignored with a warning. Served
coordinates and `instance` URLs keep the `/mcp/<repo_key>` form.

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

A Virtual `mcp` repository merges MCP members (Local, Staging, Remote; nested
Virtuals are flattened in priority order) on the same `/mcp/<key>/v0.1`
routes. It resolves nothing and contacts nothing itself: every version it
serves is a member's stored version, decided by that member's own gates
(holds, backing packages, curation and deny lists of the member) with the same
functions the member's own routes use. What a member would not serve, the
Virtual does not serve.

Serving order: hosted members (Local, Staging) by priority, then Remote
members by priority. Only members the caller may read take part, except in
the shadowing rule below.

- **Detail** (`/servers/{name}/versions/{version}`, including `latest`): the
  first member in serving order that serves that name and version answers;
  a member that holds it is skipped. `latest` is the first member's newest
  servable version (first match, not the newest across members).
- **Hosted shadows remote.** When any hosted member holds a version of a name
  (any version, any status, even one this caller cannot read), the name is
  never served from a Remote member, so an upstream server cannot take over
  an internal name (dependency confusion).
- **`/servers/{name}/versions`**: the union of the serving members' servable
  versions, each version once (from the first member that serves it), in
  version-text order; `isLatest` marks the version `latest` answers.
- **`/servers`**: each `(name, version)` once, from the member a detail read
  would answer it from; member by member in serving order, each member's rows
  in name-then-version order. `version=latest` lists one entry per name, the
  one `latest` answers. `search`, `updated_since`, `include_deleted` and
  `limit` behave as on a hosted repository.
- **Cursor**: `nextCursor` is
  `base64url("m:<member_key>:<member_cursor>")` (no padding), where
  `<member_cursor>` is that member's own `base64url("<name>:<version>")`
  cursor, or empty to start at the member's first row. A cursor naming a key
  that is not (or no longer) a member, or anything else malformed, is `400`
  (`mcp_invalid_server_json`, `detail: "cursor: invalid cursor"`).
- **Entries** are the member's served form; the
  `com.artifactkeeper.registry/source` block names the member (`repository`)
  and adds `virtualRepository: "<virtual key>"`.
- **Holds**: a reader gets the unknown-name `404` (byte-identical) for
  anything not served. A caller who holds the member that refused (the
  reason-gate predicate, evaluated per member) gets that member's reason
  body; a gate that cannot be evaluated on a member answers `503` and the
  walk does not fall past it.
- **`mcp_server_deny` on the Virtual** hides matching names on top of the
  members' own deny lists: omitted from listings, `404` on detail
  (`mcp_rejected` with `gate: curation` for a holder of the Virtual).
- **Writes** (`/publish`, status `PATCH`) answer
  `405 mcp_read_only` ("publish to one of its hosted members").
- `/ping`, `/health`, `/version` and `/openapi.yaml` answer as on any MCP
  repository; the holds listing answers `404` on a Virtual (ask its members).

### Holds listing

`GET /mcp/<repo>/v0.1/x/com.artifactkeeper/holds` (and `/v0/...`) lists the
versions a client would not be handed, for CI tooling ("why is my server not
in the gallery?"). Query: `cursor`, `limit`, `search` with the `/servers`
rules (deleted versions are not holds and are not listed).

- Only a **repository holder** (the reason-gate predicate above) gets the
  list. Every other caller, including an anonymous reader of a public
  repository, gets the unknown-name `404`: an empty list would read as
  "nothing is held". A Virtual answers `404`.
- `200`, `Cache-Control: no-store`:

```json
{"holds": [
   {"status": 404, "error": "mcp_backing_artifact_blocked",
    "detail": "A package this server version runs is held pending review",
    "name": "com.acme/db", "version": "2.0.0", "hold": "backing",
    "package": "npm:@acme/db-tool@2.0.0", "gate": "quarantine",
    "instance": "https://ak.example.com/mcp/mcp-local/v0.1/servers/com.acme%2Fdb/versions/2.0.0"}
 ],
 "metadata": {"count": 1, "nextCursor": "..."}}
```

  Each entry is the reason-gated refusal body of an exact read (without the
  RFC 9457 `type`/`title`), with `status` the HTTP status that read answers
  (`404`, or `503` with `error: mcp_gate_unavailable` when a gate cannot be
  evaluated). Members by hold: `hold` (`quarantine`, `scan_policy`,
  `backing`, `age_gate`, `unresolvable`, `resolving`, `curation`,
  `content_drift`), `gate`, `package`, `review_id`, `min_age_days`,
  `requested_age_days`, as in [What a client sees](#what-a-client-sees).
- At most 1000 rows are gated per request; a scan stopped by that bound
  answers a `nextCursor`.

### OpenAPI document

`GET /mcp/<repo>/v0.1/openapi.yaml` serves upstream's
`docs/reference/api/openapi.yaml` (`modelcontextprotocol/registry` at
`a75c727d`, MIT) verbatim, as `application/yaml`, readable like the
repository. It describes `/v0.1/servers`, `/versions`, `/versions/{version}`,
the status routes and `/publish`, which is what Artifact Keeper implements;
Artifact Keeper's additions (problem+json `error` members, the holds
listing, `/auth/github-oidc`, `/x/com.artifactkeeper/*`) are documented here,
not in that file.
