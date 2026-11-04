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

## Lint and health

### The lint

Every server version is linted (`McpLintScanner`, offline and
deterministic: no network, no model). The lint reads the stored server.json
(`title`, `description`, every package's `runtimeArguments`,
`packageArguments`, `environmentVariables` and transport `headers`, every
remote's `url`, `headers` and `variables`), the tools the publisher declares
in `_meta` (`com.artifactkeeper/capabilities.tools`, directly or inside
`io.modelcontextprotocol.registry/publisher-provided`), the tools of stored
MCPB bundles (`metadata.bundles[*].manifest.tools`), the OCI pins and image
labels, and the `statusMessage`.

It runs on every hosted publish (independent of the repository's scan
settings) and on every status change, and can be re-run over a stored
version (`services::mcp_lint::lint_stored_version`, for Remote ingest and
admin edits). Observed tool snapshots are linted with
`mcp_lint::lint_tools` and recorded under their own source
(`mcp_lint::record_lint_findings(db, artifact_id, findings, source)`), so
publisher-declared and bundle tools are not linted twice.

### Rules, actions and how the gates read them

| Rule | Actions | What it flags |
| --- | --- | --- |
| `secret_literal` | `block` | A recognisable credential (AWS key id, GitHub/GitLab/npm/PyPI/Slack/Stripe/Google token, `sk-` keys, JWT, PEM private key) in any linted string; in value positions (`default`, `value`, `choices`, header values, URL variables) also a high-entropy random literal; a password in a remote URL's user-info; a credential-named query parameter with a literal value. The value is never repeated in the finding. |
| `secret_unmarked` | `review` | An environment variable, header or argument whose name reads as a credential (`token`, `secret`, `password`, `api_key`, `auth`, `authorization`, `key`, ...) without `isSecret: true`. |
| `injection_phrase` | `review` | Instructions aimed at the model: "ignore previous instructions", "you must", "do not tell the user", "system prompt", pseudo-tags (`<important>`, `<system>`), HTML/markdown comments, `IMPORTANT:`, chat role tags (`<\|im_start\|>`, `[INST]`, `<<SYS>>`), fenced code, "before using this tool", credential file references (`~/.ssh`, `id_rsa`, `.aws/credentials`, `.npmrc`, `mcp.json`). URLs count only in descriptions and titles shown to the model (server, tools, `inputSchema`), not in `statusMessage` or variable descriptions. Decision 13: `review`, never `block`. |
| `hidden_text` | `block` | Control (other than tab and line breaks), bidirectional, zero-width or Unicode tag characters in any linted string or object key. Stored as finding class `malicious`. |
| `dangerous_args` | `block`, `review` | `block`: in `runtimeArguments`, flags that re-route installs around the backing repository (`--registry`, `--index-url`, `--extra-index-url`, `--find-links`, `--index`, `--default-index`, `--source`, `--pypi-mirror`); anywhere, `--privileged`, a bind mount of the host root (`-v /:/host`, `--mount source=/`) or of the Docker socket. `review`: the same re-routing flags in `packageArguments`, other host bind mounts, `--network/--net/--pid/--ipc/--uts/--userns=host`, `--cap-add`, `--security-opt`, `--device`, `--unsafe-perm`, `--trusted-host`, `--insecure`, `-A`/`--allow-*`, and `LD_PRELOAD`, `NODE_OPTIONS`, `PYTHONPATH` and other code-injecting variables (as `-e`/`--env` values, positional `NAME=value` arguments or environment variable names). Both `--flag value` and `--flag=value` spellings. |
| `remote_url_shape` | `review`, `warn` | `remotes[].url` only. `review`: a template variable in the host, user-info, an IP literal (private or public), `localhost`. `warn`: plain `http`, a non-default port on a public host, an internal host name (`.internal`, `.local`, `.corp`, `.lan`, `.intranet`, `.home.arpa`, `.localdomain`) in a public registry. |
| `oci_tag_digest_mismatch` | `warn` | A submitted `:tag@sha256:D` whose tag currently resolves to another digest (`D` is pinned). |
| `oci_label_mismatch` | `warn` | The pinned image's config has no `io.modelcontextprotocol.server.name` label, a label naming another server, or a config that is not stored in the backing repository (labels are read from the stored manifest and config blob, never fetched). Under `mcp_require_oci_label: true` this refuses the publish instead (see below). |
| `mcpb_missing_sha` | `block`, `review` | `block`: an `mcpb` package without `fileSha256`. `review`: an `mcpb` `fileSha256` that matches no bundle stored with the version (when bundles are stored). |
| `destructive_tool` | `review`, `warn` | `warn`: a tool whose name reads as destructive (`delete`, `drop`, `rm`, `purge`, `wipe`, `truncate`, `kill`, `reset`, `overwrite`, ...) or that declares `destructiveHint: true`. `review`: a destructive name whose annotations claim `readOnlyHint: true` or `destructiveHint: false`. |
| `shell_like_tool_name` | `review` | A tool whose name reads as running arbitrary commands (`shell`, `bash`, `sh`, `cmd`, `powershell`, `terminal`, `exec`, `eval`, `subprocess`, or `run`/`execute` with `command`/`script`/`code`/`process`). |

| Action | `scan_findings.severity` | Hosted publish / status change | Every other path (scan-policy gate) |
| --- | --- | --- | --- |
| `block` | `critical` | refused `422 mcp_lint_blocked` | held by any enabled scan policy (`max_severity` `critical` or stricter) until acknowledged |
| `review` | `high` | accepted, finding recorded | held by a scan policy at `max_severity` `high` or stricter until acknowledged |
| `warn` | `low` | accepted, finding recorded | held only by a policy at `max_severity` `low` |

A held version disappears from the MCP surface exactly as any other
scan-policy hold (`mcp_rejected`, section "What a client sees"), and
acknowledging the finding through `POST /api/v1/security/findings/{id}/acknowledge`
releases it. A finding's acknowledgement identity is the server.json bytes,
the rule and the field: re-linting the same version keeps it acknowledged.

### Where findings are stored

One completed `scan_results` row with `scan_type = "mcp_lint"` and
`scanner_version = "ak-mcp-lint/1"` per lint run of the server.json artifact,
listed by `GET /api/v1/security/artifacts/{artifact_id}/scans` like any scan.
Each finding:

| Column | Value |
| --- | --- |
| `title` | `mcp_lint/<rule>` (for example `mcp_lint/secret_literal`) |
| `description` | the one-line message |
| `affected_component` | `<source>:<path>`, for example `server_json:packages[0].environmentVariables[1].default` |
| `source` | `mcp_lint/<source>`: `server_json`, `status_message`, or the caller's source for observed tools |
| `severity` | per the action table above |
| `finding_class` | `malicious` for `hidden_text`, `policy` otherwise |
| `cve_id`, `affected_version` | `null` |

A run of one source replaces that source's findings and carries every other
source's forward, so the newest `mcp_lint` row is the whole verdict; a run
whose findings did not change writes no row.

### Publish and status refusals

`POST /v0.1/publish` and `PATCH .../status` answer `422`
`application/problem+json`:

- `mcp_lint_blocked`: `detail` lists `<rule> at <path>: <message>` for every
  `block` finding; extension member `findings: [{rule, action, path,
  message}]`.
- `mcp_oci_label_mismatch` (publish, `mcp_require_oci_label: true`):
  `detail` = `packages[<i>]: <why>; this registry requires the label
  (mcp_require_oci_label)`; `findings: [{rule: "oci_label_mismatch", action:
  "block", path: "packages[<i>].identifier"}]`.

### Server health

`GET /api/v1/repositories/{key}/mcp/servers/{serverName}/versions/{version}/health`
(`{serverName}` URL-encoded or with a literal slash; `{version}` exact).
Caller: an instance administrator or a user with `read` granted on the
repository (the quarantine-reason predicate). Anyone else, an unknown
repository, a non-MCP repository, an unknown or deleted version: `404` with
the standard error body. Works on Local, Staging and Remote repositories
(Remote: ingested versions).

`200`:

```json
{
  "name": "com.acme/weather",
  "version": "1.2.0",
  "artifactId": "8d6c…",
  "status": "warning",
  "packagePolicy": "own-repos",
  "packages": [
    {
      "index": 0, "package": "npm:@acme/weather-mcp@1.2.0", "registryType": "npm",
      "repository": "npm-local", "scanned": true, "score": 97, "grade": "A",
      "critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0,
      "gate": "allowed", "status": "warning"
    }
  ],
  "lint": {
    "ran": true, "scanId": "…", "lintedAt": "2026-11-03T10:00:00Z",
    "block": 0, "review": 1, "warn": 0,
    "findings": [
      {
        "id": "…", "rule": "secret_unmarked", "action": "review", "severity": "high",
        "source": "server_json", "path": "packages[0].environmentVariables[0].isSecret",
        "message": "\"API_TOKEN\" looks like a credential but is not marked `isSecret: true`, …",
        "acknowledged": false
      }
    ]
  }
}
```

- `packages[].counts` (`critical` .. `info`) are the unacknowledged findings
  of the pinned artifacts' current scans; `score`/`grade` use the repository
  score formula over them (`null` when unscanned). `gate` is the backing
  gate: `allowed | quarantine | scan_policy | age_gate | unresolvable |
  unavailable`.
- `lint.block/review/warn` count unacknowledged findings; `lint.findings[]`
  lists all of them (`id` is the finding id the acknowledgement API takes).
  `ran: false` (and no `scanId`) when the version was never linted.
- `status`, the worst of: per package `critical` (gate `quarantine`,
  `scan_policy` or `unresolvable`, or a critical finding), `warning`
  (`age_gate`, or a high/medium finding), `unknown` (no completed scan, or
  gate `unavailable`), else `ok`; the lint `critical` (`block` > 0),
  `warning` (`review` > 0), `unknown` (never ran); `unknown` for a version
  with packages but no pins (published under `open`). Order:
  `critical` > `warning` > `unknown` > `ok`.
