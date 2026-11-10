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
| `POST /v0.1/validate` | none on a public repository (read on a private one) | Dry run of a publish: `200` with `{valid, issues, packages}`; nothing is written. See [`POST /validate`](#post-validate). |
| `PUT /v0.1/servers/{serverName}/versions/{version}` | repository admin | Replace a version's document (admin edit). |
| `DELETE /v0.1/servers/{serverName}/versions/{version}` | write | Soft delete: status `deleted`, tombstoned. |
| `POST /v0.1/servers/{serverName}/versions/{version}/purge` | instance administrator | Purge a soft-deleted version: its server.json and bundles go to the trash, releasing its pins; the tombstone stays. See [Purge](#post-versionsversionpurge-admin-purge). |
| `PUT /v0.1/servers/{serverName}/versions/{version}/bundles/{file}.mcpb` | write | Upload an MCPB bundle for a version before publishing it. |
| `GET /v0.1/servers/{serverName}/versions/{version}/bundles/{file}.mcpb` | read | Download a bundle of a published version. |
| `PATCH /v0.1/servers/{serverName}/versions/{version}/status` | write | `{"status": "active" \| "deprecated" \| "deleted", "statusMessage": "..."}` |
| `PATCH /v0.1/servers/{serverName}/status` | write | The same for every version; answers `{updatedCount, servers}`. |
| `GET /v0.1/ping`, `/health`, `/version` | read | `{"status":"ok"}`, a database-checked health answer, `{"version": "<AK version>"}`. |
| `GET /v0.1/openapi.yaml` | read | The upstream registry API specification (`info.version: 2025-12-01`), vendored verbatim; `Content-Type: application/yaml`. See [OpenAPI document](#openapi-document). |
| `GET /v0.1/x/com.artifactkeeper/holds` | repository holder | Held versions with their hold class and reason, for CI tooling. See [Holds listing](#holds-listing). |
| `POST /v0/auth/github-oidc` (also `/v0.1`) | none (the OIDC token is the credential) | `mcp-publisher login github-oidc`. See [GitHub Actions login](#github-actions-login-mcp-publisher-login-github-oidc). |
| `GET /v0.1/servers/{serverName}/versions/{version}/capabilities` | read | Capability snapshots of a version (see [Capabilities and introspection](#capabilities-and-introspection)). |
| `POST /v0.1/servers/{serverName}/versions/{version}/capabilities` | write | Report a CI- or gateway-observed capability list. `201`. |
| `GET /v0.1/servers/{serverName}/versions/{version}/capabilities/diff` | read | Tool, resource and prompt diff between two snapshots (approval queue). |
| `POST /v0.1/servers/{serverName}/versions/{version}/capabilities/probe` | repository admin | Queue introspection jobs when the repository's settings allow them. `202`. |
| `ANY /v0/auth/*` (other) | none | `501 mcp_auth_not_supported`: use an Artifact Keeper token. |

Administration (instance administrators, under `/api/v1/admin`):

| Method and path | What it does |
| --- | --- |
| `GET /api/v1/admin/mcp/namespace-proofs` | `{"items": [Proof]}`, at most 1000, by namespace. |
| `POST /api/v1/admin/mcp/namespace-proofs` | `{"namespace": "com.acme", "method": "dns" \| "http"}` -> `Proof` (`status: pending`). `400` for another method or a namespace that is not reverse-DNS. |
| `GET /api/v1/admin/mcp/namespace-proofs/{id}` | `Proof`, `404` unknown. |
| `POST /api/v1/admin/mcp/namespace-proofs/{id}/verify` | Run the check now; `Proof` with `status` `verified` or `failed` (`last_error` says why). |
| `DELETE /api/v1/admin/mcp/namespace-proofs/{id}` | `200`, `404` unknown. |

Introspection worker API (a token with the `mcp:introspect` scope; see
[Worker API](#worker-api-apiv1mcpintrospection)):

| Method and path | What it does |
| --- | --- |
| `POST /api/v1/mcp/introspection/jobs/claim` | Worker API: claim the next job (`200`) or nothing due (`204`). |
| `POST /api/v1/mcp/introspection/jobs/{id}/complete` | Worker API: post a job's result. |

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
- `com.artifactkeeper.registry/source`: where the version comes from:

  ```json
  {"repository": "mcp-local", "artifactId": "<uuid>", "sha256": "<hex>",
   "packagePolicy": "own-repos" | "open",
   "origin": "hosted" | "remote" | "mirror",
   "upstreamVerified": false,
   "kind": "upstream", "upstreamUrl": "https://registry.modelcontextprotocol.io"}
  ```

  `sha256` is that of the stored document. `origin` is `hosted` for a
  version published to this instance, `remote` for one a Remote ingested in
  `mcp_remote_mode: allowlist`, `mirror` for one ingested in `mirror` mode.
  `kind` and `upstreamUrl` (the Remote's `upstream_url`, userinfo stripped)
  are present only on ingested versions. `upstreamVerified` is `true` only for an ingested
  version whose upstream is the official registry
  (`https://registry.modelcontextprotocol.io`) or another Artifact Keeper
  (its entries carry this same source block), whose content matched at
  ingest, and whose upstream bytes have not changed since: for an Artifact
  Keeper upstream, the `sha256` it advertises equals the sha256 of the
  document received (an upstream Artifact Keeper rewrites `registryBaseUrl`
  of pinned packages when serving, so a document with packages usually does
  not match and is `false`); the official registry advertises no content
  hash, so a document received from it over HTTPS counts as matching; a
  later sync that sees other bytes under the version (content drift) clears
  the flag for good. Every other upstream, and every hosted version, is
  `false`. A Virtual adds `virtualRepository` (see
  [Virtual repositories](#virtual-repositories)).

The publisher's own `_meta` is reduced to
`io.modelcontextprotocol.registry/publisher-provided` (at most 4096 bytes),
as upstream does.

Choices pinned for this release: list order is name then version as text
(upstream's); a version is write-once (`409` on republish, even with identical
bytes, and for ever after the version was deleted, trashed or purged: see
[Tombstones](#tombstones); a version whose package resolution failed is the
exception); `latest` is the newest version that is servable now, ordered as
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
server. `latest` looks at the newest 100 non-deleted versions of a server, on
every surface (`/versions/latest`, `isLatest`, `version=latest`): a server
whose newest 100 versions are all held has no `latest` (the unknown-name
`404` for a reader), and no entry carries `isLatest: true`.

`nextCursor` is opaque, as upstream specifies: a URL-safe string to pass back
as `cursor` unchanged. It is sealed (AES-256-GCM under a key derived from the
instance's `jwt_secret`) and bound to the repository and listing that issued
it, so a client cannot read or make one up. It never names a version the
reader is not served, not even sealed: it holds the last row the listing
served and, when the request stopped at the row bound after reading only
rows the reader is not served, the internal id of the last of those rows.
That id is a random UUID: fixed-length, unordered and meaningless outside
this instance, so it is not a server name or version. The next request
looks the row up (deleted rows included) and continues strictly after it,
so the walk moves past held rows at the cost of a keyset resume at any
depth, and a version deleted or soft-deleted between pages moves nothing.
If that row has been purged, the walk resumes after the last served row.
A Virtual's composite cursor works the same way.
A cursor this instance did not issue for that listing, including one issued
before an upgrade that introduced sealing or before a `jwt_secret` rotation,
is `400 mcp_invalid_query` (`invalid cursor`); start again without `cursor`.

Behaviour pinned by the end-to-end suite (clients may rely on it):

- A private repository answers an anonymous caller `401 mcp_unauthorized`
  (problem+json, with the `WWW-Authenticate` challenge every format route
  gives), and an authenticated user with no grant on it the plain
  unknown-name `404` (the body of [What a client sees](#what-a-client-sees)),
  on every read route. The `401` comes from the repository visibility
  middleware (`repo_visibility_middleware` in
  `backend/src/api/middleware/auth.rs`), which refuses the request before the
  MCP handler runs; `mcp_surface_guard` in `backend/src/api/handlers/mcp.rs`
  re-renders it as problem+json (test `visibility_middleware_gates_the_surface`).
  A key that names no repository gets the same `401` anonymously, so the
  status does not reveal which private registries exist.
- Writes keep that guarantee (#5458). A publish, a status change
  (`PATCH .../status`) or an introspection request (`POST .../capabilities`,
  `.../capabilities/probe`) on a private repository by an authenticated
  caller who cannot read it (an administrator of some other repository, a
  token minted for other repositories) is refused by the same middleware with
  the plain unknown-name `404`, byte for byte (status, headers, body) what a
  key naming no repository answers, before any document, namespace, OIDC or
  policy check runs; nothing is written. A caller who can read the repository
  but may not write it still gets `403 mcp_forbidden` (test
  `write_denials_to_non_readers_match_an_unknown_key`). A public or
  `internal` repository is readable by every authenticated caller, so its
  write refusal stays `403` (except for a token scoped elsewhere on an
  `internal` one). The rule is the same on every format route; see
  [Repository visibility](repository-visibility.md#write-refusals-to-callers-who-cannot-read).
  Troubleshooting: a publish to a private registry with a token scoped to
  another repository, or by a user who lost their grant, now answers the
  unknown-server-name `404`, not `403`; check the token's repository scope.
- A trailing slash (`/v0.1/servers/`) is not a route: plain `404`.
- `/versions` is not paged: it returns every servable version (at most the
  newest 1000) with no `nextCursor`.
- `POST /publish` ignores the request `Content-Type`; the body is parsed as
  JSON either way. A JSON object with a duplicate key anywhere in the document (including
  `_meta`) is `400 mcp_invalid_server_json`.
- `PATCH /servers/{serverName}/status` answers `{updatedCount, servers}` where
  `updatedCount` counts only the versions whose status actually changed;
  versions already in the requested state are left alone (and if every
  version already is, the answer is `400`).
- Malformed query parameters (`limit`, `cursor`, `updated_since`,
  `include_deleted`, an over-long `search`, `include_deleted=false` with
  `updated_since`) are `400 mcp_invalid_query`; a malformed document is `400
  mcp_invalid_server_json`; a `search` under 3 characters is `422
  mcp_search_too_short`.
- A write without `write:artifacts` is `403 mcp_forbidden` ("This token does
  not carry the write:artifacts scope"); a token minted for other repositories
  is `403 mcp_forbidden` on a public repository and the unknown-name `404` on
  a private or `internal` one (see above). The `detail` text depends on which check refuses it
  ("This token is not scoped to this repository" or "This credential may not
  write to this repository"), so clients should match on `code`, not `detail`.

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

When a package is still being filled into a Remote backing repository,
publish answers `202 resolving` and `mcp-publisher` prints that as an error
although the version was stored. Do not run it again; see [Packages in a
Remote backing repository](#packages-in-a-remote-backing-repository).

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
{"principal_type": "user", "principal_id": "<the mapping's service_account_id>",
 "target_type": "repository", "target_id": "<mcp repo id>",
 "actions": ["read", "write"],
 "conditions": {"mcp_namespaces": ["io.github.{repository_owner}/*", "com.acme"],
                "mcp_namespace_issuer": "https://token.actions.githubusercontent.com"}}
```

The account a CI identity mapping signs in as is a `user` principal: CI
OIDC mints it as a `users` row (`auth_provider: ci`), not as a service
account, so `principal_type: "service_account"` with a mapping's
`service_account_id` is refused (`400`, "does not exist as a
service_account"). A service account created under `/api/v1/service-accounts`
is granted with `principal_type: "service_account"`.

The condition is accepted only on a `repository` target that is an MCP
repository; on any other target (a project, a non-MCP repository) the write
is `400`.

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
- Claims are bound to their issuer. A rule whose patterns contain a
  `{claim}` must name `conditions.mcp_namespace_issuer` (an `http(s)` issuer
  URL, compared without a trailing `/`; `400` when missing, or when given
  without `mcp_namespaces`). Its claims are interpolated only from a session
  whose verified assertion's `iss` is that issuer, so another CI provider's
  `repository_owner` (a GitLab group of the same name, say) never satisfies a
  pattern written for GitHub's. Patterns without placeholders need no issuer.
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
- Outside the MCP namespace write gate a rule carrying `mcp_namespaces` is
  not applicable: it grants nothing (not `read`, not `write`, not `delete`) to
  the generic artifact API, the repository ACL or listings, and it does not
  make the repository count as having fine-grained rules. A namespace-scoped
  publisher that should also read a private registry needs an unconditioned
  `read` rule through another principal: a group the user belongs to, or a
  role assignment. It cannot be a second rule for the same user, because
  there is one rule per principal and repository (and `read` in the
  conditioned rule itself grants nothing here, as above). On the `/mcp/<key>/...` surface of an MCP
  repository the route-level write check counts the rule (as an applicable
  rule granting its actions), and every MCP write route there (publish, status
  change, delete, bundle upload, capability reports) then runs the namespace
  gate on the server name. Routes that need repository administration (the
  admin edit, `.../capabilities/probe`, the catalog) are not satisfied by a
  namespace rule.

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
- **`open`**. Foreign coordinates are accepted, nothing else is relaxed
  (#5452). A `registryBaseUrl` naming another registry, or an OCI image on
  another host, is not refused with `mcp_external_registry` when the package
  resolves in a hosted (Local or Staging) backing repository, or a Virtual's
  hosted member: the package is looked up there by name and version (an image
  by its path and tag or digest), pinned, served at its Artifact Keeper
  coordinates and gated exactly as under `own-repos`.

  Content that reaches this instance through a Remote came from that
  Remote's upstream, so it stands only for coordinates naming that upstream:
  the same origin (scheme, host, port) and a path under the upstream URL's
  path, compared by whole segments. A registry is often one path of a shared
  host (GitLab's `/api/v4/projects/<id>/packages/pypi/simple`, Nexus or
  Artifactory `/repository/<name>/`), so another project or repository on
  the same host does not match; a root-path upstream such as
  `https://registry.npmjs.org/` matches any path on its origin.
  Foreign coordinates naming any other host are neither pinned from a Remote
  backing repository (or a Virtual's Remote member, including its proxy
  cache) nor filled through it: the publish is refused with
  `mcp_external_registry`, and a Remote MCP repository's sync stores the
  version `unresolvable`. Without this rule `@corp/tool` on
  `npm.internal.corp` would be replaced by a same-named (possibly squatted)
  public package the Remote proxies. The foreign registry itself is never
  contacted and never served.

  A pin of foreign coordinates records the warning
  `foreign_coordinates_replaced`. The served package carries what was
  replaced in `_meta["com.artifactkeeper/resolved"]` (`submittedIdentifier`,
  `submittedRegistryBaseUrl` for npm, PyPI, NuGet and Cargo, the backing
  repository and `warnings`), and the version's health lists the warning per
  package. A package that does not resolve is refused at publish as under
  `own-repos` (`mcp_package_not_found`, or `mcp_external_registry` for a
  `registryType` with no backing repository), or `202 resolving` and filled
  through a Remote backing repository when the coordinates allow it. A
  package is never served unpinned or ungated under either policy.

  An `open` publisher needs `read` on the backing repository, as under
  `own-repos` (see below): the package is looked up there.

  Before #5452 `open` stored and served `packages[]` verbatim, without pins
  or gates. Versions stored that way are `unresolvable` (hidden, `404
  mcp_unresolvable` for a holder) until they are pinned. A Remote MCP
  repository's sync re-resolves them on every pass (the versions not
  attempted longest first) and serves each once its packages pin. A hosted
  version is re-resolved in place by an administrator's
  [`PUT .../versions/{version}`](#put-versionsversion-admin-edit) of the same
  document, or republished as a new version.

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

The same rule holds for a publisher. A publish (or an admin edit that changes
`packages`) naming a package whose mapped backing repository the publisher's
account cannot read (instance administrator, public repository, or `read`
through a grant or role; the token's repository scope is not consulted, so a
token scoped to the MCP registry still publishes) is refused with
`422 mcp_package_not_found`, with a detail that names no repository, before
any lookup. A package that exists there and one that does not get the same
answer, so publishing is not a way to learn what a private repository holds;
a publisher who can read the repository gets the precise answers (the
repository key, the not-pulled hint, `202 resolving` for a fill). `POST
/validate` reports `outcome: unchecked` in that case instead. `mcpb` entries
are matched by `fileSha256`, not by name, and are not checked this way.

Server versions enter an MCP repository only through `POST .../publish`. The
generic artifact upload routes (`PUT`/`POST /api/v1/repositories/{key}/artifacts/...`
and `/api/v1/uploads`) refuse an MCP repository with `400`, except for a
peer replication under an instance administrator's token (an administrator
sending the replication header, which is how a peer link is set up). A
service account does not qualify, for this or any other format: the header is
client-set and nothing binds a credential to a registered peer, so "a service
account plus the header" let any CI account with `write` claim a
`name@version` in another team's namespace with an unvalidated, unpinned
document (#5368, #5455). A server.json replicated this way writes the
`MCP_SERVER_PUBLISHED` audit row, with the peer's principal as its actor.
Likewise a server version (or a bundle) leaves an MCP
repository only through `DELETE .../servers/{serverName}/versions/{version}`
(the soft delete below) and, after it, the administrator
[purge](#post-versionsversionpurge-admin-purge): the generic
`DELETE /api/v1/repositories/{key}/artifacts/...` refuses an MCP repository
with `400`, administrators included, after its access checks, with the same
replication exemption (an administrator's token with the header; a service
account is refused). The generic route knows nothing of namespaces, so it
would let a writer of one namespace delete another's server.json. Lifecycle
policies skip MCP repositories altogether (see
[Lifecycle policy assignments](lifecycle-policy-assignments.md#execution)).

To publish a server under either policy, publish (or pull through a Remote) its
package first, then publish the server.json. A publish answers `422` with one
`detail` line naming the entry and the fix:

| `error` | When |
| --- | --- |
| `mcp_external_registry` | The `registryType` has no backing repository, `registryBaseUrl` names anything other than this instance's backing repository (or is present on an `mcpb` entry), an OCI image's host is not the backing Remote's upstream, or (for a Local or Staging OCI backing repository) not this instance: name the image as `<ak-host>/<repo>/<image>:<tag>`. Under `open` only the first case and `registryBaseUrl` on an `mcpb` entry are refused; foreign coordinates are looked up in the backing repository. |
| `mcp_package_not_found` | The exact package version (npm, PyPI, NuGet, Cargo) or image tag/digest (OCI) is not in a hosted backing repository, or an `mcpb` entry's `fileSha256` matches no uploaded bundle. A package missing from a Remote backing repository is not refused: it is filled (`202`, see [Write path](#write-path-phase-2-and-3)). |
| `mcp_package_shadowed` | The backing repository is a Virtual whose download route would serve the package from another member than the one holding it: a Remote member that outranks it (or, for PyPI, any Remote member with an upstream). The detail names both members and the fixes. |
| `mcp_bundle_signature_required` | The repository sets `mcp_require_bundle_signature` and an `mcpb` entry's bundle (uploaded here or found through `mcp_package_repos.mcpb`) has no recorded signature from a trusted signer (see [MCPB bundles](#mcpb-bundles)). |
| `mcp_package_version_unpinned` | An npm, PyPI, NuGet or Cargo entry has no `version`. |
| `mcp_oci_floating_tag` | An OCI identifier is `:latest` or has no tag and no digest. |
| `mcp_oci_legacy_fields` | An OCI entry carries `version`, `registryBaseUrl` or `fileSha256` (the tag or digest belongs in `identifier`). |
| `mcp_oci_not_an_image` | The pinned manifest is not a runnable image or image index. |

What is served for a pinned package:

Names and versions are matched exactly as the backing format's download
route resolves the identifier and version a client requests, never wider, so
the pinned bytes are the bytes that route serves:

| Format | Name | Version |
| --- | --- | --- |
| npm | exact (case-sensitive), after percent-decoding (`%40acme%2Fx` is `@acme/x`, as the router decodes a request path) | exact |
| PyPI | PEP 503-normalised (`Acme_SDK` is `acme-sdk`) | exact |
| NuGet | case-insensitive | NuGet's normalised form in lowercase, as a V3 client requests it (`1.0` is requested as `1.0.0`), compared exactly with the stored version: a package stored as `1.0` or `1.0.0-Beta` is not served for `1.0.0` or `1.0.0-beta` and is not pinned. A version NuGet cannot normalise is not pinned. |
| Cargo | case-insensitive; `-` and `_` are different crates (a Local repository can hold both) | exact |

A Virtual backing repository pins the member its download route serves
the version from (#5456). npm, PyPI, NuGet and Cargo clients install from
`registryBaseUrl`, which is the Virtual, so the pin is the member the
Virtual's own member walk picks: nested Virtuals expanded in place, equal
priorities broken by repository key, and each format's guard applied as the
download route applies it:

- **npm**: the tarball route's shadowing guard and scope policy. A hosted
  member holding the exact version withholds the Remote members it outranks;
  isolate mode withholds every Remote member for a hosted name; a Remote
  member outside its scope policy never serves.
- **Cargo**: a hosted member holding the exact `name@version` anywhere in
  the Virtual withholds every Remote member.
- **NuGet**: strict priority, no guard.
- **PyPI**: per file. The simple index lists the files of every hosted
  member and a download matches the file name alone, so the pin covers
  every hosted file of the version (versions compared as PEP 440: `1.0` is
  `1.0.0`; files matched by name, whatever project they were uploaded
  under). A Remote member can serve other distributions of the version from
  its upstream (a platform wheel, even when a hosted member owns the name),
  so a PyPI package is not pinned through a Virtual that has a Remote
  member with an upstream.

A Remote member that the guard does not withhold, and that is walked before
the hosted member holding the version, serves it from its upstream whether
or not it has cached it. Such a publish is refused with
`422 mcp_package_shadowed`, naming both members and the fixes (rank the
hosted member above the Remote, enable isolate mode for npm, or map the
hosted repository directly).

The same check runs on every read. When the route would no longer serve the
pinned rows, the version is held as `mcp_unresolvable` (the holder's body
carries `gate: shadowed`). That happens when a hosted member walked earlier
now holds the version (published at any quarantine state), when a Remote
member now outranks it or is no longer withheld, or when the pinned member
leaves the Virtual. For PyPI it also happens when another file of the
version appears in any hosted member, when a pinned file is gone, or when a
Remote member with an upstream joins. The pin is never moved. The version serves again
once the route serves the pinned rows again; otherwise publish a new server
version to pin what it serves now. A pinned row whose bytes changed in place
(its checksum is no longer the one pinned) no longer counts as the pinned
row.

Quarantine and shadowing together, for a Virtual `[H, L]` whose pin is A in
`L`:

| State | MCP read | Download through the Virtual |
| --- | --- | --- |
| A quarantined, nothing in `H` | held (`mcp_backing_artifact_blocked`) | refused |
| B published in `H`, then A quarantined | held (`mcp_unresolvable`, `gate: shadowed`) | serves B to every client; the approved document is never served with it |
| B published in `H` and quarantined | held (`mcp_unresolvable`, `gate: shadowed`) | refused (a member refusing what it holds does not fall through to `L`) |

The model walks every member of the Virtual, whoever is asking. Two of the
route's skips only make it hold more than the route would: PyPI curation,
and an age gate reporting that a Remote's upstream does not host the
version. Per-caller member visibility is different and is a known caveat
(#5536): the download route drops the members the caller cannot read, so for
a caller who cannot read the pinned member, a lower-ranked hosted member (or,
for NuGet, any Remote member) can serve other bytes at the pinned coordinate
while the version is still served as approved. Until #5536 lands, give every
reader of an MCP repository read access to the members that hold its pinned
packages.

**Upgrading.** The check also applies to versions approved before it
existed, so some are held as soon as the upgraded server reads them: those
pinned through an npm or NuGet Virtual with a Remote member ranked above the
hosted member holding the package, and those pinned through a PyPI Virtual
with any Remote member that has an upstream. They answer `404` to readers
(`mcp_unresolvable`, `gate: shadowed` for the repository holder), drop out of
listings and `latest`, and their health turns critical. Re-rank the hosted
member above the Remote, enable isolate mode on an npm Virtual, or (PyPI)
remove the Remote member from the Virtual: the hold clears on the next read,
with no republish, because the pin is unchanged and the check is evaluated on
every read. Mapping the hosted repository directly (`mcp_package_repos`) only
affects versions published after the change, since an existing version's
`registryBaseUrl` names the Virtual: publish a new server version for that.
A proxy-cache entry ([Packages in a Remote backing
repository](#packages-in-a-remote-backing-repository)) matches by its exact,
case-sensitive cache path (`1.0.0-RC.1` is not `1.0.0-rc.1`); a NuGet entry by
its whole flat-container or V2 path (a file name alone is ambiguous:
`x.1`@`0.0.1` and `x`@`1.0.0.1` share `x.1.0.0.1.nupkg`).

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
allowed (the retention row keeps the manifest).

**A pinned digest stays pinned until the version is purged.** There is no
override flag. The pin holds while the server version's artifact row exists
outside the trash (`services::mcp_write::digest_pinned_by_mcp`). The MCP
[`DELETE .../versions/{version}`](#delete-versionsversion-soft-delete) only
sets the status to `deleted` and keeps the artifact, so it keeps the pin; the
generic artifact `DELETE` refuses MCP repositories (`400`, see above) and
lifecycle policies skip them. To free the digest, an instance administrator
soft-deletes the version and then purges it with
[`POST .../versions/{version}/purge`](#post-versionsversionpurge-admin-purge),
which trashes its server.json and bundles, keeps its tombstone and audits
`MCP_SERVER_PURGED` with the released digests. The digest is free once no
other live version pins it (the purge answer says, per digest, whether one
still does). Deleting the whole MCP repository that holds the version
(`DELETE /api/v1/repositories/{key}`) also frees its digests: once the delete
job has removed its rows, none of its versions pins anything, and their
tombstones go with it.

Switching a repository between `open` and `own-repos` does not change
versions already published: they keep the pins they were published with and
are gated by them. A version stored unpinned (under `open` before #5452) is
`unresolvable` under either policy until republished as a new version.

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
| pinned package gone, no longer what its Virtual serves (`gate: shadowed`), or the policy changed | omitted | skipped | `404` plain | `404` + `package` | `mcp_unresolvable` |
| a gate cannot be evaluated (database error) | omitted | `503` | `503` | `503` | `mcp_gate_unavailable` |
| `deprecated` | listed | eligible | `200` | `200` | |
| `deleted` | omitted unless `include_deleted=true` | skipped | `404` plain; `200` with `include_deleted=true` | same | |

A package with no pin (a version stored under `open` before #5452) is held
as `mcp_unresolvable` too. Changing the package policy does not change a
pinned version's decision: pins and gates are the same under both policies.

- **`404` plain** is byte for byte the answer for a name that does not exist:
  `{"detail":"Server not found","status":404,"title":"Not Found","type":"about:blank"}`
  with the same headers. A reader cannot tell a held version from a missing
  one by the answer. Timing is narrowed, not closed: a miss (unknown name or
  version) runs the same repository-level gate reads a held version's
  refusal runs (the server.json download gate, the serve policy, the deny
  list, Remote curation and the server age gate) before it answers, and the
  refusal audit is written off the response path. A held version still also
  reads its backing-package gates (about one lookup per pinned package), so
  a caller timing many requests may still tell a held version that pins
  packages from a missing one. Where that matters, keep such names out of
  repositories readers can query.
- A **repository holder** (an administrator, or a user with read on the
  repository through a grant, with a credential scoped to it; the same
  predicate as `GET /api/v1/quarantine/{id}`) gets an RFC 9457 body with
  `error`, `name`, `version`, `hold`, `instance` and, for a package hold, the
  `package` as submitted (`npm:@acme/db-tool@2.0.0`) and the `gate`. It never
  names the backing repository, an artifact id, a finding or a policy.
- A served version (an exact version or `latest`) is sent with
  `Cache-Control: no-store`, since it can carry a per-caller bundle ticket;
  a listing (`/servers`, `/versions`) with `Cache-Control: private, no-cache`
  and `Vary: Authorization, Cookie`, so no shared cache keeps a decision
  that can change on the next read.
- Every refusal is `application/problem+json` with `Cache-Control: no-store`,
  and is audited as `MCP_SERVER_DOWNLOAD_REFUSED`. That includes the refusals
  the shared middleware in front of the registry gives on `/mcp/` paths
  (`401`, `404`, `429`, `503`), which keep their `WWW-Authenticate` and
  `Retry-After` headers; read refusals carry the read routes' CORS headers.
- Listings evaluate the scan-policy gate afresh on every request (no cached
  decision), since a listing entry is the whole document. That holds for
  the `/v0.1` listings and the generic artifact routes. `/api/v1/search/*`
  is the one exception: it reuses a registry's reader decision for up to 5
  seconds (see the search entry under the artifact routes below).
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
and replicate like any other artifact, except that a peer link into an MCP
repository must carry an instance administrator's token (a service account's
replication write is refused, see [Package policy](#package-policy)).

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
- A templated transport URL (`remotes[].url`, `packages[].transport.url`)
  is checked against what it can expand to, not only its shape (#5529).
  Each `{variable}` is filled with every publisher value it carries
  (`value`, `default`, `placeholder`, each `choices` entry; a remote's
  variables come from its `variables`, a package's from every argument
  whose `valueHint` or `name` matches and every environment variable whose
  `name` matches, all of them), and every combination must be an absolute
  `http`/`https` URL, or the version is refused with `400
  mcp_invalid_server_json` at `remotes[<i>].url` (or
  `packages[<i>].transport.url`), naming the variable and the expansion.
  A variable that opens the URL (`{base}/sse`) picks the scheme, so it
  needs a `default` or `choices` whether it is declared or not; a variable
  with no value anywhere else stands in for client input and is accepted.
  More than 256 combinations are refused rather than checked. The same
  rule applies to upstream versions a Remote repository ingests: one with
  such a template is not admitted (counted as invalid at sync). User-info
  in an expanded URL is not refused (as for a literal URL). A version
  stored before this rule is not re-validated; the `remote_url_shape` lint
  flags it when the version is next linted.
- Publishes are quota-admitted like any upload and capped at 256 KiB, 16
  packages, 8 remotes and 64 entries per list.

## Write path (Phase 2 and 3)

Every route here is under `/mcp/<repo_key>/v0.1` and `/v0` (identical), with
both `{serverName}` spellings. Every refusal is `application/problem+json`
with `Cache-Control: no-store` and an `error` code. Writes need repository
`write` (an API token needs `write:artifacts`) on a Local or Staging MCP
repository (`405 mcp_read_only` on a Remote or a Virtual) and are refused
on a promotion-only repository (`409 mcp_promotion_only`).

### Packages in a Remote backing repository

A package pulled through a Remote is held in the Remote's proxy cache, not as
an artifact row. Publish finds it there (npm tarball
`<name>/-/<base>-<version>.tgz`, PyPI distribution file
`simple/<normalised project>/<file>`, NuGet
`v3/flatcontainer/<id>/<version>/<id>.<version>.nupkg` (lowercase, the
normalised version) or, from a V2 feed upstream,
`v2/package/<id>/<version>/package.nupkg`, Cargo
`api/v1/crates/<name>/<version>/download`) and pins its cache path and sha256; the gate
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
   download route, in process, as the publisher with the publishing
   credential's scope (its token scopes and repository allowlist, recorded as
   `resolution.requestedScope`; a job without a readable record runs with no
   scope and fails): the Remote's curation rules, age gate, scan-on-proxy and
   quarantine apply exactly as for a client pull. The publisher, through that
   credential, must be able to read the Remote. npm: the tarball
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
   (`mcp_external_registry`), a mapping that no longer fills through the
   Remote recorded at publish (`fillRepositoryId`: the mapping now names
   another repository, or a Virtual's first Remote member changed;
   `mcp_package_not_found`, publish again), the publishing account gone or
   disabled. A
   transient one (`429`, `5xx`, a fill not finished, response body
   included, within 300 s) is retried with backoff
   (30 s doubling, at most 1 h) up to 8 attempts (`mcp_resolve_exhausted`).
   A failed version stays stored and hidden (`404 mcp_unresolvable` for a
   holder) so its `resolution.error` can be read, but it does **not** take
   the version number: it was never served, so `POST /validate` reports no
   `mcp_version_exists` for it, a bundle may still be uploaded for it, and a
   republish of the same `name@version` replaces it (the failed row and its
   tombstone are removed in one transaction, then the publish runs as a new
   one). A version that resolved (or was published with every package
   pinned), or that was deleted, stays write-once (see
   [Tombstones](#tombstones)), and so does a version whose re-resolution
   after an admin edit (`PUT`) failed: it may have been served before the
   edit (its `resolution` carries `afterEdit: true`).

With a **Virtual** mapping the fill target is the Virtual's first Remote
member, so a package that is not (yet) in the hosted member is looked up
upstream. For an internal package that is a dependency-confusion path when
its scope or name is not reserved upstream: map the hosted repository
directly, or call `POST /validate` first and refuse to publish when it
reports `outcome: fill` for an internal package. Publish the package before
the server.json; if the fill fails, publish the package and then the same
server version again.

The state is in the version's metadata (`GET /api/v1/packages` rows and the
artifact metadata API carry it), under `resolution`:

```json
{"state": "resolving" | "resolved" | "failed",
 "pending": [{"index": 0, "registryType": "npm", "identifier": "@acme/x", "version": "1.0.0",
              "fillRepository": "npm-remote", "fillRepositoryId": "...", "fillFormat": "npm"}],
 "requestedAt": "...", "requestedBy": "<user id>", "baseUrl": "https://ak.example.com",
 "requestedScope": {"scopes": ["write:artifacts"] | null, "repositories": ["<repo id>"] | null,
                    "apiToken": true},
 "attempts": 1, "lastError": "...",
 "resolvedAt": "...", "failedAt": "...",
 "error": {"error": "mcp_package_not_found", "detail": "...", "index": 0}}
```

Note: `mcp-publisher publish` accepts only `200`/`201` and prints a `202` as an
error even though the publish was stored and is being resolved. Do not run it
again: while the version is resolving, and for ever once it resolved, a second
publish of the same `name@version` is `409 mcp_version_exists`. Follow the
version instead (a holder's exact read answers `404 mcp_resolving` until it
is served, then `200`; `resolution` in the version's metadata has the state),
and republish only after it **failed**, which releases the version number.
To get a plain `200`, pull the packages through the Remote first, call
`POST /validate` and publish when every package reports `outcome: pinned`, or
publish with `curl`.

### Tombstones

Every `name@version` a repository ever stored is recorded in
`mcp_version_tombstones` (written by a database trigger on every server.json
row insert, so publish, peer replication and promotion are all covered). A
publish (or a bundle upload) of a recorded `name@version` answers
`409 mcp_version_exists`, whether the version is live, soft-deleted, purged
by an administrator (in the trash), or purged from the trash. The ledger has no link to the artifact row, so a
trash purge does not touch it, and it binds every writer, not only publish: a
database trigger (migration 328) refuses any insert of a server.json row for
a recorded `name@version`, a promotion into an MCP repository is refused
with `409` before it would replace a trashed row, and a Remote sync never
ingests a purged version again, whatever upstream serves under it now. The ledger is removed only with the repository,
with one exception: a live version whose package resolution failed (never
served) is released by a republish of it (see
[Packages in a Remote backing repository](#packages-in-a-remote-backing-repository)).

### Server names that differ only in letter case

A Local or Staging registry refuses to publish a server name that differs
only in letter case from a name it already holds (#5434): with
`io.acme/tool` stored, a publish of `io.Acme/tool` (or `IO.ACME/TOOL`)
answers `409 mcp_name_case_conflict`, and the `detail` names the stored
spelling (`server name 'io.Acme/tool' differs only in letter case from
'io.acme/tool', which this registry already holds; ...`). Nothing is
stored. The rule stops a look-alike name being published next to an
existing server in the same registry.

- **Comparison:** the whole name, ignoring letter case, folded the way the
  deny lists, the namespace allowlist and a Virtual's
  [hosted-shadows-remote](#virtual-repositories) rule fold it. Server names
  are ASCII, so this is plain `A`-`Z` to `a`-`z`.
- **Per registry:** only names in the same registry count. The same name
  publishes into another registry.
- **Existing names are kept:** a stored name is never renamed, and a
  publish of the exact stored spelling is accepted as before, also when a
  case-only twin of it was stored before this rule: both spellings keep
  publishing new versions. Only a new spelling is refused.
- **Deleted names still count:** "already holds" means recorded in the
  [tombstone ledger](#tombstones), so a name whose versions were all
  soft-deleted or purged still blocks its case twins. The look-alike is the
  risk whether or not the original is still served, and the original's
  publisher can come back to it. The one exception is the ledger's own: a
  name whose only version failed package resolution (never served) and was
  released is no longer recorded.
- **Concurrency:** the check runs inside the publish transaction under an
  advisory lock on the lowercased name, so two concurrent publishes of
  `io.acme/tool` and `io.Acme/tool` into an empty registry cannot both
  succeed: one is stored, the other is `409`.
- **Scope:** hosted publish only. An admin edit cannot change a name, a
  Remote mirrors upstream names as they are, and a Virtual collapses twins
  across members as described under
  [Virtual repositories](#virtual-repositories). Promotion and peer
  replication copy names as they are (#5435). `POST /validate` reports the conflict
  to a repository holder (`reference: "mcp_name_case_conflict"`).

Upstream context: the official registry accepts case-only twins today and
treats that as a defect; modelcontextprotocol/registry#1805 proposes the
same rule (refuse new case-only aliases, keep existing names exactly).

**Twins stored before this rule.** The rule does not touch them. To list
them, run this once against the database (read-only). It reads the ledger,
so it also lists spellings whose versions were deleted; `live_names` are
the spellings that still have a version that is not in the trash:

```sql
WITH live AS (
    SELECT DISTINCT repository_id, name
    FROM artifacts
    WHERE is_deleted = false AND path LIKE 'servers/%/server.json'
)
SELECT r.key AS registry,
       r.repo_type,
       lower(t.name) AS folded_name,
       array_agg(DISTINCT t.name ORDER BY t.name) AS stored_names,
       array_agg(DISTINCT t.name ORDER BY t.name)
           FILTER (WHERE l.name IS NOT NULL) AS live_names
FROM mcp_version_tombstones t
JOIN repositories r ON r.id = t.repository_id AND r.format = 'mcp'
LEFT JOIN live l ON l.repository_id = t.repository_id AND l.name = t.name
GROUP BY r.key, r.repo_type, lower(t.name)
HAVING count(DISTINCT t.name) > 1
ORDER BY r.key, folded_name;
```

Each row is one registry and one folded name with every stored spelling.
Remote rows are mirrors of upstream; the rule applies to `local` and
`staging` rows. To retire a spelling, delete its versions (the name stays
recorded, so it cannot be republished under another case either).

### `POST /validate`

`POST /mcp/<repo_key>/v0/validate` and `/v0.1/validate`. Body: a server.json
(256 KiB cap, `413 mcp_too_large`; `Content-Type` is ignored). No credential
is needed on a public registry (`mcp-publisher validate` and its fallback
after a `422` send none): it is the one `POST` on this surface that the
anonymous-write rule does not apply to. A private registry answers an
anonymous caller `401` and an authenticated caller who cannot read it the
plain `404`, as every read does; any reader may call it (repository `write`
is not needed). Nothing is written, pinned, held, filled or audited. A
Virtual repository answers `501`, a Remote validates against its own
settings. Always `200` for a document (also for an invalid one), with
upstream's `ValidationResult` plus `packages` (always present, and always
`[]` for an invalid document, `valid: false`):

```json
{"valid": false,
 "issues": [{"type": "semantic", "path": "packages[0]",
             "message": "packages[0]: npm @acme/x@1.0.0 is not in repository 'npm-local'",
             "severity": "error", "reference": "mcp_package_not_found"}],
 "packages": []}
```

A valid document lists what a publish would do with each package:

```json
{"valid": true,
 "issues": [{"type": "semantic", "path": "packages[1]", "severity": "info",
             "message": "npm @acme/y is not in repository 'npm-remote' yet; ...",
             "reference": "mcp_package_fill"}],
 "packages": [{"index": 0, "registryType": "npm", "outcome": "pinned"},
              {"index": 1, "registryType": "npm", "outcome": "fill",
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
  otherwise learn of a held version) and, on a Local or Staging registry,
  whether the name is a case-only twin of a stored one
  (`mcp_name_case_conflict`);
- an authenticated caller who can read every mapped backing repository: also
  package resolution. Anyone else (every anonymous caller included) gets
  `outcome: "unchecked"` per package and an `info` issue
  `mcp_packages_unchecked`, so nothing about a backing repository's content
  is revealed.

Exact shapes: `issues[]` entries are `{type, path, message, severity,
reference}` (`type` `schema` for a document that does not parse or fails the
schema, `semantic` otherwise; `path` the JSON path of the field, `""` for
the document; `reference` an error code); `packages[]` has one entry per
`packages[]` element, `{index, registryType, outcome}` plus `fillRepository`
when `outcome` is `fill`. An unchecked document answers:

```json
{"valid": true,
 "issues": [{"type": "semantic", "path": "packages", "severity": "info",
             "message": "packages were not resolved: ...", "reference": "mcp_packages_unchecked"}],
 "packages": [{"index": 0, "registryType": "npm", "outcome": "unchecked"}]}
```

### `PUT .../versions/{version}` (admin edit)

Needs repository administration (instance administrator or the `admin`
action on the repository; `403 mcp_forbidden` otherwise). Body: the full
server.json, validated exactly as a publish (`400`/`403`/`422` as there); its
`name` and `version` must be the route's (`400`). An unknown or trashed
version is `404`. A version whose packages are still being resolved is
`409 mcp_version_resolving` (edit it once it is resolved or failed). The edit
is prepared from a read outside the server's write lock; if a status change,
soft delete or another edit commits in between, the edit is refused with
`409 mcp_edit_conflict` and nothing is overwritten (read again and retry).
The edit runs every publish gate, in the publish's order:
`mcp_server_deny` (`403 mcp_server_denied`), the namespace write gate
(`403 mcp_namespace_not_granted` under `mcp_require_namespace_grant`),
package resolution, and the lint (`422 mcp_lint_blocked`,
`422 mcp_oci_label_mismatch`). After the write the stored version is
re-linted (findings replace the version's `server_json` findings), its
declared capabilities are recorded again (a changed declaration is a new
`publisher_declared` snapshot and, when its tools differ, `tool_drift`),
the introspection jobs its settings allow are queued, and its
`/api/v1/packages` row is refreshed. The stored document is replaced (new content-addressed
bytes, new sha256, scanned again, and held by the repository's upload
quarantine exactly as a publish is); registry state is kept and `updatedAt`
bumped. When `packages[]` is unchanged the pins are kept as they are;
otherwise every package is resolved again (and may answer `202` with
`status: "resolving"` exactly as a publish). Identical bytes answer `200`
without a write, except for a version with a package no pin covers (stored
under `open` before #5452): a `PUT` of the same document resolves its
packages again in place, which is how such a version is made servable
without a new version number. Like any edit it rewrites the stored bytes, so
the repository's upload quarantine hold, if it has one, applies again; the
audit records `repinned: true`. Audited `MCP_SERVER_EDITED`
(`previous_sha256`, `sha256`, `packages_changed`, `resolving`).

### `DELETE .../versions/{version}` (soft delete)

Needs repository `write` and, under `mcp_require_namespace_grant`, a
namespace grant (`403 mcp_namespace_not_granted`), exactly as a status
change. Optional body `{"statusMessage": "..."}` (at most 500 characters,
linted as a status change's: `422 mcp_lint_blocked`). Sets status `deleted`
(`400` if it already is), recomputes `isLatest`, keeps the artifact, its bytes
and its tombstone; the version answers `404` unless `include_deleted=true`.
`200` with the served entry (`status: "deleted"`). Audited
`MCP_SERVER_DELETED` (`from`, `status_message`). This is the only delete
route for a server version: the generic artifact `DELETE` answers `400` on an
MCP repository (see [Package policy](#package-policy)). The version keeps its
pins until it is [purged](#post-versionsversionpurge-admin-purge).

### `POST .../versions/{version}/purge` (admin purge)

The second, deliberate step after a soft delete (#5368). Needs an instance
administrator (`403 mcp_forbidden` otherwise, repository administrators
included); the version must be `deleted`
(`409 mcp_version_not_deleted` otherwise, with its `status`); an unknown or
already purged version is `404`. No body. Under the server's write lock the
version's server.json artifact and every bundle under
`servers/<name>/<version>/bundles/` go to the trash, as the generic artifact
delete does (the usual `ARTIFACT_DELETED` audit rows, `artifact.deleted`
webhooks and delete sync tasks to push peers follow), and `isLatest` is
recomputed. The tombstone stays, so a publish or bundle upload of the version
still answers `409 mcp_version_exists`. A trashed server.json no longer pins
anything, so an OCI `DELETE /v2/<name>/manifests/sha256:<digest>` of a digest
only this version pinned is allowed again. `200` with
`{server, version, purged: true, trashed: [paths], releasedDigests: [{repository_id, image, digest, still_pinned}]}`.
Audited `MCP_SERVER_PURGED` (`released_digests`, `pins`, `trashed`). Restoring
the server.json from the trash brings its pins back (the version is
`unresolvable` if a pinned manifest is gone by then); a trash purge or
storage GC removes it for good, the tombstone outliving it.

### MCPB bundles

An MCPB bundle (`.mcpb`, a ZIP with `manifest.json`) is uploaded beside a
version **before** the version is published:

```bash
curl -X PUT -H "Authorization: Bearer $AK_TOKEN" --data-binary @echo.mcpb \
  https://ak.example.com/mcp/mcp-local/v0.1/servers/com.acme/echo/versions/1.0.0/bundles/echo.mcpb
```

- File name: `<name>.mcpb`, letters, digits, `.`, `_`, `-`, at most 200
  characters (`400 mcp_invalid_server_json`). The name must pass the
  namespace rules and the publish's name gates (`403`: reserved or not
  allowlisted namespace, `mcp_server_denied`, `mcp_namespace_not_granted`). A version already recorded (published, even
  deleted) is `409 mcp_version_exists`. Body at most 256 MiB
  (`413 mcp_bundle_too_large`); streamed to staging, not buffered.
- A bundle's ZIP may hold at most `MAX_INGEST_ARCHIVE_ENTRIES` entries
  (default 10,000, the shared ingest ceiling); more is
  `400 mcp_bundle_invalid` before the manifest is looked up, so no bundle
  row or version is written.
- AK stores a bundle verbatim, so it vets every entry for the client that
  later unpacks it, and refuses the bundle with `400 mcp_bundle_invalid`
  (nothing stored: no bundle row, no facts, no storage object) unless:
  - every entry name is valid UTF-8 (whether or not the ZIP's UTF-8 flag is
    set; `entry N name is not UTF-8`), and the central directory and local
    header of each entry carry the same name bytes (`central/local header
    name mismatch for entry N`); an Info-ZIP Unicode path extra field
    (`0x7075`) in either header naming any other path, whatever its CRC, is
    refused as well;
  - no name is empty, absolute (`/x`, `\x`), drive-qualified (`C:x`),
    contains a `..` segment, a backslash, a `:` (also an NTFS alternate
    data stream, `manifest.json::$DATA`) or a control character
    (`unsafe entry name: <name>`), the shared archive-path policy plus the
    backslash, colon and control-character rules;
  - every entry is a regular file or directory: a symlink
    (`symlink entry: <name>`) or a device, FIFO or socket
    (`special file entry: <name>`) is refused, judged by the Unix mode in
    the external attributes whatever host made the entry (7-Zip records a
    Windows symlink as a FAT-made entry with a Unix link mode);
  - no two entries unpack to the same path (empty and `.` segments ignored,
    Unicode NFC; `duplicate entry <name>`), and exactly one entry is the root
    manifest, compared case-insensitively (Unicode upper case, so
    `manifeſt.json` counts), so `MANIFEST.JSON` or
    `./manifest.json` beside `manifest.json` is
    `duplicate entry manifest.json`;
  - `manifest.json` repeats no member name in any object
    (`manifest.json: duplicate key ...`).

  Build bundles with `mcpb pack`: it follows symlinks, so links such as
  `node_modules/.bin/*` are stored as regular files rather than refused.
- AK reads `manifest.json` (at most 1 MiB, an object with string `name` and
  `version`; else `400 mcp_bundle_invalid`) and verifies the signature
  block the `mcpb sign` tool appends (`MCPB_SIG_V1`, PKCS#7 detached
  SignedData, `MCPB_SIG_END`; both the current layout, which grows the ZIP
  comment length, and the earlier one are accepted). A signature verifies
  when the SignedData's SHA-256 message digest matches the archive, its RSA
  (PKCS#1 v1.5, SHA-256) signature over the signed attributes verifies with
  the certificate the SignerInfo names (issuer and serial number) and that
  certificate was valid at the signing time. The SignedData is parsed
  strictly: unsigned attributes, a certificate set holding anything but
  certificates, a CRL set, or a signer naming no carried certificate make the
  signature invalid; a signature block carrying ZIP records (an end record or
  a central directory header) is refused (`400 mcp_bundle_invalid`); and the
  manifest is read only from the signed bytes, never from the file as a
  whole.
- Trust is an operator allowlist, not a trust store: `MCP_TRUSTED_BUNDLE_SIGNERS`
  (environment) lists the SHA-256 fingerprints of trusted signing
  certificates (hex, comma or whitespace separated; `:` and case ignored). A
  verified signature is `valid` only when its certificate's fingerprint is on
  the list; otherwise it is `self_signed` (the bytes are what the holder of
  that certificate signed, nothing says who that is). The result records
  `signer` (subject CN), `issuer`, `fingerprint` and `selfSigned` (subject
  equals issuer) either way.
- A present but invalid signature (tampered bytes, broken block, an
  algorithm other than RSA/SHA-256) is always refused:
  `422 mcp_bundle_signature_invalid`. With `mcp_require_bundle_signature` on,
  an unsigned bundle is refused with `422 mcp_bundle_unsigned` and a
  `self_signed` one with `422 mcp_bundle_signer_untrusted`. All are audited
  `MCP_BUNDLE_SIGNATURE_REJECTED` (`file`, `file_sha256`, `signature`,
  `require_signature`, `error`).
- `201` (or `200` for a re-upload of identical bytes; other bytes under the
  same file name are `409 mcp_bundle_exists`):
  ```json
  {"file": "echo.mcpb", "fileSha256": "<hex>", "size": 1234,
   "signature": {"state": "valid" | "self_signed" | "unsigned", "signer": "...", "issuer": "...",
                 "fingerprint": "...", "selfSigned": true, "signedAt": "..."},
   "manifest": {...}, "artifactId": "...",
   "downloadUrl": "https://ak.example.com/mcp/mcp-local/v0.1/servers/com.acme/echo/versions/1.0.0/bundles/echo.mcpb",
   "packageEntry": {"registryType": "mcpb", "identifier": "<downloadUrl>",
                    "fileSha256": "<hex>", "transport": {"type": "stdio"}}}
  ```
  The bundle is an artifact at `servers/<name>/<version>/bundles/<file>`
  (metadata format `mcpb`), scanned and quota-admitted like any upload.

A bundle belongs to a version that is not published yet, so there is no
server version to attach capabilities to at upload: the publish that pins
the bundle records its manifest's tools and prompts as a declared snapshot
(`origin: "mcpb:<fileSha256>"`) and lints them (`bundles[<k>].manifest.tools`
under the `server_json` source).

Publishing the version then resolves `mcpb` entries under `own-repos` by
`fileSha256`: a bundle uploaded for this version, else one in the
repository `mcp_package_repos.mcpb` maps (an MCP registry's bundles, or a
`.mcpb` file in a Generic repository). `registryBaseUrl` on an `mcpb` entry
is `422 mcp_external_registry`; no match is `422 mcp_package_not_found`.
The publishing repository's `mcp_require_bundle_signature` applies to every
bundle it pins, wherever the bundle lives: a bundle found through the
mapping must have a recorded `valid` signature (judged against the trusted
signer list as it is at publish), so a Generic repository's `.mcpb` (no
recorded signature) or another registry's `self_signed` bundle is
`422 mcp_bundle_signature_required`. A
document with no `mcpb` entry gets one `packages[]` entry per uploaded bundle
(the `packageEntry` above), so `fileSha256` never has to be computed by hand.
The entries are added before the "a server needs `packages`, `remotes` or a
`websiteUrl`" check, so a bundle-only document (no `packages`, `remotes` or
`websiteUrl`) is accepted once a bundle is uploaded for its version; without
one it is `400 mcp_invalid_server_json`.
The served `identifier` is the bundle's Artifact Keeper URL; on an exact read
by an authenticated caller it carries a single-use download ticket
(`?ticket=...`, five minutes), so a client handed the document can fetch the
bundle of a private registry without its own credential. Listings serve the
plain URL.

The version's metadata gains `bundles[]`, one per pinned bundle:

```json
{"index": 1, "artifactId": "...", "file": "echo.mcpb", "fileSha256": "<hex>", "size": 1234,
 "signature": {"state": "valid" | "self_signed" | "unsigned" | "invalid", "signer": "..."},
 "manifest": {"name": "...", "version": "...", "tools": [{"name": "...", "description": "..."}],
              "prompts": [...], "...": "..."}}
```

(A manifest over 64 KiB keeps only its identity, `tools` and `prompts`, with
`"truncated": true`. A bundle from a Generic repository has no upload facts:
`signature.state` is `unsigned`, `manifest` is `null`.)

`GET .../bundles/{file}` serves a bundle of a version that is served to
readers: `200 application/zip` with `X-Checksum-Sha256` and
`Cache-Control: private, no-store`, streamed. The owning version's reader
serve decision comes first, so a version that is unknown, not published,
`deleted`, held (quarantine, scan policy, curation, age gate, resolving) or
refused by a backing gate answers the plain unknown-name `404` for its
bundles, as does a bundle under quarantine or refused by scan policy, or an
unknown file (`503 mcp_gate_unavailable` when a gate cannot be evaluated). The gate of a pinned bundle also holds its server
version on every read, as any backing package does.

## Generic API fields for MCP registries

What the generic (non-`/mcp`) API says about MCP registries, for UIs that
show them next to other formats.

**`GET /api/v1/packages`** (and `/api/v1/packages/{id}`): one row per server
(the newest version published or ingested), `format: "mcp"`, `version` the
server version, `description` the server's. Its `metadata`:

```json
{"format": "mcp", "source": "hosted" | "upstream", "origin": "hosted" | "remote" | "mirror",
 "name": "com.acme/weather", "version": "1.2.0", "title": "Weather" | null,
 "description": "...", "status": "active" | "deprecated" | "deleted",
 "transports": ["stdio", "streamable-http"],
 "packagesCount": 1, "remotesCount": 1, "registryTypes": ["npm"]}
```

`transports` are the distinct `packages[].transport.type` and
`remotes[].type`, `registryTypes` the distinct `packages[].registryType`,
both sorted. It is written on publish and Remote ingest and refreshed on an
admin edit, a status change, a soft delete and a mirrored upstream status
change (when the row shows that version).

The rows follow the `/v0.1` serve decision for the caller. A holder (an
instance administrator, or `read` through a grant or role) sees the stored
row, with `metadata.servable: false` when readers are not served that version
now. Any other reader is shown the server's newest servable version instead
(its `version`, `description` and `metadata`, with `servable: true`), and no
row at all when no version of the server is served: `GET
/api/v1/packages/{id}` is then `404`, and the page's `total` leaves it out.
`GET /api/v1/packages/{id}/versions` lists only servable versions for such a
reader. A soft-deleted (`deleted`) version is never servable here: a server
whose only version is deleted has no row for such a reader, as on the
`/v0.1` listing. A gate that cannot be evaluated hides the row (fail closed).

Every generic surface below applies one visibility rule to a caller who does
not hold the registry, before it counts, pages, facets or serves anything: a
version is shown only when it is not soft-deleted and the `/v0.1` listing
gate serves it to readers now (not held through its server.json or a pinned
package, including `gate: shadowed`, not refused by scan policy, curation or
`mcp_server_deny`, not resolving or unresolvable).

**The generic artifact routes** apply the same decision to an MCP
registry's stored documents and bundles (`servers/<name>/<version>/server.json`,
`servers/<name>/<version>/bundles/<file>`). For a caller who does not hold the
repository, a version that readers are not served now (held through its
server.json or a pinned package, refused by scan policy or curation,
resolving, unresolvable, or soft-deleted) is treated as missing:

- `GET /api/v1/repositories/{key}/artifacts` leaves its rows out, using
  the listing decision of `/v0.1` (fresh listing refusals). The page is cut
  from the rows the caller is served, so `pagination.total`, `total_pages`,
  `has_more` and the cursor count only those rows, on every page and with or
  without `count=exact`. The response carries `total_is_exact`. To decide, a
  request reads at most 10,000 matching rows and 10,000 server versions per
  registry. Past that, the total covers only the first ones,
  `total_is_exact` is `false`, and versions beyond the version cap are
  hidden (fail closed).
- `GET /api/v1/repositories/{key}/artifacts/{path}`,
  `GET /api/v1/repositories/{key}/versions/{path}`,
  `GET /api/v1/repositories/{key}/download/{path}`, and
  `GET /api/v1/artifacts/{id}` (with `/metadata` and `/stats`) answer the
  route's plain `404`. For a Virtual registry, the member that holds the
  path first (by priority) decides.
- A served server.json on those routes is the document the registry serves,
  every pinned package at its Artifact Keeper coordinates (#5452): the
  download and `/api/v1/tree/content` return it, and the two metadata routes
  return it as `metadata.server`. Its bytes differ from the stored
  artifact's, so its size and sha256 are not the artifact's `size_bytes` and
  `checksum_sha256`: the download carries the served bytes' sha256 in
  `X-Checksum-Sha256`. These answers are `Cache-Control: no-store` (the
  coordinates follow the request's base URL). The download still passes the
  download gate (`409`/`403` for a holder of a quarantined or rejected
  server.json) and is counted.

- `/api/v1/search/*` excludes those artifacts in the database query:
  `quick` (OpenSearch hits are re-checked in PostgreSQL), `advanced` (items,
  `pagination.total` and the facets), `checksum`, `suggest`, `trending` and
  `recent`. The same listing decision is applied to every MCP registry in
  the caller's scope that it does not hold. Whether the caller holds a
  registry is decided on every request. The set of artifacts served to
  readers is the same for every caller who does not hold the registry, so
  each replica computes it at most once per registry every 5 seconds and
  shares it across requests (concurrent requests wait for one computation;
  a holder's decision is never cached). A hold, release or status change
  therefore reaches search within 5 seconds, while the `/v0.1` surface and
  the generic artifact routes apply it on the next request. Search shows a
  reader only the artifacts that set names: an artifact stored after the
  set was computed stays hidden until it is recomputed, and the set holds
  at most 10,000 server versions and 20,000 artifact rows (by path) per
  registry; rows past that are hidden (fail closed).
- `GET /api/v1/repositories/{key}/storage/tree` is rebuilt from the rows the
  caller is served, with the materialized rollup's formula: each path counts
  toward every ancestor prefix, `physical_bytes` and `blob_count` count each
  stored object once, and `computed_at` is the rollup's. A held version adds
  no node and no bytes. Proxy-cache entries of a Remote, and paths that
  belong to no server version, are not counted for such a caller.
  `GET /api/v1/repositories/{key}/storage` (`logical_bytes`,
  `physical_bytes`, `blob_count`) and `storage_used_bytes` of
  `GET /api/v1/repositories/{key}` are computed the same way for such a
  caller (on a Local, Staging or Remote registry; a Virtual's member figure
  is not recomputed).
- `GET /api/v1/tree` (the tree browser) leaves out a held version's nodes,
  using the same listing decision, and a folder that only held versions
  fill. `GET /api/v1/tree/content` answers a held version's path with the
  same `404` as a missing path, before reading storage. Its content is sent
  with `Cache-Control: no-store` for an MCP registry (`private` for any
  non-public repository of another format).
- The security scan listings leave out the scans of such a version, and
  their `total` counts only the rest:
  `GET /api/v1/repositories/{key}/security/scans`,
  `GET /api/v1/security/scans?repository_id=`, and, as for a missing
  artifact (an empty page), `GET /api/v1/security/artifacts/{id}/scans` and
  `GET /api/v1/security/scans?artifact_id=`. `GET /api/v1/security/scans/{id}`
  and `/findings` answer the missing scan's `404`. The listings compute
  the set of a registry's scans a reader is served on every request (not
  shared like search's), with the same cap of 20,000 artifact rows per
  registry; a scan past the cap is left out.
- `GET /api/v1/packages` decides its MCP rows over the whole filtered set
  before paging (at most 10,000 MCP rows per request; rows past that are
  hidden), so `pagination.total` and every page count only the rows the
  caller is shown. A row shown with the newest servable version in place of
  a held one carries that version's `size_bytes`, `created_at` and
  `updated_at`. A package's `download_count` sums only the versions the
  caller may list, so a held version's downloads are never counted for a
  reader. A version list whose lookup fails is empty, and the count is then
  `null`.
- `POST /api/v1/repositories/{key}/artifacts-missing` reports such a path as
  `not_found`, whatever the checksum, and an upload session's
  `skip_if_present` does not report it present.
- The by-id sub-resources answer such a version exactly as a missing
  artifact (the route's own `404` body, or its empty listing):
  `/api/v1/artifacts/{id}/labels`, `/api/v1/artifacts/{id}/package-analysis`,
  `/api/v1/quarantine/{id}` (a holder still reads it),
  `/api/v1/quality/health/artifacts/{id}`, `/api/v1/quality/checks?artifact_id=`,
  `/api/v1/quality/checks/{id}` (with `/issues`),
  `/api/v1/sbom?artifact_id=`, `/api/v1/sbom/by-artifact/{id}`,
  `/api/v1/sbom/cve/history/by-artifact/{id}` and
  `/api/v1/sbom/cve/history/{id}` for an artifact id.

A holder sees every stored version there, and still gets the server.json's
own quarantine refusals (`409`/`403`) on download.

**`GET /api/v1/formats`** (and `/api/v1/formats/{key}`): every format handler
carries `repository_types`, the repository types it can be created as, in
the order `local`, `staging`, `remote`, `virtual`; `["local", "staging",
"remote", "virtual"]` for `mcp` (Agent Plugins: `["local", "staging"]`). The
field is additive; older clients ignore it.

**Instance administrator vs repository administrator.** `GET
/api/v1/auth/me` answers `is_admin` (instance administrator). The repository
responses (`POST /api/v1/repositories`, `GET` and `PATCH
/api/v1/repositories/{key}`) of an MCP registry carry
`mcp_caller_can_lock`: `true` only when the caller is an instance
administrator, the only role that may set or clear `*_locked` settings or
change a locked setting (a repository administrator gets `403`). It is
omitted for other formats and on the repository list. A UI shows the lock
switches only when `mcp_caller_can_lock` is `true` and shows a locked
setting read-only otherwise. The same responses carry
`mcp_caller_is_repo_admin`: `true` when the caller administers the
repository (the repository `admin` action, through a grant or a role such
as `repository-owner`, or an instance administrator). It is the check the
routes themselves apply to repository administration (admin edit of a
version, catalog decisions, pins and bulk decisions, a sync trigger, an
introspection request), so a UI can show those controls exactly when they
will be accepted; a caller without it gets `403` (`mcp_forbidden` on the
`/v0.1` surface). Soft delete (`DELETE .../versions/{version}`) and status
changes need only repository `write` (plus the namespace gate), so a UI must
not hide them behind this flag. Also omitted for other formats and on the
list.

## Repository settings (Phase 2 and 3)

Set on `POST /api/v1/repositories` and `PATCH /api/v1/repositories/{key}`
and echoed (effective value, defaults filled in) on every repository
response. Each is a `repository_config` key of the same name. `null`/absent on
a request leaves the stored value unchanged. A setting that does not apply to
the repository type is refused with `400`; a response omits it.

The echo is for administrators: `POST`, `GET` and `PATCH
/api/v1/repositories/{key}` carry these settings, and `mcp_package_repos` and
`mcp_namespace_allow`, only when the caller administers the repository
(`mcp_caller_is_repo_admin` is `true`). Any other caller, an anonymous reader
of a public registry or a grantee without the repository `admin` action, gets
them omitted (#5398): the backing repository keys can name repositories the
caller cannot see, and the globs are policy a reader does not need. The
package policy (`mcp_package_policy`) is echoed to every reader. The
repository list carries none of them.

| Field | Types | Values (default first) | Meaning |
| --- | --- | --- | --- |
| `mcp_server_deny` | all | glob list (`[]`) | Full server names refused on publish, edit and bundle upload, and hidden on serve. `*` matches any run of characters including `/`; matching is ASCII case-insensitive. Deny always wins, even over an approval. An entry with neither `/` nor `*` (a bare namespace) is refused with `422` (it would match no name; write `com.acme/*`); other bad syntax is `400`. |
| `mcp_remote_posture` | Remote | `approval_required` \| `allow_with_gates` | `approval_required` serves only approved names; `allow_with_gates` serves every name whose version passes the gates (lint, backing scan, age gate and typosquat still apply; flags route to review). |
| `mcp_remote_posture_locked` | Remote | `false` \| `true` | Instance-administrator lock on `mcp_remote_posture`. |
| `mcp_auto_approve_namespaces` | Remote | glob list (`[]`) | Globs over the **full** server name approved on sync: `io.github.modelcontextprotocol/*` (one namespace), `com.acme.*/*` (every sub-namespace of `com.acme`, not `com.acme` itself), `com.acme/weather` (one server). Same matching as `mcp_server_deny`; a bare namespace (`com.acme`) is refused with `422`. A denied, blocked or lookalike name is never auto-approved. |
| `mcp_oci_floating_tag_policy` | Remote | `pin` \| `hide` | Upstream OCI entries tagged `latest` or untagged: pin the digest at sync and warn, or hide the version. |
| `mcp_remote_mode` | Remote | `allowlist` \| `mirror` | `allowlist` ingests approved names only; `mirror` ingests every upstream name hourly (serving is still curated). |
| `mcp_probe_remotes` | Local, Staging, Remote | `off` \| `hosted_only` \| `all` | Opt-in remote `tools/list` probe by the isolated introspector worker. |
| `mcp_probe_remotes_locked` | Local, Staging, Remote | `false` \| `true` | Instance-administrator lock on `mcp_probe_remotes`. |
| `mcp_require_oci_label` | all | `false` \| `true` | Refuse an OCI package whose image lacks a matching `io.modelcontextprotocol.server.name` label (otherwise a lint warning). |
| `mcp_require_namespace_grant` | Local, Staging, Remote | `false` \| `true` | Publishing needs a namespace-conditioned grant, not just repository write. |
| `mcp_sandbox_introspection` | Local, Staging, Remote | `off` \| `on` | Queue sandboxed stdio introspection runs for the isolated worker. |
| `mcp_remote_sync_paused` | Remote | `false` \| `true` | The scheduled sync skips this repository (#5402). Set it on create to finish configuring a Remote before its first sync, then clear it with `PATCH`. A manual `POST .../mcp/sync` still runs a pass. Scheduled upstream jobs paused instance-wide (`upstream_jobs_paused`) stop every Remote's sync without it. |
| `mcp_require_bundle_signature` | Local, Staging, Remote | `false` \| `true` | Refuse MCPB bundles that are not signed by a trusted signer (`MCP_TRUSTED_BUNDLE_SIGNERS`): on upload (unsigned or `self_signed`) and on publish, for every pinned bundle including those found through `mcp_package_repos.mcpb` (see [MCPB bundles](#mcpb-bundles)). A present but invalid signature is always refused. |

Locks: only an instance administrator may set or clear a `*_locked` field
(`403` otherwise), and while a lock is set only an instance administrator may
change the locked setting (`403`). The posture lock also covers
`mcp_auto_approve_namespaces` (a standing approval list is posture by another
name) and bulk approvals whose pattern spans namespaces nobody named (a `*`
in the namespace part: `*`, `*/x`, `com.*`, `*.acme/*`; naming the namespace,
`com.acme/*`, stays allowed). Bulk blocks only tighten and are not
restricted. The probe lock also covers
`mcp_sandbox_introspection`.

## Remote repositories

A Remote `mcp` repository is **an allowlist that happens to be populated
from an upstream registry, not a mirror of it.** Its `upstream_url` is a
registry origin, without `/v0.1`: the official registry
(`https://registry.modelcontextprotocol.io`), another Artifact Keeper
(`https://ak.example.com/mcp/<key>`), or any server of the v0.1 API. Nothing
from upstream is served until it is approved (`mcp_remote_posture:
approval_required`, the default), and `/v0.1` on a Remote serves only what
the sync stored, through the same read path and gates as a hosted
repository. Writes (`publish`, `status`) answer `405 mcp_read_only`.

```json
{
  "key": "mcp-official", "format": "mcp", "repo_type": "remote",
  "upstream_url": "https://registry.modelcontextprotocol.io",
  "mcp_package_repos": {"npm": "npm-remote", "pypi": "pypi-remote", "oci": "ghcr-remote"},
  "mcp_auto_approve_namespaces": ["io.github.modelcontextprotocol/*"],
  "mcp_server_deny": ["*.evil/*"]
}
```

Pair it with the clients' own allowlists so developers cannot route around
it: Copilot's "Registry only" policy, Claude Code `allowedMcpServers` with
`allowManagedMcpServersOnly`, Cursor's team allowlist.

**Create the Remote in its final state.** The settings that govern the
first sync's upstream requests go in the create body, so the repository is
born with them (#5402). Nothing has to be paused around the create.

- `upstream_mode` (`online` or `cache_only`) and `egress_proxy` (the
  `PUT .../egress-proxy` body: `mode`, `proxy_url`, `no_proxy`) are taken on
  create for every Remote. They are validated before the repository exists
  and stored before anything else, so a Remote created `cache_only` never
  contacts its upstream, and the first request of one created with an
  explicit proxy goes through the proxy.
- The `mcp_*` settings above (`mcp_remote_mode`, `mcp_auto_approve_namespaces`,
  `mcp_server_deny`, ...) are taken on create too. With
  `mcp_remote_sync_paused: true` the scheduled sync leaves the Remote alone
  until the flag is cleared, so the routes that only exist once the
  repository does (`PUT .../cache-ttl`, `PUT .../upstream-auth`, ...) can be
  set first.
- A Remote that was never synced is not due until it is a minute old, so a
  scheduler tick that lands during the create cannot start a pass before
  its create-time settings are stored.
- While scheduled upstream jobs are paused instance-wide, no Remote syncs
  on its own; the switch is no longer needed to make a create safe.

```json
{
  "key": "mcp-official", "format": "mcp", "repo_type": "remote",
  "upstream_url": "https://registry.modelcontextprotocol.io",
  "egress_proxy": {"mode": "explicit", "proxy_url": "http://egress-ledger:3128"},
  "mcp_remote_sync_paused": true
}
```

A cache-only Remote's sync runs on schedule but makes no upstream request:
each page goes through the shared upstream gate, which refuses a miss
before any request is built (`lastError` names the refusal) and serves a
page that is still in the proxy cache.

### Sync

Every hour (`MCP_REMOTE_SYNC_INTERVAL_SECS`, minimum 60) and on demand, the
repository pages `GET {upstream}/v0.1/servers?limit=100&updated_since=<watermark>&cursor=...`
(`include_deleted=true` in place of `updated_since` on the first pass,
before there is a watermark) through the Remote's outbound path (SSRF guard, the repository's upstream
credentials, 8 MiB per page). One replica runs the scheduled pass (a
scheduler lease) and each repository's run holds a cluster-wide lock, so a
manual trigger never overlaps a scheduled one. The watermark is the newest
upstream `updatedAt` a completed pass saw (upstream's clock), held at least
ten minutes behind the run's start so an entry updated mid-pass is read
again; a pass that stops early (200 pages, an upstream error after the first
page) resumes at its cursor next time. Every pass therefore sees deleted
versions: `updated_since` implies `include_deleted` upstream, and the first
pass asks for them explicitly, so a version already `deleted` upstream when
the Remote is first synced is recorded (and, once ingested, stored with
status `deleted`, served only to `include_deleted=true` reads) like one
deleted later. Each run:

1. Records every upstream server name in the catalog (one `curation_packages`
   row, `format: mcp`, `version: "*"`) with a cached summary (title,
   description, versions, latest version, upstream status and time, and the
   risk inputs of the latest non-deleted document: transports, package
   registry types, secret count, package and remote counts), so browsing
   never calls upstream. A new name starts `pending`; a name whose
   full name matches a glob of `mcp_auto_approve_namespaces` starts
   `approved` (a `pending` name that a glob added later matches is approved
   on the next sync); a **lookalike** of a known name (approved, pending, in
   review, or ingested; another namespace one edit away, or equal after
   folding `rn`/`m`, `vv`/`w`, `0`/`o`, `1`/`i`/`l`, `5`/`s` and separators,
   with the same or a lookalike server slug) starts in `review` with
   `flags.typosquat.similarTo`, whatever the auto-approve list says. Names
   seen earlier in the same run count, and a still-`pending` name it looks
   like is moved to `review` and flagged as well, so which of a squat and its
   target the sync met first does not decide which one is caught.
2. **Ingests** the versions of every eligible name as artifacts of the Remote
   (path `servers/<name>/<version>/server.json`, the hosted metadata shape):
   approved names, pending names under `allow_with_gates`, approved
   `name@version` pins, and in `mcp_remote_mode: mirror` every name that is
   not denied or blocked. Upstream documents pass the hosted validation
   (except that OCI `latest`/tagless images are admitted, below, and the
   reserved `io.modelcontextprotocol` namespace is the upstream's own);
   one that fails is counted `invalid` and skipped.
3. **Pins every package at sync**, through the Remote's own
   `mcp_package_repos`, exactly as a publish does. An upstream
   `registryBaseUrl` naming the host of the backing Remote's upstream is the
   registry that Remote proxies and is accepted. An OCI `latest` or tagless
   image is resolved through the backing repository's `latest` tag and
   pinned to its digest with the pin warning `oci_floating_tag`
   (`mcp_oci_floating_tag_policy: pin`, the default), or left unpinned
   (`hide`). A package that cannot be pinned (no backing repository, not
   pulled through it yet, policy `hide`) is recorded in
   `metadata.ingest.unresolved` and the version is `unresolvable`: stored,
   never served. Each run retries the resolution of up to 100 such versions.
   A package pulled through a Remote backing repository (or a Virtual's
   first Remote member) is found in that Remote's proxy cache, as on a
   publish ([Packages in a Remote backing
   repository](#packages-in-a-remote-backing-repository)); the sync never
   fills one itself, so pull it through the Remote and the next sync pins
   and serves the version.
4. **Never overwrites** an ingested `name@version`. Changed upstream bytes
   keep the stored document, re-queue that version (a `name@version` row in
   `review` with `contentDrift: {storedSha256, upstreamSha256, detectedAt}`),
   audit `MCP_SERVER_CONTENT_DRIFT` and, when the version was being served,
   `MCP_SERVER_REOPENED`. The version is held (`hold: content_drift`) until
   an administrator approves it again, which serves the **stored** document.
   Upstream status changes (`active`, `deprecated`, `deleted`) are mirrored
   onto the stored version; they are not content.
5. Records the first sighting of every new version for the age gate, scans
   the stored document like an upload, indexes it for search (the Packages
   page and OpenSearch), and audits `MCP_MIRROR_SYNCED` with the run's
   counts.

Ingesting never makes a version visible; the read-time decision below does.

### What a Remote serves

Every row a Remote stores goes through `decide_mcp_serve` with the hold of
its curation state, evaluated on every read (strongest first):

| State | Hold (`hold`, `error` for a repository holder) |
| --- | --- |
| name matches `mcp_server_deny` (any repository type) | `curation`, `mcp_rejected` |
| name `blocked` | `curation`, `mcp_rejected` |
| version row `approved` (a pin, or re-approved drift) | none: served |
| version row `blocked` | `curation`, `mcp_rejected` |
| version row with `contentDrift`, not re-approved | `content_drift`, `mcp_pending_review` |
| version row `pending`/`review` | `curation`, `mcp_pending_review` |
| name `approved` | none |
| name `pending` under `allow_with_gates` | none |
| name `pending`/`review` (or no row) under `approval_required`; `review` under either | `curation`, `mcp_pending_review` |
| server version younger than the Remote's age gate | `age_gate`, `mcp_age_gate_blocked` |
| any of the above cannot be read (database error) | `503 mcp_gate_unavailable`, audited `MCP_GATE_UNAVAILABLE` |

Then every backing-package gate applies as for a hosted version. The reason
body (`review_id` is the curation row's id for a curation or drift hold, the
age-gate review's id for the age gate) goes only to repository holders;
everyone else gets the unknown-name `404`. Failing closed is a deliberate
divergence from the npm curation seam, which fails open: this document
decides what an agent executes.

`allow_with_gates` (`mcp_remote_posture`) serves every name that is not
denied, blocked or flagged, with every gate on. The posture can be locked by
an instance administrator (`mcp_remote_posture_locked`).

**Age gate.** Enable the Remote's own age gate (`PUT
/api/v1/repositories/{key}/age-gate`, mode `first_seen`, the only mode for
MCP: the upstream `publishedAt` is the upstream's claim) to hold every
server version until it has been known to this instance for `min_age_days`.
An exact read records a pending review in the repository's age-gate queue;
approving it releases the version.

The served `_meta["com.artifactkeeper.registry/source"]` of an ingested
version carries `"origin": "remote"` (ingested in `mcp_remote_mode:
allowlist`) or `"mirror"` (ingested in `mirror` mode), `"kind": "upstream"`
and `"upstreamUrl": "<upstream_url>"` (see [What a client sees](#what-a-client-sees)). The upstream URL
is stored, served and audited (`MCP_MIRROR_SYNCED.upstream`) without its
userinfo: credentials embedded in a Remote's `upstream_url` never appear.

**Deny list on hosted repositories.** `mcp_server_deny` also refuses a
publish to a Local or Staging repository with `403`
`{"error": "mcp_server_denied"}`, and hides an already published version
(for example one published before the glob was added) on every read.

### Management API

Base: `/api/v1/repositories/{key}/mcp`, Remote MCP repositories only (any
other key answers `404`). Reads need an authenticated caller who can read
the repository (token scope `read:repositories`); decisions need the
repository `admin` action (token scope `write:repositories`). Errors use the
API's usual `{"code", "message"}` body. A write (sync, seed, pin, a decision
or a bulk decision) refused to a caller who cannot read the repository
answers `404 Repository not found`, the same status and body as a key that
names no repository, so a non-reader cannot learn which private Remote keys
exist (#5458); a caller who can read it but is not its administrator gets
`403`.

| Method and path | Who | Request | Response |
| --- | --- | --- | --- |
| `GET /catalog` | read | query `search` (substring of the name), `status` (`pending`\|`approved`\|`blocked`\|`review`), `namespace` (exact), `requested` (`true`: someone asked for it), `queue` (`true`: name or one of its versions awaits a decision), `cursor`, `limit` (default 50, max 200) | `200 CatalogPage`; `400` bad query |
| `GET /catalog/servers/{serverName}` | read | name URL-encoded or with a literal slash | `200 CatalogItem`; `404` |
| `POST /catalog/{id}/approve` | admin | `{"reason": "..."}` (optional body) | `200 DecisionResult` |
| `POST /catalog/{id}/block` | admin | same | `200 DecisionResult` |
| `POST /catalog/{id}/reopen` | admin | same; back to `review` | `200 DecisionResult` |
| `POST /catalog/pins` | admin | `{"name": "io.github.acme/x", "version": "1.2.0", "reason": "..."}` | `200 DecisionResult`; `404` name not in the catalog; `400` bad version |
| `POST /catalog/bulk-approve` | admin | `{"pattern": "io.github.acme/*", "includeReview": false, "reason": "...", "dryRun": false}` | `200 BulkResult`; `400` bad pattern; `422` a bare namespace (`com.acme`: write `com.acme/*`); `403` a namespace-spanning pattern under `mcp_remote_posture_locked` (instance administrators excepted, dry runs included) |
| `POST /catalog/bulk-block` | admin | `{"pattern": "io.github.acme/*", "reason": "...", "dryRun": false}` | `200 BulkResult`; `400` bad pattern; `422` a bare namespace |
| `POST /catalog/bulk-decide` | admin | `{"ids": ["<uuid>", ...], "action": "approve" \| "block", "reason": "..."}` (1 to 500 ids, names or `name@version` rows) | `200 BulkDecideResult`; `400` no ids or more than 500; `422` another `action` |
| `POST /catalog/{id}/request-approval` | read | `{"note": "..."}` (optional, 500 characters kept) | `200 CatalogItem` |
| `GET /sync` | read | | `200 SyncStatus` |
| `POST /seed` | admin, or an API token with `trigger:sync` and access to the repository | `{"servers": [{"name": "io.github.acme/x", "version": "1.2.0"}, ...], "reason": "..."}` (1 to 500, concrete versions) | `202 {"jobId", "repository", "status": "pending", "total", "statusUrl"}`; `400` bad list; `409` scheduled upstream jobs paused, or the Remote is cache-only; `502` no outbound fetch path. See [Seeding named servers](#seeding-named-servers) |
| `GET /seed/{jobId}` | read | | `200 SeedJob` |
| `POST /sync` | admin, or an API token with `trigger:sync` and access to the repository | | `202 {"repository": "<key>", "status": "running", "statusUrl": "/api/v1/repositories/<key>/mcp/sync"}`: the pass runs in the background; `409` a pass is already running, or scheduled upstream jobs are paused; `502` this instance has no outbound fetch path |

`GET /api/v1/mcp/pending-summary` (authenticated; token scope
`read:repositories`) counts the approval queue across every Remote MCP
repository the caller can read (the `GET /catalog` check, so an instance
administrator sees all of them): `pending` names, flagged `review` names,
and `drifted` `name@version` rows awaiting a decision (`pending`/`review`,
a content drift). `401` without a caller.

```json
{"pending": 3, "review": 1, "drifted": 1, "total": 5,
 "repositories": [{"key": "mcp-official", "pending": 3, "review": 1, "drifted": 1}]}
```

`repositories` lists, by key, only the repositories with something in the
queue.

`{id}` is the `curation_packages` id of a name row (or of a
`name@version` row for approve/block/reopen). The generic curation routes
work on the same rows: `POST /api/v1/curation/packages/{id}/approve|block`
and `POST /api/v1/curation/packages/bulk-approve|bulk-block` (instance
administrators) audit and ingest MCP rows the same way, and
`POST /api/v1/curation/repos/{key}/sync` starts the same background pass for
a Remote MCP repository (#5422): `202 {"repository", "triggered": true,
"succeeded": true, "status_url"}`, where `succeeded` means only that the pass
started (poll `status_url`, the `GET /sync` below, for its outcome), and the
same `409` as `POST /sync` when a pass already runs or scheduled upstream
jobs are paused. For a staging repository the route is unchanged: `200` once
the pass ran, `succeeded` its result.

**Manual sync.** `POST /sync` starts a pass in the background and answers
`202` at once, so a pass longer than the request timeout
(`GLOBAL_REQUEST_TIMEOUT_SECS`, 120 s by default) is not cut off: a first
pass of the official registry often is. The pass is the scheduled one (the
same code, the same per-repository cluster-wide lock, the same stored
state), on a task of its own, so it continues after the request ends. Poll
`GET /sync`: `running` is `true` while a pass of the repository (manual or
scheduled, on any replica) holds the lock; once it is `false`,
`lastFinishedAt`, `lastError` and `lastSummary` describe the pass that ended
last. A failure the old trigger answered `502` (the first upstream page
unreadable) is now recorded there: `lastError` is set and
`lastSummary.pages` is `0`. Only one pass runs at a time: a trigger while one runs answers `409`
and starts nothing. A trigger while scheduled upstream jobs are paused
(`upstream_jobs_paused`, `UPSTREAM_JOBS_PAUSED`) also answers `409`, without
contacting the upstream, as the scheduled pass skips its tick. A cache-only
Remote's pass goes through the same upstream gate as the scheduled one, so
it reads only cached pages and makes no upstream request.

```bash
curl -s -X POST "$AK/api/v1/repositories/mcp-official/mcp/sync" -H "Authorization: Bearer $TOKEN"
# 202 {"repository":"mcp-official","status":"running","statusUrl":"/api/v1/repositories/mcp-official/mcp/sync"}
until curl -s "$AK/api/v1/repositories/mcp-official/mcp/sync" -H "Authorization: Bearer $TOKEN" \
  | jq -e '.running == false' >/dev/null; do sleep 10; done
curl -s "$AK/api/v1/repositories/mcp-official/mcp/sync" -H "Authorization: Bearer $TOKEN" \
  | jq '{lastFinishedAt, lastError, complete: .lastSummary.complete}'
```

A pass stops after 200 pages; the next one resumes at its cursor, so a
large registry needs several passes (`lastSummary.complete` is `false`
until one reaches the last page).

### Seeding named servers

`POST /seed` pins exact server versions without waiting for the sync to
reach their names (#5408). A first sync pages the upstream in name order, so
on the official registry (over 2,000 pages) a name late in the alphabet is
not in the catalog for hours, and `POST /catalog/pins` answers `404` for it
until then. "Seed exactly these servers" is also the air-gap workflow: see
[Air-gapped deployment](air-gapped.md).

```bash
curl -s -X POST "$AK/api/v1/repositories/mcp-official/mcp/seed" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"servers": [{"name": "io.github.daedalus/mcp-sqlite3", "version": "1.2.0"}], "reason": "lab seed"}'
# 202 {"jobId":"...","repository":"mcp-official","status":"pending","total":1,"statusUrl":"/api/v1/repositories/mcp-official/mcp/seed/<jobId>"}
```

The job runs in the background, one item after the other, and takes three steps per item:

1. A version that is already pinned and ingested is `already_pinned`. The
   upstream is not contacted.
2. The name's version list, `GET {upstream}/v0.1/servers/{name}/versions`,
   is fetched through the sync's outbound path: the SSRF guard, the
   upstream credentials, the egress proxy, the upstream gate and its
   cache-only refusal, and `UPSTREAM_FETCHED`. The list is recorded in the
   catalog exactly as a sync page carrying those versions would record it:
   the name row with its summary, `mcp_server_deny`, the lookalike check and
   `mcp_auto_approve_namespaces`. A later sync finds the name already known.
3. The version is pinned as `POST /catalog/pins` pins it: approved with the
   request's `reason`, audited `MCP_SERVER_APPROVED`, and ingested with its
   packages pinned through the Remote's `mcp_package_repos`.

Poll `statusUrl` until `status` is `completed`. Each item ends `pinned`,
`already_pinned`, `refused` or `failed`. `refused` covers a denied name, a
name that is blocked or flagged for review (lookalike), and a version the
upstream does not list (`reason` names the listed versions). In each case
nothing is approved. `failed` covers an upstream or ingest error. The whole
request is refused with `409`, before a job exists, while scheduled
upstream jobs are paused (`upstream_jobs_paused`) or the Remote is
cache-only, because a seed contacts the upstream. A job interrupted by a
restart stays `running`. Submit the list again: items already done answer
`already_pinned`.

```text
SeedJob  { jobId, repository, status: "pending" | "running" | "completed" | "failed",
           error, createdAt, startedAt, finishedAt,
           items: [{ name, version, state, reason, catalogId }] }
```

Approving a name (or pinning a version) ingests it right away; when upstream
cannot be reached the approval stands, `ingestError` says why, and the next
sync ingests it. When the ingested version cannot be stored, the approval
still stands (the next sync retries) but the request answers the storage
error instead of `200`: `409 CONFLICT` when the storage key is held by
another repository (only possible with `STORAGE_KEY_SCHEME=flat` on cloud
storage), `507 QUOTA_EXCEEDED` for a quota, `500 STORAGE_ERROR` otherwise. A
bulk approval ingests in the background.

Bulk decisions by pattern take a glob over the **full** server name, the
same rule as `mcp_auto_approve_namespaces` and `mcp_server_deny` (`*`
matches any run of characters, `/` included; ASCII case-insensitive):
`io.github.acme/*` (one namespace), `com.acme.*/*` (its sub-namespaces),
`io.github.acme/weather` (one server). A pattern with neither `/` nor `*`
(a bare namespace) matches no name and is refused with `422` and the
spelling that would (`use com.acme/* for every server in the namespace`).
A bulk approval takes `pending` names that match, skips denied names
(`skippedDenied`) and, unless `includeReview`, flagged ones
(`skippedReview`). A bulk block takes every matching name that is not
blocked yet (`pending`, `review` or `approved`, denied ones included); it
only tightens, so the posture lock does not restrict it. At most 5000 names
per call. With `dryRun: true` nothing is written or audited: the answer
counts and lists (every name, up to 5000) what the call would decide, with
the same refusals as the real call. A name that another decision moved out
of the state it was selected in keeps that decision.

A bulk decision by id (`bulk-decide`) approves or blocks the listed rows,
names or `name@version` pins, as one decision per row (each audited, each
approval ingested in the background). A row already in the target status is
left alone (`unchanged`), an approval skips a row whose name is denied
(`skippedDenied`), and an id that is not a row of this repository's catalog
is reported in `notFound`. Each id is named explicitly, so the posture lock
restricts it no more than a single decision.

What a caller sees of an item depends on who it is. A repository
administrator sees everything. A caller who holds the repository (`read`
through a grant or role, the reason gate of the `/v0.1` surface) sees the
decision detail but not other users: `evaluatedBy` is `null` and
`approvalRequests` is `{count}`. Anyone else who can see the repository (a
public Remote) sees the upstream entries and their status only: `denied` is
absent, `flags` is `{}`, `evaluationReason`, `evaluatedBy` and each pin's
`evaluationReason`/`contentDrift` are `null`, `ingested[].unresolved` is
`[]`, `summary.lint` is absent, and `approvalRequests` is `{count}`.
`count` is always present, `0` when nobody asked, in every view.

`summary` carries the risk inputs of a name without a per-row call: the
sync caches `transports` (package `transport.type` and remote `type`,
sorted), `registryTypes` (package `registryType`, sorted), `secretsCount`
(package environment variables, package transport headers and remote
headers marked `isSecret`), `packagesCount` and `remotesCount` from the
latest non-deleted upstream document it saw, also for a name nobody
approved. It is `null` until a sync sees a version of the name. For a name
with an ingested version, `summary.lint` adds the unacknowledged findings
per action (`block`, `review`, `warn`) of that version's newest lint run
(see [Lint and health](#lint-and-health)), where the version is the upstream
latest when it is ingested, else the highest ingested one; it is absent
while no ingested version has been linted.

A request for approval is recorded per requester
(`approvalRequests.requesters.<user id> = {at, note}`, at most 100
requesters): asking again replaces only the caller's own note and does not
count twice; `count` is the number of distinct requesters.

Shapes (JSON, camelCase):

```text
CatalogPage    { items: CatalogItem[], nextCursor: string | null,
                 counts: { pending?: n, approved?: n, blocked?: n, review?: n } }
CatalogItem    { id: uuid, name, namespace,
                 status: "pending" | "approved" | "blocked" | "review",
                 denied?: bool,                     // matches mcp_server_deny: never served (holders only)
                 title: string | null, description: string | null,
                 latestVersion: string | null, versions: string[],   // newest first, at most 200
                 upstreamStatus: "active" | "deprecated" | "deleted" | null,
                 upstreamUpdatedAt: RFC 3339 | null,
                 summary: CatalogSummary | null,
                 flags: { typosquat?: { similarTo: string } },
                 approvalRequests: { count,           // everyone (0 when nobody asked)
                                     lastRequestedAt?, lastRequestedBy?, lastNote?,
                                     requesters?: { <user id>: { at, note } } },  // administrators only
                 evaluationReason: string | null, evaluatedAt: RFC 3339 | null,
                 evaluatedBy: uuid | null, firstSeenAt: RFC 3339,
                 pins: CatalogPin[], ingested: CatalogVersion[] }
CatalogSummary { transports: string[], registryTypes: string[],
                 secretsCount: n, packagesCount: n, remotesCount: n,
                 lint?: { version, block: n, review: n, warn: n } }   // holders only
CatalogPin     { id: uuid, version, status,
                 contentDrift: { storedSha256, upstreamSha256, detectedAt } | null,
                 evaluationReason: string | null }
CatalogVersion { version, artifactId: uuid,           // the server.json artifact (capabilities diff, health)
                 upstreamStatus, unresolved: [{ index, error, detail }] }
DecisionResult { item: CatalogItem, ingestError: string | null }
BulkResult     { approved: n, blocked: n,             // one of them is 0
                 names: string[],                     // first 100; every one (up to 5000) for a dry run
                 skippedDenied: n, skippedReview: n, dryRun: bool }
BulkDecideResult { action: "approve" | "block", decided: uuid[], unchanged: uuid[],
                   skippedDenied: uuid[], notFound: uuid[] }
SyncStatus     { updatedSince, resumeCursor, resumeSince, lastStartedAt,
                 lastFinishedAt, lastSucceededAt, lastError, lastSummary: SyncSummary,
                 running: bool }                      // a pass holds the sync lock now
SyncSummary    { pages, entries, namesNew, autoApproved, flagged, ingested,
                 unchanged, statusChanged, drifted, invalid, unresolved,
                 reResolved, backfilledNames, complete: bool, errors: string[] }
```

Audit: `MCP_SERVER_APPROVED`, `MCP_SERVER_REJECTED`, `MCP_SERVER_REOPENED`,
`MCP_SERVER_CONTENT_DRIFT`, `MCP_GATE_UNAVAILABLE` and `MCP_MIRROR_SYNCED`
(see `docs/audit-events.md`).

The artifact routes (`/api/v1/repositories/{key}/artifacts`) list every
stored document of a Remote, including versions of names that are not
approved in `mirror` mode (they are public upstream documents); the `/v0.1`
surface, which clients read, is the control.

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
  an internal name (dependency confusion). This is deliberate and has a known
  cost: a reader of the Virtual can tell that some hosted member holds a name
  it cannot read (the Remote's version of that name answers `404` through the
  Virtual while the Remote serves it directly). It reveals that a name exists
  internally, nothing about its versions or content; keep names that must not
  be inferable out of a Virtual that also merges a Remote carrying them.
  Names compare case-insensitively here, as deny lists and namespace
  allowlists do: a hosted `io.acme/tool` shadows a Remote's `io.Acme/tool`
  (and every other spelling of it), so an upstream entry cannot pass for
  the internal one by letter case. Within one hosted registry a new
  case-only twin cannot be published at all
  ([Server names that differ only in letter case](#server-names-that-differ-only-in-letter-case)).
- **`/servers/{name}/versions`**: the union of the serving members' servable
  versions, each version once (from the first member that serves it), in
  version-text order; `isLatest` marks the version `latest` answers.
- **`/servers`**: each `(name, version)` once, from the member a detail read
  would answer it from; member by member in serving order, each member's rows
  in name-then-version order. `version=latest` lists one entry per name, the
  one `latest` answers. `search`, `updated_since`, `include_deleted` and
  `limit` behave as on a hosted repository.
- **Cursor**: `nextCursor` is opaque, sealed as on a hosted repository and
  bound to the Virtual: it carries the member to resume in and that member's
  keyset position. A cursor naming a key that is not (or no longer) a
  member, one the Virtual did not issue, or anything else malformed, is `400`
  (`mcp_invalid_query`, `detail: "query parameter `cursor`: invalid cursor"`),
  the same answer a hosted repository gives a malformed cursor.
- **Entries** are the member's served form; the
  `com.artifactkeeper.registry/source` block names the member (`repository`)
  and adds `virtualRepository: "<virtual key>"`.
- **Holds**: a reader gets the unknown-name `404` (byte-identical) for
  anything not served. A caller who holds the member that refused (the
  reason-gate predicate, evaluated per member) gets that member's reason
  body; a gate that cannot be evaluated on a member answers `503` and the
  walk does not fall past it. Listings do the same: a `(name, version)`
  whose gate cannot be evaluated on the member that would answer it is
  omitted from `/servers` and `/versions`, never listed from a
  lower-priority member, and a `latest` that cannot be decided on a member
  is not taken from the next one (no entry, no `isLatest`).
- **`mcp_server_deny` on the Virtual** hides matching names on top of the
  members' own deny lists: omitted from listings, `404` on detail
  (`mcp_rejected` with `gate: curation` for a holder of the Virtual).
- **Nested Virtuals** apply their `mcp_server_deny` too: a member reached
  through nested Virtuals does not serve a name any of them denies (the
  union of the deny lists along the member's path; for a member reachable
  along several paths, the path it is ranked by). Through that member the
  name is as absent as an unknown one; another member outside the nested
  Virtual may still serve it.
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

## Lint and health

### The lint

Every server version is linted (`McpLintScanner`, offline and
deterministic: no network, no model). The lint reads the stored server.json
(`title`, `description`, every package's `runtimeArguments`,
`packageArguments`, `environmentVariables` and transport `headers`, every
remote's `url`, `headers` and `variables`), the tools, resources, prompts and
`instructions` the publisher declares in `_meta`
(`com.artifactkeeper/capabilities`, directly or inside
`io.modelcontextprotocol.registry/publisher-provided`), the tools and prompts
of stored MCPB bundles (`metadata.bundles[*].manifest.tools`, `.prompts`),
the OCI pins and image labels, and the `statusMessage`.

It runs (independent of the repository's scan settings):

| When | What | Source(s) written |
| --- | --- | --- |
| hosted publish | the document (refusing on `block`), then the stored version (bundles, labels) | `server_json`, `status_message` |
| admin edit (`PUT .../versions/{v}`) | the same as a publish | `server_json`, `status_message` |
| status change, soft delete | the `statusMessage` (refusing on `block`) | `status_message` |
| Remote ingest of a new version; a mirrored upstream status change; a re-resolution that pinned packages | the stored version (`services::mcp_lint::lint_stored_version`; never refuses: a `block` finding holds the version through the scan-policy gate) | `server_json`, `status_message` |
| every stored capability snapshot that is reported or observed (`ci_reported`, `gateway_reported`, `remote_probe`, `sandbox_run`) with `outcome: ok` | its tools, resources, prompts and `instructions` (`mcp_lint::lint_capabilities`) | `capabilities:<source>` |

What each part of a capability list gets (#5388):

| Part | Rules |
| --- | --- |
| tools | every string of the tool (`name`, `title`, `description`, `inputSchema`, `outputSchema`, `annotations`, object keys): `hidden_text`, `injection_phrase`, `secret_literal`; the name: `destructive_tool`, `shell_like_tool_name`, `confusable_name` |
| resources | every string (`uri`, `name`, `title`, `description`, `mimeType`, ...): `hidden_text`, `injection_phrase`, `secret_literal`; `name`: `confusable_name` (not `uri`: a path in a non-Latin script mixes scripts with its scheme legitimately) |
| prompts | every string (`name`, `title`, `description`, argument `name`s and `description`s; an MCPB prompt's `text`): `hidden_text`, `injection_phrase`, `secret_literal`; `name`: `confusable_name` |
| `instructions` | `hidden_text`, `injection_phrase` (URLs count, as in a description), `secret_literal` |

Identifiers are refused rather than linted: a capability document
(`POST .../capabilities`, a worker result, a declared block) whose tool or
prompt `name`, resource `uri` or `name`, or prompt argument `name` contains a
control, bidirectional, zero-width or tag character answers `400` (the introspector applies the same `from_doc` check before
posting, so its attempt is recorded as `refused` with the reason), the same characters the publish path
refuses anywhere in a declared block. Free text with them is accepted and
flagged `hidden_text`. These are checks on what reaches an agent, not output
encoding: the web UI renders every capability string as text, so markup in a
description is not an XSS vector.

Publisher-declared capabilities (`_meta` and MCPB manifests) are part of the
document and are linted under `server_json`, so a `publisher_declared`
snapshot is not linted again. A new snapshot of a source replaces that
source's findings (a snapshot with no flagged tool clears them); a failed
snapshot (`outcome` other than `ok`) leaves them.

### Rules, actions and how the gates read them

| Rule | Actions | What it flags |
| --- | --- | --- |
| `secret_literal` | `block` | A recognisable credential (AWS key id, GitHub/GitLab/npm/PyPI/Slack/Stripe/Google token, `sk-` keys, JWT, PEM private key) in any linted string; in value positions (`default`, `value`, `choices`, header values, URL variables) also a high-entropy random literal; a password in a remote URL's user-info; a credential-named query parameter with a literal value. The value is never repeated in the finding. |
| `secret_unmarked` | `review` | An environment variable, header or argument whose name reads as a credential (`token`, `secret`, `password`, `api_key`, `auth`, `authorization`, `key`, ...) without `isSecret: true`. |
| `injection_phrase` | `review` | Instructions aimed at the model: "ignore previous instructions", "you must", "do not tell the user", "system prompt", pseudo-tags (`<important>`, `<system>`), HTML/markdown comments, `IMPORTANT:`, chat role tags (`<\|im_start\|>`, `[INST]`, `<<SYS>>`), fenced code, "before using this tool", credential file references (`~/.ssh`, `id_rsa`, `.aws/credentials`, `.npmrc`, `mcp.json`). URLs count only in descriptions and titles shown to the model (server, tools, `inputSchema`), not in `statusMessage` or variable descriptions. Decision 13: `review`, never `block`. |
| `hidden_text` | `block` | Control (other than tab and line breaks), bidirectional, zero-width or Unicode tag characters in any linted string or object key. Stored as finding class `malicious`. |
| `dangerous_args` | `block`, `review` | `block`: in `runtimeArguments`, flags that re-route installs around the backing repository (`--registry`, `--index-url`, `--extra-index-url`, `--find-links`, `--index`, `--default-index`, `--source`, `--pypi-mirror`); anywhere, `--privileged`, a bind mount of the host root (`-v /:/host`, `--mount source=/`) or of the Docker socket. `review`: the same re-routing flags in `packageArguments`, other host bind mounts, `--network/--net/--pid/--ipc/--uts/--userns=host`, `--cap-add`, `--security-opt`, `--device`, `--unsafe-perm`, `--trusted-host`, `--insecure`, `-A`/`--allow-*`, and `LD_PRELOAD`, `NODE_OPTIONS`, `PYTHONPATH` and other code-injecting variables (as `-e`/`--env` values, positional `NAME=value` arguments or environment variable names). Both `--flag value` and `--flag=value` spellings. |
| `remote_url_shape` | `review`, `warn` | `remotes[].url` (and `packages[].transport.url` for templates). `review`: a template variable in the host, user-info, an IP literal (private or public), `localhost`, a URL template that can expand to a non-`http(s)` URL (refused at publish since #5529; a version stored before is flagged when it is next linted, and one with more than 256 expansions has its scheme-position values checked on their own). `warn`: plain `http`, a non-default port on a public host, an internal host name (`.internal`, `.local`, `.corp`, `.lan`, `.intranet`, `.home.arpa`, `.localdomain`) in a public registry. |
| `oci_tag_digest_mismatch` | `warn` | A submitted `:tag@sha256:D` whose tag currently resolves to another digest (`D` is pinned). |
| `oci_label_mismatch` | `warn` | The pinned image's config has no `io.modelcontextprotocol.server.name` label, a label naming another server, or a config that is not stored in the backing repository (labels are read from the stored manifest and config blob, never fetched). Under `mcp_require_oci_label: true` this refuses the publish instead (see below). |
| `mcpb_missing_sha` | `block`, `review` | `block`: an `mcpb` package without `fileSha256`. `review`: an `mcpb` `fileSha256` that matches no bundle stored with the version (when bundles are stored). |
| `destructive_tool` | `review`, `warn` | `warn`: a tool whose name reads as destructive (`delete`, `drop`, `rm`, `purge`, `wipe`, `truncate`, `kill`, `reset`, `overwrite`, ...) or that declares `destructiveHint: true`. `review`: a destructive name whose annotations claim `readOnlyHint: true` or `destructiveHint: false`. |
| `shell_like_tool_name` | `review` | A tool whose name reads as running arbitrary commands (`shell`, `bash`, `sh`, `cmd`, `powershell`, `terminal`, `exec`, `eval`, `subprocess`, or `run`/`execute` with `command`/`script`/`code`/`process`). |
| `confusable_name` | `review` | A tool, prompt or resource name that carries a character which reads as ASCII (its UTS #39 confusable skeleton after NFKC is ASCII, for example Cyrillic `е` or fullwidth `ｒ`) and either mixes scripts (`rеad_file`) or reads as plain ASCII as a whole (all-Cyrillic `реа`, fullwidth `ｒｅａｄ`). The message gives the name it reads as. A name that only mixes scripts (`get_天気`) or is written in one non-Latin script (`файл`) is not flagged. Same `unicode-security` skeleton as the curation typo-squat rules. |

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
`scanner_version = "ak-mcp-lint/3"` per lint run of the server.json artifact,
listed by `GET /api/v1/security/artifacts/{artifact_id}/scans` like any scan.
Each finding:

| Column | Value |
| --- | --- |
| `title` | `mcp_lint/<rule>` (for example `mcp_lint/secret_literal`) |
| `description` | the one-line message |
| `affected_component` | `<source>:<path>`, for example `server_json:packages[0].environmentVariables[1].default` |
| `source` | `mcp_lint/<source>`: `server_json`, `status_message`, or `capabilities:<snapshot source>` (for example `mcp_lint/capabilities:ci_reported`) |
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
repository, a non-MCP repository, an unknown version, or a soft-deleted one
(status `deleted`, as on the read surface): `404` with the standard error
body. `?include_deleted=true` answers a soft-deleted version's health too
(`include_deleted` is `true` or `false`; anything else is `400`). Works on Local, Staging and Remote repositories
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
  with packages but no pins (stored under `open` before #5452; such a
  version is also held `unresolvable`). Order:
  `critical` > `warning` > `unknown` > `ok`.

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

The **current** snapshot is the freshest successful (`outcome: ok`) one of
the best source in this order: `sandbox_run`, `remote_probe`,
`gateway_reported`, `ci_reported`, `publisher_declared`. Freshness is the
latest time the content was validly seen (`lastSeenAt`, else `observedAt`),
then arrival, then id, never arrival alone (#5464): a result or report that
arrives later but was observed earlier than the current snapshot is kept as
history and does not replace it, raises no `tool_drift` finding and is not
linted (its tool text carries no lint finding in the diff view). History
(`snapshots[]`) and the diff's default `from` follow the same order.
"Newest" below means freshest in this order. A result or report dated up to
5 minutes ahead (clock skew) is stored as of its arrival. CI and gateway
reports have no lower bound on `observedAt`: a pipeline that reports a build
or commit time older than the current snapshot of its source stores history
and does not update the current view.

History is kept, deduplicated and bounded (#5386):

- **Repeats are not stored again.** A reported or observed snapshot whose
  `contentHash`, `outcome` and `authState` equal the newest snapshot of the
  same (version, `source`, `origin`) adds no row: that snapshot's
  `lastSeenAt` (and `ttlMs`, the latest re-probe hint) is updated and it is
  returned instead. A repeat is not audited, linted or compared for drift.
  `observedAt` stays the first time the content was seen, `lastSeenAt` is
  the latest (equal to `observedAt` until the content is seen again). A
  declaration is recorded once per (version, origin, content), as before.
- **Retention.** The scheduler pass keeps the newest 20 snapshots of each
  (version, `source`, `origin`) and deletes older ones, at most 1000 per pass.
  It never deletes the newest successful snapshot of a (version, `source`,
  `origin`) (the current view and the drift baseline), a snapshot a
  `tool_drift` finding names, or the snapshot an open job or the newest job of
  a target points at. An older job's `snapshotId` becomes `null` when its
  snapshot is pruned; the job itself is kept.

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
once per (version, origin, content) by one builder
(`services::mcp_capabilities::record_declared_snapshot`), after a hosted
publish, after an admin edit (a changed declaration is a new snapshot of the
same origin, so a tool change raises `tool_drift`) and after a Remote
ingests a version. A bundle is uploaded before its version exists, so its
manifest is recorded by the publish that pins it. The same three paths queue
the introspection jobs the repository's settings allow (Remote ingest with
`mcp_probe_remotes: all` only; `hosted_only` skips Remote rows).

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
    "lastSeenAt": "2026-11-03T16:00:00Z",
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
  "snapshots": [ /* summaries, freshest first: `current` without tools/resources/prompts/instructions */ ],
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
| `start_failed` (the sandbox or the connection failed, not the server:
the engine exited 125-127, the runtime, network or image was missing;
retried) | `needs_config` (the sandboxed server would not start or
answer without configuration) | `refused` (redirect, private address, over
the size cap, or a protocol violation: `details.protocolViolation` names it,
see [the worker](#the-ak-mcp-introspector-worker)) | `unsupported` |
`error`. Failed attempts are listed in
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

A CI pipeline or gateway reports what it observed. Needs `write:artifacts`, a
token scoped to the repository (`403 mcp_forbidden` otherwise) and the MCP
namespace write gate every other MCP write runs: repository `write`, or a
matching `conditions.mcp_namespaces` grant; under
`mcp_require_namespace_grant` only the namespace grant
(`403 mcp_namespace_not_granted`). The version must be visible to the caller. Allowed on
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
other member is optional (`observedAt` defaults to now, `authState` to
`unknown`). `observedAt`, `cacheScope` and `ttlMs` follow the worker result's
metadata rules (#5543), except that a report has no lower bound on
`observedAt`, since it may describe an older build: an `observedAt` at most 5
minutes (the clock-skew window) ahead of the registry's clock is accepted and
stored as of its arrival; `cacheScope` is `public` or `private`; `ttlMs` an
integer from `0` to `2592000000` (30 days). A refused report answers `400
mcp_invalid_result_metadata` with the offending `field`. Item rules are the
declaration rules above. The display label is set by AK, never by the caller:
`reported by CI (<username>[, <generatedBy>])` /
`reported by a gateway (...)`.

`201`:

```json
{"snapshot": { /* as `current` above */ }, "created": true,
 "previousSnapshotId": "uuid|null", "drift": {"scanId": "uuid"} }
```

`drift` is `null` unless this report differs from the previous one of the
same source. `created` is `false` when the report repeats the newest one of
the same source and `generatedBy` (same content, outcome and auth state):
nothing new is stored, the existing snapshot's `lastSeenAt` is bumped and it
is returned, without audit or drift. Errors: `400
mcp_invalid_result_metadata` for refused metadata (above), `400
mcp_invalid_capabilities` for a malformed body (`detail` names the field),
`401 mcp_unauthorized`, `403 mcp_forbidden`, `404` (unknown or
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

Needs `write:artifacts` (an API token without it is `403 mcp_forbidden`) and
repository `admin` (or instance administrator). Queues the jobs the
repository's settings allow for this version (an open job per target is not
duplicated). `202 {"queued": ["uuid"], "jobs": [ /* open jobs */ ]}`;
`409 mcp_introspection_disabled` when both `mcp_probe_remotes` and
`mcp_sandbox_introspection` are off for the repository. Publishing a version
queues the same jobs automatically.

### Introspection jobs

| Kind | Queued for | When |
| --- | --- | --- |
| `remote_probe` | each `remotes[]` entry of type `streamable-http` with a concrete `http(s)` URL (no `{template}` variables, no userinfo). Legacy `sse` remotes are not probed. | `mcp_probe_remotes`: `all` (Local, Staging, Remote), `hosted_only` (Local and Staging only), `off` (never, the default). Re-queued every `max(ttlMs, 6 h)` after the last probe, because a remote can change its tools without a version bump, for the server's latest version (`isLatest`) and for versions published in the last 30 days (`publishedAt`) only; an older version keeps its last snapshot and can still be probed on demand (`POST .../capabilities/probe`). Handed out only while the version is servable (as a sandbox run), so a held, blocked or unapproved version's endpoints are never contacted. |
| `sandbox_run` | each stdio `packages[]` entry of type `npm`, `pypi` or `oci` that the package policy pinned to an AK repository | `mcp_sandbox_introspection: on`. Never re-queued (the bytes are version pinned). Handed out only while the version is servable (its own and its backing packages' gates pass), so the bytes executed are the bytes AK scanned. |

Attempts: 3. `timeout`, `rate_limited`, `start_failed` and `error` results are retried after
`2^attempts` minutes (a `429`'s `Retry-After`, clamped to 1 minute .. 24 h),
except that a `sandbox_run` that times out is retried once only: a timed-out
run already held a worker for the sandbox's whole 120 s wall clock, so its
second `timeout` is final and is recorded as a `timeout` snapshot. A claim
not completed within 10 minutes returns to the queue. The scheduler pass
(every 15 minutes, idempotent) reaps expired claims, re-queues due probes
and prunes snapshot history (see [Capabilities and
introspection](#capabilities-and-introspection)).

Completing a job is atomic (#5389): the claim (job id, token hash, `claimed`
status) is checked and ended and the snapshot stored in one transaction, and
the audit, lint and drift side effects run only after it commits. Of two
completions of one claim, or a completion racing the reaper or a re-claim,
exactly one stores a snapshot; the other stores nothing and is answered
`409 mcp_claim_invalid`. A retry (`status: "retry"`) likewise only counts
when it ended the current claim, so a retry racing a successful result
never leaves a stored snapshot behind a pending job (#5461).

The same transaction also requires a live lease: a claim whose
`leaseExpiresAt` has passed cannot complete or retry, whether or not the
reaper has run yet (`409 mcp_claim_invalid`, nothing stored, the job left for
the reaper) (#5462). And it revalidates the target (#5463): the reader serve
gate a claim passes is evaluated once more just before the transaction, and
inside it these are re-read under lock: the version row's quarantine,
rejection and deletion, its registry status (`deleted`), and every backing
package's pinned rows (quarantined, rejected, deleted, or a cache pin under
its hold). The other gates (scan policy, curation and age gates, Remote
proxy verdicts, OCI manifest presence) are evaluated only by the
pre-transaction check (#5533 tracks evaluating the whole gate on the
transaction). A target that no longer qualifies answers `409
mcp_target_ineligible` with a `reason`, stores nothing and cancels the job,
as a claim of a held version does. A gate that cannot be evaluated is no
hold: a claim returns the job to the queue and tries the next candidate
(answering `503 mcp_gate_unavailable` only when nothing servable was found),
and a completion answers `503 mcp_gate_unavailable` and leaves the claim as it
was. A released job is due again after 1, 2, 4 ... up to 64 minutes; its first
five releases give the attempt back, later ones spend it, so a gate that never
becomes evaluable fails the job once its attempts are used up.

Claim order is fair across repositories: a claim hands out a due job from the
repository with the fewest jobs claimed at that moment, and within it the
oldest due job (earliest `not_before`). A publisher that queues many versions
therefore takes at most its share of the workers while other repositories'
jobs are due; with one repository queued, jobs go out oldest first.

### Worker API (`/api/v1/mcp/introspection`)

Authenticated with an API token minted with the **`mcp:introspect`** scope
(admin-only to mint; a token with `*`/`admin` or an interactive session does
not qualify: `403 mcp_forbidden`). Mint it for a dedicated service account.

A token minted with a repository restriction only works that repository's
jobs (#5460): a claim hands it only jobs of repositories it is scoped to
(another repository's due job is left untouched, so the answer is `204` when
nothing of its own is due), and a completion re-checks the token's scope
against the job's repository, and that the job belongs to the repository of
the server version it introspects, inside the transaction that ends the
claim. Holding a valid claim token is not enough: a completion by a token
that does not cover the job's repository answers `403 mcp_forbidden` and
stores nothing, leaving the claim as it was. A change to a token's
repository restriction takes effect once the API-token validation cache
(up to 5 minutes) has expired; until then requests run with the scope
the token was last validated with.

A claim is bound to the worker identity that took it (#5465): the principal
(user or service account) of the `mcp:introspect` token that sent `POST
/jobs/claim`. Only that principal can complete the job; another worker that
holds the claim token gets the same `409 mcp_claim_invalid`, with the same
body, as a wrong token (checked before the result is read, and again under
the claim's row lock), and nothing is stored or changed. The binding is to
the principal, not to the API token, so a worker that rotates its token, or
uses another `mcp:introspect` token of the same service account, mid-claim
can still complete its claim; workers that must not complete each other's
jobs need separate service accounts. `workerId` is a self-chosen label, not
an identity, and is not checked. The stored snapshot (`reportedBy`) and its
`MCP_CAPABILITIES_INGESTED` audit record name the completing worker's
principal. A claim taken before the upgrade that introduced the binding
(migration 338) has no recorded owner and cannot be completed by anyone; its
lease expires and the reaper returns the job to the queue.

`POST /jobs/claim` with `{"kinds": ["remote_probe", "sandbox_run"],
"workerId": "pod-a"}` (both optional) answers `204` when nothing is due,
`503 mcp_gate_unavailable` when nothing servable was found and a
candidate's gates could not be evaluated (it goes back to the queue), or
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

A failed outcome carries no lists. The result's metadata is validated
before anything is stored or changed (#5464, #5466); a refusal answers `400
mcp_invalid_result_metadata` with the offending `field`. Every check but
`observedAt`'s lower bound (which needs the claim time, read under the
claim's lock) runs before anything is locked, for every outcome, a retry
included:

| Field | Accepted |
| --- | --- |
| `observedAt` | default: the arrival time. At most 5 minutes (the clock-skew window) ahead of the registry's clock, and no more than 5 minutes before the job's claim. One inside the window but ahead of arrival is stored as of its arrival. |
| `cacheScope` | absent, `public` or `private` (exact, lower case). |
| `ttlMs` | absent, or an integer from `0` to `2592000000` (30 days): it only spaces re-probes (`max(ttlMs, 6 h)`). |

A refused result stores no snapshot, changes no current view, writes no
audit record and leaves the job claimed with its lease running: the worker
can post a corrected result before the lease expires, or the reaper returns
the job to the queue. The reference worker normalises a remote's hints
before posting: a `cacheScope` other than `public` is sent as `private`
(with `authState: caller_specific`) and `ttlMs` is capped at 30 days.

`200 {"status": "stored", "snapshotId", "contentHash", "current", "drift":
{"scanId"} | null}` (`snapshotId` is the existing snapshot when the result
repeats it; `current`: whether that snapshot is the version's current view
after the commit) or `200 {"status": "retry", "notBefore"}`;
`409 mcp_claim_invalid` when the token does not match the current claim
(lease expired, re-claimed or already completed) or the claim is held by
another worker identity; `409
mcp_target_ineligible` when the version or a backing package stopped being
eligible after the claim (the job is cancelled); `503 mcp_gate_unavailable`
when its gates could not be evaluated (the claim is unchanged); `403
mcp_forbidden` when the token is not scoped to the job's repository; `400
mcp_invalid_result_metadata` for refused metadata (above) and `400
mcp_invalid_capabilities` for a malformed result.

### The `ak-mcp-introspector` worker

A separate binary of the backend crate (`cargo build --release --bin
ak-mcp-introspector`). It is not part of the backend image and the server
process never runs it: it holds no database or storage credentials and talks
to the backend only through the worker API.

```text
ak-mcp-introspector run [--sandbox] [--once] [--poll-secs 30] --token-file <path | ->
    AK_URL, AK_MCP_INTROSPECTOR_TOKEN_FILE (mcp:introspect), AK_MCP_INTROSPECTOR_ID
ak-mcp-introspector probe <url>                      # one probe, printed; no backend
ak-mcp-introspector convert --from <inventory> <file> # print a report body
ak-mcp-introspector push --from <inventory> --repo <key> --server <name> --version <v> <file>
    AK_URL, AK_TOKEN (write:artifacts)
ak-mcp-introspector render-sandbox <job.json>         # print the guest spec and runner command
ak-mcp-introspector sandbox-probe <job.json>          # run that guest for real, print the result
```

The token is read from `--token-file` (`AK_MCP_INTROSPECTOR_TOKEN_FILE`; `-`
reads it from standard input, as the reference systemd unit passes it).
`--token` / `AK_MCP_INTROSPECTOR_TOKEN` still work but log a warning: a value
in the environment is readable in `/proc/<pid>/environ` by every process of
the worker's user. The worker makes itself non-dumpable at startup, so
neither its environment nor its memory can be read by another process of
that user.

`sandbox-probe` needs no backend: it runs the job document with the
configured runner and prints the probe result. It exits `0` only for
`"outcome": "ok"`, which makes it the check for a sandbox deployment.

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

Response and session integrity. Every response is matched to the one
outstanding request; a violation ends the probe `refused`, is not retried, and
nothing the server sent in that probe (capabilities, `serverInfo`,
`instructions`, list items) is reported. `details.protocolViolation`:

| Code | Cause |
|---|---|
| `response_id_mismatch` | A response (JSON body or SSE event) whose `id` is absent, `null` or not the outstanding request's; the type counts (`1` and `"1"` differ). A non-2xx body read as the request's JSON-RPC error (a modern error code, which steers the fallback) may carry `"id": null` or none, but not another request's `id`; any other non-2xx body is an HTTP-level error whose `id` is not looked at (only its status is used). |
| `duplicate_response` | A response to a request already answered, or a second response for the same `id` in the same read of an SSE stream. The stream is not read past the first response, so a duplicate sent later is never seen and never accepted. |
| `unexpected_batch` | A JSON-RPC batch carrying a response (the worker never sends a batch). A batch of only notifications or server requests is skipped. |
| `session_id_changed` | After `initialize` established an `Mcp-Session-Id`, a response carried a different one. The worker never switches sessions. |
| `session_id_invalid` | `initialize` assigned an `Mcp-Session-Id` that is not 1 to 256 visible ASCII characters. |

Notifications and server-to-client requests on an SSE stream are skipped.
An `Mcp-Session-Id` is adopted only from the successful `initialize`
response; one on any other response before that (including a modern
server's, which has no sessions) or introduced later without one is ignored
and never sent. A redirect is refused before its headers are read, so a
session id never follows one to another origin.

**Sandbox runner** (`--sandbox`). A pluggable `SandboxRunner` renders a
runner-neutral guest spec:

- npm: image `AK_MCP_SANDBOX_NODE_IMAGE` (default
  `docker.io/library/node:22-alpine` pinned by digest),
  `npx --yes --registry=<registry> <identifier>@<version> <args>` and
  `npm_config_registry=<registry>`, where `<registry>` (here and for PyPI
  below) is the canonical form of the checked `registryBaseUrl` (see "npm
  and PyPI package sources");
- pypi: image `AK_MCP_SANDBOX_PYTHON_IMAGE` (default
  `ghcr.io/astral-sh/uv:python3.12-alpine` pinned by digest), `uvx --no-config
  --default-index <registryBaseUrl>/simple <identifier>@<version> <args>`;
- oci: the AK-served `<ak host>/<repo>/<name>[:tag]@sha256:<digest>` itself,
  no network. The reference must be canonical and carry exactly one
  lower-case SHA-256 digest on the job's AK origin; a bare image name,
  another host, a SHA-512 digest, extra `@` delimiters, or a non-canonical
  path is refused. The AK host must itself be a registry host, that is
  contain `.` or `:` or be `localhost`: with a bare service name such as
  `http://artifact-keeper` as the AK base URL, an image reference's first
  component is a Docker Hub namespace, so OCI introspection is refused
  (give the base URL a domain or a port).

Only what AK serves is run: a `registryBaseUrl` or OCI identifier that is not
this AK instance is refused; an OCI package's legacy `version`,
`registryBaseUrl` or `fileSha256` is refused (the tag or digest belongs only
in `identifier`); publisher `runtimeArguments` are dropped; environment
variables that steer a package manager or runtime (`NPM_CONFIG_*`, `UV_*`,
`PIP_*`, `PYTHON*`, `NODE_OPTIONS`, `LD_*`, proxy variables, `PATH`,
`HOME`, ...) are dropped. Every `isSecret` value, every required value
without a default and every `{template}` value is the placeholder
`AK_PLACEHOLDER_<NAME>`. The whole run, install included, is capped at 120 s.
When the run ends, whatever the outcome, the engine client (or launcher)
gets `SIGTERM`, then `SIGKILL` 5 s later, and the container is removed
through the engine (`<engine> rm -f <name>`): killing the client alone
leaves the container running. An npm or PyPI guest's own network is removed
after it (`<engine> network disconnect -f <name> <gateway>`, `<engine>
network rm <name>`). An OCI package's image is removed after its
run (`<engine> rmi`); the runner images are kept. At startup the worker
removes any container, then any network, labelled
`com.artifactkeeper.mcp-sandbox.owner=<worker id>` that a crashed or killed
earlier run left behind, and warns about
runner images that are not pinned by digest. A guest that exits before
answering is reported `needs_config`, unless the engine exited `125`, `126`
or `127` (the engine failed: runtime, network or image missing, pull failed,
name in use), which is `start_failed` with the engine's message, and
retried.

**npm and PyPI package sources** (#5446). For npm and PyPI jobs the rules
in this section take precedence over the general ones above: where they
refuse something the paragraph above says is dropped, the job is refused.
Before any guest starts, an npm or PyPI job is refused (`unsupported`, with a
`registryBaseUrl: ...`, `package identifier: ...`, `package version: ...`,
`packageArguments: ...`, `runtimeArguments: ...` or
`environmentVariables: ...` reason naming the rule, never the submitted name
or value) when what it submits would make `npx`/`uvx` fetch the package from
anywhere but the AK repository it was served from; nothing is stripped to
make a job fit:

- `registryBaseUrl` is parsed as a URL and must be exactly
  `<akBaseUrl>/npm/<repository>` (npm) or `<akBaseUrl>/pypi/<repository>`
  (PyPI): the same scheme, the same host (compared lower-cased and
  IDNA-normalised), the same effective port (`:443` on `https` is the same
  origin as no port; another port is not) and that path, an optional
  trailing slash aside, at most 2048 bytes. It is never compared as a string
  prefix. Userinfo (`user@`), any percent-encoding (`%40`, `%2F`, `%3A`,
  `%2e`, ...), a backslash, a `.`/`..` segment, whitespace, a query or a
  fragment is refused, and so is the lenient `https:host/...` or
  `https:///host/...` form. The spec carries the canonical URL, not the
  submitted string.
- The package must be a plain name and one exact version: npm `name` or
  `@scope/name` (at most 214 bytes) with a SemVer version without build
  metadata (`1.2.3`, `1.2.3-rc.1`; npm reads `1.2.3+x.tgz` as a file); PyPI
  a PEP 508 project name (at most 200 bytes) with a PEP 440 version.
  Versions are at most 256 bytes and never end in `.tgz`, `.tar` or
  `.tar.gz`. A URL, path, `git+`/`github:`/`file:`/`npm:` spec, `name@url`,
  `name @ url` direct reference, extras, a range, a tag such as `latest`,
  or a marker is refused.
- `environmentVariables` may not name a variable the job's package manager
  reads for its registry, index or configuration (any case). npm:
  `NPM_CONFIG*` / `npm_config_*` (including `NPM_CONFIG_REGISTRY` and
  `NPM_CONFIG_USERCONFIG`), `YARN_*`, `PNPM_*`, `COREPACK_*` and
  `NODE_OPTIONS`. PyPI: `UV_*` (`UV_INDEX` beats `--default-index`),
  `PIP_*` (`PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`, `PIP_FIND_LINKS`,
  `PIP_CONFIG_FILE`, `PIP_TRUSTED_HOST`, ...) and `PIPX_*`. The other
  manager's variables, proxy variables, `HOME`, `XDG_*` and the rest listed
  above are dropped with a note, as for any job.
- In `packageArguments` (as rendered) and `runtimeArguments`, a source
  option whose value (`--opt=<v>`, `-i<v>`, or the next argument) is a URL
  (`scheme://...`), a `git+` or a `file:` reference is refused (option
  names compared case-insensitively, `_` read as `-`). npm: `--registry`,
  `--@<scope>:registry`. PyPI: `--index-url`/`-i`, `--extra-index-url`,
  `--find-links`/`-f`, `--default-index`, `--index`, `--from`, `--with`,
  `--with-requirements`, `--with-editable`. `npx` and `uvx` stop reading
  options at the package spec, so everything else, including these options
  with any other value (`--index products`, `-f out.json`), is the server's
  own argument; other `runtimeArguments` are still dropped.

The rendered command pins the canonical registry itself (`npx
--registry=<registry>` plus `npm_config_registry=<registry>`; `uvx
--no-config --default-index <registry>/simple` with `UV_NO_CONFIG=1`), and no
publisher argument or variable can override it. For npm and PyPI guests, a
package or environment input whose name ends in a credential word (`TOKEN`,
`SECRET`, `PASSWORD`, `PASSWD`, `APIKEY`, `API_KEY`, `ACCESS_KEY`,
`PRIVATE_KEY`, as whole `_`/`-` separated words: `GITHUB_TOKEN`,
`--password`, but not `MAX_TOKENS` or `TOKENIZER`) gets the
`AK_PLACEHOLDER_<NAME>` placeholder even when it is not marked `isSecret`.
An `akBaseUrl` with userinfo, a query or a fragment is refused for every
job.

These checks cover only what the job document names. What the installed
package pulls in itself (a `git+`, tarball or `file:` dependency, an install
script) is contained by the guest's network, which reaches only AK, not by
them.

Each stdio read is bounded: a line is read only up to what is left of the
1 MiB budget, so a guest printing one endless line costs the worker 1 MiB,
not its memory. A result the backend would refuse (a name over 256 bytes, a
resource URI over 2048, `instructions` over 64 KiB, more than 1000 items of
a kind, a request body over 1 MiB) is posted as `refused` with the reason
instead: over-long names and URIs are dropped like unusable items, the rest
refuse the result.

The engine client or launcher starts with a cleared environment: only
`PATH`, `HOME`, `USER`, `LOGNAME`, locale and `TZ`, `TMPDIR`, the `XDG_*`
directories, `DBUS_SESSION_BUS_ADDRESS`, the Podman and Docker client
variables (`CONTAINER_HOST`, `CONTAINERS_*`, `REGISTRY_AUTH_FILE`,
`DOCKER_HOST`, `DOCKER_CONFIG`, `DOCKER_CONTEXT`, `DOCKER_CERT_PATH`,
`DOCKER_TLS_VERIFY`), `KUBECONFIG` and `KUBERNETES_SERVICE_HOST`/`_PORT`,
the proxy variables (for image pulls), every `AK_MCP_SANDBOX_*` variable and
the names listed in `AK_MCP_SANDBOX_PASS_ENV` (comma separated) pass.
`AK_MCP_INTROSPECTOR_TOKEN` and `AK_TOKEN` never do.

Runners:

- **OCI runner** (default): `AK_MCP_SANDBOX_ENGINE` (`podman` default, or
  `docker`), `AK_MCP_SANDBOX_RUNTIME` (`runsc`, gVisor, by default; `kata-fc`
  or another Kata runtime works the same way; an empty runtime, `runc`,
  `crun` or any runtime that is not gVisor (`runsc*`) or Kata (`kata*`) is
  refused unless `AK_MCP_SANDBOX_ALLOW_DEFAULT_RUNTIME=true`, because a
  plain container is not a boundary for attacker-chosen install scripts),
  `AK_MCP_SANDBOX_GATEWAY` (the AK forwarder's container, default
  `ak-gateway`), `AK_MCP_SANDBOX_MEMORY` (`1g`), `AK_MCP_SANDBOX_CPUS`
  (`1`). `AK_MCP_SANDBOX_NETWORK` is retired: guests that share a network
  can reach each other (#5447), so `run --sandbox` with it set (or with an
  empty `AK_MCP_SANDBOX_GATEWAY`) exits with an error before claiming
  anything. For an npm or PyPI guest the runner first creates the
  guest's own network, `<engine> network create --internal --label=...
  <name>`, and attaches the forwarder to it under the host of the job's
  `akBaseUrl` (the backend's public base URL; `AK_URL` only when the job
  has none), `<engine> network connect --alias <AK host> <name>
  <gateway>`, then reads the forwarder's address on it (`<engine>
  container inspect --format '{{(index .NetworkSettings.Networks
  "<name>").IPAddress}}' <gateway>`) and gives the guest
  `--add-host=<AK host>:<address>`, so the guest does not depend on the
  engine's DNS; if any of these fails the guest is not started
  (`start_failed`, retried). An `akBaseUrl` with an IP address instead of a host name is
  `start_failed` too. Workers sharing a host need distinct
  `AK_MCP_INTROSPECTOR_ID`s: leftovers are reaped by that id, at startup
  and every 10 minutes while idle.
  The guest is rendered as `<engine> run --rm -i
  --name=ak-mcp-sbx-<job>-<random> --label=com.artifactkeeper.mcp-sandbox=<job>
  --label=com.artifactkeeper.mcp-sandbox.owner=<worker id> --runtime=runsc
  --network=<its own network | none> --read-only
  --tmpfs=/tmp:rw,exec,nosuid,nodev,size=512m --user=65532:65532
  --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=256
  --memory=1g --cpus=1 --pull=missing --stop-timeout=1 --log-driver=none
  --workdir=/tmp -e ... <image> <argv>`; with Podman (an engine named
  `podman*`) also `--timeout=130` (conmon kills the guest even if the
  worker died) and `--http-proxy=false`. The name is fresh per attempt, so a
  retry never collides with an earlier guest. `--log-driver=none`: the
  guest's output is read over the attach stream, and Docker would otherwise
  copy all of it into an uncapped JSON log on the host.
- **External runner**: `AK_MCP_SANDBOX_COMMAND=/path/to/launcher` is started
  as `<launcher> '<guest spec JSON>'` and must connect the guest's stdio to
  its own (a Firecracker launcher, a Kubernetes job wrapper). The spec:
  `{jobId, image, argv, env: [[name, value]], network: "ak-only" | "none",
  akBaseUrl, wallClockMs, notes, pruneImage}`. When the run ends the
  launcher gets `SIGTERM` (then `SIGKILL` after 5 s) and must remove its
  guest; exit codes `125`-`127` mean the launcher itself failed
  (`start_failed`). The Kubernetes launcher in `deploy/mcp-introspector/k8s`
  names each pod afresh, deletes it on `SIGTERM` and deletes pods an earlier
  attempt of the same job left behind.

**Inventory adapters** (`convert` / `push`, posted as `gateway_reported`):
`docker-gateway` (the array `docker mcp tools ls --format=json` prints),
`docker-catalog` (`tools.json` of the `docker/mcp-registry` catalog;
`arguments` become an `inputSchema`), `toolhive` (`thv mcp list tools
--format json`, or a ToolHive registry entry's list of tool names;
`set_during_runtime` is skipped), `static` (`{tools, resources, prompts,
instructions}`, e.g. Cisco MCP Scanner static JSON).

### What a probe cannot catch

A server can tell that it is being probed, and answer differently. Every
probe looks the same from the server's side:

- every probe names its client `ak-mcp-introspector` (`clientInfo.name`)
  and carries no credentials;
- remote probes send `User-Agent: ak-mcp-introspector/<version> (...;
  capability probe; never calls tools)`;
- sandbox runs set `CI=1`, pass `AK_PLACEHOLDER_<NAME>` for every secret,
  required or templated value, run on a network of their own, which
  reaches only AK, and end at the 120 s wall clock.

A server that checks any of these can show AK one tool list and its clients
another, or behave only after the probe has gone. `remote_probe` and
`sandbox_run` snapshots, and the `tool_drift` findings computed from them,
cannot catch such a server. A snapshot is evidence of what the server
showed AK, not of what it shows clients. Approving a remote server is
trusting its operator, and approving a package is trusting the code AK
scanned, not the tool list the probe saw.

### Deploying the worker

1. Mint the credential: create a service account, then an API token for it
   with exactly the `mcp:introspect` scope (an instance administrator must
   mint it).
2. Run the binary where its egress is restricted. Remote probes: a pod whose
   NetworkPolicy allows the AK service and `0.0.0.0/0` **except** RFC 1918,
   CGNAT (`100.64.0.0/10`), link-local (`169.254.0.0/16`, including cloud
   metadata), loopback and the IPv6 equivalents. The in-process guard is
   defence in depth, not a substitute.
3. Sandbox (optional, `--sandbox`): follow the reference deployment in
   [docs/security/mcp-sandbox.md](security/mcp-sandbox.md), which covers the
   threat model, a dedicated host with rootless Podman and gVisor (no engine
   socket in any container), an internal network per guest whose only
   other member forwards to AK, and a Kubernetes variant (gVisor
   `RuntimeClass`, one guest pod per job through the API, RBAC and
   NetworkPolicies). The files are in `deploy/mcp-introspector/`. Check the
   deployment with `sandbox-probe` before turning the sandbox on.
4. Turn it on per repository: `mcp_probe_remotes` (`hosted_only` / `all`)
   and/or `mcp_sandbox_introspection: on`. Both default to off and can be
   locked by an instance administrator.

The repository ships no container image for the worker; build it with
`cargo build --release --bin ak-mcp-introspector` and package it with your
deployment. The `mcp-sandbox` workflow runs a real sandboxed probe under
gVisor on every change to the worker (see the security page).

Audit: `MCP_CAPABILITIES_INGESTED` for every stored snapshot (declared,
reported or observed; the reporter as actor when there is one) and
`MCP_TOOLS_DRIFT` for every drift finding.
