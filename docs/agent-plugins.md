# Agent Plugins repositories

Artifact Keeper hosts AI coding-agent plugin bundles (Claude Code, Cursor,
Codex, GitHub Copilot / VS Code and the Agent Plugins Standard) in repositories
of format `agentplugins`, served at `/agentplugins/{repo_key}` (#5251). Each
plugin version is one zip. The repository generates the marketplace documents
the agents and the `ak` CLI read, so a team publishes a plugin once and installs
it into any supported agent.

```bash
# Claude Code reads the repository directly
claude plugin marketplace add https://registry.example.com/agentplugins/<repo_key>/claude-marketplace.json

# Cursor, Codex and Copilot / VS Code install through the ak CLI
ak agent plugins install <plugin> --repo <repo_key> --harness cursor
```

The design is recorded in
[`plans/2026-11-03-agent-plugins-design.md`](plans/2026-11-03-agent-plugins-design.md).

## Repository types

| Type | Supported |
|------|-----------|
| Hosted (`local`, `staging`) | Yes |
| Remote | No: creation is refused with `400` ("Agent Plugins repositories are hosted-only") |
| Virtual | No: same `400` |

There is no upstream marketplace protocol to proxy today, so only hosted
repositories exist. Every route also refuses a non-hosted repository with
`400`. The repository key `t` is reserved for this format because
`/agentplugins/t/...` is the token-in-path route.

## Layout

The path is authoritative: Artifact Keeper takes the plugin name and version
from the URL, not from a manifest inside the zip.

```text
/agentplugins/{repo}/{name}/{version}/{name}-{version}.zip
```

- `{name}` (the slug) matches `^[a-z0-9][a-z0-9-]*$` and is at most 64
  characters.
- `{version}` is strict SemVer 2.0 (`1.2.0`, `2.0.0-rc.1`; no `v` prefix, no
  two-part versions) without build metadata: `1.0.0` and `1.0.0+hotfix` have
  the same SemVer precedence, so they could not both be immutable versions
  with a well-defined latest. Use a pre-release or a new version instead.
- The file name must be exactly `{name}-{version}.zip`.

### The plugin root

The plugin root is either the zip root or exactly one top-level directory that
holds everything else, the two shapes Claude Code's `archive` source accepts.
`__MACOSX/` and `.DS_Store` entries added by archive tools are ignored when the
root is determined. A zip with two or more top-level directories and no
manifest at its root is refused because the root is ambiguous.

### Manifests and harness tags

Each marker found under the plugin root tags the plugin with a harness. The
first match, in this order, supplies the descriptive metadata (description,
author, homepage, repository, license, keywords):

| Harness tag | Marker (relative to the plugin root) |
|-------------|--------------------------------------|
| `claude` | `.claude-plugin/plugin.json` |
| `standard` | `plugin.json` whose `$schema` starts with `https://agent-plugins.org/schemas/` |
| `cursor` | `.cursor-plugin/plugin.json` |
| `codex` | `.codex-plugin/plugin.json` |
| `gemini` | `gemini-extension.json` (detected and recorded; no index or installer) |

A root `plugin.json` without the Standard `$schema` is ordinary plugin content,
not a marker.

## Publish rules

`PUT` answers `400` for each of these, and this list is complete:

| Class | Example message |
|-------|-----------------|
| Empty body | `Empty upload body` |
| `X-Checksum-Sha256` does not match the body | `X-Checksum-Sha256 mismatch: declared ... but the body hashes to ...` |
| Invalid slug (`^[a-z0-9][a-z0-9-]*$`, at most 64) | `Invalid plugin name "P": ...` |
| Version is not SemVer 2.0 | `Invalid plugin version "1.0": versions must be SemVer 2.0 ...` |
| Version carries build metadata | `... build metadata has no precedence; use a pre-release or a new version` |
| File name is not `{name}-{version}.zip` | `Invalid file name "other.zip": ...` |
| Path rejected by the shared artifact-path check (too long, null bytes) | `artifact_path ...` |
| Body is not a zip | `Invalid ZIP archive: ...` |
| More entries than `MAX_INGEST_ARCHIVE_ENTRIES` (default 10,000) | `ZIP archive contains too many entries ...` |
| Declared uncompressed total above `MAX_INGEST_DECOMPRESSED_BYTES` (default 128 MiB) | `ZIP archive expands to more than ... bytes ...` |
| Duplicate entry names | `ZIP archive contains duplicate entry names` |
| Entry name that cannot be decoded | `ZIP archive entry N has an undecodable name: ...` |
| Entry that is absolute, drive-qualified or has a `..` segment | `ZIP archive entry "../x" is an absolute path or escapes the archive root` |
| Entry name with a backslash | `... contains a backslash; use '/' as the separator` |
| Symbolic link entry | `... is a symbolic link; plugin bundles may not contain links` |
| Plugin root ambiguous (two or more top-level directories, no root manifest) | `The plugin root cannot be determined: ...` |
| No harness manifest at the plugin root | `Not an agent plugin bundle: ...` |
| A manifest larger than 1 MiB | `... exceeds the maximum manifest size of 1048576 bytes` |
| A marker manifest that is not a JSON object | `.claude-plugin/plugin.json is not a JSON object` |
| A manifest `name` other than the slug | `... declares name "q" but the upload path names the plugin "p" ...` |
| A manifest `version` other than the path version | `... declares version "0.9.0" but the upload path version is "1.0.0" ...` |
| Remote or virtual repository | `Agent Plugins repositories are hosted-only; ...` |

Other answers: `401` without credentials, `403` without `write:artifacts`,
`409` for a version that exists (or a deleted one re-published with different
bytes, below), `413` over `MAX_UPLOAD_SIZE`, `503` when the ingest-extraction
slots are saturated, `507` over a storage quota.

**Why manifest `name` and `version` must match the path.** Claude Code
resolves an installed plugin's version from its `plugin.json` first and the
marketplace entry second, and re-downloads a plugin only when that resolved
version changes. A zip whose manifest still says `1.1.0` while it is published
as `1.2.0` would therefore never reach anyone who installed `1.1.0`: every
update would look like the same version. Refusing the mismatch at publish time
keeps the index, the manifest and the installed copy in agreement. Leaving
`version` out of the manifest is fine; the marketplace entry then supplies it.
The same holds for `name`, which agents use to identify the installed plugin.

Published versions are immutable: re-publishing an existing version is `409`.
Remove a version with the ordinary REST artifact delete; every document drops
it on the next request. A deleted version can only be re-published with
identical content (restoring it); publish a new version otherwise. Claude Code
re-downloads only when the version string changes, so new bytes under an old
version would never reach existing installs.

```bash
curl -X DELETE -u user:password \
  https://registry.example.com/api/v1/repositories/<repo_key>/artifacts/<name>/<version>/<name>-<version>.zip
```

Everything that applies to hosted artifacts applies here: repository
visibility, scan-on-upload and quarantine holds, scan policies, publish quota,
download statistics, the Packages catalog, push replication to mesh peers, and
audit.

Only versions published through this route (or replicated from a peer that
did) are indexed and downloadable under `/agentplugins`. A file written into
the repository through the generic REST upload
(`PUT /api/v1/repositories/{key}/artifacts/{path}`) was never validated as a
plugin bundle, so it is ignored by every document and by the download route,
even at a path that looks like a version. The generic route is not refused
for this format, because push replication delivers through it.

## Endpoints

| Method and path | Auth | Behaviour |
|-----------------|------|-----------|
| `PUT /agentplugins/{repo}/{name}/{version}/{name}-{version}.zip` | `write:artifacts` (Basic, Bearer, `X-API-Key`) | Raw zip body (no multipart), streamed to staging and hashed. Optional `X-Checksum-Sha256`. `201` with the JSON below; `409` if the version exists. |
| `GET`/`HEAD /agentplugins/{repo}/{name}/{version}/{name}-{version}.zip` | read | The zip, streamed by Artifact Keeper itself. `Content-Type: application/zip`, `Content-Disposition: attachment`, `Content-Length`, `X-Checksum-Sha256`, `ETag: "<sha256>"`. Quarantined versions are refused. |
| `GET /agentplugins/{repo}/marketplace.json` | read | Unified index. |
| `GET /agentplugins/{repo}/claude-marketplace.json` | read | Claude Code marketplace. |
| `GET /agentplugins/{repo}/cursor-marketplace.json` | read | Per-harness index for the `ak` CLI. |
| `GET /agentplugins/{repo}/codex-marketplace.json` | read | Per-harness index for the `ak` CLI. |
| `GET /agentplugins/{repo}/vscode-marketplace.json` | read | Per-harness index for the `ak` CLI. |
| `GET /agentplugins/{repo}/{name}/index.json` | read | Every version of one plugin, newest first. |
| `GET /agentplugins/t/{token}/{repo}/...` | token in the path | Every read route above. Generated URLs keep the `/t/{token}/` prefix. Responses carry `Cache-Control: private, no-store` and `Referrer-Policy: no-referrer`. |

Archive downloads are never answered with a redirect to object storage, even
when the storage backend can presign URLs. Claude Code sends a private
marketplace's configured headers only to the marketplace URL's origin and
drops them on a redirect to another origin, so a presigned redirect would turn
every authenticated install into a failed download.

Publish response:

```json
{
  "name": "deploy-tools",
  "version": "1.2.0",
  "sha256": "6bfa...",
  "size_bytes": 48213,
  "harnesses": ["claude", "standard"],
  "marketplace_name": "plugins",
  "download_url": "https://registry.example.com/agentplugins/plugins/deploy-tools/1.2.0/deploy-tools-1.2.0.zip",
  "marketplaces": {
    "claude": "https://registry.example.com/agentplugins/plugins/claude-marketplace.json",
    "cursor": "https://registry.example.com/agentplugins/plugins/cursor-marketplace.json",
    "codex": "https://registry.example.com/agentplugins/plugins/codex-marketplace.json",
    "vscode": "https://registry.example.com/agentplugins/plugins/vscode-marketplace.json",
    "all": "https://registry.example.com/agentplugins/plugins/marketplace.json"
  }
}
```

`marketplace_name` is the name Claude Code will register the marketplace under
(see "Marketplace name" below).

## Index documents

The documents are generated from the database on every request, never stored,
so a delete, a quarantine hold or a scan-policy decision shows up immediately.
A version the download gate refuses is left out of every document: the
documents and the download route apply the same gate, quarantine and upload
holds first, then the repository's scan policies (`block_unscanned`,
`block_on_fail`, `max_severity`). Refused versions are skipped before the
latest version is chosen, so a plugin whose newest version is blocked is
listed at its newest downloadable version. Each response carries an `ETag`; a matching `If-None-Match` is
answered with `304`. Plain routes send `Cache-Control: no-cache` (cache, but
revalidate).

Membership:

| Document | Plugins tagged |
|----------|----------------|
| `marketplace.json` | any |
| `claude-marketplace.json` | `claude` or `standard` |
| `cursor-marketplace.json` | `cursor` or `standard` |
| `codex-marketplace.json` | `codex` or `standard` |
| `vscode-marketplace.json` | `standard` |

Each document lists one entry per plugin: the highest SemVer version among the
versions that document may list, with pre-releases ordered by SemVer rules
(`2.0.0-rc.1 < 2.0.0`, but `2.0.0-rc.1 > 1.9.0`). A plugin whose 2.0.0 is
Cursor-only and whose 1.0.0 also supports Claude Code is listed at 2.0.0 in
`cursor-marketplace.json` and at 1.0.0 in `claude-marketplace.json`. A Standard-layout plugin's skills load in Claude Code;
its `mcp.json` is not read by Claude Code, which only reads `.mcp.json`.

### `marketplace.json`

```json
{
  "$schema": "https://artifactkeeper.com/schemas/agent-plugins/marketplace-v1.json",
  "name": "plugins",
  "description": "Agent plugins hosted in plugins",
  "owner": { "name": "Artifact Keeper", "url": "https://registry.example.com" },
  "metadata": { "generated_at": "2026-11-03T17:55:12Z", "repository": "plugins", "plugin_count": 1 },
  "plugins": [
    {
      "name": "deploy-tools",
      "description": "Deployment commands and a review agent",
      "version": "1.2.0",
      "author": { "name": "Example Team" },
      "homepage": "https://example.com/docs",
      "repository": "https://github.com/example/deploy-tools",
      "license": "MIT",
      "keywords": ["deployment", "ci"],
      "source": {
        "source": "archive",
        "url": "https://registry.example.com/agentplugins/plugins/deploy-tools/1.2.0/deploy-tools-1.2.0.zip",
        "sha256": "6bfa..."
      },
      "metadata": {
        "harnesses": ["claude", "standard"],
        "size_bytes": 48213,
        "published_at": "2026-11-03T17:55:12Z",
        "versions_url": "https://registry.example.com/agentplugins/plugins/deploy-tools/index.json",
        "components": { "skills": ["deploy"], "commands": 3, "agents": 1, "hooks": true, "mcp": true, "lsp": false, "bin": false }
      }
    }
  ]
}
```

- `description` is the repository's description, or `Agent plugins hosted in
  <repo>` when it has none.
- `metadata.generated_at` is the publish time of the newest version the
  document lists (`null` for an empty document), so the body, and its ETag,
  change only when the listed data changes.
- Optional plugin fields (`description`, `author`, `homepage`, `repository`,
  `license`, `keywords`) are omitted when the manifest does not carry them.
- AK-specific data sits under each entry's `metadata`, an object Claude Code
  documents as never read, so `marketplace.json` is itself a valid Claude Code
  marketplace.

### `claude-marketplace.json` and the per-harness documents

The same document restricted by the membership table, without `$schema`.
`source` is always an `archive` source with the zip's `sha256`, and the entry
`version` always equals the path version (which equals any manifest version).

### Marketplace name

Claude Code registers a marketplace under the document's `name`. Artifact
Keeper derives it from the repository key, which is already limited to ASCII
letters, digits, `-`, `_` and `.`:

- the key is used unchanged, except
- a key whose first character is not a letter or digit (a leading `_`) gets an
  `ak-` prefix: `_private` becomes `ak-_private`;
- a key equal to a name Claude Code reserves (`claude-plugins-official`,
  `claude-code-plugins`, `anthropic-marketplace`, `knowledge-work-plugins`,
  `first-party-plugins`, `claude-community`, `inline`, `builtin`,
  `skills-dir`, `synced`, `claude-plugin-test`, `npm`, `pip`, `uv`, `cargo`,
  `github`, `gh`), or starting with `claudeai-`, gets an `-ak` suffix: `npm`
  becomes `npm-ak`.

The publish response reports the result as `marketplace_name`; install with
`claude plugin install <plugin>@<marketplace_name>`.

### `{name}/index.json`

```json
{
  "name": "deploy-tools",
  "latest": "1.2.0",
  "versions": [
    { "version": "1.2.0", "sha256": "...", "size_bytes": 48213, "harnesses": ["claude", "standard"], "published_at": "2026-11-03T17:55:12Z", "url": "https://registry.example.com/agentplugins/plugins/deploy-tools/1.2.0/deploy-tools-1.2.0.zip" },
    { "version": "1.1.0", "sha256": "...", "size_bytes": 47990, "harnesses": ["claude", "standard"], "published_at": "2026-10-20T09:12:40Z", "url": "https://registry.example.com/agentplugins/plugins/deploy-tools/1.1.0/deploy-tools-1.1.0.zip" }
  ]
}
```

`404` when the plugin has no servable version.

## Client setup

### `AK_EXTERNAL_URL` and https

Every absolute URL in a document is built from `AK_EXTERNAL_URL` when it is
set, otherwise from `X-Forwarded-Proto` / `X-Forwarded-Host` / `Host`. Claude
Code refuses `http://` and loopback archive URLs, so behind a TLS-terminating
proxy set `AK_EXTERNAL_URL=https://registry.example.com` (or make the proxy
send `X-Forwarded-Proto: https`); otherwise the documents advertise `http://`
archive URLs that Claude Code will not download.

### Claude Code, public repository

```bash
claude plugin marketplace add https://registry.example.com/agentplugins/<repo_key>/claude-marketplace.json
claude plugin install <plugin>@<marketplace_name>
```

or use `/plugin` inside a Claude Code session to browse and install.

### Claude Code, private repository

Claude Code supports two routes.

**1. Settings route (recommended for managed or team settings).** Register the
marketplace in `extraKnownMarketplaces` as a `url` source with an
`Authorization` header (or a `headersHelper` command that prints one):

```json
{
  "extraKnownMarketplaces": {
    "plugins": {
      "source": {
        "source": "url",
        "url": "https://registry.example.com/agentplugins/<repo_key>/claude-marketplace.json",
        "headers": { "Authorization": "Bearer <token>" }
      }
    }
  }
}
```

Claude Code sends those headers on the catalog fetch and on every archive
download on the marketplace URL's origin (same scheme, host and port), so both
the document and the zips are authenticated. This works because the archive
URLs point at the same origin and Artifact Keeper streams the zips itself
instead of redirecting to object storage.

**2. Token-in-path route (no settings edit).** Mint a repository-scoped,
read-only token and put it in the URL:

```bash
curl -X POST -u admin:password \
  -H 'Content-Type: application/json' \
  -d '{"name":"claude-code","scopes":["read:artifacts"],"expires_in_days":90}' \
  https://registry.example.com/api/v1/repositories/<repo_key>/tokens

claude plugin marketplace add https://registry.example.com/agentplugins/t/<token>/<repo_key>/claude-marketplace.json
```

Every archive URL in that document keeps the `/t/<token>/` prefix, so installs
authenticate the same way. **The token is exposed**: it is stored in plain text
in Claude Code's `known_marketplaces.json`, appears in shell history and in
any proxy or server access log that records URLs (Artifact Keeper redacts it in
its own request logs). Use a read-only, repository-scoped token with an expiry,
and revoke it when the machine no longer needs it.

### Cursor, Codex, Copilot / VS Code

None of these agents accept a hosted marketplace URL, so install through the
`ak` CLI, which reads `{name}/index.json`, verifies the SHA-256 and extracts
the plugin into the agent's local plugin directory:

```bash
ak agent plugins install deploy-tools --repo <repo_key> --harness cursor
ak agent plugins install deploy-tools --repo <repo_key> --harness codex
ak agent plugins install deploy-tools --repo <repo_key> --harness vscode
ak agent plugins install deploy-tools --repo <repo_key> --harness claude   # private repo without settings
ak agent plugins list --harness cursor --check-updates
```

The CLI authenticates with the credential stored for the instance, so private
repositories need no token in a URL.

### Publishing

```bash
ak agent plugins publish ./deploy-tools --repo <repo_key> --version 1.2.0
# or with curl
sha=$(sha256sum deploy-tools-1.2.0.zip | cut -d' ' -f1)
curl -X PUT -u user:password -H "X-Checksum-Sha256: $sha" \
  --data-binary @deploy-tools-1.2.0.zip \
  https://registry.example.com/agentplugins/<repo_key>/deploy-tools/1.2.0/deploy-tools-1.2.0.zip
```

## Limits

- Upload size: `MAX_UPLOAD_SIZE` (default 10 GiB). Claude Code itself refuses
  archives over 256 MiB or with a compression ratio above 50x.
- Entries: `MAX_INGEST_ARCHIVE_ENTRIES` (default 10,000); declared uncompressed
  total: `MAX_INGEST_DECOMPRESSED_BYTES` (default 128 MiB); manifest files: 1
  MiB each.
- Remote and virtual repositories, content policies (deny hooks, `bin/`, MCP),
  Gemini CLI and OpenCode installers, and signature verification on install
  are not supported yet.
