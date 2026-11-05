# Agent Plugins repositories: design and delivery plan

Date: 2026-11-03. Status: approved for implementation. Tracking issue: see the
`issues:` line of the changelog fragment that ships with the backend PR.

## 1. What we are building

A first-class `agentplugins` package format: a hosted repository that stores
AI coding-agent plugin bundles (Claude Code, Cursor, Codex, GitHub Copilot /
VS Code, Agent Plugins Standard) as versioned zips and generates the
marketplace index documents those agents and the `ak` CLI consume. It is the
Artifact Keeper counterpart of JFrog Artifactory's "Agent Plugins" package type
(https://docs.jfrog.com/artifactory/docs/agent-plugins-repositories, beta,
updated 2026-09-08).

Goals:

- Publish once, install anywhere: one zip per plugin version, indexed into a
  per-harness marketplace document.
- Claude Code consumes the repository natively with
  `claude plugin marketplace add <url>`; no CLI required.
- Cursor, Codex and Copilot/VS Code are served through `ak agent plugins
  install`, because none of them accept a hosted marketplace URL today.
- Everything that already applies to hosted artifacts applies here: auth and
  repository visibility, scan-on-upload and quarantine holds, publish quota,
  immutability, download statistics, Packages catalog, mesh push replication,
  audit.

Non-goals for this release (tracked as follow-ups in section 12): remote and
virtual repositories, per-repository content policy (deny hooks / bin / MCP),
Skills repositories (ClawHub protocol), Gemini CLI and OpenCode harness
installs, signing and attestation verification on install.

## 2. Research summary

### 2.1 What JFrog ships (the reference behaviour)

- Package type `agentplugins`; local repositories only ("Remote repository
  proxying of plugin ZIP files is not supported").
- Storage path is authoritative: `<name>/<version>/<name>-<version>.zip`.
  Artifactory uses the folder path as name and version, not `plugin.json`.
- Slug regex `^[a-z0-9][a-z0-9-]*$`; versions are SemVer; `latest` is the
  highest SemVer; a version that exists is overwritten only with the overwrite
  permission.
- After upload, Artifactory indexes the zip into every marketplace file whose
  manifest it finds inside: `marketplace.json` (all), `claude-marketplace.json`
  (`.claude-plugin/plugin.json`), `cursor-marketplace.json`
  (`.cursor-plugin/plugin.json` or a conforming root `plugin.json`),
  `codex-marketplace.json` (`.codex-plugin/plugin.json`),
  `vscode-marketplace.json` (conforming root `plugin.json` only). Each file
  lists only the latest version per plugin.
- Claude Code is pointed at
  `https://<HOST>/artifactory/api/agentplugins/<REPO>/claude-marketplace.json`
  (credentials in URL userinfo, which Claude Code does not document; see 2.2).
- Cursor, Codex and VS Code are "CLI install only" via
  `jf agent plugins install <slug> --repo R --harness cursor|codex|claude|vscode`,
  which extracts into `~/.cursor/plugins/local/<slug>`,
  `~/.agents/plugins/local/jfrog/<REPO>/<slug>`,
  `~/.claude/plugins/local/jfrog/<REPO>/<slug>` and
  `~/.copilot/installed-plugins/<REPO>/<slug>` and writes
  `.jfrog/plugin-info.json`.
- No REST API is documented. Xray gating applies to Skills, not plugins.
  Evidence (PGP) signing on publish and verification on install exist in the
  CLI.

### 2.2 What each client actually accepts (verified against vendor docs)

| Client | Manifest | Hosted marketplace URL? | Plugin source types in a marketplace entry | Archive support | Auth for hosted marketplace |
|---|---|---|---|---|---|
| Claude Code | `.claude-plugin/plugin.json` (optional; `skills/`, `commands/`, `agents/`, `hooks/hooks.json`, `.mcp.json`, `.lsp.json`, `bin/`) | Yes: `claude plugin marketplace add https://host/path.json` (`url` marketplace source, 5 MiB, 10 s) | relative path, `github`, `url` (git clone), `git-subdir`, `npm`, `archive` (zip, `sha256`), `command` | `archive`: https only, no loopback, plugin root at zip top or one directory down, 256 MiB, ratio 50x | `headers` / `headersHelper` in `extraKnownMarketplaces`; git credential helpers for git sources. URL userinfo and `.netrc` undocumented |
| Cursor | `.cursor-plugin/plugin.json` (`name` required) or Agent Plugins Standard root `plugin.json` | No. Team marketplaces import git repos (GitHub, GitLab, Bitbucket, Azure DevOps) | n/a | n/a | n/a |
| Codex / ChatGPT | root `plugin.json` with agent-plugins.org `$schema` (preferred); `.codex-plugin/plugin.json` fallback | No. `codex plugin marketplace add` takes `owner/repo`, git URLs, local directories | `local`, `url` (git), `git-subdir`, `npm`; `policy.installation` | none | npm registry config; git auth unspecified |
| Copilot CLI / VS Code | root `plugin.json` with `$schema` 1.0.0 or 1.1.0; legacy root `plugin.json`; VS Code also detects `.claude-plugin/plugin.json` | No. `copilot plugin marketplace add` takes `OWNER/REPO`, git URL, local path; `copilot plugin install ./dir` installs a local directory | relative, `github`, `url` | none | signed-in GitHub token |
| Agent Plugins Standard 1.0 | root `plugin.json` (`$schema`, `name` required; `additionalProperties: false`), `skills/`, `mcp.json`, `com.<vendor>/` extension dirs | not defined | not defined | directory-based by design | not defined |
| Gemini CLI | `gemini-extension.json` | No (GitHub topic gallery, GitHub Releases archives, local path). Docs banner: replaced by Antigravity CLI 2026-06-18 | n/a | `.tar.gz`/`.zip` from GitHub Releases only | n/a |
| OpenCode | none; npm packages or local `.js`/`.ts` | npm only | n/a | npm tarball | npm config |

Consequences that shape the design:

1. Claude Code is the only agent that consumes a hosted marketplace, and only
   with `archive` entries over https. Our generated `claude-marketplace.json`
   must therefore use `{"source":"archive","url":...,"sha256":...}`.
2. Claude Code resolves a plugin's version from `plugin.json` first and the
   marketplace entry second, and re-downloads only when that computed version
   string changes. If a manifest carries a stale `version`, users never see
   updates. We enforce manifest version == path version at publish (JFrog's
   CLI rewrites the manifest for the same reason).
3. Claude Code names the marketplace from the document's `name` field and
   refuses reserved or non-ASCII names; our `name` is derived from the
   repository key and sanitised.
4. Private repositories cannot rely on URL userinfo. We ship a token-in-path
   route (the pattern conda already uses) and document the `headers` route for
   managed settings.
5. Every other harness is installed from a local directory, so the `ak` CLI
   does what `jf agent plugins install` does. The per-harness JSON files exist
   for that CLI, not for the agents themselves.
6. OpenCode plugins are npm packages: an npm repository already serves them.
   Gemini CLI is deprecated upstream; detection only, no installer.

## 3. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | Format key `agentplugins`, enum `RepositoryFormat::AgentPlugins`, Postgres enum value `agentplugins`, label "Agent Plugins", web group "Extensions" | Matches JFrog's package type for migration parity; sits with VS Code and JetBrains in the UI |
| D2 | Route prefix `/agentplugins/{repo_key}/...`; handler `backend/src/api/handlers/agent_plugins.rs`; pure logic in `backend/src/formats/agent_plugins.rs` | Repo convention; pure module keeps the coverage gate satisfiable |
| D3 | Hosted (local) repositories only. Repository creation with `remote` or `virtual` is refused with 400; every handler also refuses non-hosted repos | Same as JFrog; nothing upstream to proxy today. Amended by #5289: a Remote may proxy another Artifact Keeper's hosted repository (its documents are the upstream protocol); Virtual stays refused until its merge rule lands |
| D4 | Path is authoritative: `{name}/{version}/{name}-{version}.zip`. Slug `^[a-z0-9][a-z0-9-]*$`, max 64. Version strict SemVer 2.0 | JFrog layout; SemVer needed for `latest`; the slug is the intersection of Claude, Cursor, agent-plugins.org and JFrog rules |
| D5 | A manifest `name`, when present, must equal the slug; a manifest `version`, when present, must equal the path version; otherwise 400 with an explanatory message | Prevents Claude Code's version precedence from freezing updates; keeps indexes unambiguous |
| D6 | Versions are immutable: re-publishing an existing version is 409. Removal goes through the existing REST artifact delete, and indexes reflect it immediately | Every hosted AK format behaves this way; "immutability and provenance" without an overwrite permission |
| D7 | Indexes are generated on request from the database, not stored as files. ETag plus `If-None-Match` 304. Quarantined or held versions are excluded | Always consistent with deletes and holds; no reindex job |
| D8 | Private repositories for Claude Code: `/agentplugins/t/{token}/{repo}/claude-marketplace.json`, with archive URLs carrying the same prefix, following `conda.rs::token_routes`. Responses are `Cache-Control: private, no-store` | Claude Code has no way to attach a header from `marketplace add`; conda already set the precedent |
| D9 | Harness compatibility is detected from the zip, recorded in metadata, and drives which per-harness index a plugin appears in (table in section 5) | JFrog behaviour, extended with Claude-compatibility for Standard-layout plugins |
| D10 | The `ak` CLI gains `ak agent plugins {publish,install,list,update,uninstall,search,delete}` | Cursor, Codex and Copilot have no hosted-marketplace path |
| D11 | Zip ingestion goes through `util::bounded_archive` with unsafe entry-name rejection | Same hardening the VS Code handler received in #4673 |

## 4. Package model and validation

Plugin root = zip root, or exactly one top-level directory that contains
everything (the two shapes Claude Code's `archive` source accepts). Entry
names are evaluated relative to that root.

Manifest discovery, in priority order (first match provides descriptive
metadata):

| Harness tag | Marker (relative to plugin root) |
|---|---|
| `claude` | `.claude-plugin/plugin.json` |
| `standard` | `plugin.json` whose `$schema` starts with `https://agent-plugins.org/schemas/` |
| `cursor` | `.cursor-plugin/plugin.json` |
| `codex` | `.codex-plugin/plugin.json` |
| `gemini` | `gemini-extension.json` (detection only) |

Publish is refused (400) when:

- no marker is found ("not an agent plugin bundle");
- the zip is malformed, exceeds `bounded_archive` caps, or contains an entry
  that is absolute, contains `..`, a backslash, or is a symlink;
- the filename in the URL is not `{name}-{version}.zip`, the slug fails D4, or
  the version is not SemVer;
- a found manifest is not a JSON object, or its `name` or `version` conflicts
  with the path (D5);
- the plugin root cannot be determined (two or more top-level directories and
  no root marker).

Metadata recorded in `artifact_metadata` (format `agentplugins`):

```json
{
  "name": "deploy-tools",
  "version": "1.2.0",
  "harnesses": ["claude", "standard"],
  "manifest_paths": [".claude-plugin/plugin.json", "plugin.json"],
  "root_prefix": "deploy-tools/",
  "description": "...", "display_name": "...", "author": {"name": "...", "email": "...", "url": "..."},
  "homepage": "...", "repository": "...", "license": "MIT", "keywords": ["..."],
  "components": {
    "skills": ["deploy", "rollback"], "commands": 3, "agents": 1,
    "hooks": true, "mcp": true, "lsp": false, "bin": false
  },
  "sha256": "...", "size_bytes": 12345
}
```

`components` is recorded now so a later content policy (deny hooks, deny
`bin/`, deny MCP) needs no re-index.

Storage key and artifact row follow the newest hosted format's conventions
(`put_staged_body`, `begin_admitted_publish`, `apply_upload_hold_hosted`,
`trigger_scan_on_upload`, `register_published_package`,
`queue_push_sync_tasks_for_upload`, `cleanup_soft_deleted_artifact`), exactly
as `jetbrains.rs::upload_plugin` does. The structural gates in
`proxy_helpers.rs` (scan-on-upload coverage, quota admission) scan every
handler source, so the insert must sit in the function that calls those
helpers.

The object key is content-addressed inside the repository-scoped prefix of
the #2624 scheme: `agentplugins/{repository_id}/{sha256}/{name}/{version}/{name}-{version}.zip`
on a shared cloud namespace, `agentplugins/{sha256}/...` on a filesystem
backend or under `STORAGE_KEY_SCHEME=flat`. The repository segment lets two
repositories on one bucket hold byte-identical archives without tripping the
cross-repository write guard (#5267); the hash keeps a losing concurrent
publish of different bytes from overwriting the winner's object. Downloads
read the key the artifact row recorded, never a recomputed one.

## 5. Harness compatibility and index membership

| Index document | Includes plugins tagged |
|---|---|
| `marketplace.json` | all |
| `claude-marketplace.json` | `claude` or `standard` (skills load; a Standard `mcp.json` is not read by Claude Code, which the doc states) |
| `cursor-marketplace.json` | `cursor` or `standard` |
| `codex-marketplace.json` | `codex` or `standard` |
| `vscode-marketplace.json` | `standard` |

Each per-plugin entry carries the latest SemVer version only (pre-release
versions are ordered by SemVer rules, so `2.0.0-rc.1 < 2.0.0`).

## 6. HTTP API

All routes are mounted under `/agentplugins` in `routes.rs` next to
`/jetbrains`, inside the repository visibility middleware, and the prefix is
added to `guest_access.rs` and the web proxy list.

| Method and path | Auth | Behaviour |
|---|---|---|
| `PUT /agentplugins/{repo}/{name}/{version}/{name}-{version}.zip` | `write:artifacts` (Basic, Bearer, X-API-Key) | Streams the body through `GenericStagedBody::stage_for_repo`, validates (section 4), stores, records. Optional request header `X-Checksum-Sha256`: mismatch is 400. Returns 201 with the JSON below. 409 if the version exists. |
| `GET` / `HEAD` same path | read (visibility) | Streams the zip. `Content-Type: application/zip`, `Content-Disposition: attachment`, `Content-Length`, `X-Checksum-Sha256`, `ETag: "<sha256>"`. Quarantine check and download recording as the other formats. |
| `GET /agentplugins/{repo}/marketplace.json` | read | Unified index (section 7.1) |
| `GET /agentplugins/{repo}/claude-marketplace.json` | read | Claude Code marketplace (section 7.2) |
| `GET /agentplugins/{repo}/{cursor,codex,vscode}-marketplace.json` | read | Same schema as 7.2, filtered by section 5 |
| `GET /agentplugins/{repo}/{name}/index.json` | read | All versions of one plugin, newest first (section 7.3) |
| `GET /agentplugins/t/{token}/{repo}/claude-marketplace.json` and the other read routes under the same prefix | token in path | D8. The token is validated like any API token (repository-scoped read tokens are what the docs recommend). Generated URLs keep the `/t/{token}/` prefix. |

Publish response:

```json
{
  "name": "deploy-tools", "version": "1.2.0",
  "sha256": "6bfa...", "size_bytes": 48213,
  "harnesses": ["claude", "standard"],
  "download_url": "https://ak.example.com/agentplugins/plugins/deploy-tools/1.2.0/deploy-tools-1.2.0.zip",
  "marketplaces": {
    "claude": "https://ak.example.com/agentplugins/plugins/claude-marketplace.json",
    "cursor": "...", "codex": "...", "vscode": "...", "all": ".../marketplace.json"
  }
}
```

Absolute URLs come from the `RequestBaseUrl` extractor, which honours
`AK_EXTERNAL_URL` and otherwise `X-Forwarded-Proto` plus `Host`. The doc tells
operators behind a TLS-terminating proxy to set `AK_EXTERNAL_URL`: Claude Code
refuses `http://` archive URLs.

Error bodies follow the format's existing `(StatusCode, message)` shape; the
messages for D5 must say which manifest conflicted and why it matters.

## 7. Index documents

### 7.1 `marketplace.json` (unified, AK schema, Claude-loadable superset)

```json
{
  "$schema": "https://artifactkeeper.com/schemas/agent-plugins/marketplace-v1.json",
  "name": "plugins",
  "description": "<repository description>",
  "owner": { "name": "Artifact Keeper", "url": "https://ak.example.com" },
  "metadata": { "generated_at": "2026-11-03T18:00:00Z", "repository": "plugins", "plugin_count": 2 },
  "plugins": [
    {
      "name": "deploy-tools",
      "description": "Deployment commands and a review agent",
      "version": "1.2.0",
      "author": { "name": "Example Team" },
      "homepage": "https://example.com/docs", "repository": "https://github.com/example/deploy-tools",
      "license": "MIT", "keywords": ["deployment", "ci"],
      "source": {
        "source": "archive",
        "url": "https://ak.example.com/agentplugins/plugins/deploy-tools/1.2.0/deploy-tools-1.2.0.zip",
        "sha256": "6bfa..."
      },
      "metadata": {
        "harnesses": ["claude", "standard"],
        "size_bytes": 48213,
        "published_at": "2026-11-03T17:55:12Z",
        "versions_url": "https://ak.example.com/agentplugins/plugins/deploy-tools/index.json",
        "components": { "skills": ["deploy"], "commands": 3, "agents": 1, "hooks": true, "mcp": true, "lsp": false, "bin": false }
      }
    }
  ]
}
```

AK-specific data lives under `metadata`, the free-form object Claude Code
documents as never read, so the unified file is itself a valid Claude Code
marketplace.

### 7.2 `claude-marketplace.json` (and the per-harness variants)

Same document as 7.1 restricted per section 5, with `name` derived from the
repository key by one rule shared verbatim by the backend and the web UI
(both compute it, and `plugin@<name>` hints must agree): repository keys are
already limited to ASCII letters, digits, `.`, `_`, `-`, with no leading `.`
or `-` and no `..`, which satisfies Claude Code's naming rule except for two
cases, so (1) a key whose first character is not a letter or digit (a leading
`_`) is prefixed with `ak-`, and (2) a key equal to one of Claude Code's
reserved marketplace names (`claude-plugins-official`, `claude-code-plugins`,
`anthropic-marketplace`, `knowledge-work-plugins`, `first-party-plugins`,
`claude-community`, `inline`, `builtin`, `skills-dir`, `synced`,
`claude-plugin-test`, `npm`, `pip`, `uv`, `cargo`, `github`, `gh`) or
starting with `claudeai-` gets the suffix `-ak`. Every other key is used
unchanged. The publish response and the UI show the effective name.
`owner.name` is required, and `$schema` is omitted. The entry's `version` always equals the
path version, which equals any manifest version (D5).

### 7.3 `{name}/index.json`

```json
{
  "name": "deploy-tools",
  "latest": "1.2.0",
  "versions": [
    { "version": "1.2.0", "sha256": "...", "size_bytes": 48213, "harnesses": ["claude","standard"], "published_at": "...", "url": "https://.../deploy-tools-1.2.0.zip" },
    { "version": "1.1.0", "...": "..." }
  ]
}
```

## 8. Authentication and private repositories

- Public repository: plain URLs; anonymous reads already pass the visibility
  middleware.
- Private repository, Claude Code, two supported routes:
  1. Settings route (recommended for managed or team settings): register the
     marketplace in `extraKnownMarketplaces` as a `url` source with
     `headers: {"Authorization": "Bearer <token>"}` or a `headersHelper`
     command. Claude Code sends those headers on the `marketplace.json` fetch
     and on every archive download on the same scheme, host and port
     (host-marketplace docs: "Archive downloads on the marketplace URL's
     origin"), so the catalog and the zips are both authenticated. The
     generated archive URLs must therefore stay on the marketplace's origin:
     the download route must not redirect to object storage on another
     origin for this format (a cross-origin redirect drops the headers), so
     the handler streams the zip itself rather than using a presigned
     redirect.
  2. URL route (no settings edit): `claude plugin marketplace add
     https://ak.example.com/agentplugins/t/<read-token>/plugins/claude-marketplace.json`
     with a repository-scoped read-only token minted from
     `POST /api/v1/repositories/{key}/tokens`. The doc warns that the token
     lands in Claude Code's `known_marketplaces.json` and in server access
     logs, and recommends an expiring token.
- Private repository, other harnesses: the `ak` CLI uses the instance's stored
  credential.
- Publish: `write:artifacts` scope on the repository, same as every hosted
  format.

## 9. `ak` CLI (`artifact-keeper-cli`)

`ak agent plugins <subcommand>`; the `agent` group leaves room for a later
`ak agent skills`.

| Subcommand | Behaviour |
|---|---|
| `publish <dir> --repo R [--version V] [--dry-run]` | Discovers manifests (section 4 rules, locally), fails on slug or SemVer violations, rewrites `version` in every found manifest when `--version` is given, zips with the plugin at the archive root (deterministic ordering, no symlinks), computes SHA-256, PUTs with `X-Checksum-Sha256`, prints the publish response and the Claude Code `marketplace add` command. `--dry-run` prints the entry list and stops. |
| `install <slug> --repo R --harness claude[,cursor,codex,vscode] [--version latest\|X] [--path DIR]` | Resolves the version from `{name}/index.json`, downloads the zip, verifies SHA-256, refuses zips whose entries escape the target (defence in depth), extracts the plugin root into the harness location, writes `.ak/plugin-info.json` (`instance`, `repo`, `slug`, `version`, `sha256`, `harness`, `installed_at`), runs the harness post-step. |
| `list --harness H [--check-updates]` | Reads `.ak/plugin-info.json` under the harness locations; `--check-updates` compares against `{name}/index.json` (`current`, `behind`, `ahead`, `unknown`). |
| `update <slug>\|--all --harness H` | Re-install when behind. |
| `uninstall <slug> --harness H` | Removes the directory and the marketplace entry it wrote. |
| `search <query> --repo R [--harness H]` | Filters `marketplace.json` client side (name, description, keywords). |
| `delete <slug> --version V --repo R [--yes]` | Calls the existing REST artifact delete. |

Harness locations (global scope), mirroring JFrog with an `ak` namespace:

| Harness | Location | Post-step |
|---|---|---|
| `claude` | `~/.claude/plugins/local/ak/<repo>/<slug>`; a marketplace directory `~/.claude/plugins/local/ak/<repo>/` holding `.claude-plugin/marketplace.json` (`name: "ak-<repo>"`, relative sources) | if `claude` is on PATH: `claude plugin marketplace add <dir>` (or `update`), then `claude plugin install <slug>@ak-<repo>`; otherwise print the two commands |
| `cursor` | `~/.cursor/plugins/local/<slug>` | none (auto-discovered after reload) |
| `codex` | `~/.agents/plugins/local/ak/<repo>/<slug>` plus a marketplace directory with `.agents/plugins/marketplace.json` (`source: {"source":"local","path":...}`) | if `codex` is on PATH: `codex plugin marketplace add <dir>`; otherwise print it |
| `vscode` | if `copilot` is on PATH: `copilot plugin install <extracted dir>`; otherwise copy to `~/.copilot/installed-plugins/ak-<repo>/<slug>` | print the VS Code "Chat: Manage Plugin Marketplaces" hint |

`--path DIR` installs to `DIR/<slug>` and skips post-steps. A warning is
printed when the chosen harness is not in the plugin's `harnesses` list, but
the install proceeds (Claude-layout plugins do load in VS Code, for example).

Tests: unit tests for manifest discovery, slug and SemVer checks, zip
building, harness path mapping and `plugin-info.json` round trip (pure
functions, temp dirs); `tests/e2e_agent_plugins.rs` (`#[ignore]`, needs the
E2E backend) covering publish, install `--path`, list, update and delete.

## 10. Web and site

`artifact-keeper-web`: `constants.ts` entry `{ value: "agentplugins", label:
"Agent Plugins", group: "Extensions" }` plus its test; `middleware.ts` proxy
prefix `/agentplugins`; the format unions in `types/index.ts` and
`types/packages.ts`; `package-utils.ts` install snippet
(`ak agent plugins install <name> --repo <repo> --harness claude`); setup page
instructions (Claude Code `marketplace add` URL, private token URL, `ak`
commands); `repo-tabs.ts` so the repository gets the Packages tab.

`artifact-keeper-site`: `src/data/packages.ts` entry; a row in
`package-formats.mdx`; a new guide `docs/guides/agent-plugins.mdx` with the
per-client setup from section 8 and 9.

Backend repo docs: `docs/agent-plugins.md` (protocol reference in the style of
`docs/bazel.md`), this plan under `docs/plans/`, and a changelog fragment
(`section: Added`).

## 11. Testing and validation

Backend (`artifact-keeper`):

- Unit tests in `formats/agent_plugins.rs`: root detection (root vs one
  directory down vs ambiguous), each manifest marker, Standard `$schema`
  detection, slug and SemVer rules, D5 conflicts with exact messages, unsafe
  entry names, component inventory, latest-version selection with
  pre-releases, index builders for all five documents and `index.json`,
  Claude `name` sanitisation, token-prefix URL generation.
- Handler inline tests (DB-backed, the pattern `jetbrains.rs` and `bazel.rs`
  use) under the shard `scripts/ci/test-shards.py` assigns: publish 201 with
  response fields, 409 on re-publish, 400 cases, download headers and bytes,
  index documents end to end, ETag 304, quarantine exclusion, token-in-path
  200 versus 401 without token, non-hosted repo refusal. These run in the
  unit-test job, which is the coverage run, so they are what satisfies the
  70 percent gate on changed lines.
- Integration target `backend/tests/agent_plugins_tests.rs` (`#[ignore]`d,
  wired into the Tier 2 `--test` list in `ci.yml`, otherwise
  `ci_test_surface` goes red) for the full publish, index, download, delete,
  re-index flow through the real router.
- `scripts/ci/test-shards.py check`, `cargo sqlx prepare --workspace --
  --all-targets` (the `.sqlx` cache must be regenerated for new queries),
  `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo nextest run --workspace --lib --bins` with `DATABASE_URL` and
  `AK_TESTS_REQUIRE_DB=1`, and the jscpd 3 percent duplication limit (share
  one index generator for the five documents).

Release gate (`artifact-keeper-test`):

- `tests/formats/test-agentplugins.sh`: the happy path with three fixtures
  built with `zip` (Claude layout; Standard layout with `mcp.json`; a
  multi-harness bundle wrapped in a top-level directory), publish, 409,
  download byte and checksum equality, every index document asserted with
  `jq`, second version and latest selection, `index.json`, REST delete and
  re-index. Optional `ak` CLI steps when an `ak` with `agent plugins` is on
  PATH (the gate installs the released CLI since artifact-keeper-test#708):
  `publish --dry-run`, `install --path`, `plugin-info.json`.
- `tests/formats/test-agentplugins-conformance.sh`: Claude Code schema rules
  (marketplace `name` regex, entry `name` regex, `source.source == "archive"`,
  `sha256` is 64 hex and matches the downloaded bytes, `version` equals the
  path version, no relative sources), per-harness membership table from
  section 5, negative publishes (no manifest, name conflict, version
  conflict, traversal entry, bad SemVer, wrong filename, remote repository
  creation refused), private repository via token-in-path (200 with token,
  401 or 404 without; archive URLs keep the prefix), `AK_EXTERNAL_URL` not
  asserted (environment dependent).
- Both scripts gate on backend capability using `require_feature` /
  `_feature_min_version` from `tests/lib/common.sh` so a maintenance-line
  candidate skips as not applicable instead of failing under `RELEASE_GATE=1`.
  Both are named in the `generic-protocol` batch of `format-tests.yml` and
  `release-gate.yml`; `scripts/check-formats-registration.sh` must pass.
  README batch table and `docs/format-coverage-audit.md` get a row.
- Real Claude Code verification needs an https endpoint, which the gate does
  not provide: documented as a manual step against a TLS deployment
  (`claude plugin marketplace add`, `/plugins`, `claude plugin install`).

CLI (`artifact-keeper-cli`): unit tests plus the `#[ignore]` e2e file; the e2e
file runs once a backend image with this feature is published to `ghcr.io`.

## 12. Delivery plan

Five pull requests, each from a shallow clone, each passing its repository's
checks before it is opened. Nothing is merged by the agents; merging stays a
human step after CI is green.

| PR | Repository | Branch | Scope | Depends on |
|---|---|---|---|---|
| A | artifact-keeper | `feat/agent-plugins` | sections 3 to 8, 11 backend, docs, plan, fragment, migration | none |
| B | artifact-keeper-test | `feat/agent-plugins` | section 11 release gate | validated against PR A's branch build |
| C | artifact-keeper-cli | `feat/agent-plugins` | section 9 | validated against PR A's branch build |
| D | artifact-keeper-web | `feat/agent-plugins` | section 10 web | none (format key is fixed) |
| E | artifact-keeper-site | `feat/agent-plugins` | section 10 docs | none |

Merge order: A, then B and C (B's `ak` steps skip until a CLI release
contains C), D and E any time after A.

Follow-ups to file after A merges: remote repositories proxying a
GitHub-hosted marketplace (clone and re-archive), virtual repositories
merging hosted members, per-repository content policy (`deny_hooks`,
`deny_bin`, `deny_mcp`, `require_harness`), attestation verification in
`ak agent plugins install`, Skills repositories (ClawHub v1 API, revisits
#1644 now that a client protocol exists), Gemini harness installer if
Antigravity CLI keeps the extension format.

## 13. Risks and open points

- Claude Code behaviour is documented, not tested against a live https
  endpoint in CI. The first release note should ask for a manual verification
  on the demo instance.
- Repository keys containing characters Claude Code rejects produce a
  sanitised marketplace `name`; the publish response and the UI show the
  effective name.
- Token-in-path exposes the token in URLs. The doc states the exposure and
  recommends read-only repository-scoped tokens with an expiry.
- Codex's and Cursor's local marketplace formats are documented by example
  only; the CLI post-steps print the manual command when the agent binary is
  absent so a format change degrades to instructions, not a broken install.
