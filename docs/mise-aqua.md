# GitHub release mirrors for mise

Use a `github` remote repository to cache GitHub release downloads. The `mise`
and `aqua` formats are aliases with the same behaviour, available under their own
names for discovery. All three use the existing generic HTTP handler at
`/general/<repository>/…`. Ordinary `generic` repositories keep their existing
cache and write behaviour.

This integration supports mise's aqua backend through URL replacements. It does
not add a protocol for the standalone aqua CLI.

## Create an authenticated mirror

Create a private remote repository with the GitHub origin as its upstream:

```bash
curl -u "$AK_USERNAME:$AK_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "key": "github-releases",
    "name": "GitHub Releases",
    "format": "github",
    "repo_type": "remote",
    "upstream_url": "https://github.com",
    "is_public": false
  }' \
  'https://<artifact-keeper-host>/api/v1/repositories'
```

Grant read access only to the users or CI identities that should use this mirror.
If you configure a GitHub token as upstream authentication, **every reader of the
mirror must be trusted to access everything that token can read**. These formats
reuse generic forwarding and do not impose a GitHub path allow-list. Repository
access protects cached responses as well as cache misses, but does not reproduce
GitHub's per-user permissions. Do not make a token-backed mirror public.

Use separate mirrors and narrowly scoped upstream tokens for separate trust
groups. Artifact Keeper credentials authenticate clients to the mirror; a
GitHub token, when needed, belongs in the repository's upstream-auth settings.
The existing HTTP client strips Authorization when a redirect changes origin,
including GitHub's redirects to signed object-storage download URLs.

## Configure mise

Use mise with lockfile support (2026.3 or newer). In a **private**, trusted mise
configuration file, add the following replacement. URL-encode the username and
Artifact Keeper token before inserting them, and do not commit the credentials:

```toml
[settings]
experimental = true
lockfile = true

[settings.url_replacements]
'regex:^https://github\.com/([^/]+)/([^/]+)/releases/download/(.+)' = 'https://YOUR_USERNAME:YOUR_TOKEN@<artifact-keeper-host>/general/github-releases/$1/$2/releases/download/$3'
```

Trust the configuration with `mise trust <path-to-config>`. Only redirect to an
Artifact Keeper instance you trust. For a project using jq, resolve the lockfile
while online and warm the mirror:

```bash
mise use aqua:jqlang/jq@1.7.1
mise lock
mise install --locked
```

Commit `mise.toml` and `mise.lock`, with credentials kept in the private
configuration. Locked installs use the resolved download URL and checksum,
avoiding GitHub API release lookups. Each required platform's asset must have
been downloaded through the mirror before an outage. Provision mise itself in
the runner image; the mirror does not bootstrap mise.

## Cache behaviour

For `github`, `mise` and `aqua` repositories, paths matching
`<owner>/<repo>/releases/download/<tag>/<asset>` have a **seven-day finite
freshness lifetime** by default. Checksum files use the same policy. An existing
repository cache-lifetime override takes precedence:

```bash
curl -u "$AK_USERNAME:$AK_TOKEN" -X PUT \
  -H 'Content-Type: application/json' \
  -d '{"cache_ttl_seconds": 86400}' \
  'https://<artifact-keeper-host>/api/v1/repositories/github-releases/cache-ttl'
```

Fresh entries are served without upstream requests. On expiry, the proxy checks
whether the content changed, using its existing conditional revalidation when
an ETag is available and fetching again otherwise. Replaced release files are
therefore noticed after expiry rather than silently frozen forever. A checksum
cached beside an asset proves neither that upstream still serves those bytes nor
that a release cannot be replaced. A committed lockfile can detect different
bytes from those originally pinned; it does not prevent upstream changes.

The existing stale-on-error behaviour remains in effect. Seven days is measured
from the last successful cache fill or revalidation, **not from the start of an
outage**. We do not promise an unlimited outage window. Use the cache-purge API
when an immediate refresh is required.

Other paths, including `releases/latest/download/…` and GitHub API metadata, retain
the conservative short lifetime. This change does not alter hosted-file deletion
or replacement rules.

## Installs without lockfiles

Unlocked installs can query `api.github.com` even when a tool version is pinned.
For those installs, either allow direct API access or create a second **private**
remote named `github-api`, with `format: "github"` and
`upstream_url: "https://api.github.com"`. Add this rule to the same private config:

```toml
[settings.url_replacements]
'regex:^https://api\.github\.com/(.*)' = 'https://YOUR_USERNAME:YOUR_TOKEN@<artifact-keeper-host>/general/github-api/$1'
```

Combine both rules under one `[settings.url_replacements]` table. The API mirror
has the same access restrictions as the release mirror, particularly if supplied
with a GitHub token. API responses keep the existing short cache lifetime and
error fallback. Longer API caching is tracked in
[issue #3658](https://github.com/artifact-keeper/artifact-keeper/issues/3658).

## Validation

The backend tests cover format isolation, finite expiry, replacement, unchanged
responses, missing validators, cache-lifetime overrides and upstream errors. The
cross-origin redirect test characterises existing credential stripping.

The companion `artifact-keeper-test` suite exercises authenticated mirrors and
mise locked installs using a controlled upstream, including a warm-cache install
after that upstream stops serving the asset. This avoids treating two identical
GitHub downloads as proof of a cache hit.
