# mise (aqua backend) GitHub-Releases proxy

[mise](https://mise.jdx.dev) installs most CLI tools through its
[aqua backend](https://mise.jdx.dev/dev-tools/backends/aqua.html), and aqua
packages are overwhelmingly `github_release` type: plain HTTPS downloads from

```text
https://github.com/<owner>/<repo>/releases/download/<tag>/<asset>
```

There is no aqua-specific registry protocol to implement. Artifact Keeper acts
as a caching mirror for those downloads using a **`generic` remote
repository** pointed at `https://github.com`, combined with mise's
[`url_replacements`](https://mise.jdx.dev/url-replacements.html) setting
(mise ≥ v2025.9.3), which rewrites GitHub download URLs to your registry.

Benefits: one shared cache per team/CI fleet instead of every machine hitting
GitHub, resilience to GitHub outages for already-cached assets, and no
per-developer GitHub rate-limit exhaustion for downloads.

## 1. Create the proxy repositories

Two `generic` remotes: one for the release assets, one for the GitHub API.
The second matters more than it looks — mise resolves the release **tag** via
`api.github.com` even for exactly-pinned versions, so without it a GitHub API
outage or rate-limit still breaks installs whose assets are fully cached.

```bash
curl -u admin:PASSWORD -X POST https://<artifact-keeper-host>/api/v1/repositories \
  -H "Content-Type: application/json" \
  -d '{
    "key": "github-releases",
    "name": "GitHub Releases Proxy",
    "format": "generic",
    "repo_type": "remote",
    "upstream_url": "https://github.com",
    "is_public": true
  }'

curl -u admin:PASSWORD -X POST https://<artifact-keeper-host>/api/v1/repositories \
  -H "Content-Type: application/json" \
  -d '{
    "key": "github-api",
    "name": "GitHub API Proxy",
    "format": "generic",
    "repo_type": "remote",
    "upstream_url": "https://api.github.com",
    "is_public": true
  }'
```

Any path requested under the repository is fetched from the same path on
`github.com`, streamed to the client, and cached:

```text
https://<host>/general/github-releases/jqlang/jq/releases/download/jq-1.7.1/jq-linux-amd64
                                       └────────────── same path as on github.com ─────────┘
```

Release-asset paths of this exact shape
(`<owner>/<repo>/releases/download/<tag>/<asset>`) are recognised as
version-pinned and cached **immutably** — after the first fetch they are
served from cache forever without revalidating against GitHub. Other paths
proxied through a generic repository keep the conservative short-TTL default.
If a release asset is ever re-uploaded upstream under the same tag (rare, and
mise verifies checksums client-side anyway), purge it via the repository
cache-purge API.

## 2. Point mise at the proxy

In `~/.config/mise/config.toml` (or any mise settings file):

```toml
[settings.url_replacements]
# Release asset downloads (order matters: this must come before any broader
# github.com pattern you add yourself — first match wins)
"regex:^https://github\\.com/([^/]+)/([^/]+)/releases/download/(.+)" = "https://<host>/general/github-releases/$1/$2/releases/download/$3"
# GitHub API (release/tag resolution)
"regex:^https://api\\.github\\.com/(.*)" = "https://<host>/general/github-api/$1"
```

That's the whole client integration. `mise install aqua:jqlang/jq@1.7.1` (and
every other aqua-backed tool) now resolves and downloads through Artifact
Keeper.

For a **private** repository, put credentials in the replacement URL
(`https://user:token@<host>/...`) — but note mise sends any credentials
attached to the original URL to the replacement host too, so only redirect to
hosts you trust.

## GitHub token for rate limits

The `github-api` repository should almost always carry a GitHub PAT as
upstream auth (type `bearer`, via the repository's upstream-auth API):
unauthenticated `api.github.com` requests are limited to 60/hour per IP, and
the proxy concentrates a whole fleet's requests onto one egress IP. The
5-minute response cache absorbs most of the load, but any varied toolset will
exceed 60 distinct lookups an hour. The `github-releases` repository usually
works fine anonymously; add a PAT there only if asset downloads themselves
get throttled.

Tokens are scoped per repository and sent to the configured upstream host
only. In particular, GitHub redirects asset downloads to S3-signed
`objects.githubusercontent.com` URLs, and the proxy's HTTP client strips the
`Authorization` header on that cross-origin hop (S3 would reject the request
otherwise, and the token must not leak there). This behavior is pinned by a
regression test.

## Surviving GitHub outages

With both repositories and both replacement rules in place, a runner with a
**cold client cache** can install tools while GitHub is completely down,
provided:

1. **Versions are pinned exactly** (`aqua:jqlang/jq@1.7.1`, not `latest` or
   `1.7`). Partial versions need a live version *list*; exact pins only need
   the tag-lookup JSON, which the proxy caches.
2. **The proxy cache is warm** — each tool@version was installed through the
   proxy at least once before the outage. Release assets then serve from
   cache indefinitely (they are classified immutable and never revalidate).
   A scheduled job that runs `mise install` for your standard toolset through
   the proxy is cheap insurance.
3. **The outage is shorter than the API-metadata window.** The
   `api.github.com` JSON is an unrecognised path shape to the cache
   classifier, so it gets the conservative default: a 5-minute fresh TTL plus
   a 1-hour stale-if-error grace during which stale entries are served when
   upstream is unreachable. Beyond roughly an hour, cold-client installs fail
   again even though the assets are still cached; runners that already have
   the tool installed keep working regardless. Extending this window is
   tracked in issue #3658.
4. **mise itself is baked into the runner image** — its own install/update
   comes from GitHub and is not covered by this recipe.

aqua registry metadata is not a dependency: mise ships with the standard
registry baked into its binary, so nothing is fetched from
`raw.githubusercontent.com` during a normal install. This envelope was
established empirically — a full simulated outage (every GitHub hostname
black-holed on the client, both proxy upstreams pointed at an unreachable
host) with a fresh mise client installing a pinned tool entirely from the
proxy cache, including the stale-if-error path for expired API entries.

## Scope and limitations

- The standalone `aqua` CLI (aquaproj) has no `url_replacements` equivalent
  and is not supported by this recipe — use mise's aqua backend.
- A non-GitHub upstream proxied through a *generic* repository whose paths
  happen to match `<a>/<b>/releases/download/<c>/<d>` would also be cached
  immutably. Use a dedicated repository key per upstream (as shown above) and
  this cannot arise.
- Asset names needing percent-encoding are untested through the passthrough
  path; GitHub release assets in practice use safe characters.

## End-to-end test

`scripts/native-tests/test-mise.sh` exercises this recipe against a running
instance: creates the repository, downloads a real release asset through the
proxy with checksum verification, and (when `mise` is on `PATH`) runs a real
`mise install aqua:jqlang/jq@1.7.1` through `url_replacements`.
