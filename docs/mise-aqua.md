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

## 1. Create the proxy repository

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
"regex:^https://github\\.com/([^/]+)/([^/]+)/releases/download/(.+)" = "https://<host>/general/github-releases/$1/$2/releases/download/$3"
```

That's the whole client integration. `mise install aqua:jqlang/jq@1.7.1` (and
every other aqua-backed tool) now downloads its release assets through
Artifact Keeper.

For a **private** repository, put credentials in the replacement URL
(`https://user:token@<host>/...`) — but note mise sends any credentials
attached to the original URL to the replacement host too, so only redirect to
hosts you trust.

## Optional: GitHub token for rate limits

If the proxy itself gets rate-limited by GitHub (shared CI egress IPs), attach
a GitHub PAT to the repository as upstream auth (type `bearer`) via the
repository's upstream-auth API. The token is sent to `github.com` only:
GitHub redirects asset downloads to S3-signed
`objects.githubusercontent.com` URLs, and the proxy's HTTP client strips the
`Authorization` header on that cross-origin hop (S3 would reject the request
otherwise, and the token must not leak there). This behavior is pinned by a
regression test.

## Scope and limitations

- **Only release-asset downloads are proxied.** mise still talks to GitHub
  directly for two side channels: version listing (`api.github.com`) and aqua
  registry metadata. Pin exact tool versions if you want installs to work
  without those (already-baked registry metadata covers most tools).
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
