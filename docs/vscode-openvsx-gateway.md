# VS Code/Open VSX gateway dogfood guide

This is **experimental Slice 1 prototype behavior**, not stable Artifact Keeper
support. It describes using Artifact Keeper (AK) as a pull-through
[Open VSX](https://open-vsx.org/) extension-gallery gateway. It lets supported
clients discover, install, and update extensions through AK; the client does
not need direct gallery or asset/CDN access for those actions.

It is **not** a runtime network sandbox: an installed extension can still make
its own network connections.

## Supported scope

| Area | Slice 1 position |
| --- | --- |
| Upstream | Open VSX gallery adapter only. A Remote repository's `upstream_url` must be the adapter root, for example `https://open-vsx.org/vscode/gallery`. Do not use the Open VSX site root, its native `/api` path, or a Microsoft Marketplace URL. |
| Client read access | The repository must be **public** and readable anonymously. Private repositories, bearer-token configuration, and token-bearing gallery URLs are unsupported. Never put an AK credential in a configured URL. |
| Dogfood clients | VSCodium and code-server. Official VS Code is conditional enterprise-desktop support; see below. |
| Virtual repositories | Unsupported for this prototype's gallery paths. There is no query-result merge across members; point a client at a Remote repository. |
| Microsoft Marketplace | Deferred. It needs a separate provider, licensing, and terms decision. |

## Create the gateway repository

Create a **public VS Code Remote** repository in AK and give it a stable key,
such as `openvsx`. Its upstream must be the gallery adapter root:

```text
https://open-vsx.org/vscode/gallery
```

For a self-hosted Open VSX instance, use that instance's equivalent
`/vscode/gallery` adapter root. AK owns the URLs configured in the client:

```text
https://ak.example.test/vscode/openvsx/gallery/manifest
https://ak.example.test/vscode/openvsx/gallery
https://ak.example.test/vscode/openvsx/item
https://ak.example.test/vscode/openvsx/gallery/{publisher}/{name}/latest
```

The first URL is the official VS Code manifest endpoint. The second is the
gallery service root used by VSCodium and code-server. The remaining URLs are
the item and latest-version templates. Gallery queries are POSTs beneath the
service root; AK rewrites returned asset URLs so VSIX and gallery-asset
delivery remain on AK.

## Configure a client

Set `AK_URL` and `AK_REPO` below to your public AK origin and repository key.
Use an HTTPS origin in real deployments.

### Cross-origin browser deployments

AK remains same-origin by default. If a browser-based code-server deployment
or another client sends gallery requests from a different origin, add that
**exact** origin to `CORS_ORIGINS` on AK before testing. For example, a
code-server UI at `https://code.example.test` needs:

```sh
export CORS_ORIGINS='https://code.example.test'
```

Do not use a wildcard origin or put an AK credential in a gallery URL. If a
desktop client presents an `Origin` header, record that exact value from its
network trace and add it to the configured list as well.

### VSCodium

For a disposable dogfood session, launch VSCodium with these environment
variables:

```sh
export AK_URL='https://ak.example.test'
export AK_REPO='openvsx'
export VSCODE_GALLERY_SERVICE_URL="$AK_URL/vscode/$AK_REPO/gallery"
export VSCODE_GALLERY_ITEM_URL="$AK_URL/vscode/$AK_REPO/item"
export VSCODE_GALLERY_EXTENSION_URL_TEMPLATE="$AK_URL/vscode/$AK_REPO/gallery/{publisher}/{name}/latest"
export VSCODE_GALLERY_LATEST_URL_TEMPLATE="$AK_URL/vscode/$AK_REPO/gallery/{publisher}/{name}/latest"
codium
```

For a persistent per-user configuration, create `product.json` in VSCodium's
user configuration directory (`%APPDATA%\\VSCodium` on Windows,
`~/Library/Application Support/VSCodium` on macOS, or `$XDG_CONFIG_HOME/VSCodium`
when `XDG_CONFIG_HOME` is set, otherwise `~/.config/VSCodium`, on Linux):

```json
{
  "extensionsGallery": {
    "serviceUrl": "https://ak.example.test/vscode/openvsx/gallery",
    "itemUrl": "https://ak.example.test/vscode/openvsx/item",
    "extensionUrlTemplate": "https://ak.example.test/vscode/openvsx/gallery/{publisher}/{name}/latest",
    "latestUrlTemplate": "https://ak.example.test/vscode/openvsx/gallery/{publisher}/{name}/latest",
    "controlUrl": ""
  }
}
```

Restart VSCodium after changing either form of configuration. VSCodium documents
these environment variables and the `product.json` override in its
[extension-gallery guide](https://github.com/VSCodium/vscodium/blob/master/docs/extensions.md).
`latestUrlTemplate` is required as well as `extensionUrlTemplate`: omitting it
can let an update lookup fall back to Open VSX directly.

### code-server

Pass the gallery JSON to the code-server process (for example, through its
systemd unit, container environment, or shell before starting it):

```sh
export EXTENSIONS_GALLERY='{
  "serviceUrl": "https://ak.example.test/vscode/openvsx/gallery",
  "itemUrl": "https://ak.example.test/vscode/openvsx/item",
  "extensionUrlTemplate": "https://ak.example.test/vscode/openvsx/gallery/{publisher}/{name}/latest"
}'
code-server
```

Restart the process after changing the value. `EXTENSIONS_GALLERY` maps directly
to the `extensionsGallery` portion of `product.json`; see the
[code-server FAQ](https://coder.com/docs/code-server/FAQ#how-do-i-use-my-own-extensions-marketplace).
Current code-server derives its latest-version lookup as
`{serviceUrl}/vscode/{publisher}/{name}/latest`; AK serves that Remote-only
alias in addition to VSCodium's `latestUrlTemplate` route.

### Official Visual Studio Code

Official VS Code is not configured with the VSCodium environment variables.
For eligible **desktop** installations running VS Code 1.99 or later, deploy
the enterprise `ExtensionGalleryServiceUrl` policy with this manifest URL:

```text
https://ak.example.test/vscode/openvsx/gallery/manifest
```

This is conditional support, not a general user preference: current VS Code
requires the enterprise policy path, an appropriate signed-in account and
enterprise entitlement, and a supported desktop policy deployment. Validate it
with an entitled account before claiming it works for an organization. It does
not establish a gallery bearer-token mechanism, and it does not cover VS Code
Server or VS Code for the Web.

Deploy the policy through Windows Group Policy, a macOS configuration profile,
or the supported Linux policy file as appropriate. After restarting VS Code,
run **Developer: Policy Diagnostics** and confirm that the policy is applied;
check **Show Window Log** for policy or manifest errors. See the official
[enterprise policy documentation](https://code.visualstudio.com/docs/enterprise/policies)
for the OS-specific deployment and diagnostics details. `extensions.allowed`
is useful defense in depth, but it does not replace the AK delivery boundary.

## Reusable dogfood harness and reviewed candidate

The repository includes `scripts/dogfood-vscode-openvsx.sh`. It uses isolated
client profiles and permits only `redhat.vscode-yaml`, the reviewed candidate
for this prototype. It is a genuine Open VSX extension from the established
Red Hat publisher; do not replace it with a lookalike or arbitrary extension.

Set a durable local-only artifact directory outside the public repository, then
run the protocol preflight before starting either client:

```sh
export AK_URL='https://ak.example.test'
export AK_REPO='openvsx'
export DOGFOOD_RUN_DIR="$HOME/ak-vscode-dogfood/$(date +%F)"
scripts/dogfood-vscode-openvsx.sh probe
```

`probe` records the manifest, a real Open VSX-compatible exact-ID query, the
latest lookup, and the resolved versions. It fails if any client-visible asset
URL escapes AK. For a browser code-server deployment, also set the exact UI
origin and retain the successful preflight headers:

```sh
export CORS_ORIGIN='https://code.example.test'
scripts/dogfood-vscode-openvsx.sh probe
```

Use `vscodium-ui` and `code-server-ui` for the manual Extensions-view search.
Use distinct `cold` and `warm` labels for CLI installs so no client profile or
VSIX cache is shared between them:

```sh
scripts/dogfood-vscode-openvsx.sh install-vscodium cold
scripts/dogfood-vscode-openvsx.sh install-vscodium warm
scripts/dogfood-vscode-openvsx.sh install-code-server cold
scripts/dogfood-vscode-openvsx.sh install-code-server warm
```

The first install must coincide with an AK asset-cache miss and the second with
an AK asset-cache hit; record the corresponding server telemetry/log evidence.
For a deterministic update-path test, select a prior `redhat.vscode-yaml`
version listed in `resolved-versions.tsv`, set `UPDATE_FROM_VERSION`, and run
the matching `update-*` command. It seeds that older version then forces the
client's normal latest-resolution install path. This proves the gateway update
lookup/delivery path, not a background auto-update timer.

## Dogfood verification

1. Confirm the client can reach AK and trusts its certificate:

   ```sh
   curl --fail --show-error --silent \
     https://ak.example.test/vscode/openvsx/gallery/manifest | jq .
   ```

2. In the Extensions view, search for a known public Open VSX extension. AK
   access logs should show a `POST` under
   `/vscode/openvsx/gallery/extensionquery`; the client must not call
   `open-vsx.org` directly.
3. Install the extension. This first install is the cache-miss check: observe
   AK obtain the asset from its upstream, while the client only contacts AK.
   Confirm the VSIX request is to an AK `/vscode/openvsx/...` gallery route.
4. Uninstall the extension locally and install it again. This is the cache-hit
   check: it must still succeed with the client talking only to AK. Verify the
   expected cache hit in AK telemetry/logs or object storage.
5. Exercise an available update (or use a test extension with a newer Open VSX
   version), then run **Update** from the Extensions view. Confirm the client
   uses AK for the latest-version lookup and the replacement VSIX.

Record the AK version, client version, extension ID/version/target platform,
and cache miss/hit evidence with the dogfood result. A gallery response is not
cached in Slice 1; pull-through caching applies to delivered assets.

### Network and firewall check

After endpoint configuration is working, apply an egress rule to the **test
client only** that denies all new TCP 80/443 destinations except the resolved
AK address(es), while preserving its configured DNS path. This is stronger than
only blocking `open-vsx.org`; it also covers the current Open VSX asset host
`openvsx.eclipsecontent.org` and any future CDN hostname. Do **not** apply the
restriction to AK itself: AK needs outbound access to its configured upstream
on a cache miss. Repeat the search/install/update walkthrough and retain the
client-scoped firewall policy/deny logs plus a packet or syscall trace. Set
`TRACE_NETWORK=1` for the harness CLI runs to retain an `strace` network record
alongside those firewall artifacts. The expected split is:

```text
client  -> AK gallery and asset URLs
AK      -> Open VSX only when it must fetch an uncached upstream asset/metadata
```

This test covers discovery, install, and update traffic only. It cannot prove
that an installed extension has no runtime egress; control that separately with
endpoint or network policy if needed.

## TLS, cache, and availability notes

Use a certificate trusted by every configured client. With a private CA, add
the CA to the desktop OS trust store and, for code-server, to the service
runtime/browser trust path as applicable. Do not disable certificate validation
to make a dogfood setup work.

AK streams upstream VSIX and gallery assets without modifying them. Capacity
and availability therefore depend on the cache and its storage:

- Keep cache storage durable and sized for the VSIX/assets you intend to retain.
- With multiple AK replicas, use shared durable cache storage or deliberate
  affinity; isolated per-replica caches reduce hit rate and make cold starts
  look like upstream outages.
- A cache miss still depends on the Open VSX upstream, AK outbound DNS/TLS,
  and any configured proxy. HA does not turn the prototype into an offline
  mirror.
- Preserve normal retention, backup, and upstream extension-license/terms
  review responsibilities before relying on cached artifacts operationally.

## Known limits

- Only a public, anonymous-read AK repository is supported for gallery clients
  in this slice. Private repositories and credentials in gallery URLs are
  explicitly unsupported.
- The gallery gateway is experimental prototype behavior. Virtual repositories
  are unsupported; use a Remote repository for search, install, and update.
- Gallery metadata queries are forwarded rather than cached in Slice 1. Each
  response is capped at 2 MiB and charged as a 32× wire-size working set against
  AK's shared buffered-metadata budget while AK validates and rewrites it;
  large package-index limits do not apply to gallery searches.
- Microsoft Marketplace is not an interchangeable upstream and is deferred.
- This gateway reduces client egress for gallery operations only; it makes no
  claim about an extension's runtime connections.
