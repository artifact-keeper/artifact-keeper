---
section: Fixed
issues: [#5642]
---
- **Classic conda can now use the documented `/conda/t/<TOKEN>/<repo>` channel URL** (#5642). Classic conda reads a channel token from the path with `re.search(r"/t/([a-zA-Z0-9-]*)", url)`, whose alphabet has no `_`, so it stopped at the separator inside an Artifact Keeper token (`<8 hex>_<32 hex>`), dropped the rest of the credential into the channel path and answered every read with `401`. The token channel now also accepts the token without the separator (`<8 hex><32 hex>`, the spelling classic conda can carry) and restores the canonical form before validation. micromamba and rattler/pixi are unaffected and keep using the canonical spelling.
