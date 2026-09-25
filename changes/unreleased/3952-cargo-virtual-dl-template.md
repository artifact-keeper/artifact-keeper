---
section: Fixed
issues: [#3952]
---
- **Cargo virtual repositories now resolve each Remote member's `dl` download template from that member's own `config.json`, so crates download from the member's download host instead of 404ing against its index host** (#3952). The Virtual download route built `api/v1/crates/{name}/{version}/download` against the member's `upstream_url` — the index host — so a virtual over a crates.io-backed remote (index at `index.crates.io`, bodies at `static.crates.io`) only served crates already cached through some other route. Each member's template is now resolved and SSRF-validated per member (a hostile `dl` falls that member back to its index host rather than failing the virtual), the canonical path stays the proxy-cache key, and the `dl` template markers `{prefix}` / `{lowerprefix}` from the cargo registry spec are expanded instead of left literal.
