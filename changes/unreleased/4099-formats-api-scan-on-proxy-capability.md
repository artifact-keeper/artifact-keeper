---
section: Added
issues: [#4099]
---
- **`GET /api/v1/formats` now reports whether each format enforces scan-on-proxy** (#4099). Every format handler carries `scan_on_proxy`: `enforced` when the format's proxied package downloads are scanned inline and withheld per the repository's policy (npm, PyPI, OCI and VS Code today), `accepted` when the setting is stored but proxied downloads are served unscanned, and `unsupported` for WASM plugin handlers. Clients can read this instead of keeping their own list of gated formats; the value comes from the same registration the download handlers use, and a test fails if a declared format's package routes stop reaching the scan.
  For VS Code this also closes a gap: the legacy `/extensions/{publisher}/{name}/{version}/download` route served a Remote or Virtual repository's VSIX unscanned even with scan-on-proxy on. It now applies the same scan as the gallery package route, including the stricter-of-two policy on each Virtual member.
