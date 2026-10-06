---
section: Security
issues: [#4098, #4343, #4097]
---
- **Scan-on-proxy now covers the VS Code legacy download route, and scanned virtual walks stop at a member's quarantine hold** (#4098, #4343). `GET /extensions/{publisher}/{name}/{version}/download` served Remote and Virtual VSIX bytes without the scan-on-proxy gate the gallery route applies; it now runs the same gate, and on a virtual repository walks members in strict priority order under the stricter of the virtual's and each member's policy. The scanned virtual member walks for npm, PyPI and the VS Code legacy route now stop at a member's 409 quarantine hold, as the shared resolver already did, instead of serving the same file from a lower-priority member. Underneath, the inline scan-and-block sequence is now one generic wrapper (`serve_scanned_proxy_file`) that npm, PyPI and VS Code use with no other behaviour change, and that the Maven, Cargo and NuGet scan-on-proxy support builds on (#4097).
