---
section: Changed
issues: [#3914]
---
- **VS Code gallery queries draw from their own buffered-metadata sub-budget, so a burst of anonymous gallery reads can no longer starve npm, PyPI, Debian or RPM metadata fetches** (#3914). Gallery reservations are now charged against a gallery share of the shared buffered-metadata budget as well as the budget itself, so the gallery can hold at most its share (default 3/8 of `AK_PROXY_METADATA_BUDGET_BYTES`, 384 MiB of the default 1 GiB; override with `AK_VSCODE_GALLERY_METADATA_BUDGET_BYTES`) and queues and sheds (503 + `Retry-After`) against that share alone. The new `ak_proxy_metadata_sub_budget_saturation_ratio{family="vscode_gallery"}` gauge reports how full it is. The per-query reservation is now set from measured Open VSX responses (a peak of up to 9.24x the wire size when parsed and re-serialized) at 10x the 2 MiB wire cap, replacing the estimated 6x. The sub-budget type is family-keyed so RPM repodata can adopt it next.
