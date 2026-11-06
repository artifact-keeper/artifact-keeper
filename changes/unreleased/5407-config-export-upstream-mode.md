---
section: Fixed
issues: [#5407]
---
- **A config export now carries a Remote's cache-only upstream mode, and plan and apply carry it to the target** (#5407). `GET /api/v1/admin/config/export` (#5292) left out `upstream_mode` (#5282), so re-applying a disconnected site's export to a rebuilt instance gave Remotes that contacted their upstream again. A Remote stored as `cache_only` now exports `"upstream_mode": "cache_only"` (read through `GET .../upstream-mode`; `online`, the default, is omitted), `mode=plan` reports a difference under `changes`, and `mode=apply` writes it through `PUT .../upstream-mode`. The instance-wide `PROXY_UPSTREAM_MODE` override is not exported. `docs/schemas/config-document.v1.json` and `docs/config-as-code.md` describe the field.
