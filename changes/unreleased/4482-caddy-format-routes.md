---
section: Fixed
issues: [#4482, #1772]
---
- **The stock Caddyfile now routes `/general`, `/pacman`, `/bazel` and `/lxc` to the backend** (#4482, #1772). `docker/Caddyfile` sends each native format prefix straight to the backend and lets everything else fall through to the web UI, but it was missing four prefixes the backend mounts. Behind the stock compose stack `/pacman/*` and `/bazel/*` returned the web UI's HTML 404, `/general/*` (the generic download route reported in #1772) worked only with web code that is not released yet, and `/lxc/*` worked only because the web middleware proxies it. All four are now routed directly, and a CI check derives the prefix list from `format_routes` in `backend/src/api/routes.rs` so a newly mounted format cannot be left out again.
