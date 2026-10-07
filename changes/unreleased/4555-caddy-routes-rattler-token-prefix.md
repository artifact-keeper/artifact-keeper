---
section: Fixed
issues: [#4555, #4482]
---
- **The stock Caddyfile routes rattler's `/t/<token>/conda/<repo>/...` URLs to the backend** (#4555, #4482). The conda token-in-URL mount under `/t` was added without a matching `reverse_proxy /t/* backend:8080` line, so behind the stock stack those requests fell through to the web UI and got its HTML 404, and the Caddyfile route gate (`scripts/ci/check-caddy-format-routes.sh`) failed on `main`.
