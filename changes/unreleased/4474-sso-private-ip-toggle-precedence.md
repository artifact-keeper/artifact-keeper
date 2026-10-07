---
section: Fixed
issues: [#4474]
---
- **`SSO_ALLOW_PRIVATE_IPS=true` now takes effect when `AK_SSRF_ALLOW_PRIVATE_CIDRS` is also set** (#4474). As with the webhook toggle (#4428), configuring the shared private-CIDR allowlist made it the only rule for OIDC/SSO endpoints, so an explicit SSO toggle was silently ignored and a private identity provider outside the listed CIDRs was refused, both when its URL was validated and at connect time. For SSO the two knobs are now additive: the toggle admits every private address, and without it the CIDR list still applies. Upstream behaviour is unchanged (a configured CIDR list stays authoritative there), and cloud-metadata, loopback and link-local addresses remain blocked. `.env.example` now documents `WEBHOOK_ALLOW_PRIVATE_IPS` and this rule for both surfaces.
