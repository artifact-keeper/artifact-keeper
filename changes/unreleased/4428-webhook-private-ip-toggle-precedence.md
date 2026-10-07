---
section: Fixed
issues: [#4428]
---
- **`WEBHOOK_ALLOW_PRIVATE_IPS=true` now takes effect when `AK_SSRF_ALLOW_PRIVATE_CIDRS` is also set** (#4428). Configuring the shared private-CIDR allowlist (usually to narrow the upstream/proxy surface) made it the only rule for webhook targets too, so an explicit webhook toggle was silently ignored and a private webhook receiver outside the listed CIDRs was refused at create and at delivery. For webhook targets the two knobs are now additive: the toggle admits every private address, and without it the CIDR list still applies. Upstream and SSO behaviour is unchanged (a configured CIDR list stays authoritative there), and cloud-metadata, loopback and link-local addresses remain blocked in every case.
