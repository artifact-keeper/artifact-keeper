---
section: Added
issues: [#6401]
---
- **Native package-format and OCI registry routes now support per-principal and per-client-IP request-rate limits** (#6401). `RATE_LIMIT_REGISTRY_PER_MIN` and `RATE_LIMIT_REGISTRY_PER_IP_PER_MIN` bound high-volume anonymous surfaces without spending the management API budget; both buckets are applied together for authenticated callers, honor the shared exemption and trusted-proxy policy, and refuse with `Retry-After` (OCI uses its `TOOMANYREQUESTS` envelope).
