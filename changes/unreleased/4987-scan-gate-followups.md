---
section: Changed
issues: [#4987]
---
- **Every scan-on-proxy refusal is now audited, the `PROXY_SCAN_BLOCKED` row names the API token, and the policy-blocks queue pages by keyset** (#4987). Three serve paths refused a pull from a stored `vulnerable` verdict without the audit entry or the `ak_proxy_scan_verdicts_total` count the shared gate writes: a conda `.sigs` attestation sidecar of a blocked package, the NuGet digest-pinned row repair, and an OCI blob of a blocked image. They now write both, so "who asked for this blocked package" has one answer whichever path refused it.

  The `PROXY_SCAN_BLOCKED` row now carries `api_token_id` when the pull authenticated with an API token, and two tokens of one user are aggregated separately. Each replica runs at most 4 of these audit writes at once, so many distinct callers refused together cannot crowd the database connection pool; past a backlog of 10,000 an entry is dropped and logged, and the 403 is never delayed.

  `GET /api/v1/admin/holds/policy-blocks` pages its proxy-cache half by keyset instead of re-reading the whole list and skipping an offset, so a page no longer skips an entry when an earlier one drops out of the queue, and a page filled exactly by proxy entries no longer ends the listing before the hosted half. A cursor from an earlier release is refused with `400`; start the listing again.

  A virtual Maven repository no longer asks a Remote member for the checksum of a G:A:V a hosted member owns, matching the dependency-confusion guard the artifact itself already has. The cached scan-policy decisions behind generated listings are dropped when a scan completes or a label changes, instead of within their 60 second lifetime.
