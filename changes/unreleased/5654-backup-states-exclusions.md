---
section: Fixed
issues: [#5654]
---
- **A full backup now carries Docker/OCI images, groups, webhooks, admin settings and scan data, and a restore that cannot bring something back answers `status: "partial"`** ([#5654]). A "full" backup used to capture only users, roles, tokens, repositories and artifacts. Restoring a deleted Docker repository answered `200` with `errors: []` while its images then 404ed and every later startup warned about hollow tags, and groups, webhooks, settings and scan results never came back. Backups now also archive:
  - Docker/OCI image blobs (rows and bytes), manifests, tags and the manifest index, so a restored repository's images pull again;
  - groups and members, repository role assignments, permissions, API-token repository limits and virtual-repository membership;
  - webhooks and their signing keys;
  - admin, telemetry, per-repository and LDAP/OIDC/SAML settings;
  - scan configuration, policies, results, findings, packages, SBOMs and acknowledgements.

  Each archive's `manifest.json` carries a `contents` object naming what it still leaves out (`webhook_deliveries`, `proxy_scan_data`, `package_metadata`, `signing_keys`, and `artifact_bytes` for a metadata backup) and every excluded table. The restore response gains `status` (`completed` or `partial`) and `excluded`. `errors` names missing artifact or blob bytes, and every repository whose images an archive from before this release cannot restore. See `docs/operations/backup-and-restore.md`.
