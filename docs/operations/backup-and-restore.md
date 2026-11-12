# Backup and restore: what a backup covers

`POST /api/v1/admin/backups` writes a `.tar.gz` archive of part of the server.
This page lists what each backup type captures, what it leaves out, and how a
restore reports what did not come back (#5654).

A `full` backup is not a byte-for-byte copy of the deployment. For a disaster
recovery copy, back up the PostgreSQL database (`pg_dump`, or your provider's
snapshots) and the storage backend (the filesystem volume or the bucket)
together, at the same point in time. The built-in backup is for moving or
recovering hosted repositories, their images and artifacts, and the access,
webhook, settings and scan state around them.

## What is in the archive

| Content | `full` | `incremental` (`since`) | `metadata` |
|---|---|---|---|
| Users, roles and global role grants (`users`, `roles`, `user_roles`, `permission_grants`), API tokens (`api_tokens`) | yes | yes | yes |
| `repositories` rows (filtered by `repository_ids` / `exclude_repository_ids`) | yes | yes | yes |
| `artifacts` rows (filtered by `repository_ids` / `exclude_repository_ids`; `since` for incremental) | yes | changed rows only | yes |
| `download_statistics` | for the archived artifacts | for the archived artifacts | for the archived artifacts |
| Docker/OCI images: `oci_blobs`, `oci_manifests`, `oci_tags`, `oci_manifest_refs`, `oci_manifest_subjects`, `manifest_blob_refs` | yes | yes | yes (rows only) |
| Groups and access: `groups`, `user_group_members`, `role_assignments`, `permissions`, `api_token_repositories`, `virtual_repo_members` | yes | yes | yes |
| Webhooks: `webhooks`, `webhook_signing_keys` | yes | yes | yes |
| Settings: `system_settings`, `telemetry_settings`, `repository_config`, `ldap_configs`, `oidc_configs`, `saml_configs` | yes | yes | yes |
| Scan data: `scan_configs`, `scan_policies`, `scan_results`, `scan_findings`, `scan_packages`, `sbom_documents`, `sbom_components`, `finding_acknowledgements` | yes | for the archived artifacts | yes |
| Artifact bytes for every archived `artifacts` row, and Docker/OCI blob bytes for every archived `oci_blobs` row | yes | changed rows only | **no** |

Rows that belong to a repository follow the backup's repository filter.
Download statistics, scan results, findings, packages and SBOMs follow the
archived artifacts, so a restore never inserts a download or a scan of an
artifact the archive does not carry. A scoped backup does not carry the
`repositories` rows of repositories outside its scope, so its restore never
brings one of them back.
`virtual_repo_members` is archived only when both the virtual repository and
the member are in scope. Server-wide rows (groups, permissions, settings,
global webhooks, webhook signing keys) are always archived.

Secrets in these rows are archived as stored: hashed, or encrypted with the
server's key (webhook secrets, webhook signing keys, the LDAP bind password,
OIDC client secrets). They work again only on a server with the same key
configuration. Treat the archive as sensitive.

The RPM `repodata_depth` setting travels on the `repositories` rows and is
restored by the layout step, not as a `repository_config` row.

## What is not in the archive

| Category (`excluded[].category`) | What is missing | Tables |
|---|---|---|
| `webhook_deliveries` | Webhook delivery history and retry queue | `webhook_deliveries` |
| `proxy_scan_data` | Scan verdicts of objects cached from upstreams. The proxy cache is not backed up, so these are recomputed when the objects are fetched again. | `proxy_scan_results`, `proxy_scan_findings`, `proxy_scan_packages` |
| `package_metadata` | Package and version indexes, per-artifact metadata, npm dist-tags | `packages`, `package_versions`, `artifact_metadata`, `npm_dist_tags` |
| `signing_keys` | Repository signing keys and signing configuration | `signing_keys`, `repository_signing_config` |
| `artifact_bytes` (`metadata` backups only) | All artifact and blob content | (none) |

Every other table is excluded too: audit log, lifecycle and sync policies,
peers, quality gates, format-specific indexes, and so on. The manifest lists
all of them by name (below).

## The archive manifest

`manifest.json` inside each archive carries a `contents` object, written at
backup time:

```json
"contents": {
  "artifact_bytes": true,
  "excluded": [
    { "category": "webhook_deliveries", "description": "...", "tables": ["webhook_deliveries"] },
    { "category": "package_metadata", "description": "...", "tables": ["packages", "..."] }
  ],
  "excluded_tables": ["audit_log", "webhook_deliveries", "..."],
  "oci_repositories": ["docker-local"]
}
```

- `excluded_tables` is read from the database catalog when the backup runs,
  so it is exact for that server and version.
- `oci_repositories` names the repositories in the backup's scope that hold
  Docker/OCI images. Their images are in the archive.

Archives written before 1.12.0 have no `contents` object. They lack the image,
group, webhook, settings and scan tables as well as the categories above,
and a restore reports them under `excluded` as `oci_images`, `groups`,
`webhooks`, `settings` and `scan_data`.

## How a restore reports what it could not bring back

`POST /api/v1/admin/backups/{id}/restore` answers `200` whenever the restore
ran. Read `status`, not just the HTTP code:

- `status: "completed"` means `errors` is empty: everything the archive
  carries was restored.
- `status: "partial"` means `errors` names something that did not come back:
  - Docker/OCI images of an archive written before 1.12.0, which carries the
    manifest rows but not the blobs and tags. One message names every such
    repository.
  - Artifact rows or OCI blob rows whose bytes are not in the archive. Those
    artifacts and blobs will not be downloadable after the restore.
  - Artifacts that were unreadable at backup time (opt-in partial backups).
  - An archive checked only against its own manifest (captured before
    backups recorded their payload checksum on the backup row, #3373).
- `excluded` lists the categories the archive does not carry. Whatever the
  `status`, a restore never brings these back.

Rows that already exist on the target server are kept as they are: every
table restores with `ON CONFLICT DO NOTHING`, so a restore adds what is
missing and never overwrites a live row, a live setting or a live group.

## Docker/OCI repositories

A full backup carries each in-scope image: its manifest rows and bytes, its
blob rows and bytes, its tags and its manifest index. Restoring a deleted
Docker repository brings the images back, and `docker pull` of a tag works
again. An archive written before 1.12.0 does not carry the blobs and tags.
The restore says so (`status: "partial"`), and the startup hollow-tag repair
then logs the repository as hollow. Delete and re-push it, or restore its
blobs and tags from a storage-level copy.
