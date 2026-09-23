# Hosted RPM repodata depth

Local (hosted) RPM repositories can expose independent YUM/DNF metadata roots
inside one repository. This follows Nexus Repodata Depth semantics: metadata is
generated at **exactly** the configured number of directory segments below the
repository URL, including every RPM descendant of each root.

The default, `repodata_depth: 0`, preserves existing package storage, upload
routes, root metadata, and behavior for other repository formats.

## Example

Create an empty hosted repository with `repodata_depth: 1`, then upload packages
using their complete relative paths:

```sh
curl -u "$AK_USER:$AK_PASSWORD" --upload-file package-1.2.3-1.x86_64.rpm \
  "$AK_URL/rpm/releases/build-a/package-1.2.3-1.x86_64.rpm"
curl -u "$AK_USER:$AK_PASSWORD" --upload-file package-1.2.3-1.x86_64.rpm \
  "$AK_URL/rpm/releases/build-b/package-1.2.3-1.x86_64.rpm"
```

Use a separate client base URL for each build:

```ini
[build-a]
name=Build A
baseurl=https://artifacts.example.com/rpm/releases/build-a/
enabled=1
```

`build-a/repodata/repomd.xml` describes only `build-a/` and its descendants.
`build-b/` can contain the same filename and NEVRA with different bytes.
`build-a/nested/package.rpm` belongs to `build-a`; it does not create another
metadata root. At depth two, an example root is `el9/x86_64/`.

All generated metadata routes, the detached `repomd.xml.asc` signature, and the
configured `repomd.xml.key` public key are relative to that root. Existing signing
configuration is shared by the repository; this feature does not create keys or
change signature policy. Empty, valid roots return empty metadata. Root-level
metadata and metadata at the wrong depth return 404, not the complete catalog.

## API contract

First positively detect backend support:

```http
GET /api/v1/repositories/_/capabilities
```

```json
{"rpm_repodata_depth":{"supported":true,"min":0,"max":1023,"default":0}}
```

Do not assume an older server supports depth because it accepts an unknown JSON
field. The capability endpoint uses the existing repository API authentication
and guest-access policy.

`POST /api/v1/repositories` and `PATCH /api/v1/repositories/{key}` accept an
optional top-level integer `repodata_depth` from 0 through 1023. This bound
derives from the existing 2048-byte artifact-path limit; individual paths must
still fit that limit. Omission means zero on create and no change on update.
`null`, strings, fractions, negative values, and values above the limit are
invalid.

Create, detail, update, and list responses always contain:

```json
{"repodata_depth":1,"repodata_depth_editable":true}
```

`repodata_depth_editable` describes structural eligibility and emptiness, not
permission. Existing repository creation/administration permissions still apply.
Actual depth changes are allowed only when there are **no artifact rows**,
including soft-deleted artifacts. Sending the same value is idempotent even on
a populated repository. There is no automatic conversion, relocation, purge,
or destructive rebuild.

| Condition | HTTP status / code |
| --- | --- |
| Invalid depth or noncanonical/too-shallow artifact path | 400 `VALIDATION_ERROR` |
| Actual depth change on a populated repository | 409 `CONFLICT` |
| Concurrent incompatible layout operation | 409 `CONFLICT`; retry the operation |
| Unsupported positive-depth repository combination | 422 `UNPROCESSABLE_ENTITY` |
| Copy using legacy non-content-addressed storage | 422 `UNPROCESSABLE_ENTITY`; re-upload using the full path |

Positive depth is supported only for built-in RPM local repositories (`hosted`
is the existing create alias). Remote, virtual, staging, curated repositories,
curation links, immutable publications, and virtual membership are not supported.
Explicit zero remains harmless for these modes. An unsupported combination is
reported before a populated-repository error when enabling positive depth.

## Paths and write surfaces

At positive depth, native PUT accepts a full path relative to `/rpm/{key}/`.
Native POST `/rpm/{key}/upload` accepts the full path in its filename header.
Generic raw and multipart uploads, UI/chunked uploads, and peer replication must
also provide the complete relative artifact path. Chunk completion revalidates
the current layout: creating a session does not reserve the repository's depth.

Paths cannot be absolute, contain empty, dot, parent, backslash or control
segments, or disguise traversal with encoded separators/dots. Leading or
trailing segment whitespace, the `repodata` segment, and a first `@N` segment
are reserved. `packages` and `upload` are allowed as normal root names.
Percent-encode each URL segment when uploading/downloading special characters.
Metadata locations encode each segment and are relative to the selected root.

Exact paths identify content. Positive-depth downloads never search by basename
or filename suffix. Positive-depth writes use content-addressed storage, so
identical filenames with different content cannot overwrite one another.
Promotion/import/restore persistence is subject to the same path and storage
checks. A promotion of a legacy native RPM's flat storage key is rejected before
copying; re-upload the package with a compliant relative path instead.

Subtrees are not child repositories. They share the parent repository's access,
quota, signing, and lifecycle configuration. Artifact metadata and downloads
remain path-specific, but the existing Packages catalog groups by name/version;
it may display one catalog entry for packages present in multiple roots. The
catalog chooses a representative checksum; deleting that representative can
hide the catalog coordinate even while another root contains different bytes.
Use the artifact path/tree or native root metadata when selecting an exact build.

Metadata caches and render locks are bounded and keyed by repository plus root.
Uploads, metadata changes, deletes, restores, and lifecycle cleanup invalidate
the affected root through its artifact fingerprint without including siblings.

## Backup, restore, and upgrades

Backups preserve positive depth as an optional `repodata_depth` member of each
repository record in the checksum-protected `database/repositories.json`
payload. Unrelated repository configuration and secrets are not added. Depth-zero
records retain their old shape; absence means zero. Repository layout and
artifact exports use the same database snapshot.

Restore validates all layout values before inserting rows, installs positive
depth before restoring artifacts, and rolls back database changes on any failure
in a depth-bearing archive. Restoring into an existing repository requires an
exact depth match, even if that repository is empty. A legacy record with no
depth cannot silently overwrite a positive-depth layout. To restore into an
empty repository with a different setting, explicitly change its depth first.
The existing `restore_database: false` option restores bytes only, not layout.

**Upgrade every backend node before enabling positive depth.** Mixed old/new
backend fleets are unsupported: older metadata handlers can still expose the
full repository catalog, and older write handlers do not implement subtree
routing. UI capability detection is not fleet-wide protection.

The minimum restoring backend is a build containing the #4216 implementation
(migration 234 and `rpm_repodata_depth.supported: true`). Restore depth-bearing
archives only on such a build or newer. Older restore code ignores the extra
field, and the legacy archive version field does not enforce this compatibility
boundary. Downgrading a running instance or restoring its depth-bearing backup
on an older binary is unsupported and can serve metadata at the wrong roots.
