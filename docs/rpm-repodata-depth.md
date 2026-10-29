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
Metadata locations are relative to the selected root and are written like
createrepo_c writes them: verbatim (`gcc-c++-...rpm` stays `gcc-c++-...rpm`),
percent-encoding only `%`, `?`, `#`, spaces, control and non-ASCII bytes.

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

Hosted roots are precomputed by default: see
[Precomputed repodata](#precomputed-repodata). The rest of this section
describes the on-request render, used for roots that have not been built yet,
for `repodata_mode: on_request`, for virtual repositories, and by the builder
itself.

Metadata caches and render locks are bounded and keyed by repository plus root.
Empty roots are rendered per request and never cached, so requests for made-up
roots cannot evict the metadata of populated ones.
A render reads a root's packages from one database snapshot in batches of
about 32 MiB of stored metadata and compresses each document as it is written,
so its memory use follows the batch, not the size of the root (#4544). It
still costs CPU in proportion to the root: on request, the first request
after a change to a large root can take tens of seconds.
The snapshot is a read-only transaction that stays open for the whole
render, so while a large root renders it holds back the vacuum horizon the
way any long-running query does: rows updated or deleted meanwhile are
reclaimed by the first vacuum after the render ends.
On request, uploads, metadata changes, deletes, restores, and lifecycle cleanup
invalidate the affected root through its artifact fingerprint without
including siblings. The precomputed builder heals packages before it opens its
snapshot, so its snapshot does no storage reads.

## Precomputed repodata

Hosted RPM repositories build their repodata in the background and serve it
from storage (#4544). This applies at every depth, including the default
depth zero, where the repository has one root.

- Every write that can change a root's documents marks that root dirty:
  uploads, imports, promotions, restores, deletes, lifecycle cleanup and
  metadata changes (triggers on `artifacts` and `artifact_metadata`, migration
  308). The repodata heal's own bookkeeping does not.
- A background builder runs on every replica. A dirty root is built once no
  package in it has changed for `RPM_REPODATA_BUILD_QUIET_SECS` (default 3),
  or once it has been dirty for `RPM_REPODATA_BUILD_MAX_DELAY_SECS` (default
  60) while writes continue, so a bulk import is rebuilt about once a minute
  instead of on every request. `RPM_REPODATA_BUILD_INTERVAL_SECS` (default 2)
  is how often each replica looks for dirty roots. One replica builds a given
  root at a time (a database advisory lock per root). Writers hold a shared
  lock on the root until they commit and the builder clears the dirty flag
  under the exclusive one, so every write committed before a build starts is
  in it; a build that dies half way is retried after 15 minutes.
- A build first heals packages that lack their header-derived repodata
  block, outside any snapshot, then renders the root from one read-only
  snapshot without storage reads, and writes the compressed documents through
  spool files in the upload staging directory (`AK_UPLOAD_STAGING_DIR`,
  default `<STORAGE_PATH>/.incoming`) to the repository's storage under
  `repodata/<repository id>/<root>/<revision>/`
  (`repodata/<repository id>/<revision>/` at depth zero). One database update
  makes the revision current.
- `repomd.xml` is served from the database row of the current revision,
  `primary.xml.gz`, `filelists.xml.gz` and `other.xml.gz` stream from
  storage, and `repomd.xml.asc` is signed per request over the stored
  `repomd.xml`, so a signing key rotation takes effect at once. The bytes are
  the ones the on-request render produces for the same packages.
- A root that has never been built (every root right after the upgrade to
  1.12.0, and a new root until its first build) renders on request, as
  before. An empty root is not stored: it renders an empty document.
- The previous revision is kept so a download in flight during a swap
  completes; older revisions are deleted after each build. Revisions of a deleted
  repository, or of one switched to `on_request`, are deleted by the
  builder's maintenance pass (every minute).

The cost is read-your-writes: right after an upload or a delete the root can
describe the previous state for a few seconds, until the builder runs. A CI
job that publishes and then installs from the same root should ask for the
build and wait for it:

```sh
curl -u "$AK_USER:$AK_PASSWORD" -X POST \
  "$AK_URL/api/v1/repositories/releases/rpm/repodata/rebuild?root=build-a&wait=true"
```

`root` is the metadata root (omit it at depth zero); a root that never held
packages is refused with 404. With `wait=true` the call returns `200` once a
revision that includes every write committed before the call is being served,
with the
revision and the package count; callers arriving together share one build,
and a build another replica is running is waited for (up to five minutes).
Without `wait` the call returns `202` and the next builder tick builds the
root without the debounce. It needs the repository `write` permission, like
an upload. A large root can take longer to build than a proxy or ingress
timeout allows; the build still finishes if the client gives up, so a CI job
can retry the call, which then returns at once. Each replica runs at most two
`wait=true` builds at a time and answers `503` beyond that (waiting for
another replica's build of the same root does not count).

To keep the previous behaviour for one repository, set
`"repodata_mode": "on_request"` on create or `PATCH`: every request then
validates the repository state and renders on change, as in 1.11. Switching
back to `"precomputed"` (the default) marks every root for a build; if the
builder's maintenance pass has not yet deleted the revisions stored before the
opt-out, the last of them is served until that build finishes, a few seconds.
Repository responses include `repodata_mode` for local RPM repositories, and
`GET /api/v1/repositories/_/capabilities` reports
`{"rpm_repodata_mode":{"supported":true,"default":"precomputed"}}`. Setting
`repodata_mode` on any other repository is refused with 422.

Virtual repositories always render on request: their documents depend on
which members the caller may read (#4346). Curated publications (`@N`) and
remote repositories are not affected.

Builder metrics: `ak_rpm_repodata_builds_total{result}` (`built`, `empty`,
`skipped`, `busy`, `failed`) and `ak_rpm_repodata_build_seconds`. A failed
build keeps the root dirty, records the error in
`rpm_repodata_roots.last_error` and retries after 30 seconds while the last
built revision keeps being served.


## Backup, restore, and upgrades

Backups preserve positive depth as an optional `repodata_depth` member of each
repository record in the checksum-protected `database/repositories.json`
payload. Unrelated repository configuration and secrets are not added. Depth-zero
records retain their old shape; absence means zero. Repository layout and
artifact exports use the same database snapshot.

Restore validates all layout values before inserting rows, installs positive
depth before restoring artifacts, and rolls back database changes on any failure
in a depth-bearing archive. Archives without positive depth restore row by row,
as before, collecting failures instead of aborting. Restoring into an existing
repository requires an exact depth match, even if that repository is empty. A
legacy record with no depth cannot silently overwrite a positive-depth layout.
To restore into an empty repository with a different setting, explicitly
change its depth first.
The existing `restore_database: false` option restores bytes only, not layout.

**Upgrade every backend node before enabling positive depth.** Mixed old/new
backend fleets are unsupported: older metadata handlers can still expose the
full repository catalog, and older write handlers do not implement subtree
routing. UI capability detection is not fleet-wide protection.

The minimum restoring backend is a build containing the #4216 implementation
(migration 247 and `rpm_repodata_depth.supported: true`). Restore depth-bearing
archives only on such a build or newer. Older restore code ignores the extra
field, and the legacy archive version field does not enforce this compatibility
boundary. Downgrading a running instance or restoring its depth-bearing backup
on an older binary is unsupported and can serve metadata at the wrong roots.
