# OCI digests scoped to the image name

In the OCI Distribution Spec `<name>` is `<repository key>/<image>`, and
`GET`/`HEAD /v2/<name>/manifests/<digest>` and `/v2/<name>/blobs/<digest>`
answer `404` when the digest is not in `<name>`. Since 1.12.0 a hosted (local
or staging) repository follows that (#5793). Before, a digest resolved under
any image name in the repository, including one that was never pushed.

## What resolves under `<name>`

A **manifest** digest resolves under an image when:

- a tag of the image names it (a by-digest push records one too), or a live
  manifest row of the image holds those bytes;
- the image holds it through a link: it was pushed, promoted, replicated or
  imported under the image. The link survives a tag overwrite, so the old
  digest of an overwritten tag stays pullable under its own image (#1681);
- an index that is live under the image references it (directly or through
  nested indexes), which is how a multi-platform pull fetches its children;
- it carries the backfill's **legacy marker** (see below) and the image
  already holds content in the repository.

A digest deleted under the image keeps the #4525 rule: deleted by digest, it
answers `404` under that image; deleted only through its tags, it resolves
only while an index live under the image references it. Other images are not
affected by either delete.

A **blob** digest resolves under an image when it was uploaded or mounted
under the image, or when a manifest that resolves under the image references
it (the first such read records a link, so later reads are one lookup).

Anything else answers `404 MANIFEST_UNKNOWN` or `404 BLOB_UNKNOWN`. The blob
check runs before the scan re-block, so a name that does not hold a blob gets
`404`, not `403`. The referrers API lists, under `<name>`, only the referrers
that resolve under it. A Virtual repository resolves a hosted member's digest
under the pull's image name the same way a direct pull of the member does.

Remote (proxy) repositories are unchanged. Internal readers that address a
digest directly (replication, the scanner, image builds, promotion) are
unchanged too: they do not go through `/v2/<name>`.

## Pushing a layer under a new image name

`docker push` (and other clients) `HEAD` each layer under the image being
pushed and upload the ones that answer `404`. A layer the repository already
holds under another image name is therefore uploaded again; the bytes are
content-addressed, so no extra storage is used. A client that names the
source can skip the upload with a mount, now honoured within a repository
too:

```
POST /v2/<repo>/<new image>/blobs/uploads/?mount=<digest>&from=<repo>/<image>
```

answers `201 Created` when `<repo>/<image>` holds the blob, and `202
Accepted` (a normal upload session) when it does not.

## Upgrade: the backfill and the legacy marker

Migration 363 adds three tables (`oci_image_manifests`, `oci_image_blobs`,
`oci_image_scope_backfill`) and nothing else. The links for existing content
are written by the `oci_manifests` reconcile ([its schedule](oci-manifests-reconcile.md#schedule)),
which runs at startup and every `OCI_MANIFESTS_RECONCILE_INTERVAL_SECS`:

- A repository keeps the old repository-wide rule until its first backfill
  has completed, so no read answers `404` because the backfill has not
  reached it yet. A repository whose first manifest is pushed after the
  upgrade is scoped from that push.
- The backfill links each manifest to the images that hold it: the images
  whose tags name it, whose manifest rows (canonical and migrated layouts)
  hold its bytes, and the images holding an index that references it.
- A manifest it cannot attribute to any image (the old digest of a tag
  overwritten before the upgrade: no row names it any more) gets one legacy
  marker. It resolves under any image that already holds content in the
  repository, so a pre-upgrade `<image>@<old digest>` pin keeps working, but
  never under a name that holds nothing. A delete by digest removes the
  marker. Nothing writes a marker after the first backfill.
- Each later pass links rows written since shortly before the previous pass,
  so a push a 1.11 replica serves during a rolling upgrade (it writes no
  link) is linked on the next pass. Until then a 1.11 push resolves through
  its tags and manifest rows as usual; only its blobs, read under the pushed
  image before its manifest is pushed, answer `404` on a 1.12 replica, which
  makes the client upload them again.

A restore from an archive written before 1.12.0 resets the restored
repositories to the old rule until the next reconcile pass backfills them.
Archives written by 1.12.0 carry the links.

## Rollback switch: `AK_OCI_BLOB_SCOPE`

`AK_OCI_BLOB_SCOPE=report` restores repository-wide blob reads: a blob read
under a name that does not hold it is served, counted and logged at `WARN`
instead of answering `404`. The default is `enforce`. The switch covers blob
reads only (manifest reads are always scoped), is read once at startup, and
**will be removed in 1.13**; use it while finding the clients that relied on
the old behaviour, then remove it.

## Metrics

| Metric | Type | Meaning |
|---|---|---|
| `ak_oci_blob_scope_misses_total{mode}` | counter | Hosted blob reads under an image that does not hold the blob. `mode="enforce"` answered `404`, `mode="report"` served it. |
| `ak_oci_image_scope_links_backfilled_total` | counter | Manifest links the reconcile's backfill added. Settles near zero once the upgrade is complete and every replica runs 1.12.0. |
