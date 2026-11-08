# Download holds and scan-policy blocks

Two controls refuse a hosted artifact's bytes on every download route: a
quarantine hold and a scan policy. This page lists what each answers and the
admin queues that show them. All queues are under `/api/v1/admin/holds`, need
an instance administrator holding an unrestricted credential (a
repository-scoped token is refused), and enumerate every repository.

## What a refused download answers

| Situation | Status |
| --- | --- |
| Held by the upload-time quarantine period | `409` |
| Held by an administrator (`POST /api/v1/quarantine/{id}/quarantine`) | `409` |
| Held by a scan policy (`quarantine_source = scan_policy`) | `403` |
| Held with no recorded source, and a scan policy refuses the artifact | `403` |
| Held with no recorded source, and no scan policy refuses it | `409` |
| Rejected during review | `403` |
| Not held, but a scan policy refuses it | `403` |
| MCP server version whose server.json, or a package it pins, is held | `404` on the `/mcp/{repo}/v0.1` surface for every caller; the reason is in the problem+json body only for callers who hold the repository. The generic artifact routes (listing, metadata, revision history, download, by id) treat such a version as missing for a caller who does not hold the repository (left out of listings, plain `404`); a holder keeps access and the server.json's own `409`/`403`. `/api/v1/packages` shows such a caller the server's newest servable version, or no row (holders see the stored row with `metadata.servable: false`). See [`docs/mcp-registry.md`](../mcp-registry.md#what-a-client-sees). |

Before 1.12.0 a scan-policy hold answered `409`, like any other hold. A
client that retried on `409` waiting for a release now gets `403` for a
scan-policy hold: the artifact will not be released by waiting, only by a
rescan that clears the findings, an acknowledgement (see
[Acknowledging a finding](#acknowledging-a-finding)), or a policy change. The
`403` body is the same neutral text the scan-policy gate already used
("Artifact download is blocked by the repository's scan policy"); it names no
policy or finding. A Maven checksum (`.sha1`, `.md5`, `.sha256`, `.sha512`)
of a refused artifact answers `404`.

## Turning on the upload-time quarantine period

A repository's quarantine period is set with `quarantine_enabled` and
`quarantine_duration_minutes` (minutes, non-negative). Both
`POST /api/v1/repositories` and `PATCH /api/v1/repositories/{key}` accept
them, so a repository created with `quarantine_enabled: true` holds its very
first upload; the create response, like `GET`, reports the stored values.
Enabling it on a Virtual repository is refused with `400` on both: a virtual
has no content of its own, so set it on the member repositories. Before the
fix for #5324, create accepted the two fields and stored neither, leaving the
repository unheld until a `PATCH`.

Create also refuses (`400`, naming the field) the update-only settings it
does not apply, rather than ignoring them: a non-empty
`release_repository_key`, `curation_enabled: true`, and any
`curation_default_action` other than `allow`. Set those with `PATCH` after
creating the repository.

## Where a hold came from

`artifacts.quarantine_source` (migration 299) records the origin of a hosted
hold next to `quarantine_status = 'quarantined'`:

| Value | Written by |
| --- | --- |
| `upload` | The upload-time quarantine period (always timed). |
| `admin` | An administrator's quarantine-now. |
| `scan_policy` | A scan policy refusing the artifact after a scan. |
| `null` | Holds written before 1.12.0, and by a 1.11 replica during a rolling upgrade. |

A release clears the source. The gate never trusts the free-text
`quarantine_reason`. A hold with no source answers `403` exactly when a scan
policy refuses the artifact right now (the same evaluation the gate's policy
half runs), so no backfill is needed for the status codes to be right.

## OCI images: holds follow the digest

An OCI manifest can have several `artifacts` rows in one repository: one per
tag (`v2/<name>/manifests/<tag>`) and a digest row
(`v2/<name>/manifests/sha256:<hex>`, written by an MCP pin, a push by digest
or a Remote pull). Since #5457 every read of a manifest (the native pull and
HEAD, hosted and through a Virtual, the MCP backing gate, the generic
`/download` route and the tree content read) checks every live row of the
digest in that repository, whatever the image name. If any row is held or
rejected, every reference to the digest is refused.

When a push moves a tag whose row is held (a rejection, a permanent
quarantine, or a timed hold that has not expired) to another image, the hold
moves to the old digest's digest row. That row is created if needed, and
revived if it was deleted. When it already has a hold, it keeps whichever of
the two is stronger: rejected, then a permanent quarantine, then a release,
then a timed hold. The tag row starts clean for the new image, which gets its
own upload hold if the repository has one. A moved scan-policy hold is
recorded as `admin`. The digest row has no scan of its own, so acknowledging
findings cannot release it, and an administrator releases it instead.

What this means for operators:

- Releasing or rejecting acts on one row. To serve a held image again, release
  every held row of the digest (its tag rows and its digest row). There is no
  "release this digest everywhere" action yet. While any row of the digest is
  still held, the image stays refused.
- A rejected image whose tag moved away keeps a live digest row, so it is
  retained (and listed) until an administrator deletes it.
- Only manifests are gated. Layers and other blobs are content-addressed and
  shared between images, so a client that already knows a blob digest can
  still fetch it (as since #2912).

## Queues

- `GET /api/v1/admin/holds/summary`: counts of pending age-gate reviews,
  active and rejected quarantine holds.
- `GET /api/v1/admin/holds/quarantine`: hosted and proxy-cache holds. Query:
  `repository_key`, `kind` (`active`, `expired`, `rejected`; default
  `active,rejected`), `hold_source` (`upload`, `admin`, `scan_policy`; hosted
  rows only), `page`, `per_page`. Each item carries `hold_source`.
- `GET /api/v1/admin/holds/policy-blocks`: what the download gate's scan
  policy decision refuses right now, held or not. Query: `repository_key`,
  `cursor`, `per_page` (default 50, max 200).
  - `proxy-cache` items first: a cached path (an image manifest for OCI) whose
    stored `vulnerable` verdict, newer than the 30-day verdict window, THAT
    repository's proxy scan gate refuses. Verdicts are shared by digest
    across repositories; a record-only repository, or one whose severity
    threshold is above the verdict, does not list it. Each item has
    `checksum_sha256`, `max_severity` and `scanned_at`.
  - then `hosted` items, newest first: artifacts a scan policy refuses,
    evaluated with the gate's own policy evaluation (`block_unscanned`,
    `block_on_fail`, `max_severity`, predicate policies). Each item has the
    `violations`, `quarantine_status` and `hold_source`.

  The hosted half cannot be counted without evaluating every candidate, so
  the queue pages by cursor rather than by page number: pass `next_cursor`
  back as `cursor` until it is `null`. Each page evaluates a bounded number
  of hosted artifacts (`evaluated` in the response) and may hold fewer than
  `per_page` items while still returning a cursor.

## Acknowledging a finding

`POST /api/v1/security/findings/{id}/acknowledge` with a `reason` records a
decision. It applies until it is revoked or expires, whichever scan wrote the
finding: a rescan, a dedup copy and a promotion all keep it.

| Part of the decision | What it means |
| --- | --- |
| The bytes | The artifact's SHA-256. A re-upload of the same bytes is covered; a new build under the same version is not. |
| The repository | The finding's own repository, or the one named by `repository_id`, which must hold these bytes. If the finding's scan has copies in other repositories and `repository_id` is omitted, the request answers `409`: a scan listing reports a copy under its source's id, so the row may belong to a repository other than the one you are looking at. The same bytes in another repository are not covered unless the request says `"scope": "all_repositories"`, which takes an unrestricted credential, or a promotion carried the decision. |
| Advisory, component, component version, finding class | A new CVE, or the same CVE on another component or version, stays open. The engine that reported it does not matter: one decision covers every engine reporting the same component. |
| Severity | The severity of the row acknowledged. If the finding is re-graded above it, it reopens. Acknowledging it again accepts the new severity. |
| `expires_at` (optional) | The finding reopens at this time, with no further action. Without it, the decision lasts until revoked. |

Acknowledging releases a hold whose `quarantine_source` is `scan_policy` once
the policy no longer refuses the artifact, and writes a `QUARANTINE_RELEASED`
audit row. It does not release an administrator's hold, an upload-period hold, a
rejection, or a hold with no recorded source (written before 1.12.0): those need
`POST /api/v1/quarantine/{id}/release`.

A promotion copies the source's verdict only if the target would grade what the
source grades: every scan the source's gate reads must be a complete verdict a
dedup could reuse (within its age limit, under the artifact's pin, not imported, no
crashed, running or incomplete scan after it, no external submission). Otherwise
nothing is copied and the target sees an unscanned artifact, as it did before
1.12.0: a target policy with `block_unscanned` refuses it, and one without it serves
it. The target's own policy grades whatever is copied. The source's live decisions
go with it only if the promoter could acknowledge in the target, so a
`promote:artifacts` token carries none: the finding is open there and the target's
policy decides. Each decision left behind writes a
`FINDING_ACKNOWLEDGEMENT_NOT_CARRIED` audit row.

A promotion's response (`scan_state`) and its `ARTIFACT_PROMOTED` audit row say
whether the verdict travelled and why not. A clean verdict keeps dedup's 1-day
limit, so an artifact that soaked in staging for longer than that arrives with no
verdict, and a target with `block_unscanned` refuses it until it is scanned there.

Who may decide: an instance administrator. An unrestricted credential reaches every
repository, whatever repository roles its owner holds, and a credential scoped to some
repositories reaches only those. A non-administrator cannot decide. Every path that
decides applies the same check. A decision for every repository needs an unrestricted
credential.
`GET /api/v1/security/acknowledgements` lists decisions for an unrestricted
credential, and `include_inactive=true` adds expired and revoked ones.

`GET /api/v1/security/scans/{id}/findings?artifact_id=` lists one artifact's own rows
of a reused scan. A caller who can see only a copy gets the copy's rows without it.

`DELETE /api/v1/security/findings/{id}/acknowledge` or
`DELETE /api/v1/security/acknowledgements/{id}` revokes a decision, and with it every
copy a promotion made of it that the caller has authority over. Copies past that
stay effective, and the answer counts what stays in force
(`acknowledgements_left_effective`, `left_effective`, not on gRPC). Lapsed copies are not
counted, and the by-id count includes a separate decision for every repository that
still covers the finding. A decision for every repository that the caller cannot undo is
refused rather than left half-done, because the finding would stay acknowledged in
their own repository. The finding route takes `?repository_id=` and, like an
acknowledgement, answers `409` without it when the finding's scan has copies in other
repositories. A decision made independently in another repository for the same bytes
stays. After a revoke the scan policy refuses the artifact again (`403`); the hold is
not written back.

The download gate grades each artifact's current scans: per scan type, the latest
complete scan and anything after it. A finding only an older scan reported no
longer blocks. A later scan that crashed, or that could not assess the artifact
(`partial`, `not_cataloged`), does not clear what the complete scan reported. The
promotion thresholds and `max_cve_severity` rules read the same scans, and count the
findings open for the target: a decision covers a finding there only if it is for every
repository, is live in the target, or is live in the source and the promoter could
acknowledge in the target, so the promotion carries it. A decision scoped to the source
does not open a gate for a `promote:artifacts` token. An approval re-reads the policy and
is refused on the condition a promotion is, unless the reviewer sets `skip_policy_check`.
A violation that only warns at promotion, such as `max_artifact_age_days`, does not refuse
it. Every external
scanner shares one scan type and a clean submission names no vendor, so external
submissions never supersede each other: all of them are graded, and a finding a
vendor stops reporting stays until it is acknowledged.

Upgrading to 1.12.0 turns an acknowledged row into a decision only when every row
of that finding in the artifact's current scans is acknowledged. A finding
acknowledged only in an older scan, or by one engine while another's row is open,
stays open and is acknowledged again. Proxied files have no acknowledgement
(#5152).

A 1.11 replica still running during a rolling upgrade reads the old flags on the
finding rows and not the decisions. A revoke, or a lapse once the five-minute task has
recorded it, clears those flags, so an undone decision does not read as acknowledged
there. Until that task runs, a lapsed decision that was migrated from a flag still
does. A decision made after the upgrade is not visible there, which fails closed.

Downgrading is not supported without manual work. A 1.11 binary that starts after
these migrations are applied refuses to start, because the migration ledger holds
versions it does not know, so a replica that restarts during the rollout stays down
until it is replaced. A rollback means removing those ledger rows by hand.
