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

Before 1.12.0 a scan-policy hold answered `409`, like any other hold. A
client that retried on `409` waiting for a release now gets `403` for a
scan-policy hold: the artifact will not be released by waiting, only by a
rescan that clears the findings, an acknowledgement (see
[Acknowledging a finding](#acknowledging-a-finding)), or a policy change. The
`403` body is the same neutral text the scan-policy gate already used
("Artifact download is blocked by the repository's scan policy"); it names no
policy or finding. A Maven checksum (`.sha1`, `.md5`, `.sha256`, `.sha512`)
of a refused artifact answers `404`.

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
| The repository | The finding's own repository. The same bytes in another repository are not covered unless the request says `"scope": "all_repositories"`, or they got there by promotion. |
| Advisory, component, component version, finding class | A new CVE, or the same CVE on another component or version, stays open. The engine that reported it does not matter: one decision covers every engine reporting the same component. |
| Severity | The severity of the row acknowledged. If the finding is re-graded above it, it reopens. Acknowledging it again accepts the new severity. |
| `expires_at` (optional) | The finding reopens at this time, with no further action. Without it, the decision lasts until revoked. |

Acknowledging releases a hold whose `quarantine_source` is `scan_policy` once
the policy no longer refuses the artifact, and writes a `QUARANTINE_RELEASED`
audit row. It does not release an administrator's hold, an upload-period hold, a
rejection, or a hold with no recorded source (written before 1.12.0): those need
`POST /api/v1/quarantine/{id}/release`.

A promotion copies the source's verdict (the latest completed scan of each
type, with its provenance) and its live decisions into the target repository,
where the target's own policy grades the findings. `GET /api/v1/security/acknowledgements`
lists decisions, and `include_inactive=true` adds expired and revoked ones.

`DELETE /api/v1/security/findings/{id}/acknowledge` or
`DELETE /api/v1/security/acknowledgements/{id}` revokes a decision, and with it
every copy a promotion made of it. A decision made independently in another
repository for the same bytes stays. After a revoke the scan policy refuses the
artifact again (`403`); the hold is not written back.

The download gate grades each artifact's current scans: per scan type, the latest
complete scan and anything after it. A finding only an older scan reported no
longer blocks. A later scan that crashed, or that could not assess the artifact
(`partial`, `not_cataloged`), does not clear what the complete scan reported.

Upgrading to 1.12.0 turns an acknowledged row into a decision only when every row
of that finding in the artifact's current scans is acknowledged. A finding
acknowledged only in an older scan, or by one engine while another's row is open,
stays open and is acknowledged again. Proxied files have no acknowledgement
(#5152).
