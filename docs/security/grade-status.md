# Repository grade status and coverage

Since 1.12.0 (#4336) a repository security score says how much of the
repository was assessed, instead of turning the grade letter into an F when
something could not be assessed.

## Fields

`GET /api/v1/security/scores` and `GET /api/v1/repositories/{key}/security`
(`score`) return:

| Field | Meaning |
|---|---|
| `score` | 0 to 100, from the open findings of the latest completed scans (unchanged). |
| `grade` | The letter for `score` over the assessed artifacts (A to F), `null` when `grade_status` is `unrated`. Never an F floor. |
| `grade_status` | `rated`, `incomplete` or `unrated`, below. |
| `coverage` | Counts per live artifact, below. `null` until a 1.12 replica has recalculated the score. |
| `has_failed_scan`, `has_uncataloged_scan` | Unchanged flags (#2167, #4036). |

`coverage` counts each live (not deleted) artifact once, by the latest scan
of each scanner:

| Field | Meaning |
|---|---|
| `artifacts` | Live artifacts in the repository. |
| `scanned` | Artifacts with a finished scan: `cataloged + failed + uncataloged`. |
| `failed` | Some latest scan failed. |
| `uncataloged` | Not failed, and some latest completed scan cataloged nothing (`scan_completeness = not_cataloged`). |
| `cataloged` | Assessed: the rest of `scanned`. |
| `partial` | The part of `cataloged` with a `partial` latest scan. |
| `coverage_pct` | `(cataloged - partial) / scanned`, whole percent rounded down; `null` when nothing was scanned. |

Artifacts with no finished scan (none yet, pending, running, or every scanner
not applicable) are in `artifacts` but not in `scanned`.

## Status

| `grade_status` | When |
|---|---|
| `rated` | At least one artifact assessed, and every scanned artifact fully assessed (`cataloged > 0`, `failed = uncataloged = partial = 0`). |
| `incomplete` | Something assessed (`cataloged > 0`) and something not, or only in part (`failed`, `uncataloged` or `partial` above zero). The letter covers the assessed artifacts. Also every repository with findings, or with an artifact some scanner cataloged, that the counts alone would call `unrated`: an artifact one scanner cataloged and another failed on counts as `failed`, and the findings of an earlier completed scan still count after a failed rescan. Findings always come with their letter. |
| `unrated` | Nothing assessed (`cataloged = 0`, no artifact cataloged by any scanner and no findings): no scans at all, or every scan failed or cataloged nothing. No letter. |

For a `rated` repository the letter is exactly the one earlier releases
showed. Deleting an artifact recalculates its repository's score, so removing
the artifact that could not be assessed makes the repository `rated` without
waiting for the next scan.

The security dashboard (`GET /api/v1/security/dashboard`) counts
repositories by status (`repos_rated`, `repos_incomplete`, `repos_unrated`);
`repos_grade_a` and `repos_grade_f` count the letters shown, so an `unrated`
repository is in neither.

## Per scan

Each scan row (`GET /api/v1/security/scans`, the repository and artifact
scan listings) carries `grade_status` and `grade_status_reason` in the same
vocabulary:

| Scan row | `grade_status` | `grade_status_reason` |
|---|---|---|
| completed, `scan_completeness = complete` | `rated` | `null` |
| completed, `partial` | `incomplete` | `scan_completeness_reason` |
| completed, `not_cataloged` | `unrated` | `scan_completeness_reason` |
| failed | `unrated` | points at `error_message` |
| not applicable, pending, running | `unrated` | why |

A scanner that can read only part of an artifact (for example an image whose
root filesystem could be extracted only in part) records `partial` with a
`scan_completeness_reason`, which reads as `incomplete` with that reason; one
that can read nothing records `not_cataloged`. `inventory_status` (whether the
SBOM rows were stored) does not affect the status.

## Rolling upgrade

Migration 303 adds nullable columns only. 1.12 keeps writing the `grade`
column exactly as 1.11 does, F floor included, so a 1.11 replica reads the
same letter it always did. A score a 1.11 replica writes during the upgrade
leaves the new columns empty or stale (detected by `status_calculated_at`);
1.12 then derives the status from the stored flags (`incomplete` when the
letter was floored or a flag is set, else `rated`) and reports
`coverage: null` until its own next recalculation.

Migration 361 (#4994) adds columns with defaults only; see the rolling
upgrade notes under Enforcement.

## Enforcement (#4994)

Since 1.12.0 the gates can read the status as well as the score. A repository
whose scans failed or cataloged nothing keeps a `score` of 100, so a threshold
on the score alone passed it. New gates and rules check the status by
default; gates and rules from before the upgrade do not until you set them
to (see the upgrade note below).

### Quality gates and promotion rules

A quality gate that sets `min_security_score` or `min_health_score` (both read
the repository security score: the health score weighs it in), and a
promotion rule that sets `min_health_score`, also check the grade status of
the repository the artifact lives in. `accepted_grade_status` on the gate or
rule (`POST`/`PUT /api/v1/quality/gates`, `POST`/`PUT
/api/v1/promotion-rules`, returned on every read) sets the weakest status
that passes:

| `accepted_grade_status` | Passes |
|---|---|
| `rated` (default for a new gate or rule) | `rated` only |
| `incomplete` | `rated` or `incomplete` |
| `any` | every status: the score alone decides, the behaviour before 1.12 |

A repository with no score row yet is `unrated`. A gate reports the refusal
as a violation with `rule: "grade_status"`, `expected` (`rated`, or `rated or
incomplete`) and `actual` (the status), with the coverage counts in the
message; a rule reports it in its `violations`. The gate's `action` decides
whether that blocks or warns, as for any other violation. A gate still skips
an artifact with no health score yet (#4156), as before, and a rule does the
same: neither checks the grade status of such an artifact.

What the check covers:

- **Promotion and evaluation only.** Gates and rules run when an artifact is
  promoted and on the evaluate endpoints. Downloads are not affected.
- **Global gates.** A gate with no `repository_id` applies to every
  repository that has no enabled gate of its own, so a global
  `min_security_score` or `min_health_score` gate checks the grade status in
  all of them.
- **Formats no scanner covers.** A repository whose format no scanner
  applies to has every scan `not_applicable`, so it is `unrated` for good:
  no rescan changes that, and `uncataloged_policy: warn` does not either
  (it only counts artifacts a scanner tried and could not catalog). Set
  `accepted_grade_status: any` on the gates and rules that cover such a
  repository, including any global gate.
- **API only for now.** `accepted_grade_status` is set through the API; the
  web UI does not show it yet.

**Upgrade note: existing gates and rules keep the 1.11 behaviour.**
Migration 361 sets `accepted_grade_status = 'any'` on every gate and rule
that exists at upgrade, so they decide on the score alone, as before. A gate
or rule created after the upgrade defaults to `rated` and fails closed. To
enforce on the grade status with an existing gate or rule, set
`accepted_grade_status` to `rated` or `incomplete` on it.

1.11 reports no grade status, so check what that would refuse after the
upgrade, once the repositories have been rescanned:

1. `GET /api/v1/security/scores` gives each repository's `grade_status`.
2. `GET /api/v1/repositories/{key}/security/coverage/artifacts` lists the
   artifacts that keep a repository from `rated` (see below).
3. Try a gate or rule without promoting anything:
   `POST /api/v1/quality/gates/evaluate/{artifact_id}` evaluates one artifact
   against its repository's gate (it records the evaluation and promotes
   nothing), and `POST /api/v1/promotion-rules/{id}/evaluate` evaluates every
   artifact in the rule's source repository. Set the gate or rule to `rated`
   first, since `any` never reports a `grade_status` violation.

Fix the scans, or set `uncataloged_policy: warn` where the uncataloged
artifacts are plain archives, before tightening a gate or rule that
promotions depend on. Leave `any` on the gates and rules of repositories
that no scanner covers (above).

### Scan policies: `block_uncataloged`

A scan policy (`POST`/`PUT /api/v1/security/policies`) with
`block_uncataloged: true` refuses an artifact whose latest completed scan of
some scanner cataloged nothing (`scan_completeness = not_cataloged`): on
download (`403`, like the other scan-policy refusals) and on promotion (rule
`block-uncataloged`, severity `high`, which blocks). The per-scanner latest
row is the same one the coverage counts use, so a rescan that catalogs the
artifact clears it. Default `false`: no existing policy changes outcome.

### Per repository: `uncataloged_policy`

`PUT /api/v1/repositories/{key}/security/uncataloged-policy` with
`{"uncataloged_policy": "warn"}` (instance administrators only) makes an
artifact no scanner could catalog count as assessed for the grade status, so
a generic repository of plain archives (documentation bundles, say) can be
`rated`. The artifact is still reported: it stays in `coverage.uncataloged`,
sets `has_uncataloged_scan`, and is listed below. `fail`, the default, keeps
the status above. There is no `ignore`. The write recalculates the score and
returns it; `GET /api/v1/repositories/{key}/security` shows the policy as
`uncataloged_policy`. A failed or partial scan is not relaxed by `warn`, and
`block_uncataloged` on a scan policy applies whatever the repository's
policy.

### The artifacts behind `coverage`

`GET /api/v1/repositories/{key}/security/coverage/artifacts` lists the live
artifacts by coverage status (`failed`, `uncataloged`, `partial`,
`cataloged`, `unscanned`), with each artifact's latest scan per scanner and
why it did not assess the artifact (`reason`: the scan's
`scan_completeness_reason`, or its `error_message` when it failed). By
default it lists `failed,uncataloged,partial`, the artifacts that keep the
repository from `rated`; pass `status=` (comma-separated) for others, and
`limit` (default 100, at most 1000) and `offset` to page. `counts` gives
every status computed now; the score's `coverage` is as of its last
recalculation.

### Rolling upgrade

Migration 361 adds `quality_gates.accepted_grade_status`,
`promotion_rules.accepted_grade_status`, `scan_policies.block_uncataloged`
and `repositories.uncataloged_policy`, each with a constant default and a
`NOT VALID` check (catalogue-only). Gates and rules that exist at upgrade
get `any`; the column default for later rows is `rated`. A 1.11 replica
ignores the columns: a gate, rule, policy or repository it creates gets the
column default (`rated` for a gate or rule), and its updates leave them as
they are. Until every replica runs 1.12, a promotion or
download served by a 1.11 replica is decided without these checks, and a
score a 1.11 replica recalculates ignores `uncataloged_policy` until a 1.12
replica recalculates it again (a 1.11-written row reads `incomplete` when
something could not be cataloged, as above). Finish the upgrade before
relying on the new checks.
