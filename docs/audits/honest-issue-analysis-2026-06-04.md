# Honest Issue Analysis — Re-labeled from scratch

**Date:** 2026-06-04
**Method:** The existing GitHub labels are unreliable, so all **641 issues** (open + closed) were re-classified from their **title + body** by an LLM panel (22 agents, controlled vocabulary, instructed to ignore existing labels), loaded into SQLite, and queried. A **follow-up pass (v2)** then re-judged the **269 closed defects that had a linked fix PR** using the *actual fix* (PR title/body + changed file paths) as ground truth. Dataset: `docs/audits/data/issue-classification-2026-06-04.csv` (includes both v1 and v2 columns).
**Coverage:** 641/641 classified, 0 parse errors, 0 missing. v1 confidence: **86% high, 13% med, 1% low.** v2 re-judged 269 fixes and changed **58 labels** (see §8).

> This report **corrects** the earlier `design-retro-2026-06-04.md`, which leaned on keyword matching over titles. Where they disagree, trust this one — but read the Caveats first.

---

## Headline corrections to the first retro

1. **Only 356 of 641 issues are real defects.** The rest are features (67), enhancements (75), security-hardening tasks (41), tests (22), automated bot reports (18), user questions (15), refactors (14), chores/release/docs/infra/deps (33). Quoting "636 issues" as if they were all bugs overstates the problem by ~1.8×.
2. **~9% of "defects" (33) are actually user configuration errors, not software defects.** Real, our-fault defects are closer to **~320**.
3. **The single largest defect component is SBOM / security-scanning (54 defects)** — not formats, not storage. This was *under*-weighted in the first retro. It is integration brittleness (Grype / Dependency-Track / OpenSCAP), not an architecture flaw.
4. **The three "retrofitted invariants" I built the hardening epic around explain only ~11% of defects by volume** (39–41 of 356). They are real and matter — but they are *not* the bulk of the historical bug count. They are, however, **over-represented in high-severity and open bugs** (see §5). The epic is justified by *risk*, not by *volume*. I overstated their share the first time.

---

## 1. What the 641 issues actually are

| Type | Count | Open |
|---|---|---|
| **defect** | **356** | 19 |
| enhancement | 75 | 18 |
| feature | 67 | 17 |
| security-hardening | 41 | 3 |
| test | 22 | 3 |
| automated-report | 18 | 2 |
| question | 15 | 0 |
| refactor | 14 | 8 |
| chore | 11 | 2 |
| release-task | 7 | 0 |
| docs | 6 | 0 |
| infra | 5 | 0 |
| dependency | 4 | 2 |

## 2. Where the real defects live (component)

| Component | Defects | Open |
|---|---|---|
| **sbom-scanning** | **54** | 3 |
| **auth-rbac-sso** | **43** | 0 |
| format-oci-docker | 27 | 2 |
| virtual-repo | 22 | 0 |
| format-maven | 21 | 4 |
| api-routing | 20 | 1 |
| proxy-remote | 19 | 1 |
| storage-cas | 18 | 2 |
| ci-cd-release | 14 | 1 |
| migration-import | 10 | 0 |
| format-pypi | 10 | 1 |
| (other formats) | npm 9, debian-rpm 9, incus 7, generic 7, conan 6, cargo 6, swift/other 5 | |

**Package formats combined = 117 defects** (the largest grouping). **Virtual + remote-proxy combined = 41.**

## 3. Why defects happened (root cause)

| Root cause | Defects | Open |
|---|---|---|
| auth-logic | 45 | 1 |
| format-compat (native-client quirks) | 44 | 3 |
| design-gap-other | 36 | 2 |
| config-error (*user misconfig*) | 33 | 2 |
| error-handling (panic/5xx/unwrap) | 29 | 0 |
| validation-input | 27 | 0 |
| path-normalization | 25 | 1 |
| db-schema-query | 19 | 2 |
| build-ci | 15 | 1 |
| **inv-cache-correctness** | **15** | 1 |
| **inv-streaming** | **12** | 1 |
| **inv-lifecycle-gc** | **11** | 3 |
| data-integrity | 11 | 0 |
| performance-scaling | 10 | 1 |
| concurrency-race | 8 | 0 |
| **inv-coordination** | **3** | 1 |
| upstream-dependency, ui-bug, test-infra | 5 / 5 / 2 | |

**The four invariants total ≈ 41 defects (~11.5%).** The dominant causes are auth-logic, native-client format-compat, and a long tail of ordinary error-handling / input-validation / path-normalization bugs.

## 4. How bad were they (severity)

| Severity | Defects |
|---|---|
| wrong-result | 150 |
| degraded | 127 |
| security | 35 |
| outage-oom | 20 |
| cosmetic | 10 |
| data-loss | 9 |
| data-integrity | 1 |

**Resolution:** 335 fixed, 2 duplicate, **19 still open**. ~94% of defects are closed. *(See Caveats on the `affected_release` field — it appears over-assigned and is not reported here.)*

## 5. The nuance the volume numbers hide: invariants dominate the *severe* and *open* tail

High-severity defects (data-loss + outage-oom + security = 64) by root cause:

| Root cause | High-sev defects |
|---|---|
| auth-logic | 28 *(almost all the `security` bucket)* |
| **inv-streaming** | **10** *(half of all outage-oom)* |
| **inv-lifecycle-gc** | **6** *(most of data-loss)* |
| validation-input | 4 |
| error-handling | 4 |
| path-normalization | 3 |
| inv-coordination | 1 |

And of the **19 open defects**, ~6–8 are invariant-related (#1606 coordination, #1408/#1527/#1551 lifecycle-GC, #1573 streaming, #1600 cache) — including the only two **data-loss** and the only **outage-oom** open bugs.

**So the honest verdict:** the invariants are a *small fraction of bug volume* but a *large fraction of the dangerous, still-open bugs* (storage leaks — #1408 leaked 403 GB — pod-evicting OOMs, cross-replica corruption). The hardening epic (#1607) is the right call **on risk grounds**, but "most of our bugs were caused by these invariants" would be **false**. Most of our bugs were auth logic, native-client compatibility, and ordinary error-handling/validation.

## 6. The 19 open defects (where we are now)

| # | Component | Severity | What |
|---|---|---|---|
| 1551 | storage-cas | **data-loss** | S3 repo delete leaves orphaned files; storage not reclaimed |
| 1408 | oci-docker | **data-loss** | OCI blob GC missing; ~403 GB leaked |
| 1573 | storage-cas | **outage-oom** | Multi-GiB uploads stage to /tmp, evict K8s pod |
| 1606 | proxy-remote | data-integrity | Per-process singleflight races across 8 replicas → truncated artifacts |
| 1600 | format-pypi | wrong-result | PyPI virtual unions remote versions but binds download to local member → 404 |
| 1595 | format-maven | wrong-result | Maven virtual doesn't proxy group-level plugin-prefix metadata |
| 1562 | format-maven | wrong-result | Maven virtual 404s a remote-only parent POM the member serves directly |
| 1566 | terraform | wrong-result | Tofu/Terraform remote providers fail on init |
| 1565 | edge-replication | wrong-result | Peer replication ignores S3 backend |
| 1554 | swift | wrong-result | Swift virtual read endpoints 404 |
| 1561 | sbom-scanning | wrong-result | CVE false-positive → NOT_FOUND; `cve_history` never populated |
| 1527 | oci-docker | degraded | Orphaned `oci-blobs/<digest>` on commit failure |
| 1550 | api-routing | degraded | DELETE repo with ~13.5k artifacts → 500 |
| 1599 | format-maven | degraded | Maven checksum requests do a failing DB lookup before proxying |
| 1569 | observability | degraded | Storage health probe needs bucket-admin op → /health 503 |
| 1563 | sbom-scanning | degraded | OpenSCAP/Grype scan failures |
| 1274 | sbom-scanning | degraded | scan-on-proxy doesn't auto-run on pull |
| 1547 | format-maven | cosmetic | Maven proxy creates empty dirs |
| 1572 | ci-cd-release | cosmetic | release verify expects suspended `-alpine` tag |

## 7. Revised recommendations (re-weighted by this data)

The architecture verdict from `design-retro-2026-06-04.md` **stands** (an independent clean-room design reproduced ~85% of it). But the *hardening priorities* should be re-ordered by what the honest data shows:

1. **SBOM / scanner integration is the #1 defect source (54).** Most are integration brittleness + a specific data-model rot: the `cve_history` table is referenced by the UI/findings path but **never populated** (#1561, and a recurring theme). Fix the scan/Dependency-Track/OpenSCAP integration contract and retire/repair `cve_history`. *This is higher ROI than any single invariant.*
2. **Auth/RBAC/SSO is the #2 defect source (43) and the dominant security-severity cause (28).** Recurring: SSO callback 404s, session/JWT not invalidated after password change (#505), PUT-vs-PATCH clobbering, audit-log gaps. Consolidate the auth model and add SSO callback + session-invalidation E2E. (Open hardening issues #1313–#1316, #1394 already point here.)
3. **Native-client format-compat (44) remains irreducible** — keep investing in the real-client conformance E2E suite; it is why 94% of defects closed.
4. **Then the invariants epic (#1607).** Keep it — it owns the *dangerous, open* tail (data-loss leaks, OOM, cross-replica corruption) even though it is ~11% of historical volume. Prioritize by severity: streaming (#1573) and lifecycle-GC (#1408/#1551/#1527) first.
5. **Triage hygiene:** ~9% of "defects" were user config and 15 were questions. A `not-a-bug` / `support` disposition kept rigorously would make the defect signal cleaner going forward.

---

## 8. Follow-up pass — root cause re-judged from the actual fix (v2)

For the 269 closed defects with a linked fix PR, agents re-judged `component`/`root_cause`/`severity` using the fix's **changed file paths** as ground truth (e.g. a fix touching `backend/src/storage/s3.rs` is `storage-cas`, not whatever the title implied). **58 labels changed.** What the fixes revealed:

- **We slightly *under*-counted our own fault.** **10 issues filed/labeled as `config-error` were actually our code bugs** once you read the fix — e.g. #237 (handlers hardcoded `FilesystemStorage`, ignoring `STORAGE_BACKEND`), #1298 (incus staging used the wrong storage path), #1089 (`filesystem.rs` mapped `ENOENT` to a 500 instead of NotFound, breaking proxy cache-miss refetch). `config-error` dropped 33 → 28.
- **`format-compat` was under-counted (+5).** Bugs labeled `validation-input` were really native-format/protocol compatibility: #140 (Maven SNAPSHOT filename), #134 (SAML self-closing `AuthnStatement` XML parsing), #1576 (Nexus→AK enum mapping in migration). `format-compat` is now tied with `auth-logic` as the **single largest root cause (45 each).**
- **The invariants were *over*-attributed, mostly `inv-lifecycle-gc` (11 → 6).** Reading fixes showed 5 "GC" bugs were something else — notably #735, which was not a GC design flaw but **S3 multi-delete being unsupported by Huawei OBS (405)** → `upstream-dependency`. The four invariants now total **36 of 356 defects = 10.1%** (was ~11.5%).
- **1 "defect" was not a defect** (#905 — the ghcr semver tags *were* published; the repro just lacked `--paginate`).
- **`design-gap-other` grew (36 → 47):** reading the fix often exposed a genuine code/design gap behind a vague title. This is the honest residue — real bugs we don't have a crisper bucket for, not mis-files.

**Net effect on the conclusions:** unchanged in direction, tightened in fact. SBOM-scanning (now 50) and auth/SSO (45) remain the top two defect components; `format-compat` and `auth-logic` (45 each) are the top root causes; the invariants are real but **~10% of volume** and still over-represented in the severe/open tail (high-severity by v2 cause: `auth-logic` 28, `inv-streaming` 10, `inv-lifecycle-gc` 4). The §7 recommendation order (SBOM → auth → format-compat → invariants-by-severity) holds.

## Caveats (read these before quoting numbers)

- **LLM classification, not ground truth.** Labels are an expert reading of title+body, not a verified post-mortem of each fix. 14% were med/low confidence. Treat counts as ±1 bucket, not exact.
- **`affected_release` is unreliable** — the classifier assigned "yes" to ~85% of defects, which is implausibly high (it appears to default optimistically). That dimension is in the CSV but is **excluded from this report's conclusions.**
- **Single primary component/root-cause per issue.** Cross-cutting issues (e.g. an OCI proxy streaming bug) are counted once, under their best-fit bucket — so component totals are conservative for cross-cutting subsystems.
- **Bodies truncated to 2,500 chars** for classification; very long threads may be under-characterized.
- **Closing PRs WERE read for the 269 closed defects that had one (v2, §8); the other 87 defects (68 closed without a linked PR + 19 open) are title+body only.** v2 used changed file **paths**, not full diffs — a deeper read of the patch hunks could refine the residual `design-gap-other` (47) bucket further.
- Reproduce any number: `sqlite3` over `docs/audits/data/issue-classification-2026-06-04.csv`.
