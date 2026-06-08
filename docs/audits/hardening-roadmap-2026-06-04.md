# Hardening Roadmap

**Date:** 2026-06-04
**Basis:** `design-retro-2026-06-04.md` (architecture is sound, no rewrite), `honest-issue-analysis-2026-06-04.md` (fix-verified defect classification), and community discussion #1614.
**Tracking:** Hardening Core project board. Epics #1607 (Core Invariants) and #1615 (Top Defect Sources); foundational refactor #1618; CI gate #1619.

---

## Principle

Two truths from the data drive the sequencing:

1. **By volume**, defects concentrate in SBOM/scanning (50), auth/SSO (45), and native-client format-compat (45) — *integration and correctness*, not architecture.
2. **By risk**, the "core invariants" (streaming, coordination, lifecycle-GC, cache) are only ~10% of volume but own the **severe, still-open tail** — every open data-loss leak, the OOM pod-evictions, and cross-replica corruption.

So we run **three tracks in parallel**, each on independent code surfaces, and order *within* each track by severity. We do **not** stack proxy behavioral fixes on the current copy-paste surface — that surface gets refactored first (#1618).

---

## Track A — Proxy core (sequential; gated on the refactor)

The proxy/virtual/cache layer is the highest-defect-density code (~40 defects) and an 11.5k-line copy-paste surface (#1614). Behavioral fixes here must land on clean seams or they multiply variants and conflict with the contributor's fork.

| Order | Item | Why |
|---|---|---|
| A0 | **#1618** — refactor `ProxyService`/`proxy_helpers.rs` into 5 seams | Foundation. Coordinate with @Dreamacro (singleflight-streaming fork). |
| A1 | **#1608** — streaming invariant (P0) | Owns open OOM #1573 (interim fix shipping separately, see below). |
| A2 | **#1609** — cross-replica single-flight (P1) | Owns open data-integrity #1606. Builds on @Dreamacro's fork. |
| A3 | **#1611** — cache correctness / immutable-vs-mutable (P1) | Owns the virtual/remote wrong-result family (#1600, #1595, #1562, #1554, #1566, #1599). |

Companion design already written: `design-clean-room-singleflight-cache-2026-06-04.md` (A2 + A3).

## Track B — Top defect sources (parallel; independent of Track A)

Different code, biggest volume, can run with separate hands immediately.

| Order | Item | First action |
|---|---|---|
| B1 | **#1616** — SBOM/scanner integration + `cve_history` | **Blocking decision: drop vs repair `cve_history`** (investigation in flight). Then Grype/DT/OpenSCAP integration hardening. Owns open #1561, #1563, #1274. |
| B2 | **#1617** — auth/SSO correctness | Session/token invalidation on credential change (#505/#1394), SSO callback 404s, PATCH semantics, audit logging, scope-check consolidation (#1313–#1316, #1417). |

## Stop-the-bleeding (now; mostly independent of both tracks)

Open **data-loss / OOM** bugs are hurting production users today and should not wait for the refactor.

| Item | Severity | Approach |
|---|---|---|
| **#1573** — /tmp staging evicts pod | outage-oom | Interim targeted fix (configurable staging dir) **now**; full streaming = #1608. *(PR in flight.)* |
| **#1408** — blob GC missing (~403 GB leaked) | data-loss | Safe first slice = read-only "reclaimable report" (dry-run, no deletion) now; full GC = #1610. *(Design + slice in flight.)* |
| **#1551** — S3 repo delete leaks files | data-loss | Part of #1610 lifecycle. |
| **#1550** — DELETE repo 500 on large repos | degraded | Batch the delete; part of #1610. |
| **#1572**, **#1569** | cosmetic / degraded | Quick standalone wins (CI false-red; health-probe least-privilege). |

---

## Dependencies & parallelism

```
NOW ─────────────────────────────────────────────────────────────────►
 stop-the-bleeding:  #1573 fix ──┐         #1408 reclaimable-report ──┐
                                 │                                    │
 Track A:            #1618 refactor ──► #1608 ──► #1609 ──► #1611      │
                          ▲ coordinate w/ @Dreamacro fork             │
 Track B:            cve_history decision ──► #1616 ;  #1617 (auth) ───┘
```

- Track A is internally sequential; Tracks A, B, and stop-the-bleeding are mutually parallel (distinct files).
- #1573 and #1408 ship interim/safe slices now; their "real" versions fold into #1608/#1610 once the seams exist.
- The only hard external dependency is **A0 ↔ contributor coordination**: align on the 5 seams with @Dreamacro before heavy A1–A3 work.

## Definition of "done" for this phase

- No open **data-loss** or **outage-oom** defects (#1408, #1551, #1573 closed with regression tests).
- `cve_history` decision made and #1561 closed.
- Proxy seams (#1618) merged; #1608/#1609/#1611 implementable without re-introducing variants.
- Auth session-invalidation + SSO-callback E2E green (#1617).
- CI: periodic full-repo duplication scan live (#1619) so the proxy surface can't silently re-bloat.

## Risks

- **#1618 is large and needs human review.** Mitigate with the small-independently-mergeable-steps sequence (see the #1618 implementation plan) and a behavior-preservation test gate.
- **Contributor coordination.** @Dreamacro offered help; failing to engage wastes their singleflight-streaming work and risks a hard fork.
- **GC deleting live data.** Mitigated structurally: read-only report first, grace window, single-leader, delete-after-commit, dry-run + audit. Bias to leaking storage.

## In flight as of this writing (2026-06-04)
- #1618 implementation plan (architect)
- `cve_history` drop-vs-repair investigation (architect)
- #1573 interim fix → PR (senior dev)
- #1408 design + read-only reclaimable-report slice → PR (architect)
