# Maven Spec Compliance Audit

## Context

We have had 11 Maven-related issues filed since launch (#140, #297, #303, #321, #361, #414, #415, #427, #450, #461, #532). Most are closed, but the pattern reveals systemic gaps in our Maven implementation rather than isolated bugs. This audit cross-references our code against the authoritative Maven Repository Layout spec and Maven Resolver behavior to reach 100% compliance.

**Sources:** Apache Maven Repository Layout spec, Maven Repository Metadata 1.1.0 XSD, Maven Resolver documentation, Maven Central live behavior.

---

## Gap Analysis

### Critical (breaks client workflows)

| # | Gap | Impact | Files |
|---|-----|--------|-------|
| C1 | **Version ordering is lexicographic, not semantic** | `latest` and `release` in generated `maven-metadata.xml` are wrong. SQL `ORDER BY a.version` sorts `1.0.10` before `1.0.2`. Maven uses `ComparableVersion` with qualifier ordering (alpha < beta < rc < snapshot < release < sp). | `maven.rs:351`, `maven.rs:367-368` |
| C2 | **`release` always equals `latest`** | Per spec, `release` must be the most recent non-SNAPSHOT version. We set both to `versions.last()`. If latest is a SNAPSHOT, `release` points to a SNAPSHOT, which is spec-violating. | `maven.rs:368` |
| C3 | **Virtual repo metadata not merged** | Spec requires merging `maven-metadata.xml` across all virtual members (union of versions, compute latest/release from merged set). We return the first match from a single member, so virtual repos show incomplete version lists. | `maven.rs` download section 2, `proxy_helpers.rs` |
| C4 | **No SHA-512 checksum support** | Maven 3.9+ supports `.sha512`. Our `parse_checksum_path()` only handles `.sha1`, `.md5`, `.sha256`. Clients requesting `.sha512` get 404. | `maven.rs:180-190` |
| C5 | **Content-Type wrong for POM and metadata** | We serve `application/xml` for `.pom` and `maven-metadata.xml`. Maven Central serves `text/xml`. While Maven clients don't validate this, Gradle and some CI tools do. | `maven.rs:200-208` |
| C6 | **Remote proxy doesn't fetch metadata from upstream** | When `maven-metadata.xml` is requested for a remote proxy repo and no local artifacts exist to generate it from, we return 404 instead of proxying from upstream. | `maven.rs` download section 2 |
| C7 | **Virtual repo downloads broken** (Issue #461) | Virtual Maven repos show "no members" and fail to serve artifacts. Still open. | Web + backend virtual repo handling |

### Moderate (degrades experience)

| # | Gap | Impact | Files |
|---|-----|--------|-------|
| M1 | **No `x-checksum-sha1`/`x-checksum-md5` response headers** | Clients must make separate HTTP requests for checksum files. Maven Central includes these headers to save round-trips. Adding them would reduce request volume by ~2x for downloads. | `maven.rs` download response builders |
| M2 | **No version-level SNAPSHOT metadata generation** | We store client-uploaded version-level `maven-metadata.xml` but never generate it server-side. If a SNAPSHOT is deployed via raw PUT (not `mvn deploy`), clients can't resolve the timestamp. | `maven.rs`, `formats/maven.rs` |
| M3 | **SNAPSHOT resolution uses SQL LIKE, not metadata** | Spec says clients resolve SNAPSHOTs by reading `maven-metadata.xml` to get timestamp+buildNumber. Our server-side resolution uses DB pattern matching. This works for direct downloads but means our version-level metadata may be stale or missing. | `maven.rs:92-125` |
| M4 | **Checksum not computed for MD5/SHA-1 during upload** | We store SHA-256 in the DB but compute MD5/SHA-1 on demand from the full artifact bytes. For large artifacts on S3, this means downloading the entire file just to serve a 32/40 char checksum. | `maven.rs:574-584` |
| M5 | **No `.asc` (PGP signature) content-type handling** | `.asc` files should be served as `text/plain`. Currently served as `application/octet-stream`. | `maven.rs:200-208` |

### Low (nice-to-have for full spec parity)

| # | Gap | Impact | Files |
|---|-----|--------|-------|
| L1 | **No group-level metadata for plugins** | `{groupId}/maven-metadata.xml` listing Maven plugins in that group. Only needed for `mvn` plugin prefix resolution. | Not implemented |
| L2 | **No `archetype-catalog.xml`** | Root-level file for `mvn archetype:generate`. Low usage. | Not implemented |
| L3 | **No `.index/` directory support** | Maven Indexer data for IDE integration. Most IDEs now use search APIs instead. | Not implemented |
| L4 | **No `.meta/prefixes.txt`** | Path prefix hints for efficient repository scanning. Optimization only. | Not implemented |
| L5 | **Non-unique SNAPSHOT mode not supported** | Legacy mode where files use literal `-SNAPSHOT` suffix without timestamps. Deprecated since Maven 3 but some old builds may use it. | `formats/maven.rs` |

---

## Team Structure

### Team 1: Protocol and Wire Format (6 issues)

**Scope:** Make every HTTP request/response match what Maven/Gradle clients expect.

| Task | Priority | Details |
|------|----------|---------|
| **Fix Content-Type for POM/metadata** (C5) | P1 | Change `application/xml` to `text/xml` for `.pom` and `.xml` paths. Add `text/plain` for `.asc`. |
| **Add SHA-512 checksum support** (C4) | P1 | Add `Sha512` variant to `ChecksumType`, update `parse_checksum_path()`, `checksum_suffix()`, `compute_checksum()`. |
| **Add checksum response headers** (M1) | P2 | Include `x-checksum-sha1` and `x-checksum-md5` headers on artifact download responses when the checksums are available (DB or computed). |
| **Store MD5/SHA-1 at upload time** (M4) | P2 | Compute and store `checksum_md5` and `checksum_sha1` in the artifacts table during upload. Avoids re-reading large files from storage on checksum requests. |
| **Handle `.asc` content-type** (M5) | P3 | Map `.asc` to `text/plain` in `content_type_for_path()`. |
| **Verify Expect-Continue** | P3 | Confirm Axum/hyper handles `Expect: 100-continue` correctly for PUT requests. Document if not. |

**Files touched:** `maven.rs` (handler), migration for adding `checksum_md5`/`checksum_sha1` population.

### Team 2: Metadata Engine (5 issues)

**Scope:** All `maven-metadata.xml` generation, ordering, and serving.

| Task | Priority | Details |
|------|----------|---------|
| **Implement Maven version ordering** (C1) | P0 | Port `ComparableVersion` algorithm to Rust. Use it to sort versions in `generate_metadata_for_artifact()` instead of SQL `ORDER BY`. This is the single most impactful fix: wrong `latest`/`release` values break dependency resolution for any project with >9 patch versions or qualifier-based versioning. |
| **Separate `latest` from `release`** (C2) | P0 | `latest` = highest version by Maven ordering (including SNAPSHOTs). `release` = highest non-SNAPSHOT version. If all versions are SNAPSHOTs, omit `<release>`. |
| **Merge metadata across virtual members** (C3) | P1 | When a virtual repo receives a `maven-metadata.xml` request, fetch metadata from each member (local generation or remote proxy), merge version lists (union), compute `latest`/`release` from merged set using Maven ordering, use most recent `lastUpdated`. |
| **Proxy metadata from upstream for remote repos** (C6) | P1 | In download section 2, if metadata can't be generated locally (no artifacts in DB), fall back to proxying `maven-metadata.xml` from upstream. Same pattern as the checksum proxy fix (#532). |
| **Generate version-level SNAPSHOT metadata** (M2) | P2 | When serving SNAPSHOT version-level metadata, generate `<snapshot>` and `<snapshotVersions>` entries from the DB (all timestamped files for that GAV). Needed for clients resolving SNAPSHOTs via metadata instead of relying on our server-side resolution. |

**Files touched:** `formats/maven.rs` (new `ComparableVersion` impl, `generate_metadata_xml` updates), `maven.rs` (metadata generation, virtual merging, remote proxy fallback).

### Team 3: SNAPSHOT and Storage Correctness (4 issues)

**Scope:** SNAPSHOT lifecycle, deploy correctness, storage integrity.

| Task | Priority | Details |
|------|----------|---------|
| **Fix virtual repo artifact resolution** (C7/Issue #461) | P0 | Debug and fix the virtual Maven repo member resolution. Members aren't being found during downloads. This is a user-reported open issue. |
| **Audit GAV grouping for edge cases** | P1 | The GAV grouping logic (POM+JAR under one record) has been a source of bugs (#415). Test: deploy POM first then JAR, JAR first then POM, POM-only projects, multi-classifier deploys (JAR + sources + javadoc), `.aar` Android artifacts, `.ear` enterprise archives. |
| **Handle non-unique SNAPSHOTs** (L5) | P3 | When a client uploads with literal `-SNAPSHOT` suffix (no timestamp), store and serve as-is without trying to parse a timestamp. Currently `parse_filename()` may reject these or mishandle them. |
| **SNAPSHOT cleanup/retention** | P3 | Old timestamped SNAPSHOT builds accumulate. Add configurable retention (keep last N builds per SNAPSHOT version). Not spec-required but operationally important. |

**Files touched:** `maven.rs` (virtual repo fix, GAV grouping), `formats/maven.rs` (SNAPSHOT parsing), virtual repo member resolution in `proxy_helpers.rs`.

### Team 4: Test Matrix and Validation (5 items)

**Scope:** Prove 100% compliance with automated tests.

| Task | Priority | Details |
|------|----------|---------|
| **Maven version ordering conformance tests** | P0 | Unit tests for the `ComparableVersion` port. Use the canonical test vectors from Maven's own test suite: `1.0-alpha < 1.0-beta < 1.0-rc < 1.0 < 1.0-sp`, `1.0.0 == 1.0 == 1`, `1.0.10 > 1.0.2`, etc. |
| **Metadata generation tests** | P1 | Test `maven-metadata.xml` output at all three levels. Verify `latest`/`release` are correct with mixed release+SNAPSHOT version lists. Verify `lastUpdated` format. Verify virtual repo metadata merging produces union of versions. |
| **Multi-client E2E matrix** | P1 | Test against Maven 3.8 (LTS), Maven 3.9 (current), Maven 4.0 (next-gen), and Gradle 8.x. Cover: deploy, resolve, SNAPSHOT deploy+resolve, checksum verification with `checksumPolicy=fail`, dependency resolution through virtual repos. |
| **Regression suite for historical issues** | P1 | Dedicated test for each of the 11 historical Maven issues to prevent regressions: SNAPSHOT re-upload (#297, #321), filename validation (#140), checksum XML (#414), POM+JAR grouping (#415), remote proxy (#427, #532), virtual repos (#450, #461), S3 (#361). |
| **Checksum completeness tests** | P2 | For each artifact type (JAR, POM, sources JAR, metadata), verify all checksum variants (.md5, .sha1, .sha256, .sha512) are serveable. Test both hosted repos (uploaded checksums) and remote proxy repos (proxied checksums). |

---

## Execution Order

```
Phase 1 (P0 - do first, unblocks everything):
  Team 2: Maven version ordering + latest/release separation
  Team 3: Fix virtual repo resolution (#461)
  Team 4: Version ordering conformance tests

Phase 2 (P1 - core compliance):
  Team 1: Content-Type fixes, SHA-512 support
  Team 2: Virtual metadata merging, remote metadata proxy
  Team 3: GAV grouping audit
  Team 4: Metadata tests, multi-client E2E, regression suite

Phase 3 (P2 - polish):
  Team 1: Checksum response headers, store MD5/SHA-1 at upload
  Team 2: SNAPSHOT version-level metadata generation
  Team 4: Checksum completeness tests

Phase 4 (P3 - optional, lower priority):
  Team 1: .asc content-type, Expect-Continue verification
  Team 3: Non-unique SNAPSHOTs, SNAPSHOT retention
```

---

## Key Files

| File | Lines | Role |
|------|-------|------|
| `backend/src/api/handlers/maven.rs` | ~1600 | HTTP handler: download, upload, checksum, metadata |
| `backend/src/formats/maven.rs` | ~530 | Format: coordinate parsing, POM parsing, metadata XML generation |
| `backend/src/api/handlers/proxy_helpers.rs` | ~250 | Proxy fetch, virtual repo resolution |
| `backend/src/services/proxy_service.rs` | ~400 | Upstream fetching, caching |
| `scripts/native-tests/test-maven.sh` | ~294 | Native client E2E tests |

## Historical Issues Reference

| Issue | Title | Status | Root Cause |
|-------|-------|--------|------------|
| #140 | SNAPSHOT filename validation error | Closed | `parse_filename` didn't handle timestamp format |
| #297 | SNAPSHOT re-upload blocked | Closed | UNIQUE constraint, fixed with hard-delete |
| #303 | Add E2E tests for SNAPSHOT + S3 | Closed | Test coverage added |
| #321 | SNAPSHOT upload where isDeleted=false | Closed | Soft-delete vs hard-delete confusion |
| #361 | Maven upload with S3 doesn't work | Closed | rust-s3 swallows error bodies on PUT |
| #414 | SNAPSHOT checksum returns XML | Closed | Checksum path hit metadata handler instead |
| #415 | POM+JAR not grouped as single package | Closed | GAV grouping logic added |
| #427 | Can't pull from Maven pull-through cache | Closed | Remote proxy not wired for Maven |
| #450 | Maven virtual members not working | Closed | Virtual member resolution bug |
| #461 | Maven virtual members issues (functional+visual) | **Open** | Regression or incomplete fix from #450 |
| #532 | Checksum not fetched from remote proxy | Closed | No proxy fallback in checksum code path |
