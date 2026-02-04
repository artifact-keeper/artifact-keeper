# Harbor Feature Parity - Implementation Tasks

## Phase 1: Content Trust / Image Signing (P1)

### TASK-001: Cosign signature storage model
**Estimate**: 4 hours
**Dependencies**: None

- [ ] Create `artifact_signatures` table migration
- [ ] Define `ArtifactSignature` model in `models/signature.rs`
- [ ] Implement signature CRUD in `services/signature_service.rs`
- [ ] Handle OCI referrers API for signature discovery
- [ ] Fallback: support tag-based signature storage (`sha256-<digest>.sig`)

### TASK-002: Signature verification service
**Estimate**: 6 hours
**Dependencies**: TASK-001

- [ ] Integrate cosign-rs or shell out to cosign CLI
- [ ] Implement keyless verification (Fulcio/Rekor)
- [ ] Implement key-based verification
- [ ] Cache verification results (signatures are immutable)
- [ ] Map verification status to `ArtifactSignature.verified`

### TASK-003: Signature enforcement policy
**Estimate**: 4 hours
**Dependencies**: TASK-002

- [ ] Add `require_signatures` field to repository config
- [ ] Add signature check to pull/download handlers
- [ ] Return 403 with clear error for unsigned artifacts
- [ ] Bypass for service accounts if configured

### TASK-004: Signature API endpoints
**Estimate**: 3 hours
**Dependencies**: TASK-001, TASK-002

- [ ] `GET /api/v1/artifacts/{id}/signatures` - list signatures
- [ ] `GET /api/v1/artifacts/{id}/signatures/{sig_id}` - signature details
- [ ] `POST /api/v1/artifacts/{id}/signatures/verify` - trigger verification
- [ ] `GET /api/v1/repositories/{id}/signature-policy` - get policy

### TASK-005: Signature UI components
**Estimate**: 4 hours
**Dependencies**: TASK-004

- [ ] Signature badge on artifact cards (signed/unsigned/invalid)
- [ ] Signature details panel in artifact view
- [ ] Signer identity display
- [ ] Signature policy toggle in repo settings

---

## Phase 2: Tag Retention Policies (P1)

### TASK-010: Retention policy data model
**Estimate**: 3 hours
**Dependencies**: None

- [ ] Create `retention_policies` and `retention_rules` table migrations
- [ ] Define models in `models/retention.rs`
- [ ] Implement CRUD service in `services/retention_service.rs`

### TASK-011: Retention rule engine
**Estimate**: 8 hours
**Dependencies**: TASK-010

- [ ] Implement keep-by-count logic
- [ ] Implement keep-by-age logic
- [ ] Implement keep-by-pattern (glob + regex)
- [ ] Implement exclude-pattern logic
- [ ] Rule combination: artifact kept if ANY rule matches
- [ ] Respect immutability flags

### TASK-012: RetentionAdapter trait and core infrastructure
**Estimate**: 4 hours
**Dependencies**: TASK-011

- [ ] Define `RetentionAdapter` trait in `services/retention/adapter.rs`
- [ ] Define `RetentionCandidate` struct with format-agnostic fields
- [ ] Implement adapter registry/factory pattern
- [ ] Add adapter selection based on repository format

### TASK-012a: OCI/Docker retention adapter
**Estimate**: 4 hours
**Dependencies**: TASK-012

- [ ] Implement `OciRetentionAdapter`
- [ ] List tags from OCI repository
- [ ] Handle manifest deletion and layer dereferencing
- [ ] Integration with GC for blob cleanup

### TASK-012b: Helm retention adapter
**Estimate**: 2 hours
**Dependencies**: TASK-012

- [ ] Implement `HelmRetentionAdapter`
- [ ] Parse Helm index.yaml for version listing
- [ ] Update index.yaml after version deletion

### TASK-012c: npm retention adapter
**Estimate**: 4 hours
**Dependencies**: TASK-012

- [ ] Implement `NpmRetentionAdapter`
- [ ] List versions from npm package metadata
- [ ] Protect dist-tags from deletion
- [ ] Detect and warn on dist-tag orphaning
- [ ] Handle prerelease version detection

### TASK-012d: Maven retention adapter
**Estimate**: 5 hours
**Dependencies**: TASK-012

- [ ] Implement `MavenRetentionAdapter`
- [ ] List versions from maven-metadata.xml
- [ ] Special handling for SNAPSHOTs
- [ ] Enumerate timestamped SNAPSHOT builds
- [ ] "Keep latest N SNAPSHOT builds" rule support
- [ ] Update maven-metadata.xml after deletion

### TASK-012e: PyPI retention adapter
**Estimate**: 3 hours
**Dependencies**: TASK-012

- [ ] Implement `PypiRetentionAdapter`
- [ ] List versions from simple index
- [ ] Detect prereleases (dev, alpha, beta, rc)
- [ ] Handle yanked versions

### TASK-012f: Debian/RPM/Alpine retention adapters
**Estimate**: 4 hours
**Dependencies**: TASK-012

- [ ] Implement `DebianRetentionAdapter`
- [ ] Implement `RpmRetentionAdapter`
- [ ] Implement `AlpineRetentionAdapter`
- [ ] Architecture-aware retention (keep per arch)
- [ ] Update package indices after deletion

### TASK-012g: Generic retention adapter
**Estimate**: 2 hours
**Dependencies**: TASK-012

- [ ] Implement `GenericRetentionAdapter`
- [ ] Path-based candidate listing
- [ ] Pattern matching on paths
- [ ] Age-based deletion support

### TASK-013: Retention execution engine
**Estimate**: 4 hours
**Dependencies**: TASK-011, TASK-012

- [ ] Dry-run mode (preview deletions)
- [ ] Scheduled execution (cron-based)
- [ ] On-demand execution via API
- [ ] Audit logging of all deletions
- [ ] Progress tracking for large repos

### TASK-014: Retention API endpoints
**Estimate**: 3 hours
**Dependencies**: TASK-010, TASK-013

- [ ] `POST /api/v1/repositories/{id}/retention-policies` - create policy
- [ ] `GET /api/v1/repositories/{id}/retention-policies` - list policies
- [ ] `PUT /api/v1/retention-policies/{id}` - update policy
- [ ] `DELETE /api/v1/retention-policies/{id}` - delete policy
- [ ] `POST /api/v1/retention-policies/{id}/execute` - run now
- [ ] `POST /api/v1/retention-policies/{id}/dry-run` - preview

### TASK-015: Retention UI
**Estimate**: 5 hours
**Dependencies**: TASK-014

- [ ] Retention policy list in repo settings
- [ ] Policy creation wizard with rule builder
- [ ] Dry-run preview modal
- [ ] Execution history and logs
- [ ] Visual rule builder (optional, nice-to-have)

---

## Phase 3: Garbage Collection (P1)

### TASK-020: GC data model and tracking
**Estimate**: 2 hours
**Dependencies**: None

- [ ] Create `gc_runs` table migration
- [ ] Create `blob_references` table (if not tracking refs already)
- [ ] Define models in `models/gc.rs`

### TASK-021: Mark-and-sweep GC algorithm
**Estimate**: 8 hours
**Dependencies**: TASK-020

- [ ] Mark phase: traverse all artifacts, collect referenced blob digests
- [ ] Sweep phase: delete blobs not in marked set
- [ ] Handle concurrent pushes (don't delete blobs being uploaded)
- [ ] Use soft-delete with delay before physical delete
- [ ] Support both S3 and filesystem storage backends

### TASK-022: GC execution engine
**Estimate**: 4 hours
**Dependencies**: TASK-021

- [ ] Dry-run mode
- [ ] Scheduled execution
- [ ] On-demand execution
- [ ] Progress reporting (blobs scanned, deleted, bytes reclaimed)
- [ ] Configurable batch size and parallelism

### TASK-023: GC API endpoints
**Estimate**: 2 hours
**Dependencies**: TASK-022

- [ ] `POST /api/v1/admin/gc` - trigger GC
- [ ] `POST /api/v1/admin/gc/dry-run` - preview GC
- [ ] `GET /api/v1/admin/gc/history` - list past runs
- [ ] `GET /api/v1/admin/gc/{id}` - run details

### TASK-024: GC UI
**Estimate**: 3 hours
**Dependencies**: TASK-023

- [ ] GC panel in admin settings
- [ ] Run now / dry-run buttons
- [ ] History table with stats
- [ ] Storage usage before/after visualization

---

## Phase 4: Trivy Integration (P2)

### TASK-030: Trivy scanner adapter
**Estimate**: 6 hours
**Dependencies**: None

- [ ] Create `TrivyScanner` implementing `Scanner` trait
- [ ] Shell out to `trivy image` or use Trivy server mode
- [ ] Parse Trivy JSON output into `RawFinding`
- [ ] Map Trivy severity to existing `Severity` enum
- [ ] Handle Trivy-specific fields (CVSS, references)

### TASK-031: Trivy deployment options
**Estimate**: 4 hours
**Dependencies**: TASK-030

- [ ] Document sidecar deployment in docker-compose
- [ ] Document Trivy server mode for Kubernetes
- [ ] Add Trivy configuration to `Config`
- [ ] Implement health check for Trivy availability
- [ ] Fallback to OSV.dev when Trivy unavailable

### TASK-032: Container image scanning improvements
**Estimate**: 4 hours
**Dependencies**: TASK-030

- [ ] Scan on push (already exists, ensure Trivy path works)
- [ ] Scan on pull for proxy repos
- [ ] Re-scan when Trivy DB updates
- [ ] Layer-by-layer scan results (nice-to-have)

### TASK-033: SBOM scanning via Trivy
**Estimate**: 3 hours
**Dependencies**: TASK-030

- [ ] Detect CycloneDX and SPDX formats
- [ ] Pass SBOM to Trivy for scanning
- [ ] Store SBOM scan results

---

## Phase 5: CVE Allowlisting (P2)

### TASK-040: Allowlist data model
**Estimate**: 2 hours
**Dependencies**: None

- [ ] Create `cve_allowlist` table migration
- [ ] Define model in `models/security.rs` (extend existing)
- [ ] Implement CRUD service

### TASK-041: Allowlist enforcement
**Estimate**: 4 hours
**Dependencies**: TASK-040

- [ ] Modify policy evaluation to check allowlist
- [ ] Support global vs per-repo allowlisting
- [ ] Handle expiration (auto-un-acknowledge)
- [ ] Require justification on create

### TASK-042: Allowlist API endpoints
**Estimate**: 2 hours
**Dependencies**: TASK-040, TASK-041

- [ ] `POST /api/v1/security/allowlist` - add CVE
- [ ] `GET /api/v1/security/allowlist` - list all
- [ ] `DELETE /api/v1/security/allowlist/{id}` - remove
- [ ] `POST /api/v1/security/allowlist/bulk` - bulk add

### TASK-043: Allowlist UI
**Estimate**: 3 hours
**Dependencies**: TASK-042

- [ ] Allowlist management page in security section
- [ ] "Acknowledge" button on scan findings
- [ ] Justification modal with required text
- [ ] Expiration date picker
- [ ] Bulk selection and acknowledgment

---

## Phase 6: Replication Policies (P2)

### TASK-050: Replication data model
**Estimate**: 3 hours
**Dependencies**: None

- [ ] Create `replication_policies`, `replication_executions`, `remote_registries` tables
- [ ] Define models
- [ ] Implement CRUD services

### TASK-051: Remote registry connectors
**Estimate**: 8 hours
**Dependencies**: TASK-050

- [ ] Abstract `RemoteRegistry` trait
- [ ] Implement Docker Hub connector
- [ ] Implement GHCR connector
- [ ] Implement Harbor connector
- [ ] Implement generic OCI registry connector
- [ ] Implement ECR/GCR/ACR connectors (AWS/GCP/Azure auth)

### TASK-052: Push replication engine
**Estimate**: 6 hours
**Dependencies**: TASK-051

- [ ] Webhook trigger on artifact push
- [ ] Filter matching (repo pattern, tag pattern)
- [ ] Push artifact to remote registry
- [ ] Track execution status
- [ ] Retry failed transfers

### TASK-053: Pull replication engine
**Estimate**: 4 hours
**Dependencies**: TASK-051

- [ ] Scheduled pull from remote
- [ ] Filter matching
- [ ] Download and store locally
- [ ] Track execution status

### TASK-054: Replication API endpoints
**Estimate**: 3 hours
**Dependencies**: TASK-050, TASK-052, TASK-053

- [ ] Full CRUD for policies and remote registries
- [ ] Execution history endpoints
- [ ] Manual trigger endpoint
- [ ] Connection test endpoint

### TASK-055: Replication UI
**Estimate**: 5 hours
**Dependencies**: TASK-054

- [ ] Remote registry management
- [ ] Replication policy creation wizard
- [ ] Execution history and logs
- [ ] Connection test UI

---

## Estimates Summary

| Phase | Hours |
|-------|-------|
| Phase 1: Content Trust | ~21 hours |
| Phase 2: Tag Retention (Core) | ~15 hours |
| Phase 2a-g: Format Adapters | ~28 hours |
| Phase 3: Garbage Collection | ~19 hours |
| Phase 4: Trivy Integration | ~17 hours |
| Phase 5: CVE Allowlisting | ~11 hours |
| Phase 6: Replication | ~29 hours |

**Total**: ~140 hours (~3.5-4 weeks full-time)

**Recommended order**:
1. GC (foundational, enables retention)
2. Tag Retention Core + OCI Adapter (proves the model)
3. Additional Format Adapters (npm, Maven priority)
4. Content Trust (enterprise requirement)
5. Trivy Integration (security depth)
6. CVE Allowlisting (security workflow)
7. Replication (enterprise scale)

**Format Adapter Priority**:
1. OCI/Docker (most common, proves architecture)
2. npm (large ecosystem, dist-tag complexity)
3. Maven (enterprise Java, SNAPSHOT handling)
4. Helm (Kubernetes workflows)
5. PyPI (growing ML/AI usage)
6. Debian/RPM (system packages)
7. Generic (catch-all)
