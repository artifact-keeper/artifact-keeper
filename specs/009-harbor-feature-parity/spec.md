# Feature Specification: Harbor Feature Parity

**Feature Branch**: `009-harbor-feature-parity`
**Created**: 2026-01-30
**Status**: Draft
**Input**: Add Harbor's key differentiating features to Artifact Keeper to provide best-in-class container registry capabilities while maintaining universal format support.

## Background

Harbor (CNCF graduated project) is the leading open-source container registry. While Artifact Keeper already supports OCI/Docker images alongside 40+ other formats, Harbor has several container-focused features that enterprises expect. Adding these features positions Artifact Keeper as "Harbor + everything else" — a compelling value proposition.

### What Artifact Keeper Already Has

| Feature | Status | Notes |
|---------|--------|-------|
| Vulnerability Scanning | ✓ Implemented | OSV.dev + GitHub Advisory |
| Storage Quotas | ✓ Implemented | Per-repository |
| Immutable Artifacts | ✓ Implemented | Prevents overwrites |
| API Tokens | ✓ Implemented | Scoped, expiring tokens |
| Proxy Cache | ✓ Implemented | Remote repo caching |
| Edge Replication | ✓ Implemented | Sync to edge nodes |
| Security Policies | ✓ Implemented | Block on severity |
| Quarantine | ✓ Implemented | Hold flagged artifacts |
| Retention (audit/backup) | ✓ Implemented | Cleanup old records |
| LDAP/SAML/OIDC | ✓ Implemented | Enterprise auth |

### What This Spec Adds

| Feature | Priority | Harbor Equivalent |
|---------|----------|-------------------|
| Content Trust (Image Signing) | P1 | Cosign/Notary |
| Tag Retention Policies | P1 | Tag retention rules |
| Artifact Garbage Collection | P1 | GC for orphaned blobs |
| Trivy Scanner Integration | P2 | Native Trivy support |
| CVE Allowlisting | P2 | Vulnerability exceptions |
| Replication Policies | P2 | Multi-site replication rules |
| P2P Distribution | P3 | Dragonfly/Kraken integration |
| Project-level Quotas | P3 | Quota inheritance |

---

## Architecture: Universal Retention Model

### The Challenge

Harbor's retention system was designed for containers only. Artifact Keeper supports 40+ formats, each with different versioning semantics. A universal retention system must understand these differences.

### Format Classification

All artifact formats fall into one of these categories:

#### Category 1: Tag-Based (Mutable References)

These formats have **mutable tags** that point to **immutable content**. Multiple tags can reference the same content, and tags can be moved to point to different content.

| Format | Tag Mechanism | Content Address | Example |
|--------|--------------|-----------------|---------|
| **OCI/Docker** | Image tags | Manifest digest | `myapp:v1.2.3` → `sha256:abc123` |
| **Helm** | Chart version in index | Chart digest | `mychart:0.1.0` → `sha256:def456` |
| **OCI Artifacts** | Generic tags | Manifest digest | `policy:latest` → `sha256:789xyz` |

**Retention Strategy**: Classic Harbor-style. Delete tags, then GC unreferenced blobs.

#### Category 2: Floating Tags + Versions (Hybrid)

These formats have **both** mutable "dist-tags" AND immutable versions. The dist-tags are pointers to versions.

| Format | Floating Tags | Versions | Example |
|--------|--------------|----------|---------|
| **npm** | `latest`, `next`, `beta`, `canary` | `1.2.3`, `1.2.4-rc.1` | `latest` → `1.2.3` |

**Retention Strategy**:
- Never delete dist-tags themselves
- Delete *versions* based on rules
- Block deletion of versions that dist-tags point to
- Warn user if retention would orphan a dist-tag

#### Category 3: Version-Based (Immutable)

These formats have **only immutable versions**. Once published, a version cannot be changed (only yanked/deprecated).

| Format | Version Format | Mutability | Notes |
|--------|---------------|------------|-------|
| **Maven** | `groupId:artifactId:version` | Releases immutable | SNAPSHOTs are special (see below) |
| **PyPI** | `package==1.2.3` | Immutable | Can yank but not republish |
| **NuGet** | `Package.1.2.3` | Immutable | Can unlist but not delete |
| **Cargo** | `crate@1.2.3` | Immutable | Can yank |
| **Go** | `module@v1.2.3` | Immutable | Proxy caches make deletion complex |
| **RubyGems** | `gem-1.2.3` | Immutable | Can yank |
| **Hex** | `package@1.2.3` | Immutable | Erlang/Elixir ecosystem |
| **Pub** | `package@1.2.3` | Immutable | Dart/Flutter |

**Retention Strategy**: Delete by version pattern or age. "Keep versions matching `1.*`" or "Delete versions older than 90 days".

#### Category 4: SNAPSHOT/Development Builds

These are mutable development versions that accumulate multiple builds over time.

| Format | Mechanism | Example |
|--------|----------|---------|
| **Maven SNAPSHOT** | Timestamped builds | `1.0-SNAPSHOT` has builds `1.0-20260130.143022-1`, `1.0-20260130.152033-2` |
| **npm prerelease** | Multiple prereleases | `1.0.0-alpha.1`, `1.0.0-alpha.2`, ... `1.0.0-alpha.47` |
| **PyPI dev/pre** | Dev releases | `1.0.dev1`, `1.0.dev2`, `1.0a1`, `1.0b1` |

**Retention Strategy**: "Keep latest N builds per SNAPSHOT version" or "Keep prereleases from last 7 days".

#### Category 5: System Packages (Multi-Architecture)

These formats have versions but also architecture/distribution dimensions.

| Format | Dimensions | Example |
|--------|-----------|---------|
| **Debian** | version + arch + distro | `nginx_1.24.0-1_amd64.deb` for `bookworm` |
| **RPM** | version + arch + release | `nginx-1.24.0-1.el9.x86_64.rpm` |
| **Alpine** | version + arch | `nginx-1.24.0-r0.apk` for `x86_64` |

**Retention Strategy**: Delete by version, but consider arch. "Keep latest 3 versions per architecture".

#### Category 6: Generic/Raw

Binary blobs with user-defined paths. No built-in versioning semantics.

| Format | Addressing | Example |
|--------|-----------|---------|
| **Generic** | Path-based | `/releases/myapp/1.2.3/myapp-linux-amd64` |
| **GitLFS** | OID-based | Large files tracked by Git |

**Retention Strategy**: Path pattern + age. "Delete files in `/snapshots/` older than 30 days".

### Retention Adapter Interface

To support all formats cleanly, implement a `RetentionAdapter` trait:

```rust
pub trait RetentionAdapter: Send + Sync {
    /// Get the format this adapter handles
    fn format(&self) -> PackageFormat;

    /// List all retention candidates in a repository
    /// Returns (identifier, created_at, metadata) tuples
    async fn list_candidates(&self, repo_id: Uuid) -> Result<Vec<RetentionCandidate>>;

    /// Check if a candidate is protected (e.g., dist-tag target)
    async fn is_protected(&self, candidate: &RetentionCandidate) -> Result<bool>;

    /// Delete a candidate (tag, version, or artifact)
    async fn delete(&self, candidate: &RetentionCandidate) -> Result<()>;

    /// Get format-specific rule types supported
    fn supported_rule_types(&self) -> Vec<RuleType>;
}

pub struct RetentionCandidate {
    pub id: Uuid,
    pub identifier: String,      // tag, version, or path
    pub created_at: DateTime<Utc>,
    pub size_bytes: i64,
    pub labels: HashMap<String, String>,
    pub is_prerelease: bool,
    pub digest: Option<String>,  // for dedup detection
}
```

### Format-Specific Implementations

| Format | Adapter | Special Handling |
|--------|---------|------------------|
| OCI/Docker | `OciRetentionAdapter` | Tag listing, manifest GC |
| Helm | `HelmRetentionAdapter` | Chart index management |
| npm | `NpmRetentionAdapter` | Dist-tag protection |
| Maven | `MavenRetentionAdapter` | SNAPSHOT build enumeration |
| PyPI | `PypiRetentionAdapter` | Prerelease detection |
| Debian | `DebianRetentionAdapter` | Arch-aware retention |
| Generic | `GenericRetentionAdapter` | Path-based rules |

---

### User Story 1 - Content Trust / Image Signing (Priority: P1)

As a security engineer, I want to sign container images and verify signatures before deployment so that I can ensure only trusted images run in production.

**Why this priority**: Supply chain security is critical. Signing is table stakes for enterprise container workflows. Kubernetes admission controllers (e.g., Kyverno, OPA Gatekeeper) require signature verification.

**Acceptance Scenarios**:

1. **Given** I have a Cosign keypair, **When** I push a signed image to Artifact Keeper, **Then** the signature is stored alongside the image and visible in the UI
2. **Given** an image has a valid signature, **When** I view the image details, **Then** I see signature status, signer identity, and timestamp
3. **Given** I configure a repository to require signatures, **When** someone tries to pull an unsigned image, **Then** the pull is blocked with a clear error message
4. **Given** I want to verify signatures programmatically, **When** I query the API, **Then** I receive signature verification status and signer metadata

**Technical Notes**:
- Support Cosign (Sigstore) as primary signing method
- Store signatures as OCI artifacts (referrers API or tag-based fallback)
- Support keyless signing via Fulcio/Rekor for transparency logs
- Consider Notation (CNCF project, Docker/Microsoft backed) as secondary option

---

### User Story 2 - Tag Retention Policies (Priority: P1)

As a DevOps engineer, I want to automatically delete old image tags based on configurable rules so that storage doesn't grow unbounded and I keep only relevant versions.

**Why this priority**: Container registries accumulate thousands of tags quickly. Manual cleanup is unsustainable. This is one of Harbor's most-used features.

**Acceptance Scenarios**:

1. **Given** I create a retention policy for a repository, **When** I specify "keep latest 10 tags matching `v*`", **Then** older matching tags are automatically deleted on schedule
2. **Given** I have multiple retention rules, **When** rules overlap, **Then** the most permissive rule wins (artifact is kept if ANY rule says keep)
3. **Given** an artifact is protected by immutability, **When** retention runs, **Then** the immutable artifact is skipped and logged
4. **Given** I want to preview retention effects, **When** I run a dry-run, **Then** I see which tags would be deleted without actually deleting them

**Rule Types to Support**:
- Keep by count: "Keep latest N tags"
- Keep by age: "Keep tags newer than N days"
- Keep by pattern: "Keep tags matching regex/glob"
- Keep by label: "Keep tags with specific labels"
- Exclude pattern: "Never delete tags matching pattern"

**Format-Specific Considerations**:

| Format | Tag/Version Model | Retention Notes |
|--------|------------------|-----------------|
| OCI/Docker | Tags (`myapp:v1.2.3`) | Classic tag retention |
| Helm | Chart versions | Same as OCI |
| OCI Artifacts | Generic OCI tags | Same as OCI |
| npm | Dist-tags (`latest`, `next`) | Never delete dist-tags, only unpublish versions |
| Maven | `groupId:artifactId:version` | Keep by version pattern; special handling for SNAPSHOTs (keep latest N builds) |
| PyPI/NuGet/Cargo/Go | Immutable versions | Keep by version pattern/age |
| Debian/RPM | Package versions | Keep by version/age, consider arch |

**npm Dist-Tags**: npm has both versions (`1.2.3`) and dist-tags (`latest` → `1.2.3`). Retention should target *versions*, not dist-tags. A version can be unpublished only if no dist-tag points to it.

**Maven SNAPSHOTs**: A single SNAPSHOT version (e.g., `1.0-SNAPSHOT`) can have many timestamped builds. Retention should support "keep latest N snapshot builds per version."

---

### User Story 3 - Garbage Collection (Priority: P1)

As a system administrator, I want to reclaim storage by removing orphaned blobs and layers so that disk usage reflects actual artifact content.

**Why this priority**: Deleting tags doesn't free storage — the underlying blobs remain. Without GC, storage grows forever.

**Acceptance Scenarios**:

1. **Given** I delete an image tag, **When** garbage collection runs, **Then** unreferenced layers/blobs are removed and storage is reclaimed
2. **Given** two images share a common layer, **When** I delete one image and run GC, **Then** the shared layer is preserved (still referenced)
3. **Given** GC is running, **When** a new push occurs, **Then** the push succeeds (GC doesn't block writes)
4. **Given** I want to see GC impact before running, **When** I request a GC dry-run, **Then** I see estimated reclaimable space and affected blobs

**Technical Notes**:
- Mark-and-sweep algorithm: mark all referenced blobs, delete unmarked
- Support online GC (no downtime) with read-write locking on blobs
- Schedule-based and on-demand execution
- Report: blobs deleted, space reclaimed, duration

---

### User Story 4 - Trivy Scanner Integration (Priority: P2)

As a security engineer, I want to scan container images with Trivy so that I get comprehensive vulnerability detection including OS packages, language dependencies, and misconfigurations.

**Why this priority**: Current OSV.dev scanning is good for dependency manifests but Trivy provides deeper container image analysis (OS packages, Dockerfile issues, secrets detection).

**Acceptance Scenarios**:

1. **Given** I push a container image, **When** scanning is enabled, **Then** Trivy analyzes all layers and reports OS + application vulnerabilities
2. **Given** Trivy finds vulnerabilities, **When** I view scan results, **Then** I see CVE details, severity, affected package, and fixed version (same as current UI)
3. **Given** I want to scan non-container artifacts, **When** I push a filesystem tarball or SBOM, **Then** Trivy scans it appropriately
4. **Given** Trivy is unavailable, **When** a scan is requested, **Then** the system falls back to OSV.dev scanning and logs a warning

**Technical Notes**:
- Run Trivy as sidecar container or external service
- Use Trivy's `--format json` for structured output
- Map Trivy findings to existing `ScanFinding` model
- Support scanning: container images, filesystem archives, SBOMs (CycloneDX, SPDX)

---

### User Story 5 - CVE Allowlisting (Priority: P2)

As a security engineer, I want to acknowledge/allowlist specific CVEs so that known-acceptable vulnerabilities don't block deployments or clutter dashboards.

**Why this priority**: Not all CVEs are exploitable in every context. Teams need to accept risk for specific vulnerabilities without disabling scanning entirely.

**Acceptance Scenarios**:

1. **Given** a scan finds CVE-2023-12345, **When** I add it to the allowlist with justification, **Then** future scans still detect it but mark it as "acknowledged"
2. **Given** a CVE is allowlisted, **When** security policies evaluate, **Then** the acknowledged CVE doesn't trigger policy violations
3. **Given** I allowlist a CVE with an expiration date, **When** the date passes, **Then** the CVE is automatically un-acknowledged
4. **Given** I want to see all allowlisted CVEs, **When** I view the security dashboard, **Then** I see a summary of acknowledged vulnerabilities with justifications

**Note**: Artifact Keeper already has `is_acknowledged` on findings. This story extends it with:
- Expiration dates
- Required justification text
- Audit trail of who acknowledged what
- Bulk operations (allowlist CVE across all repos)

---

### User Story 6 - Replication Policies (Priority: P2)

As a platform engineer, I want to configure replication rules that automatically sync artifacts between registries so that I can implement multi-region deployments and DR strategies.

**Why this priority**: Enterprises need artifacts available in multiple regions. Current edge sync is pull-based; this adds push-based replication with filtering.

**Acceptance Scenarios**:

1. **Given** I configure a replication policy to push to a remote registry, **When** matching artifacts are pushed locally, **Then** they are automatically replicated to the target
2. **Given** I specify filter rules (repo pattern, tag pattern), **When** replication runs, **Then** only matching artifacts are synced
3. **Given** replication fails, **When** I check the replication log, **Then** I see detailed error information and can retry failed items
4. **Given** I want to replicate from an external registry, **When** I configure a pull-based policy, **Then** matching artifacts are pulled on schedule

**Supported Targets**:
- Other Artifact Keeper instances
- Harbor registries
- Docker Hub / GHCR / ECR / GCR / ACR (push and pull)
- Generic OCI registries

---

### User Story 7 - P2P Distribution (Priority: P3)

As a platform engineer managing large Kubernetes clusters, I want to distribute images via peer-to-peer so that pulling large images to thousands of nodes doesn't overwhelm the registry.

**Why this priority**: Important for very large scale (1000+ nodes) but not needed for most deployments. Defer until there's customer demand.

**Acceptance Scenarios**:

1. **Given** P2P distribution is enabled, **When** multiple nodes pull the same image simultaneously, **Then** nodes share layers peer-to-peer, reducing registry load
2. **Given** I use Dragonfly or Kraken, **When** I configure Artifact Keeper as upstream, **Then** the P2P system caches and distributes artifacts

**Technical Notes**:
- Integrate as optional plugin, not core functionality
- Support Dragonfly (Alibaba, CNCF incubating) and Kraken (Uber)
- Provide documentation for setup, not necessarily native integration

---

## Requirements

### Functional Requirements

**Content Trust**
- **FR-001**: System MUST store OCI artifact signatures using the referrers API or fallback tag scheme
- **FR-002**: System MUST support Cosign signature format and verification
- **FR-003**: System MUST support signature verification via Fulcio/Rekor (keyless signing)
- **FR-004**: System MUST allow per-repository policy to require valid signatures for pulls
- **FR-005**: System SHOULD support Notation signatures (future consideration)

**Tag Retention (Core)**
- **FR-010**: System MUST support retention policies with keep-by-count rules
- **FR-011**: System MUST support retention policies with keep-by-age rules
- **FR-012**: System MUST support retention policies with pattern matching (glob/regex)
- **FR-013**: System MUST respect immutability flags during retention execution
- **FR-014**: System MUST support dry-run mode for retention policies
- **FR-015**: System MUST log all retention actions to audit log

**Tag Retention (Format-Specific)**
- **FR-016**: System MUST implement `RetentionAdapter` trait for format-specific behavior
- **FR-017**: System MUST protect npm dist-tags from deletion; only delete versions
- **FR-018**: System MUST support "keep latest N SNAPSHOT builds" for Maven
- **FR-019**: System MUST support architecture-aware retention for Debian/RPM/Alpine
- **FR-020**: System MUST detect and warn when retention would orphan an npm dist-tag
- **FR-021**: System MUST support prerelease detection for PyPI, npm, Cargo retention
- **FR-022**: System MUST support path-based retention rules for Generic format

**Garbage Collection**
- **FR-030**: System MUST implement mark-and-sweep garbage collection for orphaned blobs
- **FR-031**: System MUST support online GC without blocking registry operations
- **FR-032**: System MUST support scheduled and on-demand GC execution
- **FR-033**: System MUST report GC statistics (blobs deleted, space reclaimed)
- **FR-034**: System MUST support dry-run mode for GC

**Trivy Integration**
- **FR-040**: System MUST support Trivy as an optional scanner backend
- **FR-041**: System MUST map Trivy JSON output to existing finding model
- **FR-042**: System MUST support scanning container images via Trivy
- **FR-043**: System SHOULD support scanning SBOMs via Trivy
- **FR-044**: System MUST gracefully fallback if Trivy is unavailable

**CVE Allowlisting**
- **FR-050**: System MUST support allowlisting CVEs with required justification
- **FR-051**: System MUST support expiration dates on allowlist entries
- **FR-052**: System MUST exclude acknowledged CVEs from policy violations
- **FR-053**: System MUST audit all allowlist changes
- **FR-054**: System SHOULD support bulk allowlisting across repositories

**Replication**
- **FR-060**: System MUST support push-based replication to remote registries
- **FR-061**: System MUST support pull-based replication from remote registries
- **FR-062**: System MUST support filtering by repository and tag patterns
- **FR-063**: System MUST log replication status and support retry of failed items
- **FR-064**: System MUST support replication to/from: Artifact Keeper, Harbor, Docker Hub, GHCR, ECR, GCR, ACR

### Non-Functional Requirements

- **NFR-001**: Garbage collection MUST NOT cause downtime or block pushes/pulls
- **NFR-002**: Tag retention MUST process 10,000 tags within 5 minutes
- **NFR-003**: Signature verification MUST add less than 100ms latency to pulls
- **NFR-004**: Replication MUST support concurrent transfers (configurable parallelism)

---

## Data Model Changes

### New Tables

```sql
-- Tag retention policies
CREATE TABLE retention_policies (
    id UUID PRIMARY KEY,
    repository_id UUID REFERENCES repositories(id),
    name VARCHAR(255) NOT NULL,
    is_enabled BOOLEAN DEFAULT true,
    schedule VARCHAR(100), -- cron expression
    last_run_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE retention_rules (
    id UUID PRIMARY KEY,
    policy_id UUID REFERENCES retention_policies(id) ON DELETE CASCADE,
    rule_type VARCHAR(50) NOT NULL, -- 'keep_count', 'keep_age', 'keep_pattern', 'exclude_pattern'
    tag_pattern VARCHAR(255), -- glob or regex
    keep_count INTEGER, -- for keep_count type
    keep_days INTEGER, -- for keep_age type
    priority INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Artifact signatures
CREATE TABLE artifact_signatures (
    id UUID PRIMARY KEY,
    artifact_id UUID REFERENCES artifacts(id) ON DELETE CASCADE,
    signature_type VARCHAR(50) NOT NULL, -- 'cosign', 'notation'
    signature_digest VARCHAR(255) NOT NULL,
    signer_identity VARCHAR(512), -- email, OIDC subject, key fingerprint
    signing_key_id VARCHAR(255),
    transparency_log_id VARCHAR(255), -- Rekor entry ID for keyless
    verified BOOLEAN DEFAULT false,
    verified_at TIMESTAMPTZ,
    raw_signature BYTEA,
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- CVE allowlist
CREATE TABLE cve_allowlist (
    id UUID PRIMARY KEY,
    repository_id UUID REFERENCES repositories(id), -- NULL = global
    cve_id VARCHAR(50) NOT NULL,
    justification TEXT NOT NULL,
    expires_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(repository_id, cve_id)
);

-- Replication policies
CREATE TABLE replication_policies (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    direction VARCHAR(10) NOT NULL, -- 'push' or 'pull'
    source_registry_id UUID, -- NULL = local
    target_registry_id UUID, -- NULL = local
    source_repo_pattern VARCHAR(255),
    target_repo_pattern VARCHAR(255),
    tag_pattern VARCHAR(255),
    is_enabled BOOLEAN DEFAULT true,
    schedule VARCHAR(100), -- cron expression, NULL = trigger on push
    last_run_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE replication_executions (
    id UUID PRIMARY KEY,
    policy_id UUID REFERENCES replication_policies(id),
    status VARCHAR(20) NOT NULL, -- 'running', 'completed', 'failed'
    total_items INTEGER DEFAULT 0,
    completed_items INTEGER DEFAULT 0,
    failed_items INTEGER DEFAULT 0,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error_message TEXT
);

-- Remote registry connections
CREATE TABLE remote_registries (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    url VARCHAR(512) NOT NULL,
    registry_type VARCHAR(50) NOT NULL, -- 'artifact-keeper', 'harbor', 'dockerhub', 'ecr', etc.
    auth_type VARCHAR(50), -- 'basic', 'token', 'aws', 'gcp'
    credentials_encrypted BYTEA,
    is_verified BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Garbage collection runs
CREATE TABLE gc_runs (
    id UUID PRIMARY KEY,
    status VARCHAR(20) NOT NULL,
    dry_run BOOLEAN DEFAULT false,
    blobs_scanned INTEGER DEFAULT 0,
    blobs_deleted INTEGER DEFAULT 0,
    bytes_reclaimed BIGINT DEFAULT 0,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error_message TEXT
);
```

---

## Success Criteria

- **SC-001**: Users can sign images with Cosign and Artifact Keeper stores/verifies signatures
- **SC-002**: Tag retention policies can reduce tag count by 90%+ on test repository
- **SC-003**: Garbage collection reclaims >95% of orphaned blob storage
- **SC-004**: Trivy scanner provides vulnerability counts comparable to Harbor for same images
- **SC-005**: Allowlisted CVEs are correctly excluded from policy enforcement
- **SC-006**: Replication successfully syncs images to/from Harbor and Docker Hub

---

## Assumptions

- Trivy will be deployed as a sidecar or external service (not embedded)
- Cosign CLI or compatible library is available for signature operations
- Users understand that GC requires careful timing (not during heavy push activity)
- Replication credentials are securely stored using existing encryption service

---

## Out of Scope

- Native P2P implementation (document integration with Dragonfly/Kraken instead)
- Harbor-to-Artifact-Keeper migration tool (separate spec)
- OCI Distribution Spec 1.1 full compliance (referrers API) — implement progressively
- Notary v1 support (deprecated, focus on Cosign and Notation)
