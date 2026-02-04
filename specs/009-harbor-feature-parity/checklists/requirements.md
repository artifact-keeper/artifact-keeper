# Harbor Feature Parity - Requirements Checklist

## Content Trust / Image Signing

- [ ] **SIG-001**: Cosign signatures can be stored alongside OCI artifacts
- [ ] **SIG-002**: Signatures discoverable via OCI referrers API
- [ ] **SIG-003**: Keyless signing verification (Fulcio/Rekor) works
- [ ] **SIG-004**: Key-based signing verification works
- [ ] **SIG-005**: Repository can enforce signature requirement
- [ ] **SIG-006**: Unsigned pulls blocked with clear error when policy enabled
- [ ] **SIG-007**: Signature status visible in UI
- [ ] **SIG-008**: Signer identity displayed

## Tag Retention Policies (Core)

- [ ] **RET-001**: Keep-by-count rules work (keep latest N)
- [ ] **RET-002**: Keep-by-age rules work (keep newer than N days)
- [ ] **RET-003**: Keep-by-pattern rules work (glob/regex on tag)
- [ ] **RET-004**: Exclude-pattern rules work (never delete matching)
- [ ] **RET-005**: Multiple rules combine correctly (keep if ANY matches)
- [ ] **RET-006**: Immutable artifacts are never deleted by retention
- [ ] **RET-007**: Dry-run shows what would be deleted
- [ ] **RET-008**: Scheduled execution works
- [ ] **RET-009**: All deletions logged to audit

## Tag Retention (Format Adapters)

### OCI/Docker
- [ ] **RET-OCI-001**: Tag listing works
- [ ] **RET-OCI-002**: Tag deletion removes manifest reference
- [ ] **RET-OCI-003**: Shared layers preserved when one tag deleted

### npm
- [ ] **RET-NPM-001**: Version listing works
- [ ] **RET-NPM-002**: Dist-tags (`latest`, `next`, etc.) never deleted
- [ ] **RET-NPM-003**: Warning shown when retention would orphan dist-tag
- [ ] **RET-NPM-004**: Prerelease versions detected correctly
- [ ] **RET-NPM-005**: Version deletion blocked if dist-tag points to it

### Maven
- [ ] **RET-MVN-001**: Version listing from maven-metadata.xml works
- [ ] **RET-MVN-002**: SNAPSHOT builds enumerated correctly
- [ ] **RET-MVN-003**: "Keep latest N SNAPSHOT builds" rule works
- [ ] **RET-MVN-004**: maven-metadata.xml updated after deletion
- [ ] **RET-MVN-005**: Release versions handled separately from SNAPSHOTs

### Helm
- [ ] **RET-HELM-001**: Chart versions listed from index.yaml
- [ ] **RET-HELM-002**: Chart deletion updates index.yaml

### PyPI
- [ ] **RET-PYPI-001**: Version listing works
- [ ] **RET-PYPI-002**: Prereleases (dev, alpha, beta, rc) detected
- [ ] **RET-PYPI-003**: Yanked versions handled correctly

### Debian/RPM/Alpine
- [ ] **RET-DEB-001**: Architecture-aware retention works
- [ ] **RET-DEB-002**: "Keep latest N per architecture" rule works
- [ ] **RET-DEB-003**: Package indices updated after deletion

### Generic
- [ ] **RET-GEN-001**: Path-based listing works
- [ ] **RET-GEN-002**: Path pattern matching works
- [ ] **RET-GEN-003**: Age-based deletion works

## Garbage Collection

- [ ] **GC-001**: Mark-and-sweep identifies orphaned blobs
- [ ] **GC-002**: Referenced blobs are never deleted
- [ ] **GC-003**: Shared blobs preserved when only some references deleted
- [ ] **GC-004**: GC doesn't block concurrent pushes
- [ ] **GC-005**: Dry-run shows reclaimable space
- [ ] **GC-006**: Scheduled GC works
- [ ] **GC-007**: On-demand GC works
- [ ] **GC-008**: GC stats reported (blobs deleted, bytes reclaimed)
- [ ] **GC-009**: GC works with S3 storage backend
- [ ] **GC-010**: GC works with filesystem storage backend

## Trivy Integration

- [ ] **TRV-001**: Trivy scanner can be enabled alongside OSV.dev
- [ ] **TRV-002**: Trivy scans container images on push
- [ ] **TRV-003**: Trivy findings mapped to existing finding model
- [ ] **TRV-004**: Trivy severity mapped correctly
- [ ] **TRV-005**: Fallback to OSV.dev when Trivy unavailable
- [ ] **TRV-006**: Trivy server mode supported
- [ ] **TRV-007**: SBOM scanning via Trivy works (CycloneDX, SPDX)

## CVE Allowlisting

- [ ] **CVE-001**: CVE can be added to allowlist with justification
- [ ] **CVE-002**: Allowlist supports expiration dates
- [ ] **CVE-003**: Expired entries auto-un-acknowledge
- [ ] **CVE-004**: Allowlisted CVEs excluded from policy violations
- [ ] **CVE-005**: Global allowlist applies to all repos
- [ ] **CVE-006**: Per-repo allowlist overrides global
- [ ] **CVE-007**: Allowlist changes logged to audit
- [ ] **CVE-008**: Bulk allowlisting works

## Replication Policies

- [ ] **REP-001**: Push replication triggers on artifact push
- [ ] **REP-002**: Pull replication runs on schedule
- [ ] **REP-003**: Repo pattern filtering works
- [ ] **REP-004**: Tag pattern filtering works
- [ ] **REP-005**: Replication to Docker Hub works
- [ ] **REP-006**: Replication to GHCR works
- [ ] **REP-007**: Replication to Harbor works
- [ ] **REP-008**: Replication to/from ECR works
- [ ] **REP-009**: Replication to/from other Artifact Keeper instances works
- [ ] **REP-010**: Failed items can be retried
- [ ] **REP-011**: Execution history tracked

## Non-Functional

- [ ] **NFR-001**: GC completes without downtime
- [ ] **NFR-002**: Retention processes 10k tags in <5 minutes
- [ ] **NFR-003**: Signature verification adds <100ms latency
- [ ] **NFR-004**: Replication supports parallel transfers
