# Research: Staged Testing Strategy for CI/CD

**Branch**: `005-staged-testing-ci` | **Date**: 2026-01-18

## Overview

This document captures research findings for implementing the staged testing strategy. All major decisions were clarified during specification (13 Q&A items), so this research focuses on best practices and implementation patterns.

---

## 1. GitHub Actions Workflow Patterns

### Decision: Tiered CI with Conditional Jobs

**Rationale**: GitHub Actions supports job-level `if` conditions and `workflow_dispatch` for manual triggers, enabling clean tier separation.

**Best Practices Identified**:
- Use `needs` for job dependencies to create execution order
- Use `if: github.ref == 'refs/heads/main'` for main-branch-only jobs
- Use `workflow_dispatch` with inputs for manual E2E triggering
- Use `workflow_call` to share E2E workflow between manual and release triggers

**Alternatives Considered**:
- Single monolithic workflow with all tests → Rejected (slow feedback on PRs)
- Separate repos for test infrastructure → Rejected (unnecessary complexity)

---

## 2. Docker Compose Profile Strategy

### Decision: Per-Format Profiles + "all" + Default Smoke

**Rationale**: Docker Compose 2.x supports profiles natively, enabling selective service startup.

**Implementation Pattern**:
```yaml
services:
  pypi-test:
    profiles: ["pypi", "all", "smoke"]
  npm-test:
    profiles: ["npm", "all", "smoke"]
  rpm-test:
    profiles: ["rpm", "all"]  # Not in smoke
  deb-test:
    profiles: ["deb", "all"]  # Not in smoke
```

**Smoke Subset** (fastest 3 formats): PyPI, NPM, Cargo
- Rationale: Most commonly used, fastest to test, good coverage indicator

**Alternatives Considered**:
- Separate docker-compose files per format → Rejected (duplication, hard to maintain)
- Makefile targets instead of profiles → Rejected (less Docker-native)

---

## 3. Test Package Generation

### Decision: Generate from Templates in `.assets/`

**Rationale**: Air-gapped approach eliminates external dependencies and flaky tests.

**Implementation Pattern**:
```text
.assets/
├── pypi/
│   ├── pyproject.toml.template
│   └── generate.sh          # Generates wheel/sdist
├── npm/
│   ├── package.json.template
│   └── generate.sh          # Runs npm pack
└── ...
```

**Size Tiers**:
- Small (<1MB): Base package + minimal content
- Medium (~10MB): Add random binary data file
- Large (~100MB): Add larger binary data file

**Generation Script Pattern**:
```bash
#!/bin/bash
# generate.sh - Generates test package with configurable size
SIZE_TIER=${1:-small}
case $SIZE_TIER in
  small)  dd if=/dev/urandom of=data.bin bs=1K count=100 ;;
  medium) dd if=/dev/urandom of=data.bin bs=1M count=10 ;;
  large)  dd if=/dev/urandom of=data.bin bs=1M count=100 ;;
esac
# ... build package
```

**Alternatives Considered**:
- Download from real mirrors → Rejected (network dependency, licensing concerns)
- Pre-built fixtures in git → Rejected (bloats repo, versioning issues)

---

## 4. SSL/TLS Testing with Self-Signed CA

### Decision: Generate CA + Certificates in Test Setup

**Rationale**: Full TLS validation catches certificate chain issues.

**Implementation Pattern**:
```bash
# scripts/pki/generate-certs.sh
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/CN=Test CA"
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=registry.test"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt
```

**Client Trust Configuration**:
| Client | Trust Method |
|--------|--------------|
| pip | `--cert /path/to/ca.crt` or `PIP_CERT` env var |
| npm | `npm config set cafile /path/to/ca.crt` |
| cargo | `CARGO_HTTP_CAINFO=/path/to/ca.crt` |
| dnf | Copy CA to `/etc/pki/ca-trust/source/anchors/` + `update-ca-trust` |
| apt | Copy CA to `/usr/local/share/ca-certificates/` + `update-ca-certificates` |

**Alternatives Considered**:
- Disable TLS verification → Rejected (doesn't test real client behavior)
- Let's Encrypt staging → Rejected (requires network, DNS)

---

## 5. GPG Signing for RPM/Debian

### Decision: Generate Test GPG Keys

**Rationale**: Production RPM/Debian repos require GPG signing; testing validates the full flow.

**Implementation Pattern**:
```bash
# Generate GPG key (non-interactive)
gpg --batch --gen-key <<EOF
Key-Type: RSA
Key-Length: 4096
Name-Real: Test Package Signer
Name-Email: test@registry.local
Expire-Date: 0
%no-protection
EOF

# Export for distribution
gpg --export -a "Test Package Signer" > test-signing-key.pub
```

**RPM Signing**:
```bash
rpmsign --addsign --key-id="Test Package Signer" package.rpm
```

**Debian Signing**:
```bash
# Sign Release file with detached signature
gpg --armor --detach-sign -o Release.gpg Release
# Or inline signature
gpg --clearsign -o InRelease Release
```

**Alternatives Considered**:
- Skip GPG validation → Rejected (doesn't test production behavior)
- Use real keys → Rejected (security risk, key management complexity)

---

## 6. Container Base Images

### Decision: Rocky Linux UBI (RPM) + Debian Official (apt)

**Rationale**: Rocky Linux UBI is RHEL-compatible and production-oriented. Debian official is canonical for apt testing.

**Image Selection**:
| Format | Base Image | Rationale |
|--------|------------|-----------|
| RPM/dnf | `rockylinux/rockylinux:9-ubi` | RHEL-compatible, production UBI |
| Debian/apt | `debian:bookworm-slim` | Official, minimal |
| PyPI | `python:3.11-slim` | Official Python with pip |
| NPM | `node:20-slim` | Official Node with npm |
| Cargo | `rust:1.75-slim` | Official Rust with cargo |
| Go | `golang:1.21-alpine` | Official Go |
| Maven | `maven:3.9-eclipse-temurin-17` | Official Maven |
| Helm | `alpine/helm:latest` | Official Helm CLI |
| Conda | `continuumio/miniconda3` | Official Conda |
| Docker | `docker:24-cli` | Official Docker CLI |

**Pre-pull Strategy**: All base images are pulled during CI job setup (cached) to ensure air-gapped test execution.

---

## 7. Failure Injection Patterns

### Decision: Controlled Service Termination

**Rationale**: Deterministic, reproducible failure scenarios for CI.

**Implementation Patterns**:

**Server Crash Mid-Upload**:
```bash
# Start upload in background
curl -X POST ... &
PID=$!
sleep 0.5  # Wait for upload to start
docker kill backend  # Kill server
wait $PID  # Capture exit code
# Verify: no orphaned artifacts, clean rollback
```

**Database Disconnect**:
```bash
# During active transaction
docker network disconnect e2e-test-network postgres
# Verify: connection error returned, no partial state
docker network connect e2e-test-network postgres
```

**Storage Failure**:
```bash
# Mount read-only to simulate I/O error
docker exec backend mount -o remount,ro /data/storage
# Verify: write fails with clear error
docker exec backend mount -o remount,rw /data/storage
```

**Alternatives Considered**:
- Mock/stub at code level → Rejected (less realistic, misses transport issues)
- Chaos engineering tools → Rejected (overkill for deterministic CI tests)
- Network fault injection → Rejected (more complex, harder to reproduce)

---

## 8. Stress Testing Approach

### Decision: 100 Concurrent Operations

**Rationale**: Catches concurrency bugs, connection pool exhaustion, race conditions without requiring excessive CI resources.

**Implementation Pattern**:
```bash
# Using GNU parallel or similar
seq 100 | parallel -j 100 curl -X POST http://registry/api/artifacts/upload ...

# Or in test code
tokio::spawn(async move {
    let futures: Vec<_> = (0..100)
        .map(|i| upload_artifact(format!("test-{}", i)))
        .collect();
    futures::future::join_all(futures).await
});
```

**Validation Points**:
- Zero data corruption (checksums match)
- No deadlocks (all operations complete within timeout)
- Correct artifact counts in database
- No orphaned files on disk

**Alternatives Considered**:
- 10 concurrent → Rejected (too low to catch real issues)
- 1000+ concurrent → Rejected (requires dedicated infrastructure)

---

## 9. axum-test for Handler Testing

### Decision: Add axum-test Dev Dependency

**Rationale**: Enables handler unit tests without spinning up HTTP server.

**Usage Pattern**:
```rust
#[cfg(test)]
mod tests {
    use axum_test::TestServer;

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = create_app();
        let server = TestServer::new(app).unwrap();

        let response = server.get("/health").await;
        response.assert_status_ok();
    }
}
```

**Cargo.toml Addition**:
```toml
[dev-dependencies]
axum-test = "15"
```

---

## Summary of Key Decisions

| Topic | Decision | Rationale |
|-------|----------|-----------|
| CI Tiers | Tier 1 (PR), Tier 2 (main), Tier 3 (release/manual) | Fast feedback + thorough validation |
| Docker Profiles | Per-format + all + smoke default | Flexible selective testing |
| Artifact Source | Generate from `.assets/` templates | Air-gapped, deterministic |
| Size Tiers | Small/Medium/Large | Covers basic to chunked transfer |
| TLS Testing | Self-signed CA | Full certificate chain validation |
| GPG Testing | Generated test keys | Production-realistic signing |
| Base Images | Rocky UBI + Debian official | Production-compatible |
| Failure Injection | Container kill/disconnect | Deterministic, reproducible |
| Stress Level | 100 concurrent | Practical for CI, catches real bugs |
| Handler Testing | axum-test | Fast unit tests without HTTP server |

---

## References

- [GitHub Actions Workflow Syntax](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions)
- [Docker Compose Profiles](https://docs.docker.com/compose/profiles/)
- [axum-test Crate](https://docs.rs/axum-test/latest/axum_test/)
- [RPM Signing Guide](https://access.redhat.com/articles/3359321)
- [Debian Repository Signing](https://wiki.debian.org/SecureApt)
