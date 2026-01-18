# Data Model: Staged Testing Strategy for CI/CD

**Branch**: `005-staged-testing-ci` | **Date**: 2026-01-18

## Overview

This feature primarily involves CI/CD infrastructure and test tooling rather than application data models. The entities below represent configuration structures and test artifacts rather than database tables.

---

## Core Entities

### 1. Test Tier

Classification of test types with associated triggers and timing targets.

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Tier identifier (tier1, tier2, tier3) |
| `displayName` | string | Human-readable name (Fast CI, Integration, E2E) |
| `trigger` | TriggerConfig | Events that activate this tier |
| `targetDuration` | duration | Maximum expected completion time |
| `tests` | TestConfig[] | Tests included in this tier |

**Tier Definitions**:
```yaml
tier1:
  displayName: "Fast CI"
  trigger: { push: true, pull_request: true }
  targetDuration: 5m
  tests: [lint-rust, lint-typescript, test-backend-unit, test-frontend-unit]

tier2:
  displayName: "Integration"
  trigger: { push: { branches: [main] } }
  targetDuration: 15m
  tests: [tier1, test-backend-integration, docker-build]

tier3:
  displayName: "E2E"
  trigger: { workflow_dispatch: true, release: true }
  targetDuration: 30m
  tests: [tier2, test-e2e, native-client-tests, stress-tests, failure-tests]
```

---

### 2. Docker Compose Profile

Profile configuration for selective test execution.

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Profile identifier (pypi, npm, rpm, all, etc.) |
| `services` | string[] | Services activated by this profile |
| `isSmoke` | boolean | Included in default (no profile) runs |
| `dependencies` | string[] | Other profiles/services required |

**Profile Matrix**:
| Profile | Services | Smoke | Dependencies |
|---------|----------|-------|--------------|
| `pypi` | pypi-test | ✅ | backend, pki |
| `npm` | npm-test | ✅ | backend, pki |
| `cargo` | cargo-test | ✅ | backend, pki |
| `maven` | maven-test | ❌ | backend, pki |
| `go` | go-test | ❌ | backend, pki |
| `rpm` | rpm-test | ❌ | backend, pki, gpg |
| `deb` | deb-test | ❌ | backend, pki, gpg |
| `helm` | helm-test | ❌ | backend, pki |
| `conda` | conda-test | ❌ | backend, pki |
| `docker` | docker-test | ❌ | backend, pki, registry |
| `all` | (all above) | ❌ | (all above) |

---

### 3. Test Asset Template

Package template configuration for generating test artifacts.

| Field | Type | Description |
|-------|------|-------------|
| `format` | PackageFormat | Package format identifier |
| `templateDir` | path | Directory containing template files |
| `generateScript` | path | Script to generate package from template |
| `sizeTiers` | SizeConfig | Configuration for size variants |
| `outputPattern` | string | Glob pattern for generated artifacts |

**Package Format Enum**:
```
PackageFormat = pypi | npm | cargo | maven | go | rpm | deb | helm | conda | docker
```

**Size Configuration**:
```yaml
sizeTiers:
  small:
    maxSize: 1MB
    dataFile: null  # No extra data
  medium:
    maxSize: 10MB
    dataFile: { size: 10MB, random: true }
  large:
    maxSize: 100MB
    dataFile: { size: 100MB, random: true }
```

---

### 4. PKI Configuration

TLS and GPG key configuration for secure testing.

| Field | Type | Description |
|-------|------|-------------|
| `caKeyPath` | path | CA private key location |
| `caCertPath` | path | CA certificate location |
| `serverKeyPath` | path | Server private key location |
| `serverCertPath` | path | Server certificate location |
| `gpgKeyId` | string | GPG key identifier for signing |
| `gpgPublicKeyPath` | path | Exported public key for clients |

**Generated Files**:
```text
.pki/
├── ca.key           # CA private key (gitignored)
├── ca.crt           # CA certificate
├── server.key       # Server private key (gitignored)
├── server.crt       # Server certificate
├── gpg-signing.key  # GPG private key (gitignored)
└── gpg-signing.pub  # GPG public key
```

---

### 5. Test Report

Artifacts produced by test runs.

| Field | Type | Description |
|-------|------|-------------|
| `tier` | TestTier | Tier that produced this report |
| `workflow` | string | CI workflow run identifier |
| `timestamp` | datetime | Report generation time |
| `status` | TestStatus | Overall status (pass, fail, skip) |
| `duration` | duration | Total execution time |
| `artifacts` | Artifact[] | Generated test artifacts |
| `retentionDays` | int | Days to retain (default: 14) |

**Test Status Enum**:
```
TestStatus = pass | fail | skip | timeout | cancelled
```

**Artifacts**:
| Artifact Type | Path Pattern | Description |
|--------------|--------------|-------------|
| Playwright Report | `playwright-report/` | HTML test report |
| Test Results | `test-results/` | Raw test output |
| Coverage | `coverage/` | Code coverage data |
| Logs | `logs/` | Service logs from containers |

---

### 6. Native Client Test Case

Test case definition for package manager client testing.

| Field | Type | Description |
|-------|------|-------------|
| `format` | PackageFormat | Package format being tested |
| `operation` | Operation | push or pull |
| `client` | ClientConfig | Client binary and configuration |
| `testPackage` | TestAssetTemplate | Package to use for testing |
| `validation` | ValidationRule[] | Post-operation validation checks |

**Operation Enum**:
```
Operation = push | pull
```

**Client Configuration**:
| Format | Client Binary | Push Command | Pull Command |
|--------|---------------|--------------|--------------|
| pypi | `pip`, `twine` | `twine upload` | `pip install` |
| npm | `npm` | `npm publish` | `npm install` |
| cargo | `cargo` | `cargo publish` | `cargo install` |
| maven | `mvn` | `mvn deploy` | `mvn dependency:get` |
| go | `go` | `GOPROXY=... go mod tidy` | `go get` |
| rpm | `dnf` | N/A (API upload) | `dnf install` |
| deb | `apt` | N/A (API upload) | `apt install` |
| helm | `helm` | `helm push` | `helm pull` |
| conda | `conda` | N/A (API upload) | `conda install` |
| docker | `docker` | `docker push` | `docker pull` |

---

### 7. Failure Test Scenario

Configuration for failure injection tests.

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Scenario identifier |
| `failureType` | FailureType | Type of failure to inject |
| `triggerPoint` | string | When to inject failure |
| `expectedBehavior` | string | Expected system response |
| `validation` | ValidationRule[] | Post-failure checks |

**Failure Type Enum**:
```
FailureType = server_crash | db_disconnect | storage_failure
```

**Predefined Scenarios**:
| Scenario | Failure Type | Trigger Point | Expected Behavior |
|----------|--------------|---------------|-------------------|
| `crash-mid-upload` | server_crash | After 50% upload | Atomic rollback, no partial artifacts |
| `db-disconnect-transaction` | db_disconnect | During write transaction | Clean error, no partial state |
| `storage-write-failure` | storage_failure | During artifact write | Error returned, no orphaned files |

---

## State Transitions

### CI Workflow States

```
[trigger] → PENDING → RUNNING → COMPLETED
                 ↓         ↓
              SKIPPED   FAILED
                         ↓
                      CANCELLED
```

### Test Tier Execution Flow

```
Push/PR Event
    │
    ▼
┌─────────┐
│ Tier 1  │ ← Always runs (lint + unit)
└────┬────┘
     │ pass
     ▼
┌─────────┐
│ Tier 2  │ ← Only on main branch merge
└────┬────┘
     │ pass
     ▼
┌─────────┐
│ Tier 3  │ ← Only on release tag or manual trigger
└─────────┘
```

---

## Validation Rules

### Package Validation (Post-Generation)

| Rule | Validation |
|------|------------|
| Valid format | Package can be parsed by native client |
| Correct metadata | Name, version match template |
| Size within tier | Artifact size ≤ tier maximum |
| Installable | Native client can install successfully |

### Rollback Validation (Post-Failure)

| Rule | Validation |
|------|------------|
| No orphaned artifacts | Storage has no partial files |
| No orphaned DB records | Database has no incomplete entries |
| Clean error response | Client received appropriate error code |
| Service recoverable | Service restarts and functions normally |

### Stress Test Validation

| Rule | Validation |
|------|------------|
| All operations complete | 100/100 operations finished |
| No data corruption | All checksums match |
| No deadlocks | No operations timed out |
| Correct counts | DB artifact count matches expected |
