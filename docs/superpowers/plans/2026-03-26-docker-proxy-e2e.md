# Docker Hub Proxy E2E Test Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create an E2E test script that validates the Docker Hub `library/` prefix fix (PR #586) and run it on a fresh AWS EC2 instance.

**Architecture:** A standalone bash test script (`test-docker-proxy.sh`) that creates remote OCI repos pointing at Docker Hub and ghcr.io, then fetches manifests through the proxy to verify the `library/` prefix is correctly applied for official images and not applied for namespaced images or non-Docker Hub registries. Deployed to a fresh t3.small EC2 using the same compose pattern as the demo instance.

**Tech Stack:** Bash, curl, jq, Docker Compose, AWS CLI, ghcr.io images

---

### Task 1: Write the E2E test script

**Files:**
- Create: `scripts/native-tests/test-docker-proxy.sh`

- [ ] **Step 1: Create test-docker-proxy.sh**

The script follows the established patterns from `test-proxy-virtual.sh`:
- Authenticates via `/api/v1/auth/login`
- Creates a remote OCI repo pointing at `registry-1.docker.io`
- Creates a second remote OCI repo pointing at `ghcr.io` (control group)
- Fetches manifests for official single-name images (`alpine`, `nginx`, `ubuntu`) through the Docker Hub proxy and asserts 200 with valid manifest JSON
- Fetches a namespaced image (`grafana/grafana`) through the Docker Hub proxy and asserts 200
- Fetches an image through the ghcr.io proxy to verify no `library/` prefix is applied
- Verifies write rejection (PUT to remote repo returns 405)
- Reports pass/fail/skip counts

- [ ] **Step 2: Make executable and verify locally**

```bash
chmod +x scripts/native-tests/test-docker-proxy.sh
```

### Task 2: Wire into test runner

**Files:**
- Modify: `scripts/e2e-setup.sh` (add Docker Hub remote repo to bootstrap)
- Modify: `docker-compose.test.yml` (add docker-proxy profile)
- Modify: `scripts/run-e2e-tests.sh` (add docker-proxy profile option)

- [ ] **Step 1: Add Docker Hub proxy repo to e2e-setup.sh**

Add `"docker-hub-proxy:Docker Hub Proxy:docker:https://registry-1.docker.io"` to the remote repos creation loop.

- [ ] **Step 2: Add docker-proxy test container to docker-compose.test.yml**

Add a new service with `profiles: ["docker-proxy", "all"]`.

- [ ] **Step 3: Add profile to run-e2e-tests.sh**

Add `docker-proxy` to the profile list and help text.

### Task 3: Provision fresh EC2 and deploy

- [ ] **Step 1: Launch t3.small EC2 instance**

Using the same VPC/subnet/SG as the demo instance with Ubuntu 24.04 AMI.

- [ ] **Step 2: Install Docker and Docker Compose on the instance**

- [ ] **Step 3: Trigger Docker Publish workflow for PR branch image**

Use `gh workflow run docker-publish.yml --ref fix/docker-remote-library-prefix` to build an image tagged with the commit SHA.

- [ ] **Step 4: Deploy backend + postgres via docker compose**

Minimal compose (postgres + backend only, no web/trivy needed for this test). Pull the SHA-tagged image.

- [ ] **Step 5: Copy and run the test script**

SCP the script to the instance and run it against the deployed backend.

### Task 4: Cleanup

- [ ] **Step 1: Terminate the EC2 instance after tests pass**

- [ ] **Step 2: Commit the test script**
