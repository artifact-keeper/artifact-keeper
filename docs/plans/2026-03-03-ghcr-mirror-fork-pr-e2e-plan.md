# GHCR Image Mirroring Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Mirror Docker Hub images to GHCR so fork PRs can run smoke E2E tests without Docker Hub credentials.

**Architecture:** A scheduled GitHub Actions workflow pulls 5 base images from Docker Hub weekly and pushes them to `ghcr.io/artifact-keeper/mirror/`. The E2E compose file references GHCR mirrors. The CI workflow removes its fork-PR skip and Docker Hub login step.

**Tech Stack:** GitHub Actions, Docker, GHCR, docker-compose

---

### Task 1: Create the mirror workflow

**Files:**
- Create: `.github/workflows/mirror-images.yml`

**Step 1: Write the workflow file**

```yaml
name: Mirror Docker Hub Images

on:
  schedule:
    - cron: '0 4 * * 1'  # Monday 4am UTC
  workflow_dispatch:

permissions:
  contents: read
  packages: write

jobs:
  mirror:
    name: Mirror Images to GHCR
    runs-on: ubuntu-latest
    strategy:
      matrix:
        image:
          - source: postgres:16-alpine
            target: ghcr.io/artifact-keeper/mirror/postgres:16-alpine
          - source: alpine:3.19
            target: ghcr.io/artifact-keeper/mirror/alpine:3.19
          - source: python:3.12-slim
            target: ghcr.io/artifact-keeper/mirror/python:3.12-slim
          - source: node:20-slim
            target: ghcr.io/artifact-keeper/mirror/node:20-slim
          - source: rust:1.75-slim
            target: ghcr.io/artifact-keeper/mirror/rust:1.75-slim
    steps:
      - name: Login to GHCR
        run: echo "${{ secrets.GITHUB_TOKEN }}" | docker login ghcr.io -u ${{ github.actor }} --password-stdin

      - name: Pull from Docker Hub
        run: docker pull ${{ matrix.image.source }}

      - name: Tag for GHCR
        run: docker tag ${{ matrix.image.source }} ${{ matrix.image.target }}

      - name: Push to GHCR
        run: docker push ${{ matrix.image.target }}
```

**Step 2: Validate YAML syntax**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/mirror-images.yml')); print('Valid')"`
Expected: `Valid`

**Step 3: Commit**

```bash
git add .github/workflows/mirror-images.yml
git commit -m "chore(ci): add scheduled workflow to mirror Docker Hub images to GHCR"
```

---

### Task 2: Run the mirror workflow to seed GHCR

**Step 1: Push the branch and trigger the workflow manually**

```bash
git push -u origin <branch-name>
gh workflow run mirror-images.yml --ref <branch-name>
```

**Step 2: Wait for the workflow to complete**

```bash
gh run list --workflow mirror-images.yml --limit 1
```

Expected: 5 matrix jobs, all succeeded.

**Step 3: Verify images exist on GHCR**

```bash
gh api orgs/artifact-keeper/packages/container/mirror%2Fpostgres/versions --jq '.[0].metadata.container.tags'
gh api orgs/artifact-keeper/packages/container/mirror%2Falpine/versions --jq '.[0].metadata.container.tags'
gh api orgs/artifact-keeper/packages/container/mirror%2Fpython/versions --jq '.[0].metadata.container.tags'
gh api orgs/artifact-keeper/packages/container/mirror%2Fnode/versions --jq '.[0].metadata.container.tags'
gh api orgs/artifact-keeper/packages/container/mirror%2Frust/versions --jq '.[0].metadata.container.tags'
```

Expected: Each returns the expected tag (e.g., `["16-alpine"]`, `["3.19"]`, etc.).

---

### Task 3: Update docker-compose.test.yml image references

**Files:**
- Modify: `docker-compose.test.yml`

**Step 1: Replace Docker Hub references with GHCR mirrors**

Replace these image references (only in services that are part of the smoke profile):

| Line | Old | New |
|------|-----|-----|
| 31 | `docker.io/postgres:16-alpine` | `ghcr.io/artifact-keeper/mirror/postgres:16-alpine` |
| 87 | `alpine:3.19` | `ghcr.io/artifact-keeper/mirror/alpine:3.19` |
| 106 | `alpine:3.19` | `ghcr.io/artifact-keeper/mirror/alpine:3.19` |
| 143 | `python:3.12-slim` | `ghcr.io/artifact-keeper/mirror/python:3.12-slim` |
| 163 | `node:20-slim` | `ghcr.io/artifact-keeper/mirror/node:20-slim` |
| 183 | `rust:1.75-slim` | `ghcr.io/artifact-keeper/mirror/rust:1.75-slim` |

Do NOT change images in non-smoke services (maven, go, rpm, deb, helm, conda, docker profiles). Those still pull from Docker Hub and are only used in the `all` profile which runs on internal infrastructure.

Also replace any other `alpine:3.19` references in smoke-profile services (check lines 357, 416 if they are in the smoke profile).

**Step 2: Validate compose file**

Run: `docker compose -f docker-compose.test.yml --profile smoke config > /dev/null`
Expected: No errors.

**Step 3: Commit**

```bash
git add docker-compose.test.yml
git commit -m "chore: update smoke E2E images to use GHCR mirrors"
```

---

### Task 4: Update ci.yml to remove fork PR restrictions

**Files:**
- Modify: `.github/workflows/ci.yml`

**Step 1: Remove the fork PR skip condition from smoke-e2e job**

Change lines 186-188 from:

```yaml
    # Skip for fork PRs: Docker Hub secrets are unavailable and anonymous
    # pulls hit rate limits. E2E runs on main after merge.
    if: github.event.pull_request.head.repo.full_name == github.repository || github.event_name != 'pull_request'
```

To: (delete all three lines entirely, no `if` condition)

**Step 2: Remove the Docker Hub login step**

Delete lines 240-244:

```yaml
      - name: Login to Docker Hub
        if: env.DOCKERHUB_USERNAME != ''
        env:
          DOCKERHUB_USERNAME: ${{ secrets.DOCKERHUB_USERNAME }}
        run: echo "${{ secrets.DOCKERHUB_TOKEN }}" | docker login -u "${{ secrets.DOCKERHUB_USERNAME }}" --password-stdin
```

**Step 3: Revert ci-complete smoke E2E check to require success**

Change the smoke E2E section in `ci-complete` (around line 444) from:

```yaml
          # Smoke E2E (skipped for fork PRs where Docker Hub secrets are unavailable)
          smoke_result="${{ needs.smoke-e2e.result }}"
          if [[ "$smoke_result" == "success" ]]; then
            echo "✅ smoke-e2e" >> $GITHUB_STEP_SUMMARY
          elif [[ "$smoke_result" == "skipped" ]]; then
            echo "⏭️ smoke-e2e (fork PR — skipped)" >> $GITHUB_STEP_SUMMARY
          else
            echo "❌ smoke-e2e: $smoke_result" >> $GITHUB_STEP_SUMMARY
            tier1_pass=false
          fi
```

To:

```yaml
          # Smoke E2E
          if [[ "${{ needs.smoke-e2e.result }}" == "success" ]]; then
            echo "✅ smoke-e2e" >> $GITHUB_STEP_SUMMARY
          else
            echo "❌ smoke-e2e: ${{ needs.smoke-e2e.result }}" >> $GITHUB_STEP_SUMMARY
            tier1_pass=false
          fi
```

**Step 4: Validate YAML**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('Valid')"`
Expected: `Valid`

**Step 5: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "chore(ci): remove fork PR E2E skip, all images now from GHCR"
```

---

### Task 5: Create PR and verify

**Step 1: Push and create PR**

```bash
git push -u origin <branch-name>
gh pr create --title "chore(ci): mirror Docker Hub images to GHCR for fork PR E2E parity" --body "..."
```

**Step 2: Verify CI passes**

All checks should pass, including smoke E2E pulling from GHCR mirrors.

**Step 3: After merge, verify on a fork PR**

Close/reopen PR #337 (or any fork PR) and confirm smoke E2E runs and passes.
