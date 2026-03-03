# GHCR Image Mirroring for Fork PR E2E Parity

Date: 2026-03-03

## Problem

Fork PRs cannot access GitHub Actions secrets (security restriction). The smoke E2E tests pull base images from Docker Hub (postgres, python, node, rust, alpine), and without `DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN`, anonymous pulls hit Docker Hub's rate limit (100 pulls per 6 hours per IP). ARC runners share IPs, making the limit easy to exhaust.

Currently, smoke E2E is skipped entirely for fork PRs, meaning external contributor PRs get no integration test coverage until after merge.

## Solution

Mirror the Docker Hub images used by the E2E test stack to GHCR (`ghcr.io/artifact-keeper/mirror/`). `GITHUB_TOKEN` is always available in GitHub Actions, even for fork PRs, so GHCR pulls always succeed with no rate limit issues.

## Design

### 1. Mirror Workflow

New file: `.github/workflows/mirror-images.yml`

- Trigger: weekly schedule (Monday 4am UTC) + `workflow_dispatch` for manual runs
- Uses `GITHUB_TOKEN` for GHCR push (no additional secrets needed)
- Matrix job over the image list: pull from Docker Hub, tag, push to GHCR
- Destination pattern: `ghcr.io/artifact-keeper/mirror/<image>:<tag>`

Images to mirror (smoke profile only):

| Source (Docker Hub) | Destination (GHCR) |
|---|---|
| `postgres:16-alpine` | `ghcr.io/artifact-keeper/mirror/postgres:16-alpine` |
| `alpine:3.19` | `ghcr.io/artifact-keeper/mirror/alpine:3.19` |
| `python:3.12-slim` | `ghcr.io/artifact-keeper/mirror/python:3.12-slim` |
| `node:20-slim` | `ghcr.io/artifact-keeper/mirror/node:20-slim` |
| `rust:1.75-slim` | `ghcr.io/artifact-keeper/mirror/rust:1.75-slim` |

### 2. Compose File Changes

Update `docker-compose.test.yml` to reference GHCR mirrors for the five images above. No changes to `docker-compose.local-dev.yml` (developers pull locally with their own Docker Hub auth).

### 3. CI Workflow Changes

In `.github/workflows/ci.yml`:

- Remove the fork PR skip condition on the smoke E2E job. All PRs run E2E.
- Remove the Docker Hub login step (no longer needed for E2E).
- GHCR login stays as-is (`GITHUB_TOKEN`).
- Revert `ci-complete` to require smoke E2E success (no "skipped for fork PR" path).

### 4. Rollback

If the mirror breaks: run the mirror workflow manually via `workflow_dispatch` (~2 minutes). Nuclear option: revert the compose file to Docker Hub references and re-add Docker Hub login. One commit.

## Out of Scope

- Mirroring images for the `all` E2E profile (maven, go, helm, conda, etc.). Can be added later.
- Changing `docker-compose.local-dev.yml`. Developers use their own Docker Hub auth.
- `aquasec/trivy:latest`. Not in the smoke profile.
