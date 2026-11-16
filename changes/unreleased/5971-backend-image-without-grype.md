---
section: Changed
issues: [#5971, #4548]
---
- **`artifact-keeper-backend:<tag>` no longer ships grype or its vulnerability database, `artifact-keeper-backend:<tag>-scanner` does** (#5971, #4548). grype and its seeded database of about 3 GB were in the image only so the API process could scan in process. `docker/Dockerfile.backend` now has a `runtime` target without them and a `scanner` target (the last stage, so a build without `--target` still has grype) that adds both. Docker Publish builds the two on one builder, publishes the scanner variant with the `-scanner` suffix on every tag (`1.13.0-scanner`, `1.13-scanner`, `latest-scanner`, `dev-scanner`, `sha-<sha>-scanner`) on ghcr.io and Docker Hub, signs and attests it, and runs the Trivy gate on both.

  Upgrade: anything that scans in the backend process (a single instance, `docker-compose.yml`, the chart without a scan worker) moves to the `-scanner` tag. `docker-compose.yml` here does. A fleet with the scan queue on runs the API pods on the plain tag with `SCAN_WORKER_ENABLED=false` and the scan workers on `-scanner`.
