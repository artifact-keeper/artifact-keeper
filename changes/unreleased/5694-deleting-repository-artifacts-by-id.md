---
section: Fixed
issues: [#5694]
---
- **Artifacts of a repository being deleted no longer resolve by id** ([#5694]). From the moment `DELETE /api/v1/repositories/{key}` queues its job the repository's key stops resolving, but its artifacts kept answering `GET /api/v1/artifacts/{id}`, `/stats` and `/metadata` until the job reached their rows, for a time that grows with the repository (over 100 s for 10,000 artifacts on S3). The shared by-id visibility check now treats an artifact of a repository under delete as missing, so these routes, the artifact label routes and the other by-id surfaces built on it (SBOM, security, quality-gate and package-analysis reads) answer the same `404 Artifact not found` as for an id that does not exist.
