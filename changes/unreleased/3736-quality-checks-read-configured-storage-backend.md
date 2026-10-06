---
section: Fixed
issues: [#3736, #4090]
---
- **Quality checks now read artifacts from the repository's configured storage backend, so they work on S3, GCS and Azure** (#3736, #4090). Both ways of running checks, the automatic check after an upload and `POST /api/v1/quality/checks/trigger` for an artifact or a repository, read the artifact from the default filesystem backend, so a check of anything stored in object storage failed with "Storage key not found" even though the object existed. Checks now read from the backend the repository is configured with.
