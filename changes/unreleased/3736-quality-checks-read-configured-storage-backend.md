---
section: Fixed
issues: [#3736, #4090]
---
- **Quality checks now read artifacts from the repository's configured storage backend, so they work on S3, GCS and Azure** (#3736, #4090). `QualityCheckService` was built without the storage registry on every path that runs checks (the upload auto-check and `POST /api/v1/quality/checks/trigger` for an artifact or a repository), so it fell back to the default filesystem backend and failed with "Storage key not found" for any artifact stored in object storage, even though the object existed and matched its `storage_key`. Both paths now resolve the backend the repository is configured with.
