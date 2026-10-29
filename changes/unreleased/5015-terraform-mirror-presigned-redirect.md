---
section: Changed
issues: [#5015]
---
- **A remote Terraform repository's network mirror redirects cached provider archives to presigned object-storage URLs** (#5015). With `PRESIGNED_DOWNLOADS_ENABLED` and a backend that can sign, a fresh cache hit no longer streams the archive through the backend; a miss, a `HEAD` and backends that cannot sign still stream.
