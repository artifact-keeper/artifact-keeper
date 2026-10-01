---
section: Fixed
issues: [#4191]
---
- **Go module catalog entries no longer report the `go.mod` sidecar's size after a backfill** (#4191). The catalog backfill did not exclude sidecar rows, so a module's reported size flipped between the archive's and the go.mod's depending on row order; `.mod`/`.info` (Go) and `.prov` (Helm) rows are now excluded from the candidate set and the archive row always registers the version.
