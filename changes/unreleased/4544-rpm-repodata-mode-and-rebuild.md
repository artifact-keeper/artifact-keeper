---
section: Added
issues: [#4544]
---
- **`repodata_mode` and a rebuild endpoint for hosted RPM repositories** (#4544). A CI job that publishes an RPM and installs it from the same repository right away can call `POST /api/v1/repositories/{key}/rpm/repodata/rebuild?root=<root>&wait=true` (write access to the repository): it answers `200` with the revision once the precomputed repodata includes every write committed before the call. Without `wait=true` it answers `202` and the background builder builds the root at its next tick, skipping the debounce. To keep 1.11's behaviour for one repository (render on request and validate on every request, read-your-writes), set `"repodata_mode": "on_request"` on create or `PATCH`; `"precomputed"` is the default. Repository responses include `repodata_mode` for local RPM repositories, and `GET /api/v1/repositories/_/capabilities` reports `rpm_repodata_mode`. See `docs/rpm-repodata-depth.md`.
