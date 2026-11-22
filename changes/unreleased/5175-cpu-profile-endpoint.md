---
section: Added
issues: [#5175]
---
- **The backend can now capture an admin-only CPU profile from a profiling build** (#5175). The opt-in `profiling` feature adds `GET /api/v1/admin/cpu-profile` with a bounded sampling duration and pprof-compatible output, so operators can build a symbolized profiling binary without changing the release profile's `strip = true`.
