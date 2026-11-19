---
section: Changed
issues: [#6242]
---
- **Development and CI: CI and the release pipeline are steadier on hosted runners** (#6242). Check Rust runs clippy in two passes so the library and its tests no longer compile at the same time and swap the 16 GB runner, with a memory watchdog that leaves evidence if a run stalls (#6263); the Windows cross-check installs only the x86_64 mingw toolchain with a bounded, mirror-fallback download and is a required check again (#6265); and Docker Publish runs for `main` pushes coalesce to the newest pending commit, with the Release Candidate re-running its own commit's build if it was replaced (#6264).
