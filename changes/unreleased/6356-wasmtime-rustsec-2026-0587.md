---
section: Security
issues: [#6356]
---
- **wasmtime and wasmtime-wasi are bumped to 36.0.22 for RUSTSEC-2026-0587** (#6356). The advisory is a WASI filesystem sandbox escape on Windows through a drive-prefixed path component. Artifact Keeper's plugin runtime gives plugins a WASI context with standard I/O only and preopens no directories, so no known path reaches it, on Windows or elsewhere. The bump stays within the 36.x line.
